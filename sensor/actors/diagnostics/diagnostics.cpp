/**
 * @file diagnostics.cpp
 * @brief DiagnosticsActor implementation.
 */
#include "diagnostics/diagnostics.hpp"

#include <algorithm>
#include <array>
#include <fstream>

#include "ieso/core/base64.hpp"
#include "ieso/core/json.hpp"
#include "ieso/core/runtime.hpp"
#include "ieso/core/sha256.hpp"
#include "ieso/core/time_util.hpp"
#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "diagnostics";
/// @brief Compiled-in probe allowlist (read-only probes only; DESIGN §10.3). Mirrors the control plane's list.
constexpr std::array<std::string_view, 4> kProbeAllowlist = {"net.config", "net.synthetic_tls", "env.extensions",
                                                             "svc.launchctl"};
constexpr std::size_t kMaxSeenRequests = 256;
constexpr std::int64_t kMaxProbeClockSkewMs = 5 * 60 * 1000;

/**
 * @brief Writes one ResourceSample as a JSON object.
 * @param[in,out] w Writer.
 * @param[in] s Sample.
 * @return SRESULT::Ok or writer error.
 */
SRESULT write_sample(JsonWriter& w, const ResourceSample& s) {
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("ts_ms"));
  HS_RETURN_IF_FAILED(w.value(s.ts_ms));
  HS_RETURN_IF_FAILED(w.key("pid"));
  HS_RETURN_IF_FAILED(w.value(s.pid));
  if (s.pid == kGapMarkerPid) {  // sensor was down between the previous entry and this one
    HS_RETURN_IF_FAILED(w.key("gap"));
    HS_RETURN_IF_FAILED(w.value(true));
  }
  HS_RETURN_IF_FAILED(w.key("cpu_pct"));
  HS_RETURN_IF_FAILED(w.value(s.cpu_pct));
  HS_RETURN_IF_FAILED(w.key("rss_bytes"));
  HS_RETURN_IF_FAILED(w.value(static_cast<std::int64_t>(s.rss_bytes)));
  HS_RETURN_IF_FAILED(w.key("threads"));
  HS_RETURN_IF_FAILED(w.value(static_cast<std::int64_t>(s.threads)));
  HS_RETURN_IF_FAILED(w.key("fds"));
  HS_RETURN_IF_FAILED(w.value(static_cast<std::int64_t>(s.fds)));
  HS_RETURN_IF_FAILED(w.key("disk_free_bytes"));
  HS_RETURN_IF_FAILED(w.value(static_cast<std::int64_t>(s.disk_free_bytes)));
  return w.end_object();
}

/**
 * @brief Writes a flat field list as a JSON object member value.
 * @param[in,out] w Writer.
 * @param[in] fields Fields.
 * @return SRESULT::Ok or writer error.
 */
SRESULT write_fields(JsonWriter& w, const Fields& fields) {
  HS_RETURN_IF_FAILED(w.begin_object());
  for (const Field& f : fields) {
    HS_RETURN_IF_FAILED(w.key(f.key));
    HS_RETURN_IF_FAILED(w.field_value(f.value));
  }
  return w.end_object();
}
}  // namespace

DiagnosticsActor::DiagnosticsActor(EventBus& bus, EventFactory& factory, const IClock& clock,
                                   std::shared_ptr<IDiagnosticsPlatform> platform, DiagnosticsOptions opts)
    : Actor("diagnostics"),
      bus_(bus),
      factory_(factory),
      clock_(clock),
      platform_(std::move(platform)),
      opts_(std::move(opts)),
      redactor_(opts_.redaction_salt),
      budget_(clock, opts_.captures_per_incident, opts_.captures_per_hour),
      probe_budget_(clock, opts_.probes_per_incident, opts_.probes_per_hour) {}

SRESULT DiagnosticsActor::on_start(ActorContext& ctx) {
  if (!platform_ || opts_.incident_dir.empty()) return SRESULT::InvalidArgument;
  std::error_code ec;
  std::filesystem::create_directories(opts_.incident_dir, ec);
  if (ec) {
    HS_TRACE_ERROR(kComponent, "cannot create incident dir '{}': {}", opts_.incident_dir.string(), ec.message());
    return SRESULT::IoError;
  }
  HS_RETURN_IF_FAILED(FlightRecorder::Create(recorder_));
  HS_RETURN_IF_FAILED(load_checkpoint());
  HS_RETURN_IF_FAILED(clock_.now_steady(last_checkpoint_));
  HS_RETURN_IF_FAILED(subscribe<ResourceSampled>(ctx.bus, [this](const auto& e) {
    const SRESULT r = recorder_->ingest(e->sample);
    return r == SRESULT::InvalidArgument ? SRESULT::Ok : r;  // out-of-order sample already traced
  }));
  HS_RETURN_IF_FAILED(subscribe<LogRecordObserved>(ctx.bus, [this](const auto& e) {
    LogLine l;
    HS_RETURN_IF_FAILED(to_unix_ms(e->hdr.ts, l.ts_ms));
    l.level = e->level;
    l.subsystem = e->subsystem;
    l.category = e->category;
    l.message = e->message;
    (void)logs_.push(l);  // Dropped = oldest line rolled out
    return SRESULT::Ok;
  }));
  HS_RETURN_IF_FAILED(subscribe<TargetLifecycle>(ctx.bus, [this](const auto& e) {
    pid_ = e->phase == "launch" ? e->pid : 0;
    return SRESULT::Ok;
  }));
  HS_RETURN_IF_FAILED(subscribe<ProcessHangDetected>(ctx.bus, [this](const auto& e) {
    return on_incident(e, "hang", e->pid, true);
  }));
  HS_RETURN_IF_FAILED(subscribe<ProcessCrashDetected>(ctx.bus, [this](const auto& e) {
    return on_incident(e, "crash", e->pid, false);
  }));
  HS_RETURN_IF_FAILED(subscribe<ResourceAnomalyDetected>(ctx.bus, [this](const auto& e) {
    return on_incident(e, "resource:" + e->metric, pid_, false);
  }));
  HS_RETURN_IF_FAILED(subscribe<UserVisibleErrorObserved>(ctx.bus, [this](const auto& e) {
    return on_incident(e, "user_visible_error", e->pid, false);
  }));
  HS_RETURN_IF_FAILED(
      subscribe<DiagnosticEscalationRequested>(ctx.bus, [this](const auto& e) { return on_escalation(e); }));
  HS_RETURN_IF_FAILED(subscribe<ProbeRequested>(ctx.bus, [this](const auto& e) { return on_probe(e); }));
  TimerId id = 0;
  return ctx.runtime.schedule_every(shared_from_this(), opts_.tick, [this] { return tick(); }, id);
}

SRESULT DiagnosticsActor::check_probe(const ProbeRequested& req, std::string& reason) {
  reason.clear();
  if (std::find(kProbeAllowlist.begin(), kProbeAllowlist.end(), req.probe_id) == kProbeAllowlist.end()) {
    reason = "probe '" + req.probe_id + "' is not on the allowlist";
    return SRESULT::Ok;
  }
  std::string self;
  HS_RETURN_IF_FAILED(factory_.endpoint_id(self));
  if (req.endpoint != self) {
    reason = "request targets endpoint '" + req.endpoint + "', not this one";
    return SRESULT::Ok;
  }
  std::chrono::system_clock::time_point now_tp;
  HS_RETURN_IF_FAILED(clock_.now_system(now_tp));
  std::int64_t now = 0;
  HS_RETURN_IF_FAILED(to_unix_ms(now_tp, now));
  if (now > req.expires_at || req.issued_at > now + kMaxProbeClockSkewMs || req.expires_at <= req.issued_at) {
    reason = "request expired or not yet valid";
    return SRESULT::Ok;
  }
  if (!opts_.probe_verifier) {
    reason = "no probe-signing key pinned on this endpoint";
    return SRESULT::Ok;
  }
  std::string sig;
  if (HS_FAILED(base64_decode(req.signature, sig)) || sig.empty()) {
    reason = "signature is not valid base64";
    return SRESULT::Ok;
  }
  const std::string canonical = "v1|" + req.request_id + "|" + req.endpoint + "|" + req.probe_id + "|" +
                                req.incident_id + "|" + std::to_string(req.issued_at) + "|" +
                                std::to_string(req.expires_at);
  bool valid = false;
  HS_RETURN_IF_FAILED(opts_.probe_verifier->verify(canonical, sig, valid));
  if (!valid) {
    reason = "signature does not verify against the pinned control-plane key";
    return SRESULT::Ok;
  }
  if (std::find(seen_requests_.begin(), seen_requests_.end(), req.request_id) != seen_requests_.end()) {
    reason = "replayed request id";
    return SRESULT::Ok;
  }
  seen_requests_.push_back(req.request_id);
  if (seen_requests_.size() > kMaxSeenRequests) seen_requests_.pop_front();
  if (probe_budget_.try_acquire(req.incident_id) != SRESULT::Ok) {
    reason = "probe budget exhausted";
    return SRESULT::Ok;
  }
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::on_probe(const std::shared_ptr<const ProbeRequested>& req) {
  std::string reason;
  HS_RETURN_IF_FAILED(check_probe(*req, reason));
  std::shared_ptr<ProbeResultReady> res;
  HS_RETURN_IF_FAILED(factory_.make<ProbeResultReady>(res));
  res->probe_id = req->probe_id;
  res->request_id = req->request_id;
  res->incident_id = req->incident_id;
  if (!reason.empty()) {
    HS_TRACE_WARNING(kComponent, "probe {} ({}) refused: {}", req->probe_id, req->request_id, reason);
    res->output = "refused: " + reason;
    res->exit_status = -1;
  } else {
    HS_TRACE_INFO(kComponent, "running probe {} for incident {} (signature verified)", req->probe_id,
                  req->incident_id);
    const SRESULT r = platform_->run_probe(req->probe_id, res->output, res->exit_status);
    if (HS_FAILED(r)) {
      std::string_view name;
      (void)to_string(r, name);  // always Ok
      res->output = "probe failed: " + std::string(name);
      res->exit_status = -2;
    }
  }
  return bus_.post(std::move(res));
}

SRESULT DiagnosticsActor::load_checkpoint() {
  if (opts_.checkpoint_file.empty()) return SRESULT::NoOp;
  std::ifstream f(opts_.checkpoint_file, std::ios::binary);
  if (!f.is_open()) return SRESULT::NoOp;  // first start
  const std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  f.close();
  std::chrono::system_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_system(now));
  std::int64_t now_ms = 0;
  HS_RETURN_IF_FAILED(to_unix_ms(now, now_ms));
  RestoreStats st;
  const SRESULT r = recorder_->restore(data, now_ms, st);
  if (HS_FAILED(r)) {
    // Never block startup on a bad checkpoint: keep it aside for analysis and start with empty rings.
    HS_TRACE_WARNING(kComponent, "flight-recorder checkpoint {} not restored: {}; starting empty",
                     opts_.checkpoint_file.string(), r);
    std::error_code ec;
    std::filesystem::rename(opts_.checkpoint_file, opts_.checkpoint_file.string() + ".bad", ec);
    return SRESULT::NoOp;
  }
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::save_checkpoint() {
  if (opts_.checkpoint_file.empty() || !recorder_) return SRESULT::NoOp;
  std::chrono::system_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_system(now));
  std::int64_t now_ms = 0;
  HS_RETURN_IF_FAILED(to_unix_ms(now, now_ms));
  std::string data;
  HS_RETURN_IF_FAILED(recorder_->checkpoint(now_ms, data));
  const std::filesystem::path tmp = opts_.checkpoint_file.string() + ".tmp";
  HS_RETURN_IF_FAILED(write_file(tmp, data));
  std::error_code ec;
  std::filesystem::permissions(tmp, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                               std::filesystem::perm_options::replace, ec);
  std::filesystem::rename(tmp, opts_.checkpoint_file, ec);  // atomic replace: a crash leaves old or new, never half
  if (ec) {
    HS_TRACE_ERROR(kComponent, "checkpoint rename failed: {}", ec.message());
    return SRESULT::IoError;
  }
  HS_RETURN_IF_FAILED(clock_.now_steady(last_checkpoint_));
  HS_TRACE_DEBUG(kComponent, "flight recorder checkpointed ({} bytes)", data.size());
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::on_stop() {
  (void)save_checkpoint();  // final checkpoint on clean shutdown / before update; failure already traced
  for (const auto& p : pending_) (void)build_incident(p);  // flush: never lose an incident on shutdown
  pending_.clear();
  for (const auto& [subsystem, deadline] : escalated_) {
    (void)platform_->reset_log_mode(subsystem);  // best-effort revert on shutdown
  }
  escalated_.clear();
  return Actor::on_stop();
}

SRESULT DiagnosticsActor::on_escalation(const std::shared_ptr<const DiagnosticEscalationRequested>& ev) {
  if (ev->subsystem.empty()) return SRESULT::InvalidArgument;
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  const auto deadline = now + std::chrono::seconds(ev->duration_s);
  const auto it = escalated_.find(ev->subsystem);
  if (it != escalated_.end()) {  // already escalated: extend
    if (deadline > it->second) it->second = deadline;
    return SRESULT::NoOp;
  }
  const SRESULT r = platform_->set_log_mode(ev->subsystem, opts_.log_mode);
  if (HS_FAILED(r)) {
    if (!escalation_denied_warned_) {
      HS_TRACE_WARNING(kComponent, "log escalation for {} not applied ({}); needs root. Continuing without it",
                       ev->subsystem, r);
      escalation_denied_warned_ = true;
    }
    return SRESULT::NoOp;
  }
  escalated_[ev->subsystem] = deadline;
  HS_TRACE_INFO(kComponent, "log level of {} raised to {} for {} s (reason: {})", ev->subsystem, opts_.log_mode,
                ev->duration_s, ev->reason);
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::tick() {
  const auto real_now = std::chrono::steady_clock::now();  // settle delay is scheduling, not business time
  std::vector<PendingIncident> ready;
  for (auto it = pending_.begin(); it != pending_.end();) {
    if (real_now - it->queued >= opts_.incident_settle) {
      ready.push_back(std::move(*it));
      it = pending_.erase(it);
    } else {
      ++it;
    }
  }
  for (const auto& p : ready) {
    const SRESULT r = build_incident(p);
    if (HS_FAILED(r)) HS_TRACE_ERROR(kComponent, "incident {} failed: {}", p.trigger->hdr.id, r);
  }
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  if (!opts_.checkpoint_file.empty() && now - last_checkpoint_ >= opts_.checkpoint_period) {
    (void)save_checkpoint();  // retried next tick on failure; already traced
  }
  if (escalated_.empty()) return SRESULT::Ok;
  for (auto it = escalated_.begin(); it != escalated_.end();) {
    if (now >= it->second) {
      const SRESULT r = platform_->reset_log_mode(it->first);
      HS_TRACE_INFO(kComponent, "log level of {} reverted: {}", it->first, r);
      it = escalated_.erase(it);
    } else {
      ++it;
    }
  }
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::text(JsonWriter& w, std::string_view v, bool sanitized, bool free_text) const {
  if (!sanitized) return w.value(v);
  std::string clean;
  HS_RETURN_IF_FAILED(free_text ? redactor_.redact_free_text(v, clean) : redactor_.redact(v, clean));
  return w.value(std::string_view(clean));
}

SRESULT DiagnosticsActor::redact_fields(Fields& fields) const {
  for (Field& f : fields) {
    if (f.verbatim || !std::holds_alternative<std::string>(f.value)) continue;
    std::string& s = std::get<std::string>(f.value);
    std::string clean;
    HS_RETURN_IF_FAILED(f.free_text ? redactor_.redact_free_text(s, clean) : redactor_.redact(s, clean));
    s = std::move(clean);
  }
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::write_file(const std::filesystem::path& path, const std::string& data) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(data.data(), static_cast<std::streamsize>(data.size()));
  if (!f.good()) {
    HS_TRACE_ERROR(kComponent, "cannot write bundle {}", path.string());
    return SRESULT::IoError;
  }
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::build_bundle(const Event& trigger, const std::string& symptom, const FrozenRings& rings,
                                       const std::string& capture, SRESULT capture_status, bool sanitized,
                                       std::string& out) {
  std::string_view type;
  HS_RETURN_IF_FAILED(trigger.type_name(type));
  Fields trigger_fields, env;
  HS_RETURN_IF_FAILED(trigger.fields(trigger_fields));
  HS_RETURN_IF_FAILED(platform_->environment(env));
  if (sanitized) {
    HS_RETURN_IF_FAILED(redact_fields(trigger_fields));
    HS_RETURN_IF_FAILED(redact_fields(env));
  }
  std::vector<LogLine> logs;
  HS_RETURN_IF_FAILED(logs_.snapshot(logs));
  std::string_view capture_status_name;
  HS_RETURN_IF_FAILED(to_string(capture_status, capture_status_name));
  std::string frozen_at;
  std::chrono::system_clock::time_point frozen_tp;
  HS_RETURN_IF_FAILED(from_unix_ms(rings.frozen_at_ms, frozen_tp));
  HS_RETURN_IF_FAILED(format_utc_ms(frozen_tp, frozen_at));

  JsonWriter w;
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("schema"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(sanitized ? "ieso.incident.v1.sanitized" : "ieso.incident.v1")));
  HS_RETURN_IF_FAILED(w.key("incident_id"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(trigger.hdr.id)));
  HS_RETURN_IF_FAILED(w.key("endpoint_id"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(trigger.hdr.endpoint_id)));
  HS_RETURN_IF_FAILED(w.key("symptom"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(symptom)));
  HS_RETURN_IF_FAILED(w.key("frozen_at"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(frozen_at)));
  HS_RETURN_IF_FAILED(w.key("trigger"));
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("type"));
  HS_RETURN_IF_FAILED(w.value(type));
  HS_RETURN_IF_FAILED(w.key("fields"));
  HS_RETURN_IF_FAILED(write_fields(w, trigger_fields));
  HS_RETURN_IF_FAILED(w.end_object());
  HS_RETURN_IF_FAILED(w.key("environment"));
  HS_RETURN_IF_FAILED(write_fields(w, env));

  HS_RETURN_IF_FAILED(w.key("rings"));
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("hot_100ms"));
  HS_RETURN_IF_FAILED(w.begin_array());
  for (const auto& s : rings.hot) HS_RETURN_IF_FAILED(write_sample(w, s));
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.key("warm_1s"));
  HS_RETURN_IF_FAILED(w.begin_array());
  for (const auto& s : rings.warm) HS_RETURN_IF_FAILED(write_sample(w, s));
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.key("cold_1min"));
  HS_RETURN_IF_FAILED(w.begin_array());
  for (const auto& a : rings.cold) {
    HS_RETURN_IF_FAILED(w.begin_object());
    HS_RETURN_IF_FAILED(w.key("start_ms"));
    HS_RETURN_IF_FAILED(w.value(a.start_ms));
    HS_RETURN_IF_FAILED(w.key("count"));
    HS_RETURN_IF_FAILED(w.value(static_cast<std::int64_t>(a.count)));
    HS_RETURN_IF_FAILED(w.key("min"));
    HS_RETURN_IF_FAILED(write_sample(w, a.min));
    HS_RETURN_IF_FAILED(w.key("max"));
    HS_RETURN_IF_FAILED(write_sample(w, a.max));
    HS_RETURN_IF_FAILED(w.key("avg"));
    HS_RETURN_IF_FAILED(write_sample(w, a.avg));
    HS_RETURN_IF_FAILED(w.end_object());
  }
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());

  HS_RETURN_IF_FAILED(w.key("recent_logs"));
  HS_RETURN_IF_FAILED(w.begin_array());
  for (const auto& l : logs) {
    HS_RETURN_IF_FAILED(w.begin_object());
    HS_RETURN_IF_FAILED(w.key("ts_ms"));
    HS_RETURN_IF_FAILED(w.value(l.ts_ms));
    HS_RETURN_IF_FAILED(w.key("level"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(l.level)));
    HS_RETURN_IF_FAILED(w.key("subsystem"));
    HS_RETURN_IF_FAILED(text(w, l.subsystem, sanitized, false));
    HS_RETURN_IF_FAILED(w.key("category"));
    HS_RETURN_IF_FAILED(text(w, l.category, sanitized, false));
    HS_RETURN_IF_FAILED(w.key("message"));
    HS_RETURN_IF_FAILED(text(w, l.message, sanitized, true));
    HS_RETURN_IF_FAILED(w.end_object());
  }
  HS_RETURN_IF_FAILED(w.end_array());

  HS_RETURN_IF_FAILED(w.key("deep_capture"));
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("kind"));
  HS_RETURN_IF_FAILED(w.value(std::string_view("sample")));
  HS_RETURN_IF_FAILED(w.key("status"));
  HS_RETURN_IF_FAILED(w.value(capture_status_name));
  HS_RETURN_IF_FAILED(w.key("text"));
  HS_RETURN_IF_FAILED(text(w, capture, sanitized, false));  // stacks: redact paths, never truncate
  HS_RETURN_IF_FAILED(w.end_object());
  HS_RETURN_IF_FAILED(w.end_object());
  return w.str(out);
}

SRESULT DiagnosticsActor::on_incident(std::shared_ptr<const Event> trigger, std::string symptom, std::int64_t pid,
                                      bool want_stacks) {
  PendingIncident p;
  p.trigger = std::move(trigger);
  p.symptom = std::move(symptom);
  p.pid = pid;
  p.want_stacks = want_stacks;
  p.queued = std::chrono::steady_clock::now();
  pending_.push_back(std::move(p));
  return SRESULT::Ok;
}

SRESULT DiagnosticsActor::build_incident(const PendingIncident& p) {
  const Event& trigger = *p.trigger;
  const std::string& symptom = p.symptom;
  const std::int64_t pid = p.pid;
  const bool want_stacks = p.want_stacks;
  std::chrono::system_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_system(now));
  std::int64_t now_ms = 0;
  HS_RETURN_IF_FAILED(to_unix_ms(now, now_ms));
  FrozenRings rings;
  HS_RETURN_IF_FAILED(recorder_->freeze(now_ms, rings));

  std::string capture;
  SRESULT capture_status = SRESULT::NoOp;
  if (want_stacks && pid > 0) {
    capture_status = budget_.try_acquire(trigger.hdr.id);
    if (capture_status == SRESULT::Ok) {
      HS_TRACE_INFO(kComponent, "capturing stacks of pid {} for {} s", pid, opts_.sample_duration.count());
      capture_status = platform_->capture_stacks(pid, opts_.sample_duration, capture);
      if (HS_FAILED(capture_status)) HS_TRACE_WARNING(kComponent, "stack capture failed: {}", capture_status);
    }
  }

  std::string bundle;
  HS_RETURN_IF_FAILED(build_bundle(trigger, symptom, rings, capture, capture_status, false, bundle));
  std::string hash;
  HS_RETURN_IF_FAILED(Sha256::hex(bundle, hash));
  const auto path = opts_.incident_dir / (trigger.hdr.id + ".json");
  HS_RETURN_IF_FAILED(write_file(path, bundle));

  std::string upload;
  HS_RETURN_IF_FAILED(build_bundle(trigger, symptom, rings, capture, capture_status, true, upload));
  std::string upload_hash;
  HS_RETURN_IF_FAILED(Sha256::hex(upload, upload_hash));
  const std::string upload_ref = trigger.hdr.id + ".sanitized.json";
  HS_RETURN_IF_FAILED(write_file(opts_.incident_dir / upload_ref, upload));

  std::shared_ptr<IncidentBundleReady> ready;
  HS_RETURN_IF_FAILED(factory_.make<IncidentBundleReady>(ready));
  ready->incident_id = trigger.hdr.id;
  ready->symptom = symptom;
  ready->bundle_hash = hash;
  ready->bundle_path = path.string();
  ready->upload_ref = upload_ref;
  ready->upload_sha256 = upload_hash;
  HS_TRACE_INFO(kComponent, "incident bundle ready: {} symptom={} bytes={} sha256={}", path.string(), symptom,
                bundle.size(), hash.substr(0, 16));
  return bus_.post(std::move(ready));
}

}  // namespace ieso
