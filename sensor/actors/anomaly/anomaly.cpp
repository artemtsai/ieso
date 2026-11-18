/**
 * @file anomaly.cpp
 * @brief AnomalyActor implementation.
 */
#include "anomaly/anomaly.hpp"

#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "anomaly";

/**
 * @brief Least-squares slope of (ts_ms, value) in units per minute.
 * @param[in] pts Samples (>= 2, distinct timestamps).
 * @param[out] out Slope per minute (0 if degenerate).
 * @return SRESULT::Ok.
 */
SRESULT slope_per_min(const std::deque<std::pair<std::int64_t, std::uint64_t>>& pts, double& out) {
  out = 0;
  if (pts.size() < 2) return SRESULT::Ok;
  const double t0 = static_cast<double>(pts.front().first);
  double sx = 0, sy = 0, sxx = 0, sxy = 0;
  for (const auto& [ts, v] : pts) {
    const double x = static_cast<double>(ts) - t0;
    const double y = static_cast<double>(v);
    sx += x;
    sy += y;
    sxx += x * x;
    sxy += x * y;
  }
  const double n = static_cast<double>(pts.size());
  const double den = n * sxx - sx * sx;
  if (den <= 0) return SRESULT::Ok;
  out = (n * sxy - sx * sy) / den * 60000.0;  // per ms -> per minute
  return SRESULT::Ok;
}
}  // namespace

AnomalyActor::AnomalyActor(EventBus& bus, EventFactory& factory, const IClock& clock, AnomalyOptions opts)
    : Actor("anomaly"), bus_(bus), factory_(factory), clock_(clock), opts_(opts) {}

SRESULT AnomalyActor::on_start(ActorContext& ctx) {
  HS_RETURN_IF_FAILED(subscribe<ResponsivenessProbed>(ctx.bus, [this](const auto& e) { return on_probe(e); }));
  HS_RETURN_IF_FAILED(subscribe<TelemetrySnapshotCaptured>(ctx.bus, [this](const auto& e) { return on_snapshot(e); }));
  HS_RETURN_IF_FAILED(subscribe<ProcessCrashDetected>(ctx.bus, [this](const auto& e) { return on_crash(e); }));
  return subscribe<TargetLifecycle>(ctx.bus, [this](const auto& e) { return on_lifecycle(e); });
}

SRESULT AnomalyActor::on_lifecycle(const std::shared_ptr<const TargetLifecycle>& ev) {
  pid_ = ev->phase == "launch" ? ev->pid : 0;
  if (!ev->bundle_id.empty()) subsystem_ = ev->bundle_id;
  timeouts_ = 0;
  hang_reported_ = false;
  rss_window_.clear();
  return SRESULT::Ok;
}

SRESULT AnomalyActor::escalate(const std::string& reason) {
  if (subsystem_.empty()) return SRESULT::NoOp;  // unknown vendor subsystem: Apple subsystems + deep capture only
  std::shared_ptr<DiagnosticEscalationRequested> esc;
  HS_RETURN_IF_FAILED(factory_.make<DiagnosticEscalationRequested>(esc));
  esc->reason = reason;
  esc->subsystem = subsystem_;
  esc->verbosity_level = "debug";
  esc->duration_s = opts_.escalation_duration_s;
  return bus_.post(std::move(esc));
}

SRESULT AnomalyActor::on_probe(const std::shared_ptr<const ResponsivenessProbed>& ev) {
  if (!ev->permitted) {
    if (!permission_warned_) {
      HS_TRACE_WARNING(kComponent, "AX probe not permitted: grant Accessibility to the sensor; hang detection is off");
      permission_warned_ = true;
    }
    return SRESULT::NoOp;
  }
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  if (!ev->timed_out) {
    if (hang_reported_) {
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - hang_start_).count();
      HS_TRACE_INFO(kComponent, "pid {} responsive again after ~{} ms", ev->pid, ms);
    }
    timeouts_ = 0;
    hang_reported_ = false;
    return SRESULT::Ok;
  }
  if (timeouts_++ == 0) hang_start_ = now - std::chrono::milliseconds(ev->latency_ms);
  HS_TRACE_DEBUG(kComponent, "pid {} probe timeout {}/{}", ev->pid, timeouts_, opts_.hang_consecutive_timeouts);
  if (hang_reported_ || timeouts_ < opts_.hang_consecutive_timeouts) return SRESULT::Ok;

  std::shared_ptr<ProcessHangDetected> hang;
  HS_RETURN_IF_FAILED(factory_.make<ProcessHangDetected>(hang));
  hang->pid = ev->pid;
  hang->probe_latency_ms = ev->latency_ms;
  hang->duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - hang_start_).count();
  hang_reported_ = true;
  HS_TRACE_WARNING(kComponent, "HANG detected: pid {} unresponsive for {} ms ({} probe timeouts)", hang->pid,
                   hang->duration_ms, timeouts_);
  HS_RETURN_IF_FAILED(bus_.post(std::move(hang)));
  return escalate("hang");
}

SRESULT AnomalyActor::fire(const std::string& metric, double value, double baseline, double trend) {
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  const auto it = last_fired_.find(metric);
  if (it != last_fired_.end() && now - it->second < opts_.refire_interval) return SRESULT::NoOp;
  last_fired_[metric] = now;
  std::shared_ptr<ResourceAnomalyDetected> a;
  HS_RETURN_IF_FAILED(factory_.make<ResourceAnomalyDetected>(a));
  a->metric = metric;
  a->value = value;
  a->baseline = baseline;
  a->trend = trend;
  HS_TRACE_WARNING(kComponent, "RESOURCE anomaly {}: value={} baseline={} trend/min={}", metric, value, baseline,
                   trend);
  HS_RETURN_IF_FAILED(bus_.post(std::move(a)));
  return escalate(metric);
}

SRESULT AnomalyActor::on_snapshot(const std::shared_ptr<const TelemetrySnapshotCaptured>& ev) {
  const ResourceSample& s = ev->sample;
  rss_window_.emplace_back(s.ts_ms, s.rss_bytes);
  const std::int64_t window_ms = opts_.leak_window.count();
  while (!rss_window_.empty() && s.ts_ms - rss_window_.front().first > window_ms) rss_window_.pop_front();

  const std::int64_t span = rss_window_.back().first - rss_window_.front().first;
  if (rss_window_.size() >= 5 && span >= window_ms * 8 / 10) {
    double slope = 0;
    HS_RETURN_IF_FAILED(slope_per_min(rss_window_, slope));
    if (slope > opts_.leak_slope_bytes_per_min) {
      (void)fire("rss_growth", static_cast<double>(s.rss_bytes), static_cast<double>(rss_window_.front().second),
                 slope);  // NoOp when rate-limited
    }
  }
  if (s.rss_bytes > opts_.rss_limit_bytes) {
    (void)fire("rss_bytes", static_cast<double>(s.rss_bytes), static_cast<double>(opts_.rss_limit_bytes), 0);
  }
  if (s.fds > opts_.fd_limit) {
    (void)fire("fds", s.fds, opts_.fd_limit, 0);
  }
  if (s.disk_free_bytes != 0 && s.disk_free_bytes < opts_.disk_free_min_bytes) {
    (void)fire("disk_free_bytes", static_cast<double>(s.disk_free_bytes),
               static_cast<double>(opts_.disk_free_min_bytes), 0);
  }
  return SRESULT::Ok;
}

SRESULT AnomalyActor::on_crash(const std::shared_ptr<const ProcessCrashDetected>& /*ev*/) {
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  crashes_.push_back(now);
  while (!crashes_.empty() && now - crashes_.front() > opts_.crash_loop_window) crashes_.pop_front();
  HS_RETURN_IF_FAILED(escalate("crash"));
  if (crashes_.size() >= opts_.crash_loop_count) {
    (void)fire("crash_loop", static_cast<double>(crashes_.size()), 0, 0);  // NoOp when rate-limited
  }
  return SRESULT::Ok;
}

}  // namespace ieso
