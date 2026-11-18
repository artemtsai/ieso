/**
 * @file events.cpp
 * @brief Events ontology implementation: payload field mapping for every event and the CloudEvents envelope.
 */
#include "ontology/events.hpp"

#include <fmt/format.h>

#include "ieso/core/json.hpp"
#include "ieso/core/time_util.hpp"

namespace ieso {
namespace {

/**
 * @brief Appends a string field.
 * @param[in,out] out Field list.
 * @param[in] k Key.
 * @param[in] v Value.
 * @param[in] free_text True for untrusted user/app text.
 * @return SRESULT::Ok.
 */
SRESULT add(Fields& out, std::string_view k, const std::string& v, bool free_text = false) {
  out.push_back({std::string(k), FieldValue{v}, free_text});
  return SRESULT::Ok;
}

/**
 * @brief Appends a sensor-generated identifier that must not be redacted (e.g. a SHA-256 hex digest).
 * @param[in,out] out Field list.
 * @param[in] k Key.
 * @param[in] v Value.
 * @return SRESULT::Ok.
 */
SRESULT add_verbatim(Fields& out, std::string_view k, const std::string& v) {
  out.push_back({std::string(k), FieldValue{v}, false, true});
  return SRESULT::Ok;
}

/// @brief Appends an integer field. @param[in,out] out Fields. @param[in] k Key. @param[in] v Value. @return Ok.
SRESULT add(Fields& out, std::string_view k, std::int64_t v) {
  out.push_back({std::string(k), FieldValue{v}, false});
  return SRESULT::Ok;
}

/// @brief Appends an unsigned field (saturated to int64). @param[in,out] out Fields. @param[in] k Key. @param[in] v Value. @return Ok.
SRESULT add_u(Fields& out, std::string_view k, std::uint64_t v) {
  const auto s = v > static_cast<std::uint64_t>(INT64_MAX) ? INT64_MAX : static_cast<std::int64_t>(v);
  return add(out, k, s);
}

/// @brief Appends a double field. @param[in,out] out Fields. @param[in] k Key. @param[in] v Value. @return Ok.
SRESULT add_d(Fields& out, std::string_view k, double v) {
  out.push_back({std::string(k), FieldValue{v}, false});
  return SRESULT::Ok;
}

/// @brief Appends a bool field. @param[in,out] out Fields. @param[in] k Key. @param[in] v Value. @return Ok.
SRESULT add_b(Fields& out, std::string_view k, bool v) {
  out.push_back({std::string(k), FieldValue{v}, false});
  return SRESULT::Ok;
}

/**
 * @brief Joins strings with commas.
 * @param[in] items Strings.
 * @param[out] out Joined text.
 * @return SRESULT::Ok.
 */
SRESULT join(const std::vector<std::string>& items, std::string& out) {
  out.clear();
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i != 0) out.push_back(',');
    out += items[i];
  }
  return SRESULT::Ok;
}

}  // namespace

SRESULT DeviceBootstrapped::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "hardware_fingerprint", hardware_fingerprint));
  return add(out, "os_build", os_build);
}

SRESULT CertificateAssigned::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "keychain_ref", keychain_ref));
  return add(out, "expiry_ms", expiry_ms);
}

SRESULT ConfigRefreshTriggered::fields(Fields& out) const { return add(out, "source", source); }

SRESULT ConfigurationUpdated::fields(Fields& out) const {
  std::string keys;
  HS_RETURN_IF_FAILED(join(changed_keys, keys));
  HS_RETURN_IF_FAILED(add(out, "policy_version", policy_version));
  return add(out, "changed_keys", keys);
}

SRESULT TargetLifecycle::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "phase", phase));
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "bundle_id", bundle_id));
  HS_RETURN_IF_FAILED(add(out, "version", version));
  return add(out, "exit_status", exit_status);
}

SRESULT TelemetrySnapshotCaptured::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "sample_ts_ms", sample.ts_ms));
  HS_RETURN_IF_FAILED(add_d(out, "cpu_pct", sample.cpu_pct));
  HS_RETURN_IF_FAILED(add_u(out, "rss_bytes", sample.rss_bytes));
  HS_RETURN_IF_FAILED(add(out, "threads", static_cast<std::int64_t>(sample.threads)));
  HS_RETURN_IF_FAILED(add(out, "fds", static_cast<std::int64_t>(sample.fds)));
  HS_RETURN_IF_FAILED(add_u(out, "disk_free_bytes", sample.disk_free_bytes));
  return add(out, "thermal_level", static_cast<std::int64_t>(sample.thermal_level));
}

SRESULT ResourceSampled::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "sample_ts_ms", sample.ts_ms));
  HS_RETURN_IF_FAILED(add_d(out, "cpu_pct", sample.cpu_pct));
  return add_u(out, "rss_bytes", sample.rss_bytes);
}

SRESULT ResponsivenessProbed::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "latency_ms", latency_ms));
  HS_RETURN_IF_FAILED(add_b(out, "timed_out", timed_out));
  return add_b(out, "permitted", permitted);
}

SRESULT LogRecordObserved::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "subsystem", subsystem));
  HS_RETURN_IF_FAILED(add(out, "category", category));
  HS_RETURN_IF_FAILED(add(out, "level", level));
  return add(out, "message", message, true);
}

SRESULT UserVisibleErrorObserved::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "window_title", window_title, true));
  return add(out, "dialog_text", dialog_text, true);
}

SRESULT ProcessHangDetected::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "probe_latency_ms", probe_latency_ms));
  HS_RETURN_IF_FAILED(add(out, "duration_ms", duration_ms));
  return add(out, "sample_ref", sample_ref);
}

SRESULT ProcessCrashDetected::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "pid", pid));
  HS_RETURN_IF_FAILED(add(out, "exception_type", exception_type));
  HS_RETURN_IF_FAILED(add(out, "signal", signal));
  HS_RETURN_IF_FAILED(add(out, "termination_reason", termination_reason, true));
  HS_RETURN_IF_FAILED(add(out, "faulting_module", faulting_module));
  HS_RETURN_IF_FAILED(add(out, "offset", offset));
  // Fleet-groupable signature without symbols: module + offset + exception (DESIGN.md §9.2).
  // No report (macOS throttled it): the exit signal is all we know, and the signature says so.
  HS_RETURN_IF_FAILED(add(out, "signature", report_path.empty()
                                                ? fmt::format("{} {} (no crash report)", faulting_module, signal)
                                                : fmt::format("{}+0x{:x} {}", faulting_module, offset, exception_type)));
  HS_RETURN_IF_FAILED(add(out, "report_path", report_path));
  HS_RETURN_IF_FAILED(add(out, "exception_subtype", exception_subtype));
  HS_RETURN_IF_FAILED(add(out, "exception_codes", exception_codes));
  HS_RETURN_IF_FAILED(add(out, "app_version", app_version));
  HS_RETURN_IF_FAILED(add(out, "crashed_thread", crashed_thread));
  // Redacted like every field, but not free text: up to kMaxCrashFrames frames must not be cut at 512 chars.
  return add(out, "backtrace", backtrace);
}

SRESULT ResourceAnomalyDetected::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "metric", metric));
  HS_RETURN_IF_FAILED(add_d(out, "value", value));
  HS_RETURN_IF_FAILED(add_d(out, "baseline", baseline));
  return add_d(out, "trend", trend);
}

SRESULT DiagnosticEscalationRequested::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "reason", reason));
  HS_RETURN_IF_FAILED(add(out, "subsystem", subsystem));
  HS_RETURN_IF_FAILED(add(out, "verbosity_level", verbosity_level));
  return add(out, "duration_s", duration_s);
}

SRESULT IncidentBundleReady::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "incident_id", incident_id));
  HS_RETURN_IF_FAILED(add(out, "symptom", symptom));
  HS_RETURN_IF_FAILED(add_verbatim(out, "bundle_hash", bundle_hash));
  HS_RETURN_IF_FAILED(add(out, "bundle_path", bundle_path));  // contains the user name: redacted
  HS_RETURN_IF_FAILED(add_verbatim(out, "upload_ref", upload_ref));
  return add_verbatim(out, "upload_sha256", upload_sha256);
}

SRESULT ProbeRequested::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "probe_id", probe_id));
  HS_RETURN_IF_FAILED(add(out, "request_id", request_id));
  HS_RETURN_IF_FAILED(add(out, "incident_id", incident_id));
  HS_RETURN_IF_FAILED(add(out, "endpoint", endpoint));
  HS_RETURN_IF_FAILED(add(out, "issued_at", issued_at));
  return add(out, "expires_at", expires_at);  // signature deliberately not exposed
}

SRESULT ProbeResultReady::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add_verbatim(out, "probe_id", probe_id));
  HS_RETURN_IF_FAILED(add_verbatim(out, "request_id", request_id));
  HS_RETURN_IF_FAILED(add_verbatim(out, "incident_id", incident_id));
  HS_RETURN_IF_FAILED(add(out, "output", output));  // redacted, not truncated: the runner already caps it
  return add(out, "exit_status", exit_status);
}

SRESULT SpooledEvent::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "envelope_id", envelope ? envelope->hdr.id : std::string()));
  return add(out, "attempts", static_cast<std::int64_t>(attempts));
}

SRESULT SpoolStorageUpdated::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add_u(out, "bytes", bytes));
  HS_RETURN_IF_FAILED(add_u(out, "count", count));
  return add(out, "oldest_age_s", oldest_age_s);
}

SRESULT NetworkStatusChanged::fields(Fields& out) const { return add_b(out, "online", online); }

SRESULT TelemetryDelivered::fields(Fields& out) const {
  std::string ids_joined;
  HS_RETURN_IF_FAILED(join(ids, ids_joined));
  return add(out, "ids", ids_joined);
}

// ---------------- CloudEventSanitized ----------------

CloudEventSanitized::CloudEventSanitized(Key /*key*/, std::string source_in, std::string type_in,
                                         std::string data_json_in)
    : source(std::move(source_in)), type(std::move(type_in)), data_json(std::move(data_json_in)) {}

SRESULT CloudEventSanitized::type_name(std::string_view& out) const {
  out = kTypeName;
  return SRESULT::Ok;
}

SRESULT CloudEventSanitized::fields(Fields& out) const {
  HS_RETURN_IF_FAILED(add(out, "source", source));
  return add(out, "type", type);
}

SRESULT CloudEventSanitized::to_json(std::string& out) const {
  std::string time;
  HS_RETURN_IF_FAILED(format_utc_ms(hdr.ts, time));
  JsonWriter w;
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("specversion"));
  HS_RETURN_IF_FAILED(w.value(std::string_view("1.0")));
  HS_RETURN_IF_FAILED(w.key("id"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(hdr.id)));
  HS_RETURN_IF_FAILED(w.key("source"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(source)));
  HS_RETURN_IF_FAILED(w.key("type"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(type)));
  HS_RETURN_IF_FAILED(w.key("time"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(time)));
  HS_RETURN_IF_FAILED(w.key("datacontenttype"));
  HS_RETURN_IF_FAILED(w.value(std::string_view("application/json")));
  HS_RETURN_IF_FAILED(w.key("iesoclass"));
  HS_RETURN_IF_FAILED(w.value(static_cast<std::int64_t>(hdr.cls)));
  HS_RETURN_IF_FAILED(w.key("data"));
  HS_RETURN_IF_FAILED(w.raw(data_json));
  HS_RETURN_IF_FAILED(w.end_object());
  return w.str(out);
}

}  // namespace ieso
