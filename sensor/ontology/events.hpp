/**
 * @file events.hpp
 * @brief The events ontology (DESIGN.md §7): every event type of the sensor, in one header.
 * @details Sections: (1) primitives (class, header, payload fields, Event base, traits macro);
 *          (2) concrete events by category; (3) CloudEventSanitized, the only type that may leave the Mac;
 *          (4) AllEvents, used to subscribe the PII filter to exactly the egress-eligible types.
 *          Events are immutable once posted (the bus accepts std::shared_ptr<const Event> only).
 *
 *  | Event                          | Class    | Overflow   | Egress |
 *  |--------------------------------|----------|------------|--------|
 *  | DeviceBootstrapped             | Control  | NeverDrop  | no     |
 *  | CertificateAssigned            | Control  | NeverDrop  | no     |
 *  | ConfigRefreshTriggered         | Control  | NeverDrop  | no     |
 *  | ConfigurationUpdated           | Control  | NeverDrop  | no     |
 *  | TargetLifecycle                | Control  | NeverDrop  | yes    |
 *  | TelemetrySnapshotCaptured      | Routine  | DropOldest | yes    |
 *  | ResourceSampled                | Routine  | DropOldest | no     |
 *  | ResponsivenessProbed           | Routine  | DropOldest | no     |
 *  | LogRecordObserved              | Routine  | Sample     | yes    |
 *  | UserVisibleErrorObserved       | Incident | NeverDrop  | yes    |
 *  | ProcessHangDetected            | Incident | NeverDrop  | yes    |
 *  | ProcessCrashDetected           | Incident | NeverDrop  | yes    |
 *  | ResourceAnomalyDetected        | Incident | NeverDrop  | yes    |
 *  | DiagnosticEscalationRequested  | Control  | NeverDrop  | no     |
 *  | IncidentBundleReady            | Incident | NeverDrop  | yes    |
 *  | ProbeRequested                 | Control  | NeverDrop  | no     |
 *  | ProbeResultReady               | Incident | NeverDrop  | yes    |
 *  | SpooledEvent                   | Control  | NeverDrop  | no     |
 *  | SpoolStorageUpdated            | Routine  | DropOldest | no     |
 *  | NetworkStatusChanged           | Control  | NeverDrop  | no     |
 *  | TelemetryDelivered             | Routine  | DropOldest | no     |
 *  | CloudEventSanitized            | (source) | (source)   | sink   |
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "ieso/core/bounded_queue.hpp"
#include "ieso/core/sample.hpp"
#include "ieso/core/sresult.hpp"

// =====================================================================================================================
// 1. Primitives
// =====================================================================================================================

namespace ieso {

/// @brief Event class; selects the mailbox lane and default overflow policy (DESIGN.md §7).
enum class EventClass : std::uint8_t {
  Control = 0,   ///< Bootstrap/config/transport control; never dropped.
  Incident = 1,  ///< Anomalies and diagnostics; never dropped.
  Routine = 2,   ///< Telemetry; may be sampled or dropped (counted).
};

/// @brief Common metadata on every event; filled by EventFactory.
struct EventHeader {
  std::string id;                                ///< UUIDv7; stable across retries for dedupe.
  std::string endpoint_id;                       ///< Opaque endpoint identity (not PII).
  std::chrono::system_clock::time_point ts{};    ///< Creation time.
  EventClass cls = EventClass::Routine;          ///< Lane selection.
  OverflowPolicy overflow = OverflowPolicy::DropOldest;  ///< Behavior when the lane is full.
  bool egress = false;                           ///< Seen by the PII filter and may leave the Mac.
  bool spillable = false;                        ///< May be spilled to the spool on overflow (sanitized only).
};

/// @brief One payload value.
using FieldValue = std::variant<std::monostate, bool, std::int64_t, double, std::string>;

/// @brief One named payload value; free_text marks user/app text that gets stricter redaction.
struct Field {
  std::string key;          ///< JSON key.
  FieldValue value;         ///< Value.
  bool free_text = false;   ///< Truncated and redacted as untrusted text.
  bool verbatim = false;    ///< Sensor-generated identifier (hash, own file ref): never redacted.
};

/// @brief Flat payload of an event.
using Fields = std::vector<Field>;

/**
 * @brief Polymorphic base of all events.
 * @note Derived types declare their traits with IESO_EVENT_TRAITS.
 */
class Event {
 public:
  virtual ~Event() = default;

  /**
   * @brief Stable type name, e.g. "ProcessCrashDetected".
   * @param[out] out Static string.
   * @return SRESULT::Ok.
   */
  virtual SRESULT type_name(std::string_view& out) const = 0;

  /**
   * @brief Exposes the payload as flat fields (header excluded).
   * @param[out] out Appended fields.
   * @return SRESULT::Ok.
   */
  virtual SRESULT fields(Fields& out) const = 0;

  EventHeader hdr;  ///< Metadata; set by EventFactory before posting.
};

/// @brief Compile-time list of types, used to iterate all event types.
template <class... T>
struct TypeList {};

/**
 * @brief True for events the PII filter must process before egress.
 * @tparam T Concrete event type.
 */
template <class T>
inline constexpr bool is_egress_eligible_v = std::is_base_of_v<Event, T> && T::kEgress;

}  // namespace ieso

/**
 * @brief Declares routing traits and type_name() for a concrete event.
 * @param Name Class name.
 * @param Cls  EventClass enumerator.
 * @param Ovf  OverflowPolicy enumerator.
 * @param Egr  true if egress-eligible.
 */
#define IESO_EVENT_TRAITS(Name, Cls, Ovf, Egr)                                    \
  static constexpr std::string_view kTypeName = #Name;                              \
  static constexpr ::ieso::EventClass kClass = ::ieso::EventClass::Cls;         \
  static constexpr ::ieso::OverflowPolicy kOverflow = ::ieso::OverflowPolicy::Ovf; \
  static constexpr bool kEgress = Egr;                                              \
  static constexpr bool kSpillable = false;                                         \
  ::ieso::SRESULT type_name(std::string_view& out) const override { \
    out = kTypeName;                                                                \
    return ::ieso::SRESULT::Ok;                                                   \
  }

// =====================================================================================================================
// 2. Concrete events
// =====================================================================================================================

namespace ieso {

class PiiFilter;
class Spool;
class CloudEventSanitized;

// ---------------- Bootstrap ----------------

/// @brief Device identity established at first run.
struct DeviceBootstrapped final : Event {
  IESO_EVENT_TRAITS(DeviceBootstrapped, Control, NeverDrop, false)
  std::string hardware_fingerprint;  ///< Hash of hardware identifiers.
  std::string os_build;              ///< e.g. "25G72".
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Endpoint certificate issued and stored in the Keychain.
struct CertificateAssigned final : Event {
  IESO_EVENT_TRAITS(CertificateAssigned, Control, NeverDrop, false)
  std::string keychain_ref;     ///< Keychain item reference.
  std::int64_t expiry_ms = 0;   ///< Expiry, Unix ms.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

// ---------------- Configuration ----------------

/// @brief Request to fetch policy (timer or push).
struct ConfigRefreshTriggered final : Event {
  IESO_EVENT_TRAITS(ConfigRefreshTriggered, Control, NeverDrop, false)
  std::string source;  ///< "timer" or "push".
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief New policy applied at runtime (FR-7).
struct ConfigurationUpdated final : Event {
  IESO_EVENT_TRAITS(ConfigurationUpdated, Control, NeverDrop, false)
  std::int64_t policy_version = 0;        ///< Monotonic policy version.
  std::vector<std::string> changed_keys;  ///< Keys whose values changed.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

// ---------------- Telemetry ----------------

/// @brief Target app launched or exited.
struct TargetLifecycle final : Event {
  IESO_EVENT_TRAITS(TargetLifecycle, Control, NeverDrop, true)
  std::string phase;            ///< "launch" or "exit".
  std::int64_t pid = 0;         ///< Process id.
  std::string bundle_id;        ///< App bundle identifier.
  std::string version;          ///< App version string.
  std::int64_t exit_status = 0; ///< Valid when phase == "exit".
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Periodic resource sample of the target.
struct TelemetrySnapshotCaptured final : Event {
  IESO_EVENT_TRAITS(TelemetrySnapshotCaptured, Routine, DropOldest, true)
  std::int64_t pid = 0;   ///< Process id.
  ResourceSample sample;  ///< Metrics.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief High-rate (100 ms) internal sample feeding the flight recorder's hot ring. Never leaves the Mac.
struct ResourceSampled final : Event {
  IESO_EVENT_TRAITS(ResourceSampled, Routine, DropOldest, false)
  std::int64_t pid = 0;   ///< Process id.
  ResourceSample sample;  ///< Metrics.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Result of one Accessibility responsiveness probe (DESIGN.md §9.1).
struct ResponsivenessProbed final : Event {
  IESO_EVENT_TRAITS(ResponsivenessProbed, Routine, DropOldest, false)
  std::int64_t pid = 0;         ///< Probed process.
  std::int64_t latency_ms = 0;  ///< Time the AX request took.
  bool timed_out = false;       ///< Main run loop did not answer within the messaging timeout.
  bool permitted = true;        ///< False if the sensor lacks the Accessibility permission.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief One unified-log record of the app or a selected Apple subsystem.
struct LogRecordObserved final : Event {
  IESO_EVENT_TRAITS(LogRecordObserved, Routine, Sample, true)
  std::int64_t pid = 0;   ///< Emitting process.
  std::string subsystem;  ///< os_log subsystem.
  std::string category;   ///< os_log category.
  std::string level;      ///< "default", "info", "debug", "error", "fault".
  std::string message;    ///< Message text (free text).
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

// ---------------- Anomaly ----------------

/// @brief An alert or sheet appeared in the app (FR-12).
struct UserVisibleErrorObserved final : Event {
  IESO_EVENT_TRAITS(UserVisibleErrorObserved, Incident, NeverDrop, true)
  std::int64_t pid = 0;      ///< Process id.
  std::string window_title;  ///< Window title (free text).
  std::string dialog_text;   ///< Dialog text (free text).
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Main thread stopped servicing AX requests (DESIGN.md §9.1).
struct ProcessHangDetected final : Event {
  IESO_EVENT_TRAITS(ProcessHangDetected, Incident, NeverDrop, true)
  std::int64_t pid = 0;               ///< Process id.
  std::int64_t probe_latency_ms = 0;  ///< Last AX probe latency.
  std::int64_t duration_ms = 0;       ///< Hang duration so far.
  std::string sample_ref;             ///< Reference to captured stacks, if any.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Target crashed; signature from the .ips report (DESIGN.md §9.2).
struct ProcessCrashDetected final : Event {
  IESO_EVENT_TRAITS(ProcessCrashDetected, Incident, NeverDrop, true)
  std::int64_t pid = 0;            ///< Process id.
  std::string exception_type;      ///< e.g. "EXC_BAD_ACCESS".
  std::string signal;              ///< e.g. "SIGSEGV".
  std::string termination_reason;  ///< From the report.
  std::string faulting_module;     ///< Image of the faulting frame.
  std::int64_t offset = 0;         ///< Offset within faulting_module.
  std::string report_path;         ///< Path of the .ips (contains user name; redacted).
  std::string exception_subtype;   ///< e.g. "KERN_INVALID_ADDRESS at 0x0000000000000008".
  std::string exception_codes;     ///< Mach exception codes as reported.
  std::string app_version;         ///< Crashed app's CFBundleShortVersionString.
  std::string crashed_thread;      ///< e.g. "0 (com.apple.main-thread)".
  std::string backtrace;           ///< Crashed thread, one frame per line: "0 DemoApp +0x8875 Symbol + 949".
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Metric out of bounds versus threshold/baseline.
struct ResourceAnomalyDetected final : Event {
  IESO_EVENT_TRAITS(ResourceAnomalyDetected, Incident, NeverDrop, true)
  std::string metric;     ///< e.g. "rss_bytes".
  double value = 0.0;     ///< Observed value.
  double baseline = 0.0;  ///< Expected value.
  double trend = 0.0;     ///< Slope per minute.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

// ---------------- Diagnostics ----------------

/// @brief Raise the app's log verbosity for a while (FR-11).
struct DiagnosticEscalationRequested final : Event {
  IESO_EVENT_TRAITS(DiagnosticEscalationRequested, Control, NeverDrop, false)
  std::string reason;            ///< Triggering anomaly.
  std::string subsystem;         ///< os_log subsystem to escalate (the app's bundle id).
  std::string verbosity_level;   ///< e.g. "debug".
  std::int64_t duration_s = 0;   ///< Auto-revert after this many seconds.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Incident bundle packaged and signed (FR-4).
struct IncidentBundleReady final : Event {
  IESO_EVENT_TRAITS(IncidentBundleReady, Incident, NeverDrop, true)
  std::string incident_id;  ///< Incident identity.
  std::string symptom;      ///< Symptom class.
  std::string bundle_hash;  ///< SHA-256 of the bundle.
  std::string bundle_path;  ///< Local path of the raw bundle (redacted on egress; never uploaded).
  std::string upload_ref;     ///< File name (no directory) of the sanitized bundle copy to upload.
  std::string upload_sha256;  ///< SHA-256 of the sanitized copy (verified by the control plane).
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

// ---------------- Investigation ----------------

/// @brief Backend asked for an allowlisted probe (FR-14).
struct ProbeRequested final : Event {
  IESO_EVENT_TRAITS(ProbeRequested, Control, NeverDrop, false)
  std::string probe_id;          ///< Allowlist ID, never a command.
  std::string request_id;        ///< Correlation id (replays are refused).
  std::string incident_id;       ///< Incident the probe investigates (budget scope).
  std::string endpoint;          ///< Target endpoint; must be this one.
  std::int64_t issued_at = 0;    ///< Unix ms.
  std::int64_t expires_at = 0;   ///< Unix ms; expired requests are refused.
  std::string signature;         ///< base64 DER ECDSA P-256 over the canonical request (control-plane key).
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Probe finished.
struct ProbeResultReady final : Event {
  IESO_EVENT_TRAITS(ProbeResultReady, Incident, NeverDrop, true)
  std::string probe_id;          ///< Allowlist ID.
  std::string request_id;        ///< Correlation id.
  std::string incident_id;       ///< Incident under investigation.
  std::string output;            ///< Probe output (redacted, capped at 8 KB) or "refused: <reason>".
  std::int64_t exit_status = 0;  ///< Exit status; -1 = refused by the endpoint's policy.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

// ---------------- Storage / transport ----------------

/// @brief Cloud Client could not send; envelope goes to the spool.
struct SpooledEvent final : Event {
  IESO_EVENT_TRAITS(SpooledEvent, Control, NeverDrop, false)
  std::shared_ptr<const CloudEventSanitized> envelope;  ///< Already sanitized.
  std::uint32_t attempts = 0;                           ///< Send attempts so far.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Spool size report (self-telemetry).
struct SpoolStorageUpdated final : Event {
  IESO_EVENT_TRAITS(SpoolStorageUpdated, Routine, DropOldest, false)
  std::uint64_t bytes = 0;        ///< Spool size on disk.
  std::uint64_t count = 0;        ///< Records.
  std::int64_t oldest_age_s = 0;  ///< Age of oldest record.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Backend reachability changed.
struct NetworkStatusChanged final : Event {
  IESO_EVENT_TRAITS(NetworkStatusChanged, Control, NeverDrop, false)
  bool online = false;  ///< True if the backend is reachable.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

/// @brief Backend acknowledged these event ids.
struct TelemetryDelivered final : Event {
  IESO_EVENT_TRAITS(TelemetryDelivered, Routine, DropOldest, false)
  std::vector<std::string> ids;  ///< Acknowledged ids.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};

// =====================================================================================================================
// 3. Egress envelope
// =====================================================================================================================

/**
 * @brief Sanitized CloudEvents 1.0 envelope.
 * @note hdr.id equals the source event id, so retries keep the same identity for backend dedupe.
 * @warning Not egress-eligible itself: the PII filter never sees its own output.
 */
class CloudEventSanitized final : public Event {
 public:
  /// @brief Passkey; constructible only by the friends below.
  class Key {
    friend class PiiFilter;
    friend class Spool;
    Key() = default;
  };

  static constexpr std::string_view kTypeName = "CloudEventSanitized";
  static constexpr EventClass kClass = EventClass::Incident;            ///< Default; overwritten from source.
  static constexpr OverflowPolicy kOverflow = OverflowPolicy::NeverDrop;  ///< Default; overwritten from source.
  static constexpr bool kEgress = false;
  static constexpr bool kSpillable = true;

  /**
   * @brief Builds an envelope.
   * @param[in] key Passkey proving the caller is PiiFilter or Spool.
   * @param[in] source CloudEvents "source" URI.
   * @param[in] type CloudEvents "type", e.g. "com.ieso.ProcessCrashDetected".
   * @param[in] data_json Redacted payload as a JSON object.
   */
  CloudEventSanitized(Key key, std::string source, std::string type, std::string data_json);

  /// @copydoc Event::type_name
  SRESULT type_name(std::string_view& out) const override;
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;

  /**
   * @brief Serializes the full CloudEvents 1.0 structured-mode JSON.
   * @param[out] out JSON with specversion, id, source, type, time, datacontenttype, data.
   * @return SRESULT::Ok.
   */
  SRESULT to_json(std::string& out) const;

  const std::string source;     ///< CloudEvents source.
  const std::string type;       ///< CloudEvents type.
  const std::string data_json;  ///< Sanitized data object.
};

// =====================================================================================================================
// 4. Type list
// =====================================================================================================================

/// @brief Every concrete event type except CloudEventSanitized (which only the filter emits).
using AllEvents =
    TypeList<DeviceBootstrapped, CertificateAssigned, ConfigRefreshTriggered, ConfigurationUpdated, TargetLifecycle,
             TelemetrySnapshotCaptured, ResourceSampled, ResponsivenessProbed, LogRecordObserved, UserVisibleErrorObserved, ProcessHangDetected,
             ProcessCrashDetected, ResourceAnomalyDetected, DiagnosticEscalationRequested, IncidentBundleReady,
             ProbeRequested, ProbeResultReady, SpooledEvent, SpoolStorageUpdated, NetworkStatusChanged,
             TelemetryDelivered>;

}  // namespace ieso
