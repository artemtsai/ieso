/**
 * @file diagnostics.hpp
 * @brief Diagnostics actor: flight recorder, budgeted deep capture, verbosity escalation, incident bundles.
 * @details DESIGN.md §8, §9.3–9.5, FR-2, FR-4, FR-11, NFR-4. It only captures; judging is the Anomaly actor's job.
 *          OS-specific work goes through IDiagnosticsPlatform so this logic is portable and unit-tested.
 * @note Two files per incident: `<id>.json` holds raw local evidence and never leaves the Mac;
 *       `<id>.sanitized.json` has every string passed through the Redactor and is what the Cloud Client uploads
 *       (IncidentBundleReady.upload_ref / upload_sha256).
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <deque>
#include <map>
#include <memory>
#include <string>

#include "ieso/core/actor.hpp"
#include "ieso/core/capture_budget.hpp"
#include "ieso/core/clock.hpp"
#include "ieso/core/diagnostics_platform.hpp"
#include "ieso/core/probe_verifier.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"
#include "ieso/core/redactor.hpp"
#include "ieso/core/ring.hpp"

namespace ieso {

class JsonWriter;

/// @brief One recent log line kept for the incident bundle.
struct LogLine {
  std::int64_t ts_ms = 0;   ///< Event time.
  std::string level;        ///< Level.
  std::string subsystem;    ///< Subsystem.
  std::string category;     ///< Category.
  std::string message;      ///< Message.
};

/// @brief Diagnostics options.
struct DiagnosticsOptions {
  std::filesystem::path incident_dir;                               ///< Where bundles are written.
  std::chrono::seconds sample_duration{3};                          ///< `sample` length.
  std::uint32_t captures_per_incident = config::kCapturesPerIncident;  ///< Budget.
  std::uint32_t captures_per_hour = config::kCapturesPerHour;          ///< Budget.
  std::string log_mode = "level:debug,persist:debug";               ///< Escalated mode.
  std::chrono::milliseconds tick{250};                              ///< Revert / pending-incident check period.
  std::chrono::milliseconds incident_settle{250};                   ///< Delay before freezing (see on_incident).
  std::string redaction_salt = "ieso";                            ///< IP-hash salt for the sanitized copy.
  std::filesystem::path checkpoint_file;                            ///< Flight-recorder checkpoint (NFR-11); empty = off.
  std::chrono::milliseconds checkpoint_period{60000};               ///< Checkpoint cadence (max history lost).
  std::shared_ptr<const IProbeVerifier> probe_verifier;             ///< Pinned control-plane key; empty = refuse all.
  std::uint32_t probes_per_incident = 4;                            ///< NFR-10 probe budget per incident.
  std::uint32_t probes_per_hour = 20;                               ///< NFR-10 probe budget per hour.
};

/**
 * @brief Diagnostics actor.
 */
class DiagnosticsActor final : public Actor {
 public:
  /// @brief Recent log lines kept for bundles.
  static constexpr std::size_t kLogSlots = 512;

  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] clock Time for budgets and escalation deadlines.
   * @param[in] platform OS hooks.
   * @param[in] opts Options.
   */
  DiagnosticsActor(EventBus& bus, EventFactory& factory, const IClock& clock,
                   std::shared_ptr<IDiagnosticsPlatform> platform, DiagnosticsOptions opts);

  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;
  /// @copydoc Actor::on_stop
  SRESULT on_stop() override;

 private:
  /// @brief An incident waiting for routine telemetry posted just before it to be recorded.
  struct PendingIncident {
    std::shared_ptr<const Event> trigger;               ///< Anomaly event (its id is the incident id).
    std::string symptom;                                ///< Symptom class.
    std::int64_t pid = 0;                               ///< Target pid.
    bool want_stacks = false;                           ///< Take a stack capture.
    std::chrono::steady_clock::time_point queued{};     ///< Real time it was queued.
  };

  /**
   * @brief Queues an incident. Incidents use a higher-priority lane than routine telemetry, so the log lines and
   *        samples posted just before the anomaly may still be queued; the bundle is built on a later tick.
   * @param[in] trigger Anomaly event.
   * @param[in] symptom Symptom class ("hang", "crash", ...).
   * @param[in] pid Target pid (0 if unknown).
   * @param[in] want_stacks Take a budgeted stack capture (process must be alive).
   * @return SRESULT::Ok.
   */
  SRESULT on_incident(std::shared_ptr<const Event> trigger, std::string symptom, std::int64_t pid, bool want_stacks);
  /**
   * @brief Builds, writes and announces one incident bundle.
   * @param[in] p Pending incident.
   * @return SRESULT::Ok or an I/O failure.
   */
  SRESULT build_incident(const PendingIncident& p);
  /// @brief Applies or extends an escalation. @param[in] ev Request. @return SRESULT::Ok or NoOp.
  SRESULT on_escalation(const std::shared_ptr<const DiagnosticEscalationRequested>& ev);
  /// @brief Reverts expired escalations, builds settled incidents, checkpoints the recorder. @return SRESULT::Ok.
  SRESULT tick();
  /**
   * @brief Runs a remote probe after the endpoint-side policy accepts it, else reports the refusal (FR-14).
   * @param[in] req Signed probe request from the control plane.
   * @return Result of posting ProbeResultReady.
   */
  SRESULT on_probe(const std::shared_ptr<const ProbeRequested>& req);
  /**
   * @brief Endpoint-side probe policy: allowlist, scope, expiry, signature, replay, budget (in that order).
   * @param[in] req Request.
   * @param[out] reason Empty if accepted, else why it was refused.
   * @return SRESULT::Ok.
   */
  SRESULT check_probe(const ProbeRequested& req, std::string& reason);
  /// @brief Restores the recorder from opts_.checkpoint_file if present (NFR-11). @return SRESULT::Ok or NoOp.
  SRESULT load_checkpoint();
  /// @brief Writes the recorder checkpoint atomically (temp + rename, 0600). @return SRESULT::Ok, NoOp or IoError.
  SRESULT save_checkpoint();
  /**
   * @brief Serializes the bundle.
   * @param[in] trigger Trigger event.
   * @param[in] symptom Symptom.
   * @param[in] rings Frozen rings.
   * @param[in] capture Stack capture text (may be empty).
   * @param[in] capture_status Result of the capture attempt.
   * @param[in] sanitized Redact every string (upload copy) instead of keeping raw evidence.
   * @param[out] out JSON text.
   * @return SRESULT::Ok.
   */
  SRESULT build_bundle(const Event& trigger, const std::string& symptom, const FrozenRings& rings,
                       const std::string& capture, SRESULT capture_status, bool sanitized, std::string& out);
  /**
   * @brief Writes a string value, redacted when @p sanitized.
   * @param[in,out] w Writer.
   * @param[in] v Raw text.
   * @param[in] sanitized Redact.
   * @param[in] free_text Use free-text rules (truncation) when redacting.
   * @return SRESULT::Ok or writer error.
   */
  SRESULT text(JsonWriter& w, std::string_view v, bool sanitized, bool free_text) const;
  /// @brief Redacts every string field in place. @param[in,out] fields Fields. @return SRESULT::Ok.
  SRESULT redact_fields(Fields& fields) const;
  /**
   * @brief Writes @p data to @p path.
   * @param[in] path File.
   * @param[in] data Bytes.
   * @return SRESULT::Ok or IoError.
   */
  static SRESULT write_file(const std::filesystem::path& path, const std::string& data);

  EventBus& bus_;                                       ///< Bus.
  EventFactory& factory_;                               ///< Factory.
  const IClock& clock_;                                 ///< Time.
  std::shared_ptr<IDiagnosticsPlatform> platform_;      ///< OS hooks.
  const DiagnosticsOptions opts_;                       ///< Options.
  const Redactor redactor_;                             ///< For the sanitized bundle copy.
  std::unique_ptr<FlightRecorder> recorder_;            ///< Rings.
  FixedRing<LogLine, kLogSlots> logs_;                  ///< Recent logs.
  CaptureBudget budget_;                                ///< Observer-effect budget.
  std::int64_t pid_ = 0;                                ///< Live target pid (0 if not running).
  std::map<std::string, std::chrono::steady_clock::time_point> escalated_;  ///< subsystem -> revert deadline.
  bool escalation_denied_warned_ = false;               ///< PermissionDenied traced once.
  std::vector<PendingIncident> pending_;                ///< Incidents waiting to settle.
  std::chrono::steady_clock::time_point last_checkpoint_{};  ///< Last successful checkpoint.
  CaptureBudget probe_budget_;                          ///< NFR-10: probes per incident / per hour.
  std::deque<std::string> seen_requests_;               ///< Recent request ids (replay protection), bounded.
};

}  // namespace ieso
