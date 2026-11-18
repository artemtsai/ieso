/**
 * @file diagnostics_platform.hpp
 * @brief OS hooks the Diagnostics actor needs (stack capture, log verbosity, environment).
 * @details Lives in core so the actor (sensor/actors/diagnostics) and the macOS implementation
 *          (sensor/platform/macos) both depend on core, not on each other.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include "ontology/events.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief OS hooks used by the Diagnostics actor.
 * @note Calls run on the Diagnostics actor thread and may block (e.g. a 3 s `sample`).
 */
class IDiagnosticsPlatform {
 public:
  virtual ~IDiagnosticsPlatform() = default;
  /**
   * @brief Captures thread stacks of a live process (macOS: `sample <pid> <s>`).
   * @param[in] pid Target.
   * @param[in] duration Sampling time.
   * @param[out] out Text report.
   * @return SRESULT::Ok, PermissionDenied, NotFound (process gone) or IoError.
   */
  virtual SRESULT capture_stacks(std::int64_t pid, std::chrono::seconds duration, std::string& out) = 0;
  /**
   * @brief Raises an os_log subsystem's level (macOS: `log config --subsystem S --mode M`, root).
   * @param[in] subsystem Subsystem.
   * @param[in] mode Mode string, e.g. "level:debug,persist:debug".
   * @return SRESULT::Ok or PermissionDenied.
   */
  virtual SRESULT set_log_mode(const std::string& subsystem, const std::string& mode) = 0;
  /**
   * @brief Restores the subsystem's default level (macOS: `log config --subsystem S --reset`).
   * @param[in] subsystem Subsystem.
   * @return SRESULT::Ok or PermissionDenied.
   */
  virtual SRESULT reset_log_mode(const std::string& subsystem) = 0;
  /**
   * @brief Environment snapshot (OS build, hardware model, ...).
   * @param[out] out Fields.
   * @return SRESULT::Ok.
   */
  virtual SRESULT environment(Fields& out) = 0;
  /**
   * @brief Runs one read-only, allowlisted probe (the caller has already verified signature, scope and budget).
   * @param[in] probe_id Allowlist ID (net.config, net.synthetic_tls, env.extensions, svc.launchctl).
   * @param[out] output Probe output, capped at 8 KB.
   * @param[out] exit_status 0 on success.
   * @return SRESULT::Ok, Unsupported (unknown id) or Timeout.
   */
  virtual SRESULT run_probe(const std::string& probe_id, std::string& output, std::int64_t& exit_status) = 0;
};

}  // namespace ieso
