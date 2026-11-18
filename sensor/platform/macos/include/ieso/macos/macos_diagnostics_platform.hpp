/**
 * @file macos_diagnostics_platform.hpp
 * @brief macOS implementation of IDiagnosticsPlatform: `sample`, `log config`, sysctl environment, read-only probes.
 * @details DESIGN.md §9.4, §9.5. `log config` needs root; without it escalation returns PermissionDenied and the
 *          incident still proceeds (rings + logs + stacks). Calls are rate-limited by the Diagnostics actor.
 */
#pragma once

#include <filesystem>

#include "ieso/core/diagnostics_platform.hpp"

namespace ieso::macos {

/// @brief Fixed probe parameters, set by policy at start (requests carry IDs only, never parameters).
struct ProbeConfig {
  std::string app_backend_url;  ///< Target of net.synthetic_tls (the app's own backend).
  std::string demo_proxy;       ///< Stands in for the system HTTPS proxy in the demo ("" = use system settings).
  std::string direct_address;   ///< "host:port" to reach the backend without the proxy ("" = normal DNS).
  std::string launchctl_label;  ///< Helper job inspected by svc.launchctl.
};

/**
 * @brief macOS diagnostics hooks.
 */
class MacosDiagnosticsPlatform final : public IDiagnosticsPlatform {
 public:
  /// @brief Creates the platform. @param[in] scratch_dir Directory for temporary capture files.
  /// @param[in] scratch_dir Temp dir. @param[in] probes Probe parameters.
  MacosDiagnosticsPlatform(std::filesystem::path scratch_dir, ProbeConfig probes = {});
  /// @copydoc IDiagnosticsPlatform::capture_stacks
  SRESULT capture_stacks(std::int64_t pid, std::chrono::seconds duration, std::string& out) override;
  /// @copydoc IDiagnosticsPlatform::set_log_mode
  SRESULT set_log_mode(const std::string& subsystem, const std::string& mode) override;
  /// @copydoc IDiagnosticsPlatform::reset_log_mode
  SRESULT reset_log_mode(const std::string& subsystem) override;
  /// @copydoc IDiagnosticsPlatform::environment
  SRESULT environment(Fields& out) override;
  /// @copydoc IDiagnosticsPlatform::run_probe
  SRESULT run_probe(const std::string& probe_id, std::string& output, std::int64_t& exit_status) override;

 private:
  /// @brief net.config: proxy and DNS configuration. @param[out] out Text. @return SRESULT::Ok.
  SRESULT probe_net_config(std::string& out);
  /// @brief net.synthetic_tls: TLS path to the app backend via proxy and direct (JSON). @param[out] out JSON. @return Ok.
  SRESULT probe_synthetic_tls(std::string& out);
  /// @brief The HTTPS proxy in effect (demo override, else system settings). @param[out] out "http://host:port" or "".
  /// @return SRESULT::Ok.
  SRESULT effective_proxy(std::string& out);

  const std::filesystem::path scratch_;  ///< Temp files.
  const ProbeConfig probes_;             ///< Probe parameters.
};

}  // namespace ieso::macos
