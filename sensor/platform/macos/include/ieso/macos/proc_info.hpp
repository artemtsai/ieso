/**
 * @file proc_info.hpp
 * @brief libproc/sysctl helpers: find the target, read its resources, describe the host.
 * @details Works without root for processes of the same user (FR-1 black-box telemetry).
 */
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

#include "ieso/core/sresult.hpp"

namespace ieso::macos {

/// @brief Task counters of one process.
struct TaskInfo {
  std::uint64_t cpu_ns = 0;     ///< User + system CPU time, nanoseconds.
  std::uint64_t rss_bytes = 0;  ///< Resident size.
  std::uint32_t threads = 0;    ///< Thread count.
};

/// @brief All pids currently running. @param[out] out Pids. @return SRESULT::Ok or IoError.
SRESULT list_pids(std::vector<pid_t>& out);

/**
 * @brief Executable path of a pid.
 * @param[in] pid Process.
 * @param[out] out Absolute path.
 * @return SRESULT::Ok or NotFound.
 */
SRESULT pid_path(pid_t pid, std::string& out);

/**
 * @brief Finds the newest process whose executable is `<name>.app/Contents/MacOS/<x>` or whose basename is @p name.
 * @param[in] name Target app name (e.g. "DemoApp").
 * @param[out] pid Process id.
 * @param[out] exe Executable path.
 * @return SRESULT::Ok or NotFound.
 */
SRESULT find_target(const std::string& name, pid_t& pid, std::string& exe);

/**
 * @brief Bundle identifier and short version of the .app containing @p exe.
 * @param[in] exe Executable path inside a bundle.
 * @param[out] bundle_id CFBundleIdentifier.
 * @param[out] version CFBundleShortVersionString.
 * @return SRESULT::Ok or NotFound (not in a bundle).
 */
SRESULT bundle_info(const std::string& exe, std::string& bundle_id, std::string& version);

/**
 * @brief CPU time, RSS and threads (PROC_PIDTASKINFO).
 * @param[in] pid Process.
 * @param[out] out Counters.
 * @return SRESULT::Ok, NotFound (exited) or PermissionDenied.
 */
SRESULT task_info(pid_t pid, TaskInfo& out);

/// @brief Open file descriptors (PROC_PIDLISTFDS). @param[in] pid Process. @param[out] out Count. @return Ok or NotFound.
SRESULT fd_count(pid_t pid, std::uint32_t& out);

/// @brief Free bytes on the volume of @p path (statfs). @param[in] path Path. @param[out] out Bytes. @return Ok or IoError.
SRESULT disk_free(const std::string& path, std::uint64_t& out);

/**
 * @brief Reads a string sysctl (e.g. "kern.osproductversion").
 * @param[in] name Sysctl name.
 * @param[out] out Value.
 * @return SRESULT::Ok or NotFound.
 */
SRESULT sysctl_string(const char* name, std::string& out);

}  // namespace ieso::macos
