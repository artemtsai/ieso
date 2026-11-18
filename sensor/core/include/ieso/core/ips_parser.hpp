/**
 * @file ips_parser.hpp
 * @brief Parser for macOS crash reports (.ips, JSON since macOS 12) (DESIGN.md §9.2).
 * @details An .ips file is one header JSON line followed by one body JSON document.
 *          Without symbols, the fleet-groupable signature is faulting module + offset + exception type.
 *          The crashed thread's top frames are kept (image name, offset, symbol) for the crash dump section of
 *          investigation reports; image paths are never copied (they can contain the user's home directory).
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief Maximum number of crashed-thread frames kept from a report.
constexpr std::size_t kMaxCrashFrames = 12;

/// @brief One frame of the crashed thread.
struct CrashFrame {
  std::string image;                 ///< Image name (usedImages[i].name), never its path.
  std::int64_t offset = 0;           ///< Offset in that image.
  std::string symbol;                ///< Symbol, when the report is symbolicated; else empty.
  std::int64_t symbol_location = 0;  ///< Offset from the symbol start.
};

/// @brief Fields extracted from one crash report.
struct CrashReport {
  std::string bug_type;            ///< Header bug_type ("309" = crash).
  std::string incident_id;         ///< Report's own incident UUID.
  std::string proc_name;           ///< Process name.
  std::string bundle_id;           ///< CFBundleIdentifier.
  std::string app_version;         ///< CFBundleShortVersionString.
  std::string os_version;          ///< Header os_version.
  std::int64_t pid = 0;            ///< Crashed pid.
  std::string exception_type;      ///< e.g. "EXC_BAD_ACCESS".
  std::string signal;              ///< e.g. "SIGSEGV".
  std::string exception_subtype;   ///< e.g. "KERN_INVALID_ADDRESS at 0x8".
  std::string termination_reason;  ///< namespace + indicator, e.g. "SIGNAL: Segmentation fault: 11".
  std::string faulting_module;     ///< Image name of the faulting frame.
  std::int64_t offset = 0;         ///< Offset of the faulting frame in that image.
  std::string exception_codes;     ///< e.g. "0x0000000000000001, 0x0000000000000008".
  std::string crashed_thread;      ///< Index and queue/name, e.g. "0 (com.apple.main-thread)".
  std::int64_t timestamp_ms = 0;   ///< Crash time from the header "timestamp" (Unix epoch ms); 0 if unknown.
  std::vector<CrashFrame> backtrace;  ///< Crashed thread, top kMaxCrashFrames frames, innermost first.
};

/**
 * @brief Parses .ips text.
 * @param[in] text Whole file contents.
 * @param[out] out Extracted fields; frame info is best-effort.
 * @retval SRESULT::Ok
 * @retval SRESULT::CorruptData Missing header/body or not JSON (e.g. file still being written).
 * @retval SRESULT::Unsupported Not a crash report (bug_type other than 309).
 */
SRESULT parse_ips(std::string_view text, CrashReport& out);

/**
 * @brief Converts an .ips header timestamp to Unix epoch milliseconds.
 * @param[in] text Header value, e.g. "2026-11-17 18:54:05.00 -0800" (fraction and offset optional; no offset = UTC).
 * @param[out] out_ms Epoch milliseconds.
 * @retval SRESULT::Ok
 * @retval SRESULT::CorruptData Not in that format.
 */
SRESULT parse_ips_timestamp(std::string_view text, std::int64_t& out_ms);

}  // namespace ieso
