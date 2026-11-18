/**
 * @file sresult.hpp
 * @brief The single, project-wide result code returned by every function.
 * @details Codes below 100 are successes, 100 and above are failures.
 *          Add new codes here only; never define local error schemes.
 */
#pragma once

#include <cstdint>
#include <fmt/format.h>
#include <string_view>

namespace ieso {

/**
 * @brief Generalized result code (see docs/STYLEGUIDE.md §3).
 * @note Success codes carry extra information; test with HS_SUCCEEDED, not `== Ok`.
 * @note The type is [[nodiscard]]: ignoring a result is a compile error. Discard via `(void)expr;  // reason`.
 */
enum class [[nodiscard]] SRESULT : std::int32_t {
  // ---- success (< 100) ----
  Ok = 0,        ///< Completed as requested.
  NoOp = 1,      ///< Nothing to do (e.g. no subscribers, already stopped).
  Dropped = 2,   ///< Routine item dropped by its overflow policy; counted.
  Spilled = 3,   ///< Never-drop item handed to the spill sink instead of a full queue.
  Adjusted = 4,  ///< Completed, but inputs were clamped to hard caps.

  // ---- failure (>= 100) ----
  InvalidArgument = 100,  ///< Caller passed a bad value.
  NullPointer = 101,      ///< Required pointer/handle was empty.
  OutOfMemory = 102,      ///< Pool cap reached; nothing allocated.
  CapacityExceeded = 103, ///< Bounded structure is at its hard limit.
  NotFound = 104,         ///< Key, file or item does not exist.
  AlreadyExists = 105,    ///< Item with this identity already present.
  InvalidState = 106,     ///< Operation not allowed in the current state.
  Timeout = 107,          ///< Deadline passed before completion.
  IoError = 108,          ///< Filesystem or OS I/O failure.
  CorruptData = 109,      ///< Stored or received data failed validation.
  Unsupported = 110,      ///< Feature not available on this build/platform.
  PermissionDenied = 111, ///< OS or policy refused the operation.
  RateLimited = 112,      ///< Token bucket empty; retry later.
  BudgetExhausted = 113,  ///< Observer-effect or probe budget spent.
  Expired = 114,          ///< Item is past its TTL.
  Closed = 115,           ///< Target queue/actor is shut down.
  Internal = 116,         ///< Invariant violated; a bug.
};

/**
 * @brief Maps a code to its stable name.
 * @param[in] code Code to describe.
 * @param[out] out Static string; valid for the program lifetime.
 * @retval SRESULT::Ok Always; unknown values map to "Unknown".
 */
SRESULT to_string(SRESULT code, std::string_view& out) noexcept;

}  // namespace ieso

/// @brief True if @p r is a success code.
#define HS_SUCCEEDED(r) (static_cast<std::int32_t>(r) < 100)
/// @brief True if @p r is a failure code.
#define HS_FAILED(r) (static_cast<std::int32_t>(r) >= 100)
/// @brief Evaluates @p expr once and returns its code from the caller on failure.
#define HS_RETURN_IF_FAILED(expr)              \
  do {                                         \
    const ::ieso::SRESULT hs_rif_ = (expr);  \
    if (HS_FAILED(hs_rif_)) return hs_rif_;    \
  } while (0)

/**
 * @brief Lets SRESULT be used directly in fmt::format / trace messages.
 * @note fmt-mandated interface; exempt from the SRESULT return rule.
 */
template <>
struct fmt::formatter<ieso::SRESULT> : fmt::formatter<std::string_view> {
  auto format(ieso::SRESULT r, fmt::format_context& ctx) const {
    std::string_view name;
    (void)ieso::to_string(r, name);  // always Ok
    return fmt::formatter<std::string_view>::format(name, ctx);
  }
};
