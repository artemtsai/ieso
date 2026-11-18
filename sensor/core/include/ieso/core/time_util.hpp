/**
 * @file time_util.hpp
 * @brief Time conversions without C++20 chrono calendar support.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Formats a time point as RFC 3339 UTC with milliseconds, e.g. "2026-01-01T00:00:00.123Z".
 * @param[in] tp Time point.
 * @param[out] out Formatted text.
 * @retval SRESULT::Ok
 * @retval SRESULT::InvalidArgument Time not representable (gmtime failed).
 */
SRESULT format_utc_ms(std::chrono::system_clock::time_point tp, std::string& out);

/**
 * @brief Converts a time point to Unix milliseconds.
 * @param[in] tp Time point.
 * @param[out] out Milliseconds since 1970-01-01Z.
 * @return SRESULT::Ok.
 */
SRESULT to_unix_ms(std::chrono::system_clock::time_point tp, std::int64_t& out);

/**
 * @brief Converts Unix milliseconds to a time point.
 * @param[in] ms Milliseconds since 1970-01-01Z.
 * @param[out] out Time point.
 * @return SRESULT::Ok.
 */
SRESULT from_unix_ms(std::int64_t ms, std::chrono::system_clock::time_point& out);

}  // namespace ieso
