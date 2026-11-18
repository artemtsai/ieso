/**
 * @file time_util.cpp
 * @brief gmtime_r/strftime based UTC formatting.
 */
#include "ieso/core/time_util.hpp"

#include <array>
#include <ctime>

#include <fmt/format.h>

namespace ieso {

SRESULT to_unix_ms(std::chrono::system_clock::time_point tp, std::int64_t& out) {
  out = static_cast<std::int64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count());
  return SRESULT::Ok;
}

SRESULT from_unix_ms(std::int64_t ms, std::chrono::system_clock::time_point& out) {
  out = std::chrono::system_clock::time_point(
      std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::milliseconds(ms)));
  return SRESULT::Ok;
}

SRESULT format_utc_ms(std::chrono::system_clock::time_point tp, std::string& out) {
  std::int64_t ms = 0;
  HS_RETURN_IF_FAILED(to_unix_ms(tp, ms));
  std::int64_t secs = ms / 1000;
  std::int64_t frac = ms % 1000;
  if (frac < 0) {
    frac += 1000;
    --secs;
  }
  const std::time_t t = static_cast<std::time_t>(secs);
  std::tm tm{};
  if (gmtime_r(&t, &tm) == nullptr) return SRESULT::InvalidArgument;
  std::array<char, 32> buf{};
  const std::size_t n = std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%S", &tm);
  if (n == 0) return SRESULT::InvalidArgument;
  out = fmt::format("{}.{:03}Z", std::string_view(buf.data(), n), frac);
  return SRESULT::Ok;
}

}  // namespace ieso
