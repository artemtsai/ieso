/**
 * @file uuid.cpp
 * @brief UUIDv7 generation with per-millisecond monotonic counter.
 */
#include "ieso/core/uuid.hpp"

#include <array>
#include <fmt/format.h>

namespace ieso {

UuidGenerator::UuidGenerator(const IClock& clock, std::uint64_t seed)
    : clock_(clock), rng_(seed != 0 ? seed : std::random_device{}()) {}

SRESULT UuidGenerator::next(std::string& out) {
  std::chrono::system_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_system(now));
  const auto ms_signed = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  std::uint64_t ms = ms_signed > 0 ? static_cast<std::uint64_t>(ms_signed) : 0;

  std::uint64_t rand_b = 0;
  std::uint32_t seq = 0;
  {
    std::lock_guard lock(mu_);
    if (ms > last_ms_) {
      last_ms_ = ms;
      counter_ = static_cast<std::uint32_t>(rng_() & 0x3FF);  // leave headroom within the ms
    } else {
      ++counter_;
      if (counter_ > 0xFFF) {  // counter exhausted: borrow the next millisecond
        ++last_ms_;
        counter_ = 0;
      }
    }
    ms = last_ms_;
    seq = counter_;
    rand_b = rng_();
  }

  const std::uint64_t hi = ((ms & 0xFFFFFFFFFFFFull) << 16) | (0x7ull << 12) | (seq & 0xFFF);
  const std::uint64_t lo = (0x2ull << 62) | (rand_b & 0x3FFFFFFFFFFFFFFFull);
  out = fmt::format("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}", hi >> 32, (hi >> 16) & 0xFFFF, hi & 0xFFFF,
                    lo >> 48, lo & 0xFFFFFFFFFFFFull);
  return SRESULT::Ok;
}

}  // namespace ieso
