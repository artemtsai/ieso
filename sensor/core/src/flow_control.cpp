/**
 * @file flow_control.cpp
 * @brief Backoff and TokenBucket implementation.
 */
#include "ieso/core/flow_control.hpp"

#include <algorithm>
#include <cmath>

namespace ieso {

Backoff::Backoff(std::chrono::milliseconds base, std::chrono::milliseconds cap, std::uint64_t seed)
    : base_(base.count() > 0 ? base : std::chrono::milliseconds(1)), cap_(std::max(cap, base_)), rng_(seed) {}

SRESULT Backoff::ceiling(std::chrono::milliseconds& out) const {
  const std::uint32_t shift = std::min<std::uint32_t>(attempt_, 30);
  const auto raw = static_cast<std::int64_t>(base_.count()) << shift;
  out = std::chrono::milliseconds(std::min<std::int64_t>(raw, static_cast<std::int64_t>(cap_.count())));
  return SRESULT::Ok;
}

SRESULT Backoff::next(std::chrono::milliseconds& out) {
  std::chrono::milliseconds ceil{0};
  HS_RETURN_IF_FAILED(ceiling(ceil));
  std::uniform_int_distribution<std::int64_t> dist(0, static_cast<std::int64_t>(ceil.count()));
  out = std::chrono::milliseconds(dist(rng_));
  if (attempt_ < 64) ++attempt_;
  return SRESULT::Ok;
}

SRESULT Backoff::reset() {
  attempt_ = 0;
  return SRESULT::Ok;
}

TokenBucket::TokenBucket(double rate_per_s, double burst, std::chrono::steady_clock::time_point now)
    : rate_(rate_per_s > 0 ? rate_per_s : 1.0), burst_(burst >= 1 ? burst : 1.0), tokens_(burst_), last_(now) {}

SRESULT TokenBucket::refill(std::chrono::steady_clock::time_point now) {
  if (now > last_) {
    const double secs = std::chrono::duration<double>(now - last_).count();
    tokens_ = std::min(burst_, tokens_ + secs * rate_);
    last_ = now;
  }
  return SRESULT::Ok;
}

SRESULT TokenBucket::take_up_to(std::chrono::steady_clock::time_point now, std::uint32_t want,
                                std::uint32_t& granted) {
  HS_RETURN_IF_FAILED(refill(now));
  const double whole = std::floor(tokens_);
  granted = static_cast<std::uint32_t>(std::min(whole, static_cast<double>(want)));
  tokens_ -= granted;
  return granted > 0 ? SRESULT::Ok : SRESULT::RateLimited;
}

SRESULT TokenBucket::refund(std::uint32_t n) {
  tokens_ = std::min(burst_, tokens_ + n);
  return SRESULT::Ok;
}

}  // namespace ieso
