/**
 * @file clock.cpp
 * @brief SystemClock and ManualClock implementations.
 */
#include "ieso/core/clock.hpp"

namespace ieso {

SRESULT SystemClock::now_system(std::chrono::system_clock::time_point& out) const {
  out = std::chrono::system_clock::now();
  return SRESULT::Ok;
}

SRESULT SystemClock::now_steady(std::chrono::steady_clock::time_point& out) const {
  out = std::chrono::steady_clock::now();
  return SRESULT::Ok;
}

ManualClock::ManualClock()
    : system_(std::chrono::seconds{1767225600}),  // 2026-01-01T00:00:00Z
      steady_(std::chrono::steady_clock::time_point{} + std::chrono::hours{1000}) {}

SRESULT ManualClock::now_system(std::chrono::system_clock::time_point& out) const {
  std::lock_guard lock(mu_);
  out = system_;
  return SRESULT::Ok;
}

SRESULT ManualClock::now_steady(std::chrono::steady_clock::time_point& out) const {
  std::lock_guard lock(mu_);
  out = steady_;
  return SRESULT::Ok;
}

SRESULT ManualClock::advance(std::chrono::milliseconds d) {
  if (d.count() < 0) return SRESULT::InvalidArgument;
  std::lock_guard lock(mu_);
  system_ += d;
  steady_ += d;
  return SRESULT::Ok;
}

}  // namespace ieso
