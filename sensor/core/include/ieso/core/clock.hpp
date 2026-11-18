/**
 * @file clock.hpp
 * @brief Injectable time source so TTLs, budgets and backoff are testable.
 */
#pragma once

#include <chrono>
#include <mutex>

#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Abstract clock with wall-clock and monotonic time.
 * @note Implementations must be thread-safe.
 */
class IClock {
 public:
  virtual ~IClock() = default;
  /**
   * @brief Wall-clock time (event timestamps, TTLs that survive restart).
   * @param[out] out Current system time.
   * @return SRESULT::Ok.
   */
  virtual SRESULT now_system(std::chrono::system_clock::time_point& out) const = 0;
  /**
   * @brief Monotonic time (rate limits, sliding windows).
   * @param[out] out Current steady time.
   * @return SRESULT::Ok.
   */
  virtual SRESULT now_steady(std::chrono::steady_clock::time_point& out) const = 0;
};

/// @brief Real OS clocks.
class SystemClock final : public IClock {
 public:
  /// @copydoc IClock::now_system
  SRESULT now_system(std::chrono::system_clock::time_point& out) const override;
  /// @copydoc IClock::now_steady
  SRESULT now_steady(std::chrono::steady_clock::time_point& out) const override;
};

/// @brief Manually advanced clock for tests; both timelines move together.
class ManualClock final : public IClock {
 public:
  /// @brief Starts at 2026-01-01T00:00:00Z and an arbitrary steady origin.
  ManualClock();
  /// @copydoc IClock::now_system
  SRESULT now_system(std::chrono::system_clock::time_point& out) const override;
  /// @copydoc IClock::now_steady
  SRESULT now_steady(std::chrono::steady_clock::time_point& out) const override;
  /**
   * @brief Moves both clocks forward.
   * @param[in] d Non-negative duration.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidArgument @p d is negative.
   */
  SRESULT advance(std::chrono::milliseconds d);

 private:
  mutable std::mutex mu_;                         ///< Guards both time points.
  std::chrono::system_clock::time_point system_;  ///< Current wall time.
  std::chrono::steady_clock::time_point steady_;  ///< Current monotonic time.
};

}  // namespace ieso
