/**
 * @file flow_control.hpp
 * @brief Retry backoff with full jitter and a token-bucket rate limiter (DESIGN.md §9.7).
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <random>

#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Exponential backoff with full jitter: delay = U(0, min(cap, base * 2^attempt)).
 * @note Full jitter spreads a fleet's reconnects so the backend is not stormed.
 * @warning Not thread-safe; owned by one actor.
 */
class Backoff {
 public:
  /**
   * @brief Creates a backoff.
   * @param[in] base Ceiling of the first delay (> 0).
   * @param[in] cap Max ceiling.
   * @param[in] seed RNG seed (deterministic tests).
   */
  Backoff(std::chrono::milliseconds base, std::chrono::milliseconds cap, std::uint64_t seed);

  /**
   * @brief Next delay; increments the attempt counter.
   * @param[out] out Delay in [0, ceiling].
   * @return SRESULT::Ok.
   */
  SRESULT next(std::chrono::milliseconds& out);

  /**
   * @brief Current ceiling without advancing.
   * @param[out] out Ceiling for the next call.
   * @return SRESULT::Ok.
   */
  SRESULT ceiling(std::chrono::milliseconds& out) const;

  /// @brief Resets after a success. @return SRESULT::Ok.
  SRESULT reset();

 private:
  std::chrono::milliseconds base_;  ///< First ceiling.
  std::chrono::milliseconds cap_;   ///< Max ceiling.
  std::uint32_t attempt_ = 0;       ///< Failures since reset.
  std::mt19937_64 rng_;             ///< Jitter source.
};

/**
 * @brief Token bucket: @p rate tokens/s, at most @p burst stored.
 * @warning Not thread-safe; owned by one actor.
 */
class TokenBucket {
 public:
  /**
   * @brief Creates a full bucket.
   * @param[in] rate_per_s Refill rate (> 0).
   * @param[in] burst Capacity (>= 1).
   * @param[in] now Start time.
   */
  TokenBucket(double rate_per_s, double burst, std::chrono::steady_clock::time_point now);

  /**
   * @brief Takes up to @p want whole tokens.
   * @param[in] now Current time.
   * @param[in] want Requested tokens.
   * @param[out] granted Tokens taken (0..want).
   * @retval SRESULT::Ok          At least one token granted.
   * @retval SRESULT::RateLimited None available.
   */
  SRESULT take_up_to(std::chrono::steady_clock::time_point now, std::uint32_t want, std::uint32_t& granted);

  /**
   * @brief Returns unused tokens (capped at burst).
   * @param[in] n Tokens to return.
   * @return SRESULT::Ok.
   */
  SRESULT refund(std::uint32_t n);

 private:
  /// @brief Adds tokens for elapsed time. @param[in] now Current time. @return SRESULT::Ok.
  SRESULT refill(std::chrono::steady_clock::time_point now);

  double rate_;                                  ///< Tokens per second.
  double burst_;                                 ///< Capacity.
  double tokens_;                                ///< Available.
  std::chrono::steady_clock::time_point last_;   ///< Last refill.
};

}  // namespace ieso
