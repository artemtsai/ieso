/**
 * @file uuid.hpp
 * @brief UUIDv7 (RFC 9562) generator for stable, time-ordered event IDs.
 * @details IDs are monotonic within one generator, so lexical order equals creation order.
 *          The backend dedupes on these IDs (at-least-once delivery, DESIGN.md §9.7).
 */
#pragma once

#include <cstdint>
#include <mutex>
#include <random>
#include <string>

#include "ieso/core/clock.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Thread-safe UUIDv7 generator.
 * @note Layout: 48-bit Unix ms | ver 7 | 12-bit counter | variant 10 | 62 random bits.
 *       If the clock goes backwards, the last timestamp is reused and the counter keeps rising.
 */
class UuidGenerator {
 public:
  /**
   * @brief Creates a generator.
   * @param[in] clock Time source; must outlive the generator.
   * @param[in] seed RNG seed; 0 seeds from std::random_device.
   */
  explicit UuidGenerator(const IClock& clock, std::uint64_t seed = 0);

  /**
   * @brief Produces the next ID in canonical 8-4-4-4-12 lowercase hex form.
   * @param[out] out New UUID string.
   * @return SRESULT::Ok.
   */
  SRESULT next(std::string& out);

 private:
  const IClock& clock_;          ///< Time source.
  std::mutex mu_;                ///< Guards state below.
  std::mt19937_64 rng_;          ///< Random bits.
  std::uint64_t last_ms_ = 0;    ///< Timestamp of the previous ID.
  std::uint32_t counter_ = 0;    ///< 12-bit sequence within last_ms_.
};

}  // namespace ieso
