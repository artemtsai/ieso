/**
 * @file capture_budget.hpp
 * @brief Observer-effect budget for captures that pause or load the target app (NFR-4).
 * @details Default: at most 1 sample/spindump per incident and 4 per sliding hour.
 *          The sensor must never become the cause of the app's problem.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <string>

#include "ieso/core/clock.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Thread-safe per-incident and per-hour capture limiter.
 * @note Tracks at most kMaxIncidents incidents; the oldest is forgotten first.
 */
class CaptureBudget {
 public:
  /// @brief Incidents remembered for per-incident accounting.
  static constexpr std::size_t kMaxIncidents = 256;

  /**
   * @brief Creates a budget (values should already be clamped by Policy).
   * @param[in] clock Time source; must outlive the budget.
   * @param[in] per_incident Max captures per incident id.
   * @param[in] per_hour Max captures in any 60-minute window.
   */
  CaptureBudget(const IClock& clock, std::uint32_t per_incident, std::uint32_t per_hour);

  /**
   * @brief Consumes one capture if both limits allow it.
   * @param[in] incident_id Incident the capture belongs to.
   * @retval SRESULT::Ok
   * @retval SRESULT::BudgetExhausted Per-incident or hourly limit reached (nothing consumed).
   */
  SRESULT try_acquire(const std::string& incident_id);

  /**
   * @brief Captures still allowed in the current hour window.
   * @param[out] out Remaining count.
   * @return SRESULT::Ok.
   */
  SRESULT remaining_this_hour(std::uint32_t& out);

 private:
  /// @brief Drops window entries older than 1 h. @param[in] now Current time. @return SRESULT::Ok.
  SRESULT prune(std::chrono::steady_clock::time_point now);

  const IClock& clock_;                                   ///< Time source.
  const std::uint32_t per_incident_;                      ///< Limit per incident.
  const std::uint32_t per_hour_;                          ///< Limit per hour.
  std::mutex mu_;                                         ///< Guards state.
  std::deque<std::chrono::steady_clock::time_point> window_;  ///< Capture times in the last hour.
  std::map<std::string, std::uint32_t> by_incident_;     ///< Captures per incident.
  std::deque<std::string> incident_order_;                ///< FIFO for forgetting incidents.
};

}  // namespace ieso
