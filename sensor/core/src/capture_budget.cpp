/**
 * @file capture_budget.cpp
 * @brief CaptureBudget implementation.
 */
#include "ieso/core/capture_budget.hpp"

#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "budget";
}  // namespace

CaptureBudget::CaptureBudget(const IClock& clock, std::uint32_t per_incident, std::uint32_t per_hour)
    : clock_(clock), per_incident_(per_incident), per_hour_(per_hour) {}

SRESULT CaptureBudget::prune(std::chrono::steady_clock::time_point now) {
  while (!window_.empty() && now - window_.front() >= std::chrono::hours(1)) window_.pop_front();
  return SRESULT::Ok;
}

SRESULT CaptureBudget::try_acquire(const std::string& incident_id) {
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  std::lock_guard lock(mu_);
  HS_RETURN_IF_FAILED(prune(now));
  const auto it = by_incident_.find(incident_id);
  const std::uint32_t used = it == by_incident_.end() ? 0 : it->second;
  if (used >= per_incident_) {
    HS_TRACE_INFO(kComponent, "capture denied: incident {} used {}/{}", incident_id, used, per_incident_);
    return SRESULT::BudgetExhausted;
  }
  if (window_.size() >= per_hour_) {
    HS_TRACE_INFO(kComponent, "capture denied: hourly budget {}/{} spent", window_.size(), per_hour_);
    return SRESULT::BudgetExhausted;
  }
  window_.push_back(now);
  if (it == by_incident_.end()) {
    by_incident_[incident_id] = 1;
    incident_order_.push_back(incident_id);
    if (incident_order_.size() > kMaxIncidents) {
      by_incident_.erase(incident_order_.front());
      incident_order_.pop_front();
    }
  } else {
    ++it->second;
  }
  return SRESULT::Ok;
}

SRESULT CaptureBudget::remaining_this_hour(std::uint32_t& out) {
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  std::lock_guard lock(mu_);
  HS_RETURN_IF_FAILED(prune(now));
  out = window_.size() >= per_hour_ ? 0 : per_hour_ - static_cast<std::uint32_t>(window_.size());
  return SRESULT::Ok;
}

}  // namespace ieso
