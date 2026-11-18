/**
 * @file config.cpp
 * @brief Policy clamping to hard caps.
 */
#include "ieso/core/config.hpp"

#include <algorithm>

namespace ieso::config {
namespace {

/**
 * @brief Clamps one value into [lo, hi] and records whether it changed.
 * @tparam T Arithmetic type.
 * @param[in,out] v Value to clamp.
 * @param[in] lo Lower bound.
 * @param[in] hi Upper bound.
 * @param[in,out] changed Set to true if @p v was modified.
 * @return SRESULT::Ok.
 */
template <class T>
SRESULT clamp_one(T& v, T lo, T hi, bool& changed) {
  const T c = std::clamp(v, lo, hi);
  changed = changed || (c != v);
  v = c;
  return SRESULT::Ok;
}

}  // namespace

SRESULT Policy::clamp() {
  bool changed = false;
  HS_RETURN_IF_FAILED(clamp_one<std::size_t>(routine_lane_capacity, 1, kMaxLaneCapacity, changed));
  HS_RETURN_IF_FAILED(clamp_one<std::size_t>(event_pool_bytes, kPoolHeadroomBytes * 2, kEventPoolHardCap, changed));
  HS_RETURN_IF_FAILED(clamp_one<std::uint64_t>(spool_max_bytes, 1u << 20, kSpoolHardCapBytes, changed));
  HS_RETURN_IF_FAILED(clamp_one<std::uint32_t>(captures_per_incident, 0, kCapturesPerIncidentHardCap, changed));
  HS_RETURN_IF_FAILED(clamp_one<std::uint32_t>(captures_per_hour, 0, kCapturesPerHourHardCap, changed));
  return changed ? SRESULT::Adjusted : SRESULT::Ok;
}

}  // namespace ieso::config
