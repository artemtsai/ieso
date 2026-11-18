/**
 * @file config.hpp
 * @brief Compile-time capacities, budgets and hard caps, plus the runtime Policy that may tune them.
 * @details All bounds the sensor relies on live here (DESIGN.md §3 "Bounded everything").
 *          Policy values may change at runtime but are always clamped to the hard caps.
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

#include "ieso/core/sresult.hpp"

namespace ieso::config {

using namespace std::chrono_literals;

// ---- Mailbox lanes (per actor, per event class) ----
inline constexpr std::size_t kRoutineLaneCapacity = 1024;   ///< Routine telemetry lane depth.
inline constexpr std::size_t kIncidentLaneCapacity = 256;   ///< Incident lane soft depth.
inline constexpr std::size_t kControlLaneCapacity = 256;    ///< Control lane soft depth.
inline constexpr std::size_t kNeverDropHardMultiplier = 4;  ///< Never-drop lanes may grow to soft x this.
inline constexpr std::size_t kSampleKeepEvery = 4;          ///< Sample policy keeps 1 of N above watermark.
inline constexpr std::size_t kSampleWatermarkPct = 50;      ///< Sampling starts at this % of capacity.
inline constexpr std::size_t kMaxLaneCapacity = 65536;      ///< Hard cap for any lane.

// ---- Flight recorder (DESIGN.md §9.3) ----
inline constexpr std::size_t kHotSlots = 50;     ///< 5 s at 100 ms.
inline constexpr std::size_t kWarmSlots = 600;   ///< 10 min at 1 s.
inline constexpr std::size_t kColdSlots = 1440;  ///< 24 h of 1-min aggregates.
inline constexpr std::int64_t kWarmBucketMs = 1000;   ///< Warm ring resolution.
inline constexpr std::int64_t kColdBucketMs = 60000;  ///< Cold ring resolution.

// ---- Event pool ----
inline constexpr std::size_t kEventPoolBytes = 8u << 20;      ///< Default event pool cap.
inline constexpr std::size_t kEventPoolHardCap = 16u << 20;   ///< Never exceeded by policy.
inline constexpr std::size_t kPoolHeadroomBytes = 256u << 10;  ///< Reserve kept for pool chunk growth.

// ---- Spool (DESIGN.md §9.7, NFR-2, NFR-5) ----
inline constexpr std::uint64_t kSpoolMaxBytes = 250ull << 20;   ///< Default spool cap.
inline constexpr std::uint64_t kSpoolHardCapBytes = 250ull << 20;  ///< Policy may only lower it.
inline constexpr std::chrono::hours kTtlRoutine = 24h;           ///< Routine telemetry TTL.
inline constexpr std::chrono::hours kTtlIncident = 7 * 24h;      ///< Incident/control TTL.
inline constexpr std::uint32_t kReplayPerSecond = 50;            ///< Drain rate limit.
inline constexpr std::uint32_t kReplayBurst = 100;               ///< Drain burst size.
inline constexpr std::chrono::milliseconds kBackoffBase = 500ms; ///< First retry delay ceiling.
inline constexpr std::chrono::milliseconds kBackoffCap = 5min;   ///< Max retry delay ceiling.

// ---- Observer-effect budget (NFR-4) ----
inline constexpr std::uint32_t kCapturesPerIncident = 1;  ///< Default deep captures per incident.
inline constexpr std::uint32_t kCapturesPerHour = 4;      ///< Default deep captures per hour.
inline constexpr std::uint32_t kCapturesPerIncidentHardCap = 2;
inline constexpr std::uint32_t kCapturesPerHourHardCap = 12;

/**
 * @brief Runtime-tunable limits delivered by the control plane (FR-7).
 * @note Always call clamp() after applying a new policy.
 */
struct Policy {
  std::size_t routine_lane_capacity = kRoutineLaneCapacity;  ///< Per-actor routine lane depth.
  std::size_t event_pool_bytes = kEventPoolBytes;            ///< Event pool cap.
  std::uint64_t spool_max_bytes = kSpoolMaxBytes;            ///< Spool size cap.
  std::uint32_t captures_per_incident = kCapturesPerIncident;
  std::uint32_t captures_per_hour = kCapturesPerHour;

  /**
   * @brief Clamps every value into [1, hard cap].
   * @retval SRESULT::Ok       Nothing changed.
   * @retval SRESULT::Adjusted At least one value was clamped.
   */
  SRESULT clamp();
};

}  // namespace ieso::config
