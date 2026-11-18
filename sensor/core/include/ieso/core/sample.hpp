/**
 * @file sample.hpp
 * @brief Resource sample of the target app, as stored in the flight recorder.
 */
#pragma once

#include <cstdint>

namespace ieso {

/// @brief pid of a gap marker: "no samples between the previous ring entry and this one" (sensor was down).
inline constexpr std::int64_t kGapMarkerPid = -1;

/// @brief Point-in-time resource metrics of the target process and host (trivially copyable).
struct ResourceSample {
  std::int64_t ts_ms = 0;            ///< Unix time in ms.
  std::int64_t pid = 0;              ///< Target process the sample belongs to (rings never mix processes).
  double cpu_pct = 0.0;              ///< Process CPU, percent of one core.
  std::uint64_t rss_bytes = 0;       ///< Resident set size.
  std::uint32_t threads = 0;         ///< Thread count.
  std::uint32_t fds = 0;             ///< Open file descriptors.
  std::uint64_t disk_free_bytes = 0; ///< Free bytes on the app's volume.
  std::int32_t thermal_level = 0;    ///< 0 nominal .. 3 critical.
};

/// @brief Min/max/avg of samples within one cold-ring bucket (all from one pid: min.pid == max.pid == avg.pid).
struct AggregateSample {
  std::int64_t start_ms = 0;  ///< Bucket start (Unix ms).
  std::uint32_t count = 0;    ///< Samples aggregated.
  ResourceSample min;         ///< Field-wise minimum.
  ResourceSample max;         ///< Field-wise maximum.
  ResourceSample avg;         ///< Field-wise mean.
};

}  // namespace ieso
