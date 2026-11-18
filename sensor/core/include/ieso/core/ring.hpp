/**
 * @file ring.hpp
 * @brief Fixed-capacity overwrite ring and the tiered flight recorder (DESIGN.md §9.3).
 * @details Hot: 5 s @100 ms. Warm: 10 min @1 s. Cold: 24 h of 1-min min/max/avg.
 *          Storage is a fixed array sized at compile time; nothing allocates after construction.
 *          Writes take no locks: the recorder is owned by one actor (Diagnostics) and
 *          other actors reach it only through bus events.
 *          Every sample carries its pid. When the pid changes (target restarted), the open 1 s and 1 min
 *          buckets are closed early, so a mean or aggregate never mixes two processes.
 *          Durability (NFR-11): the warm and cold tiers (with their open buckets) are checkpointed and restored,
 *          so a sensor restart loses at most one checkpoint period; the gap is marked with kGapMarkerPid.
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "ieso/core/config.hpp"
#include "ieso/core/sample.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Ring that overwrites the oldest slot when full.
 * @tparam T Trivially copyable slot type.
 * @tparam N Slot count (> 0).
 * @warning Not thread-safe; owned by a single actor.
 */
template <class T, std::size_t N>
class FixedRing {
  static_assert(N > 0, "ring needs at least one slot");

 public:
  /**
   * @brief Appends, overwriting the oldest slot when full.
   * @param[in] v Value.
   * @retval SRESULT::Ok      Slot was free.
   * @retval SRESULT::Dropped Oldest value overwritten.
   */
  SRESULT push(const T& v) {
    slots_[head_] = v;
    head_ = (head_ + 1) % N;
    if (size_ < N) {
      ++size_;
      return SRESULT::Ok;
    }
    return SRESULT::Dropped;
  }

  /**
   * @brief Copies contents oldest-first.
   * @param[out] out Replaced with up to N values.
   * @return SRESULT::Ok.
   */
  SRESULT snapshot(std::vector<T>& out) const {
    out.clear();
    out.reserve(size_);
    const std::size_t start = (head_ + N - size_) % N;
    for (std::size_t i = 0; i < size_; ++i) out.push_back(slots_[(start + i) % N]);
    return SRESULT::Ok;
  }

  /**
   * @brief Current element count.
   * @param[out] out Count (<= N).
   * @return SRESULT::Ok.
   */
  SRESULT size(std::size_t& out) const {
    out = size_;
    return SRESULT::Ok;
  }

 private:
  std::array<T, N> slots_{};  ///< Storage.
  std::size_t head_ = 0;      ///< Next write index.
  std::size_t size_ = 0;      ///< Valid elements.
};

/// @brief Outcome of FlightRecorder::restore().
struct RestoreStats {
  std::size_t warm = 0;            ///< 1 s entries restored.
  std::size_t cold = 0;            ///< 1 min aggregates restored.
  std::size_t dropped_old = 0;     ///< Entries discarded as older than their tier window.
  std::int64_t gap_from_ms = 0;    ///< Last sample before the restart.
  std::int64_t gap_to_ms = 0;      ///< Restore time (gap end).
};

/// @brief Copy of all three rings at freeze time, oldest-first.
struct FrozenRings {
  std::int64_t frozen_at_ms = 0;        ///< Freeze time (Unix ms).
  std::vector<ResourceSample> hot;      ///< 100 ms samples.
  std::vector<ResourceSample> warm;     ///< 1 s means.
  std::vector<AggregateSample> cold;    ///< 1 min aggregates.
};

/**
 * @brief Running min/max/sum over one bucket.
 * @note Internal helper of FlightRecorder.
 */
struct BucketAccumulator {
  std::int64_t start_ms = -1;  ///< Bucket start; -1 = empty.
  std::int64_t pid = 0;        ///< Process of every sample in the bucket.
  std::uint32_t count = 0;     ///< Samples seen.
  ResourceSample min;          ///< Field-wise min.
  ResourceSample max;          ///< Field-wise max.
  double sum_cpu = 0, sum_rss = 0, sum_threads = 0, sum_fds = 0, sum_disk = 0, sum_thermal = 0;  ///< Sums.

  /**
   * @brief Adds a sample.
   * @param[in] s Sample.
   * @return SRESULT::Ok.
   */
  SRESULT add(const ResourceSample& s);
  /**
   * @brief Produces the aggregate and resets.
   * @param[out] out Aggregate of the bucket.
   * @retval SRESULT::Ok
   * @retval SRESULT::NotFound Bucket empty.
   */
  SRESULT take(AggregateSample& out);
};

/**
 * @brief Tiered flight recorder.
 * @warning Not thread-safe; owned by the Diagnostics actor.
 */
class FlightRecorder {
 public:
  /**
   * @brief Allocates a recorder (about 280 KB, once).
   * @param[out] out New recorder.
   * @return SRESULT::Ok.
   */
  static SRESULT Create(std::unique_ptr<FlightRecorder>& out);

  /**
   * @brief Records a sample into hot; rolls completed 1 s / 1 min buckets into warm / cold.
   * @note A pid change closes the open buckets early, so warm/cold may hold two entries with the same start time
   *       (one per process).
   * @param[in] s Sample; ts_ms must not go backwards.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidArgument Timestamp older than the previous sample (traced WARNING).
   */
  SRESULT ingest(const ResourceSample& s);

  /**
   * @brief Copies all rings for an incident bundle; recording continues.
   * @param[in] now_ms Freeze timestamp.
   * @param[out] out Frozen copy (completed buckets only for warm/cold).
   * @return SRESULT::Ok.
   */
  SRESULT freeze(std::int64_t now_ms, FrozenRings& out) const;

  /**
   * @brief Serializes the warm and cold tiers plus their open buckets (the hot tier is not persisted).
   * @param[in] now_ms Checkpoint time.
   * @param[out] out Versioned, CRC-protected binary checkpoint (about 300 KB at full rings).
   * @return SRESULT::Ok.
   */
  SRESULT checkpoint(std::int64_t now_ms, std::string& out) const;

  /**
   * @brief Restores a checkpoint into an empty recorder. Entries older than their tier window are dropped, open
   *        buckets are closed, and a gap marker (pid kGapMarkerPid, ts = now) is appended to each non-empty tier.
   * @param[in] data Checkpoint bytes.
   * @param[in] now_ms Current time.
   * @param[out] out What was restored.
   * @retval SRESULT::Ok
   * @retval SRESULT::CorruptData  Bad magic, length or CRC.
   * @retval SRESULT::Unsupported  Unknown checkpoint version.
   * @retval SRESULT::InvalidState Recorder not empty, or the checkpoint is from the future (clock skew).
   */
  SRESULT restore(std::string_view data, std::int64_t now_ms, RestoreStats& out);

 private:
  FixedRing<ResourceSample, config::kHotSlots> hot_;     ///< 5 s @ 100 ms.
  FixedRing<ResourceSample, config::kWarmSlots> warm_;   ///< 10 min @ 1 s.
  FixedRing<AggregateSample, config::kColdSlots> cold_;  ///< 24 h @ 1 min.
  BucketAccumulator warm_acc_;                           ///< Current second.
  BucketAccumulator cold_acc_;                           ///< Current minute.
  std::int64_t last_ts_ms_ = INT64_MIN;                  ///< Monotonicity check.
};

}  // namespace ieso
