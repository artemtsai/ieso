/**
 * @file bounded_queue.hpp
 * @brief Fixed-capacity FIFO with explicit overflow policies and drop accounting.
 * @details Not synchronized; the owning Mailbox provides locking.
 *          Routine telemetry may be dropped or sampled; never-drop items are refused when full so
 *          the caller can spill or force-push up to a hard cap (DESIGN.md §3).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <utility>

#include "ieso/core/config.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief What a full queue does with a new item.
enum class OverflowPolicy : std::uint8_t {
  DropOldest = 0,  ///< Evict the oldest item, accept the new one.
  Sample = 1,      ///< Above the watermark keep 1 of N new items; when full drop the new item.
  NeverDrop = 2,   ///< Refuse with CapacityExceeded; caller spills or force-pushes.
};

/// @brief Counters exported as self-telemetry (NFR-9).
struct QueueStats {
  std::size_t depth = 0;       ///< Current item count.
  std::size_t high_water = 0;  ///< Max depth seen.
  std::uint64_t pushed = 0;    ///< Items accepted.
  std::uint64_t dropped = 0;   ///< Items discarded by policy.
  std::uint64_t forced = 0;    ///< Never-drop items accepted above soft capacity.
};

/**
 * @brief Bounded FIFO of @p T.
 * @tparam T Movable item type.
 * @warning Not thread-safe.
 */
template <class T>
class BoundedQueue {
 public:
  /**
   * @brief Creates an empty queue.
   * @param[in] capacity Soft capacity (>= 1); clamped to config::kMaxLaneCapacity.
   */
  explicit BoundedQueue(std::size_t capacity)
      : capacity_(capacity == 0 ? 1 : (capacity > config::kMaxLaneCapacity ? config::kMaxLaneCapacity : capacity)) {}

  /**
   * @brief Pushes an item according to @p policy.
   * @param[in,out] item Moved from only when accepted.
   * @param[in] policy Overflow behavior for this item.
   * @retval SRESULT::Ok               Accepted.
   * @retval SRESULT::Dropped          Accepted after evicting the oldest (DropOldest) or discarded (Sample).
   * @retval SRESULT::CapacityExceeded NeverDrop item refused; @p item untouched.
   */
  SRESULT push(T& item, OverflowPolicy policy) {
    switch (policy) {
      case OverflowPolicy::DropOldest:
        if (items_.size() >= capacity_) {
          items_.pop_front();
          ++stats_.dropped;
          HS_RETURN_IF_FAILED(accept(item));
          return SRESULT::Dropped;
        }
        return accept(item);
      case OverflowPolicy::Sample: {
        const std::size_t watermark = capacity_ * config::kSampleWatermarkPct / 100;
        if (items_.size() >= capacity_) {
          ++stats_.dropped;
          return SRESULT::Dropped;
        }
        if (items_.size() >= watermark) {
          if ((sample_counter_++ % config::kSampleKeepEvery) != 0) {
            ++stats_.dropped;
            return SRESULT::Dropped;
          }
        } else {
          sample_counter_ = 0;
        }
        return accept(item);
      }
      case OverflowPolicy::NeverDrop:
        if (items_.size() >= capacity_) return SRESULT::CapacityExceeded;
        return accept(item);
    }
    return SRESULT::InvalidArgument;
  }

  /**
   * @brief Accepts a never-drop item above soft capacity, up to @p hard_cap.
   * @param[in,out] item Moved from when accepted.
   * @param[in] hard_cap Absolute depth limit.
   * @retval SRESULT::Ok               Accepted (counted as forced if above soft capacity).
   * @retval SRESULT::CapacityExceeded Hard cap reached; @p item untouched.
   */
  SRESULT force_push(T& item, std::size_t hard_cap) {
    if (items_.size() >= hard_cap) return SRESULT::CapacityExceeded;
    if (items_.size() >= capacity_) ++stats_.forced;
    return accept(item);
  }

  /**
   * @brief Removes the oldest item.
   * @param[out] out Receives the item.
   * @retval SRESULT::Ok
   * @retval SRESULT::NotFound Queue is empty.
   */
  SRESULT pop(T& out) {
    if (items_.empty()) return SRESULT::NotFound;
    out = std::move(items_.front());
    items_.pop_front();
    stats_.depth = items_.size();
    return SRESULT::Ok;
  }

  /**
   * @brief Reads the counters.
   * @param[out] out Snapshot of stats.
   * @return SRESULT::Ok.
   */
  SRESULT stats(QueueStats& out) const {
    out = stats_;
    out.depth = items_.size();
    return SRESULT::Ok;
  }

  /**
   * @brief Reports emptiness.
   * @param[out] out True if no items are queued.
   * @return SRESULT::Ok.
   */
  SRESULT empty(bool& out) const {
    out = items_.empty();
    return SRESULT::Ok;
  }

  /**
   * @brief Reads the soft capacity.
   * @param[out] out Capacity.
   * @return SRESULT::Ok.
   */
  SRESULT capacity(std::size_t& out) const {
    out = capacity_;
    return SRESULT::Ok;
  }

 private:
  /**
   * @brief Appends and updates counters.
   * @param[in,out] item Moved into the queue.
   * @return SRESULT::Ok.
   */
  SRESULT accept(T& item) {
    items_.push_back(std::move(item));
    ++stats_.pushed;
    stats_.depth = items_.size();
    if (stats_.depth > stats_.high_water) stats_.high_water = stats_.depth;
    return SRESULT::Ok;
  }

  std::size_t capacity_;            ///< Soft capacity.
  std::deque<T> items_;             ///< FIFO storage.
  QueueStats stats_;                ///< Counters.
  std::size_t sample_counter_ = 0;  ///< Sample policy phase.
};

}  // namespace ieso
