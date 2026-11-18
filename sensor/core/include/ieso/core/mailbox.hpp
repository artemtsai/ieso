/**
 * @file mailbox.hpp
 * @brief Per-actor inbox with three bounded lanes (control, incident, routine) drained in priority order.
 */
#pragma once

#include <array>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>

#include "ieso/core/bounded_queue.hpp"
#include "ieso/core/config.hpp"
#include "ontology/events.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief Unit of work executed on the owning actor's thread.
using Task = std::function<SRESULT()>;

/// @brief Soft capacities per lane.
struct MailboxCapacities {
  std::size_t control = config::kControlLaneCapacity;    ///< Control lane.
  std::size_t incident = config::kIncidentLaneCapacity;  ///< Incident lane.
  std::size_t routine = config::kRoutineLaneCapacity;    ///< Routine lane.
};

/// @brief Per-lane counters.
struct MailboxStats {
  QueueStats control;   ///< Control lane.
  QueueStats incident;  ///< Incident lane.
  QueueStats routine;   ///< Routine lane.
};

/**
 * @brief Thread-safe multi-producer, single-consumer inbox.
 * @note Pop order: all control, then incident, then routine (incidents beat telemetry).
 */
class Mailbox {
 public:
  /**
   * @brief Creates an open mailbox.
   * @param[in] name Owner name for traces.
   * @param[in] caps Soft capacities.
   */
  explicit Mailbox(std::string name, MailboxCapacities caps = {});

  /**
   * @brief Enqueues a task in @p lane using @p policy.
   * @param[in] lane Event class lane.
   * @param[in] policy Overflow policy.
   * @param[in,out] task Moved from when accepted.
   * @retval SRESULT::Ok / SRESULT::Dropped  See BoundedQueue::push.
   * @retval SRESULT::CapacityExceeded       Never-drop lane full; @p task untouched.
   * @retval SRESULT::Closed                 Mailbox closed.
   */
  SRESULT push(EventClass lane, OverflowPolicy policy, Task& task);

  /**
   * @brief Enqueues above soft capacity up to soft x kNeverDropHardMultiplier.
   * @param[in] lane Lane.
   * @param[in,out] task Moved from when accepted.
   * @retval SRESULT::Ok
   * @retval SRESULT::CapacityExceeded Hard cap reached.
   * @retval SRESULT::Closed           Mailbox closed.
   */
  SRESULT force_push(EventClass lane, Task& task);

  /**
   * @brief Blocks until a task is available or the mailbox is closed and drained.
   * @param[out] out Next task.
   * @retval SRESULT::Ok
   * @retval SRESULT::Closed Closed and empty (close() is the actor's stop signal).
   */
  SRESULT pop_wait(Task& out);

  /// @brief Rejects further pushes and wakes the consumer; queued tasks still drain. @return SRESULT::Ok.
  SRESULT close();

  /**
   * @brief Reads lane counters.
   * @param[out] out Stats.
   * @return SRESULT::Ok.
   */
  SRESULT stats(MailboxStats& out) const;

  /**
   * @brief Owner name.
   * @param[out] out Name.
   * @return SRESULT::Ok.
   */
  SRESULT name(std::string& out) const;

 private:
  const std::string name_;                 ///< Owner name.
  mutable std::mutex mu_;                  ///< Guards lanes_ and closed_.
  std::condition_variable cv_;             ///< Signals new work / close.
  std::array<BoundedQueue<Task>, 3> lanes_;  ///< Indexed by EventClass.
  bool closed_ = false;                    ///< No more pushes.
};

}  // namespace ieso
