/**
 * @file runtime.hpp
 * @brief Owns actors and their threads; starts/stops them in order and runs coalescing timers.
 */
#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "ieso/core/actor.hpp"
#include "ieso/core/bus.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief Timer handle.
using TimerId = std::uint64_t;

/**
 * @brief Actor runtime.
 * @details start(): on_start() for each actor in registration order, then one thread per actor.
 *          stop(): timers first, then actors in reverse order (close mailbox, drain, on_stop, join).
 *          Timers post tasks into the actor's control lane; a tick is skipped while the previous one
 *          is still queued, so a slow actor never accumulates ticks.
 */
class Runtime {
 public:
  /**
   * @brief Binds the bus.
   * @param[in] bus Bus passed to actors; must outlive the runtime.
   */
  explicit Runtime(EventBus& bus);
  /// @brief Stops everything if still running.
  ~Runtime();
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  /**
   * @brief Registers an actor (before start()).
   * @param[in] actor Actor.
   * @retval SRESULT::Ok
   * @retval SRESULT::NullPointer  Empty actor.
   * @retval SRESULT::InvalidState Already started.
   */
  SRESULT add(std::shared_ptr<Actor> actor);

  /**
   * @brief Starts all actors and the timer thread.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidState Already started.
   * @return Otherwise the failing actor's on_start() code (already-started actors are stopped).
   */
  SRESULT start();

  /**
   * @brief Stops timers and actors; idempotent.
   * @retval SRESULT::Ok
   * @retval SRESULT::NoOp Not running.
   */
  SRESULT stop();

  /**
   * @brief Runs @p task on @p actor's thread every @p period.
   * @param[in] actor Target actor (held weakly).
   * @param[in] period Interval (> 0).
   * @param[in] task Work; failures are traced as WARNING.
   * @param[out] out Timer id for cancel_timer().
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidArgument Bad period or empty task/actor.
   */
  SRESULT schedule_every(const std::shared_ptr<Actor>& actor, std::chrono::milliseconds period,
                                       Task task, TimerId& out);

  /**
   * @brief Cancels a timer.
   * @param[in] id Timer id.
   * @retval SRESULT::Ok
   * @retval SRESULT::NotFound Unknown id.
   */
  SRESULT cancel_timer(TimerId id);

 private:
  /// @brief One periodic timer.
  struct Timer {
    TimerId id = 0;                                 ///< Handle.
    std::weak_ptr<Mailbox> mailbox;                 ///< Target inbox.
    std::chrono::milliseconds period{0};            ///< Interval.
    std::chrono::steady_clock::time_point next{};   ///< Next deadline.
    std::shared_ptr<Task> task;                     ///< Shared with queued ticks.
    std::shared_ptr<std::atomic<bool>> pending;     ///< Tick queued and not yet run.
  };

  /// @brief Timer thread body; exits when stopping_ is set. @return SRESULT::Ok.
  SRESULT timer_loop();
  /// @brief Stops actors [0, count) in reverse order. @param[in] count Number started. @return SRESULT::Ok.
  SRESULT stop_actors(std::size_t count);

  EventBus& bus_;                                  ///< Bus.
  std::vector<std::shared_ptr<Actor>> actors_;     ///< Registration order.
  std::vector<std::thread> threads_;               ///< One per actor, same order.
  std::thread timer_thread_;                       ///< Timer service.
  std::mutex timer_mu_;                            ///< Guards timers_.
  std::condition_variable timer_cv_;               ///< Wakes the timer thread.
  bool stopping_ = false;                          ///< Timer thread exit flag (guarded by timer_mu_).
  std::vector<Timer> timers_;                      ///< Active timers.
  TimerId next_timer_ = 1;                         ///< Next handle.
  bool timers_changed_ = false;                    ///< Wakes the timer wait early.
  bool running_ = false;                           ///< Between start() and stop().
};

}  // namespace ieso
