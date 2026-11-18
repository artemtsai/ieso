/**
 * @file ui_observer.hpp
 * @brief UI Observer: Accessibility responsiveness probe and error-dialog capture (DESIGN.md §9.1, FR-12).
 * @details AX requests are served by the target's main run loop, so an AX call that times out means the
 *          main thread is not servicing events: the outside-in view of a beachball.
 *          An AXObserver on window/sheet creation captures what the user saw (dialog title and text).
 * @warning Requires the Accessibility permission for the sensor process (MDM PPPC in production).
 */
#pragma once

#include <ApplicationServices/ApplicationServices.h>

#include <atomic>
#include <chrono>
#include <deque>
#include <memory>
#include <thread>
#include <utility>

#include "ieso/core/actor.hpp"
#include "ieso/core/event_factory.hpp"
#include "ieso/core/event_source.hpp"
#include "ontology/events.hpp"
#include "ieso/macos/cf_ref.hpp"

namespace ieso::macos {

/// @brief UI observer options.
struct UiObserverOptions {
  std::chrono::milliseconds probe_period{2000};  ///< Probe interval (§9.1).
  float probe_timeout_s = 1.0f;                  ///< AX messaging timeout.
  std::chrono::milliseconds dialog_settle{300};  ///< Wait before reading a new window's texts.
};

/**
 * @brief Periodic AX responsiveness probe source.
 */
class AxProbeSource final : public IEventSource {
 public:
  /**
   * @brief Configures the probe.
   * @param[in] bus Bus; must outlive the source.
   * @param[in] factory Factory; must outlive the source.
   * @param[in] opts Options.
   */
  AxProbeSource(EventBus& bus, EventFactory& factory, UiObserverOptions opts);
  ~AxProbeSource() override;
  /// @copydoc IEventSource::start
  SRESULT start() override;
  /// @copydoc IEventSource::stop
  SRESULT stop() override;
  /// @brief Sets the pid to probe (0 = idle). @param[in] pid Target. @return SRESULT::Ok.
  SRESULT set_pid(pid_t pid);
  /**
   * @brief Runs one probe now (also used by tests).
   * @param[in] pid Target.
   * @param[out] latency_ms AX round-trip time.
   * @param[out] timed_out True if the main run loop did not answer.
   * @param[out] permitted False without the Accessibility permission.
   * @return SRESULT::Ok.
   */
  SRESULT probe(pid_t pid, std::int64_t& latency_ms, bool& timed_out, bool& permitted);

 private:
  /// @brief Probe loop. @return SRESULT::Ok.
  SRESULT loop();

  EventBus& bus_;                    ///< Bus.
  EventFactory& factory_;            ///< Factory.
  const UiObserverOptions opts_;     ///< Options.
  std::atomic<pid_t> pid_{0};        ///< Target.
  std::thread thread_;               ///< Probe thread.
  std::atomic<bool> stop_{false};    ///< Exit flag.
  std::atomic<bool> running_{false}; ///< Started.
};

/**
 * @brief AXObserver source for dialogs/sheets; runs a private CFRunLoop thread.
 */
class AxDialogSource final : public IEventSource {
 public:
  /**
   * @brief Configures the source.
   * @param[in] bus Bus; must outlive the source.
   * @param[in] factory Factory; must outlive the source.
   * @param[in] opts Options.
   */
  AxDialogSource(EventBus& bus, EventFactory& factory, UiObserverOptions opts);
  ~AxDialogSource() override;
  /// @copydoc IEventSource::start
  SRESULT start() override;
  /// @copydoc IEventSource::stop
  SRESULT stop() override;
  /// @brief Sets the pid to observe (0 = none). @param[in] pid Target. @return SRESULT::Ok.
  SRESULT set_pid(pid_t pid);
  /**
   * @brief Queues a newly created window (AXObserver callback, run-loop thread only).
   * @param[in] window Borrowed element.
   * @return SRESULT::Ok.
   */
  SRESULT queue_window(AXUIElementRef window);

 private:
  /// @brief Run-loop thread body. @return SRESULT::Ok.
  SRESULT loop();
  /// @brief Attaches the observer to @p pid on the current run loop. @param[in] pid Target. @return Ok or error.
  SRESULT attach(pid_t pid);
  /// @brief Detaches the current observer. @return SRESULT::Ok.
  SRESULT detach();
  /// @brief Reads a window and posts UserVisibleErrorObserved if it is a dialog. @param[in] window Window. @return Ok or NoOp.
  SRESULT inspect(AXUIElementRef window);

  EventBus& bus_;                                        ///< Bus.
  EventFactory& factory_;                                ///< Factory.
  const UiObserverOptions opts_;                         ///< Options.
  std::atomic<pid_t> want_pid_{0};                       ///< Requested target.
  pid_t pid_ = 0;                                        ///< Attached target (run-loop thread).
  pid_t attempt_pid_ = 0;                                ///< Target the attach attempts are for (run-loop thread).
  int attempts_ = 0;                                     ///< Attach attempts made for attempt_pid_.
  std::chrono::steady_clock::time_point next_attempt_{}; ///< Earliest time of the next attach attempt.
  CfRef<AXObserverRef> observer_;                        ///< Observer (run-loop thread).
  CfRef<AXUIElementRef> app_;                            ///< App element (run-loop thread).
  std::deque<std::pair<CfRef<AXUIElementRef>, std::chrono::steady_clock::time_point>> windows_;  ///< To inspect.
  std::thread thread_;                                   ///< Run-loop thread.
  std::atomic<bool> stop_{false};                        ///< Exit flag.
  std::atomic<bool> running_{false};                     ///< Started.
};

/**
 * @brief UI Observer actor (owns the probe and dialog sources).
 */
class UiObserverActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] opts Options.
   */
  UiObserverActor(EventBus& bus, EventFactory& factory, UiObserverOptions opts = {});
  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;
  /// @copydoc Actor::on_stop
  SRESULT on_stop() override;

 private:
  EventBus& bus_;                           ///< Bus.
  EventFactory& factory_;                   ///< Factory.
  const UiObserverOptions opts_;            ///< Options.
  std::unique_ptr<AxProbeSource> probe_;    ///< Responsiveness probe.
  std::unique_ptr<AxDialogSource> dialogs_; ///< Dialog capture.
};

}  // namespace ieso::macos
