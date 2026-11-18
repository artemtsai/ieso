/**
 * @file anomaly.hpp
 * @brief Anomaly Detection actor: judges hangs, leaks, resource limits and crash loops (DESIGN.md §8).
 * @details It only judges; capturing evidence is the Diagnostics actor's job.
 *          Every anomaly also requests log-verbosity escalation so the next occurrence carries debug logs.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <utility>

#include "ieso/core/actor.hpp"
#include "ieso/core/clock.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"

namespace ieso {

/// @brief Thresholds (policy-tunable in a later step).
struct AnomalyOptions {
  std::uint32_t hang_consecutive_timeouts = 3;              ///< Probe timeouts in a row to call a hang.
  std::chrono::milliseconds leak_window{30000};             ///< RSS slope window.
  double leak_slope_bytes_per_min = 100.0 * 1024 * 1024;    ///< RSS growth that counts as a leak.
  std::uint64_t rss_limit_bytes = 4ull << 30;               ///< Absolute RSS limit.
  std::uint32_t fd_limit = 4096;                            ///< Open-FD limit.
  std::uint64_t disk_free_min_bytes = 1ull << 30;           ///< Free-disk floor.
  std::chrono::milliseconds refire_interval{600000};        ///< Per-metric rate limit.
  std::uint32_t crash_loop_count = 3;                       ///< Crashes in the window to call a loop.
  std::chrono::milliseconds crash_loop_window{600000};      ///< Crash-loop window.
  std::int64_t escalation_duration_s = 900;                 ///< Debug-log duration per escalation.
};

/**
 * @brief Anomaly Detection actor.
 */
class AnomalyActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] clock Steady time for hang durations and rate limits.
   * @param[in] opts Thresholds.
   */
  AnomalyActor(EventBus& bus, EventFactory& factory, const IClock& clock, AnomalyOptions opts = {});

  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;

 private:
  /// @brief Hang judgement. @param[in] ev Probe result. @return Result of posts.
  SRESULT on_probe(const std::shared_ptr<const ResponsivenessProbed>& ev);
  /// @brief Resource judgement. @param[in] ev 1 s snapshot. @return Result of posts.
  SRESULT on_snapshot(const std::shared_ptr<const TelemetrySnapshotCaptured>& ev);
  /// @brief Crash-loop judgement. @param[in] ev Crash. @return Result of posts.
  SRESULT on_crash(const std::shared_ptr<const ProcessCrashDetected>& ev);
  /// @brief Resets per-process state. @param[in] ev Lifecycle. @return SRESULT::Ok.
  SRESULT on_lifecycle(const std::shared_ptr<const TargetLifecycle>& ev);
  /**
   * @brief Emits ResourceAnomalyDetected for @p metric unless rate-limited, then escalates.
   * @param[in] metric Metric name.
   * @param[in] value Observed value.
   * @param[in] baseline Expected value.
   * @param[in] trend Slope (units per minute).
   * @retval SRESULT::Ok    Emitted.
   * @retval SRESULT::NoOp  Rate-limited.
   */
  SRESULT fire(const std::string& metric, double value, double baseline, double trend);
  /// @brief Posts DiagnosticEscalationRequested. @param[in] reason Trigger. @return Result of post.
  SRESULT escalate(const std::string& reason);

  EventBus& bus_;                    ///< Bus.
  EventFactory& factory_;            ///< Factory.
  const IClock& clock_;              ///< Time.
  const AnomalyOptions opts_;        ///< Thresholds.
  std::int64_t pid_ = 0;             ///< Current target pid.
  std::string subsystem_;            ///< Target bundle id (escalation subsystem).
  std::uint32_t timeouts_ = 0;       ///< Consecutive probe timeouts.
  bool hang_reported_ = false;       ///< Current episode already reported.
  bool permission_warned_ = false;   ///< AX permission warning traced.
  std::chrono::steady_clock::time_point hang_start_{};                ///< First timeout of the episode.
  std::deque<std::pair<std::int64_t, std::uint64_t>> rss_window_;    ///< (ts_ms, rss) samples.
  std::map<std::string, std::chrono::steady_clock::time_point> last_fired_;  ///< Rate limit per metric.
  std::deque<std::chrono::steady_clock::time_point> crashes_;        ///< Recent crash times.
};

}  // namespace ieso
