/**
 * @file spooler.hpp
 * @brief Spooler actor: store-and-forward with priority, rate-limited, backed-off replay (DESIGN.md §9.7).
 * @details SpooledEvent -> spool.put (re-spool in place). TelemetryDelivered -> ack + reset backoff.
 *          NetworkStatusChanged(online) -> start draining; offline -> release in-flight records.
 *          A replay that fails again arrives as SpooledEvent while online -> exponential backoff with jitter.
 *          It also installs the bus spill sink, so full never-drop envelopes land here instead of being lost.
 */
#pragma once

#include <chrono>
#include <memory>

#include "ieso/core/actor.hpp"
#include "ieso/core/clock.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"
#include "ieso/core/flow_control.hpp"
#include "ieso/core/spool.hpp"

namespace ieso {

/// @brief Spooler timing and rate options.
struct SpoolerOptions {
  std::chrono::milliseconds drain_tick{100};       ///< Drain timer period.
  std::chrono::milliseconds purge_period{60000};   ///< TTL purge + SpoolStorageUpdated period.
  double replay_per_second = config::kReplayPerSecond;  ///< Token-bucket rate.
  double replay_burst = config::kReplayBurst;            ///< Token-bucket burst.
  std::chrono::milliseconds backoff_base = config::kBackoffBase;  ///< First backoff ceiling.
  std::chrono::milliseconds backoff_cap = config::kBackoffCap;    ///< Max backoff ceiling.
  std::uint64_t seed = 0x5eed;                     ///< Jitter seed.
};

/**
 * @brief Spooler actor; owns the Spool.
 */
class SpoolerActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Event factory; must outlive the actor.
   * @param[in] clock Clock for backoff and rate limiting; must outlive the actor.
   * @param[in] spool Opened spool (ownership moves in).
   * @param[in] opts Options.
   */
  SpoolerActor(EventBus& bus, EventFactory& factory, const IClock& clock, std::unique_ptr<Spool> spool,
               SpoolerOptions opts = {});

  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;
  /// @copydoc Actor::on_stop
  SRESULT on_stop() override;

 private:
  /// @brief Stores an undeliverable envelope. @param[in] ev Event. @return Result of put.
  SRESULT on_spooled(const std::shared_ptr<const SpooledEvent>& ev);
  /// @brief Online/offline transition. @param[in] ev Event. @return SRESULT::Ok.
  SRESULT on_network(const std::shared_ptr<const NetworkStatusChanged>& ev);
  /// @brief Deletes acknowledged records. @param[in] ev Event. @return SRESULT::Ok.
  SRESULT on_delivered(const std::shared_ptr<const TelemetryDelivered>& ev);
  /// @brief Replays a rate-limited batch when online and not backing off. @return SRESULT::Ok or NoOp.
  SRESULT drain_tick();
  /// @brief Purges expired records and posts SpoolStorageUpdated. @return SRESULT::Ok.
  SRESULT purge_tick();
  /// @brief Posts SpoolStorageUpdated. @return Result of post.
  SRESULT publish_storage();
  /// @brief Spill sink body (runs on the posting thread). @param[in] ev Overflowing event. @return Result of post.
  SRESULT spill(const std::shared_ptr<const Event>& ev);

  EventBus& bus_;                              ///< Bus.
  EventFactory& factory_;                      ///< Event allocation.
  const IClock& clock_;                        ///< Time.
  std::unique_ptr<Spool> spool_;               ///< Owned spool.
  const SpoolerOptions opts_;                  ///< Options.
  Backoff backoff_;                            ///< Replay backoff.
  TokenBucket bucket_;                         ///< Replay rate limit.
  bool online_ = false;                        ///< Backend reachable.
  std::chrono::steady_clock::time_point paused_until_{};  ///< Backoff deadline.
};

}  // namespace ieso
