/**
 * @file resource_sampler.hpp
 * @brief Resource Sampler: polls libproc for the target and feeds the flight recorder (DESIGN.md §8, §9.3).
 * @details Every period (100 ms) -> ResourceSampled (internal). Every Nth (1 s) -> TelemetrySnapshotCaptured
 *          (egress, judged by the Anomaly actor). Runs only while the target is alive.
 */
#pragma once

#include <sys/types.h>

#include <chrono>
#include <cstdint>
#include <string>

#include "ieso/core/actor.hpp"
#include "ieso/core/clock.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"

namespace ieso::macos {

/// @brief Sampler options.
struct SamplerOptions {
  std::chrono::milliseconds period{100};  ///< Hot-ring resolution.
  std::uint32_t snapshot_every = 10;      ///< Samples per TelemetrySnapshotCaptured.
  std::string disk_path = "/";            ///< Volume for disk-free (the app's data volume).
};

/**
 * @brief Resource Sampler actor.
 */
class ResourceSamplerActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] clock Wall clock for sample timestamps.
   * @param[in] opts Options.
   */
  ResourceSamplerActor(EventBus& bus, EventFactory& factory, const IClock& clock, SamplerOptions opts = {});
  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;

 private:
  /// @brief Takes one sample if a target is alive. @return SRESULT::Ok or NoOp.
  SRESULT tick();

  EventBus& bus_;                 ///< Bus.
  EventFactory& factory_;         ///< Factory.
  const IClock& clock_;           ///< Time.
  const SamplerOptions opts_;     ///< Options.
  pid_t pid_ = 0;                 ///< Target (0 = none).
  std::uint64_t last_cpu_ns_ = 0; ///< Previous CPU time.
  std::int64_t last_wall_ns_ = 0; ///< Previous wall time (steady).
  std::uint32_t count_ = 0;       ///< Samples since launch.
  std::uint64_t disk_free_ = 0;   ///< Cached disk-free (refreshed per snapshot).
};

}  // namespace ieso::macos
