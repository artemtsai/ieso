/**
 * @file event_source.hpp
 * @brief Interface for OS telemetry sources that run their own thread and post to the bus.
 * @details kqueue, FSEvents, `log stream` and Accessibility sources implement it today. A future
 *          Endpoint Security system extension plugs in behind the same interface over XPC (DESIGN.md §3),
 *          without touching the bus or the actors.
 */
#pragma once

#include "ieso/core/bus.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief A telemetry producer owned by an actor.
 * @note Sources receive the bus (by reference) at construction. start()/stop() are called on the owning
 *       actor's thread; the source posts from its own thread.
 */
class IEventSource {
 public:
  virtual ~IEventSource() = default;
  /**
   * @brief Starts producing.
   * @return SRESULT::Ok, or a failure (PermissionDenied, IoError, ...) traced at the origin.
   */
  virtual SRESULT start() = 0;
  /**
   * @brief Stops producing and joins internal threads; idempotent.
   * @return SRESULT::Ok or SRESULT::NoOp.
   */
  virtual SRESULT stop() = 0;
};

}  // namespace ieso
