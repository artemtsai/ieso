/**
 * @file outbox.hpp
 * @brief Stand-in for the mTLS Cloud Client until step 3: "delivers" sanitized envelopes to an NDJSON file.
 * @details Each CloudEventSanitized becomes one CloudEvents JSON line, then TelemetryDelivered acks it,
 *          so the spool/ack path behaves as with a real backend. The smoke test asserts on this file.
 */
#pragma once

#include <filesystem>
#include <fstream>

#include "ieso/core/actor.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"

namespace ieso {

/**
 * @brief File outbox actor.
 */
class FileOutboxActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] path NDJSON file (appended).
   */
  FileOutboxActor(EventBus& bus, EventFactory& factory, std::filesystem::path path);

  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;
  /// @copydoc Actor::on_stop
  SRESULT on_stop() override;

 private:
  /// @brief Appends and acks one envelope. @param[in] env Envelope. @return Ok or IoError.
  SRESULT deliver(const std::shared_ptr<const CloudEventSanitized>& env);

  EventBus& bus_;                    ///< Bus.
  EventFactory& factory_;            ///< Factory.
  const std::filesystem::path path_; ///< Output file.
  std::ofstream out_;                ///< Open stream (actor thread only).
};

}  // namespace ieso
