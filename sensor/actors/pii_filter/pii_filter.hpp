/**
 * @file pii_filter.hpp
 * @brief The PII Filter actor: the only producer of CloudEventSanitized (DESIGN.md §9.6, FR-5, NFR-7).
 * @details Subscribes to exactly the egress-eligible types in AllEvents (compile-time selection).
 *          Every string field is redacted; free-text fields are also truncated.
 *          The envelope keeps the source event id, so retries dedupe at the backend.
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "ieso/core/actor.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"
#include "ieso/core/redactor.hpp"

namespace ieso {

static_assert(!CloudEventSanitized::kEgress, "the filter must never see its own output");

/**
 * @brief PII Filter actor.
 * @note Subscribes only to types with kEgress == true; it cannot receive anything else.
 */
class PiiFilter final : public Actor {
 public:
  /**
   * @brief Creates the filter.
   * @param[in] bus Bus to post envelopes to; must outlive the actor.
   * @param[in] factory Event factory; must outlive the actor.
   * @param[in] redactor Redaction rules (holds the IP salt).
   */
  PiiFilter(EventBus& bus, EventFactory& factory, Redactor redactor);

  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;

  /**
   * @brief Builds a sanitized envelope for @p ev (also used directly by tests).
   * @param[in] ev Egress-eligible event.
   * @param[out] out Envelope with redacted data, source id/class/overflow copied.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidArgument @p ev is not egress-eligible.
   * @retval SRESULT::OutOfMemory     Pool exhausted.
   */
  SRESULT sanitize(const Event& ev, std::shared_ptr<CloudEventSanitized>& out) const;

  /**
   * @brief Number of envelopes posted so far.
   * @param[out] out Count.
   * @return SRESULT::Ok.
   */
  SRESULT sanitized_count(std::uint64_t& out) const;

 private:
  /// @brief Subscribes to T if it is egress-eligible. @tparam T Event type. @param[in] bus Bus. @return Ok.
  template <class T>
  SRESULT subscribe_if_egress(EventBus& bus) {
    if constexpr (is_egress_eligible_v<T>) {
      return subscribe<T>(bus, [this](const std::shared_ptr<const T>& e) { return on_event(*e); });
    } else {
      return SRESULT::Ok;
    }
  }

  /// @brief Applies subscribe_if_egress to every type in a TypeList. @tparam T Types. @param[in] bus Bus. @return Ok or first failure.
  template <class... T>
  SRESULT subscribe_all(EventBus& bus, TypeList<T...> /*types*/) {
    SRESULT r = SRESULT::Ok;
    ((r = HS_SUCCEEDED(r) ? subscribe_if_egress<T>(bus) : r), ...);
    return r;
  }

  /// @brief Handler: sanitize and post. @param[in] ev Source event. @return Result of post or sanitize.
  SRESULT on_event(const Event& ev);

  EventBus& bus_;                           ///< Egress bus.
  EventFactory& factory_;                   ///< Envelope allocation.
  const Redactor redactor_;                 ///< Rules.
  std::string source_;                      ///< CloudEvents source URI.
  std::atomic<std::uint64_t> sanitized_{0};  ///< Posted envelopes.
};

}  // namespace ieso
