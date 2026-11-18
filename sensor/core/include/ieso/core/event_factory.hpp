/**
 * @file event_factory.hpp
 * @brief Creates pool-allocated events with a filled header (id, endpoint, ts, routing traits).
 */
#pragma once

#include <memory>
#include <string>

#include "ieso/core/clock.hpp"
#include "ontology/events.hpp"
#include "ieso/core/pools.hpp"
#include "ieso/core/uuid.hpp"

namespace ieso {

/**
 * @brief Single place where events are born.
 * @note Thread-safe. The returned object is mutable until posted; post it as shared_ptr<const T>.
 */
class EventFactory {
 public:
  /**
   * @brief Binds dependencies; all must outlive the factory.
   * @param[in] pools Event memory pool.
   * @param[in] clock Time source for hdr.ts.
   * @param[in] uuid ID generator.
   * @param[in] endpoint_id Opaque endpoint identity.
   */
  EventFactory(Pools& pools, const IClock& clock, UuidGenerator& uuid, std::string endpoint_id)
      : pools_(pools), clock_(clock), uuid_(uuid), endpoint_id_(std::move(endpoint_id)) {}

  /**
   * @brief Allocates a T from the pool and fills its header from T's traits.
   * @tparam T Concrete event type with IESO_EVENT_TRAITS (or the same static traits).
   * @tparam A Constructor argument types.
   * @param[out] out New event.
   * @param[in] args Forwarded to T's constructor.
   * @retval SRESULT::Ok
   * @retval SRESULT::OutOfMemory Pool cap reached.
   */
  template <class T, class... A>
  SRESULT make(std::shared_ptr<T>& out, A&&... args) {
    std::shared_ptr<T> ev;
    HS_RETURN_IF_FAILED(pools_.allocate_shared<T>(ev, std::forward<A>(args)...));
    HS_RETURN_IF_FAILED(uuid_.next(ev->hdr.id));
    HS_RETURN_IF_FAILED(clock_.now_system(ev->hdr.ts));
    ev->hdr.endpoint_id = endpoint_id_;
    ev->hdr.cls = T::kClass;
    ev->hdr.overflow = T::kOverflow;
    ev->hdr.egress = T::kEgress;
    ev->hdr.spillable = T::kSpillable;
    out = std::move(ev);
    return SRESULT::Ok;
  }

  /**
   * @brief Endpoint identity used in headers.
   * @param[out] out Endpoint id.
   * @return SRESULT::Ok.
   */
  SRESULT endpoint_id(std::string& out) const {
    out = endpoint_id_;
    return SRESULT::Ok;
  }

 private:
  Pools& pools_;              ///< Memory.
  const IClock& clock_;       ///< Time.
  UuidGenerator& uuid_;       ///< IDs.
  const std::string endpoint_id_;  ///< Endpoint identity.
};

}  // namespace ieso
