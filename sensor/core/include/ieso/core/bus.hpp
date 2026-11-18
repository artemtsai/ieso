/**
 * @file bus.hpp
 * @brief Typed, asynchronous event bus with RAII subscriptions (DESIGN.md §3 "Actors on an event bus").
 * @details post() never blocks: it routes by dynamic type (RTTI) into each subscriber's mailbox lane.
 *          Routine overflow is dropped/sampled and counted. Never-drop overflow is spilled (sanitized,
 *          spillable events only) or force-queued up to a hard cap. Per-type counters are self-telemetry.
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <typeindex>
#include <unordered_map>
#include <vector>

#include "ontology/events.hpp"
#include "ieso/core/mailbox.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief Type-erased handler stored by the bus.
using EventHandler = std::function<SRESULT(const std::shared_ptr<const Event>&)>;

/// @brief Receives never-drop, spillable events that did not fit a subscriber's lane.
using SpillSink = std::function<SRESULT(const std::shared_ptr<const Event>&)>;

namespace detail {

/// @brief One subscriber registration; shared by the registry, queued tasks and the token.
struct SubscriberEntry {
  std::uint64_t id = 0;              ///< Registration id.
  std::weak_ptr<Mailbox> mailbox;    ///< Owner's inbox.
  EventHandler handler;              ///< Runs on the owner's thread.
  std::atomic<bool> active{true};    ///< Cleared by the token; queued tasks re-check it.
};

/// @brief Per-type routing slot and counters.
struct TypeSlot {
  std::string name;                                       ///< Type name.
  std::vector<std::shared_ptr<SubscriberEntry>> subs;     ///< Guarded by registry mutex.
  std::atomic<std::uint64_t> posted{0};                   ///< post() calls.
  std::atomic<std::uint64_t> delivered{0};                ///< Accepted by a lane.
  std::atomic<std::uint64_t> dropped{0};                  ///< Dropped by routine policy.
  std::atomic<std::uint64_t> spilled{0};                  ///< Sent to the spill sink.
  std::atomic<std::uint64_t> forced{0};                   ///< Queued above soft capacity.
  std::atomic<std::uint64_t> lost{0};                     ///< Never-drop refused at hard cap (bug/overload).
};

/// @brief Shared bus state; Subscriptions hold it weakly so bus teardown order does not matter.
struct BusRegistry {
  mutable std::shared_mutex mu;                                        ///< Guards slots and subs vectors.
  std::unordered_map<std::type_index, std::shared_ptr<TypeSlot>> slots;  ///< Routing table.
  std::atomic<std::uint64_t> next_id{1};                               ///< Registration ids.
};

}  // namespace detail

/**
 * @brief RAII subscription token; unsubscribes on destruction.
 * @note Move-only. After reset(), already-queued deliveries are skipped, never executed.
 * @warning Destroy on the owner actor's thread (or after it stopped) so a running handler is not raced.
 */
class Subscription {
 public:
  Subscription() = default;
  ~Subscription();
  Subscription(Subscription&& other) noexcept;
  Subscription& operator=(Subscription&& other) noexcept;
  Subscription(const Subscription&) = delete;
  Subscription& operator=(const Subscription&) = delete;

  /// @brief Unsubscribes now. @retval SRESULT::Ok @retval SRESULT::NoOp Already inactive.
  SRESULT reset();

  /**
   * @brief Reports whether the token is still registered.
   * @param[out] out True if active.
   * @return SRESULT::Ok.
   */
  SRESULT active(bool& out) const;

 private:
  friend class EventBus;
  /// @brief Created by EventBus::subscribe.
  Subscription(std::weak_ptr<detail::BusRegistry> reg, std::type_index type,
               std::shared_ptr<detail::SubscriberEntry> entry);

  std::weak_ptr<detail::BusRegistry> registry_;        ///< Bus state (weak).
  std::type_index type_{typeid(void)};                 ///< Subscribed type.
  std::shared_ptr<detail::SubscriberEntry> entry_;     ///< Registration.
};

/// @brief Per-type counters snapshot.
struct TypeStats {
  std::string type;              ///< Event type name.
  std::size_t subscribers = 0;   ///< Active subscribers.
  std::uint64_t posted = 0;      ///< post() calls.
  std::uint64_t delivered = 0;   ///< Accepted by lanes.
  std::uint64_t dropped = 0;     ///< Routine drops.
  std::uint64_t spilled = 0;     ///< Spilled to spool.
  std::uint64_t forced = 0;      ///< Above soft capacity.
  std::uint64_t lost = 0;        ///< Refused at hard cap.
};

/**
 * @brief The event bus.
 * @note Thread-safe. Actors never reference each other; they only post and subscribe.
 */
class EventBus {
 public:
  EventBus();

  /**
   * @brief Subscribes @p mailbox to events of exact type @p T.
   * @tparam T Concrete event type.
   * @param[in] mailbox Subscriber inbox; handler runs on its consumer thread.
   * @param[in] handler Called with the immutable event.
   * @param[out] out RAII token.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidArgument Empty mailbox or handler.
   */
  template <class T>
  SRESULT subscribe(const std::shared_ptr<Mailbox>& mailbox,
                                  std::function<SRESULT(const std::shared_ptr<const T>&)> handler,
                                  Subscription& out) {
    static_assert(std::is_base_of_v<Event, T>, "T must derive from Event");
    if (!mailbox || !handler) return SRESULT::InvalidArgument;
    EventHandler erased = [h = std::move(handler)](const std::shared_ptr<const Event>& e) -> SRESULT {
      return h(std::static_pointer_cast<const T>(e));  // routed by exact typeid(T): cast is safe
    };
    return subscribe_impl(std::type_index(typeid(T)), T::kTypeName, mailbox, std::move(erased), out);
  }

  /**
   * @brief Posts an immutable event to all subscribers of its dynamic type. Never blocks.
   * @param[in] ev Event; header must be filled (EventFactory).
   * @retval SRESULT::Ok        Queued for every live subscriber.
   * @retval SRESULT::NoOp      No subscribers.
   * @retval SRESULT::Dropped   Dropped for at least one subscriber (routine policy).
   * @retval SRESULT::Spilled   Handed to the spill sink for at least one subscriber.
   * @retval SRESULT::NullPointer Empty @p ev.
   * @retval SRESULT::CapacityExceeded Never-drop event refused at hard cap (traced ERROR).
   */
  SRESULT post(std::shared_ptr<const Event> ev);

  /**
   * @brief Installs the spill sink (normally the spooler).
   * @param[in] sink Called on the posting thread; must not block. Empty disables spilling.
   * @return SRESULT::Ok.
   */
  SRESULT set_spill_sink(SpillSink sink);

  /**
   * @brief Snapshot of per-type counters, sorted by type name.
   * @param[out] out Stats.
   * @return SRESULT::Ok.
   */
  SRESULT stats(std::vector<TypeStats>& out) const;

 private:
  /// @brief Non-template part of subscribe(). @return SRESULT::Ok.
  SRESULT subscribe_impl(std::type_index type, std::string_view name,
                                       const std::shared_ptr<Mailbox>& mailbox, EventHandler handler,
                                       Subscription& out);
  /**
   * @brief Finds or creates the slot for @p type.
   * @param[in] type Event type.
   * @param[in] name Type name for stats.
   * @param[out] out Slot.
   * @return SRESULT::Ok.
   */
  SRESULT slot_for(std::type_index type, std::string_view name, std::shared_ptr<detail::TypeSlot>& out);

  std::shared_ptr<detail::BusRegistry> registry_;  ///< Shared with tokens (weakly).
  mutable std::mutex spill_mu_;                    ///< Guards spill_.
  SpillSink spill_;                                ///< Overflow target.
};

}  // namespace ieso
