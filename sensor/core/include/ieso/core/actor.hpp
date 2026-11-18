/**
 * @file actor.hpp
 * @brief Actor base: one responsibility, one mailbox, one thread; talks only through the bus.
 */
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "ieso/core/bus.hpp"
#include "ieso/core/mailbox.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

class Runtime;

/// @brief Services available to an actor during on_start().
struct ActorContext {
  EventBus& bus;      ///< The bus.
  Runtime& runtime;   ///< For timers.
};

/**
 * @brief Base class of all actors.
 * @details Subscribe in on_start(); handlers then run serially on the actor's own thread, so actor state
 *          needs no locks. on_stop() runs on the same thread after the mailbox drained.
 * @warning Must be owned by std::shared_ptr (Runtime::add) because timers/subscriptions use weak refs.
 */
class Actor : public std::enable_shared_from_this<Actor> {
 public:
  /**
   * @brief Creates the actor and its mailbox.
   * @param[in] name Unique actor name for traces and stats.
   * @param[in] caps Mailbox lane capacities.
   */
  explicit Actor(std::string name, MailboxCapacities caps = {});
  virtual ~Actor() = default;
  Actor(const Actor&) = delete;
  Actor& operator=(const Actor&) = delete;

  /**
   * @brief Called once on the runtime thread before any actor thread starts. Subscribe here.
   * @param[in] ctx Bus and runtime.
   * @return SRESULT::Ok to continue; a failure aborts Runtime::start().
   */
  virtual SRESULT on_start(ActorContext& ctx) = 0;

  /**
   * @brief Called on the actor thread after the mailbox drained. Default drops subscriptions.
   * @return SRESULT::Ok.
   */
  virtual SRESULT on_stop();

  /**
   * @brief Actor name.
   * @param[out] out Name.
   * @return SRESULT::Ok.
   */
  SRESULT name(std::string& out) const;

  /**
   * @brief Actor inbox (shared with the bus and timers).
   * @param[out] out Mailbox.
   * @return SRESULT::Ok.
   */
  SRESULT mailbox(std::shared_ptr<Mailbox>& out) const;

 protected:
  /**
   * @brief Subscribes this actor to @p T and keeps the token until on_stop().
   * @tparam T Event type.
   * @param[in] bus Bus.
   * @param[in] handler Handler run on this actor's thread.
   * @return Result of EventBus::subscribe.
   */
  template <class T>
  SRESULT subscribe(EventBus& bus, std::function<SRESULT(const std::shared_ptr<const T>&)> handler) {
    Subscription s;
    HS_RETURN_IF_FAILED(bus.subscribe<T>(mailbox_, std::move(handler), s));
    subs_.push_back(std::move(s));
    return SRESULT::Ok;
  }

  /// @brief Drops all subscriptions. @return SRESULT::Ok.
  SRESULT unsubscribe_all();

 private:
  friend class Runtime;
  /**
   * @brief Thread body: drains the mailbox until closed, then calls on_stop().
   * @return Result of on_stop().
   */
  SRESULT run();

  const std::string name_;             ///< Name.
  std::shared_ptr<Mailbox> mailbox_;   ///< Inbox.
  std::vector<Subscription> subs_;     ///< Live subscriptions.
};

}  // namespace ieso
