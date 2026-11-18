/**
 * @file test_util.hpp
 * @brief Shared test helpers: polling waits, temp directories, a collecting actor, a wired test rig.
 */
#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <fmt/format.h>

#include "ieso/core/actor.hpp"
#include "ieso/core/bus.hpp"
#include "ieso/core/clock.hpp"
#include "ieso/core/event_factory.hpp"
#include "ieso/core/pools.hpp"
#include "ieso/core/runtime.hpp"
#include "ieso/core/uuid.hpp"

namespace ieso::test {

/**
 * @brief Polls @p pred until true or timeout.
 * @param[in] pred Condition.
 * @param[in] timeout Deadline.
 * @return SRESULT::Ok or SRESULT::Timeout.
 */
inline SRESULT wait_until(const std::function<bool()>& pred,
                          std::chrono::milliseconds timeout = std::chrono::milliseconds(3000)) {
  const auto end = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < end) {
    if (pred()) return SRESULT::Ok;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return pred() ? SRESULT::Ok : SRESULT::Timeout;
}

/// @brief Unique temp directory removed on destruction.
class TempDir {
 public:
  TempDir() {
    std::error_code ec;
    std::random_device rd;
    path_ = std::filesystem::temp_directory_path(ec) / fmt::format("ieso-test-{:x}", rd());
    std::filesystem::create_directories(path_, ec);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;
  /// @brief Directory path. @param[out] out Path. @return SRESULT::Ok.
  SRESULT path(std::filesystem::path& out) const {
    out = path_;
    return SRESULT::Ok;
  }

 private:
  std::filesystem::path path_;  ///< Directory.
};

/**
 * @brief Actor that records every received event of type T (thread-safe snapshot).
 * @tparam T Event type.
 */
template <class T>
class Collector final : public Actor {
 public:
  /// @brief Creates the collector. @param[in] name Actor name. @param[in] caps Mailbox capacities.
  explicit Collector(std::string name = "collector", MailboxCapacities caps = {}) : Actor(std::move(name), caps) {}
  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override {
    return subscribe<T>(ctx.bus, [this](const std::shared_ptr<const T>& e) {
      if (gate_) {
        SRESULT g = gate_();
        (void)g;  // gate only delays
      }
      std::lock_guard lock(mu_);
      got_.push_back(e);
      return SRESULT::Ok;
    });
  }
  /// @brief Snapshot of received events. @param[out] out Events. @return SRESULT::Ok.
  SRESULT received(std::vector<std::shared_ptr<const T>>& out) const {
    std::lock_guard lock(mu_);
    out = got_;
    return SRESULT::Ok;
  }
  /// @brief Number received. @param[out] out Count. @return SRESULT::Ok.
  SRESULT count(std::size_t& out) const {
    std::lock_guard lock(mu_);
    out = got_.size();
    return SRESULT::Ok;
  }
  /// @brief Runs before each record (e.g. to block the handler). @param[in] g Gate. @return SRESULT::Ok.
  SRESULT set_gate(std::function<SRESULT()> g) {
    gate_ = std::move(g);
    return SRESULT::Ok;
  }
  /// @brief Exposes the protected unsubscribe for tests. @return SRESULT::Ok.
  SRESULT drop_subscriptions() { return unsubscribe_all(); }

 private:
  mutable std::mutex mu_;                       ///< Guards got_.
  std::vector<std::shared_ptr<const T>> got_;   ///< Received events.
  std::function<SRESULT()> gate_;               ///< Optional pre-hook.
};

/**
 * @brief Counts received events as an atomic, for polling from the test thread.
 * @tparam T Collector event type.
 * @param[in] c Collector.
 * @return Number of events.
 */
template <class T>
std::size_t count_of(const Collector<T>& c) {
  std::size_t n = 0;
  (void)c.count(n);  // always Ok
  return n;
}

/// @brief Pools + clock + uuid + factory + bus bundle used by most tests.
struct Rig {
  std::unique_ptr<Pools> pools = std::make_unique<Pools>(config::kEventPoolBytes);  ///< Pool.
  ManualClock clock;                                                                ///< Test clock.
  UuidGenerator uuid{clock, 42};                                                    ///< IDs.
  EventFactory factory{*pools, clock, uuid, "endpoint-test"};                       ///< Factory.
  EventBus bus;                                                                     ///< Bus.
};

}  // namespace ieso::test
