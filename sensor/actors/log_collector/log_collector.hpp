/**
 * @file log_collector.hpp
 * @brief Log Collector: filtered `/usr/bin/log stream --style ndjson` for the app and related Apple subsystems.
 * @details DESIGN.md §2 ("logs are only somewhat helpful"), §8. Records become LogRecordObserved (Routine/Sample,
 *          egress through the PII filter). The stream is restarted with a delay if `log` exits.
 */
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "ieso/core/actor.hpp"
#include "ieso/core/event_factory.hpp"
#include "ieso/core/event_source.hpp"
#include "ontology/events.hpp"

namespace ieso::macos {

/// @brief Fields of one ndjson record.
struct LogStreamRecord {
  std::int64_t pid = 0;   ///< processID.
  std::string process;    ///< Basename of processImagePath.
  std::string subsystem;  ///< subsystem.
  std::string category;   ///< category.
  std::string level;      ///< messageType lowercased ("default", "error", ...).
  std::string message;    ///< eventMessage.
};

/**
 * @brief Parses one `log stream --style ndjson` line.
 * @param[in] line Text line.
 * @param[out] out Record.
 * @retval SRESULT::Ok
 * @retval SRESULT::NoOp        Not a log event (banner line, activity, ...).
 * @retval SRESULT::CorruptData Not JSON.
 */
SRESULT parse_log_stream_line(std::string_view line, LogStreamRecord& out);

/**
 * @brief Builds the `log stream` predicate for a target app.
 * @param[in] target App process name.
 * @param[out] out Predicate: the app's own records plus tccd records mentioning it.
 * @return SRESULT::Ok.
 */
SRESULT log_predicate(const std::string& target, std::string& out);

/**
 * @brief `log stream` subprocess source.
 */
class LogStreamSource final : public IEventSource {
 public:
  /**
   * @brief Configures the source.
   * @param[in] bus Bus; must outlive the source.
   * @param[in] factory Factory; must outlive the source.
   * @param[in] predicate NSPredicate for `log stream`.
   */
  LogStreamSource(EventBus& bus, EventFactory& factory, std::string predicate);
  ~LogStreamSource() override;
  /// @copydoc IEventSource::start
  SRESULT start() override;
  /// @copydoc IEventSource::stop
  SRESULT stop() override;

 private:
  /// @brief Spawn/read/respawn loop. @return SRESULT::Ok.
  SRESULT loop();

  EventBus& bus_;                  ///< Bus.
  EventFactory& factory_;          ///< Factory.
  const std::string predicate_;    ///< Filter.
  std::thread thread_;             ///< Reader.
  std::atomic<bool> stop_{false};  ///< Exit flag.
  std::atomic<bool> running_{false};  ///< Started.
};

/**
 * @brief Log Collector actor (owns the stream source).
 */
class LogCollectorActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] target App process name.
   */
  LogCollectorActor(EventBus& bus, EventFactory& factory, std::string target);
  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;
  /// @copydoc Actor::on_stop
  SRESULT on_stop() override;

 private:
  EventBus& bus_;                           ///< Bus.
  EventFactory& factory_;                   ///< Factory.
  const std::string target_;                ///< Target name.
  std::unique_ptr<LogStreamSource> source_; ///< Stream.
};

}  // namespace ieso::macos
