/**
 * @file trace.hpp
 * @brief Minimal tracing facade with FATAL..TRACE levels and pluggable sinks.
 * @details Macros check the level before formatting, so disabled levels cost one atomic load.
 *          IESO_TRACE_COMPILE_LEVEL removes levels above it at compile time.
 *          The default sink writes to stderr; step 2 adds an os_log sink.
 */
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fmt/format.h>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "ieso/core/sresult.hpp"

#ifndef IESO_TRACE_COMPILE_LEVEL
/// @brief Highest level compiled in (6 = Trace keeps everything).
#define IESO_TRACE_COMPILE_LEVEL 6
#endif

namespace ieso::trace {

/// @brief Severity levels; lower value means more severe.
enum class Level : std::uint8_t { Off = 0, Fatal = 1, Error = 2, Warning = 3, Info = 4, Debug = 5, Trace = 6 };

/// @brief One trace record as delivered to a sink. Views are valid only during ITraceSink::write.
struct Record {
  Level level{Level::Info};                       ///< Severity.
  std::chrono::system_clock::time_point ts{};     ///< Wall-clock time of emission.
  std::thread::id thread{};                       ///< Emitting thread.
  std::string_view component;                     ///< Short component tag, e.g. "bus".
  std::string_view file;                          ///< Source file basename.
  int line{0};                                    ///< Source line.
  std::string_view message;                       ///< Formatted message.
};

/**
 * @brief Destination for trace records.
 * @warning write() may be called from any thread; implementations must be thread-safe.
 */
class ITraceSink {
 public:
  virtual ~ITraceSink() = default;
  /**
   * @brief Consumes one record.
   * @param[in] rec Record; views die after return.
   * @return SRESULT::Ok or SRESULT::IoError.
   */
  virtual SRESULT write(const Record& rec) = 0;
};

/// @brief Writes one formatted line per record to stderr.
class StderrSink final : public ITraceSink {
 public:
  /// @copydoc ITraceSink::write
  SRESULT write(const Record& rec) override;

 private:
  std::mutex mu_;  ///< Serializes lines from concurrent threads.
};

/// @brief Keeps formatted lines in memory; for tests and self-test output.
class MemorySink final : public ITraceSink {
 public:
  /// @copydoc ITraceSink::write
  SRESULT write(const Record& rec) override;
  /**
   * @brief Copies captured lines.
   * @param[out] out Lines in emission order.
   * @return SRESULT::Ok.
   */
  SRESULT lines(std::vector<std::string>& out) const;
  /// @brief Drops captured lines. @return SRESULT::Ok.
  SRESULT clear();

 private:
  mutable std::mutex mu_;          ///< Guards lines_.
  std::vector<std::string> lines_; ///< Captured lines.
};

namespace detail {
/// @brief Current runtime level; read lock-free by the macros.
inline std::atomic<std::uint8_t> g_level{static_cast<std::uint8_t>(Level::Info)};
}  // namespace detail

/**
 * @brief Sets the runtime minimum level.
 * @param[in] level Records more verbose than this are discarded.
 * @return SRESULT::Ok.
 */
SRESULT set_level(Level level);

/**
 * @brief Reads the runtime minimum level.
 * @param[out] out Current level.
 * @return SRESULT::Ok.
 */
SRESULT get_level(Level& out);

/**
 * @brief Replaces the process-wide sink.
 * @param[in] sink New sink; empty restores the stderr sink.
 * @return SRESULT::Ok.
 */
SRESULT set_sink(std::shared_ptr<ITraceSink> sink);

/**
 * @brief Returns the short name of a level ("ERROR", ...).
 * @param[in] level Level to name.
 * @param[out] out Static string.
 * @return SRESULT::Ok.
 */
SRESULT level_name(Level level, std::string_view& out);

/**
 * @brief Formats a record into one line: "ts LEVEL [component] file:line tid message".
 * @param[in] rec Record to format.
 * @param[out] out Formatted line without newline.
 * @return SRESULT::Ok.
 */
SRESULT format_line(const Record& rec, std::string& out);

/**
 * @brief Delivers a message to the current sink. Use the HS_TRACE_* macros instead.
 * @param[in] level Severity.
 * @param[in] component Component tag.
 * @param[in] file __FILE__ of the caller.
 * @param[in] line __LINE__ of the caller.
 * @param[in] message Formatted message.
 * @return Result of the sink write.
 */
SRESULT emit(Level level, std::string_view component, std::string_view file, int line,
                           std::string message);

}  // namespace ieso::trace

/// @brief Emits at @p lvl if enabled at compile time and runtime. Arguments are {fmt} style.
#define HS_TRACE_AT(lvl, component, ...)                                                          \
  do {                                                                                            \
    if constexpr (static_cast<int>(lvl) <= IESO_TRACE_COMPILE_LEVEL) {                          \
      if (static_cast<std::uint8_t>(lvl) <=                                                       \
          ::ieso::trace::detail::g_level.load(std::memory_order_relaxed)) {                     \
        (void)::ieso::trace::emit((lvl), (component), __FILE__, __LINE__, fmt::format(__VA_ARGS__)); \
      }                                                                                           \
    }                                                                                             \
  } while (0)

/// @brief Unrecoverable error: traces and aborts (launchd KeepAlive restarts the agent).
#define HS_TRACE_FATAL(component, ...)                                                        \
  do {                                                                                        \
    (void)::ieso::trace::emit(::ieso::trace::Level::Fatal, (component), __FILE__, __LINE__, \
                                fmt::format(__VA_ARGS__));                                    \
    std::abort();                                                                             \
  } while (0)
#define HS_TRACE_ERROR(component, ...) HS_TRACE_AT(::ieso::trace::Level::Error, component, __VA_ARGS__)
#define HS_TRACE_WARNING(component, ...) HS_TRACE_AT(::ieso::trace::Level::Warning, component, __VA_ARGS__)
#define HS_TRACE_INFO(component, ...) HS_TRACE_AT(::ieso::trace::Level::Info, component, __VA_ARGS__)
#define HS_TRACE_DEBUG(component, ...) HS_TRACE_AT(::ieso::trace::Level::Debug, component, __VA_ARGS__)
#define HS_TRACE_TRACE(component, ...) HS_TRACE_AT(::ieso::trace::Level::Trace, component, __VA_ARGS__)
