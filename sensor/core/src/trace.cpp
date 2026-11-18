/**
 * @file trace.cpp
 * @brief Tracing facade implementation: global sink, line formatting, sinks.
 */
#include "ieso/core/trace.hpp"

#include <cstdio>
#include <functional>

#include "ieso/core/time_util.hpp"

namespace ieso::trace {
namespace {

/// @brief Process-wide sink state guarded by a mutex (swap is rare, emit copies the pointer).
struct SinkState {
  std::mutex mu;                       ///< Guards sink.
  std::shared_ptr<ITraceSink> sink;    ///< Current sink; never empty after init.
};

/// @brief Global sink state. @warning Do not trace from other static initializers.
SinkState g_sink{{}, std::make_shared<StderrSink>()};

/**
 * @brief Strips directories from a path.
 * @param[in] path Full path.
 * @param[out] out Basename view into @p path.
 * @return SRESULT::Ok.
 */
SRESULT basename_of(std::string_view path, std::string_view& out) {
  const auto pos = path.find_last_of('/');
  out = (pos == std::string_view::npos) ? path : path.substr(pos + 1);
  return SRESULT::Ok;
}

}  // namespace

SRESULT set_level(Level level) {
  detail::g_level.store(static_cast<std::uint8_t>(level), std::memory_order_relaxed);
  return SRESULT::Ok;
}

SRESULT get_level(Level& out) {
  out = static_cast<Level>(detail::g_level.load(std::memory_order_relaxed));
  return SRESULT::Ok;
}

SRESULT set_sink(std::shared_ptr<ITraceSink> sink) {
  std::lock_guard lock(g_sink.mu);
  g_sink.sink = sink ? std::move(sink) : std::make_shared<StderrSink>();
  return SRESULT::Ok;
}

SRESULT level_name(Level level, std::string_view& out) {
  switch (level) {
    case Level::Off: out = "OFF"; break;
    case Level::Fatal: out = "FATAL"; break;
    case Level::Error: out = "ERROR"; break;
    case Level::Warning: out = "WARNING"; break;
    case Level::Info: out = "INFO"; break;
    case Level::Debug: out = "DEBUG"; break;
    case Level::Trace: out = "TRACE"; break;
    default: out = "?"; break;
  }
  return SRESULT::Ok;
}

SRESULT format_line(const Record& rec, std::string& out) {
  std::string_view lvl;
  HS_RETURN_IF_FAILED(level_name(rec.level, lvl));
  std::string ts;
  HS_RETURN_IF_FAILED(format_utc_ms(rec.ts, ts));
  const auto tid = std::hash<std::thread::id>{}(rec.thread) % 100000;
  out = fmt::format("{} {:<7} [{}] {}:{} t{} {}", ts, lvl, rec.component, rec.file, rec.line, tid, rec.message);
  return SRESULT::Ok;
}

SRESULT emit(Level level, std::string_view component, std::string_view file, int line, std::string message) {
  std::shared_ptr<ITraceSink> sink;
  {
    std::lock_guard lock(g_sink.mu);
    sink = g_sink.sink;
  }
  Record rec;
  rec.level = level;
  rec.ts = std::chrono::system_clock::now();
  rec.thread = std::this_thread::get_id();
  rec.component = component;
  HS_RETURN_IF_FAILED(basename_of(file, rec.file));
  rec.line = line;
  rec.message = message;
  return sink->write(rec);
}

SRESULT StderrSink::write(const Record& rec) {
  std::string line;
  HS_RETURN_IF_FAILED(format_line(rec, line));
  line.push_back('\n');
  std::lock_guard lock(mu_);
  return (std::fputs(line.c_str(), stderr) >= 0) ? SRESULT::Ok : SRESULT::IoError;
}

SRESULT MemorySink::write(const Record& rec) {
  std::string line;
  HS_RETURN_IF_FAILED(format_line(rec, line));
  std::lock_guard lock(mu_);
  lines_.push_back(std::move(line));
  return SRESULT::Ok;
}

SRESULT MemorySink::lines(std::vector<std::string>& out) const {
  std::lock_guard lock(mu_);
  out = lines_;
  return SRESULT::Ok;
}

SRESULT MemorySink::clear() {
  std::lock_guard lock(mu_);
  lines_.clear();
  return SRESULT::Ok;
}

}  // namespace ieso::trace
