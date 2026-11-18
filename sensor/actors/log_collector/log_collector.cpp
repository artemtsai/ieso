/**
 * @file log_collector.cpp
 * @brief LogCollectorActor, LogStreamSource and the ndjson line parser.
 */
#include "log_collector/log_collector.hpp"

#include <cctype>

#include "ieso/core/json_reader.hpp"
#include "ieso/core/trace.hpp"
#include "ieso/macos/subprocess.hpp"

namespace ieso::macos {
namespace {
constexpr std::string_view kComponent = "logs";
}  // namespace

SRESULT parse_log_stream_line(std::string_view line, LogStreamRecord& out) {
  if (line.empty() || line.front() != '{') return SRESULT::NoOp;  // "Filtering the log data using ..." banner
  std::shared_ptr<const JsonValue> v;
  if (HS_FAILED(JsonValue::Parse(line, v))) return SRESULT::CorruptData;
  std::string type;
  if (v->get_string("eventType", type) == SRESULT::Ok && type != "logEvent") return SRESULT::NoOp;
  LogStreamRecord r;
  if (v->get_string("eventMessage", r.message) != SRESULT::Ok) return SRESULT::NoOp;
  (void)v->get_string("subsystem", r.subsystem);  // optional members
  (void)v->get_string("category", r.category);
  (void)v->get_int("processID", r.pid);
  std::string image;
  if (v->get_string("processImagePath", image) == SRESULT::Ok) {
    const auto slash = image.find_last_of('/');
    r.process = slash == std::string::npos ? image : image.substr(slash + 1);
  }
  std::string level;
  (void)v->get_string("messageType", level);
  for (char& c : level) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  r.level = level.empty() ? "default" : level;
  out = std::move(r);
  return SRESULT::Ok;
}

SRESULT log_predicate(const std::string& target, std::string& out) {
  out = "process == \"" + target + "\" OR (process == \"tccd\" AND eventMessage CONTAINS \"" + target + "\")";
  return SRESULT::Ok;
}

// ---------------- LogStreamSource ----------------

LogStreamSource::LogStreamSource(EventBus& bus, EventFactory& factory, std::string predicate)
    : bus_(bus), factory_(factory), predicate_(std::move(predicate)) {}

LogStreamSource::~LogStreamSource() { (void)stop(); }

SRESULT LogStreamSource::start() {
  if (running_.exchange(true)) return SRESULT::NoOp;
  stop_.store(false);
  thread_ = std::thread([this] { (void)loop(); });  // loop() always returns Ok
  return SRESULT::Ok;
}

SRESULT LogStreamSource::stop() {
  if (!running_.exchange(false)) return SRESULT::NoOp;
  stop_.store(true);
  if (thread_.joinable()) thread_.join();
  return SRESULT::Ok;
}

SRESULT LogStreamSource::loop() {
  const std::vector<std::string> argv = {"/usr/bin/log", "stream", "--style", "ndjson", "--level", "debug",
                                         "--predicate", predicate_};
  while (!stop_.load()) {
    std::unique_ptr<Subprocess> p;
    if (HS_FAILED(Subprocess::Spawn(argv, p))) {
      std::this_thread::sleep_for(std::chrono::seconds(2));
      continue;
    }
    HS_TRACE_INFO(kComponent, "log stream started: {}", predicate_);
    std::uint64_t records = 0;
    while (!stop_.load()) {
      std::string line;
      const SRESULT r = p->read_line(line, std::chrono::milliseconds(250));
      if (r == SRESULT::Timeout) continue;
      if (r != SRESULT::Ok) break;  // log exited
      LogStreamRecord rec;
      if (parse_log_stream_line(line, rec) != SRESULT::Ok) continue;
      std::shared_ptr<LogRecordObserved> ev;
      if (HS_FAILED(factory_.make<LogRecordObserved>(ev))) continue;  // pool pressure: drop routine telemetry
      ev->pid = rec.pid;
      ev->subsystem = rec.subsystem;
      ev->category = rec.category;
      ev->level = rec.level;
      ev->message = rec.message;
      (void)bus_.post(std::move(ev));  // Routine/Sample: drops are counted by the bus
      ++records;
    }
    if (!stop_.load()) {
      HS_TRACE_WARNING(kComponent, "log stream exited after {} records; restarting in 2 s", records);
      std::this_thread::sleep_for(std::chrono::seconds(2));
    }
  }  // Subprocess destructor terminates and reaps `log`
  return SRESULT::Ok;
}

// ---------------- LogCollectorActor ----------------

LogCollectorActor::LogCollectorActor(EventBus& bus, EventFactory& factory, std::string target)
    : Actor("log_collector"), bus_(bus), factory_(factory), target_(std::move(target)) {}

SRESULT LogCollectorActor::on_start(ActorContext& /*ctx*/) {
  std::string predicate;
  HS_RETURN_IF_FAILED(log_predicate(target_, predicate));
  source_ = std::make_unique<LogStreamSource>(bus_, factory_, predicate);
  return source_->start();
}

SRESULT LogCollectorActor::on_stop() {
  if (source_) (void)source_->stop();  // NoOp if not running
  return Actor::on_stop();
}

}  // namespace ieso::macos
