/**
 * @file process_watcher.cpp
 * @brief Process Watcher actor, kqueue exit source and FSEvents DiagnosticReports source.
 */
#include "process_watcher/process_watcher.hpp"

#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iterator>

#include <fmt/format.h>

#include "ieso/core/ips_parser.hpp"
#include "ieso/core/runtime.hpp"
#include "ieso/core/trace.hpp"
#include "ieso/macos/cf_ref.hpp"
#include "ieso/macos/proc_info.hpp"

namespace ieso::macos {
namespace {
constexpr std::string_view kComponent = "watcher";
constexpr int kMaxParseAttempts = 40;  // x 250 ms = 10 s for ReportCrash to finish writing
constexpr std::size_t kMaxSeenIncidents = 512;  // remembered report UUIDs (dedupe across moves)
constexpr std::int64_t kStartSlackMs = 60000;    // a crash just before the sensor started still counts

/**
 * @brief FSEvents callback (C API signature; exempt from the SRESULT rule).
 * @param[in] info The DiagnosticReportsSource registered in the stream context.
 * @param[in] n Number of events.
 * @param[in] paths C string array of paths.
 */
void on_fsevents(ConstFSEventStreamRef /*stream*/, void* info, size_t n, void* paths,
                 const FSEventStreamEventFlags* /*flags*/, const FSEventStreamEventId* /*ids*/) {
  auto& self = *static_cast<DiagnosticReportsSource*>(info);  // context pointer set in start()
  const auto* const* p = static_cast<const char* const*>(paths);
  for (size_t i = 0; i < n; ++i) (void)self.offer(p[i]);  // NoOp for unrelated files
}
}  // namespace

// ---------------- KqueueExitSource ----------------

KqueueExitSource::KqueueExitSource(EventBus& bus, EventFactory& factory) : bus_(bus), factory_(factory) {}

KqueueExitSource::~KqueueExitSource() { (void)stop(); }

SRESULT KqueueExitSource::start() {
  if (kq_ >= 0) return SRESULT::NoOp;
  kq_ = kqueue();
  if (kq_ < 0) {
    HS_TRACE_ERROR(kComponent, "kqueue failed: {}", std::strerror(errno));
    return SRESULT::IoError;
  }
  stop_.store(false);
  thread_ = std::thread([this] { (void)loop(); });  // loop() always returns Ok
  return SRESULT::Ok;
}

SRESULT KqueueExitSource::stop() {
  if (kq_ < 0) return SRESULT::NoOp;
  stop_.store(true);
  if (thread_.joinable()) thread_.join();
  close(kq_);
  kq_ = -1;
  return SRESULT::Ok;
}

SRESULT KqueueExitSource::post_exit(pid_t pid, std::int64_t status) {
  std::shared_ptr<TargetLifecycle> ev;
  HS_RETURN_IF_FAILED(factory_.make<TargetLifecycle>(ev));
  ev->phase = "exit";
  ev->pid = pid;
  ev->exit_status = status;
  {
    std::lock_guard lock(mu_);
    ev->bundle_id = bundle_id_;
    ev->version = version_;
  }
  HS_TRACE_INFO(kComponent, "target pid {} exited (status {})", pid, status);
  return bus_.post(std::move(ev));
}

SRESULT KqueueExitSource::watch(pid_t pid, const std::string& bundle_id, const std::string& version) {
  {
    std::lock_guard lock(mu_);
    bundle_id_ = bundle_id;
    version_ = version;
  }
  struct kevent kev {};
  EV_SET(&kev, static_cast<uintptr_t>(pid), EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT | NOTE_EXITSTATUS, 0,
         nullptr);
  if (kevent(kq_, &kev, 1, nullptr, 0, nullptr) != 0) {
    if (errno == ESRCH) {
      HS_RETURN_IF_FAILED(post_exit(pid, -1));
      return SRESULT::NotFound;
    }
    HS_TRACE_ERROR(kComponent, "kevent register pid {} failed: {}", pid, std::strerror(errno));
    return SRESULT::IoError;
  }
  return SRESULT::Ok;
}

SRESULT KqueueExitSource::loop() {
  while (!stop_.load()) {
    struct kevent ev {};
    const timespec timeout{0, 250 * 1000 * 1000};
    const int n = kevent(kq_, nullptr, 0, &ev, 1, &timeout);
    if (n <= 0) continue;
    if (ev.filter == EVFILT_PROC && (ev.fflags & NOTE_EXIT) != 0) {
      const int raw = static_cast<int>(ev.data);
      const std::int64_t status = WIFSIGNALED(raw) ? -WTERMSIG(raw) : WEXITSTATUS(raw);
      (void)post_exit(static_cast<pid_t>(ev.ident), status);  // post failure already traced by the bus
    }
  }
  return SRESULT::Ok;
}

// ---------------- CrashExitTracker ----------------

SRESULT CrashExitTracker::crash_signal_name(std::int64_t sig, std::string& out) {
  switch (sig) {
    case SIGSEGV: out = "SIGSEGV"; return SRESULT::Ok;
    case SIGBUS: out = "SIGBUS"; return SRESULT::Ok;
    case SIGABRT: out = "SIGABRT"; return SRESULT::Ok;
    case SIGILL: out = "SIGILL"; return SRESULT::Ok;
    case SIGFPE: out = "SIGFPE"; return SRESULT::Ok;
    case SIGTRAP: out = "SIGTRAP"; return SRESULT::Ok;
    default: return SRESULT::NotFound;  // SIGTERM/SIGKILL/normal exit: not a crash
  }
}

SRESULT CrashExitTracker::on_exit(pid_t pid, std::int64_t exit_status, const std::string& version,
                                  std::chrono::steady_clock::time_point now) {
  std::string name;
  if (exit_status >= 0 || crash_signal_name(-exit_status, name) != SRESULT::Ok) return SRESULT::NoOp;
  pending_.push_back({pid, -exit_status, version, now});
  if (pending_.size() > kMaxPending) pending_.pop_front();
  return SRESULT::Ok;
}

SRESULT CrashExitTracker::on_report(pid_t pid) {
  const auto before = pending_.size();
  pending_.erase(std::remove_if(pending_.begin(), pending_.end(), [pid](const Pending& p) { return p.pid == pid; }),
                 pending_.end());
  return pending_.size() == before ? SRESULT::NoOp : SRESULT::Ok;
}

SRESULT CrashExitTracker::due(std::chrono::steady_clock::time_point now, std::chrono::milliseconds grace,
                              std::vector<Pending>& out) {
  while (!pending_.empty() && now - pending_.front().at >= grace) {  // oldest first, bounded by kMaxPending
    out.push_back(std::move(pending_.front()));
    pending_.pop_front();
  }
  return SRESULT::Ok;
}

// ---------------- DiagnosticReportsSource ----------------

DiagnosticReportsSource::DiagnosticReportsSource(EventBus& bus, EventFactory& factory, const IClock& clock,
                                                 std::string target_name, std::vector<std::filesystem::path> dirs,
                                                 std::chrono::milliseconds max_age)
    : bus_(bus), factory_(factory), clock_(clock), target_(std::move(target_name)), max_age_(max_age),
      dirs_(std::move(dirs)) {}

DiagnosticReportsSource::~DiagnosticReportsSource() { (void)stop(); }

SRESULT DiagnosticReportsSource::start() {
  if (stream_ != nullptr) return SRESULT::NoOp;
  std::chrono::system_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_system(now));
  started_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  CfRef<CFMutableArrayRef> paths(CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks));
  for (const auto& d : dirs_) {
    std::error_code ec;
    if (!std::filesystem::exists(d, ec)) continue;
    CfRef<CFStringRef> s(CFStringCreateWithCString(kCFAllocatorDefault, d.c_str(), kCFStringEncodingUTF8));
    CFArrayAppendValue(*paths, *s);
  }
  if (CFArrayGetCount(*paths) == 0) {
    HS_TRACE_WARNING(kComponent, "no DiagnosticReports directory exists; crash reasons unavailable");
    return SRESULT::NotFound;
  }
  FSEventStreamContext ctx{0, this, nullptr, nullptr, nullptr};  // C API: info pointer back to this source
  stream_ = FSEventStreamCreate(kCFAllocatorDefault, &on_fsevents, &ctx, *paths, kFSEventStreamEventIdSinceNow, 0.25,
                                kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer);
  if (stream_ == nullptr) {
    HS_TRACE_ERROR(kComponent, "FSEventStreamCreate failed");
    return SRESULT::IoError;
  }
  queue_ = dispatch_queue_create("ieso.fsevents", DISPATCH_QUEUE_SERIAL);
  FSEventStreamSetDispatchQueue(stream_, queue_);
  if (!FSEventStreamStart(stream_)) {
    HS_TRACE_ERROR(kComponent, "FSEventStreamStart failed");
    (void)stop();
    return SRESULT::IoError;
  }
  stop_.store(false);
  thread_ = std::thread([this] { (void)loop(); });  // loop() always returns Ok
  HS_TRACE_INFO(kComponent, "watching {} DiagnosticReports dir(s) for {}-*.ips", CFArrayGetCount(*paths), target_);
  return SRESULT::Ok;
}

SRESULT DiagnosticReportsSource::stop() {
  if (stream_ == nullptr) return SRESULT::NoOp;
  stop_.store(true);
  if (thread_.joinable()) thread_.join();
  FSEventStreamStop(stream_);
  FSEventStreamInvalidate(stream_);
  FSEventStreamRelease(stream_);
  stream_ = nullptr;
  if (queue_ != nullptr) {
    dispatch_release(queue_);
    queue_ = nullptr;
  }
  return SRESULT::Ok;
}

SRESULT DiagnosticReportsSource::offer(const std::string& path) {
  const auto slash = path.find_last_of('/');
  const std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
  const std::string prefix = target_ + "-";
  if (base.compare(0, prefix.size(), prefix) != 0 || base.size() < 4 || base.substr(base.size() - 4) != ".ips") {
    return SRESULT::NoOp;
  }
  if (path.find("/Retired/") != std::string::npos) return SRESULT::NoOp;  // macOS moved an already-seen report
  std::lock_guard lock(mu_);
  if (seen_.count(path) != 0) return SRESULT::NoOp;
  for (const auto& p : pending_) {
    if (p.path == path) return SRESULT::NoOp;
  }
  pending_.push_back({path, 0});
  return SRESULT::Ok;
}

SRESULT DiagnosticReportsSource::try_parse(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return SRESULT::CorruptData;  // not there yet / not readable yet
  const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  CrashReport r;
  HS_RETURN_IF_FAILED(parse_ips(text, r));
  if (r.timestamp_ms > 0) {  // macOS rewrites and re-retires old reports: only crashes from this sensor's lifetime count
    std::chrono::system_clock::time_point now;
    HS_RETURN_IF_FAILED(clock_.now_system(now));
    const std::int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    const std::int64_t oldest = std::max(now_ms - max_age_.count(), started_ms_ > 0 ? started_ms_ - kStartSlackMs : 0);
    if (r.timestamp_ms < oldest) {
      HS_TRACE_DEBUG(kComponent, "report {} is about an old crash ({} s ago); ignored", path,
                     (now_ms - r.timestamp_ms) / 1000);
      return SRESULT::NoOp;
    }
  }
  {
    std::lock_guard lock(mu_);
    if (std::find(reported_pids_.begin(), reported_pids_.end(), static_cast<pid_t>(r.pid)) != reported_pids_.end()) {
      HS_TRACE_DEBUG(kComponent, "report {} for pid {} arrived after the exit-signal fallback; ignored", path, r.pid);
      return SRESULT::NoOp;
    }
  }
  if (!r.incident_id.empty()) {  // one crash, one event: the same report may show up under several paths
    std::lock_guard lock(mu_);
    if (seen_incidents_.count(r.incident_id) != 0) {
      HS_TRACE_DEBUG(kComponent, "report {} is crash {} again (moved); ignored", path, r.incident_id);
      return SRESULT::NoOp;
    }
    seen_incidents_.insert(r.incident_id);
    incident_order_.push_back(r.incident_id);
    if (incident_order_.size() > kMaxSeenIncidents) {
      seen_incidents_.erase(incident_order_.front());
      incident_order_.pop_front();
    }
  }
  std::shared_ptr<ProcessCrashDetected> ev;
  HS_RETURN_IF_FAILED(factory_.make<ProcessCrashDetected>(ev));
  ev->pid = r.pid;
  ev->exception_type = r.exception_type;
  ev->signal = r.signal;
  ev->termination_reason = r.termination_reason;
  ev->faulting_module = r.faulting_module;
  ev->offset = r.offset;
  ev->report_path = path;
  ev->exception_subtype = r.exception_subtype;
  ev->exception_codes = r.exception_codes;
  ev->app_version = r.app_version;
  ev->crashed_thread = r.crashed_thread;
  for (std::size_t i = 0; i < r.backtrace.size(); ++i) {  // bounded by kMaxCrashFrames
    const auto& fr = r.backtrace[i];
    ev->backtrace += fmt::format("{} {} +0x{:x}", i, fr.image, fr.offset);
    if (!fr.symbol.empty()) ev->backtrace += fmt::format(" {} + {}", fr.symbol, fr.symbol_location);
    ev->backtrace += '\n';
  }
  HS_TRACE_WARNING(kComponent, "CRASH detected: {} pid {} {} {} at {}+0x{:x}", r.proc_name, r.pid, r.exception_type,
                   r.signal, r.faulting_module, r.offset);
  const SRESULT posted = bus_.post(std::move(ev));
  return HS_FAILED(posted) ? posted : SRESULT::Ok;  // NoOp from the bus (no subscribers) is still "posted"
}

SRESULT DiagnosticReportsSource::mark_reported(pid_t pid) {
  std::lock_guard lock(mu_);
  reported_pids_.push_back(pid);
  if (reported_pids_.size() > CrashExitTracker::kMaxPending) reported_pids_.pop_front();
  return SRESULT::Ok;
}

SRESULT DiagnosticReportsSource::loop() {
  while (!stop_.load()) {
    std::vector<Pending> work;
    {
      std::lock_guard lock(mu_);
      work.swap(pending_);
    }
    std::vector<Pending> retry;
    for (auto& p : work) {
      const SRESULT r = try_parse(p.path);
      if (r == SRESULT::CorruptData && ++p.attempts < kMaxParseAttempts) {
        retry.push_back(std::move(p));
        continue;
      }
      if (HS_FAILED(r) && r != SRESULT::Unsupported) {
        HS_TRACE_WARNING(kComponent, "giving up on report {}: {}", p.path, r);
      }
      std::lock_guard lock(mu_);
      seen_.insert(p.path);
    }
    {
      std::lock_guard lock(mu_);
      for (auto& p : retry) pending_.push_back(std::move(p));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
  return SRESULT::Ok;
}

// ---------------- ProcessWatcherActor ----------------

ProcessWatcherActor::ProcessWatcherActor(EventBus& bus, EventFactory& factory, const IClock& clock,
                                         WatcherOptions opts)
    : Actor("process_watcher"), bus_(bus), factory_(factory), clock_(clock), opts_(std::move(opts)) {}

SRESULT ProcessWatcherActor::on_start(ActorContext& ctx) {
  if (opts_.target_name.empty()) return SRESULT::InvalidArgument;
  exits_ = std::make_unique<KqueueExitSource>(bus_, factory_);
  HS_RETURN_IF_FAILED(exits_->start());
  std::vector<std::filesystem::path> dirs = opts_.report_dirs;
  if (dirs.empty()) {
    if (const char* home = std::getenv("HOME")) dirs.emplace_back(std::filesystem::path(home) / "Library/Logs/DiagnosticReports");
    dirs.emplace_back("/Library/Logs/DiagnosticReports");
  }
  reports_ = std::make_unique<DiagnosticReportsSource>(bus_, factory_, clock_, opts_.target_name, dirs,
                                                       opts_.max_report_age);
  (void)reports_->start();  // NotFound already traced; exits are still detected
  HS_RETURN_IF_FAILED(subscribe<TargetLifecycle>(ctx.bus, [this](const auto& e) {
    if (e->phase == "exit" && e->pid == pid_) {
      last_exited_ = pid_;  // a dying pid may linger briefly in the process list
      pid_ = 0;             // rescan picks up a relaunch
      std::chrono::steady_clock::time_point now;
      HS_RETURN_IF_FAILED(clock_.now_steady(now));
      (void)crash_exits_.on_exit(static_cast<pid_t>(e->pid), e->exit_status, e->version, now);  // NoOp: not a crash
    }
    return SRESULT::Ok;
  }));
  HS_RETURN_IF_FAILED(subscribe<ProcessCrashDetected>(ctx.bus, [this](const auto& e) {
    (void)crash_exits_.on_report(static_cast<pid_t>(e->pid));  // NoOp: no exit was waiting for it
    return SRESULT::Ok;
  }));
  TimerId id = 0;
  HS_RETURN_IF_FAILED(ctx.runtime.schedule_every(shared_from_this(), opts_.scan_period, [this] { return scan(); }, id));
  HS_TRACE_INFO(kComponent, "watching for target '{}'", opts_.target_name);
  return SRESULT::Ok;
}

SRESULT ProcessWatcherActor::on_stop() {
  if (exits_) (void)exits_->stop();      // NoOp if never started
  if (reports_) (void)reports_->stop();  // NoOp if never started
  return Actor::on_stop();
}

SRESULT ProcessWatcherActor::report_unreported_crashes() {
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  std::vector<CrashExitTracker::Pending> due;
  HS_RETURN_IF_FAILED(crash_exits_.due(now, opts_.report_grace, due));
  for (const auto& d : due) {
    std::string name;
    (void)CrashExitTracker::crash_signal_name(d.signal, name);  // always a crash signal: on_exit filtered
    if (reports_) (void)reports_->mark_reported(d.pid);         // a late report must not become a second incident
    std::shared_ptr<ProcessCrashDetected> ev;
    HS_RETURN_IF_FAILED(factory_.make<ProcessCrashDetected>(ev));
    ev->pid = d.pid;
    ev->signal = name;
    ev->faulting_module = opts_.target_name;
    ev->termination_reason = "SIGNAL: " + name + " (macOS wrote no crash report; detected from the exit signal)";
    ev->app_version = d.version;
    HS_TRACE_WARNING(kComponent, "CRASH detected from exit signal: {} pid {} {} (no crash report within {} s)",
                     opts_.target_name, d.pid, name, opts_.report_grace.count() / 1000);
    HS_RETURN_IF_FAILED(bus_.post(std::move(ev)));
  }
  return SRESULT::Ok;
}

SRESULT ProcessWatcherActor::scan() {
  HS_RETURN_IF_FAILED(report_unreported_crashes());
  if (pid_ != 0) return SRESULT::NoOp;
  pid_t pid = 0;
  std::string exe;
  if (find_target(opts_.target_name, pid, exe) != SRESULT::Ok || pid == last_exited_) return SRESULT::NoOp;
  std::string bundle_id, version;
  (void)bundle_info(exe, bundle_id, version);  // NotFound for bare executables
  std::shared_ptr<TargetLifecycle> ev;
  HS_RETURN_IF_FAILED(factory_.make<TargetLifecycle>(ev));
  ev->phase = "launch";
  ev->pid = pid;
  ev->bundle_id = bundle_id;
  ev->version = version;
  pid_ = pid;
  HS_TRACE_INFO(kComponent, "target found: pid {} {} {} ({})", pid, bundle_id, version, exe);
  HS_RETURN_IF_FAILED(bus_.post(std::move(ev)));
  const SRESULT w = exits_->watch(pid, bundle_id, version);
  return w == SRESULT::NotFound ? SRESULT::Ok : w;  // already gone: exit was posted
}

}  // namespace ieso::macos
