/**
 * @file process_watcher.hpp
 * @brief Process Watcher: finds the target, tracks launch/exit (kqueue), and turns new .ips reports into crashes.
 * @details DESIGN.md §8, §9.2. kqueue NOTE_EXIT says *that* the target died; the .ips report (found via FSEvents
 *          on DiagnosticReports) says *why*. Both sources run on their own threads (IEventSource).
 */
#pragma once

#include <CoreServices/CoreServices.h>
#include <dispatch/dispatch.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <deque>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "ieso/core/actor.hpp"
#include "ieso/core/clock.hpp"
#include "ieso/core/event_factory.hpp"
#include "ieso/core/event_source.hpp"
#include "ontology/events.hpp"

namespace ieso::macos {

/// @brief Watcher options.
struct WatcherOptions {
  std::string target_name;                              ///< App name, e.g. "DemoApp".
  std::chrono::milliseconds scan_period{1000};          ///< libproc scan while the target is not running.
  std::vector<std::filesystem::path> report_dirs;       ///< DiagnosticReports directories.
  std::chrono::milliseconds max_report_age{600000};     ///< Reports about older crashes are ignored (macOS rewrites old files).
  std::chrono::milliseconds report_grace{30000};        ///< Crash-signal exit without a report after this: report it anyway.
};

/**
 * @brief Remembers crash-signal exits until a crash report arrives for the same pid.
 * @details macOS throttles crash reports for an app that crashes often (and sometimes only rewrites an old one).
 *          A target that died on SIGSEGV/SIGBUS/SIGABRT/SIGILL/SIGFPE/SIGTRAP without a fresh report within the
 *          grace period is still a crash; due() hands those out once. Bounded to kMaxPending entries.
 */
class CrashExitTracker {
 public:
  /// @brief One exit waiting for its report.
  struct Pending {
    pid_t pid = 0;                                     ///< Exited pid.
    std::int64_t signal = 0;                           ///< Signal number (positive).
    std::string version;                               ///< App version from the lifecycle event.
    std::chrono::steady_clock::time_point at{};        ///< Exit time.
  };
  static constexpr std::size_t kMaxPending = 16;       ///< Oldest entries are dropped beyond this.

  /**
   * @brief Records an exit; only crash signals are kept.
   * @param[in] pid Pid. @param[in] exit_status Negative signal number, or the exit code.
   * @param[in] version App version. @param[in] now Exit time.
   * @return SRESULT::Ok if recorded, NoOp if it was not a crash signal.
   */
  SRESULT on_exit(pid_t pid, std::int64_t exit_status, const std::string& version,
                  std::chrono::steady_clock::time_point now);

  /// @brief A report arrived for @p pid; forget it. @param[in] pid Pid. @return SRESULT::Ok or NoOp.
  SRESULT on_report(pid_t pid);

  /**
   * @brief Moves the exits older than @p grace into @p out (each is handed out once).
   * @param[in] now Current time. @param[in] grace Report grace period. @param[out] out Due exits.
   * @return SRESULT::Ok.
   */
  SRESULT due(std::chrono::steady_clock::time_point now, std::chrono::milliseconds grace, std::vector<Pending>& out);

  /// @brief Maps a positive signal number to its name ("SIGSEGV"). @param[in] sig Signal. @param[out] out Name.
  /// @return SRESULT::Ok, or NotFound for signals that are not crashes.
  static SRESULT crash_signal_name(std::int64_t sig, std::string& out);

 private:
  std::deque<Pending> pending_;  ///< Oldest first.
};

/**
 * @brief kqueue EVFILT_PROC/NOTE_EXIT source for one pid at a time.
 */
class KqueueExitSource final : public IEventSource {
 public:
  /// @brief Binds dependencies. @param[in] bus Bus. @param[in] factory Factory. Both must outlive the source.
  KqueueExitSource(EventBus& bus, EventFactory& factory);
  ~KqueueExitSource() override;
  /// @copydoc IEventSource::start
  SRESULT start() override;
  /// @copydoc IEventSource::stop
  SRESULT stop() override;
  /**
   * @brief Starts watching @p pid; posts TargetLifecycle(exit) when it exits.
   * @param[in] pid Process.
   * @param[in] bundle_id Copied into the exit event.
   * @param[in] version Copied into the exit event.
   * @return SRESULT::Ok, or NotFound if it already exited (exit event posted).
   */
  SRESULT watch(pid_t pid, const std::string& bundle_id, const std::string& version);

 private:
  /// @brief Thread body. @return SRESULT::Ok.
  SRESULT loop();
  /// @brief Posts TargetLifecycle(exit). @param[in] pid Pid. @param[in] status Exit status. @return Post result.
  SRESULT post_exit(pid_t pid, std::int64_t status);

  EventBus& bus_;                      ///< Bus.
  EventFactory& factory_;              ///< Factory.
  int kq_ = -1;                        ///< kqueue fd.
  std::thread thread_;                 ///< Wait loop.
  std::atomic<bool> stop_{false};      ///< Exit flag.
  std::mutex mu_;                      ///< Guards bundle info.
  std::string bundle_id_, version_;    ///< Info for the watched pid.
};

/**
 * @brief FSEvents source on DiagnosticReports: new `<target>-*.ips` -> ProcessCrashDetected.
 * @note ReportCrash may write the file in steps, so unparsable files are retried for ~10 s.
 */
class DiagnosticReportsSource final : public IEventSource {
 public:
  /**
   * @brief Configures the source.
   * @param[in] bus Bus; must outlive the source.
   * @param[in] factory Factory; must outlive the source.
   * @param[in] clock Wall time for report freshness; must outlive the source.
   * @param[in] target_name Report file prefix.
   * @param[in] dirs Directories to watch.
   * @param[in] max_age Reports about crashes older than this (or older than start()) are ignored.
   */
  DiagnosticReportsSource(EventBus& bus, EventFactory& factory, const IClock& clock, std::string target_name,
                          std::vector<std::filesystem::path> dirs,
                          std::chrono::milliseconds max_age = std::chrono::milliseconds(600000));
  ~DiagnosticReportsSource() override;
  /// @copydoc IEventSource::start
  SRESULT start() override;
  /// @copydoc IEventSource::stop
  SRESULT stop() override;

  /**
   * @brief Queues a file for parsing (FSEvents callback; also used by tests).
   * @param[in] path File path.
   * @return SRESULT::Ok or NoOp if not a report of the target.
   */
  SRESULT offer(const std::string& path);

  /**
   * @brief Parses one report and posts ProcessCrashDetected once per crash.
   * @details macOS moves reports (for example into DiagnosticReports/Retired/) after writing them, so a crash is
   *          identified by the report's own incident UUID, not by its path.
   * @param[in] path Report file.
   * @retval SRESULT::Ok          Posted.
   * @retval SRESULT::NoOp        Same crash already posted (report seen under another path), or a stale report:
   *                              its crash happened before the sensor started or longer than max_age ago.
   * @retval SRESULT::CorruptData Not complete yet; retry.
   * @retval SRESULT::Unsupported Not a crash report; drop.
   */
  SRESULT try_parse(const std::string& path);

  /**
   * @brief Marks @p pid as already reported (from its exit signal); a late report for it is then dropped.
   * @param[in] pid Pid. @return SRESULT::Ok.
   */
  SRESULT mark_reported(pid_t pid);

 private:
  /// @brief Retry/parse loop. @return SRESULT::Ok.
  SRESULT loop();

  /// @brief A file waiting to be parsed.
  struct Pending {
    std::string path;    ///< File.
    int attempts = 0;    ///< Tries so far.
  };

  EventBus& bus_;                                 ///< Bus.
  EventFactory& factory_;                         ///< Factory.
  const IClock& clock_;                           ///< Wall time for report freshness.
  const std::string target_;                      ///< Target name.
  const std::chrono::milliseconds max_age_;       ///< Oldest crash accepted, relative to now.
  std::int64_t started_ms_ = 0;                   ///< Wall time of start() (epoch ms); 0 = not started.
  const std::vector<std::filesystem::path> dirs_; ///< Watched dirs.
  FSEventStreamRef stream_ = nullptr;             ///< C API handle; released in stop().
  dispatch_queue_t queue_ = nullptr;              ///< C API handle; released in stop().
  std::thread thread_;                            ///< Retry loop.
  std::atomic<bool> stop_{false};                 ///< Exit flag.
  std::mutex mu_;                                 ///< Guards pending_ and seen_.
  std::vector<Pending> pending_;                  ///< Files to parse.
  std::set<std::string> seen_;                    ///< Paths already handled.
  std::set<std::string> seen_incidents_;          ///< Report incident UUIDs already posted (bounded).
  std::deque<std::string> incident_order_;        ///< Insertion order of seen_incidents_, for eviction.
  std::deque<pid_t> reported_pids_;               ///< Pids already reported from their exit signal (bounded).
};

/**
 * @brief Process Watcher actor.
 */
class ProcessWatcherActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] clock Wall time (report freshness); must outlive the actor.
   * @param[in] opts Options.
   */
  ProcessWatcherActor(EventBus& bus, EventFactory& factory, const IClock& clock, WatcherOptions opts);
  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;
  /// @copydoc Actor::on_stop
  SRESULT on_stop() override;

 private:
  /// @brief Looks for the target if not tracked; also reports crash exits whose report never came. @return Ok/NoOp.
  SRESULT scan();
  /// @brief Posts ProcessCrashDetected for crash-signal exits without a report after the grace period. @return Ok.
  SRESULT report_unreported_crashes();

  EventBus& bus_;                                         ///< Bus.
  EventFactory& factory_;                                 ///< Factory.
  const IClock& clock_;                                   ///< Wall time.
  const WatcherOptions opts_;                             ///< Options.
  std::unique_ptr<KqueueExitSource> exits_;               ///< Exit source.
  std::unique_ptr<DiagnosticReportsSource> reports_;      ///< Crash report source.
  pid_t pid_ = 0;                                         ///< Tracked pid (actor thread).
  pid_t last_exited_ = 0;                                 ///< Last pid that exited (not re-adopted).
  CrashExitTracker crash_exits_;                          ///< Crash exits waiting for a report (actor thread).
};

}  // namespace ieso::macos
