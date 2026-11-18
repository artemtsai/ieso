/**
 * @file process_watcher_test.cpp
 * @brief Watcher end to end with a real child process (libproc launch, kqueue exit), plus crash-report handling:
 *        dedupe across moves, stale reports, and the exit-signal fallback when macOS writes no report.
 */
#include <gtest/gtest.h>

#include <csignal>
#include <fstream>
#include <iterator>

#include "ieso/core/ips_parser.hpp"
#include "ieso/macos/subprocess.hpp"
#include "process_watcher/process_watcher.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::macos;
using namespace ieso::test;

/// A spawned process is adopted as the target and its exit is reported.
TEST(ProcessWatcher, LaunchAndExit) {
  Rig rig;
  TempDir tmp;
  std::filesystem::path dir;
  ASSERT_EQ(tmp.path(dir), SRESULT::Ok);
  // Copy /bin/sleep under a unique name so no other process matches.
  const auto exe = dir / "iesosleeper";
  std::error_code ec;
  std::filesystem::copy_file("/bin/sleep", exe, ec);
  ASSERT_FALSE(ec) << ec.message();
  // A copied platform binary fails code-signature checks (SIGKILL + crash report); re-sign it ad hoc.
  std::string out;
  int code = -1;
  ASSERT_EQ(Subprocess::Run({"/usr/bin/codesign", "--force", "--sign", "-", exe.string()}, std::chrono::seconds(20),
                            out, code), SRESULT::Ok);
  ASSERT_EQ(code, 0) << out;

  Runtime rt(rig.bus);
  WatcherOptions o;
  o.target_name = "iesosleeper";
  o.scan_period = std::chrono::milliseconds(50);
  o.report_dirs = {dir};
  auto watcher = std::make_shared<ProcessWatcherActor>(rig.bus, rig.factory, rig.clock, o);
  auto events = std::make_shared<Collector<TargetLifecycle>>("lifecycle");
  ASSERT_EQ(rt.add(events), SRESULT::Ok);
  ASSERT_EQ(rt.add(watcher), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);

  std::unique_ptr<Subprocess> child;
  ASSERT_EQ(Subprocess::Spawn({exe.string(), "1"}, child), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*events) >= 2; }, std::chrono::seconds(5)), SRESULT::Ok);
  ASSERT_EQ(rt.stop(), SRESULT::Ok);

  std::vector<std::shared_ptr<const TargetLifecycle>> got;
  ASSERT_EQ(events->received(got), SRESULT::Ok);
  EXPECT_EQ(got[0]->phase, "launch");
  EXPECT_EQ(got[1]->phase, "exit");
  EXPECT_EQ(got[0]->pid, got[1]->pid);
  EXPECT_EQ(got[1]->exit_status, 0);  // clean exit, not a code-signing kill
}

/// Only `<target>-*.ips` files are queued by the reports source.
TEST(ProcessWatcher, ReportFilter) {
  Rig rig;
  DiagnosticReportsSource src(rig.bus, rig.factory, rig.clock, "DemoApp", {});
  EXPECT_EQ(src.offer("/x/DemoApp-2026-11-17-101010.ips"), SRESULT::Ok);
  EXPECT_EQ(src.offer("/x/DemoApp-2026-11-17-101010.ips"), SRESULT::NoOp);  // duplicate
  EXPECT_EQ(src.offer("/x/Other-2026-11-17-101010.ips"), SRESULT::NoOp);
  EXPECT_EQ(src.offer("/x/DemoApp-2026-11-17-101010.diag"), SRESULT::NoOp);
  EXPECT_EQ(src.offer("/x/Retired/DemoApp-2026-11-17-101010.ips"), SRESULT::NoOp);  // macOS moved it there
}

namespace {
constexpr std::int64_t kFixtureCrashMs = 1794970445000;     // DemoApp-crash.ips: "2026-11-17 18:54:05.00 -0800"
constexpr std::int64_t kManualClockStartMs = 1767225600000;  // ManualClock starts at 2026-01-01T00:00:00Z
}  // namespace

/// One crash is one event even when macOS moves the report: dedupe by the report's incident UUID, not its path.
TEST(ProcessWatcher, MovedReportPostsOnce) {
  Rig rig;
  TempDir tmp;
  std::filesystem::path dir;
  ASSERT_EQ(tmp.path(dir), SRESULT::Ok);
  const auto fixture = std::filesystem::path(IESO_FIXTURES_DIR) / "DemoApp-crash.ips";
  const auto first = dir / "DemoApp-2026-11-17-185405.ips";
  std::error_code ec;
  std::filesystem::create_directories(dir / "moved", ec);
  const auto moved = dir / "moved" / "DemoApp-2026-11-17-185405.ips";
  std::filesystem::copy_file(fixture, first, ec);
  ASSERT_FALSE(ec) << ec.message();
  std::filesystem::copy_file(fixture, moved, ec);
  ASSERT_FALSE(ec) << ec.message();

  ASSERT_EQ(rig.clock.advance(std::chrono::milliseconds(kFixtureCrashMs - kManualClockStartMs + 60000)), SRESULT::Ok);
  DiagnosticReportsSource src(rig.bus, rig.factory, rig.clock, "DemoApp", {});
  EXPECT_EQ(src.try_parse(first.string()), SRESULT::Ok);
  EXPECT_EQ(src.try_parse(moved.string()), SRESULT::NoOp);  // same incident UUID under another path
}

/// macOS rewrites old reports in place; a report about a crash from yesterday must not become a new incident.
TEST(ProcessWatcher, StaleReportIgnored) {
  Rig rig;
  TempDir tmp;
  std::filesystem::path dir;
  ASSERT_EQ(tmp.path(dir), SRESULT::Ok);
  const auto file = dir / "DemoApp-2026-11-17-185405.ips";
  std::error_code ec;
  std::filesystem::copy_file(std::filesystem::path(IESO_FIXTURES_DIR) / "DemoApp-crash.ips", file, ec);
  ASSERT_FALSE(ec) << ec.message();
  // One day after the crash.
  ASSERT_EQ(rig.clock.advance(std::chrono::milliseconds(kFixtureCrashMs - kManualClockStartMs + 86400000)),
            SRESULT::Ok);
  DiagnosticReportsSource src(rig.bus, rig.factory, rig.clock, "DemoApp", {});
  EXPECT_EQ(src.try_parse(file.string()), SRESULT::NoOp);
}

/// A crash-signal exit without a report is handed out once after the grace period; a report cancels it.
TEST(ProcessWatcher, CrashExitTracker) {
  CrashExitTracker t;
  const auto t0 = std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
  const auto grace = std::chrono::milliseconds(30000);
  EXPECT_EQ(t.on_exit(100, -SIGSEGV, "1.4.2", t0), SRESULT::Ok);
  EXPECT_EQ(t.on_exit(101, -SIGTERM, "1.4.2", t0), SRESULT::NoOp);  // killed, not crashed
  EXPECT_EQ(t.on_exit(102, 0, "1.4.2", t0), SRESULT::NoOp);         // clean exit
  EXPECT_EQ(t.on_exit(103, -SIGABRT, "1.4.2", t0), SRESULT::Ok);
  EXPECT_EQ(t.on_report(103), SRESULT::Ok);                         // its report arrived
  std::vector<CrashExitTracker::Pending> due;
  ASSERT_EQ(t.due(t0 + std::chrono::seconds(10), grace, due), SRESULT::Ok);
  EXPECT_TRUE(due.empty());  // still within the grace period
  ASSERT_EQ(t.due(t0 + std::chrono::seconds(31), grace, due), SRESULT::Ok);
  ASSERT_EQ(due.size(), 1u);
  EXPECT_EQ(due[0].pid, 100);
  EXPECT_EQ(due[0].signal, SIGSEGV);
  due.clear();
  ASSERT_EQ(t.due(t0 + std::chrono::seconds(60), grace, due), SRESULT::Ok);
  EXPECT_TRUE(due.empty());  // handed out once
  std::string name;
  EXPECT_EQ(CrashExitTracker::crash_signal_name(SIGBUS, name), SRESULT::Ok);
  EXPECT_EQ(name, "SIGBUS");
  EXPECT_EQ(CrashExitTracker::crash_signal_name(SIGKILL, name), SRESULT::NotFound);
}

/// After the exit-signal fallback reported a pid, a late report for that pid is dropped.
TEST(ProcessWatcher, LateReportAfterFallbackDropped) {
  Rig rig;
  TempDir tmp;
  std::filesystem::path dir;
  ASSERT_EQ(tmp.path(dir), SRESULT::Ok);
  const auto file = dir / "DemoApp-2026-11-17-185405.ips";
  std::error_code ec;
  std::filesystem::copy_file(std::filesystem::path(IESO_FIXTURES_DIR) / "DemoApp-crash.ips", file, ec);
  ASSERT_FALSE(ec) << ec.message();
  std::ifstream f(file);
  const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  CrashReport r;
  ASSERT_EQ(parse_ips(text, r), SRESULT::Ok);
  ASSERT_EQ(rig.clock.advance(std::chrono::milliseconds(kFixtureCrashMs - kManualClockStartMs + 60000)), SRESULT::Ok);
  DiagnosticReportsSource src(rig.bus, rig.factory, rig.clock, "DemoApp", {});
  ASSERT_EQ(src.mark_reported(static_cast<pid_t>(r.pid)), SRESULT::Ok);
  EXPECT_EQ(src.try_parse(file.string()), SRESULT::NoOp);
}
