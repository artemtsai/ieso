/**
 * @file anomaly_test.cpp
 * @brief Anomaly actor judgements: hang episodes, leak slope, crash loop, rate limit, escalation.
 */
#include <gtest/gtest.h>

#include "anomaly/anomaly.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {

/// @brief Runtime with an AnomalyActor and collectors for its outputs.
struct AnomalyRig {
  Rig rig;                                                                         ///< Core rig.
  Runtime rt{rig.bus};                                                             ///< Runtime.
  std::shared_ptr<Collector<ProcessHangDetected>> hangs = std::make_shared<Collector<ProcessHangDetected>>("h");
  std::shared_ptr<Collector<ResourceAnomalyDetected>> anomalies =
      std::make_shared<Collector<ResourceAnomalyDetected>>("a");
  std::shared_ptr<Collector<DiagnosticEscalationRequested>> escalations =
      std::make_shared<Collector<DiagnosticEscalationRequested>>("e");

  /// @brief Starts the runtime. @param[in] opts Thresholds. @return Result of start.
  SRESULT start(AnomalyOptions opts = {}) {
    HS_RETURN_IF_FAILED(rt.add(hangs));
    HS_RETURN_IF_FAILED(rt.add(anomalies));
    HS_RETURN_IF_FAILED(rt.add(escalations));
    HS_RETURN_IF_FAILED(rt.add(std::make_shared<AnomalyActor>(rig.bus, rig.factory, rig.clock, opts)));
    return rt.start();
  }
  /// @brief Posts a launch of pid 42 / com.example.app. @return Result of post.
  SRESULT launch() {
    std::shared_ptr<TargetLifecycle> e;
    HS_RETURN_IF_FAILED(rig.factory.make<TargetLifecycle>(e));
    e->phase = "launch";
    e->pid = 42;
    e->bundle_id = "com.example.app";
    return rig.bus.post(std::move(e));
  }
  /// @brief Posts one probe result and advances the clock 3 s. @param[in] timed_out Result. @return Ok.
  SRESULT probe(bool timed_out) {
    std::shared_ptr<ResponsivenessProbed> e;
    HS_RETURN_IF_FAILED(rig.factory.make<ResponsivenessProbed>(e));
    e->pid = 42;
    e->timed_out = timed_out;
    e->latency_ms = timed_out ? 1000 : 3;
    HS_RETURN_IF_FAILED(rig.bus.post(std::move(e)));
    return rig.clock.advance(std::chrono::milliseconds(3000));
  }
  /// @brief Posts a 1 s snapshot. @param[in] ts_ms Time. @param[in] rss RSS. @return Result of post.
  SRESULT snapshot(std::int64_t ts_ms, std::uint64_t rss) {
    std::shared_ptr<TelemetrySnapshotCaptured> e;
    HS_RETURN_IF_FAILED(rig.factory.make<TelemetrySnapshotCaptured>(e));
    e->pid = 42;
    e->sample.ts_ms = ts_ms;
    e->sample.rss_bytes = rss;
    e->sample.disk_free_bytes = 100ull << 30;
    return rig.bus.post(std::move(e));
  }
  /// @brief Waits until the actor drained everything posted so far. @return Ok or Timeout.
  SRESULT settle() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return SRESULT::Ok;
  }
};

}  // namespace

/// Three consecutive timeouts make one hang per episode; a responsive probe resets the episode.
TEST(Anomaly, HangEpisodes) {
  AnomalyRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(r.launch(), SRESULT::Ok);
  ASSERT_EQ(r.settle(), SRESULT::Ok);
  for (bool t : {true, true, false, true, true, true, true, true}) ASSERT_EQ(r.probe(t), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r.hangs) == 1; }), SRESULT::Ok);
  ASSERT_EQ(r.settle(), SRESULT::Ok);
  EXPECT_EQ(count_of(*r.hangs), 1u);  // the 4th and 5th timeouts belong to the same episode
  for (bool t : {false, true, true, true}) ASSERT_EQ(r.probe(t), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r.hangs) == 2; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);

  std::vector<std::shared_ptr<const ProcessHangDetected>> hangs;
  ASSERT_EQ(r.hangs->received(hangs), SRESULT::Ok);
  EXPECT_EQ(hangs[0]->pid, 42);
  EXPECT_GE(hangs[0]->duration_ms, 1000);  // at least the first probe's 1 s timeout
  std::vector<std::shared_ptr<const DiagnosticEscalationRequested>> esc;
  ASSERT_EQ(r.escalations->received(esc), SRESULT::Ok);
  ASSERT_EQ(esc.size(), 2u);
  EXPECT_EQ(esc[0]->subsystem, "com.example.app");
  EXPECT_EQ(esc[0]->reason, "hang");
}

/// Probes without the Accessibility permission never produce hangs.
TEST(Anomaly, NoPermissionNoHang) {
  AnomalyRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<ResponsivenessProbed> e;
    ASSERT_EQ(r.rig.factory.make<ResponsivenessProbed>(e), SRESULT::Ok);
    e->permitted = false;
    ASSERT_EQ(r.rig.bus.post(std::move(e)), SRESULT::Ok);
  }
  ASSERT_EQ(r.settle(), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  EXPECT_EQ(count_of(*r.hangs), 0u);
}

/// Steady RSS growth above the slope threshold fires rss_growth once (rate-limited); flat RSS does not.
TEST(Anomaly, LeakSlope) {
  AnomalyRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(r.launch(), SRESULT::Ok);
  for (int i = 0; i < 40; ++i) ASSERT_EQ(r.snapshot(1000LL * i, 200ull << 20), SRESULT::Ok);  // flat
  ASSERT_EQ(r.settle(), SRESULT::Ok);
  EXPECT_EQ(count_of(*r.anomalies), 0u);
  for (int i = 40; i < 100; ++i) {
    ASSERT_EQ(r.snapshot(1000LL * i, (200ull << 20) + (5ull << 20) * static_cast<std::uint64_t>(i - 40)), SRESULT::Ok);
  }
  ASSERT_EQ(wait_until([&] { return count_of(*r.anomalies) >= 1; }), SRESULT::Ok);
  ASSERT_EQ(r.settle(), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  std::vector<std::shared_ptr<const ResourceAnomalyDetected>> a;
  ASSERT_EQ(r.anomalies->received(a), SRESULT::Ok);
  ASSERT_EQ(a.size(), 1u);
  EXPECT_EQ(a[0]->metric, "rss_growth");
  // Fires as soon as the window's slope crosses 100 MB/min, i.e. before it reaches the full 5 MB/s = 300 MB/min.
  EXPECT_GT(a[0]->trend, 100.0 * 1024 * 1024);
  EXPECT_LE(a[0]->trend, 301.0 * 1024 * 1024);
}

/// Three crashes within the window are a crash loop; every crash escalates logging.
TEST(Anomaly, CrashLoop) {
  AnomalyRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(r.launch(), SRESULT::Ok);
  for (int i = 0; i < 3; ++i) {
    std::shared_ptr<ProcessCrashDetected> c;
    ASSERT_EQ(r.rig.factory.make<ProcessCrashDetected>(c), SRESULT::Ok);
    ASSERT_EQ(r.rig.bus.post(std::move(c)), SRESULT::Ok);
    ASSERT_EQ(r.rig.clock.advance(std::chrono::minutes(1)), SRESULT::Ok);
  }
  ASSERT_EQ(wait_until([&] { return count_of(*r.anomalies) == 1; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  std::vector<std::shared_ptr<const ResourceAnomalyDetected>> a;
  ASSERT_EQ(r.anomalies->received(a), SRESULT::Ok);
  EXPECT_EQ(a[0]->metric, "crash_loop");
  EXPECT_GE(count_of(*r.escalations), 3u);
}
