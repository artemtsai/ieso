/**
 * @file ring_test.cpp
 * @brief FixedRing wraparound and FlightRecorder tier rollups.
 */
#include <gtest/gtest.h>

#include "ieso/core/binary_io.hpp"
#include "ieso/core/ring.hpp"

using namespace ieso;

namespace {
/// @brief Builds a sample at @p ts with rss = @p rss. @param[in] ts Time ms. @param[in] rss RSS. @return Sample.
ResourceSample at(std::int64_t ts, std::uint64_t rss) {
  ResourceSample s;
  s.ts_ms = ts;
  s.rss_bytes = rss;
  s.cpu_pct = static_cast<double>(rss);
  return s;
}
}  // namespace

/// The ring overwrites the oldest slot and snapshots oldest-first.
TEST(FixedRing, Wraparound) {
  FixedRing<int, 3> r;
  for (int i = 0; i < 3; ++i) EXPECT_EQ(r.push(i), SRESULT::Ok);
  EXPECT_EQ(r.push(3), SRESULT::Dropped);
  EXPECT_EQ(r.push(4), SRESULT::Dropped);
  std::vector<int> v;
  ASSERT_EQ(r.snapshot(v), SRESULT::Ok);
  EXPECT_EQ(v, (std::vector<int>{2, 3, 4}));
}

/// Hot keeps the last 5 s; completed seconds roll into warm as means; completed minutes into cold.
TEST(FlightRecorder, TierRollups) {
  std::unique_ptr<FlightRecorder> fr;
  ASSERT_EQ(FlightRecorder::Create(fr), SRESULT::Ok);
  // 2 minutes + 1 sample at 100 ms; rss ramps by second index.
  const std::int64_t base = 1767225600000;
  for (std::int64_t i = 0; i <= 1200; ++i) {
    const std::int64_t ts = base + i * 100;
    ASSERT_EQ(fr->ingest(at(ts, static_cast<std::uint64_t>(i / 10))), SRESULT::Ok);
  }
  FrozenRings f;
  ASSERT_EQ(fr->freeze(base + 120100, f), SRESULT::Ok);
  EXPECT_EQ(f.hot.size(), config::kHotSlots);
  EXPECT_EQ(f.hot.back().ts_ms, base + 120000);
  ASSERT_EQ(f.warm.size(), 120u);  // 120 completed seconds
  EXPECT_EQ(f.warm[0].rss_bytes, 0u);
  EXPECT_EQ(f.warm[119].rss_bytes, 119u);
  EXPECT_EQ(f.warm[5].ts_ms, base + 5000);
  ASSERT_EQ(f.cold.size(), 2u);  // 2 completed minutes
  EXPECT_EQ(f.cold[0].count, 600u);
  EXPECT_EQ(f.cold[0].min.rss_bytes, 0u);
  EXPECT_EQ(f.cold[0].max.rss_bytes, 59u);
  EXPECT_EQ(f.cold[1].start_ms, base + 60000);
  EXPECT_NEAR(f.cold[1].avg.cpu_pct, 89.5, 1e-9);
}

/// A target restart (pid change) closes the open buckets: no 1 s mean or 1 min aggregate mixes two processes.
TEST(FlightRecorder, PidChangeSplitsBuckets) {
  std::unique_ptr<FlightRecorder> fr;
  ASSERT_EQ(FlightRecorder::Create(fr), SRESULT::Ok);
  const std::int64_t base = 1767225600000;
  for (std::int64_t t = 0; t < 600; t += 100) {  // old process: 6 samples, rss 100
    ResourceSample s = at(base + t, 100);
    s.pid = 11;
    ASSERT_EQ(fr->ingest(s), SRESULT::Ok);
  }
  for (std::int64_t t = 600; t <= 1500; t += 100) {  // restarted process within the same second, rss 900
    ResourceSample s = at(base + t, 900);
    s.pid = 22;
    ASSERT_EQ(fr->ingest(s), SRESULT::Ok);
  }
  FrozenRings f;
  ASSERT_EQ(fr->freeze(base + 1500, f), SRESULT::Ok);
  ASSERT_EQ(f.warm.size(), 2u);  // second 0 split into one mean per process; second 1 still open
  EXPECT_EQ(f.warm[0].pid, 11);
  EXPECT_EQ(f.warm[0].rss_bytes, 100u);
  EXPECT_EQ(f.warm[1].pid, 22);
  EXPECT_EQ(f.warm[1].rss_bytes, 900u);
  EXPECT_EQ(f.warm[0].ts_ms, f.warm[1].ts_ms);  // same bucket start, different process
  ASSERT_EQ(f.cold.size(), 1u);                 // the old process's partial minute was closed
  EXPECT_EQ(f.cold[0].avg.pid, 11);
  EXPECT_EQ(f.cold[0].count, 6u);
  EXPECT_EQ(f.cold[0].max.rss_bytes, 100u);
  EXPECT_EQ(f.hot.front().pid, 11);
  EXPECT_EQ(f.hot.back().pid, 22);
}

namespace {
constexpr std::int64_t kT0 = 1767225600000;  // 2026-01-01T00:00:00Z

/// @brief A recorder fed with @p seconds of 100 ms samples (pid 7, rss = second index) starting at kT0.
std::unique_ptr<FlightRecorder> fed(std::int64_t seconds) {
  std::unique_ptr<FlightRecorder> fr;
  EXPECT_EQ(FlightRecorder::Create(fr), SRESULT::Ok);
  for (std::int64_t i = 0; i <= seconds * 10; ++i) {
    ResourceSample s = at(kT0 + i * 100, static_cast<std::uint64_t>(i / 10));
    s.pid = 7;
    EXPECT_EQ(fr->ingest(s), SRESULT::Ok);
  }
  return fr;
}
}  // namespace

/// NFR-11: warm and cold tiers (with their open buckets) survive a restart; the gap is marked; recording continues.
TEST(FlightRecorder, CheckpointRoundTrip) {
  auto before = fed(180);  // 3 min: warm 180 means + open second, cold 3 minutes + open minute
  std::string ckpt;
  ASSERT_EQ(before->checkpoint(kT0 + 180000, ckpt), SRESULT::Ok);
  EXPECT_LT(ckpt.size(), 1u << 20);  // NFR-11 bound

  std::unique_ptr<FlightRecorder> after;
  ASSERT_EQ(FlightRecorder::Create(after), SRESULT::Ok);
  RestoreStats st;
  const std::int64_t now = kT0 + 210000;  // restarted 30 s later
  ASSERT_EQ(after->restore(ckpt, now, st), SRESULT::Ok);
  EXPECT_EQ(st.warm, 181u);  // 180 completed seconds + the closed open second
  EXPECT_EQ(st.cold, 4u);    // 3 completed minutes + the closed open minute
  EXPECT_EQ(st.gap_from_ms, kT0 + 180000);
  EXPECT_EQ(st.gap_to_ms, now);

  FrozenRings f;
  ASSERT_EQ(after->freeze(now, f), SRESULT::Ok);
  EXPECT_TRUE(f.hot.empty());  // hot tier is not persisted
  ASSERT_EQ(f.warm.size(), 182u);
  EXPECT_EQ(f.warm[0].ts_ms, kT0);
  EXPECT_EQ(f.warm[0].pid, 7);
  EXPECT_EQ(f.warm[179].rss_bytes, 179u);
  EXPECT_EQ(f.warm.back().pid, kGapMarkerPid);
  EXPECT_EQ(f.warm.back().ts_ms, now);
  ASSERT_EQ(f.cold.size(), 5u);
  EXPECT_EQ(f.cold[0].count, 600u);
  EXPECT_EQ(f.cold[1].max.rss_bytes, 119u);
  EXPECT_EQ(f.cold.back().avg.pid, kGapMarkerPid);
  EXPECT_EQ(f.cold.back().count, 0u);

  ResourceSample next = at(now + 100, 42);  // recording resumes after the gap
  next.pid = 8;
  EXPECT_EQ(after->ingest(next), SRESULT::Ok);
  EXPECT_EQ(after->ingest(at(now - 1, 1)), SRESULT::InvalidArgument);  // nothing before the gap
}

/// Entries older than their tier window are dropped on restore; a fully expired checkpoint adds no gap markers.
TEST(FlightRecorder, RestoreTrimsWindows) {
  auto before = fed(180);
  std::string ckpt;
  ASSERT_EQ(before->checkpoint(kT0 + 180000, ckpt), SRESULT::Ok);

  std::unique_ptr<FlightRecorder> later;
  ASSERT_EQ(FlightRecorder::Create(later), SRESULT::Ok);
  RestoreStats st;
  ASSERT_EQ(later->restore(ckpt, kT0 + 11 * 60000, st), SRESULT::Ok);  // 11 min later: warm window is 10 min
  EXPECT_EQ(st.warm, 121u);  // seconds 60..179 inside the 10 min window + the closed open second (180)
  EXPECT_EQ(st.cold, 4u);    // all within 24 h
  EXPECT_EQ(st.dropped_old, 60u);  // seconds 0..59

  std::unique_ptr<FlightRecorder> next_day;
  ASSERT_EQ(FlightRecorder::Create(next_day), SRESULT::Ok);
  ASSERT_EQ(next_day->restore(ckpt, kT0 + 25 * 3600000LL, st), SRESULT::Ok);
  EXPECT_EQ(st.warm, 0u);
  EXPECT_EQ(st.cold, 0u);
  FrozenRings f;
  ASSERT_EQ(next_day->freeze(kT0 + 25 * 3600000LL, f), SRESULT::Ok);
  EXPECT_TRUE(f.warm.empty() && f.cold.empty());
}

/// Bad checkpoints are refused without touching the recorder: corrupt, truncated, future, unknown version, non-empty.
TEST(FlightRecorder, RestoreRejectsBadCheckpoints) {
  auto before = fed(30);
  std::string ckpt;
  ASSERT_EQ(before->checkpoint(kT0 + 30000, ckpt), SRESULT::Ok);
  RestoreStats st;
  auto fresh = [] {
    std::unique_ptr<FlightRecorder> fr;
    EXPECT_EQ(FlightRecorder::Create(fr), SRESULT::Ok);
    return fr;
  };
  std::string flipped = ckpt;
  flipped[flipped.size() / 2] ^= 0x5A;
  EXPECT_EQ(fresh()->restore(flipped, kT0 + 30000, st), SRESULT::CorruptData);
  EXPECT_EQ(fresh()->restore(ckpt.substr(0, ckpt.size() - 10), kT0 + 30000, st), SRESULT::CorruptData);
  EXPECT_EQ(fresh()->restore("garbage", kT0, st), SRESULT::CorruptData);
  EXPECT_EQ(fresh()->restore(ckpt, kT0 - 3600000, st), SRESULT::InvalidState);  // clock went back an hour
  std::string v2 = ckpt.substr(0, ckpt.size() - 4);
  v2[4] = 2;  // version field
  std::uint32_t crc = 0;
  ASSERT_EQ(bin::crc32(v2, crc), SRESULT::Ok);
  ASSERT_EQ(bin::put_le<std::uint32_t>(v2, crc), SRESULT::Ok);
  EXPECT_EQ(fresh()->restore(v2, kT0 + 30000, st), SRESULT::Unsupported);
  EXPECT_EQ(before->restore(ckpt, kT0 + 30000, st), SRESULT::InvalidState);  // only into an empty recorder
}

/// Freeze is a copy: recording continues afterwards.
TEST(FlightRecorder, FreezeKeepsRecording) {
  std::unique_ptr<FlightRecorder> fr;
  ASSERT_EQ(FlightRecorder::Create(fr), SRESULT::Ok);
  ASSERT_EQ(fr->ingest(at(1000, 1)), SRESULT::Ok);
  FrozenRings a;
  ASSERT_EQ(fr->freeze(1000, a), SRESULT::Ok);
  ASSERT_EQ(fr->ingest(at(1100, 2)), SRESULT::Ok);
  FrozenRings b;
  ASSERT_EQ(fr->freeze(1100, b), SRESULT::Ok);
  EXPECT_EQ(a.hot.size(), 1u);
  EXPECT_EQ(b.hot.size(), 2u);
}

/// Out-of-order samples are rejected.
TEST(FlightRecorder, RejectsTimeTravel) {
  std::unique_ptr<FlightRecorder> fr;
  ASSERT_EQ(FlightRecorder::Create(fr), SRESULT::Ok);
  ASSERT_EQ(fr->ingest(at(2000, 1)), SRESULT::Ok);
  EXPECT_EQ(fr->ingest(at(1999, 1)), SRESULT::InvalidArgument);
}
