/**
 * @file pools_test.cpp
 * @brief Pool cap enforcement and event allocation through the factory.
 */
#include <gtest/gtest.h>

#include "ontology/events.hpp"
#include "test_util.hpp"

using namespace ieso;

/// Caps outside [2 x headroom, hard cap] are rejected.
TEST(Pools, CreateValidatesCap) {
  std::unique_ptr<Pools> p;
  EXPECT_EQ(Pools::Create(1024, p), SRESULT::InvalidArgument);
  EXPECT_EQ(Pools::Create(config::kEventPoolHardCap + 1, p), SRESULT::InvalidArgument);
  EXPECT_EQ(Pools::Create(config::kEventPoolBytes, p), SRESULT::Ok);
}

/// Allocation fails with OutOfMemory before the cap is breached (no abort), and recovers after frees.
TEST(Pools, OutOfMemoryBeforeCap) {
  std::unique_ptr<Pools> pools;
  ASSERT_EQ(Pools::Create(2 * config::kPoolHeadroomBytes, pools), SRESULT::Ok);
  ManualClock clock;
  UuidGenerator uuid(clock, 1);
  EventFactory factory(*pools, clock, uuid, "e");
  std::vector<std::shared_ptr<ProcessHangDetected>> held;
  SRESULT r = SRESULT::Ok;
  for (int i = 0; i < 1000000 && r == SRESULT::Ok; ++i) {
    std::shared_ptr<ProcessHangDetected> ev;
    r = factory.make<ProcessHangDetected>(ev);
    if (r == SRESULT::Ok) held.push_back(std::move(ev));
  }
  EXPECT_EQ(r, SRESULT::OutOfMemory);
  EXPECT_GT(held.size(), 100u);
  PoolStats st;
  ASSERT_EQ(pools->stats(st), SRESULT::Ok);
  EXPECT_LE(st.in_use_bytes, st.cap_bytes);
  EXPECT_LE(st.live_bytes + config::kPoolHeadroomBytes, st.cap_bytes + sizeof(ProcessHangDetected) * 2);
  EXPECT_GE(st.refusals, 1u);
  held.clear();  // live bytes drop even though the pool keeps its chunks
  ASSERT_EQ(pools->stats(st), SRESULT::Ok);
  EXPECT_EQ(st.live_bytes, 0u);
  std::shared_ptr<ProcessHangDetected> again;
  EXPECT_EQ(factory.make<ProcessHangDetected>(again), SRESULT::Ok);
}

/// The factory fills id, endpoint, timestamp and routing traits.
TEST(Pools, FactoryFillsHeader) {
  test::Rig rig;
  std::shared_ptr<LogRecordObserved> ev;
  ASSERT_EQ(rig.factory.make<LogRecordObserved>(ev), SRESULT::Ok);
  EXPECT_EQ(ev->hdr.endpoint_id, "endpoint-test");
  EXPECT_EQ(ev->hdr.cls, EventClass::Routine);
  EXPECT_EQ(ev->hdr.overflow, OverflowPolicy::Sample);
  EXPECT_TRUE(ev->hdr.egress);
  EXPECT_FALSE(ev->hdr.spillable);
  std::chrono::system_clock::time_point now;
  ASSERT_EQ(rig.clock.now_system(now), SRESULT::Ok);
  EXPECT_EQ(ev->hdr.ts, now);
}
