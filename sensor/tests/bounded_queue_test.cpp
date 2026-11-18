/**
 * @file bounded_queue_test.cpp
 * @brief Overflow policies and counters of BoundedQueue.
 */
#include <gtest/gtest.h>

#include "ieso/core/bounded_queue.hpp"

using namespace ieso;

/// DropOldest evicts the oldest item and counts the drop.
TEST(BoundedQueue, DropOldest) {
  BoundedQueue<int> q(3);
  for (int i = 0; i < 3; ++i) {
    int v = i;
    ASSERT_EQ(q.push(v, OverflowPolicy::DropOldest), SRESULT::Ok);
  }
  int v = 3;
  EXPECT_EQ(q.push(v, OverflowPolicy::DropOldest), SRESULT::Dropped);
  int out = -1;
  ASSERT_EQ(q.pop(out), SRESULT::Ok);
  EXPECT_EQ(out, 1);  // 0 was evicted
  QueueStats st;
  ASSERT_EQ(q.stats(st), SRESULT::Ok);
  EXPECT_EQ(st.dropped, 1u);
  EXPECT_EQ(st.high_water, 3u);
}

/// Sample keeps 1 of N above the watermark and drops new items when full.
TEST(BoundedQueue, SampleAboveWatermark) {
  BoundedQueue<int> q(8);  // watermark 4
  int accepted = 0;
  for (int i = 0; i < 100; ++i) {
    int v = i;
    if (q.push(v, OverflowPolicy::Sample) == SRESULT::Ok) ++accepted;
  }
  QueueStats st;
  ASSERT_EQ(q.stats(st), SRESULT::Ok);
  EXPECT_EQ(st.depth, 8u);
  EXPECT_EQ(accepted, 8);
  EXPECT_EQ(st.dropped, 92u);
  // Above the watermark only every kSampleKeepEvery-th item got in, so the 5th accepted is item 4.
  std::vector<int> items;
  int out = 0;
  while (q.pop(out) == SRESULT::Ok) items.push_back(out);
  EXPECT_EQ(items[4], 4);
  EXPECT_EQ(items[5], 4 + static_cast<int>(config::kSampleKeepEvery));
}

/// NeverDrop refuses when full without consuming the item; force_push respects the hard cap.
TEST(BoundedQueue, NeverDropAndForce) {
  BoundedQueue<std::string> q(1);
  std::string a = "a", b = "b", c = "c";
  ASSERT_EQ(q.push(a, OverflowPolicy::NeverDrop), SRESULT::Ok);
  EXPECT_EQ(q.push(b, OverflowPolicy::NeverDrop), SRESULT::CapacityExceeded);
  EXPECT_EQ(b, "b");  // untouched
  EXPECT_EQ(q.force_push(b, 2), SRESULT::Ok);
  EXPECT_EQ(q.force_push(c, 2), SRESULT::CapacityExceeded);
  QueueStats st;
  ASSERT_EQ(q.stats(st), SRESULT::Ok);
  EXPECT_EQ(st.forced, 1u);
  EXPECT_EQ(st.dropped, 0u);
}
