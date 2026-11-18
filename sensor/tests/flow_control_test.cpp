/**
 * @file flow_control_test.cpp
 * @brief Backoff bounds/jitter/reset and token bucket refill.
 */
#include <gtest/gtest.h>

#include <set>

#include "ieso/core/flow_control.hpp"

using namespace ieso;
using namespace std::chrono_literals;

/// Delays stay within [0, min(cap, base*2^n)] and the ceiling doubles until the cap.
TEST(Backoff, BoundsAndCap) {
  Backoff b(100ms, 1000ms, 1);
  const std::int64_t ceilings[] = {100, 200, 400, 800, 1000, 1000};
  for (const auto c : ceilings) {
    std::chrono::milliseconds ceil{0}, d{0};
    ASSERT_EQ(b.ceiling(ceil), SRESULT::Ok);
    EXPECT_EQ(ceil.count(), c);
    ASSERT_EQ(b.next(d), SRESULT::Ok);
    EXPECT_GE(d.count(), 0);
    EXPECT_LE(d.count(), c);
  }
  ASSERT_EQ(b.reset(), SRESULT::Ok);
  std::chrono::milliseconds ceil{0};
  ASSERT_EQ(b.ceiling(ceil), SRESULT::Ok);
  EXPECT_EQ(ceil.count(), 100);
}

/// Full jitter: different seeds spread delays (no thundering herd).
TEST(Backoff, JitterSpreads) {
  std::set<std::int64_t> seen;
  for (std::uint64_t seed = 1; seed <= 50; ++seed) {
    Backoff b(1000ms, 1000ms, seed);
    std::chrono::milliseconds d{0};
    ASSERT_EQ(b.next(d), SRESULT::Ok);
    seen.insert(d.count());
  }
  EXPECT_GT(seen.size(), 40u);
}

/// The bucket grants up to burst, refills at rate, and accepts refunds.
TEST(TokenBucket, BurstRefillRefund) {
  const auto t0 = std::chrono::steady_clock::time_point{} + 1h;
  TokenBucket tb(10.0, 5.0, t0);
  std::uint32_t got = 0;
  ASSERT_EQ(tb.take_up_to(t0, 100, got), SRESULT::Ok);
  EXPECT_EQ(got, 5u);
  EXPECT_EQ(tb.take_up_to(t0, 1, got), SRESULT::RateLimited);
  ASSERT_EQ(tb.take_up_to(t0 + 300ms, 100, got), SRESULT::Ok);
  EXPECT_EQ(got, 3u);
  ASSERT_EQ(tb.refund(2), SRESULT::Ok);
  ASSERT_EQ(tb.take_up_to(t0 + 300ms, 100, got), SRESULT::Ok);
  EXPECT_EQ(got, 2u);
}
