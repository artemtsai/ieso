/**
 * @file capture_budget_test.cpp
 * @brief Observer-effect budget: per-incident and sliding-hour limits (NFR-4).
 */
#include <gtest/gtest.h>

#include "ieso/core/capture_budget.hpp"
#include "ieso/core/config.hpp"

using namespace ieso;
using namespace std::chrono_literals;

/// At most one capture per incident.
TEST(CaptureBudget, PerIncident) {
  ManualClock clock;
  CaptureBudget b(clock, config::kCapturesPerIncident, config::kCapturesPerHour);
  EXPECT_EQ(b.try_acquire("inc-1"), SRESULT::Ok);
  EXPECT_EQ(b.try_acquire("inc-1"), SRESULT::BudgetExhausted);
  EXPECT_EQ(b.try_acquire("inc-2"), SRESULT::Ok);
}

/// At most four per sliding hour; capacity returns as old captures age out.
TEST(CaptureBudget, SlidingHour) {
  ManualClock clock;
  CaptureBudget b(clock, 1, 4);
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(b.try_acquire("i" + std::to_string(i)), SRESULT::Ok);
    ASSERT_EQ(clock.advance(10min), SRESULT::Ok);
  }
  EXPECT_EQ(b.try_acquire("i4"), SRESULT::BudgetExhausted);
  std::uint32_t left = 9;
  ASSERT_EQ(b.remaining_this_hour(left), SRESULT::Ok);
  EXPECT_EQ(left, 0u);
  ASSERT_EQ(clock.advance(20min), SRESULT::Ok);  // first capture is now 60 min old
  ASSERT_EQ(b.remaining_this_hour(left), SRESULT::Ok);
  EXPECT_EQ(left, 1u);
  EXPECT_EQ(b.try_acquire("i4"), SRESULT::Ok);
}
