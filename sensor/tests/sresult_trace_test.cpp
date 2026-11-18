/**
 * @file sresult_trace_test.cpp
 * @brief SRESULT helpers, Policy clamping, time formatting and the tracing facade.
 */
#include <gtest/gtest.h>

#include "ieso/core/config.hpp"
#include "ieso/core/sresult.hpp"
#include "ieso/core/time_util.hpp"
#include "ieso/core/trace.hpp"

using namespace ieso;

namespace {
/// @brief Returns @p r through HS_RETURN_IF_FAILED, Ok otherwise.
SRESULT propagate(SRESULT r) {
  HS_RETURN_IF_FAILED(r);
  return SRESULT::Ok;
}
}  // namespace

/// Success codes are < 100, failures >= 100, and HS_RETURN_IF_FAILED propagates only failures.
TEST(SResult, SuccessAndFailureClasses) {
  EXPECT_TRUE(HS_SUCCEEDED(SRESULT::Ok));
  EXPECT_TRUE(HS_SUCCEEDED(SRESULT::Dropped));
  EXPECT_TRUE(HS_FAILED(SRESULT::IoError));
  EXPECT_EQ(propagate(SRESULT::NoOp), SRESULT::Ok);
  EXPECT_EQ(propagate(SRESULT::Timeout), SRESULT::Timeout);
}

/// Every code has a stable name and formats through fmt.
TEST(SResult, Names) {
  std::string_view n;
  EXPECT_EQ(to_string(SRESULT::BudgetExhausted, n), SRESULT::Ok);
  EXPECT_EQ(n, "BudgetExhausted");
  EXPECT_EQ(fmt::format("{}", SRESULT::CapacityExceeded), "CapacityExceeded");
}

/// Policy values are clamped to hard caps and report Adjusted.
TEST(Policy, ClampsToHardCaps) {
  config::Policy p;
  EXPECT_EQ(p.clamp(), SRESULT::Ok);
  p.captures_per_hour = 1000;
  p.spool_max_bytes = 10ull << 30;
  EXPECT_EQ(p.clamp(), SRESULT::Adjusted);
  EXPECT_EQ(p.captures_per_hour, config::kCapturesPerHourHardCap);
  EXPECT_EQ(p.spool_max_bytes, config::kSpoolHardCapBytes);
}

/// RFC 3339 UTC formatting with milliseconds.
TEST(TimeUtil, FormatsUtcMillis) {
  std::chrono::system_clock::time_point tp;
  ASSERT_EQ(from_unix_ms(1767225600123, tp), SRESULT::Ok);
  std::string s;
  ASSERT_EQ(format_utc_ms(tp, s), SRESULT::Ok);
  EXPECT_EQ(s, "2026-01-01T00:00:00.123Z");
}

/// Records below the runtime level are discarded; lines carry level, component and message.
TEST(Trace, LevelFilterAndFormat) {
  auto sink = std::make_shared<trace::MemorySink>();
  ASSERT_EQ(trace::set_sink(sink), SRESULT::Ok);
  ASSERT_EQ(trace::set_level(trace::Level::Warning), SRESULT::Ok);
  HS_TRACE_INFO("test", "hidden {}", 1);
  HS_TRACE_ERROR("test", "shown {}", 2);
  std::vector<std::string> lines;
  ASSERT_EQ(sink->lines(lines), SRESULT::Ok);
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_NE(lines[0].find("ERROR"), std::string::npos);
  EXPECT_NE(lines[0].find("[test]"), std::string::npos);
  EXPECT_NE(lines[0].find("shown 2"), std::string::npos);
  EXPECT_NE(lines[0].find("sresult_trace_test.cpp"), std::string::npos);
  ASSERT_EQ(trace::set_level(trace::Level::Info), SRESULT::Ok);
  ASSERT_EQ(trace::set_sink(nullptr), SRESULT::Ok);
}
