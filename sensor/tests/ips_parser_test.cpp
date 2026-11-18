/**
 * @file ips_parser_test.cpp
 * @brief .ips parsing with a real (sanitized) DemoApp crash report and synthetic edge cases.
 */
#include <gtest/gtest.h>

#include <fstream>
#include <iterator>

#include "ieso/core/ips_parser.hpp"

using namespace ieso;

/// The real DemoApp EXC_BAD_ACCESS report yields the fleet signature fields.
TEST(IpsParser, RealDemoAppCrash) {
  std::ifstream f(std::string(IESO_FIXTURES_DIR) + "/DemoApp-crash.ips");
  ASSERT_TRUE(f.is_open());
  const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  CrashReport r;
  ASSERT_EQ(parse_ips(text, r), SRESULT::Ok);
  EXPECT_EQ(r.bug_type, "309");
  EXPECT_EQ(r.proc_name, "DemoApp");
  EXPECT_EQ(r.bundle_id, "com.ieso.demoapp");
  EXPECT_EQ(r.app_version, "1.4.2");
  EXPECT_EQ(r.exception_type, "EXC_BAD_ACCESS");
  EXPECT_EQ(r.signal, "SIGSEGV");
  EXPECT_EQ(r.termination_reason, "SIGNAL: Segmentation fault: 11");
  EXPECT_EQ(r.faulting_module, "DemoApp");
  EXPECT_EQ(r.offset, 25685);
  EXPECT_GT(r.pid, 0);
  EXPECT_NE(r.exception_subtype.find("KERN_INVALID_ADDRESS"), std::string::npos);
  EXPECT_EQ(r.exception_codes, "0x0000000000000001, 0x0000000000000008");
  EXPECT_EQ(r.crashed_thread, "0 (com.apple.main-thread)");
  EXPECT_EQ(r.timestamp_ms, 1794970445000);  // "2026-11-17 18:54:05.00 -0800" = 2026-11-18T02:54:05Z
  ASSERT_GE(r.backtrace.size(), 3u);
  EXPECT_LE(r.backtrace.size(), kMaxCrashFrames);
  EXPECT_EQ(r.backtrace[0].image, "DemoApp");
  EXPECT_EQ(r.backtrace[0].offset, 25685);
  EXPECT_EQ(r.backtrace[0].symbol, "AppDelegate.faultCrash()");
  EXPECT_EQ(r.backtrace[1].symbol, "closure #1 in AppDelegate.scheduleFaultFromArguments()");
  for (const auto& frame : r.backtrace) EXPECT_EQ(frame.image.find('/'), std::string::npos);  // names only, never paths
}

/// Truncated files are CorruptData (still being written); other report types are Unsupported.
TEST(IpsParser, EdgeCases) {
  CrashReport r;
  EXPECT_EQ(parse_ips(R"({"bug_type":"309"})", r), SRESULT::CorruptData);
  EXPECT_EQ(parse_ips("{\"bug_type\":\"309\"}\n{\"pid\":1, \"exc", r), SRESULT::CorruptData);
  EXPECT_EQ(parse_ips("{\"bug_type\":\"288\"}\n{}", r), SRESULT::Unsupported);
  ASSERT_EQ(parse_ips("{\"bug_type\":\"309\",\"app_name\":\"X\"}\n{\"pid\":7,\"exception\":{\"type\":\"EXC_CRASH\"}}", r),
            SRESULT::Ok);
  EXPECT_EQ(r.proc_name, "X");
  EXPECT_EQ(r.exception_type, "EXC_CRASH");
  EXPECT_TRUE(r.faulting_module.empty());  // no frames: still a crash
}

/// Header timestamps: offset applied, fraction ignored, no offset = UTC, garbage rejected.
TEST(IpsParser, Timestamp) {
  std::int64_t ms = 0;
  ASSERT_EQ(parse_ips_timestamp("2026-11-17 18:54:05.00 -0800", ms), SRESULT::Ok);
  EXPECT_EQ(ms, 1794970445000);
  ASSERT_EQ(parse_ips_timestamp("2026-11-18 02:54:05.00 +0000", ms), SRESULT::Ok);
  EXPECT_EQ(ms, 1794970445000);
  ASSERT_EQ(parse_ips_timestamp("2026-11-18 08:24:05 +0530", ms), SRESULT::Ok);
  EXPECT_EQ(ms, 1794970445000);
  ASSERT_EQ(parse_ips_timestamp("1970-01-01 00:00:00", ms), SRESULT::Ok);
  EXPECT_EQ(ms, 0);
  EXPECT_EQ(parse_ips_timestamp("yesterday", ms), SRESULT::CorruptData);
}
