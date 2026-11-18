/**
 * @file log_collector_test.cpp
 * @brief `log stream --style ndjson` line parsing and predicate construction.
 */
#include <gtest/gtest.h>

#include "log_collector/log_collector.hpp"

using namespace ieso;
using namespace ieso::macos;

/// A real-shaped ndjson record maps to LogStreamRecord.
TEST(LogStream, ParsesRecord) {
  const std::string line =
      R"({"traceID":1,"eventMessage":"Request failed: The request timed out.","eventType":"logEvent",)"
      R"("source":null,"formatString":"%s","activityIdentifier":0,"subsystem":"com.ieso.demoapp",)"
      R"("category":"network","threadID":42,"senderImageUUID":"X","backtrace":{"frames":[]},"bootUUID":"",)"
      R"("processImagePath":"\/Applications\/DemoApp.app\/Contents\/MacOS\/DemoApp","senderImagePath":"",)"
      R"("timestamp":"2026-11-17 18:20:01.123456-0800","machTimestamp":1,"messageType":"Error",)"
      R"("processImageUUID":"Y","processID":4242,"senderProgramCounter":0,"parentActivityIdentifier":0,)"
      R"("timezoneName":""})";
  LogStreamRecord r;
  ASSERT_EQ(parse_log_stream_line(line, r), SRESULT::Ok);
  EXPECT_EQ(r.pid, 4242);
  EXPECT_EQ(r.process, "DemoApp");
  EXPECT_EQ(r.subsystem, "com.ieso.demoapp");
  EXPECT_EQ(r.category, "network");
  EXPECT_EQ(r.level, "error");
  EXPECT_EQ(r.message, "Request failed: The request timed out.");
}

/// The banner line and non-log events are skipped; broken JSON is CorruptData.
TEST(LogStream, SkipsNonEvents) {
  LogStreamRecord r;
  EXPECT_EQ(parse_log_stream_line("Filtering the log data using \"process == \\\"X\\\"\"", r), SRESULT::NoOp);
  EXPECT_EQ(parse_log_stream_line(R"({"eventType":"activityCreateEvent","eventMessage":"x"})", r), SRESULT::NoOp);
  EXPECT_EQ(parse_log_stream_line("{broken", r), SRESULT::CorruptData);
}

/// The predicate covers the app and tccd records mentioning it.
TEST(LogStream, Predicate) {
  std::string p;
  ASSERT_EQ(log_predicate("DemoApp", p), SRESULT::Ok);
  EXPECT_EQ(p, R"(process == "DemoApp" OR (process == "tccd" AND eventMessage CONTAINS "DemoApp"))");
}
