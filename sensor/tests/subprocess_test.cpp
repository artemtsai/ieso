/**
 * @file subprocess_test.cpp
 * @brief posix_spawn wrapper: capture, line reading, timeout and kill.
 */
#include <gtest/gtest.h>

#include "ieso/macos/subprocess.hpp"

using namespace ieso;
using namespace ieso::macos;
using namespace std::chrono_literals;

/// Run captures combined output and the exit code.
TEST(Subprocess, RunCapture) {
  std::string out;
  int code = -5;
  ASSERT_EQ(Subprocess::Run({"/bin/sh", "-c", "echo hello; echo err >&2; exit 3"}, 5s, out, code), SRESULT::Ok);
  EXPECT_EQ(code, 3);
  EXPECT_NE(out.find("hello"), std::string::npos);
  EXPECT_NE(out.find("err"), std::string::npos);
}

/// Lines are delivered one by one; EOF is Closed.
TEST(Subprocess, ReadLines) {
  std::unique_ptr<Subprocess> p;
  ASSERT_EQ(Subprocess::Spawn({"/usr/bin/printf", "a\\nb\\nc"}, p), SRESULT::Ok);
  std::string l;
  ASSERT_EQ(p->read_line(l, 2s), SRESULT::Ok);
  EXPECT_EQ(l, "a");
  ASSERT_EQ(p->read_line(l, 2s), SRESULT::Ok);
  EXPECT_EQ(l, "b");
  ASSERT_EQ(p->read_line(l, 2s), SRESULT::Ok);
  EXPECT_EQ(l, "c");
  EXPECT_EQ(p->read_line(l, 2s), SRESULT::Closed);
}

/// A silent child times out; Run kills a child that exceeds its deadline; relative paths are refused.
TEST(Subprocess, TimeoutsAndValidation) {
  std::unique_ptr<Subprocess> p;
  ASSERT_EQ(Subprocess::Spawn({"/bin/sleep", "5"}, p), SRESULT::Ok);
  std::string l;
  EXPECT_EQ(p->read_line(l, 100ms), SRESULT::Timeout);
  p.reset();  // destructor terminates and reaps
  std::string out;
  int code = 0;
  const auto t0 = std::chrono::steady_clock::now();
  EXPECT_EQ(Subprocess::Run({"/bin/sleep", "5"}, 200ms, out, code), SRESULT::Timeout);
  EXPECT_LT(std::chrono::steady_clock::now() - t0, 3s);
  EXPECT_EQ(Subprocess::Spawn({"sleep", "1"}, p), SRESULT::InvalidArgument);
}
