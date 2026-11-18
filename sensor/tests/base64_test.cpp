/**
 * @file base64_test.cpp
 * @brief base64 decoding (RFC 4648 vectors and malformed input).
 */
#include <gtest/gtest.h>

#include "ieso/core/base64.hpp"

using namespace ieso;

/// RFC 4648 test vectors, with whitespace ignored.
TEST(Base64, Vectors) {
  const std::pair<const char*, const char*> v[] = {{"", ""},         {"Zg==", "f"},         {"Zm8=", "fo"},
                                                   {"Zm9v", "foo"},  {"Zm9vYg==", "foob"},  {"Zm9vYmE=", "fooba"},
                                                   {"Zm9v\nYmFy", "foobar"}};
  for (const auto& [enc, dec] : v) {
    std::string out;
    ASSERT_EQ(base64_decode(enc, out), SRESULT::Ok) << enc;
    EXPECT_EQ(out, dec);
  }
}

/// Bad characters, bad length and data after padding are CorruptData.
TEST(Base64, Malformed) {
  std::string out;
  for (const char* bad : {"Zm9", "Zm9v!", "Zg==Zg==", "Z==="}) EXPECT_EQ(base64_decode(bad, out), SRESULT::CorruptData) << bad;
}
