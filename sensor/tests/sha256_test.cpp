/**
 * @file sha256_test.cpp
 * @brief SHA-256 against FIPS 180-4 test vectors.
 */
#include <gtest/gtest.h>

#include "ieso/core/sha256.hpp"

using namespace ieso;

/// Standard vectors, including the two-block padding case and incremental updates.
TEST(Sha256, Vectors) {
  std::string h;
  ASSERT_EQ(Sha256::hex("", h), SRESULT::Ok);
  EXPECT_EQ(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  ASSERT_EQ(Sha256::hex("abc", h), SRESULT::Ok);
  EXPECT_EQ(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  ASSERT_EQ(Sha256::hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", h), SRESULT::Ok);
  EXPECT_EQ(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  Sha256 inc;
  for (int i = 0; i < 1000; ++i) ASSERT_EQ(inc.update(std::string(1000, 'a')), SRESULT::Ok);
  ASSERT_EQ(inc.finish(h), SRESULT::Ok);
  EXPECT_EQ(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  EXPECT_EQ(inc.update("x"), SRESULT::InvalidState);
}
