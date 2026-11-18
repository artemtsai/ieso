/**
 * @file uuid_test.cpp
 * @brief UUIDv7 format, ordering and uniqueness.
 */
#include <gtest/gtest.h>

#include <set>

#include "ieso/core/clock.hpp"
#include "ieso/core/uuid.hpp"

using namespace ieso;

/// Canonical 36-char form with version 7 and RFC variant bits.
TEST(Uuid, VersionAndVariant) {
  SystemClock clock;
  UuidGenerator gen(clock, 1);
  std::string id;
  ASSERT_EQ(gen.next(id), SRESULT::Ok);
  ASSERT_EQ(id.size(), 36u);
  EXPECT_EQ(id[8], '-');
  EXPECT_EQ(id[14], '7');
  EXPECT_NE(std::string("89ab").find(id[19]), std::string::npos);
}

/// IDs are strictly increasing within one generator, even with a frozen clock (counter path).
TEST(Uuid, MonotonicWithFrozenClock) {
  ManualClock clock;
  UuidGenerator gen(clock, 7);
  std::string prev;
  ASSERT_EQ(gen.next(prev), SRESULT::Ok);
  for (int i = 0; i < 10000; ++i) {  // > 4096 forces counter overflow into the next ms
    std::string id;
    ASSERT_EQ(gen.next(id), SRESULT::Ok);
    ASSERT_LT(prev, id);
    prev = id;
  }
}

/// 100k IDs are unique.
TEST(Uuid, Unique) {
  SystemClock clock;
  UuidGenerator gen(clock);
  std::set<std::string> ids;
  for (int i = 0; i < 100000; ++i) {
    std::string id;
    ASSERT_EQ(gen.next(id), SRESULT::Ok);
    ids.insert(id);
  }
  EXPECT_EQ(ids.size(), 100000u);
}
