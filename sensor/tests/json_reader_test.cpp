/**
 * @file json_reader_test.cpp
 * @brief Iterative JSON parser: values, escapes, limits and malformed input.
 */
#include <gtest/gtest.h>

#include "ieso/core/json_reader.hpp"

using namespace ieso;

/// Objects, arrays, numbers, booleans, null and nested lookups.
TEST(JsonReader, ParsesDocument) {
  std::shared_ptr<const JsonValue> v;
  ASSERT_EQ(JsonValue::Parse(R"( {"a":1,"b":[true,false,null,-2.5e1],"c":{"d":"x"},"e":{},"f":[]} )", v),
            SRESULT::Ok);
  std::int64_t a = 0;
  ASSERT_EQ(v->get_int("a", a), SRESULT::Ok);
  EXPECT_EQ(a, 1);
  std::shared_ptr<const JsonValue> b, item, c;
  ASSERT_EQ(v->get("b", b), SRESULT::Ok);
  std::size_t n = 0;
  ASSERT_EQ(b->size(n), SRESULT::Ok);
  EXPECT_EQ(n, 4u);
  ASSERT_EQ(b->at(3, item), SRESULT::Ok);
  double d = 0;
  ASSERT_EQ(item->as_double(d), SRESULT::Ok);
  EXPECT_DOUBLE_EQ(d, -25.0);
  ASSERT_EQ(v->get("c", c), SRESULT::Ok);
  std::string s;
  ASSERT_EQ(c->get_string("d", s), SRESULT::Ok);
  EXPECT_EQ(s, "x");
  EXPECT_EQ(v->get("missing", c), SRESULT::NotFound);
  EXPECT_EQ(b->get("x", c), SRESULT::InvalidState);
  std::vector<std::string> keys;
  ASSERT_EQ(v->keys(keys), SRESULT::Ok);
  EXPECT_EQ(keys, (std::vector<std::string>{"a", "b", "c", "e", "f"}));
}

/// Escapes and surrogate pairs decode to UTF-8.
TEST(JsonReader, Escapes) {
  std::shared_ptr<const JsonValue> v;
  ASSERT_EQ(JsonValue::Parse(R"("q\"\\\/\né😀")", v), SRESULT::Ok);
  std::string s;
  ASSERT_EQ(v->as_string(s), SRESULT::Ok);
  EXPECT_EQ(s, "q\"\\/\n\xC3\xA9\xF0\x9F\x98\x80");
}

/// Deep nesting is bounded (no recursion, no stack overflow) and returns CapacityExceeded.
TEST(JsonReader, DepthLimit) {
  std::shared_ptr<const JsonValue> v;
  const std::string ok = std::string(JsonValue::kMaxDepth, '[') + std::string(JsonValue::kMaxDepth, ']');
  EXPECT_EQ(JsonValue::Parse(ok, v), SRESULT::Ok);
  const std::string deep = std::string(100000, '[') + std::string(100000, ']');
  EXPECT_EQ(JsonValue::Parse(deep, v), SRESULT::CapacityExceeded);
}

/// Malformed input is CorruptData.
TEST(JsonReader, Malformed) {
  std::shared_ptr<const JsonValue> v;
  for (const char* bad : {"", "{", "[1,]", "{\"a\" 1}", "{\"a\":1,}", "tru", "\"unterminated", "1 2", "[1}", "-"}) {
    EXPECT_EQ(JsonValue::Parse(bad, v), SRESULT::CorruptData) << bad;
  }
}
