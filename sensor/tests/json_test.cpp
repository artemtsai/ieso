/**
 * @file json_test.cpp
 * @brief JsonWriter output, escaping and misuse detection.
 */
#include <gtest/gtest.h>

#include "ieso/core/json.hpp"

using namespace ieso;

/// Nested objects/arrays get commas in the right places; strings are escaped.
TEST(Json, StructureAndEscaping) {
  JsonWriter w;
  ASSERT_EQ(w.begin_object(), SRESULT::Ok);
  ASSERT_EQ(w.key("a"), SRESULT::Ok);
  ASSERT_EQ(w.value(std::int64_t{1}), SRESULT::Ok);
  ASSERT_EQ(w.key("s"), SRESULT::Ok);
  ASSERT_EQ(w.value(std::string_view("q\"\\\n\x01")), SRESULT::Ok);
  ASSERT_EQ(w.key("arr"), SRESULT::Ok);
  ASSERT_EQ(w.begin_array(), SRESULT::Ok);
  ASSERT_EQ(w.value(true), SRESULT::Ok);
  ASSERT_EQ(w.null(), SRESULT::Ok);
  ASSERT_EQ(w.value(1.5), SRESULT::Ok);
  ASSERT_EQ(w.end_array(), SRESULT::Ok);
  ASSERT_EQ(w.end_object(), SRESULT::Ok);
  std::string out;
  ASSERT_EQ(w.str(out), SRESULT::Ok);
  EXPECT_EQ(out, R"({"a":1,"s":"q\"\\\n\u0001","arr":[true,null,1.5]})");
}

/// Values without keys, unbalanced ends and unfinished documents are InvalidState.
TEST(Json, Misuse) {
  JsonWriter w;
  ASSERT_EQ(w.begin_object(), SRESULT::Ok);
  EXPECT_EQ(w.value(true), SRESULT::InvalidState);
  EXPECT_EQ(w.end_array(), SRESULT::InvalidState);
  std::string out;
  EXPECT_EQ(w.str(out), SRESULT::InvalidState);
}

/// Fields serialize as a flat object with typed values.
TEST(Json, FieldsToJson) {
  Fields f;
  f.push_back({"n", FieldValue{std::int64_t{3}}, false});
  f.push_back({"t", FieldValue{std::string("x")}, true});
  f.push_back({"nil", FieldValue{}, false});
  std::string out;
  ASSERT_EQ(fields_to_json(f, out), SRESULT::Ok);
  EXPECT_EQ(out, R"({"n":3,"t":"x","nil":null})");
}
