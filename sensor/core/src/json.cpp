/**
 * @file json.cpp
 * @brief JsonWriter implementation.
 */
#include "ieso/core/json.hpp"

#include <cmath>
#include <fmt/format.h>

namespace ieso {

SRESULT JsonWriter::escape(std::string_view in, std::string& out) {
  for (const char c : in) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          out += fmt::format("\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(c)));
        } else {
          out.push_back(c);
        }
    }
  }
  return SRESULT::Ok;
}

SRESULT JsonWriter::before_value() {
  if (stack_.empty()) {
    if (root_done_) return SRESULT::InvalidState;
    root_done_ = true;
    return SRESULT::Ok;
  }
  Frame& f = stack_.back();
  if (f.is_object) {
    if (!f.expect_value) return SRESULT::InvalidState;
    f.expect_value = false;
    return SRESULT::Ok;
  }
  if (f.has_items) buf_.push_back(',');
  f.has_items = true;
  return SRESULT::Ok;
}

SRESULT JsonWriter::begin_object() {
  HS_RETURN_IF_FAILED(before_value());
  buf_.push_back('{');
  stack_.push_back({true, false, false});
  return SRESULT::Ok;
}

SRESULT JsonWriter::end_object() {
  if (stack_.empty() || !stack_.back().is_object || stack_.back().expect_value) return SRESULT::InvalidState;
  stack_.pop_back();
  buf_.push_back('}');
  return SRESULT::Ok;
}

SRESULT JsonWriter::begin_array() {
  HS_RETURN_IF_FAILED(before_value());
  buf_.push_back('[');
  stack_.push_back({false, false, false});
  return SRESULT::Ok;
}

SRESULT JsonWriter::end_array() {
  if (stack_.empty() || stack_.back().is_object) return SRESULT::InvalidState;
  stack_.pop_back();
  buf_.push_back(']');
  return SRESULT::Ok;
}

SRESULT JsonWriter::key(std::string_view k) {
  if (stack_.empty() || !stack_.back().is_object || stack_.back().expect_value) return SRESULT::InvalidState;
  Frame& f = stack_.back();
  if (f.has_items) buf_.push_back(',');
  f.has_items = true;
  f.expect_value = true;
  buf_.push_back('"');
  HS_RETURN_IF_FAILED(escape(k, buf_));
  buf_ += "\":";
  return SRESULT::Ok;
}

SRESULT JsonWriter::value(std::string_view v) {
  HS_RETURN_IF_FAILED(before_value());
  buf_.push_back('"');
  HS_RETURN_IF_FAILED(escape(v, buf_));
  buf_.push_back('"');
  return SRESULT::Ok;
}

SRESULT JsonWriter::value(std::int64_t v) {
  HS_RETURN_IF_FAILED(before_value());
  buf_ += fmt::format("{}", v);
  return SRESULT::Ok;
}

SRESULT JsonWriter::value(double v) {
  HS_RETURN_IF_FAILED(before_value());
  buf_ += std::isfinite(v) ? fmt::format("{}", v) : std::string("null");
  return SRESULT::Ok;
}

SRESULT JsonWriter::value(bool v) {
  HS_RETURN_IF_FAILED(before_value());
  buf_ += v ? "true" : "false";
  return SRESULT::Ok;
}

SRESULT JsonWriter::null() {
  HS_RETURN_IF_FAILED(before_value());
  buf_ += "null";
  return SRESULT::Ok;
}

SRESULT JsonWriter::raw(std::string_view json) {
  HS_RETURN_IF_FAILED(before_value());
  buf_ += json;
  return SRESULT::Ok;
}

SRESULT JsonWriter::field_value(const FieldValue& v) {
  if (std::holds_alternative<bool>(v)) return value(std::get<bool>(v));
  if (std::holds_alternative<std::int64_t>(v)) return value(std::get<std::int64_t>(v));
  if (std::holds_alternative<double>(v)) return value(std::get<double>(v));
  if (std::holds_alternative<std::string>(v)) return value(std::string_view(std::get<std::string>(v)));
  return null();
}

SRESULT JsonWriter::str(std::string& out) const {
  if (!stack_.empty()) return SRESULT::InvalidState;
  out = buf_;
  return SRESULT::Ok;
}

SRESULT fields_to_json(const Fields& fields, std::string& out) {
  JsonWriter w;
  HS_RETURN_IF_FAILED(w.begin_object());
  for (const Field& f : fields) {
    HS_RETURN_IF_FAILED(w.key(f.key));
    HS_RETURN_IF_FAILED(w.field_value(f.value));
  }
  HS_RETURN_IF_FAILED(w.end_object());
  return w.str(out);
}

}  // namespace ieso
