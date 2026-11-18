/**
 * @file json_reader.cpp
 * @brief Iterative (explicit-stack) JSON parser with depth limit and UTF-8 output for \u escapes.
 */
#include "ieso/core/json_reader.hpp"

#include <charconv>
#include <cstdlib>

namespace ieso {

/**
 * @brief Iterative JSON parser: an explicit container stack replaces recursion (STYLEGUIDE §7).
 * @note Friend of JsonValue; builds nodes directly. Depth is capped by JsonValue::kMaxDepth.
 */
class JsonParser {
 public:
  /// @brief Binds the input. @param[in] text Input.
  explicit JsonParser(std::string_view text) : s_(text) {}

  /**
   * @brief Parses the whole document.
   * @param[out] out Root value.
   * @return SRESULT::Ok, CorruptData or CapacityExceeded.
   */
  SRESULT parse(std::shared_ptr<const JsonValue>& out) {
    std::shared_ptr<JsonValue> root;
    std::vector<std::shared_ptr<JsonValue>> stack;  // open containers, innermost last
    std::string key;                                // pending object key
    bool need_value = true;                         // next token must be a value
    for (;;) {
      if (need_value) {
        HS_RETURN_IF_FAILED(ws());
        if (i_ >= s_.size()) return SRESULT::CorruptData;
        auto v = std::make_shared<JsonValue>();
        const char c = s_[i_];
        const bool opens = (c == '{' || c == '[');
        if (c == '{') {
          v->kind_ = JsonValue::Kind::Object;
          ++i_;
        } else if (c == '[') {
          v->kind_ = JsonValue::Kind::Array;
          ++i_;
        } else if (c == '"') {
          v->kind_ = JsonValue::Kind::String;
          HS_RETURN_IF_FAILED(string(v->str_));
        } else if (c == 't' || c == 'f' || c == 'n') {
          HS_RETURN_IF_FAILED(literal(*v));
        } else {
          HS_RETURN_IF_FAILED(number(*v));
        }
        HS_RETURN_IF_FAILED(attach(stack, key, v, root));
        if (!opens) {
          need_value = false;
          continue;
        }
        if (stack.size() >= static_cast<std::size_t>(JsonValue::kMaxDepth)) return SRESULT::CapacityExceeded;
        stack.push_back(v);
        HS_RETURN_IF_FAILED(ws());
        const char close = v->kind_ == JsonValue::Kind::Object ? '}' : ']';
        if (i_ < s_.size() && s_[i_] == close) {  // empty container
          ++i_;
          stack.pop_back();
          need_value = false;
          continue;
        }
        if (v->kind_ == JsonValue::Kind::Object) HS_RETURN_IF_FAILED(member_key(key));
        continue;  // need_value stays true
      }
      // After a complete value: finish, separator, or close.
      if (stack.empty()) break;
      HS_RETURN_IF_FAILED(ws());
      if (i_ >= s_.size()) return SRESULT::CorruptData;
      const char c = s_[i_++];
      const bool in_object = stack.back()->kind_ == JsonValue::Kind::Object;
      if (c == ',') {
        if (in_object) HS_RETURN_IF_FAILED(member_key(key));
        need_value = true;
      } else if ((c == '}' && in_object) || (c == ']' && !in_object)) {
        stack.pop_back();
      } else {
        return SRESULT::CorruptData;
      }
    }
    HS_RETURN_IF_FAILED(ws());
    if (i_ != s_.size()) return SRESULT::CorruptData;
    out = std::move(root);
    return SRESULT::Ok;
  }

 private:
  /**
   * @brief Adds a finished or newly opened value to its parent (or makes it the root).
   * @param[in] stack Open containers.
   * @param[in,out] key Pending object key; consumed for objects.
   * @param[in] v Value.
   * @param[out] root Set when the stack is empty.
   * @return SRESULT::Ok.
   */
  static SRESULT attach(std::vector<std::shared_ptr<JsonValue>>& stack, std::string& key,
                        const std::shared_ptr<JsonValue>& v, std::shared_ptr<JsonValue>& root) {
    if (stack.empty()) {
      root = v;
      return SRESULT::Ok;
    }
    JsonValue& parent = *stack.back();
    if (parent.kind_ == JsonValue::Kind::Object) {
      parent.members_.emplace_back(std::move(key), v);
      key.clear();
    } else {
      parent.items_.push_back(v);
    }
    return SRESULT::Ok;
  }

  /// @brief Parses `"key" :` inside an object. @param[out] key Key text. @return Ok or CorruptData.
  SRESULT member_key(std::string& key) {
    HS_RETURN_IF_FAILED(ws());
    if (i_ >= s_.size() || s_[i_] != '"') return SRESULT::CorruptData;
    key.clear();
    HS_RETURN_IF_FAILED(string(key));
    return expect(':');
  }

  /// @brief Skips whitespace. @return SRESULT::Ok.
  SRESULT ws() {
    while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\n' || s_[i_] == '\r' || s_[i_] == '\t')) ++i_;
    return SRESULT::Ok;
  }

  /// @brief Consumes @p c or fails. @param[in] c Expected char. @return SRESULT::Ok or CorruptData.
  SRESULT expect(char c) {
    HS_RETURN_IF_FAILED(ws());
    if (i_ >= s_.size() || s_[i_] != c) return SRESULT::CorruptData;
    ++i_;
    return SRESULT::Ok;
  }

  /**
   * @brief Appends a code point as UTF-8.
   * @param[in] cp Code point.
   * @param[in,out] out Destination.
   * @return SRESULT::Ok.
   */
  static SRESULT utf8(std::uint32_t cp, std::string& out) {
    if (cp < 0x80) {
      out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return SRESULT::Ok;
  }

  /// @brief Reads 4 hex digits. @param[out] out Value. @return Ok or CorruptData.
  SRESULT hex4(std::uint32_t& out) {
    if (i_ + 4 > s_.size()) return SRESULT::CorruptData;
    out = 0;
    for (int k = 0; k < 4; ++k) {
      const char c = s_[i_++];
      out <<= 4;
      if (c >= '0' && c <= '9') out |= static_cast<std::uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f') out |= static_cast<std::uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') out |= static_cast<std::uint32_t>(c - 'A' + 10);
      else return SRESULT::CorruptData;
    }
    return SRESULT::Ok;
  }

  /// @brief Parses a string literal at the cursor. @param[out] out Decoded text. @return Ok or CorruptData.
  SRESULT string(std::string& out) {
    ++i_;  // opening quote
    for (;;) {
      if (i_ >= s_.size()) return SRESULT::CorruptData;
      const char c = s_[i_++];
      if (c == '"') return SRESULT::Ok;
      if (c != '\\') {
        out.push_back(c);
        continue;
      }
      if (i_ >= s_.size()) return SRESULT::CorruptData;
      const char e = s_[i_++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          std::uint32_t cp = 0;
          HS_RETURN_IF_FAILED(hex4(cp));
          if (cp >= 0xD800 && cp <= 0xDBFF && i_ + 1 < s_.size() && s_[i_] == '\\' && s_[i_ + 1] == 'u') {
            i_ += 2;
            std::uint32_t lo = 0;
            HS_RETURN_IF_FAILED(hex4(lo));
            if (lo < 0xDC00 || lo > 0xDFFF) return SRESULT::CorruptData;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          }
          HS_RETURN_IF_FAILED(utf8(cp, out));
          break;
        }
        default:
          return SRESULT::CorruptData;
      }
    }
  }

  /// @brief Parses true/false/null. @param[out] v Node. @return Ok or CorruptData.
  SRESULT literal(JsonValue& v) {
    const std::string_view rest = s_.substr(i_);
    if (rest.substr(0, 4) == "true") {
      v.kind_ = JsonValue::Kind::Bool;
      v.bool_ = true;
      i_ += 4;
    } else if (rest.substr(0, 5) == "false") {
      v.kind_ = JsonValue::Kind::Bool;
      i_ += 5;
    } else if (rest.substr(0, 4) == "null") {
      v.kind_ = JsonValue::Kind::Null;
      i_ += 4;
    } else {
      return SRESULT::CorruptData;
    }
    return SRESULT::Ok;
  }

  /// @brief Parses a number (integer fast path, strtod otherwise). @param[out] v Node. @return Ok or CorruptData.
  SRESULT number(JsonValue& v) {
    const std::size_t start = i_;
    if (i_ < s_.size() && s_[i_] == '-') ++i_;
    bool frac = false;
    while (i_ < s_.size()) {
      const char c = s_[i_];
      if (c >= '0' && c <= '9') {
        ++i_;
      } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || (c == '-' && i_ > start)) {
        frac = true;
        ++i_;
      } else {
        break;
      }
    }
    const std::string_view tok = s_.substr(start, i_ - start);
    if (tok.empty() || tok == "-") return SRESULT::CorruptData;
    v.kind_ = JsonValue::Kind::Number;
    if (!frac) {
      const auto res = std::from_chars(tok.data(), tok.data() + tok.size(), v.int_);
      if (res.ec == std::errc() && res.ptr == tok.data() + tok.size()) {
        v.num_ = static_cast<double>(v.int_);
        return SRESULT::Ok;
      }
    }
    const std::string copy(tok);  // strtod needs a terminated buffer
    char* end = nullptr;          // C API out-parameter
    v.num_ = std::strtod(copy.c_str(), &end);
    if (end != copy.c_str() + copy.size()) return SRESULT::CorruptData;
    v.int_ = static_cast<std::int64_t>(v.num_);
    return SRESULT::Ok;
  }

  std::string_view s_;  ///< Input.
  std::size_t i_ = 0;   ///< Cursor.
};

SRESULT JsonValue::Parse(std::string_view text, std::shared_ptr<const JsonValue>& out) {
  if (text.size() > kMaxInput) return SRESULT::CapacityExceeded;
  JsonParser p(text);
  return p.parse(out);
}

SRESULT JsonValue::kind(Kind& out) const {
  out = kind_;
  return SRESULT::Ok;
}

SRESULT JsonValue::get(std::string_view key, std::shared_ptr<const JsonValue>& out) const {
  if (kind_ != Kind::Object) return SRESULT::InvalidState;
  for (const auto& [k, v] : members_) {
    if (k == key) {
      out = v;
      return SRESULT::Ok;
    }
  }
  return SRESULT::NotFound;
}

SRESULT JsonValue::at(std::size_t i, std::shared_ptr<const JsonValue>& out) const {
  if (kind_ != Kind::Array) return SRESULT::InvalidState;
  if (i >= items_.size()) return SRESULT::NotFound;
  out = items_[i];
  return SRESULT::Ok;
}

SRESULT JsonValue::size(std::size_t& out) const {
  out = kind_ == Kind::Array ? items_.size() : (kind_ == Kind::Object ? members_.size() : 0);
  return SRESULT::Ok;
}

SRESULT JsonValue::keys(std::vector<std::string>& out) const {
  if (kind_ != Kind::Object) return SRESULT::InvalidState;
  out.clear();
  for (const auto& m : members_) out.push_back(m.first);
  return SRESULT::Ok;
}

SRESULT JsonValue::as_string(std::string& out) const {
  if (kind_ != Kind::String) return SRESULT::InvalidState;
  out = str_;
  return SRESULT::Ok;
}

SRESULT JsonValue::as_int(std::int64_t& out) const {
  if (kind_ != Kind::Number) return SRESULT::InvalidState;
  out = int_;
  return SRESULT::Ok;
}

SRESULT JsonValue::as_double(double& out) const {
  if (kind_ != Kind::Number) return SRESULT::InvalidState;
  out = num_;
  return SRESULT::Ok;
}

SRESULT JsonValue::as_bool(bool& out) const {
  if (kind_ != Kind::Bool) return SRESULT::InvalidState;
  out = bool_;
  return SRESULT::Ok;
}

SRESULT JsonValue::get_string(std::string_view key, std::string& out) const {
  std::shared_ptr<const JsonValue> v;
  HS_RETURN_IF_FAILED(get(key, v));
  return v->as_string(out);
}

SRESULT JsonValue::get_int(std::string_view key, std::int64_t& out) const {
  std::shared_ptr<const JsonValue> v;
  HS_RETURN_IF_FAILED(get(key, v));
  return v->as_int(out);
}

}  // namespace ieso
