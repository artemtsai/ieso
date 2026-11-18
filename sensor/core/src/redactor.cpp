/**
 * @file redactor.cpp
 * @brief Redaction passes. Each pass is a single linear scan.
 */
#include "ieso/core/redactor.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <fmt/format.h>

namespace ieso {
namespace {

/// @brief Secret-bearing keys (compared case-insensitively).
constexpr std::array<std::string_view, 10> kSecretKeys = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_token", "authorization", "auth"};

/**
 * @brief ASCII class tests on raw bytes (safe for any char value).
 * @param[in] c Byte.
 * @param[out] out Result.
 * @return SRESULT::Ok.
 */
SRESULT is_alnum(char c, bool& out) {
  out = std::isalnum(static_cast<unsigned char>(c)) != 0;
  return SRESULT::Ok;
}

/// @brief Email local-part char. @param[in] c Byte. @param[out] out Result. @return Ok.
SRESULT is_email_local(char c, bool& out) {
  HS_RETURN_IF_FAILED(is_alnum(c, out));
  out = out || c == '.' || c == '_' || c == '%' || c == '+' || c == '-';
  return SRESULT::Ok;
}

/// @brief Email domain char. @param[in] c Byte. @param[out] out Result. @return Ok.
SRESULT is_email_domain(char c, bool& out) {
  HS_RETURN_IF_FAILED(is_alnum(c, out));
  out = out || c == '.' || c == '-';
  return SRESULT::Ok;
}

/// @brief Hex digit. @param[in] c Byte. @param[out] out Result. @return Ok.
SRESULT is_hex(char c, bool& out) {
  out = std::isxdigit(static_cast<unsigned char>(c)) != 0;
  return SRESULT::Ok;
}

/// @brief Token char for secret runs (base64/url-safe). @param[in] c Byte. @param[out] out Result. @return Ok.
SRESULT is_token_char(char c, bool& out) {
  HS_RETURN_IF_FAILED(is_alnum(c, out));
  out = out || c == '+' || c == '/' || c == '=' || c == '_' || c == '-';
  return SRESULT::Ok;
}

/**
 * @brief Case-insensitive ASCII equality.
 * @param[in] a Left.
 * @param[in] b Right.
 * @param[out] out True if equal.
 * @return SRESULT::Ok.
 */
SRESULT iequals(std::string_view a, std::string_view b, bool& out) {
  out = a.size() == b.size();
  for (std::size_t i = 0; out && i < a.size(); ++i) {
    out = std::tolower(static_cast<unsigned char>(a[i])) == std::tolower(static_cast<unsigned char>(b[i]));
  }
  return SRESULT::Ok;
}

/**
 * @brief Tries to parse an IPv4 literal at @p pos.
 * @param[in] s Text.
 * @param[in] pos Start index (must not follow an alnum/dot).
 * @param[out] len Length of the literal, 0 if none.
 * @return SRESULT::Ok.
 */
SRESULT match_ipv4(std::string_view s, std::size_t pos, std::size_t& len) {
  len = 0;
  std::size_t i = pos;
  for (int octet = 0; octet < 4; ++octet) {
    if (octet > 0) {
      if (i >= s.size() || s[i] != '.') return SRESULT::Ok;
      ++i;
    }
    std::size_t digits = 0;
    int value = 0;
    while (i < s.size() && digits < 4 && std::isdigit(static_cast<unsigned char>(s[i]))) {
      value = value * 10 + (s[i] - '0');
      ++i;
      ++digits;
    }
    if (digits == 0 || digits > 3 || value > 255) return SRESULT::Ok;
  }
  bool an = false;
  if (i < s.size()) HS_RETURN_IF_FAILED(is_alnum(s[i], an));
  if (an || (i < s.size() && s[i] == '.' && i + 1 < s.size() && std::isdigit(static_cast<unsigned char>(s[i + 1])))) {
    return SRESULT::Ok;
  }
  len = i - pos;
  return SRESULT::Ok;
}

/**
 * @brief Tries to parse an IPv6-looking literal at @p pos (hex groups with >= 3 colons or "::").
 * @param[in] s Text.
 * @param[in] pos Start index.
 * @param[out] len Length, 0 if none.
 * @return SRESULT::Ok.
 */
SRESULT match_ipv6(std::string_view s, std::size_t pos, std::size_t& len) {
  len = 0;
  std::size_t i = pos;
  std::size_t colons = 0;
  std::size_t hex = 0;
  bool double_colon = false;
  std::size_t group = 0;
  while (i < s.size()) {
    bool hx = false;
    HS_RETURN_IF_FAILED(is_hex(s[i], hx));
    if (hx) {
      if (++group > 4) return SRESULT::Ok;
      ++hex;
    } else if (s[i] == ':') {
      if (i > pos && s[i - 1] == ':') double_colon = true;
      ++colons;
      group = 0;
    } else {
      break;
    }
    ++i;
  }
  bool an = false;
  if (i < s.size()) HS_RETURN_IF_FAILED(is_alnum(s[i], an));
  if (an || hex == 0 || colons > 7 || (colons < 3 && !(double_colon && colons >= 2))) return SRESULT::Ok;
  len = i - pos;
  return SRESULT::Ok;
}

}  // namespace

Redactor::Redactor(std::string ip_salt) : salt_(std::move(ip_salt)) {}

SRESULT Redactor::hash_ip(std::string_view ip, std::string& out) const {
  std::uint64_t h = 1469598103934665603ull;  // FNV-1a 64
  for (const char c : salt_) h = (h ^ static_cast<unsigned char>(c)) * 1099511628211ull;
  h = (h ^ 0xFFu) * 1099511628211ull;
  for (const char c : ip) h = (h ^ static_cast<unsigned char>(c)) * 1099511628211ull;
  out = fmt::format("ip:{:08x}", static_cast<std::uint32_t>(h ^ (h >> 32)));
  return SRESULT::Ok;
}

SRESULT Redactor::pass_kv_secrets(std::string_view in, std::string& out) const {
  out.clear();
  std::size_t i = 0;
  while (i < in.size()) {
    // Find a key token [A-Za-z_]+ followed by '=' or ':' (optionally one space).
    bool an = false;
    HS_RETURN_IF_FAILED(is_alnum(in[i], an));
    if (!(an || in[i] == '_') || (i > 0 && (std::isalnum(static_cast<unsigned char>(in[i - 1])) || in[i - 1] == '_'))) {
      out.push_back(in[i++]);
      continue;
    }
    std::size_t j = i;
    while (j < in.size() && (std::isalnum(static_cast<unsigned char>(in[j])) || in[j] == '_')) ++j;
    const std::string_view key = in.substr(i, j - i);
    bool secret = false;
    bool whole_segment = false;  // "Authorization: Bearer x" -> scheme and credential both go
    HS_RETURN_IF_FAILED(iequals(key, "authorization", whole_segment));
    for (const auto k : kSecretKeys) {
      bool eq = false;
      HS_RETURN_IF_FAILED(iequals(key, k, eq));
      secret = secret || eq;
    }
    std::size_t v = j;
    if (secret && v < in.size() && (in[v] == '=' || in[v] == ':')) {
      ++v;
      while (v < in.size() && in[v] == ' ') ++v;
      std::size_t e = v;
      const bool quoted = e < in.size() && (in[e] == '"' || in[e] == '\'');
      const char q = quoted ? in[e] : '\0';
      if (quoted) ++e;
      while (e < in.size() && (quoted ? in[e] != q
                                      : ((whole_segment || in[e] != ' ') && in[e] != '&' && in[e] != ',' &&
                                         in[e] != ';' && in[e] != '\n'))) {
        ++e;
      }
      if (quoted && e < in.size()) ++e;
      if (e > v) {
        out.append(in.substr(i, v - i));
        out += "<redacted>";
        i = e;
        continue;
      }
    }
    out.append(key);
    i = j;
  }
  return SRESULT::Ok;
}

SRESULT Redactor::pass_bearer(std::string_view in, std::string& out) const {
  out.clear();
  std::size_t i = 0;
  while (i < in.size()) {
    bool eq = false;
    if (i + 7 <= in.size()) HS_RETURN_IF_FAILED(iequals(in.substr(i, 7), "bearer ", eq));
    if (eq) {
      std::size_t e = i + 7;
      while (e < in.size() && in[e] == ' ') ++e;
      const std::size_t v = e;
      bool tc = true;
      while (e < in.size() && tc) {
        HS_RETURN_IF_FAILED(is_token_char(in[e], tc));
        if (tc || in[e] == '.') {
          tc = true;
          ++e;
        }
      }
      if (e > v) {
        out.append(in.substr(i, 7));
        out += "<token>";
        i = e;
        continue;
      }
    }
    out.push_back(in[i++]);
  }
  return SRESULT::Ok;
}

SRESULT Redactor::pass_emails(std::string_view in, std::string& out) const {
  out.clear();
  std::size_t emitted = 0;  // in[0, emitted) already copied to out
  for (std::size_t at = in.find('@'); at != std::string_view::npos; at = in.find('@', at + 1)) {
    if (at < emitted) continue;
    std::size_t l = at;
    bool ok = true;
    while (l > emitted && ok) {
      HS_RETURN_IF_FAILED(is_email_local(in[l - 1], ok));
      if (ok) --l;
    }
    std::size_t r = at + 1;
    bool has_dot = false;
    ok = true;
    while (r < in.size() && ok) {
      HS_RETURN_IF_FAILED(is_email_domain(in[r], ok));
      if (ok) {
        has_dot = has_dot || in[r] == '.';
        ++r;
      }
    }
    while (r > at + 1 && (in[r - 1] == '.' || in[r - 1] == '-')) --r;  // trailing punctuation
    has_dot = in.substr(at + 1, r - at - 1).find('.') != std::string_view::npos;
    if (l < at && has_dot && r > at + 3) {
      out.append(in.substr(emitted, l - emitted));
      out += "<email>";
      emitted = r;
      at = r - 1;
    }
  }
  out.append(in.substr(emitted));
  return SRESULT::Ok;
}

SRESULT Redactor::pass_home_paths(std::string_view in, std::string& out) const {
  out.clear();
  std::size_t i = 0;
  while (i < in.size()) {
    std::size_t prefix = 0;
    if (in.substr(i, 7) == "/Users/") prefix = 7;
    else if (in.substr(i, 6) == "/home/") prefix = 6;
    if (prefix != 0) {
      std::size_t e = i + prefix;
      while (e < in.size() && in[e] != '/' && in[e] != ' ' && in[e] != '"' && in[e] != '\'' && in[e] != ':') ++e;
      const std::string_view user = in.substr(i + prefix, e - i - prefix);
      if (!user.empty() && user != "Shared" && user != "<user>") {
        out.append(in.substr(i, prefix));
        out += "<user>";
        i = e;
        continue;
      }
    }
    out.push_back(in[i++]);
  }
  return SRESULT::Ok;
}

SRESULT Redactor::pass_ips(std::string_view in, std::string& out) const {
  out.clear();
  std::size_t i = 0;
  while (i < in.size()) {
    bool prev_word = false;
    if (i > 0) {
      HS_RETURN_IF_FAILED(is_alnum(in[i - 1], prev_word));
      prev_word = prev_word || in[i - 1] == '.' || in[i - 1] == ':';
    }
    if (!prev_word) {
      std::size_t len = 0;
      HS_RETURN_IF_FAILED(match_ipv4(in, i, len));
      if (len == 0) HS_RETURN_IF_FAILED(match_ipv6(in, i, len));
      if (len != 0) {
        std::string token;
        HS_RETURN_IF_FAILED(hash_ip(in.substr(i, len), token));
        out += token;
        i += len;
        continue;
      }
    }
    out.push_back(in[i++]);
  }
  return SRESULT::Ok;
}

SRESULT Redactor::pass_long_secrets(std::string_view in, std::string& out) const {
  out.clear();
  std::size_t i = 0;
  while (i < in.size()) {
    bool tc = false;
    HS_RETURN_IF_FAILED(is_token_char(in[i], tc));
    if (!tc) {
      out.push_back(in[i++]);
      continue;
    }
    std::size_t e = i;
    bool all_hex = true, has_digit = false, has_alpha = false;
    while (e < in.size()) {
      HS_RETURN_IF_FAILED(is_token_char(in[e], tc));
      if (!tc) break;
      bool hx = false;
      HS_RETURN_IF_FAILED(is_hex(in[e], hx));
      all_hex = all_hex && hx;
      has_digit = has_digit || std::isdigit(static_cast<unsigned char>(in[e]));
      has_alpha = has_alpha || std::isalpha(static_cast<unsigned char>(in[e]));
      ++e;
    }
    const std::size_t len = e - i;
    const std::string_view run = in.substr(i, len);
    const bool is_path_like = run.find('/') != std::string_view::npos && run.find('=') == std::string_view::npos &&
                              run.find('+') == std::string_view::npos;
    if ((all_hex && len >= 32) || (!is_path_like && len >= 40 && has_digit && has_alpha)) {
      out += "<secret>";
    } else {
      out.append(run);
    }
    i = e;
  }
  return SRESULT::Ok;
}

SRESULT Redactor::redact(std::string_view in, std::string& out) const {
  std::string a, b;
  HS_RETURN_IF_FAILED(pass_kv_secrets(in, a));
  HS_RETURN_IF_FAILED(pass_bearer(a, b));
  HS_RETURN_IF_FAILED(pass_emails(b, a));
  HS_RETURN_IF_FAILED(pass_home_paths(a, b));
  HS_RETURN_IF_FAILED(pass_ips(b, a));
  HS_RETURN_IF_FAILED(pass_long_secrets(a, out));
  return SRESULT::Ok;
}

SRESULT Redactor::redact_free_text(std::string_view in, std::string& out) const {
  HS_RETURN_IF_FAILED(redact(in, out));
  if (out.size() > kMaxFreeText) {
    std::size_t cut = kMaxFreeText;
    while (cut > 0 && (static_cast<unsigned char>(out[cut]) & 0xC0) == 0x80) --cut;  // keep UTF-8 whole
    out.resize(cut);
    out += "...[truncated]";
  }
  return SRESULT::Ok;
}

}  // namespace ieso
