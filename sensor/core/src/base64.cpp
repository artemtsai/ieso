/**
 * @file base64.cpp
 * @brief base64 decoder (iterative, bounds-checked).
 */
#include "ieso/core/base64.hpp"

#include <cstdint>

namespace ieso {

SRESULT base64_decode(std::string_view in, std::string& out) {
  out.clear();
  std::uint32_t acc = 0;
  int bits = 0;
  std::size_t pad = 0;
  std::size_t symbols = 0;
  for (const char c : in) {
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
    if (c == '=') {
      ++pad;
      ++symbols;
      continue;
    }
    if (pad != 0) return SRESULT::CorruptData;  // data after padding
    std::uint32_t v = 0;
    if (c >= 'A' && c <= 'Z') v = static_cast<std::uint32_t>(c - 'A');
    else if (c >= 'a' && c <= 'z') v = static_cast<std::uint32_t>(c - 'a' + 26);
    else if (c >= '0' && c <= '9') v = static_cast<std::uint32_t>(c - '0' + 52);
    else if (c == '+') v = 62;
    else if (c == '/') v = 63;
    else return SRESULT::CorruptData;
    acc = (acc << 6) | v;
    bits += 6;
    ++symbols;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((acc >> bits) & 0xFF));
    }
  }
  if (symbols % 4 != 0 || pad > 2) return SRESULT::CorruptData;
  return SRESULT::Ok;
}

}  // namespace ieso
