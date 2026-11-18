/**
 * @file binary_io.hpp
 * @brief Little-endian binary encoding helpers and CRC-32 for on-disk records (spool, flight-recorder checkpoint).
 * @details Fixed-width little-endian fields keep files portable across architectures; every reader is
 *          bounds-checked and returns CorruptData instead of reading past the end.
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "ieso/core/sresult.hpp"

namespace ieso::bin {

/**
 * @brief Bitwise CRC-32 (IEEE 802.3). Inputs are small, so table-free is fine.
 * @param[in] data Bytes.
 * @param[out] out Checksum.
 * @return SRESULT::Ok.
 */
inline SRESULT crc32(std::string_view data, std::uint32_t& out) {
  std::uint32_t crc = 0xFFFFFFFFu;
  for (const char ch : data) {
    crc ^= static_cast<unsigned char>(ch);
    for (int k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
  }
  out = ~crc;
  return SRESULT::Ok;
}

/**
 * @brief Appends a little-endian unsigned integer.
 * @tparam T Unsigned integer type.
 * @param[in,out] out Buffer.
 * @param[in] v Value.
 * @return SRESULT::Ok.
 */
template <class T>
SRESULT put_le(std::string& out, T v) {
  for (std::size_t i = 0; i < sizeof(T); ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xFF));
  return SRESULT::Ok;
}

/// @brief Appends a signed 64-bit integer (two's complement). @param[in,out] out Buffer. @param[in] v Value. @return Ok.
inline SRESULT put_i64(std::string& out, std::int64_t v) { return put_le<std::uint64_t>(out, static_cast<std::uint64_t>(v)); }

/// @brief Appends a double as its IEEE-754 bit pattern. @param[in,out] out Buffer. @param[in] v Value. @return Ok.
inline SRESULT put_f64(std::string& out, double v) {
  std::uint64_t bits = 0;
  static_assert(sizeof(bits) == sizeof(v), "IEEE-754 double expected");
  std::memcpy(&bits, &v, sizeof(bits));
  return put_le<std::uint64_t>(out, bits);
}

/// @brief Appends a length-prefixed string. @param[in,out] out Buffer. @param[in] s Bytes. @return Ok.
inline SRESULT put_str(std::string& out, std::string_view s) {
  HS_RETURN_IF_FAILED(put_le<std::uint32_t>(out, static_cast<std::uint32_t>(s.size())));
  out.append(s);
  return SRESULT::Ok;
}

/// @brief Sequential, bounds-checked reader.
struct Reader {
  std::string_view data;  ///< Bytes.
  std::size_t pos = 0;    ///< Cursor.

  /// @brief Reads a little-endian unsigned integer. @tparam T Type. @param[out] v Value. @return Ok or CorruptData.
  template <class T>
  SRESULT le(T& v) {
    if (pos + sizeof(T) > data.size()) return SRESULT::CorruptData;
    v = 0;
    for (std::size_t i = 0; i < sizeof(T); ++i) {
      v = static_cast<T>(v | (static_cast<T>(static_cast<unsigned char>(data[pos + i])) << (8 * i)));
    }
    pos += sizeof(T);
    return SRESULT::Ok;
  }
  /// @brief Reads a signed 64-bit integer. @param[out] v Value. @return Ok or CorruptData.
  SRESULT i64(std::int64_t& v) {
    std::uint64_t u = 0;
    HS_RETURN_IF_FAILED(le(u));
    v = static_cast<std::int64_t>(u);
    return SRESULT::Ok;
  }
  /// @brief Reads a double. @param[out] v Value. @return Ok or CorruptData.
  SRESULT f64(double& v) {
    std::uint64_t bits = 0;
    HS_RETURN_IF_FAILED(le(bits));
    std::memcpy(&v, &bits, sizeof(v));
    return SRESULT::Ok;
  }
  /// @brief Reads a length-prefixed string. @param[out] s Bytes. @return Ok or CorruptData.
  SRESULT str(std::string& s) {
    std::uint32_t n = 0;
    HS_RETURN_IF_FAILED(le(n));
    if (pos + n > data.size()) return SRESULT::CorruptData;
    s.assign(data.substr(pos, n));
    pos += n;
    return SRESULT::Ok;
  }
};

}  // namespace ieso::bin
