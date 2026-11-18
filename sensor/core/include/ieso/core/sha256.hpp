/**
 * @file sha256.hpp
 * @brief Portable SHA-256 (FIPS 180-4) for incident bundle hashes.
 */
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Incremental SHA-256.
 * @note Not thread-safe; one instance per hash.
 */
class Sha256 {
 public:
  Sha256();

  /**
   * @brief Absorbs bytes.
   * @param[in] data Input.
   * @return SRESULT::Ok, or SRESULT::InvalidState after finish().
   */
  SRESULT update(std::string_view data);

  /**
   * @brief Completes the hash.
   * @param[out] out Lowercase hex digest (64 chars).
   * @return SRESULT::Ok, or SRESULT::InvalidState if already finished.
   */
  SRESULT finish(std::string& out);

  /**
   * @brief One-shot helper.
   * @param[in] data Input.
   * @param[out] out Hex digest.
   * @return SRESULT::Ok.
   */
  static SRESULT hex(std::string_view data, std::string& out);

 private:
  /// @brief Processes the 64-byte block in buf_. @return SRESULT::Ok.
  SRESULT compress();

  std::array<std::uint32_t, 8> h_{};      ///< State.
  std::array<std::uint8_t, 64> buf_{};    ///< Partial block.
  std::size_t buf_len_ = 0;               ///< Bytes in buf_.
  std::uint64_t total_ = 0;               ///< Total bytes.
  bool done_ = false;                     ///< finish() called.
};

}  // namespace ieso
