/**
 * @file codec.hpp
 * @brief Spool payload codec interface; the codec id is stored per record.
 * @note Only IdentityCodec ships in step 1. A zstd codec (NFR-5) plugs in behind the same interface.
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief Payload encoder/decoder. Implementations must be thread-safe and deterministic.
class ICodec {
 public:
  virtual ~ICodec() = default;
  /**
   * @brief Stable codec id written into each record.
   * @param[out] out Id (0 = identity).
   * @return SRESULT::Ok.
   */
  virtual SRESULT id(std::uint8_t& out) const = 0;
  /**
   * @brief Encodes a payload.
   * @param[in] in Plain bytes.
   * @param[out] out Encoded bytes.
   * @return SRESULT::Ok or SRESULT::Internal.
   */
  virtual SRESULT encode(std::string_view in, std::string& out) const = 0;
  /**
   * @brief Decodes a payload.
   * @param[in] in Encoded bytes.
   * @param[out] out Plain bytes.
   * @return SRESULT::Ok or SRESULT::CorruptData.
   */
  virtual SRESULT decode(std::string_view in, std::string& out) const = 0;
};

/// @brief Pass-through codec (id 0).
class IdentityCodec final : public ICodec {
 public:
  /// @copydoc ICodec::id
  SRESULT id(std::uint8_t& out) const override {
    out = 0;
    return SRESULT::Ok;
  }
  /// @copydoc ICodec::encode
  SRESULT encode(std::string_view in, std::string& out) const override {
    out.assign(in);
    return SRESULT::Ok;
  }
  /// @copydoc ICodec::decode
  SRESULT decode(std::string_view in, std::string& out) const override {
    out.assign(in);
    return SRESULT::Ok;
  }
};

}  // namespace ieso
