/**
 * @file json_reader.hpp
 * @brief Small, exception-free JSON parser producing an immutable DOM.
 * @details Used for crash reports (.ips) and `log stream --style ndjson` lines.
 *          Depth and size are bounded; malformed input returns CorruptData, never aborts.
 */
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ieso/core/sresult.hpp"

namespace ieso {

class JsonParser;

/**
 * @brief Immutable JSON value.
 * @note Children are shared, so sub-values can outlive the root safely.
 */
class JsonValue {
 public:
  /// @brief Value kind.
  enum class Kind : std::uint8_t { Null, Bool, Number, String, Array, Object };

  /// @brief Max nesting depth accepted by Parse().
  static constexpr int kMaxDepth = 64;
  /// @brief Max input size accepted by Parse() (crash reports are well below this).
  static constexpr std::size_t kMaxInput = 16u << 20;

  /**
   * @brief Parses a complete JSON document (trailing whitespace allowed).
   * @param[in] text Input.
   * @param[out] out Root value.
   * @retval SRESULT::Ok
   * @retval SRESULT::CorruptData     Syntax error or trailing garbage.
   * @retval SRESULT::CapacityExceeded Input too large or too deep.
   */
  static SRESULT Parse(std::string_view text, std::shared_ptr<const JsonValue>& out);

  /// @brief Kind of this value. @param[out] out Kind. @return SRESULT::Ok.
  SRESULT kind(Kind& out) const;
  /**
   * @brief Object member lookup (first match).
   * @param[in] key Member name.
   * @param[out] out Member value.
   * @retval SRESULT::Ok
   * @retval SRESULT::NotFound     No such key.
   * @retval SRESULT::InvalidState Not an object.
   */
  SRESULT get(std::string_view key, std::shared_ptr<const JsonValue>& out) const;
  /**
   * @brief Array element.
   * @param[in] i Index.
   * @param[out] out Element.
   * @retval SRESULT::Ok
   * @retval SRESULT::NotFound     Index out of range.
   * @retval SRESULT::InvalidState Not an array.
   */
  SRESULT at(std::size_t i, std::shared_ptr<const JsonValue>& out) const;
  /// @brief Element/member count (0 for scalars). @param[out] out Count. @return SRESULT::Ok.
  SRESULT size(std::size_t& out) const;
  /// @brief Object member names in order. @param[out] out Keys. @return Ok or InvalidState.
  SRESULT keys(std::vector<std::string>& out) const;

  /// @brief String value. @param[out] out Text. @return Ok or InvalidState.
  SRESULT as_string(std::string& out) const;
  /// @brief Integer value (numbers with fraction are truncated). @param[out] out Value. @return Ok or InvalidState.
  SRESULT as_int(std::int64_t& out) const;
  /// @brief Numeric value. @param[out] out Value. @return Ok or InvalidState.
  SRESULT as_double(double& out) const;
  /// @brief Boolean value. @param[out] out Value. @return Ok or InvalidState.
  SRESULT as_bool(bool& out) const;

  /**
   * @brief Convenience: object member as string.
   * @param[in] key Member name.
   * @param[out] out Text.
   * @return SRESULT::Ok, NotFound or InvalidState.
   */
  SRESULT get_string(std::string_view key, std::string& out) const;
  /**
   * @brief Convenience: object member as integer.
   * @param[in] key Member name.
   * @param[out] out Value.
   * @return SRESULT::Ok, NotFound or InvalidState.
   */
  SRESULT get_int(std::string_view key, std::int64_t& out) const;

 private:
  friend class JsonParser;
  Kind kind_ = Kind::Null;                                                   ///< Kind.
  bool bool_ = false;                                                        ///< Bool payload.
  double num_ = 0.0;                                                         ///< Number payload.
  std::int64_t int_ = 0;                                                     ///< Integer view of the number.
  std::string str_;                                                          ///< String payload.
  std::vector<std::shared_ptr<const JsonValue>> items_;                      ///< Array payload.
  std::vector<std::pair<std::string, std::shared_ptr<const JsonValue>>> members_;  ///< Object payload.
};

}  // namespace ieso
