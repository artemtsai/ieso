/**
 * @file json.hpp
 * @brief Small streaming JSON writer (no parser) for CloudEvents serialization.
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ontology/events.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Builds compact JSON text with automatic comma placement.
 * @note Structural misuse (value without key in an object, unbalanced end) returns InvalidState.
 */
class JsonWriter {
 public:
  /// @brief Opens an object. @return SRESULT::Ok or SRESULT::InvalidState.
  SRESULT begin_object();
  /// @brief Closes the current object. @return SRESULT::Ok or SRESULT::InvalidState.
  SRESULT end_object();
  /// @brief Opens an array. @return SRESULT::Ok or SRESULT::InvalidState.
  SRESULT begin_array();
  /// @brief Closes the current array. @return SRESULT::Ok or SRESULT::InvalidState.
  SRESULT end_array();
  /**
   * @brief Writes an object key; the next call must write its value.
   * @param[in] k Key text (escaped).
   * @return SRESULT::Ok or SRESULT::InvalidState.
   */
  SRESULT key(std::string_view k);
  /// @brief Writes an escaped string value. @param[in] v Text. @return SRESULT::Ok or InvalidState.
  SRESULT value(std::string_view v);
  /// @brief Writes an integer value. @param[in] v Number. @return SRESULT::Ok or InvalidState.
  SRESULT value(std::int64_t v);
  /// @brief Writes a double (non-finite becomes null). @param[in] v Number. @return SRESULT::Ok or InvalidState.
  SRESULT value(double v);
  /// @brief Writes a boolean value. @param[in] v Flag. @return SRESULT::Ok or InvalidState.
  SRESULT value(bool v);
  /// @brief Deleted: a literal would otherwise bind to value(bool). Wrap it in std::string_view.
  SRESULT value(const char*) = delete;
  /// @brief Writes null. @return SRESULT::Ok or InvalidState.
  SRESULT null();
  /// @brief Writes a FieldValue as the matching JSON type. @param[in] v Value. @return SRESULT::Ok or InvalidState.
  SRESULT field_value(const FieldValue& v);
  /**
   * @brief Inserts pre-serialized JSON as a value.
   * @param[in] json Must be valid JSON; not checked.
   * @return SRESULT::Ok or SRESULT::InvalidState.
   */
  SRESULT raw(std::string_view json);
  /**
   * @brief Returns the document.
   * @param[out] out JSON text.
   * @retval SRESULT::Ok
   * @retval SRESULT::InvalidState Containers still open.
   */
  SRESULT str(std::string& out) const;

  /**
   * @brief Appends @p in to @p out with JSON string escaping (no quotes).
   * @param[in] in Raw text.
   * @param[in,out] out Destination.
   * @return SRESULT::Ok.
   */
  static SRESULT escape(std::string_view in, std::string& out);

 private:
  /// @brief Per-container state.
  struct Frame {
    bool is_object;      ///< Object vs array.
    bool has_items;      ///< Needs a comma before the next item.
    bool expect_value;   ///< Object: key written, value pending.
  };
  /// @brief Writes a separator and validates position before a value. @return Ok or InvalidState.
  SRESULT before_value();

  std::string buf_;            ///< Output.
  std::vector<Frame> stack_;   ///< Open containers.
  bool root_done_ = false;     ///< A complete root value was written.
};

/**
 * @brief Serializes fields as one JSON object.
 * @param[in] fields Payload.
 * @param[out] out JSON object text.
 * @return SRESULT::Ok or a JsonWriter error.
 */
SRESULT fields_to_json(const Fields& fields, std::string& out);

}  // namespace ieso
