/**
 * @file base64.hpp
 * @brief Standard base64 (RFC 4648) decoding for signatures received from the control plane.
 */
#pragma once

#include <string>
#include <string_view>

#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Decodes standard base64 (A–Z a–z 0–9 + /, '=' padding). Whitespace is ignored.
 * @param[in] in Encoded text.
 * @param[out] out Decoded bytes.
 * @retval SRESULT::Ok
 * @retval SRESULT::CorruptData Invalid character or length.
 */
SRESULT base64_decode(std::string_view in, std::string& out);

}  // namespace ieso
