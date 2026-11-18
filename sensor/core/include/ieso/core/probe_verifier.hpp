/**
 * @file probe_verifier.hpp
 * @brief Verifies the control plane's signature on a remote probe request (FR-14, NFR-10, DESIGN.md §12).
 * @details Probes are IDs from a signed allowlist, never commands. A compromised backend cannot make the endpoint run
 *          anything without the offline-held signing key; the sensor pins the public key.
 */
#pragma once

#include <string_view>

#include "ieso/core/sresult.hpp"

namespace ieso {

/**
 * @brief Signature check for canonical probe requests.
 * @note Implementations are platform specific (macOS: Security.framework ECDSA P-256); absent = refuse all.
 */
class IProbeVerifier {
 public:
  virtual ~IProbeVerifier() = default;
  /**
   * @brief Checks @p signature over @p message.
   * @param[in] message Canonical request "v1|request_id|endpoint|probe_id|incident_id|issued_at|expires_at".
   * @param[in] signature DER-encoded ECDSA signature (already base64-decoded).
   * @param[out] valid True only for a valid signature by the pinned key.
   * @return SRESULT::Ok (inspect @p valid) or an internal failure.
   */
  virtual SRESULT verify(std::string_view message, std::string_view signature, bool& valid) const = 0;
};

}  // namespace ieso
