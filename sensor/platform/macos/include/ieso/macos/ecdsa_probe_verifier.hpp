/**
 * @file ecdsa_probe_verifier.hpp
 * @brief macOS IProbeVerifier: ECDSA P-256 / SHA-256 signature check with Security.framework (SecKey).
 * @details The control plane's public key is pinned from a PEM file (SubjectPublicKeyInfo). Only requests signed by the
 *          matching private key are accepted; there is no fallback and no other trusted key.
 */
#pragma once

#include <Security/Security.h>

#include <memory>
#include <string>

#include "ieso/core/probe_verifier.hpp"
#include "ieso/macos/cf_ref.hpp"

namespace ieso::macos {

/**
 * @brief Pinned-key ECDSA verifier.
 */
class EcdsaProbeVerifier final : public IProbeVerifier {
 public:
  /**
   * @brief Loads the pinned public key.
   * @param[in] pem_path PEM "PUBLIC KEY" (P-256 SubjectPublicKeyInfo).
   * @param[out] out Verifier.
   * @retval SRESULT::Ok
   * @retval SRESULT::NotFound    File missing.
   * @retval SRESULT::CorruptData Not a P-256 public key.
   */
  static SRESULT Create(const std::string& pem_path, std::unique_ptr<EcdsaProbeVerifier>& out);

  /// @brief Use Create(). @param[in] key Adopted SecKey.
  explicit EcdsaProbeVerifier(CfRef<SecKeyRef> key);

  /// @copydoc IProbeVerifier::verify
  SRESULT verify(std::string_view message, std::string_view signature, bool& valid) const override;

 private:
  CfRef<SecKeyRef> key_;  ///< Pinned public key.
};

}  // namespace ieso::macos
