/**
 * @file ecdsa_probe_verifier.cpp
 * @brief EcdsaProbeVerifier: PEM SPKI -> X9.63 point -> SecKey; SecKeyVerifySignature (ECDSA X9.62 SHA-256).
 */
#include "ieso/macos/ecdsa_probe_verifier.hpp"

#include <fstream>
#include <iterator>

#include "ieso/core/base64.hpp"
#include "ieso/core/trace.hpp"

namespace ieso::macos {
namespace {
constexpr std::string_view kComponent = "probe-verify";
constexpr std::size_t kP256SpkiSize = 91;   // SEQUENCE{ AlgorithmIdentifier(ecPublicKey, prime256v1), BIT STRING }
constexpr std::size_t kP256PointSize = 65;  // 0x04 || X || Y
}  // namespace

EcdsaProbeVerifier::EcdsaProbeVerifier(CfRef<SecKeyRef> key) : key_(std::move(key)) {}

SRESULT EcdsaProbeVerifier::Create(const std::string& pem_path, std::unique_ptr<EcdsaProbeVerifier>& out) {
  std::ifstream f(pem_path);
  if (!f.is_open()) {
    HS_TRACE_ERROR(kComponent, "probe signing key not found: {}", pem_path);
    return SRESULT::NotFound;
  }
  const std::string pem((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  constexpr std::string_view kBegin = "-----BEGIN PUBLIC KEY-----";
  constexpr std::string_view kEnd = "-----END PUBLIC KEY-----";
  const auto b = pem.find(kBegin);
  const auto e = pem.find(kEnd);
  if (b == std::string::npos || e == std::string::npos || e < b) return SRESULT::CorruptData;
  std::string der;
  HS_RETURN_IF_FAILED(base64_decode(std::string_view(pem).substr(b + kBegin.size(), e - b - kBegin.size()), der));
  if (der.size() != kP256SpkiSize || static_cast<unsigned char>(der[kP256SpkiSize - kP256PointSize]) != 0x04) {
    HS_TRACE_ERROR(kComponent, "{} is not a P-256 public key ({} bytes)", pem_path, der.size());
    return SRESULT::CorruptData;
  }
  const std::string point = der.substr(kP256SpkiSize - kP256PointSize);
  CfRef<CFDataRef> data(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(point.data()),
                                     static_cast<CFIndex>(point.size())));
  const void* keys[] = {kSecAttrKeyType, kSecAttrKeyClass};                       // C API boundary
  const void* values[] = {kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPublic};
  CfRef<CFDictionaryRef> attrs(CFDictionaryCreate(kCFAllocatorDefault, keys, values, 2,
                                                  &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
  CFErrorRef err = nullptr;  // C API out-parameter, adopted below
  CfRef<SecKeyRef> key(SecKeyCreateWithData(*data, *attrs, &err));
  CfRef<CFErrorRef> err_owner(err);
  if (!key) {
    HS_TRACE_ERROR(kComponent, "SecKeyCreateWithData rejected the probe signing key");
    return SRESULT::CorruptData;
  }
  out = std::make_unique<EcdsaProbeVerifier>(std::move(key));
  HS_TRACE_INFO(kComponent, "pinned probe-signing key loaded from {}", pem_path);
  return SRESULT::Ok;
}

SRESULT EcdsaProbeVerifier::verify(std::string_view message, std::string_view signature, bool& valid) const {
  valid = false;
  CfRef<CFDataRef> msg(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(message.data()),
                                    static_cast<CFIndex>(message.size())));
  CfRef<CFDataRef> sig(CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(signature.data()),
                                    static_cast<CFIndex>(signature.size())));
  if (!msg || !sig) return SRESULT::OutOfMemory;
  CFErrorRef err = nullptr;  // C API out-parameter, adopted below
  valid = SecKeyVerifySignature(*key_, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, *msg, *sig, &err);
  CfRef<CFErrorRef> err_owner(err);
  return SRESULT::Ok;
}

}  // namespace ieso::macos
