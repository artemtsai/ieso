/**
 * @file http_transport.hpp
 * @brief Minimal HTTP transport interface used by the Cloud Client, plus its TLS material.
 * @details Design rule (CLAUDE.md): all HTTP(S) in the sensor goes through libcurl behind this one interface
 *          (CurlTransport); tests substitute fakes. Transport rule (DESIGN.md NFR-6): TLS 1.3 only with mTLS;
 *          TLS 1.2 and older are refused, never negotiated down.
 */
#pragma once

#include <string>
#include <vector>

#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief HTTP response.
struct HttpResponse {
  long status = 0;          ///< HTTP status; 0 = transport failure (DNS, TLS refused, timeout, ...).
  std::string body;         ///< Response body (truncated to 64 KB).
  std::string tls_version;  ///< Negotiated protocol, e.g. "TLSv1.3" (empty if no handshake completed).
};

/**
 * @brief Minimal HTTP transport so the actor is testable without a network.
 * @note Called only from the Cloud Client actor thread.
 */
class ITransportClient {
 public:
  virtual ~ITransportClient() = default;
  /**
   * @brief Performs one request.
   * @param[in] method "GET", "POST" or "PUT".
   * @param[in] url Absolute URL.
   * @param[in] headers "Name: value" lines.
   * @param[in] body Request body (empty for GET).
   * @param[out] out Response; status 0 on transport failure.
   * @return SRESULT::Ok (inspect out.status) or InvalidArgument.
   */
  virtual SRESULT request(const std::string& method, const std::string& url, const std::vector<std::string>& headers,
                          const std::string& body, HttpResponse& out) = 0;
};

/// @brief TLS material for the backend (stub of FR-6 enrollment: local CA + PKCS#12 identity).
/// @note Transport rule: TLS 1.3 only with mutual authentication; implementations must refuse TLS 1.2 and older.
struct TlsConfig {
  std::string ca_file;          ///< PEM of the only trusted CA (pinned backend CA, NFR-6).
  std::string client_p12;       ///< Endpoint identity (PKCS#12). Empty = no client certificate.
  std::string p12_password;     ///< PKCS#12 password.
};

}  // namespace ieso
