/**
 * @file cloud_client.hpp
 * @brief Cloud Client actor: mTLS egress of sanitized events to the backend, ack tracking (DESIGN.md §8).
 * @details Batches CloudEventSanitized and ships them as OTLP/HTTP JSON (metrics + logs) to the OTel Collector;
 *          incident-class events also go to the control plane index, and sanitized incident bundles are uploaded.
 *          Delivered -> TelemetryDelivered (spool acks). Failed -> SpooledEvent + NetworkStatusChanged(offline);
 *          a health probe brings it back online and the Spooler drains (at-least-once, backend dedupes by id).
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include "ieso/core/actor.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"
#include "ieso/core/http_transport.hpp"
#include "ieso/core/otlp_json.hpp"

namespace ieso {

/**
 * @brief libcurl transport, the sensor's only HTTP client: TLS 1.3 only, CA pinning, client certificate (mTLS).
 * @details TLS 1.3 is enforced per TLS backend of the linked libcurl:
 *          - OpenSSL / BoringSSL / wolfSSL: CURLOPT_SSLVERSION min = max = TLS 1.3.
 *          - LibreSSL (macOS system libcurl, which cannot set a minimum version): only TLS 1.3 cipher suites are
 *            offered, so a TLS 1.2 handshake cannot be negotiated.
 *          - Anything else: Create() fails (fail closed).
 *          Every response also reports the negotiated version; anything but TLSv1.3 is rejected (status 0).
 */
class CurlTransport final : public ITransportClient {
 public:
  /**
   * @brief Creates a transport.
   * @param[in] tls TLS material.
   * @param[out] out Transport.
   * @return SRESULT::Ok, NotFound (missing cert files) or Internal (libcurl init).
   */
  static SRESULT Create(const TlsConfig& tls, std::unique_ptr<CurlTransport>& out);

  /// @brief How TLS 1.3 is enforced for the linked libcurl's TLS backend.
  enum class Tls13Policy : std::uint8_t {
    MinMaxVersion,       ///< CURLOPT_SSLVERSION = TLSv1_3 | MAX_TLSv1_3.
    Tls13CiphersOnly,    ///< Offer only TLS 1.3 cipher suites (LibreSSL).
  };

  /// @brief Use Create(). @param[in] tls TLS material. @param[in] policy Enforcement method.
  CurlTransport(TlsConfig tls, Tls13Policy policy);
  /// @copydoc ITransportClient::request
  SRESULT request(const std::string& method, const std::string& url, const std::vector<std::string>& headers,
                  const std::string& body, HttpResponse& out) override;

 private:
  const TlsConfig tls_;        ///< TLS material.
  const Tls13Policy policy_;   ///< TLS 1.3 enforcement.
};

/// @brief Cloud Client options.
struct CloudClientOptions {
  std::string otlp_base = "https://localhost:4318";          ///< OTel Collector OTLP/HTTP base URL.
  std::string control_base = "https://localhost:8443";       ///< Control plane base URL.
  std::string collector_health = "https://localhost:13133/";  ///< Collector health_check URL (TLS 1.3 + mTLS).
  std::filesystem::path incident_dir;                        ///< Where sanitized bundles are read from.
  std::chrono::milliseconds flush_period{500};               ///< Batch flush timer.
  std::size_t max_batch = 200;                               ///< Flush early at this size.
  std::chrono::milliseconds health_period{5000};             ///< Probe period while offline.
  std::size_t max_pending_uploads = 64;                      ///< Bundle upload retry queue bound.
  std::chrono::milliseconds probe_poll_period{3000};         ///< Signed probe request poll (FR-14) while online.
};

/**
 * @brief Cloud Client actor.
 */
class CloudClientActor final : public Actor {
 public:
  /**
   * @brief Creates the actor.
   * @param[in] bus Bus; must outlive the actor.
   * @param[in] factory Factory; must outlive the actor.
   * @param[in] transport HTTP transport (owned).
   * @param[in] resource OTLP resource attributes (endpoint id).
   * @param[in] opts Options.
   */
  CloudClientActor(EventBus& bus, EventFactory& factory, std::unique_ptr<ITransportClient> transport, OtlpResource resource,
                   CloudClientOptions opts);
  /// @copydoc Actor::on_start
  SRESULT on_start(ActorContext& ctx) override;
  /// @copydoc Actor::on_stop
  SRESULT on_stop() override;

 private:
  /// @brief A sanitized bundle waiting for upload.
  struct Upload {
    std::string incident_id;  ///< Incident id.
    std::string ref;          ///< File name in incident_dir.
    std::string sha256;       ///< Expected hash.
  };

  /// @brief Queues an envelope; incidents flush at once. @param[in] env Envelope. @return Flush result or Ok.
  SRESULT on_envelope(const std::shared_ptr<const CloudEventSanitized>& env);
  /// @brief Sends the batch (or spools it while offline). @return SRESULT::Ok or NoOp.
  SRESULT flush();
  /// @brief Probes the backend while offline. @return SRESULT::Ok or NoOp.
  SRESULT health();
  /// @brief Fetches signed probe requests and posts ProbeRequested (verified by Diagnostics). @return Ok or NoOp.
  SRESULT poll_probes();
  /// @brief Uploads pending bundles. @return SRESULT::Ok or NoOp.
  SRESULT upload_bundles();
  /**
   * @brief Posts one JSON body.
   * @param[in] url URL.
   * @param[in] body JSON.
   * @param[out] status HTTP status (0 = transport failure).
   * @return SRESULT::Ok.
   */
  SRESULT post_json(const std::string& url, const std::string& body, long& status);
  /// @brief Hands envelopes to the Spooler. @param[in] envs Envelopes. @return SRESULT::Ok.
  SRESULT spool(const Envelopes& envs);
  /// @brief Online/offline transition (posts NetworkStatusChanged on change). @param[in] online New state. @return Ok.
  SRESULT set_online(bool online);
  /// @brief Queues the bundle announced by an IncidentBundleReady envelope. @param[in] env Envelope. @return Ok or NoOp.
  SRESULT queue_upload(const CloudEventSanitized& env);

  EventBus& bus_;                            ///< Bus.
  EventFactory& factory_;                    ///< Factory.
  std::unique_ptr<ITransportClient> transport_;    ///< HTTP.
  const OtlpResource resource_;              ///< OTLP resource.
  const CloudClientOptions opts_;            ///< Options.
  Envelopes batch_;                          ///< Pending envelopes.
  std::deque<Upload> uploads_;               ///< Pending bundle uploads.
  bool online_ = false;                      ///< Backend reachable.
  bool known_ = false;                       ///< online_ has been established once.
  std::uint64_t delivered_ = 0;              ///< Envelopes acked.
};

}  // namespace ieso
