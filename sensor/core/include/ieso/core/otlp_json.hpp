/**
 * @file otlp_json.hpp
 * @brief Encodes sanitized CloudEvents as OTLP/HTTP JSON (logs and gauge metrics). No protobuf dependency.
 * @details DESIGN.md §11 "Ingress": the OTel Collector receives metrics and logs.
 *          TelemetrySnapshotCaptured -> gauges; every other egress event -> one log record whose body is the
 *          CloudEvent JSON (so the full sanitized event is searchable in Loki).
 */
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "ontology/events.hpp"
#include "ieso/core/sresult.hpp"

namespace ieso {

/// @brief OTLP resource attributes describing this sensor.
struct OtlpResource {
  std::string service_name = "ieso-sensor";  ///< service.name.
  std::string service_version = "0.3.0";       ///< service.version.
  std::string instance_id;                     ///< service.instance.id = endpoint id.
};

/// @brief Envelope list type used by the encoders.
using Envelopes = std::vector<std::shared_ptr<const CloudEventSanitized>>;

/**
 * @brief True if the envelope carries a TelemetrySnapshotCaptured (encoded as metrics).
 * @param[in] env Envelope.
 * @param[out] out Result.
 * @return SRESULT::Ok.
 */
SRESULT otlp_is_metric(const CloudEventSanitized& env, bool& out);

/**
 * @brief Encodes envelopes as an OTLP ExportLogsServiceRequest.
 * @param[in] res Resource attributes.
 * @param[in] envs Envelopes (non-metric).
 * @param[out] out JSON body for POST /v1/logs.
 * @return SRESULT::Ok or a JSON writer error.
 */
SRESULT otlp_logs_json(const OtlpResource& res, const Envelopes& envs, std::string& out);

/**
 * @brief Encodes TelemetrySnapshotCaptured envelopes as an OTLP ExportMetricsServiceRequest (gauges).
 * @param[in] res Resource attributes.
 * @param[in] envs Snapshot envelopes; others are skipped.
 * @param[out] out JSON body for POST /v1/metrics.
 * @retval SRESULT::Ok
 * @retval SRESULT::CorruptData An envelope's data is not valid JSON.
 */
SRESULT otlp_metrics_json(const OtlpResource& res, const Envelopes& envs, std::string& out);

}  // namespace ieso
