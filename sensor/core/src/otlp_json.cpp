/**
 * @file otlp_json.cpp
 * @brief OTLP JSON encoding (proto3 JSON mapping: 64-bit integers as strings).
 */
#include "ieso/core/otlp_json.hpp"

#include <array>

#include <fmt/format.h>

#include "ieso/core/json.hpp"
#include "ieso/core/json_reader.hpp"
#include "ieso/core/time_util.hpp"

namespace ieso {
namespace {

constexpr std::string_view kSnapshotType = "com.ieso.TelemetrySnapshotCaptured";

/// @brief One gauge derived from a snapshot field.
struct GaugeDef {
  const char* name;   ///< OTel metric name.
  const char* unit;   ///< UCUM unit (drives the Prometheus suffix).
  const char* field;  ///< Snapshot data key.
  bool is_int;        ///< asInt vs asDouble.
};

constexpr std::array<GaugeDef, 5> kGauges = {{
    {"process.cpu.utilization", "%", "cpu_pct", false},
    {"process.memory.rss", "By", "rss_bytes", true},
    {"process.threads", "{thread}", "threads", true},
    {"process.open_fds", "{fd}", "fds", true},
    {"system.disk.free", "By", "disk_free_bytes", true},
}};

/**
 * @brief Writes {"key":k,"value":{"stringValue":v}}.
 * @param[in,out] w Writer.
 * @param[in] k Key.
 * @param[in] v Value.
 * @return SRESULT::Ok or writer error.
 */
SRESULT attr_str(JsonWriter& w, std::string_view k, std::string_view v) {
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("key"));
  HS_RETURN_IF_FAILED(w.value(k));
  HS_RETURN_IF_FAILED(w.key("value"));
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("stringValue"));
  HS_RETURN_IF_FAILED(w.value(v));
  HS_RETURN_IF_FAILED(w.end_object());
  return w.end_object();
}

/**
 * @brief Writes the "resource" object.
 * @param[in,out] w Writer.
 * @param[in] res Resource.
 * @return SRESULT::Ok or writer error.
 */
SRESULT write_resource(JsonWriter& w, const OtlpResource& res) {
  HS_RETURN_IF_FAILED(w.key("resource"));
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("attributes"));
  HS_RETURN_IF_FAILED(w.begin_array());
  HS_RETURN_IF_FAILED(attr_str(w, "service.name", res.service_name));
  HS_RETURN_IF_FAILED(attr_str(w, "service.version", res.service_version));
  HS_RETURN_IF_FAILED(attr_str(w, "service.instance.id", res.instance_id));
  HS_RETURN_IF_FAILED(w.end_array());
  return w.end_object();
}

/// @brief Writes the "scope" object. @param[in,out] w Writer. @param[in] res Resource. @return Ok or writer error.
SRESULT write_scope(JsonWriter& w, const OtlpResource& res) {
  HS_RETURN_IF_FAILED(w.key("scope"));
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("name"));
  HS_RETURN_IF_FAILED(w.value(std::string_view("ieso.sensor")));
  HS_RETURN_IF_FAILED(w.key("version"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(res.service_version)));
  return w.end_object();
}

/**
 * @brief Nanoseconds since the epoch as a decimal string.
 * @param[in] tp Time.
 * @param[out] out Text.
 * @return SRESULT::Ok.
 */
SRESULT nanos(std::chrono::system_clock::time_point tp, std::string& out) {
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch()).count();
  out = fmt::format("{}", ns);
  return SRESULT::Ok;
}

/**
 * @brief OTel severity for an envelope (app log level for LogRecordObserved, else by event class).
 * @param[in] env Envelope.
 * @param[out] number SeverityNumber.
 * @param[out] text SeverityText.
 * @return SRESULT::Ok.
 */
SRESULT severity(const CloudEventSanitized& env, std::int64_t& number, std::string& text) {
  number = env.hdr.cls == EventClass::Incident ? 13 : 9;
  text = env.hdr.cls == EventClass::Incident ? "WARN" : "INFO";
  if (env.type != "com.ieso.LogRecordObserved") return SRESULT::Ok;
  std::shared_ptr<const JsonValue> data;
  std::string level;
  if (JsonValue::Parse(env.data_json, data) != SRESULT::Ok || data->get_string("level", level) != SRESULT::Ok) {
    return SRESULT::Ok;
  }
  if (level == "error") {
    number = 17;
    text = "ERROR";
  } else if (level == "fault") {
    number = 21;
    text = "FATAL";
  } else if (level == "debug") {
    number = 5;
    text = "DEBUG";
  }
  return SRESULT::Ok;
}

/// @brief Class name for the event.class attribute. @param[in] c Class. @param[out] out Name. @return Ok.
SRESULT class_name(EventClass c, std::string_view& out) {
  out = c == EventClass::Incident ? "incident" : (c == EventClass::Control ? "control" : "routine");
  return SRESULT::Ok;
}

}  // namespace

SRESULT otlp_is_metric(const CloudEventSanitized& env, bool& out) {
  out = env.type == kSnapshotType;
  return SRESULT::Ok;
}

SRESULT otlp_logs_json(const OtlpResource& res, const Envelopes& envs, std::string& out) {
  JsonWriter w;
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("resourceLogs"));
  HS_RETURN_IF_FAILED(w.begin_array());
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(write_resource(w, res));
  HS_RETURN_IF_FAILED(w.key("scopeLogs"));
  HS_RETURN_IF_FAILED(w.begin_array());
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(write_scope(w, res));
  HS_RETURN_IF_FAILED(w.key("logRecords"));
  HS_RETURN_IF_FAILED(w.begin_array());
  for (const auto& env : envs) {
    std::string body, ts;
    HS_RETURN_IF_FAILED(env->to_json(body));
    HS_RETURN_IF_FAILED(nanos(env->hdr.ts, ts));
    std::int64_t sev = 9;
    std::string sev_text;
    HS_RETURN_IF_FAILED(severity(*env, sev, sev_text));
    std::string_view cls;
    HS_RETURN_IF_FAILED(class_name(env->hdr.cls, cls));
    HS_RETURN_IF_FAILED(w.begin_object());
    HS_RETURN_IF_FAILED(w.key("timeUnixNano"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(ts)));
    HS_RETURN_IF_FAILED(w.key("severityNumber"));
    HS_RETURN_IF_FAILED(w.value(sev));
    HS_RETURN_IF_FAILED(w.key("severityText"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(sev_text)));
    HS_RETURN_IF_FAILED(w.key("body"));
    HS_RETURN_IF_FAILED(w.begin_object());
    HS_RETURN_IF_FAILED(w.key("stringValue"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(body)));
    HS_RETURN_IF_FAILED(w.end_object());
    HS_RETURN_IF_FAILED(w.key("attributes"));
    HS_RETURN_IF_FAILED(w.begin_array());
    HS_RETURN_IF_FAILED(attr_str(w, "event.type", env->type));
    HS_RETURN_IF_FAILED(attr_str(w, "event.id", env->hdr.id));
    HS_RETURN_IF_FAILED(attr_str(w, "event.class", cls));
    HS_RETURN_IF_FAILED(w.end_array());
    HS_RETURN_IF_FAILED(w.end_object());
  }
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());
  return w.str(out);
}

SRESULT otlp_metrics_json(const OtlpResource& res, const Envelopes& envs, std::string& out) {
  // Parse each snapshot once; one gauge per metric with one data point per snapshot.
  std::vector<std::shared_ptr<const JsonValue>> datas;
  std::vector<std::string> times;
  for (const auto& env : envs) {
    bool metric = false;
    HS_RETURN_IF_FAILED(otlp_is_metric(*env, metric));
    if (!metric) continue;
    std::shared_ptr<const JsonValue> d;
    if (HS_FAILED(JsonValue::Parse(env->data_json, d))) return SRESULT::CorruptData;
    std::int64_t sample_ms = 0;
    std::string ts;
    if (d->get_int("sample_ts_ms", sample_ms) == SRESULT::Ok && sample_ms > 0) {
      ts = fmt::format("{}", sample_ms * 1000000);
    } else {
      HS_RETURN_IF_FAILED(nanos(env->hdr.ts, ts));
    }
    datas.push_back(std::move(d));
    times.push_back(std::move(ts));
  }

  JsonWriter w;
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("resourceMetrics"));
  HS_RETURN_IF_FAILED(w.begin_array());
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(write_resource(w, res));
  HS_RETURN_IF_FAILED(w.key("scopeMetrics"));
  HS_RETURN_IF_FAILED(w.begin_array());
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(write_scope(w, res));
  HS_RETURN_IF_FAILED(w.key("metrics"));
  HS_RETURN_IF_FAILED(w.begin_array());
  for (const GaugeDef& g : kGauges) {
    HS_RETURN_IF_FAILED(w.begin_object());
    HS_RETURN_IF_FAILED(w.key("name"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(g.name)));
    HS_RETURN_IF_FAILED(w.key("unit"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(g.unit)));
    HS_RETURN_IF_FAILED(w.key("gauge"));
    HS_RETURN_IF_FAILED(w.begin_object());
    HS_RETURN_IF_FAILED(w.key("dataPoints"));
    HS_RETURN_IF_FAILED(w.begin_array());
    for (std::size_t i = 0; i < datas.size(); ++i) {
      std::shared_ptr<const JsonValue> v;
      if (datas[i]->get(g.field, v) != SRESULT::Ok) continue;
      std::int64_t pid = 0;
      (void)datas[i]->get_int("pid", pid);  // optional attribute
      HS_RETURN_IF_FAILED(w.begin_object());
      HS_RETURN_IF_FAILED(w.key("timeUnixNano"));
      HS_RETURN_IF_FAILED(w.value(std::string_view(times[i])));
      if (g.is_int) {
        std::int64_t iv = 0;
        HS_RETURN_IF_FAILED(v->as_int(iv));
        HS_RETURN_IF_FAILED(w.key("asInt"));
        HS_RETURN_IF_FAILED(w.value(std::string_view(fmt::format("{}", iv))));
      } else {
        double dv = 0;
        HS_RETURN_IF_FAILED(v->as_double(dv));
        HS_RETURN_IF_FAILED(w.key("asDouble"));
        HS_RETURN_IF_FAILED(w.value(dv));
      }
      HS_RETURN_IF_FAILED(w.key("attributes"));
      HS_RETURN_IF_FAILED(w.begin_array());
      HS_RETURN_IF_FAILED(attr_str(w, "process.pid", fmt::format("{}", pid)));
      HS_RETURN_IF_FAILED(w.end_array());
      HS_RETURN_IF_FAILED(w.end_object());
    }
    HS_RETURN_IF_FAILED(w.end_array());
    HS_RETURN_IF_FAILED(w.end_object());
    HS_RETURN_IF_FAILED(w.end_object());
  }
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());
  return w.str(out);
}

}  // namespace ieso
