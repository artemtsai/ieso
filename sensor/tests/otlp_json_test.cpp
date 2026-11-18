/**
 * @file otlp_json_test.cpp
 * @brief OTLP/HTTP JSON encoding of sanitized envelopes (logs and gauges).
 */
#include <gtest/gtest.h>

#include "ieso/core/json_reader.hpp"
#include "ieso/core/otlp_json.hpp"
#include "pii_filter/pii_filter.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {
/// @brief Builds an envelope from an event filled by @p fill. @tparam T Event. @return Envelope.
template <class T>
std::shared_ptr<const CloudEventSanitized> env(Rig& rig, PiiFilter& f, const std::function<void(T&)>& fill) {
  std::shared_ptr<T> e;
  EXPECT_EQ(rig.factory.make<T>(e), SRESULT::Ok);
  fill(*e);
  std::shared_ptr<CloudEventSanitized> out;
  EXPECT_EQ(f.sanitize(*e, out), SRESULT::Ok);
  return out;
}
/// @brief Follows a path of object keys / array indices. @return Value or null.
std::shared_ptr<const JsonValue> at(std::shared_ptr<const JsonValue> v, std::initializer_list<const char*> path) {
  for (const char* p : path) {
    std::shared_ptr<const JsonValue> next;
    const bool idx = p[0] >= '0' && p[0] <= '9';
    if ((idx ? v->at(static_cast<std::size_t>(std::atoi(p)), next) : v->get(p, next)) != SRESULT::Ok) return nullptr;
    v = next;
  }
  return v;
}
}  // namespace

/// Log records carry the CloudEvent as body, type/id/class attributes and the endpoint resource.
TEST(OtlpJson, Logs) {
  Rig rig;
  PiiFilter f(rig.bus, rig.factory, Redactor("s"));
  OtlpResource res;
  res.instance_id = "ep-demo";
  Envelopes envs = {env<ProcessCrashDetected>(rig, f, [](auto& e) { e.signal = "SIGSEGV"; }),
                    env<LogRecordObserved>(rig, f, [](auto& e) { e.level = "error"; e.message = "say \"hi\""; })};
  std::string body;
  ASSERT_EQ(otlp_logs_json(res, envs, body), SRESULT::Ok);
  std::shared_ptr<const JsonValue> doc;
  ASSERT_EQ(JsonValue::Parse(body, doc), SRESULT::Ok);
  std::string s;
  ASSERT_EQ(at(doc, {"resourceLogs", "0", "resource", "attributes", "2", "value"})->get_string("stringValue", s),
            SRESULT::Ok);
  EXPECT_EQ(s, "ep-demo");
  auto rec0 = at(doc, {"resourceLogs", "0", "scopeLogs", "0", "logRecords", "0"});
  ASSERT_TRUE(rec0);
  std::int64_t sev = 0;
  ASSERT_EQ(rec0->get_int("severityNumber", sev), SRESULT::Ok);
  EXPECT_EQ(sev, 13);  // incident -> WARN
  ASSERT_EQ(at(rec0, {"attributes", "0", "value"})->get_string("stringValue", s), SRESULT::Ok);
  EXPECT_EQ(s, "com.ieso.ProcessCrashDetected");
  ASSERT_EQ(at(rec0, {"body"})->get_string("stringValue", s), SRESULT::Ok);
  EXPECT_NE(s.find("\"SIGSEGV\""), std::string::npos);  // body is the CloudEvent JSON
  ASSERT_EQ(at(rec0, {})->get_string("timeUnixNano", s), SRESULT::Ok);
  EXPECT_EQ(s, "1767225600000000000");  // ManualClock epoch in ns, as a string (proto3 JSON int64)
  auto rec1 = at(doc, {"resourceLogs", "0", "scopeLogs", "0", "logRecords", "1"});
  ASSERT_EQ(rec1->get_int("severityNumber", sev), SRESULT::Ok);
  EXPECT_EQ(sev, 17);  // app error level -> ERROR
}

/// Snapshots become one gauge per metric with one data point per snapshot at the sample time.
TEST(OtlpJson, Metrics) {
  Rig rig;
  PiiFilter f(rig.bus, rig.factory, Redactor("s"));
  OtlpResource res;
  res.instance_id = "ep-demo";
  Envelopes envs;
  for (int i = 0; i < 2; ++i) {
    envs.push_back(env<TelemetrySnapshotCaptured>(rig, f, [i](auto& e) {
      e.pid = 42;
      e.sample.ts_ms = 1767225600000 + i * 1000;
      e.sample.cpu_pct = 12.5;
      e.sample.rss_bytes = 1000u + static_cast<std::uint64_t>(i);
    }));
  }
  envs.push_back(env<ProcessHangDetected>(rig, f, [](auto&) {}));  // not a metric: skipped
  bool metric = false;
  ASSERT_EQ(otlp_is_metric(*envs[0], metric), SRESULT::Ok);
  EXPECT_TRUE(metric);
  std::string body;
  ASSERT_EQ(otlp_metrics_json(res, envs, body), SRESULT::Ok);
  std::shared_ptr<const JsonValue> doc;
  ASSERT_EQ(JsonValue::Parse(body, doc), SRESULT::Ok);
  auto metrics = at(doc, {"resourceMetrics", "0", "scopeMetrics", "0", "metrics"});
  std::size_t n = 0;
  ASSERT_EQ(metrics->size(n), SRESULT::Ok);
  EXPECT_EQ(n, 5u);
  std::string s;
  auto rss = at(metrics, {"1"});
  ASSERT_EQ(rss->get_string("name", s), SRESULT::Ok);
  EXPECT_EQ(s, "process.memory.rss");
  ASSERT_EQ(rss->get_string("unit", s), SRESULT::Ok);
  EXPECT_EQ(s, "By");
  auto pts = at(rss, {"gauge", "dataPoints"});
  ASSERT_EQ(pts->size(n), SRESULT::Ok);
  EXPECT_EQ(n, 2u);
  ASSERT_EQ(at(pts, {"1"})->get_string("asInt", s), SRESULT::Ok);
  EXPECT_EQ(s, "1001");
  ASSERT_EQ(at(pts, {"1"})->get_string("timeUnixNano", s), SRESULT::Ok);
  EXPECT_EQ(s, "1767225601000000000");
  double cpu = 0;
  ASSERT_EQ(at(metrics, {"0", "gauge", "dataPoints", "0", "asDouble"})->as_double(cpu), SRESULT::Ok);
  EXPECT_DOUBLE_EQ(cpu, 12.5);
}
