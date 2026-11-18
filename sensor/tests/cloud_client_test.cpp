/**
 * @file cloud_client_test.cpp
 * @brief Cloud Client with a scripted fake transport: batching, acks, spooling, health, bundle upload.
 */
#include <gtest/gtest.h>

#include <fstream>

#include "cloud_client/cloud_client.hpp"
#include "ieso/core/sha256.hpp"
#include "pii_filter/pii_filter.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {

/// @brief Records requests; answers with a configurable status per URL substring.
class FakeTransport final : public ITransportClient {
 public:
  /// @brief One recorded request.
  struct Call {
    std::string method, url, body;
    std::vector<std::string> headers;
  };
  SRESULT request(const std::string& method, const std::string& url, const std::vector<std::string>& headers,
                  const std::string& body, HttpResponse& out) override {
    std::lock_guard lock(mu);
    calls.push_back({method, url, body, headers});
    out.status = up.load() ? 200 : 0;
    if (url.find("/v1/probes/pending") != std::string::npos) {
      out.body = pending_body;
      pending_body = "[]";  // handed out once, like the control plane
    }
    if (up.load() && url.find(fail_path) != std::string::npos && !fail_path.empty()) out.status = fail_status;
    return SRESULT::Ok;
  }
  /// @brief Count of calls whose URL contains @p part. @param[in] part Substring. @return Count.
  std::size_t count(const std::string& part) {
    std::lock_guard lock(mu);
    std::size_t n = 0;
    for (const auto& c : calls) n += c.url.find(part) != std::string::npos ? 1 : 0;
    return n;
  }
  /// @brief Copy of the calls. @return Calls.
  std::vector<Call> snapshot() {
    std::lock_guard lock(mu);
    return calls;
  }
  std::mutex mu;                  ///< Guards calls.
  std::vector<Call> calls;        ///< Recorded requests.
  std::atomic<bool> up{true};     ///< Backend reachable.
  std::string fail_path;          ///< URL part that answers fail_status.
  std::string pending_body = "[]";  ///< Response of GET /v1/probes/pending.
  long fail_status = 500;         ///< Status for fail_path.
};

/// @brief Runtime with a Cloud Client on a fake transport and collectors for its outputs.
struct CloudRig {
  Rig rig;                                                    ///< Core rig.
  TempDir tmp;                                                ///< Incident dir.
  Runtime rt{rig.bus};                                        ///< Runtime.
  PiiFilter filter{rig.bus, rig.factory, Redactor("s")};      ///< Envelope builder.
  FakeTransport* fake = nullptr;                              ///< Non-owning view for assertions (test only).
  std::shared_ptr<Collector<TelemetryDelivered>> acks = std::make_shared<Collector<TelemetryDelivered>>("acks");
  std::shared_ptr<Collector<SpooledEvent>> spooled = std::make_shared<Collector<SpooledEvent>>("spooled");
  std::shared_ptr<Collector<NetworkStatusChanged>> net = std::make_shared<Collector<NetworkStatusChanged>>("net");
  std::shared_ptr<Collector<ProbeRequested>> probes = std::make_shared<Collector<ProbeRequested>>("probes");

  /// @brief Starts the runtime. @param[in] up Initial reachability. @return Result of start.
  SRESULT start(bool up = true) {
    auto t = std::make_unique<FakeTransport>();
    t->up = up;
    fake = t.get();
    CloudClientOptions o;
    HS_RETURN_IF_FAILED(tmp.path(o.incident_dir));
    o.flush_period = std::chrono::milliseconds(20);
    o.health_period = std::chrono::milliseconds(20);
    o.probe_poll_period = std::chrono::milliseconds(20);
    OtlpResource res;
    res.instance_id = "ep-test";
    HS_RETURN_IF_FAILED(rt.add(acks));
    HS_RETURN_IF_FAILED(rt.add(spooled));
    HS_RETURN_IF_FAILED(rt.add(net));
    HS_RETURN_IF_FAILED(rt.add(probes));
    HS_RETURN_IF_FAILED(rt.add(std::make_shared<CloudClientActor>(rig.bus, rig.factory, std::move(t), res, o)));
    return rt.start();
  }
  /// @brief Posts a sanitized envelope of an event filled by @p fill. @tparam T Event. @return Envelope id.
  template <class T>
  std::string send(const std::function<void(T&)>& fill = [](T&) {}) {
    std::shared_ptr<T> e;
    EXPECT_EQ(rig.factory.make<T>(e), SRESULT::Ok);
    fill(*e);
    std::shared_ptr<CloudEventSanitized> env;
    EXPECT_EQ(filter.sanitize(*e, env), SRESULT::Ok);
    const std::string id = env->hdr.id;
    EXPECT_TRUE(HS_SUCCEEDED(rig.bus.post(env)));
    return id;
  }
  /// @brief Ids acknowledged so far. @return Ids.
  std::vector<std::string> acked() {
    std::vector<std::shared_ptr<const TelemetryDelivered>> got;
    (void)acks->received(got);  // always Ok
    std::vector<std::string> ids;
    for (const auto& a : got) ids.insert(ids.end(), a->ids.begin(), a->ids.end());
    return ids;
  }
};

}  // namespace

/// Online: telemetry goes to /v1/metrics, events to /v1/logs, incidents also to the control plane; all acked.
TEST(CloudClient, ShipsAndAcks) {
  CloudRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r.net) == 1; }), SRESULT::Ok);
  r.send<TelemetrySnapshotCaptured>([](auto& e) { e.sample.rss_bytes = 5; });
  r.send<LogRecordObserved>([](auto& e) { e.message = "hello"; });
  r.send<ProcessCrashDetected>();
  ASSERT_EQ(wait_until([&] { return r.acked().size() == 3; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  EXPECT_GE(r.fake->count("/v1/metrics"), 1u);
  EXPECT_GE(r.fake->count("/v1/logs"), 1u);
  EXPECT_EQ(r.fake->count("/v1/events"), 1u);
  EXPECT_EQ(count_of(*r.spooled), 0u);
  std::vector<std::shared_ptr<const NetworkStatusChanged>> net;
  ASSERT_EQ(r.net->received(net), SRESULT::Ok);
  EXPECT_TRUE(net[0]->online);
}

/// Unreachable backend: offline status, envelopes spooled; when it comes back, online is announced.
TEST(CloudClient, OfflineSpoolsThenRecovers) {
  CloudRig r;
  ASSERT_EQ(r.start(false), SRESULT::Ok);
  r.send<ProcessHangDetected>();
  ASSERT_EQ(wait_until([&] { return count_of(*r.spooled) == 1; }), SRESULT::Ok);
  EXPECT_TRUE(r.acked().empty());
  r.fake->up = true;
  ASSERT_EQ(wait_until([&] { return count_of(*r.net) == 2; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  std::vector<std::shared_ptr<const NetworkStatusChanged>> net;
  ASSERT_EQ(r.net->received(net), SRESULT::Ok);
  EXPECT_FALSE(net[0]->online);
  EXPECT_TRUE(net[1]->online);
}

/// A 5xx while online flips to offline and spools; a permanent 4xx is dropped (acked) to avoid a replay loop.
TEST(CloudClient, ServerErrorsVsRefusals) {
  CloudRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r.net) == 1; }), SRESULT::Ok);
  r.fake->fail_path = "/v1/logs";
  r.fake->fail_status = 400;
  const std::string refused = r.send<ProcessHangDetected>();
  ASSERT_EQ(wait_until([&] { return r.acked().size() == 1; }), SRESULT::Ok);
  EXPECT_EQ(r.acked()[0], refused);
  r.fake->fail_status = 503;
  r.send<ProcessHangDetected>();
  ASSERT_EQ(wait_until([&] { return count_of(*r.spooled) == 1; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
}

/// IncidentBundleReady triggers a PUT of the sanitized bundle with its hash; path traversal is rejected.
TEST(CloudClient, UploadsSanitizedBundle) {
  CloudRig r;
  std::filesystem::path dir;
  ASSERT_EQ(r.tmp.path(dir), SRESULT::Ok);
  const std::string bundle = R"({"schema":"ieso.incident.v1.sanitized"})";
  { std::ofstream(dir / "inc-1.sanitized.json") << bundle; }
  std::string sha;
  ASSERT_EQ(Sha256::hex(bundle, sha), SRESULT::Ok);
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r.net) == 1; }), SRESULT::Ok);
  r.send<IncidentBundleReady>([&](auto& e) {
    e.incident_id = "inc-1";
    e.upload_ref = "inc-1.sanitized.json";
    e.upload_sha256 = sha;
  });
  r.send<IncidentBundleReady>([&](auto& e) {
    e.incident_id = "inc-2";
    e.upload_ref = "../../etc/passwd";
    e.upload_sha256 = sha;
  });
  ASSERT_EQ(wait_until([&] { return r.fake->count("/v1/bundles/") == 1 && r.acked().size() == 2; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  for (const auto& c : r.fake->snapshot()) {
    if (c.url.find("/v1/bundles/") == std::string::npos) continue;
    EXPECT_EQ(c.method, "PUT");
    EXPECT_NE(c.url.find("/v1/bundles/inc-1"), std::string::npos);
    EXPECT_EQ(c.body, bundle);
    EXPECT_NE(std::find(c.headers.begin(), c.headers.end(), "X-Bundle-SHA256: " + sha), c.headers.end());
  }
}

/// FR-14: pending signed probe requests are fetched while online and posted as ProbeRequested (verified later).
TEST(CloudClient, FetchesPendingProbes) {
  CloudRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r.net) == 1; }), SRESULT::Ok);
  {
    std::lock_guard lock(r.fake->mu);
    r.fake->pending_body = R"([{"request_id":"rq-1","endpoint":"ep-test","incident_id":"inc-9","probe_id":)"
                           R"("net.synthetic_tls","issued_at":1767225600000,"expires_at":1767225660000,)"
                           R"("signature":"c2ln"}])";
  }
  ASSERT_EQ(wait_until([&] { return count_of(*r.probes) == 1; }), SRESULT::Ok);
  std::this_thread::sleep_for(std::chrono::milliseconds(60));  // later polls return [] -> no duplicates
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  std::vector<std::shared_ptr<const ProbeRequested>> got;
  ASSERT_EQ(r.probes->received(got), SRESULT::Ok);
  ASSERT_EQ(got.size(), 1u);
  EXPECT_EQ(got[0]->probe_id, "net.synthetic_tls");
  EXPECT_EQ(got[0]->incident_id, "inc-9");
  EXPECT_EQ(got[0]->expires_at, 1767225660000);
  EXPECT_EQ(got[0]->signature, "c2ln");
}
