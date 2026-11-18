/**
 * @file diagnostics_test.cpp
 * @brief Diagnostics actor with a fake platform: bundles, capture budget, escalation and revert.
 */
#include <gtest/gtest.h>

#include <fstream>
#include <iterator>

#include "diagnostics/diagnostics.hpp"
#include "ieso/core/json_reader.hpp"
#include "ieso/core/sha256.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {

/// @brief Records platform calls; thread-safe counters.
class FakePlatform final : public IDiagnosticsPlatform {
 public:
  SRESULT capture_stacks(std::int64_t /*pid*/, std::chrono::seconds /*d*/, std::string& out) override {
    captures.fetch_add(1);
    out = "FAKE STACKS: Call graph /Users/alice/Library/x.dylib";
    return SRESULT::Ok;
  }
  SRESULT set_log_mode(const std::string& /*subsystem*/, const std::string& /*mode*/) override {
    sets.fetch_add(1);
    return deny ? SRESULT::PermissionDenied : SRESULT::Ok;
  }
  SRESULT reset_log_mode(const std::string& /*subsystem*/) override {
    resets.fetch_add(1);
    return SRESULT::Ok;
  }
  SRESULT environment(Fields& out) override {
    out.push_back({"os_version", FieldValue{std::string("26.6")}, false});
    return SRESULT::Ok;
  }
  SRESULT run_probe(const std::string& probe_id, std::string& output, std::int64_t& exit_status) override {
    probes.fetch_add(1);
    output = "output of " + probe_id;
    exit_status = 0;
    return SRESULT::Ok;
  }
  std::atomic<int> captures{0}, sets{0}, resets{0}, probes{0};  ///< Call counts.
  bool deny = false;                                  ///< Simulate non-root.
};

/// @brief Accepts exactly the signature "good-sig" over a v1 canonical request (stands in for ECDSA).
class FakeVerifier final : public IProbeVerifier {
 public:
  SRESULT verify(std::string_view message, std::string_view signature, bool& valid) const override {
    valid = signature == "good-sig" && message.compare(0, 3, "v1|") == 0;
    return SRESULT::Ok;
  }
};

/// @brief Runtime + DiagnosticsActor + bundle collector.
struct DiagRig {
  Rig rig;                                                     ///< Core rig.
  TempDir tmp;                                                 ///< Incident dir.
  Runtime rt{rig.bus};                                         ///< Runtime.
  std::shared_ptr<FakePlatform> platform = std::make_shared<FakePlatform>();  ///< Fake OS.
  std::shared_ptr<Collector<IncidentBundleReady>> bundles = std::make_shared<Collector<IncidentBundleReady>>("b");

  std::filesystem::path checkpoint;  ///< Optional recorder checkpoint file.
  std::shared_ptr<const IProbeVerifier> verifier;  ///< Optional probe verifier.
  std::shared_ptr<Collector<ProbeResultReady>> results = std::make_shared<Collector<ProbeResultReady>>("probes");

  /// @brief Starts everything. @return Result of start.
  SRESULT start() {
    DiagnosticsOptions o;
    HS_RETURN_IF_FAILED(tmp.path(o.incident_dir));
    o.tick = std::chrono::milliseconds(10);
    o.checkpoint_file = checkpoint;
    o.probe_verifier = verifier;
    HS_RETURN_IF_FAILED(rt.add(results));
    HS_RETURN_IF_FAILED(rt.add(bundles));
    HS_RETURN_IF_FAILED(rt.add(std::make_shared<DiagnosticsActor>(rig.bus, rig.factory, rig.clock, platform, o)));
    return rt.start();
  }
  /// @brief Posts an event built by @p fill. @tparam T Event. @param[in] fill Mutator. @return Post result.
  template <class T>
  SRESULT post(const std::function<void(T&)>& fill) {
    std::shared_ptr<T> e;
    HS_RETURN_IF_FAILED(rig.factory.make<T>(e));
    fill(*e);
    return rig.bus.post(std::move(e));
  }
};

}  // namespace

/// A hang yields a hashed bundle with rings, logs, environment and the stack capture.
TEST(Diagnostics, HangBundle) {
  DiagRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(r.post<TargetLifecycle>([](auto& e) { e.phase = "launch"; e.pid = 42; }), SRESULT::Ok);
  for (int i = 0; i < 30; ++i) {
    ASSERT_EQ(r.post<ResourceSampled>([i](auto& e) {
      e.pid = 42;
      e.sample.pid = 42;
      e.sample.ts_ms = 1767225600000 + i * 100;
      e.sample.rss_bytes = 1000u + static_cast<std::uint64_t>(i);
    }), SRESULT::Ok);
  }
  ASSERT_EQ(r.post<LogRecordObserved>([](auto& e) {
    e.level = "error";
    e.message = "ledger sync blocked for alice@corp.example";
  }),
            SRESULT::Ok);
  std::string hang_id;
  {
    std::shared_ptr<ProcessHangDetected> h;
    ASSERT_EQ(r.rig.factory.make<ProcessHangDetected>(h), SRESULT::Ok);
    h->pid = 42;
    hang_id = h->hdr.id;
    ASSERT_EQ(r.rig.bus.post(std::move(h)), SRESULT::Ok);
  }
  ASSERT_EQ(wait_until([&] { return count_of(*r.bundles) == 1; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);

  std::vector<std::shared_ptr<const IncidentBundleReady>> got;
  ASSERT_EQ(r.bundles->received(got), SRESULT::Ok);
  EXPECT_EQ(got[0]->incident_id, hang_id);
  EXPECT_EQ(got[0]->symptom, "hang");
  EXPECT_EQ(r.platform->captures.load(), 1);
  std::ifstream f(got[0]->bundle_path);
  ASSERT_TRUE(f.is_open());
  const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::string hash;
  ASSERT_EQ(Sha256::hex(text, hash), SRESULT::Ok);
  EXPECT_EQ(hash, got[0]->bundle_hash);

  std::shared_ptr<const JsonValue> doc, rings, hot, logs, capture;
  ASSERT_EQ(JsonValue::Parse(text, doc), SRESULT::Ok);
  std::string s;
  ASSERT_EQ(doc->get_string("symptom", s), SRESULT::Ok);
  EXPECT_EQ(s, "hang");
  ASSERT_EQ(doc->get("rings", rings), SRESULT::Ok);
  ASSERT_EQ(rings->get("hot_100ms", hot), SRESULT::Ok);
  std::size_t n = 0;
  ASSERT_EQ(hot->size(n), SRESULT::Ok);
  EXPECT_EQ(n, 30u);
  std::shared_ptr<const JsonValue> first;
  ASSERT_EQ(hot->at(0, first), SRESULT::Ok);
  std::int64_t sample_pid = 0;
  ASSERT_EQ(first->get_int("pid", sample_pid), SRESULT::Ok);
  EXPECT_EQ(sample_pid, 42);  // every ring sample names its process
  ASSERT_EQ(doc->get("recent_logs", logs), SRESULT::Ok);
  ASSERT_EQ(logs->size(n), SRESULT::Ok);
  EXPECT_EQ(n, 1u);
  ASSERT_EQ(doc->get("deep_capture", capture), SRESULT::Ok);
  ASSERT_EQ(capture->get_string("status", s), SRESULT::Ok);
  EXPECT_EQ(s, "Ok");

  // Upload copy: same incident, every string redacted, hash announced in the event.
  ASSERT_EQ(got[0]->upload_ref, hang_id + ".sanitized.json");
  std::ifstream u(std::filesystem::path(got[0]->bundle_path).parent_path() / got[0]->upload_ref);
  ASSERT_TRUE(u.is_open());
  const std::string up((std::istreambuf_iterator<char>(u)), std::istreambuf_iterator<char>());
  std::string up_hash;
  ASSERT_EQ(Sha256::hex(up, up_hash), SRESULT::Ok);
  EXPECT_EQ(up_hash, got[0]->upload_sha256);
  EXPECT_NE(up.find("ieso.incident.v1.sanitized"), std::string::npos);
  EXPECT_EQ(up.find("/Users/alice"), std::string::npos);
  EXPECT_EQ(up.find("alice@corp.example"), std::string::npos);
  EXPECT_NE(up.find("/Users/<user>/Library"), std::string::npos);
  EXPECT_NE(text.find("/Users/alice/Library"), std::string::npos);  // raw local copy keeps evidence
}

/// NFR-11 end to end: a sensor restart keeps the warm tier; the next bundle shows the old samples and the gap.
TEST(Diagnostics, HistorySurvivesRestart) {
  TempDir keep;
  std::filesystem::path dir;
  ASSERT_EQ(keep.path(dir), SRESULT::Ok);
  const auto ckpt = dir / "recorder.ckpt";
  {
    DiagRig r;
    r.checkpoint = ckpt;
    ASSERT_EQ(r.start(), SRESULT::Ok);
    for (int i = 0; i < 25; ++i) {  // 2.5 s of samples -> 2 completed seconds + an open one
      ASSERT_EQ(r.post<ResourceSampled>([i](auto& e) {
        e.sample.pid = 42;
        e.sample.ts_ms = 1767225600000 + i * 100;
        e.sample.rss_bytes = 1000;
      }), SRESULT::Ok);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ASSERT_EQ(r.rt.stop(), SRESULT::Ok);  // on_stop writes the final checkpoint
  }
  ASSERT_TRUE(std::filesystem::exists(ckpt));
  const auto perms = std::filesystem::status(ckpt).permissions();
  EXPECT_EQ(perms & std::filesystem::perms::all,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);  // 0600

  DiagRig r2;  // "restarted sensor": same checkpoint file, fresh actor
  r2.checkpoint = ckpt;
  ASSERT_EQ(r2.start(), SRESULT::Ok);
  ASSERT_EQ(r2.post<ProcessHangDetected>([](auto& e) { e.pid = 42; }), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r2.bundles) == 1; }), SRESULT::Ok);
  ASSERT_EQ(r2.rt.stop(), SRESULT::Ok);
  std::vector<std::shared_ptr<const IncidentBundleReady>> got;
  ASSERT_EQ(r2.bundles->received(got), SRESULT::Ok);
  std::ifstream f(got[0]->bundle_path);
  const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::shared_ptr<const JsonValue> doc, rings, warm, last;
  ASSERT_EQ(JsonValue::Parse(text, doc), SRESULT::Ok);
  ASSERT_EQ(doc->get("rings", rings), SRESULT::Ok);
  ASSERT_EQ(rings->get("warm_1s", warm), SRESULT::Ok);
  std::size_t n = 0;
  ASSERT_EQ(warm->size(n), SRESULT::Ok);
  EXPECT_EQ(n, 4u);  // 2 seconds + closed open second + gap marker
  ASSERT_EQ(warm->at(n - 1, last), SRESULT::Ok);
  bool gap = false;
  std::shared_ptr<const JsonValue> g;
  ASSERT_EQ(last->get("gap", g), SRESULT::Ok);
  ASSERT_EQ(g->as_bool(gap), SRESULT::Ok);
  EXPECT_TRUE(gap);
}

/// A corrupt checkpoint never blocks startup: it is set aside as .bad and the rings start empty.
TEST(Diagnostics, CorruptCheckpointDoesNotBlockStart) {
  DiagRig r;
  std::filesystem::path dir;
  ASSERT_EQ(r.tmp.path(dir), SRESULT::Ok);
  r.checkpoint = dir / "recorder.ckpt";
  { std::ofstream(r.checkpoint) << "not a checkpoint"; }
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  EXPECT_TRUE(std::filesystem::exists(dir / "recorder.ckpt.bad"));
  EXPECT_TRUE(std::filesystem::exists(r.checkpoint));  // a fresh checkpoint was written on stop
}

namespace {
/// @brief A request that passes every check (signature "good-sig" base64-encoded).
void valid_request(ProbeRequested& e, const std::string& id) {
  e.probe_id = "net.config";
  e.request_id = id;
  e.incident_id = "inc-1";
  e.endpoint = "endpoint-test";
  e.issued_at = 1767225600000;
  e.expires_at = 1767225600000 + 60000;
  e.signature = "Z29vZC1zaWc=";  // base64("good-sig")
}
}  // namespace

/// FR-14/NFR-10: a signed, in-scope, unexpired, allowlisted request runs; every violation is refused and reported.
TEST(Diagnostics, ProbePolicy) {
  DiagRig r;
  r.verifier = std::make_shared<FakeVerifier>();
  ASSERT_EQ(r.start(), SRESULT::Ok);
  const std::vector<std::pair<std::string, std::function<void(ProbeRequested&)>>> cases = {
      {"ok", [](ProbeRequested& e) { valid_request(e, "r-ok"); }},
      {"allowlist", [](ProbeRequested& e) { valid_request(e, "r-1"); e.probe_id = "shell.exec"; }},
      {"endpoint", [](ProbeRequested& e) { valid_request(e, "r-2"); e.endpoint = "ep-other"; }},
      {"expired", [](ProbeRequested& e) { valid_request(e, "r-3"); e.expires_at = 1767225599000; }},
      {"signature", [](ProbeRequested& e) { valid_request(e, "r-4"); e.signature = "YmFkLXNpZw=="; }},
      {"replay", [](ProbeRequested& e) { valid_request(e, "r-ok"); }},
  };
  for (const auto& [name, fill] : cases) {
    ASSERT_EQ(r.post<ProbeRequested>(fill), SRESULT::Ok) << name;
  }
  ASSERT_EQ(wait_until([&] { return count_of(*r.results) == cases.size(); }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  std::vector<std::shared_ptr<const ProbeResultReady>> got;
  ASSERT_EQ(r.results->received(got), SRESULT::Ok);
  EXPECT_EQ(got[0]->exit_status, 0);
  EXPECT_EQ(got[0]->output, "output of net.config");
  EXPECT_EQ(got[0]->incident_id, "inc-1");
  const char* reasons[] = {"allowlist", "not this one", "expired", "does not verify", "replayed"};
  for (std::size_t i = 1; i < got.size(); ++i) {
    EXPECT_EQ(got[i]->exit_status, -1) << i;
    EXPECT_NE(got[i]->output.find("refused: "), std::string::npos) << got[i]->output;
    EXPECT_NE(got[i]->output.find(reasons[i - 1]), std::string::npos) << got[i]->output;
  }
  EXPECT_EQ(r.platform->probes.load(), 1);  // only the valid request reached the platform
}

/// Without a pinned key every probe is refused; the per-incident budget (4) is enforced.
TEST(Diagnostics, ProbeKeyAndBudget) {
  {
    DiagRig r;  // no verifier
    ASSERT_EQ(r.start(), SRESULT::Ok);
    ASSERT_EQ(r.post<ProbeRequested>([](auto& e) { valid_request(e, "x"); }), SRESULT::Ok);
    ASSERT_EQ(wait_until([&] { return count_of(*r.results) == 1; }), SRESULT::Ok);
    ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
    std::vector<std::shared_ptr<const ProbeResultReady>> got;
    ASSERT_EQ(r.results->received(got), SRESULT::Ok);
    EXPECT_NE(got[0]->output.find("no probe-signing key"), std::string::npos);
  }
  DiagRig r;
  r.verifier = std::make_shared<FakeVerifier>();
  ASSERT_EQ(r.start(), SRESULT::Ok);
  for (int i = 0; i < 5; ++i) {
    ASSERT_EQ(r.post<ProbeRequested>([i](auto& e) { valid_request(e, "b-" + std::to_string(i)); }), SRESULT::Ok);
  }
  ASSERT_EQ(wait_until([&] { return count_of(*r.results) == 5; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  EXPECT_EQ(r.platform->probes.load(), 4);
  std::vector<std::shared_ptr<const ProbeResultReady>> got;
  ASSERT_EQ(r.results->received(got), SRESULT::Ok);
  EXPECT_NE(got[4]->output.find("budget exhausted"), std::string::npos);
}

/// The hourly capture budget (4) is enforced across incidents; crashes never sample (process is gone).
TEST(Diagnostics, CaptureBudget) {
  DiagRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  for (int i = 0; i < 6; ++i) ASSERT_EQ(r.post<ProcessHangDetected>([](auto& e) { e.pid = 42; }), SRESULT::Ok);
  ASSERT_EQ(r.post<ProcessCrashDetected>([](auto& e) { e.pid = 42; }), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return count_of(*r.bundles) == 7; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  EXPECT_EQ(r.platform->captures.load(), 4);
}

/// Escalation is applied once, extended by repeats, and reverted after the deadline.
TEST(Diagnostics, EscalationAndRevert) {
  DiagRig r;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  for (int i = 0; i < 2; ++i) {
    ASSERT_EQ(r.post<DiagnosticEscalationRequested>([](auto& e) {
      e.subsystem = "com.example.app";
      e.duration_s = 60;
    }), SRESULT::Ok);
  }
  ASSERT_EQ(wait_until([&] { return r.platform->sets.load() == 1; }), SRESULT::Ok);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  EXPECT_EQ(r.platform->resets.load(), 0);
  ASSERT_EQ(r.rig.clock.advance(std::chrono::seconds(61)), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return r.platform->resets.load() == 1; }), SRESULT::Ok);
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  EXPECT_EQ(r.platform->sets.load(), 1);
}

/// Without root, escalation is skipped and nothing is reverted later.
TEST(Diagnostics, EscalationDenied) {
  DiagRig r;
  r.platform->deny = true;
  ASSERT_EQ(r.start(), SRESULT::Ok);
  ASSERT_EQ(r.post<DiagnosticEscalationRequested>([](auto& e) {
    e.subsystem = "com.example.app";
    e.duration_s = 1;
  }), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return r.platform->sets.load() == 1; }), SRESULT::Ok);
  ASSERT_EQ(r.rig.clock.advance(std::chrono::seconds(5)), SRESULT::Ok);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  ASSERT_EQ(r.rt.stop(), SRESULT::Ok);
  EXPECT_EQ(r.platform->resets.load(), 0);
}
