/**
 * @file pii_filter_test.cpp
 * @brief Redaction rules, egress-only subscription and CloudEvents envelope shape.
 */
#include <gtest/gtest.h>

#include "pii_filter/pii_filter.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

// Compile-time guarantees (NFR-7).
static_assert(!std::is_default_constructible_v<CloudEventSanitized::Key>, "passkey must be private");
static_assert(!std::is_constructible_v<CloudEventSanitized, std::string, std::string, std::string>,
              "envelope needs the passkey");
static_assert(is_egress_eligible_v<ProcessCrashDetected>);
static_assert(!is_egress_eligible_v<ConfigurationUpdated>);
static_assert(!is_egress_eligible_v<CloudEventSanitized>);

namespace {
/// @brief Redacts @p in with a fixed salt. @param[in] in Text. @return Redacted text.
std::string R(std::string_view in) {
  Redactor r("salt");
  std::string out;
  EXPECT_EQ(r.redact(in, out), SRESULT::Ok);
  return out;
}
}  // namespace

/// Home-directory user names are replaced; /Users/Shared is kept.
TEST(Redactor, HomePaths) {
  EXPECT_EQ(R("/Users/alice/Library/Logs/x.ips"), "/Users/<user>/Library/Logs/x.ips");
  EXPECT_EQ(R("open /home/bob failed"), "open /home/<user> failed");
  EXPECT_EQ(R("/Users/Shared/app"), "/Users/Shared/app");
}

/// Emails are replaced; a lone '@' is not.
TEST(Redactor, Emails) {
  EXPECT_EQ(R("contact alice.smith+x@corp.example.com now"), "contact <email> now");
  EXPECT_EQ(R("a @ b"), "a @ b");
}

/// IPv4/IPv6 are hashed deterministically; versions and times are not IPs.
TEST(Redactor, IpsHashedAndStable) {
  const std::string a = R("from 10.1.2.3 to 10.1.2.3");
  EXPECT_EQ(a.find("10.1.2.3"), std::string::npos);
  const auto first = a.find("ip:");
  ASSERT_NE(first, std::string::npos);
  EXPECT_EQ(a.substr(first, 11), a.substr(a.rfind("ip:"), 11));  // same IP -> same token
  EXPECT_EQ(R("peer fe80::1ff:fe23:4567:890a up").find("fe80"), std::string::npos);
  EXPECT_EQ(R("version 1.2.3 at 12:30:45"), "version 1.2.3 at 12:30:45");
  EXPECT_EQ(R("bad 999.1.1.1"), "bad 999.1.1.1");
}

/// Secrets in key=value pairs, Bearer tokens and long hex runs are removed.
TEST(Redactor, Secrets) {
  EXPECT_EQ(R("login password=hunter2 ok"), "login password=<redacted> ok");
  EXPECT_EQ(R("api_key: \"abc def\""), "api_key: <redacted>");
  EXPECT_EQ(R("Authorization: Bearer eyJhbGciOi.payload.sig; next"), "Authorization: <redacted>; next");
  EXPECT_EQ(R("sent Bearer eyJhbGciOi.payload.sig"), "sent Bearer <token>");
  EXPECT_EQ(R("sha 0123456789abcdef0123456789abcdef00"), "sha <secret>");
  EXPECT_EQ(R("uuid 01a1ec71-dad3-70fc-94a1-ebc1c4ba914e"), "uuid 01a1ec71-dad3-70fc-94a1-ebc1c4ba914e");
}

/// Free text is truncated after redaction.
TEST(Redactor, FreeTextTruncated) {
  Redactor r("salt");
  std::string out;
  ASSERT_EQ(r.redact_free_text(std::string(2000, 'x') + " y", out), SRESULT::Ok);
  EXPECT_LE(out.size(), Redactor::kMaxFreeText + 20);
  EXPECT_NE(out.find("[truncated]"), std::string::npos);
}

/// sanitize() keeps id/class, redacts strings, and produces a CloudEvents 1.0 envelope.
TEST(PiiFilter, EnvelopeShape) {
  Rig rig;
  PiiFilter f(rig.bus, rig.factory, Redactor("salt"));
  std::shared_ptr<UserVisibleErrorObserved> ev;
  ASSERT_EQ(rig.factory.make<UserVisibleErrorObserved>(ev), SRESULT::Ok);
  ev->pid = 9;
  ev->dialog_text = "Cannot open /Users/alice/Documents/q3.xlsx for alice@corp.example";
  std::shared_ptr<CloudEventSanitized> env;
  ASSERT_EQ(f.sanitize(*ev, env), SRESULT::Ok);
  EXPECT_EQ(env->hdr.id, ev->hdr.id);
  EXPECT_EQ(env->hdr.cls, EventClass::Incident);
  EXPECT_FALSE(env->hdr.egress);
  EXPECT_TRUE(env->hdr.spillable);
  EXPECT_EQ(env->type, "com.ieso.UserVisibleErrorObserved");
  std::string json;
  ASSERT_EQ(env->to_json(json), SRESULT::Ok);
  EXPECT_NE(json.find(R"("specversion":"1.0")"), std::string::npos);
  EXPECT_NE(json.find(R"("id":")" + ev->hdr.id + "\""), std::string::npos);
  EXPECT_NE(json.find(R"("time":"2026-01-01T00:00:00.000Z")"), std::string::npos);
  EXPECT_EQ(json.find("alice"), std::string::npos);
  EXPECT_NE(json.find("/Users/<user>/Documents/q3.xlsx for <email>"), std::string::npos);
}

/// Sensor-generated hashes survive the long-secret rule (verbatim fields); the raw path is still redacted.
TEST(PiiFilter, VerbatimFieldsKept) {
  Rig rig;
  PiiFilter f(rig.bus, rig.factory, Redactor("salt"));
  std::shared_ptr<IncidentBundleReady> ev;
  ASSERT_EQ(rig.factory.make<IncidentBundleReady>(ev), SRESULT::Ok);
  ev->bundle_hash = std::string(64, 'a');
  ev->upload_sha256 = std::string(64, 'b');
  ev->bundle_path = "/Users/alice/Library/Application Support/ieso/incidents/x.json";
  std::shared_ptr<CloudEventSanitized> env;
  ASSERT_EQ(f.sanitize(*ev, env), SRESULT::Ok);
  EXPECT_NE(env->data_json.find(std::string(64, 'a')), std::string::npos);
  EXPECT_NE(env->data_json.find(std::string(64, 'b')), std::string::npos);
  EXPECT_EQ(env->data_json.find("alice"), std::string::npos);
}

/// Non-egress events are refused by sanitize().
TEST(PiiFilter, RefusesNonEgress) {
  Rig rig;
  PiiFilter f(rig.bus, rig.factory, Redactor("salt"));
  std::shared_ptr<ConfigurationUpdated> ev;
  ASSERT_EQ(rig.factory.make<ConfigurationUpdated>(ev), SRESULT::Ok);
  std::shared_ptr<CloudEventSanitized> env;
  EXPECT_EQ(f.sanitize(*ev, env), SRESULT::InvalidArgument);
}

/// Running filter: egress events produce envelopes, non-egress events produce nothing.
TEST(PiiFilter, SubscribesOnlyToEgressTypes) {
  Rig rig;
  Runtime rt(rig.bus);
  auto filter = std::make_shared<PiiFilter>(rig.bus, rig.factory, Redactor("salt"));
  auto sink = std::make_shared<Collector<CloudEventSanitized>>("sink");
  ASSERT_EQ(rt.add(filter), SRESULT::Ok);
  ASSERT_EQ(rt.add(sink), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);

  std::shared_ptr<ConfigurationUpdated> cfg;
  ASSERT_EQ(rig.factory.make<ConfigurationUpdated>(cfg), SRESULT::Ok);
  EXPECT_EQ(rig.bus.post(cfg), SRESULT::NoOp);  // nobody subscribes: the filter never sees it
  std::shared_ptr<ProcessHangDetected> hang;
  ASSERT_EQ(rig.factory.make<ProcessHangDetected>(hang), SRESULT::Ok);
  EXPECT_EQ(rig.bus.post(hang), SRESULT::Ok);

  ASSERT_EQ(wait_until([&] { return count_of(*sink) == 1; }), SRESULT::Ok);
  ASSERT_EQ(rt.stop(), SRESULT::Ok);
  std::vector<std::shared_ptr<const CloudEventSanitized>> got;
  ASSERT_EQ(sink->received(got), SRESULT::Ok);
  EXPECT_EQ(got[0]->type, "com.ieso.ProcessHangDetected");

  std::vector<TypeStats> stats;
  ASSERT_EQ(rig.bus.stats(stats), SRESULT::Ok);
  for (const auto& s : stats) {
    if (s.type == "ConfigurationUpdated" || s.type == "ProbeRequested") EXPECT_EQ(s.subscribers, 0u);
  }
}
