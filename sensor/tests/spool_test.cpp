/**
 * @file spool_test.cpp
 * @brief Spool ordering, idempotency, caps, TTL, ack, restart and corruption handling.
 */
#include <gtest/gtest.h>

#include <fstream>

#include "pii_filter/pii_filter.hpp"
#include "ieso/core/spool.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {

/// @brief Rig + filter + temp spool dir.
struct SpoolRig {
  Rig rig;                                                       ///< Core rig.
  PiiFilter filter{rig.bus, rig.factory, Redactor("salt")};      ///< Envelope builder.
  TempDir tmp;                                                   ///< Spool dir.
  std::shared_ptr<const ICodec> codec = std::make_shared<IdentityCodec>();  ///< Codec.

  /// @brief Opens a spool. @param[in] max_bytes Cap. @param[out] out Spool. @return Result of Create.
  SRESULT open(std::uint64_t max_bytes, std::unique_ptr<Spool>& out) {
    SpoolOptions o;
    HS_RETURN_IF_FAILED(tmp.path(o.dir));
    o.max_bytes = max_bytes;
    o.ttl_routine = std::chrono::hours(1);
    o.ttl_incident = std::chrono::hours(48);
    return Spool::Create(o, rig.clock, codec, out);
  }

  /// @brief Makes an envelope from event type T. @tparam T Event. @param[out] out Envelope. @return Ok.
  template <class T>
  SRESULT envelope(std::shared_ptr<const CloudEventSanitized>& out) {
    std::shared_ptr<T> ev;
    HS_RETURN_IF_FAILED(rig.factory.make<T>(ev));
    std::shared_ptr<CloudEventSanitized> env;
    HS_RETURN_IF_FAILED(filter.sanitize(*ev, env));
    out = std::move(env);
    return SRESULT::Ok;
  }
};

/**
 * @brief Drains everything and returns the ids in order.
 * @param[in] s Spool.
 * @return Ids.
 */
std::vector<std::string> drain_ids(Spool& s) {
  std::vector<SpoolItem> items;
  (void)s.drain(1000, items);  // NoOp when empty is fine
  std::vector<std::string> ids;
  for (const auto& i : items) ids.push_back(i.envelope->hdr.id);
  return ids;
}

}  // namespace

/// Incidents drain before routine telemetry; within a class, oldest first.
TEST(Spool, PriorityThenAge) {
  SpoolRig r;
  std::unique_ptr<Spool> s;
  ASSERT_EQ(r.open(1 << 20, s), SRESULT::Ok);
  std::shared_ptr<const CloudEventSanitized> t1, c1, t2, c2;
  ASSERT_EQ(r.envelope<TelemetrySnapshotCaptured>(t1), SRESULT::Ok);
  ASSERT_EQ(s->put(*t1, 1), SRESULT::Ok);
  ASSERT_EQ(r.rig.clock.advance(std::chrono::milliseconds(5)), SRESULT::Ok);
  ASSERT_EQ(r.envelope<ProcessCrashDetected>(c1), SRESULT::Ok);
  ASSERT_EQ(s->put(*c1, 1), SRESULT::Ok);
  ASSERT_EQ(r.rig.clock.advance(std::chrono::milliseconds(5)), SRESULT::Ok);
  ASSERT_EQ(r.envelope<TelemetrySnapshotCaptured>(t2), SRESULT::Ok);
  ASSERT_EQ(s->put(*t2, 1), SRESULT::Ok);
  ASSERT_EQ(r.rig.clock.advance(std::chrono::milliseconds(5)), SRESULT::Ok);
  ASSERT_EQ(r.envelope<ProcessHangDetected>(c2), SRESULT::Ok);
  ASSERT_EQ(s->put(*c2, 1), SRESULT::Ok);
  EXPECT_EQ(drain_ids(*s), (std::vector<std::string>{c1->hdr.id, c2->hdr.id, t1->hdr.id, t2->hdr.id}));
}

/// Re-spooling an id rewrites in place (no duplicate) and keeps the attempt count; drained items are in-flight.
TEST(Spool, IdempotentAndInFlight) {
  SpoolRig r;
  std::unique_ptr<Spool> s;
  ASSERT_EQ(r.open(1 << 20, s), SRESULT::Ok);
  std::shared_ptr<const CloudEventSanitized> c;
  ASSERT_EQ(r.envelope<ProcessCrashDetected>(c), SRESULT::Ok);
  ASSERT_EQ(s->put(*c, 1), SRESULT::Ok);
  ASSERT_EQ(s->put(*c, 2), SRESULT::Ok);
  SpoolStats st;
  ASSERT_EQ(s->stats(st), SRESULT::Ok);
  EXPECT_EQ(st.count, 1u);

  std::vector<SpoolItem> items;
  ASSERT_EQ(s->drain(10, items), SRESULT::Ok);
  ASSERT_EQ(items.size(), 1u);
  EXPECT_EQ(items[0].attempts, 2u);
  EXPECT_EQ(items[0].envelope->data_json, c->data_json);
  EXPECT_EQ(s->drain(10, items), SRESULT::NoOp);  // in flight
  ASSERT_EQ(s->put(*c, 3), SRESULT::Ok);           // replay failed -> pending again
  ASSERT_EQ(s->drain(10, items), SRESULT::Ok);
  EXPECT_EQ(items[0].attempts, 3u);
  ASSERT_EQ(s->release_in_flight(), SRESULT::Ok);
  ASSERT_EQ(s->ack(c->hdr.id), SRESULT::Ok);
  EXPECT_EQ(s->ack(c->hdr.id), SRESULT::NotFound);
  ASSERT_EQ(s->stats(st), SRESULT::Ok);
  EXPECT_EQ(st.count, 0u);
  EXPECT_EQ(st.bytes, 0u);
}

/// At the cap, oldest routine records are evicted; incidents are never evicted.
TEST(Spool, SizeCapEvictsRoutineOnly) {
  SpoolRig r;
  std::unique_ptr<Spool> s;
  std::shared_ptr<const CloudEventSanitized> probe;
  ASSERT_EQ(r.envelope<TelemetrySnapshotCaptured>(probe), SRESULT::Ok);
  ASSERT_EQ(r.open(4000, s), SRESULT::Ok);  // fits roughly 8-10 small records
  std::vector<std::string> incidents;
  for (int i = 0; i < 4; ++i) {
    std::shared_ptr<const CloudEventSanitized> c;
    ASSERT_EQ(r.envelope<ProcessHangDetected>(c), SRESULT::Ok);
    ASSERT_EQ(s->put(*c, 1), SRESULT::Ok);
    incidents.push_back(c->hdr.id);
  }
  for (int i = 0; i < 50; ++i) {
    std::shared_ptr<const CloudEventSanitized> t;
    ASSERT_EQ(r.envelope<TelemetrySnapshotCaptured>(t), SRESULT::Ok);
    ASSERT_EQ(r.rig.clock.advance(std::chrono::milliseconds(1)), SRESULT::Ok);
    ASSERT_EQ(s->put(*t, 1), SRESULT::Ok);
  }
  SpoolStats st;
  ASSERT_EQ(s->stats(st), SRESULT::Ok);
  EXPECT_LE(st.bytes, 4000u);
  EXPECT_GT(st.evicted, 0u);
  const auto ids = drain_ids(*s);
  for (std::size_t i = 0; i < incidents.size(); ++i) EXPECT_EQ(ids[i], incidents[i]);

  // Fill with incidents only: a new incident that cannot fit is refused, not stored by evicting incidents.
  std::unique_ptr<Spool> tiny;
  SpoolRig r2;
  ASSERT_EQ(r2.open(600, tiny), SRESULT::Ok);
  SRESULT last = SRESULT::Ok;
  for (int i = 0; i < 10 && last == SRESULT::Ok; ++i) {
    std::shared_ptr<const CloudEventSanitized> c;
    ASSERT_EQ(r2.envelope<ProcessHangDetected>(c), SRESULT::Ok);
    last = tiny->put(*c, 1);
  }
  EXPECT_EQ(last, SRESULT::CapacityExceeded);
}

/// Records past their class TTL are purged.
TEST(Spool, TtlPurge) {
  SpoolRig r;
  std::unique_ptr<Spool> s;
  ASSERT_EQ(r.open(1 << 20, s), SRESULT::Ok);
  std::shared_ptr<const CloudEventSanitized> t, c;
  ASSERT_EQ(r.envelope<TelemetrySnapshotCaptured>(t), SRESULT::Ok);
  ASSERT_EQ(r.envelope<ProcessCrashDetected>(c), SRESULT::Ok);
  ASSERT_EQ(s->put(*t, 1), SRESULT::Ok);
  ASSERT_EQ(s->put(*c, 1), SRESULT::Ok);
  ASSERT_EQ(r.rig.clock.advance(std::chrono::hours(2)), SRESULT::Ok);
  std::size_t purged = 0;
  ASSERT_EQ(s->purge_expired(purged), SRESULT::Ok);
  EXPECT_EQ(purged, 1u);  // routine TTL 1 h passed, incident TTL 48 h not
  EXPECT_EQ(drain_ids(*s), (std::vector<std::string>{c->hdr.id}));
}

/// The spool survives a restart; temp files and corrupt records are cleaned up on open.
TEST(Spool, ReopenAndCorruption) {
  SpoolRig r;
  std::shared_ptr<const CloudEventSanitized> c;
  ASSERT_EQ(r.envelope<ProcessCrashDetected>(c), SRESULT::Ok);
  {
    std::unique_ptr<Spool> s;
    ASSERT_EQ(r.open(1 << 20, s), SRESULT::Ok);
    ASSERT_EQ(s->put(*c, 4), SRESULT::Ok);
  }
  std::filesystem::path dir;
  ASSERT_EQ(r.tmp.path(dir), SRESULT::Ok);
  { std::ofstream(dir / "0_0000000000000001_bad.rec") << "garbage"; }
  { std::ofstream(dir / "x.rec.tmp") << "partial"; }

  std::unique_ptr<Spool> s;
  ASSERT_EQ(r.open(1 << 20, s), SRESULT::Ok);
  SpoolStats st;
  ASSERT_EQ(s->stats(st), SRESULT::Ok);
  EXPECT_EQ(st.count, 1u);
  EXPECT_EQ(st.corrupt, 1u);
  EXPECT_FALSE(std::filesystem::exists(dir / "x.rec.tmp"));
  std::vector<SpoolItem> items;
  ASSERT_EQ(s->drain(10, items), SRESULT::Ok);
  ASSERT_EQ(items.size(), 1u);
  EXPECT_EQ(items[0].envelope->hdr.id, c->hdr.id);
  EXPECT_EQ(items[0].attempts, 4u);
  EXPECT_EQ(items[0].envelope->hdr.cls, EventClass::Incident);
  EXPECT_EQ(items[0].envelope->hdr.ts, c->hdr.ts);
  std::string a, b;
  ASSERT_EQ(items[0].envelope->to_json(a), SRESULT::Ok);
  ASSERT_EQ(c->to_json(b), SRESULT::Ok);
  EXPECT_EQ(a, b);
}

/// Bad options are rejected.
TEST(Spool, InvalidOptions) {
  ManualClock clock;
  std::unique_ptr<Spool> s;
  SpoolOptions o;
  EXPECT_EQ(Spool::Create(o, clock, std::make_shared<IdentityCodec>(), s), SRESULT::InvalidArgument);
  o.dir = "/tmp/x";
  EXPECT_EQ(Spool::Create(o, clock, nullptr, s), SRESULT::InvalidArgument);
}
