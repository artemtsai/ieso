/**
 * @file bus_test.cpp
 * @brief Typed routing, RAII unsubscription, overflow, spill and stats of the EventBus.
 */
#include <gtest/gtest.h>

#include "ontology/events.hpp"
#include "pii_filter/pii_filter.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {

/**
 * @brief Runs every queued task in a mailbox (closes it first so pop_wait never blocks).
 * @param[in] mb Mailbox.
 * @param[out] ran Tasks executed.
 * @return SRESULT::Ok.
 */
SRESULT run_all(Mailbox& mb, std::size_t& ran) {
  ran = 0;
  HS_RETURN_IF_FAILED(mb.close());
  Task t;
  while (mb.pop_wait(t) == SRESULT::Ok) {
    (void)t();  // handler results are checked by the test via side effects
    ++ran;
  }
  return SRESULT::Ok;
}

/**
 * @brief Makes a routine telemetry event.
 * @param[in] rig Rig.
 * @param[out] out Event.
 * @return Result of make.
 */
SRESULT telemetry(Rig& rig, std::shared_ptr<TelemetrySnapshotCaptured>& out) {
  return rig.factory.make<TelemetrySnapshotCaptured>(out);
}

}  // namespace

/// Only subscribers of the exact dynamic type receive the event; the header is filled by the factory.
TEST(Bus, TypedDelivery) {
  Rig rig;
  auto mb = std::make_shared<Mailbox>("m");
  int crashes = 0, hangs = 0;
  Subscription s1, s2;
  ASSERT_EQ(rig.bus.subscribe<ProcessCrashDetected>(mb, [&](const auto& e) {
    EXPECT_EQ(e->pid, 7);
    EXPECT_EQ(e->hdr.cls, EventClass::Incident);
    EXPECT_TRUE(e->hdr.egress);
    EXPECT_EQ(e->hdr.id.size(), 36u);
    ++crashes;
    return SRESULT::Ok;
  }, s1), SRESULT::Ok);
  ASSERT_EQ(rig.bus.subscribe<ProcessHangDetected>(mb, [&](const auto&) { ++hangs; return SRESULT::Ok; }, s2),
            SRESULT::Ok);
  std::shared_ptr<ProcessCrashDetected> c;
  ASSERT_EQ(rig.factory.make<ProcessCrashDetected>(c), SRESULT::Ok);
  c->pid = 7;
  EXPECT_EQ(rig.bus.post(c), SRESULT::Ok);
  std::size_t ran = 0;
  ASSERT_EQ(run_all(*mb, ran), SRESULT::Ok);
  EXPECT_EQ(crashes, 1);
  EXPECT_EQ(hangs, 0);
}

/// Posting with no subscribers is NoOp; a null event is NullPointer.
TEST(Bus, NoSubscribersAndNull) {
  Rig rig;
  std::shared_ptr<TelemetrySnapshotCaptured> t;
  ASSERT_EQ(telemetry(rig, t), SRESULT::Ok);
  EXPECT_EQ(rig.bus.post(t), SRESULT::NoOp);
  EXPECT_EQ(rig.bus.post(nullptr), SRESULT::NullPointer);
}

/// After the token is reset, already-queued deliveries are skipped and new posts don't reach it.
TEST(Bus, RaiiUnsubscribeSkipsQueued) {
  Rig rig;
  auto mb = std::make_shared<Mailbox>("m");
  int got = 0;
  {
    Subscription s;
    ASSERT_EQ(rig.bus.subscribe<TelemetrySnapshotCaptured>(mb, [&](const auto&) { ++got; return SRESULT::Ok; }, s),
              SRESULT::Ok);
    std::shared_ptr<TelemetrySnapshotCaptured> t;
    ASSERT_EQ(telemetry(rig, t), SRESULT::Ok);
    ASSERT_EQ(rig.bus.post(t), SRESULT::Ok);  // queued, not yet run
  }  // token destroyed here
  std::shared_ptr<TelemetrySnapshotCaptured> t2;
  ASSERT_EQ(telemetry(rig, t2), SRESULT::Ok);
  EXPECT_EQ(rig.bus.post(t2), SRESULT::NoOp);
  std::size_t ran = 0;
  ASSERT_EQ(run_all(*mb, ran), SRESULT::Ok);
  EXPECT_EQ(ran, 1u);
  EXPECT_EQ(got, 0);
}

/// A handler may drop its own subscription while being dispatched.
TEST(Bus, UnsubscribeDuringDispatch) {
  Rig rig;
  auto mb = std::make_shared<Mailbox>("m");
  int got = 0;
  Subscription s;
  ASSERT_EQ(rig.bus.subscribe<TelemetrySnapshotCaptured>(mb, [&](const auto&) {
    ++got;
    return s.reset();
  }, s), SRESULT::Ok);
  for (int i = 0; i < 3; ++i) {
    std::shared_ptr<TelemetrySnapshotCaptured> t;
    ASSERT_EQ(telemetry(rig, t), SRESULT::Ok);
    ASSERT_EQ(rig.bus.post(t), SRESULT::Ok);
  }
  std::size_t ran = 0;
  ASSERT_EQ(run_all(*mb, ran), SRESULT::Ok);
  EXPECT_EQ(got, 1);
}

/// Routine overflow drops oldest and is counted; never-drop overflow is force-queued, not lost.
TEST(Bus, OverflowPolicies) {
  Rig rig;
  MailboxCapacities caps;
  caps.routine = 2;
  caps.incident = 2;
  auto mb = std::make_shared<Mailbox>("m", caps);
  Subscription s1, s2;
  ASSERT_EQ(rig.bus.subscribe<TelemetrySnapshotCaptured>(mb, [](const auto&) { return SRESULT::Ok; }, s1),
            SRESULT::Ok);
  ASSERT_EQ(rig.bus.subscribe<ProcessHangDetected>(mb, [](const auto&) { return SRESULT::Ok; }, s2), SRESULT::Ok);
  for (int i = 0; i < 5; ++i) {
    std::shared_ptr<TelemetrySnapshotCaptured> t;
    ASSERT_EQ(telemetry(rig, t), SRESULT::Ok);
    (void)rig.bus.post(t);  // Ok or Dropped; checked via stats below
    std::shared_ptr<ProcessHangDetected> h;
    ASSERT_EQ(rig.factory.make<ProcessHangDetected>(h), SRESULT::Ok);
    EXPECT_EQ(rig.bus.post(h), SRESULT::Ok);
  }
  std::vector<TypeStats> stats;
  ASSERT_EQ(rig.bus.stats(stats), SRESULT::Ok);
  for (const auto& st : stats) {
    if (st.type == "TelemetrySnapshotCaptured") EXPECT_EQ(st.dropped, 3u);
    if (st.type == "ProcessHangDetected") {
      EXPECT_EQ(st.forced, 3u);
      EXPECT_EQ(st.lost, 0u);
      EXPECT_EQ(st.delivered, 5u);
    }
  }
  MailboxStats ms;
  ASSERT_EQ(mb->stats(ms), SRESULT::Ok);
  EXPECT_EQ(ms.incident.depth, 5u);
  EXPECT_EQ(ms.routine.depth, 2u);
}

/// A full lane spills sanitized (spillable) envelopes to the spill sink exactly once.
TEST(Bus, SpillSinkForSanitizedEnvelopes) {
  Rig rig;
  PiiFilter filter(rig.bus, rig.factory, Redactor("salt"));
  MailboxCapacities caps;
  caps.incident = 1;
  auto mb = std::make_shared<Mailbox>("cloud", caps);
  Subscription s;
  ASSERT_EQ(rig.bus.subscribe<CloudEventSanitized>(mb, [](const auto&) { return SRESULT::Ok; }, s), SRESULT::Ok);
  int spilled = 0;
  ASSERT_EQ(rig.bus.set_spill_sink([&](const std::shared_ptr<const Event>&) {
    ++spilled;
    return SRESULT::Ok;
  }), SRESULT::Ok);
  for (int i = 0; i < 3; ++i) {
    std::shared_ptr<ProcessCrashDetected> c;
    ASSERT_EQ(rig.factory.make<ProcessCrashDetected>(c), SRESULT::Ok);
    std::shared_ptr<CloudEventSanitized> env;
    ASSERT_EQ(filter.sanitize(*c, env), SRESULT::Ok);
    const SRESULT r = rig.bus.post(env);
    EXPECT_EQ(r, i == 0 ? SRESULT::Ok : SRESULT::Spilled);
  }
  EXPECT_EQ(spilled, 2);
}

/// A slow subscriber never blocks the poster.
TEST(Bus, PostDoesNotBlockOnSlowSubscriber) {
  Rig rig;
  Runtime rt(rig.bus);
  auto slow = std::make_shared<Collector<TelemetrySnapshotCaptured>>("slow");
  std::atomic<bool> release{false};
  ASSERT_EQ(slow->set_gate([&] {
    while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return SRESULT::Ok;
  }), SRESULT::Ok);
  ASSERT_EQ(rt.add(slow), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);
  const auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < 2000; ++i) {
    std::shared_ptr<TelemetrySnapshotCaptured> t;
    ASSERT_EQ(telemetry(rig, t), SRESULT::Ok);
    (void)rig.bus.post(t);  // drops are expected once the lane is full
  }
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  EXPECT_LT(elapsed, std::chrono::seconds(1));
  release.store(true);
  ASSERT_EQ(rt.stop(), SRESULT::Ok);
}
