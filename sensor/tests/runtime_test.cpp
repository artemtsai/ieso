/**
 * @file runtime_test.cpp
 * @brief Actor lifecycle, thread affinity, timers and shutdown drain.
 */
#include <gtest/gtest.h>

#include "ontology/events.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {

/// @brief Actor that logs lifecycle calls and runs a timer.
class Probe final : public Actor {
 public:
  /// @brief Creates the probe. @param[in] name Name. @param[in] log Shared lifecycle log. @param[in] fail Fail on_start.
  Probe(std::string name, std::shared_ptr<std::vector<std::string>> log, bool fail = false)
      : Actor(name), name_(std::move(name)), log_(std::move(log)), fail_(fail) {}

  SRESULT on_start(ActorContext& ctx) override {
    log_->push_back("start:" + name_);
    if (fail_) return SRESULT::PermissionDenied;
    HS_RETURN_IF_FAILED(subscribe<TelemetrySnapshotCaptured>(ctx.bus, [this](const auto&) {
      handler_thread_ = std::this_thread::get_id();
      handled_.fetch_add(1);
      return SRESULT::Ok;
    }));
    TimerId id = 0;
    return ctx.runtime.schedule_every(shared_from_this(), std::chrono::milliseconds(5), [this] {
      timer_thread_ = std::this_thread::get_id();
      ticks_.fetch_add(1);
      return SRESULT::Ok;
    }, id);
  }
  SRESULT on_stop() override {
    log_->push_back("stop:" + name_);
    return Actor::on_stop();
  }

  std::atomic<int> handled_{0};      ///< Events handled.
  std::atomic<int> ticks_{0};        ///< Timer ticks.
  std::thread::id handler_thread_;   ///< Thread of the last handler (read after stop).
  std::thread::id timer_thread_;     ///< Thread of the last tick (read after stop).

 private:
  std::string name_;                                ///< Name.
  std::shared_ptr<std::vector<std::string>> log_;   ///< Lifecycle log (stop runs serially).
  bool fail_;                                       ///< Fail on_start.
};

}  // namespace

/// Actors start in order, stop in reverse; handlers and timers run on the same actor thread.
TEST(Runtime, LifecycleOrderAndAffinity) {
  Rig rig;
  auto log = std::make_shared<std::vector<std::string>>();
  auto a = std::make_shared<Probe>("a", log);
  auto b = std::make_shared<Probe>("b", log);
  Runtime rt(rig.bus);
  ASSERT_EQ(rt.add(a), SRESULT::Ok);
  ASSERT_EQ(rt.add(b), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);
  EXPECT_EQ(rt.add(a), SRESULT::InvalidState);
  std::shared_ptr<TelemetrySnapshotCaptured> t;
  ASSERT_EQ(rig.factory.make<TelemetrySnapshotCaptured>(t), SRESULT::Ok);
  ASSERT_EQ(rig.bus.post(t), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return a->handled_ == 1 && b->handled_ == 1 && a->ticks_ >= 2; }), SRESULT::Ok);
  ASSERT_EQ(rt.stop(), SRESULT::Ok);
  EXPECT_EQ(rt.stop(), SRESULT::NoOp);
  EXPECT_EQ(a->handler_thread_, a->timer_thread_);
  EXPECT_NE(a->handler_thread_, b->handler_thread_);
  EXPECT_EQ(*log, (std::vector<std::string>{"start:a", "start:b", "stop:b", "stop:a"}));
}

/// A failing on_start aborts start() and rolls back already-started actors.
TEST(Runtime, StartFailureRollsBack) {
  Rig rig;
  auto log = std::make_shared<std::vector<std::string>>();
  Runtime rt(rig.bus);
  ASSERT_EQ(rt.add(std::make_shared<Probe>("a", log)), SRESULT::Ok);
  ASSERT_EQ(rt.add(std::make_shared<Probe>("bad", log, true)), SRESULT::Ok);
  EXPECT_EQ(rt.start(), SRESULT::PermissionDenied);
  EXPECT_EQ(*log, (std::vector<std::string>{"start:a", "start:bad", "stop:bad", "stop:a"}));
}

/// Events queued before stop() are still delivered (drain on shutdown).
TEST(Runtime, StopDrainsPendingEvents) {
  Rig rig;
  auto c = std::make_shared<Collector<ProcessHangDetected>>();
  std::atomic<bool> release{false};
  ASSERT_EQ(c->set_gate([&] {
    while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return SRESULT::Ok;
  }), SRESULT::Ok);
  Runtime rt(rig.bus);
  ASSERT_EQ(rt.add(c), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);
  for (int i = 0; i < 50; ++i) {
    std::shared_ptr<ProcessHangDetected> h;
    ASSERT_EQ(rig.factory.make<ProcessHangDetected>(h), SRESULT::Ok);
    ASSERT_EQ(rig.bus.post(h), SRESULT::Ok);
  }
  release.store(true);
  ASSERT_EQ(rt.stop(), SRESULT::Ok);
  EXPECT_EQ(count_of(*c), 50u);
}

/// Timers coalesce: a blocked actor gets at most one queued tick, not a backlog.
TEST(Runtime, TimersCoalesce) {
  Rig rig;
  auto c = std::make_shared<Collector<ProcessHangDetected>>();
  Runtime rt(rig.bus);
  ASSERT_EQ(rt.add(c), SRESULT::Ok);
  std::atomic<int> ticks{0};
  std::atomic<bool> release{false};
  TimerId id = 0;
  ASSERT_EQ(rt.schedule_every(c, std::chrono::milliseconds(1), [&] {
    ticks.fetch_add(1);
    while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    return SRESULT::Ok;
  }, id), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);
  std::this_thread::sleep_for(std::chrono::milliseconds(100));  // ~100 periods while blocked
  MailboxStats ms;
  std::shared_ptr<Mailbox> mb;
  ASSERT_EQ(c->mailbox(mb), SRESULT::Ok);
  ASSERT_EQ(mb->stats(ms), SRESULT::Ok);
  EXPECT_LE(ms.control.depth, 1u);
  ASSERT_EQ(rt.cancel_timer(id), SRESULT::Ok);
  EXPECT_EQ(rt.cancel_timer(id), SRESULT::NotFound);
  release.store(true);
  ASSERT_EQ(rt.stop(), SRESULT::Ok);
  EXPECT_LE(ticks.load(), 3);
}
