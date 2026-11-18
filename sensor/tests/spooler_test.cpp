/**
 * @file spooler_test.cpp
 * @brief End-to-end store-and-forward: offline spool, online drain, ack, no duplicates.
 */
#include <gtest/gtest.h>

#include <set>

#include "pii_filter/pii_filter.hpp"
#include "spooler/spooler.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

namespace {

/// @brief Fake Cloud Client: records ids; offline -> SpooledEvent, online -> TelemetryDelivered.
class FakeCloud final : public Actor {
 public:
  /// @brief Binds the bus and factory. @param[in] bus Bus. @param[in] factory Factory.
  FakeCloud(EventBus& bus, EventFactory& factory) : Actor("fake_cloud"), bus_(bus), factory_(factory) {}

  SRESULT on_start(ActorContext& ctx) override {
    HS_RETURN_IF_FAILED(subscribe<NetworkStatusChanged>(ctx.bus, [this](const auto& e) {
      online_ = e->online;
      return SRESULT::Ok;
    }));
    return subscribe<CloudEventSanitized>(ctx.bus, [this](const std::shared_ptr<const CloudEventSanitized>& e) {
      if (!online_) {
        std::shared_ptr<SpooledEvent> sp;
        HS_RETURN_IF_FAILED(factory_.make<SpooledEvent>(sp));
        sp->envelope = e;
        sp->attempts = 1;
        return bus_.post(std::move(sp));
      }
      {
        std::lock_guard lock(mu_);
        delivered_.push_back(e->hdr.id);
      }
      std::shared_ptr<TelemetryDelivered> ack;
      HS_RETURN_IF_FAILED(factory_.make<TelemetryDelivered>(ack));
      ack->ids.push_back(e->hdr.id);
      return bus_.post(std::move(ack));
    });
  }
  /// @brief Delivered ids. @param[out] out Ids. @return SRESULT::Ok.
  SRESULT delivered(std::vector<std::string>& out) const {
    std::lock_guard lock(mu_);
    out = delivered_;
    return SRESULT::Ok;
  }

 private:
  EventBus& bus_;                       ///< Bus.
  EventFactory& factory_;               ///< Factory.
  bool online_ = false;                 ///< Actor-thread state.
  mutable std::mutex mu_;               ///< Guards delivered_.
  std::vector<std::string> delivered_;  ///< Delivered ids.
};

/// @brief Posts NetworkStatusChanged. @param[in] rig Rig. @param[in] online State. @return Result of post.
SRESULT net(Rig& rig, bool online) {
  std::shared_ptr<NetworkStatusChanged> e;
  HS_RETURN_IF_FAILED(rig.factory.make<NetworkStatusChanged>(e));
  e->online = online;
  return rig.bus.post(std::move(e));
}

}  // namespace

/// 20 incidents while offline are spooled; going online delivers each exactly once and empties the spool.
TEST(SpoolerActor, OfflineThenDrainWithoutDuplicates) {
  Rig rig;
  TempDir tmp;
  SystemClock wall;  // drain timers and the token bucket need real time
  SpoolOptions so;
  ASSERT_EQ(tmp.path(so.dir), SRESULT::Ok);
  std::unique_ptr<Spool> spool;
  ASSERT_EQ(Spool::Create(so, wall, std::make_shared<IdentityCodec>(), spool), SRESULT::Ok);

  SpoolerOptions opts;
  opts.drain_tick = std::chrono::milliseconds(5);
  opts.replay_per_second = 1000;
  opts.replay_burst = 5;  // forces several drain rounds
  Runtime rt(rig.bus);
  auto pii = std::make_shared<PiiFilter>(rig.bus, rig.factory, Redactor("salt"));
  auto cloud = std::make_shared<FakeCloud>(rig.bus, rig.factory);
  auto spooler = std::make_shared<SpoolerActor>(rig.bus, rig.factory, wall, std::move(spool), opts);
  ASSERT_EQ(rt.add(pii), SRESULT::Ok);
  ASSERT_EQ(rt.add(cloud), SRESULT::Ok);
  ASSERT_EQ(rt.add(spooler), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);

  std::set<std::string> sent;
  for (int i = 0; i < 20; ++i) {
    std::shared_ptr<ProcessHangDetected> h;
    ASSERT_EQ(rig.factory.make<ProcessHangDetected>(h), SRESULT::Ok);
    sent.insert(h->hdr.id);
    ASSERT_EQ(rig.bus.post(h), SRESULT::Ok);
  }
  std::filesystem::path dir;
  ASSERT_EQ(tmp.path(dir), SRESULT::Ok);
  const auto files = [&] {
    std::error_code ec;
    std::size_t n = 0;
    for (std::filesystem::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) ++n;
    return n;
  };
  ASSERT_EQ(wait_until([&] { return files() == 20; }), SRESULT::Ok);

  ASSERT_EQ(net(rig, true), SRESULT::Ok);
  std::vector<std::string> got;
  ASSERT_EQ(wait_until([&] { return HS_SUCCEEDED(cloud->delivered(got)) && got.size() >= 20; }), SRESULT::Ok);
  ASSERT_EQ(wait_until([&] { return files() == 0; }), SRESULT::Ok);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));  // allow any (wrong) duplicate to show up
  ASSERT_EQ(rt.stop(), SRESULT::Ok);

  ASSERT_EQ(cloud->delivered(got), SRESULT::Ok);
  EXPECT_EQ(got.size(), 20u);
  EXPECT_EQ(std::set<std::string>(got.begin(), got.end()), sent);
}
