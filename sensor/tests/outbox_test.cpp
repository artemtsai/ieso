/**
 * @file outbox_test.cpp
 * @brief File outbox: one CloudEvents line per envelope, acked with TelemetryDelivered.
 */
#include <gtest/gtest.h>

#include <fstream>

#include "outbox/outbox.hpp"
#include "pii_filter/pii_filter.hpp"
#include "test_util.hpp"

using namespace ieso;
using namespace ieso::test;

/// Envelopes are appended as JSON lines and acknowledged.
TEST(FileOutbox, AppendsAndAcks) {
  Rig rig;
  TempDir tmp;
  std::filesystem::path dir;
  ASSERT_EQ(tmp.path(dir), SRESULT::Ok);
  const auto file = dir / "out" / "outbox.ndjson";
  Runtime rt(rig.bus);
  auto acks = std::make_shared<Collector<TelemetryDelivered>>("acks");
  ASSERT_EQ(rt.add(acks), SRESULT::Ok);
  ASSERT_EQ(rt.add(std::make_shared<FileOutboxActor>(rig.bus, rig.factory, file)), SRESULT::Ok);
  ASSERT_EQ(rt.start(), SRESULT::Ok);
  PiiFilter filter(rig.bus, rig.factory, Redactor("s"));
  std::vector<std::string> ids;
  for (int i = 0; i < 3; ++i) {
    std::shared_ptr<ProcessHangDetected> h;
    ASSERT_EQ(rig.factory.make<ProcessHangDetected>(h), SRESULT::Ok);
    std::shared_ptr<CloudEventSanitized> env;
    ASSERT_EQ(filter.sanitize(*h, env), SRESULT::Ok);
    ids.push_back(env->hdr.id);
    ASSERT_EQ(rig.bus.post(env), SRESULT::Ok);
  }
  ASSERT_EQ(wait_until([&] { return count_of(*acks) == 3; }), SRESULT::Ok);
  ASSERT_EQ(rt.stop(), SRESULT::Ok);
  std::ifstream f(file);
  std::string line;
  std::size_t n = 0;
  while (std::getline(f, line)) {
    EXPECT_NE(line.find("\"id\":\"" + ids[n] + "\""), std::string::npos);
    ++n;
  }
  EXPECT_EQ(n, 3u);
}
