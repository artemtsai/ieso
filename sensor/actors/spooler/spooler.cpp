/**
 * @file spooler.cpp
 * @brief SpoolerActor implementation.
 */
#include "spooler/spooler.hpp"

#include "ieso/core/runtime.hpp"
#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "spooler";
}  // namespace

SpoolerActor::SpoolerActor(EventBus& bus, EventFactory& factory, const IClock& clock, std::unique_ptr<Spool> spool,
                           SpoolerOptions opts)
    : Actor("spooler"),
      bus_(bus),
      factory_(factory),
      clock_(clock),
      spool_(std::move(spool)),
      opts_(opts),
      backoff_(opts.backoff_base, opts.backoff_cap, opts.seed),
      bucket_(opts.replay_per_second, opts.replay_burst, std::chrono::steady_clock::time_point{}) {}

SRESULT SpoolerActor::on_start(ActorContext& ctx) {
  if (!spool_) return SRESULT::NullPointer;
  HS_RETURN_IF_FAILED(subscribe<SpooledEvent>(ctx.bus, [this](const auto& e) { return on_spooled(e); }));
  HS_RETURN_IF_FAILED(subscribe<NetworkStatusChanged>(ctx.bus, [this](const auto& e) { return on_network(e); }));
  HS_RETURN_IF_FAILED(subscribe<TelemetryDelivered>(ctx.bus, [this](const auto& e) { return on_delivered(e); }));
  HS_RETURN_IF_FAILED(ctx.bus.set_spill_sink([this](const std::shared_ptr<const Event>& e) { return spill(e); }));
  auto self = shared_from_this();
  TimerId drain_id = 0;
  TimerId purge_id = 0;
  HS_RETURN_IF_FAILED(ctx.runtime.schedule_every(self, opts_.drain_tick, [this] { return drain_tick(); }, drain_id));
  HS_RETURN_IF_FAILED(ctx.runtime.schedule_every(self, opts_.purge_period, [this] { return purge_tick(); }, purge_id));
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  bucket_ = TokenBucket(opts_.replay_per_second, opts_.replay_burst, now);
  return SRESULT::Ok;
}

SRESULT SpoolerActor::on_stop() {
  HS_RETURN_IF_FAILED(bus_.set_spill_sink({}));
  return Actor::on_stop();
}

SRESULT SpoolerActor::spill(const std::shared_ptr<const Event>& ev) {
  auto env = std::dynamic_pointer_cast<const CloudEventSanitized>(ev);
  if (!env) return SRESULT::InvalidArgument;  // only sanitized envelopes may reach disk
  std::shared_ptr<SpooledEvent> sp;
  HS_RETURN_IF_FAILED(factory_.make<SpooledEvent>(sp));
  sp->envelope = std::move(env);
  sp->attempts = 0;
  return bus_.post(std::move(sp));
}

SRESULT SpoolerActor::on_spooled(const std::shared_ptr<const SpooledEvent>& ev) {
  if (!ev->envelope) return SRESULT::NullPointer;
  HS_RETURN_IF_FAILED(spool_->put(*ev->envelope, ev->attempts));
  if (online_ && ev->attempts > 0) {
    // A replay failed while we believed the backend was up: back off with jitter.
    std::chrono::milliseconds delay{0};
    HS_RETURN_IF_FAILED(backoff_.next(delay));
    std::chrono::steady_clock::time_point now;
    HS_RETURN_IF_FAILED(clock_.now_steady(now));
    paused_until_ = now + delay;
    HS_TRACE_INFO(kComponent, "replay failed for {}; backing off {} ms", ev->envelope->hdr.id, delay.count());
  }
  return SRESULT::Ok;
}

SRESULT SpoolerActor::on_network(const std::shared_ptr<const NetworkStatusChanged>& ev) {
  if (ev->online == online_) return SRESULT::NoOp;
  online_ = ev->online;
  HS_TRACE_INFO(kComponent, "network {}", online_ ? "online: draining spool" : "offline: spooling");
  if (!online_) return spool_->release_in_flight();
  HS_RETURN_IF_FAILED(backoff_.reset());
  paused_until_ = {};
  return SRESULT::Ok;
}

SRESULT SpoolerActor::on_delivered(const std::shared_ptr<const TelemetryDelivered>& ev) {
  for (const std::string& id : ev->ids) {
    const SRESULT r = spool_->ack(id);
    if (r != SRESULT::Ok && r != SRESULT::NotFound) return r;  // NotFound: delivered live, never spooled
  }
  return backoff_.reset();
}

SRESULT SpoolerActor::drain_tick() {
  if (!online_) return SRESULT::NoOp;
  std::chrono::steady_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_steady(now));
  if (now < paused_until_) return SRESULT::NoOp;
  std::uint32_t granted = 0;
  if (bucket_.take_up_to(now, static_cast<std::uint32_t>(opts_.replay_burst), granted) != SRESULT::Ok) {
    return SRESULT::NoOp;
  }
  std::vector<SpoolItem> items;
  const SRESULT r = spool_->drain(granted, items);
  HS_RETURN_IF_FAILED(r);
  if (items.size() < granted) HS_RETURN_IF_FAILED(bucket_.refund(granted - static_cast<std::uint32_t>(items.size())));
  for (SpoolItem& item : items) {
    const SRESULT p = bus_.post(item.envelope);
    if (HS_FAILED(p)) HS_TRACE_WARNING(kComponent, "replay post failed for {}: {}", item.envelope->hdr.id, p);
  }
  if (!items.empty()) HS_TRACE_DEBUG(kComponent, "replayed {} spooled envelopes", items.size());
  return SRESULT::Ok;
}

SRESULT SpoolerActor::purge_tick() {
  std::size_t purged = 0;
  HS_RETURN_IF_FAILED(spool_->purge_expired(purged));
  return publish_storage();
}

SRESULT SpoolerActor::publish_storage() {
  SpoolStats st;
  HS_RETURN_IF_FAILED(spool_->stats(st));
  std::shared_ptr<SpoolStorageUpdated> ev;
  HS_RETURN_IF_FAILED(factory_.make<SpoolStorageUpdated>(ev));
  ev->bytes = st.bytes;
  ev->count = st.count;
  std::chrono::system_clock::time_point now;
  HS_RETURN_IF_FAILED(clock_.now_system(now));
  const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  ev->oldest_age_s = st.oldest_enqueue_ms == 0 ? 0 : (now_ms - st.oldest_enqueue_ms) / 1000;
  const SRESULT r = bus_.post(std::move(ev));
  return r == SRESULT::NoOp ? SRESULT::Ok : r;
}

}  // namespace ieso
