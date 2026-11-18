/**
 * @file bus.cpp
 * @brief EventBus and Subscription implementation.
 */
#include "ieso/core/bus.hpp"

#include <algorithm>

#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "bus";
}  // namespace

// ---------------- Subscription ----------------

Subscription::Subscription(std::weak_ptr<detail::BusRegistry> reg, std::type_index type,
                           std::shared_ptr<detail::SubscriberEntry> entry)
    : registry_(std::move(reg)), type_(type), entry_(std::move(entry)) {}

Subscription::~Subscription() { (void)reset(); }

Subscription::Subscription(Subscription&& other) noexcept
    : registry_(std::move(other.registry_)), type_(other.type_), entry_(std::move(other.entry_)) {}

Subscription& Subscription::operator=(Subscription&& other) noexcept {
  if (this != &other) {
    (void)reset();
    registry_ = std::move(other.registry_);
    type_ = other.type_;
    entry_ = std::move(other.entry_);
  }
  return *this;
}

SRESULT Subscription::reset() {
  if (!entry_) return SRESULT::NoOp;
  entry_->active.store(false, std::memory_order_release);
  if (auto reg = registry_.lock()) {
    std::unique_lock lock(reg->mu);
    auto it = reg->slots.find(type_);
    if (it != reg->slots.end()) {
      auto& subs = it->second->subs;
      subs.erase(std::remove_if(subs.begin(), subs.end(), [&](const auto& e) { return e == entry_; }), subs.end());
    }
  }
  entry_.reset();
  registry_.reset();
  return SRESULT::Ok;
}

SRESULT Subscription::active(bool& out) const {
  out = entry_ && entry_->active.load(std::memory_order_acquire);
  return SRESULT::Ok;
}

// ---------------- EventBus ----------------

EventBus::EventBus() : registry_(std::make_shared<detail::BusRegistry>()) {}

SRESULT EventBus::slot_for(std::type_index type, std::string_view name, std::shared_ptr<detail::TypeSlot>& out) {
  {
    std::shared_lock lock(registry_->mu);
    auto it = registry_->slots.find(type);
    if (it != registry_->slots.end()) {
      out = it->second;
      return SRESULT::Ok;
    }
  }
  std::unique_lock lock(registry_->mu);
  auto& slot = registry_->slots[type];
  if (!slot) {
    slot = std::make_shared<detail::TypeSlot>();
    slot->name = std::string(name);
  }
  out = slot;
  return SRESULT::Ok;
}

SRESULT EventBus::subscribe_impl(std::type_index type, std::string_view name, const std::shared_ptr<Mailbox>& mailbox,
                                 EventHandler handler, Subscription& out) {
  std::shared_ptr<detail::TypeSlot> slot;
  HS_RETURN_IF_FAILED(slot_for(type, name, slot));
  auto entry = std::make_shared<detail::SubscriberEntry>();
  entry->id = registry_->next_id.fetch_add(1, std::memory_order_relaxed);
  entry->mailbox = mailbox;
  entry->handler = std::move(handler);
  {
    std::unique_lock lock(registry_->mu);
    slot->subs.push_back(entry);
  }
  std::string owner;
  HS_RETURN_IF_FAILED(mailbox->name(owner));
  HS_TRACE_DEBUG(kComponent, "{} subscribed to {}", owner, name);
  out = Subscription(registry_, type, std::move(entry));
  return SRESULT::Ok;
}

SRESULT EventBus::set_spill_sink(SpillSink sink) {
  std::lock_guard lock(spill_mu_);
  spill_ = std::move(sink);
  return SRESULT::Ok;
}

SRESULT EventBus::post(std::shared_ptr<const Event> ev) {
  if (!ev) return SRESULT::NullPointer;
  std::string_view name;
  HS_RETURN_IF_FAILED(ev->type_name(name));
  std::shared_ptr<detail::TypeSlot> slot;
  const Event& ref = *ev;  // typeid on a plain reference: dynamic type, no side-effect warning
  HS_RETURN_IF_FAILED(slot_for(std::type_index(typeid(ref)), name, slot));
  slot->posted.fetch_add(1, std::memory_order_relaxed);

  std::vector<std::shared_ptr<detail::SubscriberEntry>> subs;
  {
    std::shared_lock lock(registry_->mu);
    subs = slot->subs;  // copy: handlers may (un)subscribe concurrently
  }
  if (subs.empty()) return SRESULT::NoOp;

  bool any_dropped = false;
  bool spilled = false;
  bool lost = false;
  for (const auto& entry : subs) {
    auto mb = entry->mailbox.lock();
    if (!mb) continue;
    Task task = [entry, ev]() -> SRESULT {
      if (!entry->active.load(std::memory_order_acquire)) return SRESULT::NoOp;
      return entry->handler(ev);
    };
    SRESULT r = mb->push(ev->hdr.cls, ev->hdr.overflow, task);
    if (r == SRESULT::CapacityExceeded) {
      // Never-drop lane full. Sanitized envelopes go to the spool; everything else is force-queued.
      if (ev->hdr.spillable && !spilled) {
        SpillSink sink;
        {
          std::lock_guard lock(spill_mu_);
          sink = spill_;
        }
        if (sink && HS_SUCCEEDED(sink(ev))) {
          spilled = true;
          slot->spilled.fetch_add(1, std::memory_order_relaxed);
          continue;
        }
      }
      r = mb->force_push(ev->hdr.cls, task);
      if (r == SRESULT::Ok) {
        slot->forced.fetch_add(1, std::memory_order_relaxed);
        slot->delivered.fetch_add(1, std::memory_order_relaxed);
        continue;
      }
    }
    switch (r) {
      case SRESULT::Ok:
        slot->delivered.fetch_add(1, std::memory_order_relaxed);
        break;
      case SRESULT::Dropped:
        // DropOldest still delivered the new event (an older one was evicted); Sample discarded it.
        any_dropped = true;
        slot->dropped.fetch_add(1, std::memory_order_relaxed);
        if (ev->hdr.overflow == OverflowPolicy::DropOldest) slot->delivered.fetch_add(1, std::memory_order_relaxed);
        break;
      case SRESULT::Closed:
        break;  // subscriber is shutting down
      default: {
        lost = true;
        slot->lost.fetch_add(1, std::memory_order_relaxed);
        std::string owner;
        (void)mb->name(owner);
        HS_TRACE_ERROR(kComponent, "never-drop {} id={} refused by {}: {}", name, ev->hdr.id, owner, r);
        break;
      }
    }
  }
  if (lost) return SRESULT::CapacityExceeded;
  if (spilled) return SRESULT::Spilled;
  if (any_dropped) return SRESULT::Dropped;
  return SRESULT::Ok;
}

SRESULT EventBus::stats(std::vector<TypeStats>& out) const {
  out.clear();
  std::shared_lock lock(registry_->mu);
  for (const auto& [type, slot] : registry_->slots) {
    TypeStats s;
    s.type = slot->name;
    s.subscribers = slot->subs.size();
    s.posted = slot->posted.load(std::memory_order_relaxed);
    s.delivered = slot->delivered.load(std::memory_order_relaxed);
    s.dropped = slot->dropped.load(std::memory_order_relaxed);
    s.spilled = slot->spilled.load(std::memory_order_relaxed);
    s.forced = slot->forced.load(std::memory_order_relaxed);
    s.lost = slot->lost.load(std::memory_order_relaxed);
    out.push_back(std::move(s));
  }
  std::sort(out.begin(), out.end(), [](const TypeStats& a, const TypeStats& b) { return a.type < b.type; });
  return SRESULT::Ok;
}

}  // namespace ieso
