/**
 * @file runtime.cpp
 * @brief Actor and Runtime implementation.
 */
#include "ieso/core/runtime.hpp"

#include <algorithm>

#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "runtime";
}  // namespace

// ---------------- Actor ----------------

Actor::Actor(std::string name, MailboxCapacities caps)
    : name_(std::move(name)), mailbox_(std::make_shared<Mailbox>(name_, caps)) {}

SRESULT Actor::on_stop() { return unsubscribe_all(); }

SRESULT Actor::name(std::string& out) const {
  out = name_;
  return SRESULT::Ok;
}

SRESULT Actor::mailbox(std::shared_ptr<Mailbox>& out) const {
  out = mailbox_;
  return SRESULT::Ok;
}

SRESULT Actor::unsubscribe_all() {
  subs_.clear();  // token destructors unsubscribe
  return SRESULT::Ok;
}

SRESULT Actor::run() {
  HS_TRACE_DEBUG(kComponent, "actor {} thread started", name_);
  for (;;) {
    Task task;
    if (mailbox_->pop_wait(task) != SRESULT::Ok) break;  // Closed: drained and stopping
    const SRESULT r = task();
    if (HS_FAILED(r)) HS_TRACE_WARNING(kComponent, "actor {} task failed: {}", name_, r);
  }
  const SRESULT r = on_stop();
  HS_TRACE_DEBUG(kComponent, "actor {} stopped: {}", name_, r);
  return r;
}

// ---------------- Runtime ----------------

Runtime::Runtime(EventBus& bus) : bus_(bus) {}

Runtime::~Runtime() { (void)stop(); }

SRESULT Runtime::add(std::shared_ptr<Actor> actor) {
  if (!actor) return SRESULT::NullPointer;
  if (running_) return SRESULT::InvalidState;
  actors_.push_back(std::move(actor));
  return SRESULT::Ok;
}

SRESULT Runtime::start() {
  if (running_) return SRESULT::InvalidState;
  ActorContext ctx{bus_, *this};
  for (std::size_t i = 0; i < actors_.size(); ++i) {
    const SRESULT r = actors_[i]->on_start(ctx);
    if (HS_FAILED(r)) {
      std::string n;
      (void)actors_[i]->name(n);
      HS_TRACE_ERROR(kComponent, "actor {} failed to start: {}", n, r);
      for (std::size_t j = i + 1; j-- > 0;) (void)actors_[j]->on_stop();  // best-effort rollback
      return r;
    }
  }
  threads_.reserve(actors_.size());
  for (const auto& a : actors_) {
    threads_.emplace_back([a] { (void)a->run(); });  // run() traces its own outcome
  }
  {
    std::lock_guard lock(timer_mu_);
    stopping_ = false;
  }
  timer_thread_ = std::thread([this] { (void)timer_loop(); });  // always Ok
  running_ = true;
  HS_TRACE_INFO(kComponent, "runtime started with {} actors", actors_.size());
  return SRESULT::Ok;
}

SRESULT Runtime::stop_actors(std::size_t count) {
  for (std::size_t i = count; i-- > 0;) {
    std::shared_ptr<Mailbox> mb;
    HS_RETURN_IF_FAILED(actors_[i]->mailbox(mb));
    HS_RETURN_IF_FAILED(mb->close());
    if (i < threads_.size() && threads_[i].joinable()) threads_[i].join();
  }
  threads_.clear();
  return SRESULT::Ok;
}

SRESULT Runtime::stop() {
  if (!running_) return SRESULT::NoOp;
  if (timer_thread_.joinable()) {
    {
      std::lock_guard lock(timer_mu_);
      stopping_ = true;
    }
    timer_cv_.notify_all();
    timer_thread_.join();
  }
  HS_RETURN_IF_FAILED(stop_actors(actors_.size()));
  running_ = false;
  HS_TRACE_INFO(kComponent, "runtime stopped");
  return SRESULT::Ok;
}

SRESULT Runtime::schedule_every(const std::shared_ptr<Actor>& actor, std::chrono::milliseconds period, Task task,
                                TimerId& out) {
  if (!actor || !task || period.count() <= 0) return SRESULT::InvalidArgument;
  std::shared_ptr<Mailbox> mb;
  HS_RETURN_IF_FAILED(actor->mailbox(mb));
  Timer t;
  t.mailbox = mb;
  t.period = period;
  t.next = std::chrono::steady_clock::now() + period;
  t.task = std::make_shared<Task>(std::move(task));
  t.pending = std::make_shared<std::atomic<bool>>(false);
  {
    std::lock_guard lock(timer_mu_);
    t.id = next_timer_++;
    out = t.id;
    timers_.push_back(std::move(t));
    timers_changed_ = true;
  }
  timer_cv_.notify_all();
  return SRESULT::Ok;
}

SRESULT Runtime::cancel_timer(TimerId id) {
  std::lock_guard lock(timer_mu_);
  const auto before = timers_.size();
  timers_.erase(std::remove_if(timers_.begin(), timers_.end(), [id](const Timer& t) { return t.id == id; }), timers_.end());
  return timers_.size() == before ? SRESULT::NotFound : SRESULT::Ok;
}

SRESULT Runtime::timer_loop() {
  std::unique_lock lock(timer_mu_);
  while (!stopping_) {
    const auto now = std::chrono::steady_clock::now();
    auto next_deadline = now + std::chrono::seconds(1);
    for (auto& t : timers_) {
      if (t.next <= now) {
        t.next = now + t.period;
        auto mb = t.mailbox.lock();
        bool expected = false;
        if (mb && t.pending->compare_exchange_strong(expected, true)) {
          Task tick = [task = t.task, pending = t.pending]() -> SRESULT {
            pending->store(false);
            return (*task)();
          };
          if (HS_FAILED(mb->force_push(EventClass::Control, tick))) t.pending->store(false);  // closed/full: retry next period
        }
      }
      next_deadline = std::min(next_deadline, t.next);
    }
    timer_cv_.wait_until(lock, next_deadline, [this] { return timers_changed_ || stopping_; });
    timers_changed_ = false;
  }
  return SRESULT::Ok;
}

}  // namespace ieso
