/**
 * @file mailbox.cpp
 * @brief Mailbox implementation.
 */
#include "ieso/core/mailbox.hpp"

namespace ieso {

Mailbox::Mailbox(std::string name, MailboxCapacities caps)
    : name_(std::move(name)),
      lanes_{BoundedQueue<Task>(caps.control), BoundedQueue<Task>(caps.incident), BoundedQueue<Task>(caps.routine)} {}

SRESULT Mailbox::push(EventClass lane, OverflowPolicy policy, Task& task) {
  const auto idx = static_cast<std::size_t>(lane);
  if (idx >= lanes_.size()) return SRESULT::InvalidArgument;
  SRESULT r = SRESULT::Ok;
  {
    std::lock_guard lock(mu_);
    if (closed_) return SRESULT::Closed;
    r = lanes_[idx].push(task, policy);
  }
  if (HS_SUCCEEDED(r)) cv_.notify_one();
  return r;
}

SRESULT Mailbox::force_push(EventClass lane, Task& task) {
  const auto idx = static_cast<std::size_t>(lane);
  if (idx >= lanes_.size()) return SRESULT::InvalidArgument;
  SRESULT r = SRESULT::Ok;
  {
    std::lock_guard lock(mu_);
    if (closed_) return SRESULT::Closed;
    std::size_t cap = 0;
    HS_RETURN_IF_FAILED(lanes_[idx].capacity(cap));
    r = lanes_[idx].force_push(task, cap * config::kNeverDropHardMultiplier);
  }
  if (HS_SUCCEEDED(r)) cv_.notify_one();
  return r;
}

SRESULT Mailbox::pop_wait(Task& out) {
  std::unique_lock lock(mu_);
  for (;;) {
    for (auto& lane : lanes_) {
      if (lane.pop(out) == SRESULT::Ok) return SRESULT::Ok;
    }
    if (closed_) return SRESULT::Closed;
    cv_.wait(lock, [this] {
      bool any = closed_;
      for (const auto& lane : lanes_) {
        bool e = true;
        (void)lane.empty(e);  // always Ok
        any = any || !e;
      }
      return any;
    });
  }
}

SRESULT Mailbox::close() {
  {
    std::lock_guard lock(mu_);
    closed_ = true;
  }
  cv_.notify_all();
  return SRESULT::Ok;
}

SRESULT Mailbox::stats(MailboxStats& out) const {
  std::lock_guard lock(mu_);
  HS_RETURN_IF_FAILED(lanes_[0].stats(out.control));
  HS_RETURN_IF_FAILED(lanes_[1].stats(out.incident));
  return lanes_[2].stats(out.routine);
}

SRESULT Mailbox::name(std::string& out) const {
  out = name_;
  return SRESULT::Ok;
}

}  // namespace ieso
