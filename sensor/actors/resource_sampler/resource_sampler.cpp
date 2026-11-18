/**
 * @file resource_sampler.cpp
 * @brief ResourceSamplerActor implementation.
 */
#include "resource_sampler/resource_sampler.hpp"

#include "ieso/core/runtime.hpp"
#include "ieso/core/time_util.hpp"
#include "ieso/core/trace.hpp"
#include "ieso/macos/proc_info.hpp"

namespace ieso::macos {

ResourceSamplerActor::ResourceSamplerActor(EventBus& bus, EventFactory& factory, const IClock& clock,
                                           SamplerOptions opts)
    : Actor("resource_sampler"), bus_(bus), factory_(factory), clock_(clock), opts_(std::move(opts)) {}

SRESULT ResourceSamplerActor::on_start(ActorContext& ctx) {
  HS_RETURN_IF_FAILED(subscribe<TargetLifecycle>(ctx.bus, [this](const auto& e) {
    pid_ = e->phase == "launch" ? static_cast<pid_t>(e->pid) : 0;
    last_cpu_ns_ = 0;
    last_wall_ns_ = 0;
    count_ = 0;
    return SRESULT::Ok;
  }));
  TimerId id = 0;
  return ctx.runtime.schedule_every(shared_from_this(), opts_.period, [this] { return tick(); }, id);
}

SRESULT ResourceSamplerActor::tick() {
  if (pid_ == 0) return SRESULT::NoOp;
  TaskInfo ti;
  if (task_info(pid_, ti) != SRESULT::Ok) return SRESULT::NoOp;  // exiting; lifecycle event follows

  std::chrono::steady_clock::time_point steady;
  std::chrono::system_clock::time_point wall;
  HS_RETURN_IF_FAILED(clock_.now_steady(steady));
  HS_RETURN_IF_FAILED(clock_.now_system(wall));
  const std::int64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(steady.time_since_epoch()).count();

  ResourceSample s;
  s.pid = pid_;
  HS_RETURN_IF_FAILED(to_unix_ms(wall, s.ts_ms));
  if (last_wall_ns_ != 0 && now_ns > last_wall_ns_ && ti.cpu_ns >= last_cpu_ns_) {
    s.cpu_pct = 100.0 * static_cast<double>(ti.cpu_ns - last_cpu_ns_) / static_cast<double>(now_ns - last_wall_ns_);
  }
  last_cpu_ns_ = ti.cpu_ns;
  last_wall_ns_ = now_ns;
  s.rss_bytes = ti.rss_bytes;
  s.threads = ti.threads;
  (void)fd_count(pid_, s.fds);  // 0 if the process is exiting
  const bool snapshot = (count_++ % opts_.snapshot_every) == 0;
  if (snapshot) (void)disk_free(opts_.disk_path, disk_free_);  // keep last value on error
  s.disk_free_bytes = disk_free_;

  std::shared_ptr<ResourceSampled> hot;
  HS_RETURN_IF_FAILED(factory_.make<ResourceSampled>(hot));
  hot->pid = pid_;
  hot->sample = s;
  HS_RETURN_IF_FAILED(bus_.post(std::move(hot)));
  if (!snapshot) return SRESULT::Ok;

  std::shared_ptr<TelemetrySnapshotCaptured> snap;
  HS_RETURN_IF_FAILED(factory_.make<TelemetrySnapshotCaptured>(snap));
  snap->pid = pid_;
  snap->sample = s;
  return bus_.post(std::move(snap));
}

}  // namespace ieso::macos
