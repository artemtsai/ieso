/**
 * @file flight_recorder.cpp
 * @brief Bucket aggregation and FlightRecorder implementation.
 */
#include <algorithm>
#include <cmath>

#include "ieso/core/binary_io.hpp"
#include "ieso/core/ring.hpp"
#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "recorder";
constexpr std::string_view kMagic = "HSFR";
constexpr std::uint16_t kCheckpointVersion = 1;
constexpr std::int64_t kWarmWindowMs = static_cast<std::int64_t>(config::kWarmSlots) * config::kWarmBucketMs;
constexpr std::int64_t kColdWindowMs = static_cast<std::int64_t>(config::kColdSlots) * config::kColdBucketMs;
constexpr std::int64_t kMaxClockSkewMs = 5 * 60 * 1000;  // checkpoint newer than now + this = clock went back

/// @brief Writes one sample. @param[in,out] o Buffer. @param[in] s Sample. @return SRESULT::Ok.
SRESULT put_sample(std::string& o, const ResourceSample& s) {
  HS_RETURN_IF_FAILED(bin::put_i64(o, s.ts_ms));
  HS_RETURN_IF_FAILED(bin::put_i64(o, s.pid));
  HS_RETURN_IF_FAILED(bin::put_f64(o, s.cpu_pct));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint64_t>(o, s.rss_bytes));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint32_t>(o, s.threads));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint32_t>(o, s.fds));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint64_t>(o, s.disk_free_bytes));
  return bin::put_i64(o, s.thermal_level);
}

/// @brief Reads one sample. @param[in,out] r Reader. @param[out] s Sample. @return Ok or CorruptData.
SRESULT get_sample(bin::Reader& r, ResourceSample& s) {
  std::int64_t thermal = 0;
  HS_RETURN_IF_FAILED(r.i64(s.ts_ms));
  HS_RETURN_IF_FAILED(r.i64(s.pid));
  HS_RETURN_IF_FAILED(r.f64(s.cpu_pct));
  HS_RETURN_IF_FAILED(r.le(s.rss_bytes));
  HS_RETURN_IF_FAILED(r.le(s.threads));
  HS_RETURN_IF_FAILED(r.le(s.fds));
  HS_RETURN_IF_FAILED(r.le(s.disk_free_bytes));
  HS_RETURN_IF_FAILED(r.i64(thermal));
  s.thermal_level = static_cast<std::int32_t>(thermal);
  return SRESULT::Ok;
}

/// @brief Writes one aggregate. @param[in,out] o Buffer. @param[in] a Aggregate. @return SRESULT::Ok.
SRESULT put_aggregate(std::string& o, const AggregateSample& a) {
  HS_RETURN_IF_FAILED(bin::put_i64(o, a.start_ms));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint32_t>(o, a.count));
  HS_RETURN_IF_FAILED(put_sample(o, a.min));
  HS_RETURN_IF_FAILED(put_sample(o, a.max));
  return put_sample(o, a.avg);
}

/// @brief Reads one aggregate. @param[in,out] r Reader. @param[out] a Aggregate. @return Ok or CorruptData.
SRESULT get_aggregate(bin::Reader& r, AggregateSample& a) {
  HS_RETURN_IF_FAILED(r.i64(a.start_ms));
  HS_RETURN_IF_FAILED(r.le(a.count));
  HS_RETURN_IF_FAILED(get_sample(r, a.min));
  HS_RETURN_IF_FAILED(get_sample(r, a.max));
  return get_sample(r, a.avg);
}

/// @brief Writes an open bucket. @param[in,out] o Buffer. @param[in] b Bucket. @return SRESULT::Ok.
SRESULT put_bucket(std::string& o, const BucketAccumulator& b) {
  HS_RETURN_IF_FAILED(bin::put_i64(o, b.start_ms));
  HS_RETURN_IF_FAILED(bin::put_i64(o, b.pid));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint32_t>(o, b.count));
  HS_RETURN_IF_FAILED(put_sample(o, b.min));
  HS_RETURN_IF_FAILED(put_sample(o, b.max));
  for (const double v : {b.sum_cpu, b.sum_rss, b.sum_threads, b.sum_fds, b.sum_disk, b.sum_thermal}) {
    HS_RETURN_IF_FAILED(bin::put_f64(o, v));
  }
  return SRESULT::Ok;
}

/// @brief Reads an open bucket. @param[in,out] r Reader. @param[out] b Bucket. @return Ok or CorruptData.
SRESULT get_bucket(bin::Reader& r, BucketAccumulator& b) {
  HS_RETURN_IF_FAILED(r.i64(b.start_ms));
  HS_RETURN_IF_FAILED(r.i64(b.pid));
  HS_RETURN_IF_FAILED(r.le(b.count));
  HS_RETURN_IF_FAILED(get_sample(r, b.min));
  HS_RETURN_IF_FAILED(get_sample(r, b.max));
  HS_RETURN_IF_FAILED(r.f64(b.sum_cpu));
  HS_RETURN_IF_FAILED(r.f64(b.sum_rss));
  HS_RETURN_IF_FAILED(r.f64(b.sum_threads));
  HS_RETURN_IF_FAILED(r.f64(b.sum_fds));
  HS_RETURN_IF_FAILED(r.f64(b.sum_disk));
  return r.f64(b.sum_thermal);
}

/**
 * @brief Floors a timestamp to its bucket start.
 * @param[in] ts_ms Timestamp.
 * @param[in] width_ms Bucket width.
 * @param[out] out Bucket start.
 * @return SRESULT::Ok.
 */
SRESULT bucket_of(std::int64_t ts_ms, std::int64_t width_ms, std::int64_t& out) {
  std::int64_t q = ts_ms / width_ms;
  if (ts_ms < 0 && ts_ms % width_ms != 0) --q;
  out = q * width_ms;
  return SRESULT::Ok;
}
}  // namespace

SRESULT BucketAccumulator::add(const ResourceSample& s) {
  if (count == 0) {
    pid = s.pid;
    min = s;
    max = s;
  } else {
    min.cpu_pct = std::min(min.cpu_pct, s.cpu_pct);
    max.cpu_pct = std::max(max.cpu_pct, s.cpu_pct);
    min.rss_bytes = std::min(min.rss_bytes, s.rss_bytes);
    max.rss_bytes = std::max(max.rss_bytes, s.rss_bytes);
    min.threads = std::min(min.threads, s.threads);
    max.threads = std::max(max.threads, s.threads);
    min.fds = std::min(min.fds, s.fds);
    max.fds = std::max(max.fds, s.fds);
    min.disk_free_bytes = std::min(min.disk_free_bytes, s.disk_free_bytes);
    max.disk_free_bytes = std::max(max.disk_free_bytes, s.disk_free_bytes);
    min.thermal_level = std::min(min.thermal_level, s.thermal_level);
    max.thermal_level = std::max(max.thermal_level, s.thermal_level);
    max.ts_ms = s.ts_ms;
  }
  ++count;
  sum_cpu += s.cpu_pct;
  sum_rss += static_cast<double>(s.rss_bytes);
  sum_threads += s.threads;
  sum_fds += s.fds;
  sum_disk += static_cast<double>(s.disk_free_bytes);
  sum_thermal += s.thermal_level;
  return SRESULT::Ok;
}

SRESULT BucketAccumulator::take(AggregateSample& out) {
  if (count == 0) return SRESULT::NotFound;
  const double n = count;
  out.start_ms = start_ms;
  out.count = count;
  out.min = min;
  out.max = max;
  out.avg.ts_ms = start_ms;
  out.avg.pid = pid;
  out.min.pid = pid;
  out.max.pid = pid;
  out.avg.cpu_pct = sum_cpu / n;
  out.avg.rss_bytes = static_cast<std::uint64_t>(std::llround(sum_rss / n));
  out.avg.threads = static_cast<std::uint32_t>(std::lround(sum_threads / n));
  out.avg.fds = static_cast<std::uint32_t>(std::lround(sum_fds / n));
  out.avg.disk_free_bytes = static_cast<std::uint64_t>(std::llround(sum_disk / n));
  out.avg.thermal_level = static_cast<std::int32_t>(std::lround(sum_thermal / n));
  *this = BucketAccumulator{};
  return SRESULT::Ok;
}

SRESULT FlightRecorder::Create(std::unique_ptr<FlightRecorder>& out) {
  out = std::make_unique<FlightRecorder>();
  return SRESULT::Ok;
}

SRESULT FlightRecorder::ingest(const ResourceSample& s) {
  if (s.ts_ms < last_ts_ms_) {
    HS_TRACE_WARNING(kComponent, "sample out of order: ts={} last={}", s.ts_ms, last_ts_ms_);
    return SRESULT::InvalidArgument;
  }
  last_ts_ms_ = s.ts_ms;
  (void)hot_.push(s);  // Dropped just means the hot window rolled over

  std::int64_t sec = 0;
  std::int64_t minute = 0;
  HS_RETURN_IF_FAILED(bucket_of(s.ts_ms, config::kWarmBucketMs, sec));
  HS_RETURN_IF_FAILED(bucket_of(s.ts_ms, config::kColdBucketMs, minute));

  // A new bucket starts on a time boundary or when the target process changed (restart): never mix pids.
  if (warm_acc_.start_ms != sec || (warm_acc_.count != 0 && warm_acc_.pid != s.pid)) {
    AggregateSample done;
    if (warm_acc_.take(done) == SRESULT::Ok) {
      done.avg.ts_ms = done.start_ms;
      (void)warm_.push(done.avg);
    }
    warm_acc_.start_ms = sec;
  }
  HS_RETURN_IF_FAILED(warm_acc_.add(s));

  if (cold_acc_.start_ms != minute || (cold_acc_.count != 0 && cold_acc_.pid != s.pid)) {
    AggregateSample done;
    if (cold_acc_.take(done) == SRESULT::Ok) (void)cold_.push(done);
    cold_acc_.start_ms = minute;
  }
  return cold_acc_.add(s);
}

SRESULT FlightRecorder::freeze(std::int64_t now_ms, FrozenRings& out) const {
  out.frozen_at_ms = now_ms;
  HS_RETURN_IF_FAILED(hot_.snapshot(out.hot));
  HS_RETURN_IF_FAILED(warm_.snapshot(out.warm));
  HS_RETURN_IF_FAILED(cold_.snapshot(out.cold));
  HS_TRACE_INFO(kComponent, "rings frozen: hot={} warm={} cold={}", out.hot.size(), out.warm.size(), out.cold.size());
  return SRESULT::Ok;
}

SRESULT FlightRecorder::checkpoint(std::int64_t now_ms, std::string& out) const {
  std::vector<ResourceSample> warm;
  std::vector<AggregateSample> cold;
  HS_RETURN_IF_FAILED(warm_.snapshot(warm));
  HS_RETURN_IF_FAILED(cold_.snapshot(cold));
  out.clear();
  out.reserve(64 + warm.size() * 52 + cold.size() * 168);
  out.append(kMagic);
  HS_RETURN_IF_FAILED(bin::put_le<std::uint16_t>(out, kCheckpointVersion));
  HS_RETURN_IF_FAILED(bin::put_i64(out, now_ms));
  HS_RETURN_IF_FAILED(bin::put_i64(out, last_ts_ms_));
  HS_RETURN_IF_FAILED(put_bucket(out, warm_acc_));
  HS_RETURN_IF_FAILED(put_bucket(out, cold_acc_));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint32_t>(out, static_cast<std::uint32_t>(warm.size())));
  for (const auto& w : warm) HS_RETURN_IF_FAILED(put_sample(out, w));
  HS_RETURN_IF_FAILED(bin::put_le<std::uint32_t>(out, static_cast<std::uint32_t>(cold.size())));
  for (const auto& c : cold) HS_RETURN_IF_FAILED(put_aggregate(out, c));
  std::uint32_t crc = 0;
  HS_RETURN_IF_FAILED(bin::crc32(out, crc));
  return bin::put_le<std::uint32_t>(out, crc);
}

SRESULT FlightRecorder::restore(std::string_view data, std::int64_t now_ms, RestoreStats& out) {
  std::size_t hot = 0, warm_n = 0, cold_n = 0;
  HS_RETURN_IF_FAILED(hot_.size(hot));
  HS_RETURN_IF_FAILED(warm_.size(warm_n));
  HS_RETURN_IF_FAILED(cold_.size(cold_n));
  if (hot + warm_n + cold_n != 0 || last_ts_ms_ != INT64_MIN) return SRESULT::InvalidState;
  if (data.size() < kMagic.size() + 2 + 4 || data.substr(0, kMagic.size()) != kMagic) return SRESULT::CorruptData;
  std::uint32_t expect = 0, crc = 0;
  HS_RETURN_IF_FAILED(bin::crc32(data.substr(0, data.size() - 4), expect));
  bin::Reader tail{data, data.size() - 4};
  HS_RETURN_IF_FAILED(tail.le(crc));
  if (crc != expect) return SRESULT::CorruptData;

  bin::Reader r{data.substr(0, data.size() - 4), kMagic.size()};
  std::uint16_t version = 0;
  HS_RETURN_IF_FAILED(r.le(version));
  if (version != kCheckpointVersion) return SRESULT::Unsupported;
  std::int64_t saved_at = 0, last_ts = 0;
  HS_RETURN_IF_FAILED(r.i64(saved_at));
  HS_RETURN_IF_FAILED(r.i64(last_ts));
  if (saved_at > now_ms + kMaxClockSkewMs) {
    HS_TRACE_WARNING(kComponent, "checkpoint saved at {} is in the future (now {}): clock skew, not restored", saved_at,
                     now_ms);
    return SRESULT::InvalidState;
  }
  BucketAccumulator wacc, cacc;
  HS_RETURN_IF_FAILED(get_bucket(r, wacc));
  HS_RETURN_IF_FAILED(get_bucket(r, cacc));

  RestoreStats st;
  std::uint32_t n = 0;
  HS_RETURN_IF_FAILED(r.le(n));
  std::vector<ResourceSample> warm(n);
  for (auto& w : warm) HS_RETURN_IF_FAILED(get_sample(r, w));
  HS_RETURN_IF_FAILED(r.le(n));
  std::vector<AggregateSample> cold(n);
  for (auto& c : cold) HS_RETURN_IF_FAILED(get_aggregate(r, c));
  if (r.pos != r.data.size()) return SRESULT::CorruptData;

  // Rebuild oldest-first; the open buckets were the newest entries, so close them last.
  for (const auto& w : warm) {
    if (w.ts_ms >= now_ms - kWarmWindowMs) {
      (void)warm_.push(w);  // fits: at most kWarmSlots entries were saved
      ++st.warm;
    } else {
      ++st.dropped_old;
    }
  }
  AggregateSample closed;
  if (wacc.take(closed) == SRESULT::Ok && closed.start_ms >= now_ms - kWarmWindowMs) {
    closed.avg.ts_ms = closed.start_ms;
    (void)warm_.push(closed.avg);  // may evict the oldest entry: ring semantics
    ++st.warm;
  }
  for (const auto& c : cold) {
    if (c.start_ms >= now_ms - kColdWindowMs) {
      (void)cold_.push(c);
      ++st.cold;
    } else {
      ++st.dropped_old;
    }
  }
  if (cacc.take(closed) == SRESULT::Ok && closed.start_ms >= now_ms - kColdWindowMs) {
    (void)cold_.push(closed);
    ++st.cold;
  }
  // Gap markers: the timeline must never interpolate across the time the sensor was down.
  ResourceSample gap;
  gap.ts_ms = now_ms;
  gap.pid = kGapMarkerPid;
  if (st.warm != 0) (void)warm_.push(gap);
  if (st.cold != 0) {
    AggregateSample g;
    g.start_ms = now_ms;
    g.count = 0;
    g.min = gap;
    g.max = gap;
    g.avg = gap;
    (void)cold_.push(g);
  }
  const bool had_data = last_ts != INT64_MIN;
  last_ts_ms_ = had_data ? std::max(last_ts, now_ms) : INT64_MIN;
  st.gap_from_ms = had_data ? last_ts : now_ms;
  st.gap_to_ms = now_ms;
  out = st;
  HS_TRACE_INFO(kComponent, "restored flight recorder: warm={} cold={} dropped_old={} gap={} s", st.warm, st.cold,
                st.dropped_old, (st.gap_to_ms - st.gap_from_ms) / 1000);
  return SRESULT::Ok;
}

}  // namespace ieso
