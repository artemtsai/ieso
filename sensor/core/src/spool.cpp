/**
 * @file spool.cpp
 * @brief Spool record format, crash-safe file I/O and index maintenance.
 * @details Record (little endian): "HSP1" | u8 ver | u8 cls | u8 overflow | u8 codec | u32 attempts |
 *          i64 enqueue_ms | i64 event_ts_ms | str id | str endpoint | str source | str type | str payload | u32 crc32.
 *          str = u32 length + bytes. CRC covers everything before it.
 */
#include "ieso/core/spool.hpp"

#include "ieso/core/binary_io.hpp"

#include <fstream>
#include <iterator>

#include <fmt/format.h>

#include "ieso/core/time_util.hpp"
#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "spool";
constexpr std::string_view kMagic = "HSP1";
constexpr std::uint8_t kVersion = 1;
constexpr std::string_view kExt = ".rec";
constexpr std::string_view kTmpExt = ".tmp";

using bin::crc32;
using bin::put_le;
using bin::put_str;
using bin::Reader;

/**
 * @brief Checks whether @p s ends with @p suffix (C++17 has no ends_with).
 * @param[in] s Text.
 * @param[in] suffix Suffix.
 * @param[out] out Result.
 * @return SRESULT::Ok.
 */
SRESULT ends_with(std::string_view s, std::string_view suffix, bool& out) {
  out = s.size() >= suffix.size() && s.substr(s.size() - suffix.size()) == suffix;
  return SRESULT::Ok;
}

}  // namespace

Spool::Spool(SpoolOptions opts, const IClock& clock, std::shared_ptr<const ICodec> codec)
    : opts_(std::move(opts)), clock_(clock), codec_(std::move(codec)) {}

SRESULT Spool::Create(const SpoolOptions& opts, const IClock& clock, std::shared_ptr<const ICodec> codec,
                      std::unique_ptr<Spool>& out) {
  if (opts.dir.empty() || !codec || opts.max_bytes == 0 || opts.max_bytes > config::kSpoolHardCapBytes) {
    HS_TRACE_ERROR(kComponent, "invalid spool options (dir='{}', max_bytes={})", opts.dir.string(), opts.max_bytes);
    return SRESULT::InvalidArgument;
  }
  auto spool = std::make_unique<Spool>(opts, clock, std::move(codec));
  HS_RETURN_IF_FAILED(spool->open());
  out = std::move(spool);
  return SRESULT::Ok;
}

SRESULT Spool::open() {
  std::error_code ec;
  std::filesystem::create_directories(opts_.dir, ec);
  if (ec) {
    HS_TRACE_ERROR(kComponent, "cannot create spool dir '{}': {}", opts_.dir.string(), ec.message());
    return SRESULT::IoError;
  }
  std::filesystem::directory_iterator it(opts_.dir, ec);
  if (ec) {
    HS_TRACE_ERROR(kComponent, "cannot list spool dir '{}': {}", opts_.dir.string(), ec.message());
    return SRESULT::IoError;
  }
  std::vector<std::string> names;
  for (const std::filesystem::directory_iterator end; it != end; it.increment(ec)) {
    if (ec) return SRESULT::IoError;
    names.push_back(it->path().filename().string());
  }
  for (const std::string& name : names) {
    bool is_tmp = false;
    bool is_rec = false;
    HS_RETURN_IF_FAILED(ends_with(name, kTmpExt, is_tmp));
    HS_RETURN_IF_FAILED(ends_with(name, kExt, is_rec));
    if (is_tmp) {  // interrupted write; the rename never happened
      std::filesystem::remove(opts_.dir / name, ec);
      continue;
    }
    if (!is_rec) continue;
    std::string data;
    SpoolItem item;
    Entry entry;
    if (HS_FAILED(read_file(name, data)) || HS_FAILED(decode_record(data, item, entry))) {
      HS_TRACE_WARNING(kComponent, "dropping corrupt spool record {}", name);
      std::filesystem::remove(opts_.dir / name, ec);
      ++counters_.corrupt;
      continue;
    }
    file_by_id_[entry.id] = name;
    bytes_ += entry.size;
    by_file_[name] = std::move(entry);
  }
  HS_TRACE_INFO(kComponent, "spool open: dir='{}' records={} bytes={}", opts_.dir.string(), by_file_.size(), bytes_);
  return SRESULT::Ok;
}

SRESULT Spool::encode_record(const CloudEventSanitized& env, std::uint32_t attempts, std::int64_t enqueue_ms,
                             std::string& out) const {
  std::uint8_t codec_id = 0;
  HS_RETURN_IF_FAILED(codec_->id(codec_id));
  std::string payload;
  HS_RETURN_IF_FAILED(codec_->encode(env.data_json, payload));
  std::int64_t ts_ms = 0;
  HS_RETURN_IF_FAILED(to_unix_ms(env.hdr.ts, ts_ms));
  out.clear();
  out.append(kMagic);
  HS_RETURN_IF_FAILED(put_le<std::uint8_t>(out, kVersion));
  HS_RETURN_IF_FAILED(put_le<std::uint8_t>(out, static_cast<std::uint8_t>(env.hdr.cls)));
  HS_RETURN_IF_FAILED(put_le<std::uint8_t>(out, static_cast<std::uint8_t>(env.hdr.overflow)));
  HS_RETURN_IF_FAILED(put_le<std::uint8_t>(out, codec_id));
  HS_RETURN_IF_FAILED(put_le<std::uint32_t>(out, attempts));
  HS_RETURN_IF_FAILED(put_le<std::uint64_t>(out, static_cast<std::uint64_t>(enqueue_ms)));
  HS_RETURN_IF_FAILED(put_le<std::uint64_t>(out, static_cast<std::uint64_t>(ts_ms)));
  HS_RETURN_IF_FAILED(put_str(out, env.hdr.id));
  HS_RETURN_IF_FAILED(put_str(out, env.hdr.endpoint_id));
  HS_RETURN_IF_FAILED(put_str(out, env.source));
  HS_RETURN_IF_FAILED(put_str(out, env.type));
  HS_RETURN_IF_FAILED(put_str(out, payload));
  std::uint32_t crc = 0;
  HS_RETURN_IF_FAILED(crc32(out, crc));
  return put_le<std::uint32_t>(out, crc);
}

SRESULT Spool::decode_record(const std::string& data, SpoolItem& item, Entry& entry) const {
  if (data.size() < kMagic.size() + 4 || std::string_view(data).substr(0, kMagic.size()) != kMagic) {
    return SRESULT::CorruptData;
  }
  std::uint32_t expect = 0;
  HS_RETURN_IF_FAILED(crc32(std::string_view(data).substr(0, data.size() - 4), expect));
  Reader tail{std::string_view(data), data.size() - 4};
  std::uint32_t crc = 0;
  HS_RETURN_IF_FAILED(tail.le(crc));
  if (crc != expect) return SRESULT::CorruptData;

  Reader r{std::string_view(data).substr(0, data.size() - 4), kMagic.size()};
  std::uint8_t ver = 0, cls = 0, ovf = 0, codec_id = 0, my_codec = 0;
  std::uint32_t attempts = 0;
  std::uint64_t enqueue_ms = 0, ts_ms = 0;
  std::string id, endpoint, source, type, payload, data_json;
  HS_RETURN_IF_FAILED(r.le(ver));
  HS_RETURN_IF_FAILED(r.le(cls));
  HS_RETURN_IF_FAILED(r.le(ovf));
  HS_RETURN_IF_FAILED(r.le(codec_id));
  HS_RETURN_IF_FAILED(r.le(attempts));
  HS_RETURN_IF_FAILED(r.le(enqueue_ms));
  HS_RETURN_IF_FAILED(r.le(ts_ms));
  HS_RETURN_IF_FAILED(r.str(id));
  HS_RETURN_IF_FAILED(r.str(endpoint));
  HS_RETURN_IF_FAILED(r.str(source));
  HS_RETURN_IF_FAILED(r.str(type));
  HS_RETURN_IF_FAILED(r.str(payload));
  HS_RETURN_IF_FAILED(codec_->id(my_codec));
  if (ver != kVersion || cls > 2 || ovf > 2 || codec_id != my_codec || r.pos != r.data.size() || id.empty()) {
    return SRESULT::CorruptData;
  }
  if (HS_FAILED(codec_->decode(payload, data_json))) return SRESULT::CorruptData;

  // Spool is a friend of the passkey: it restores envelopes that were sanitized before being written.
  auto env = std::make_shared<CloudEventSanitized>(CloudEventSanitized::Key{}, std::move(source), std::move(type),
                                                   std::move(data_json));
  env->hdr.id = id;
  env->hdr.endpoint_id = std::move(endpoint);
  HS_RETURN_IF_FAILED(from_unix_ms(static_cast<std::int64_t>(ts_ms), env->hdr.ts));
  env->hdr.cls = static_cast<EventClass>(cls);
  env->hdr.overflow = static_cast<OverflowPolicy>(ovf);
  env->hdr.egress = false;
  env->hdr.spillable = true;

  item.envelope = std::move(env);
  item.attempts = attempts;
  entry.id = std::move(id);
  entry.cls = static_cast<EventClass>(cls);
  entry.enqueue_ms = static_cast<std::int64_t>(enqueue_ms);
  entry.size = data.size();
  entry.in_flight = false;
  return SRESULT::Ok;
}

SRESULT Spool::write_file(const std::string& file, const std::string& data) {
  const auto final_path = opts_.dir / file;
  auto tmp_path = final_path;
  tmp_path += std::string(kTmpExt);
  {
    std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    f.flush();
    if (!f.good()) {
      HS_TRACE_ERROR(kComponent, "write failed: {}", tmp_path.string());
      std::error_code ec;
      std::filesystem::remove(tmp_path, ec);
      return SRESULT::IoError;
    }
  }
  std::error_code ec;
  std::filesystem::rename(tmp_path, final_path, ec);
  if (ec) {
    HS_TRACE_ERROR(kComponent, "rename failed {}: {}", final_path.string(), ec.message());
    std::filesystem::remove(tmp_path, ec);
    return SRESULT::IoError;
  }
  return SRESULT::Ok;
}

SRESULT Spool::read_file(const std::string& file, std::string& out) const {
  std::ifstream f(opts_.dir / file, std::ios::binary);
  if (!f.is_open()) return SRESULT::IoError;
  out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  return f.bad() ? SRESULT::IoError : SRESULT::Ok;
}

SRESULT Spool::remove(const std::string& file) {
  const auto it = by_file_.find(file);
  if (it == by_file_.end()) return SRESULT::NotFound;
  std::error_code ec;
  std::filesystem::remove(opts_.dir / file, ec);
  if (ec) HS_TRACE_WARNING(kComponent, "remove failed {}: {}", file, ec.message());
  bytes_ -= it->second.size;
  file_by_id_.erase(it->second.id);
  by_file_.erase(it);
  return SRESULT::Ok;
}

SRESULT Spool::make_room(std::uint64_t needed, const std::string& keep) {
  while (bytes_ + needed > opts_.max_bytes) {
    std::string victim;
    for (const auto& [file, e] : by_file_) {  // prio-1 files sort last; take the oldest routine one
      if (e.cls == EventClass::Routine && file != keep) {
        victim = file;
        break;
      }
    }
    if (victim.empty()) return SRESULT::CapacityExceeded;
    HS_RETURN_IF_FAILED(remove(victim));
    ++counters_.evicted;
  }
  return SRESULT::Ok;
}

SRESULT Spool::put(const CloudEventSanitized& env, std::uint32_t attempts) {
  if (env.hdr.id.empty()) return SRESULT::InvalidArgument;
  const auto existing = file_by_id_.find(env.hdr.id);
  std::string file;
  std::int64_t enqueue_ms = 0;
  std::uint64_t old_size = 0;
  if (existing != file_by_id_.end()) {
    file = existing->second;
    const Entry& e = by_file_[file];
    enqueue_ms = e.enqueue_ms;  // keep original age for TTL and order
    old_size = e.size;
  } else {
    std::chrono::system_clock::time_point now;
    HS_RETURN_IF_FAILED(clock_.now_system(now));
    HS_RETURN_IF_FAILED(to_unix_ms(now, enqueue_ms));
    const int prio = env.hdr.cls == EventClass::Routine ? 1 : 0;
    file = fmt::format("{}_{:016}_{}{}", prio, enqueue_ms, env.hdr.id, kExt);
  }

  std::string record;
  HS_RETURN_IF_FAILED(encode_record(env, attempts, enqueue_ms, record));
  if (record.size() > old_size) {
    const SRESULT room = make_room(record.size() - old_size, file);
    if (HS_FAILED(room)) {
      if (env.hdr.cls == EventClass::Routine) {
        HS_TRACE_WARNING(kComponent, "spool full ({} bytes); routine {} not stored", bytes_, env.hdr.id);
      } else {
        HS_TRACE_ERROR(kComponent, "spool full ({} bytes) of incidents; {} not stored", bytes_, env.hdr.id);
      }
      return room;
    }
  }
  HS_RETURN_IF_FAILED(write_file(file, record));

  Entry& e = by_file_[file];
  bytes_ = bytes_ - old_size + record.size();
  e.id = env.hdr.id;
  e.cls = env.hdr.cls;
  e.enqueue_ms = enqueue_ms;
  e.size = record.size();
  e.in_flight = false;
  file_by_id_[env.hdr.id] = file;
  HS_TRACE_DEBUG(kComponent, "spooled {} attempts={} ({} bytes total)", env.hdr.id, attempts, bytes_);
  return SRESULT::Ok;
}

SRESULT Spool::drain(std::size_t max, std::vector<SpoolItem>& out) {
  out.clear();
  std::vector<std::string> corrupt;
  for (auto& [file, e] : by_file_) {
    if (out.size() >= max) break;
    if (e.in_flight) continue;
    std::string data;
    SpoolItem item;
    Entry parsed;
    if (HS_FAILED(read_file(file, data)) || HS_FAILED(decode_record(data, item, parsed))) {
      corrupt.push_back(file);
      continue;
    }
    e.in_flight = true;
    out.push_back(std::move(item));
  }
  for (const std::string& file : corrupt) {
    HS_TRACE_WARNING(kComponent, "dropping unreadable spool record {}", file);
    HS_RETURN_IF_FAILED(remove(file));
    ++counters_.corrupt;
  }
  return out.empty() ? SRESULT::NoOp : SRESULT::Ok;
}

SRESULT Spool::ack(const std::string& id) {
  const auto it = file_by_id_.find(id);
  if (it == file_by_id_.end()) return SRESULT::NotFound;
  const std::string file = it->second;
  return remove(file);
}

SRESULT Spool::release_in_flight() {
  for (auto& [file, e] : by_file_) e.in_flight = false;
  return SRESULT::Ok;
}

SRESULT Spool::purge_expired(std::size_t& purged) {
  purged = 0;
  std::chrono::system_clock::time_point now_tp;
  HS_RETURN_IF_FAILED(clock_.now_system(now_tp));
  std::int64_t now = 0;
  HS_RETURN_IF_FAILED(to_unix_ms(now_tp, now));
  std::vector<std::string> expired;
  for (const auto& [file, e] : by_file_) {
    const auto ttl = e.cls == EventClass::Routine ? opts_.ttl_routine : opts_.ttl_incident;
    if (now - e.enqueue_ms > static_cast<std::int64_t>(ttl.count())) expired.push_back(file);
  }
  for (const std::string& file : expired) HS_RETURN_IF_FAILED(remove(file));
  purged = expired.size();
  counters_.purged += purged;
  if (purged > 0) HS_TRACE_INFO(kComponent, "purged {} expired spool records", purged);
  return SRESULT::Ok;
}

SRESULT Spool::stats(SpoolStats& out) const {
  out = counters_;
  out.bytes = bytes_;
  out.count = by_file_.size();
  out.in_flight = 0;
  out.oldest_enqueue_ms = 0;
  for (const auto& [file, e] : by_file_) {
    if (e.in_flight) ++out.in_flight;
    if (out.oldest_enqueue_ms == 0 || e.enqueue_ms < out.oldest_enqueue_ms) out.oldest_enqueue_ms = e.enqueue_ms;
  }
  return SRESULT::Ok;
}

}  // namespace ieso
