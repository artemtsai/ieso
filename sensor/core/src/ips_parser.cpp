/**
 * @file ips_parser.cpp
 * @brief .ips header/body extraction.
 */
#include "ieso/core/ips_parser.hpp"

#include <cstdio>
#include <memory>
#include <string>

#include "ieso/core/json_reader.hpp"

namespace ieso {
namespace {

/**
 * @brief Reads an optional string member (missing is not an error).
 * @param[in] obj Object.
 * @param[in] key Member.
 * @param[out] out Value or unchanged.
 * @return SRESULT::Ok.
 */
SRESULT opt_string(const JsonValue& obj, std::string_view key, std::string& out) {
  std::string v;
  if (obj.get_string(key, v) == SRESULT::Ok) out = std::move(v);
  return SRESULT::Ok;
}

/**
 * @brief Resolves one frame's image name: usedImages[imageIndex].name, else the path's basename.
 * @param[in] images usedImages array.
 * @param[in] frame Frame object.
 * @param[out] out Frame receiving image and offset.
 * @return SRESULT::Ok, or NotFound if the structure is missing.
 */
SRESULT resolve_frame(const JsonValue& images, const JsonValue& frame, CrashFrame& out) {
  std::int64_t image_idx = 0;
  std::shared_ptr<const JsonValue> image;
  HS_RETURN_IF_FAILED(frame.get_int("imageIndex", image_idx));
  HS_RETURN_IF_FAILED(frame.get_int("imageOffset", out.offset));
  HS_RETURN_IF_FAILED(images.at(static_cast<std::size_t>(image_idx), image));
  if (image->get_string("name", out.image) != SRESULT::Ok) {
    std::string path;
    HS_RETURN_IF_FAILED(image->get_string("path", path));
    const auto slash = path.find_last_of('/');
    out.image = slash == std::string::npos ? path : path.substr(slash + 1);
  }
  HS_RETURN_IF_FAILED(opt_string(frame, "symbol", out.symbol));
  (void)frame.get_int("symbolLocation", out.symbol_location);  // optional: absent without symbols
  return SRESULT::Ok;
}

/**
 * @brief Reads the crashed thread: threads[faultingThread] -> top frames, its queue/name, faulting module + offset.
 * @param[in] body Body object.
 * @param[in,out] out Report receiving faulting module, offset, crashed_thread and backtrace.
 * @return SRESULT::Ok, or NotFound if the structure is missing.
 * @note Bounded loop over at most kMaxCrashFrames frames.
 */
SRESULT crashed_thread(const JsonValue& body, CrashReport& out) {
  std::int64_t thread_idx = 0;
  if (body.get_int("faultingThread", thread_idx) != SRESULT::Ok) thread_idx = 0;
  std::shared_ptr<const JsonValue> threads, thread, frames, images;
  HS_RETURN_IF_FAILED(body.get("threads", threads));
  HS_RETURN_IF_FAILED(threads->at(static_cast<std::size_t>(thread_idx), thread));
  std::string label;
  HS_RETURN_IF_FAILED(opt_string(*thread, "name", label));
  HS_RETURN_IF_FAILED(opt_string(*thread, "queue", label));  // the queue is more telling than the name
  out.crashed_thread = std::to_string(thread_idx) + (label.empty() ? "" : " (" + label + ")");
  HS_RETURN_IF_FAILED(thread->get("frames", frames));
  HS_RETURN_IF_FAILED(body.get("usedImages", images));
  std::size_t n = 0;
  HS_RETURN_IF_FAILED(frames->size(n));
  for (std::size_t i = 0; i < n && i < kMaxCrashFrames; ++i) {
    std::shared_ptr<const JsonValue> frame;
    CrashFrame f;
    if (frames->at(i, frame) != SRESULT::Ok || resolve_frame(*images, *frame, f) != SRESULT::Ok) break;
    out.backtrace.push_back(std::move(f));
  }
  if (out.backtrace.empty()) return SRESULT::NotFound;
  out.faulting_module = out.backtrace.front().image;
  out.offset = out.backtrace.front().offset;
  return SRESULT::Ok;
}

/**
 * @brief Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's days_from_civil).
 * @param[in] y Year. @param[in] m Month 1..12. @param[in] d Day 1..31.
 * @param[out] out Days since the epoch.
 * @return SRESULT::Ok.
 */
SRESULT days_from_civil(std::int64_t y, unsigned m, unsigned d, std::int64_t& out) {
  y -= m <= 2 ? 1 : 0;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const auto yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  out = era * 146097 + static_cast<std::int64_t>(doe) - 719468;
  return SRESULT::Ok;
}

}  // namespace

SRESULT parse_ips_timestamp(std::string_view text, std::int64_t& out_ms) {
  const std::string t(text);  // NUL-terminated copy for sscanf (C API boundary)
  int y = 0, mo = 0, d = 0, h = 0, mi = 0, sec = 0;
  if (std::sscanf(t.c_str(), "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &sec) != 6 || mo < 1 || mo > 12 || d < 1 ||
      d > 31 || h > 23 || mi > 59 || sec > 60) {
    return SRESULT::CorruptData;
  }
  std::int64_t offset_s = 0;  // trailing "+HHMM" / "-HHMM", if any
  const auto sp = t.find_last_of(' ');
  if (sp != std::string::npos && sp + 5 < t.size() + 1 && (t[sp + 1] == '+' || t[sp + 1] == '-')) {
    int hhmm = 0;
    if (std::sscanf(t.c_str() + sp + 2, "%4d", &hhmm) == 1) {
      offset_s = (hhmm / 100) * 3600 + (hhmm % 100) * 60;
      if (t[sp + 1] == '-') offset_s = -offset_s;
    }
  }
  std::int64_t days = 0;
  HS_RETURN_IF_FAILED(days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d), days));
  out_ms = ((days * 86400) + h * 3600 + mi * 60 + sec - offset_s) * 1000;
  return SRESULT::Ok;
}

SRESULT parse_ips(std::string_view text, CrashReport& out) {
  const auto nl = text.find('\n');
  if (nl == std::string_view::npos) return SRESULT::CorruptData;
  std::shared_ptr<const JsonValue> header, body;
  if (HS_FAILED(JsonValue::Parse(text.substr(0, nl), header))) return SRESULT::CorruptData;
  if (HS_FAILED(JsonValue::Parse(text.substr(nl + 1), body))) return SRESULT::CorruptData;

  CrashReport r;
  HS_RETURN_IF_FAILED(opt_string(*header, "bug_type", r.bug_type));
  if (r.bug_type != "309") return SRESULT::Unsupported;
  HS_RETURN_IF_FAILED(opt_string(*header, "incident_id", r.incident_id));
  std::string ts;
  HS_RETURN_IF_FAILED(opt_string(*header, "timestamp", ts));
  if (!ts.empty()) (void)parse_ips_timestamp(ts, r.timestamp_ms);  // unknown format: 0, freshness not checked
  HS_RETURN_IF_FAILED(opt_string(*header, "os_version", r.os_version));
  HS_RETURN_IF_FAILED(opt_string(*header, "app_version", r.app_version));
  HS_RETURN_IF_FAILED(opt_string(*header, "bundleID", r.bundle_id));
  HS_RETURN_IF_FAILED(opt_string(*header, "app_name", r.proc_name));

  HS_RETURN_IF_FAILED(opt_string(*body, "procName", r.proc_name));
  (void)body->get_int("pid", r.pid);  // optional
  std::shared_ptr<const JsonValue> bundle, exc, term;
  if (body->get("bundleInfo", bundle) == SRESULT::Ok) {
    HS_RETURN_IF_FAILED(opt_string(*bundle, "CFBundleIdentifier", r.bundle_id));
    HS_RETURN_IF_FAILED(opt_string(*bundle, "CFBundleShortVersionString", r.app_version));
  }
  if (body->get("exception", exc) == SRESULT::Ok) {
    HS_RETURN_IF_FAILED(opt_string(*exc, "type", r.exception_type));
    HS_RETURN_IF_FAILED(opt_string(*exc, "signal", r.signal));
    HS_RETURN_IF_FAILED(opt_string(*exc, "subtype", r.exception_subtype));
    HS_RETURN_IF_FAILED(opt_string(*exc, "codes", r.exception_codes));
  }
  if (body->get("termination", term) == SRESULT::Ok) {
    std::string ns, indicator;
    HS_RETURN_IF_FAILED(opt_string(*term, "namespace", ns));
    HS_RETURN_IF_FAILED(opt_string(*term, "indicator", indicator));
    r.termination_reason = ns.empty() ? indicator : ns + ": " + indicator;
  }
  (void)crashed_thread(*body, r);  // best-effort: reports without frames still count as crashes
  out = std::move(r);
  return SRESULT::Ok;
}

}  // namespace ieso
