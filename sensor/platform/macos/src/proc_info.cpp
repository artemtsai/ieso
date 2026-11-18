/**
 * @file proc_info.cpp
 * @brief libproc, sysctl, statfs and CFBundle helpers.
 */
#include "ieso/macos/proc_info.hpp"

#include <libproc.h>
#include <mach/mach_time.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>

#include <array>
#include <cerrno>

#include "ieso/macos/cf_ref.hpp"

namespace ieso::macos {

SRESULT to_utf8(CFStringRef s, std::string& out) {
  if (s == nullptr) return SRESULT::NullPointer;
  const CFIndex len = CFStringGetLength(s);
  const CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
  std::string buf(static_cast<std::size_t>(max), '\0');
  if (!CFStringGetCString(s, buf.data(), max, kCFStringEncodingUTF8)) return SRESULT::CorruptData;
  buf.resize(std::char_traits<char>::length(buf.c_str()));
  out = std::move(buf);
  return SRESULT::Ok;
}

SRESULT list_pids(std::vector<pid_t>& out) {
  const int n = proc_listallpids(nullptr, 0);
  if (n <= 0) return SRESULT::IoError;
  std::vector<pid_t> pids(static_cast<std::size_t>(n) + 64);
  const int got = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
  if (got <= 0) return SRESULT::IoError;
  pids.resize(static_cast<std::size_t>(got));
  out = std::move(pids);
  return SRESULT::Ok;
}

SRESULT pid_path(pid_t pid, std::string& out) {
  std::array<char, PROC_PIDPATHINFO_MAXSIZE> buf{};
  const int n = proc_pidpath(pid, buf.data(), static_cast<std::uint32_t>(buf.size()));
  if (n <= 0) return SRESULT::NotFound;
  out.assign(buf.data(), static_cast<std::size_t>(n));
  return SRESULT::Ok;
}

SRESULT find_target(const std::string& name, pid_t& pid, std::string& exe) {
  std::vector<pid_t> pids;
  HS_RETURN_IF_FAILED(list_pids(pids));
  const std::string in_bundle = "/" + name + ".app/Contents/MacOS/";
  pid_t best = 0;
  std::string best_path;
  for (const pid_t p : pids) {
    if (p <= 0) continue;
    std::string path;
    if (pid_path(p, path) != SRESULT::Ok) continue;
    const auto slash = path.find_last_of('/');
    const std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
    if ((path.find(in_bundle) != std::string::npos || base == name) && p > best) {
      best = p;  // newest pid wins if several instances run
      best_path = path;
    }
  }
  if (best == 0) return SRESULT::NotFound;
  pid = best;
  exe = best_path;
  return SRESULT::Ok;
}

SRESULT bundle_info(const std::string& exe, std::string& bundle_id, std::string& version) {
  const auto pos = exe.find(".app/Contents/MacOS/");
  if (pos == std::string::npos) return SRESULT::NotFound;
  const std::string app = exe.substr(0, pos + 4);
  CfRef<CFURLRef> url(CFURLCreateFromFileSystemRepresentation(
      kCFAllocatorDefault, reinterpret_cast<const UInt8*>(app.c_str()), static_cast<CFIndex>(app.size()), true));
  if (!url) return SRESULT::NotFound;
  CfRef<CFBundleRef> bundle(CFBundleCreate(kCFAllocatorDefault, *url));
  if (!bundle) return SRESULT::NotFound;
  if (const CFStringRef id = CFBundleGetIdentifier(*bundle)) (void)to_utf8(id, bundle_id);  // +0, borrowed
  const CFTypeRef v = CFBundleGetValueForInfoDictionaryKey(*bundle, CFSTR("CFBundleShortVersionString"));
  if (v != nullptr && CFGetTypeID(v) == CFStringGetTypeID()) {
    (void)to_utf8(static_cast<CFStringRef>(v), version);  // optional key
  }
  return SRESULT::Ok;
}

SRESULT task_info(pid_t pid, TaskInfo& out) {
  proc_taskinfo ti{};
  const int n = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof(ti));
  if (n != static_cast<int>(sizeof(ti))) return errno == EPERM ? SRESULT::PermissionDenied : SRESULT::NotFound;
  static const mach_timebase_info_data_t tb = [] {  // thread-safe one-time init
    mach_timebase_info_data_t t{};
    (void)mach_timebase_info(&t);  // cannot fail on macOS
    return t;
  }();
  const std::uint64_t ticks = ti.pti_total_user + ti.pti_total_system;  // mach time units on Apple silicon
  out.cpu_ns = ticks * tb.numer / tb.denom;
  out.rss_bytes = ti.pti_resident_size;
  out.threads = static_cast<std::uint32_t>(ti.pti_threadnum);
  return SRESULT::Ok;
}

SRESULT fd_count(pid_t pid, std::uint32_t& out) {
  const int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
  if (bytes <= 0) return SRESULT::NotFound;
  out = static_cast<std::uint32_t>(static_cast<std::size_t>(bytes) / sizeof(proc_fdinfo));
  return SRESULT::Ok;
}

SRESULT disk_free(const std::string& path, std::uint64_t& out) {
  struct statfs st {};
  if (statfs(path.c_str(), &st) != 0) return SRESULT::IoError;
  out = static_cast<std::uint64_t>(st.f_bavail) * st.f_bsize;
  return SRESULT::Ok;
}

SRESULT sysctl_string(const char* name, std::string& out) {
  std::size_t len = 0;
  if (sysctlbyname(name, nullptr, &len, nullptr, 0) != 0 || len == 0) return SRESULT::NotFound;
  std::string buf(len, '\0');
  if (sysctlbyname(name, buf.data(), &len, nullptr, 0) != 0) return SRESULT::NotFound;
  buf.resize(std::char_traits<char>::length(buf.c_str()));
  out = std::move(buf);
  return SRESULT::Ok;
}

}  // namespace ieso::macos
