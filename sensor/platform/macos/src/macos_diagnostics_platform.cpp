/**
 * @file macos_diagnostics_platform.cpp
 * @brief MacosDiagnosticsPlatform implementation.
 */
#include "ieso/macos/macos_diagnostics_platform.hpp"

#include <CFNetwork/CFNetwork.h>
#include <curl/curl.h>
#include <unistd.h>

#include <fstream>
#include <iterator>

#include <fmt/format.h>

#include "ieso/core/json.hpp"
#include "ieso/core/trace.hpp"
#include "ieso/macos/cf_ref.hpp"
#include "ieso/macos/proc_info.hpp"
#include "ieso/macos/subprocess.hpp"

namespace ieso::macos {
namespace {
constexpr std::string_view kComponent = "diag-macos";
constexpr std::size_t kMaxCaptureBytes = 4u << 20;  // stacks of a big app fit easily
constexpr std::size_t kMaxProbeOutput = 8u << 10;   // NFR-10: probe outputs are small and bounded

/// @brief RAII deleter for CURL handles (functor: exempt from the SRESULT rule).
struct CurlEasyDeleter {
  void operator()(CURL* h) const { curl_easy_cleanup(h); }
};

/**
 * @brief libcurl debug callback (C API signature; exempt). Captures "SSL connection using TLSv1.x".
 * @return 0.
 */
int on_probe_debug(CURL* /*h*/, curl_infotype type, char* data, size_t size, void* user) {
  if (type != CURLINFO_TEXT) return 0;
  const std::string_view text(data, size);
  constexpr std::string_view kPrefix = "SSL connection using ";
  if (text.compare(0, kPrefix.size(), kPrefix) != 0) return 0;
  const std::string_view rest = text.substr(kPrefix.size());
  static_cast<std::string*>(user)->assign(rest.substr(0, rest.find_first_of(" /\r\n")));
  return 0;
}

/// @brief libcurl write callback that discards the body (C API signature; exempt). @return Bytes consumed.
size_t on_probe_discard(char* /*data*/, size_t size, size_t n, void* /*user*/) { return size * n; }

/// @brief One TLS path observation of net.synthetic_tls.
struct TlsObservation {
  std::string verify_error;   ///< Empty if the chain verified against the system trust store.
  std::string tls_version;    ///< Negotiated protocol.
  long http_status = 0;       ///< HTTP status (chain-capture attempt).
  std::vector<std::pair<std::string, std::string>> chain;  ///< (subject, issuer), leaf first.
  std::string error;          ///< Transport error of the chain-capture attempt.
};

/**
 * @brief Connects to @p url (optionally via @p proxy) twice: once verifying with system trust, once capturing the chain.
 * @param[in] url Target.
 * @param[in] proxy Proxy URL, or "" for a direct connection.
 * @param[in] connect_to Direct path only: libcurl CONNECT_TO entry "host:port:addr:port" ("" = normal DNS).
 * @param[out] out Observation.
 * @return SRESULT::Ok or Internal.
 */
SRESULT observe_tls(const std::string& url, const std::string& proxy, const std::string& connect_to,
                    TlsObservation& out) {
  for (int attempt = 0; attempt < 2; ++attempt) {
    std::unique_ptr<CURL, CurlEasyDeleter> h(curl_easy_init());
    if (!h) return SRESULT::Internal;
    std::string version;
    curl_easy_setopt(h.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(h.get(), CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(h.get(), CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(h.get(), CURLOPT_CONNECTTIMEOUT_MS, 4000L);
    curl_easy_setopt(h.get(), CURLOPT_TIMEOUT_MS, 6000L);
    curl_easy_setopt(h.get(), CURLOPT_WRITEFUNCTION, &on_probe_discard);
    curl_easy_setopt(h.get(), CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(h.get(), CURLOPT_DEBUGFUNCTION, &on_probe_debug);
    curl_easy_setopt(h.get(), CURLOPT_DEBUGDATA, &version);
    std::unique_ptr<curl_slist, void (*)(curl_slist*)> connect(nullptr, &curl_slist_free_all);
    if (proxy.empty()) {
      curl_easy_setopt(h.get(), CURLOPT_NOPROXY, "*");
      if (!connect_to.empty()) {
        connect.reset(curl_slist_append(nullptr, connect_to.c_str()));
        curl_easy_setopt(h.get(), CURLOPT_CONNECT_TO, connect.get());
      }
    } else {
      curl_easy_setopt(h.get(), CURLOPT_PROXY, proxy.c_str());
    }
    const bool capture = attempt == 1;
    if (capture) {  // diagnosis only: read whatever chain the path presents, without trusting it
      curl_easy_setopt(h.get(), CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(h.get(), CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(h.get(), CURLOPT_CERTINFO, 1L);
    }
    const CURLcode rc = curl_easy_perform(h.get());
    if (!capture) {
      out.verify_error = rc == CURLE_OK ? "" : curl_easy_strerror(rc);
      continue;
    }
    out.tls_version = version;
    if (rc != CURLE_OK) out.error = curl_easy_strerror(rc);
    curl_easy_getinfo(h.get(), CURLINFO_RESPONSE_CODE, &out.http_status);
    curl_certinfo* ci = nullptr;  // owned by the handle; read before cleanup
    if (curl_easy_getinfo(h.get(), CURLINFO_CERTINFO, &ci) == CURLE_OK && ci != nullptr) {
      for (int i = 0; i < ci->num_of_certs; ++i) {
        std::string subject, issuer;
        for (curl_slist* e = ci->certinfo[i]; e != nullptr; e = e->next) {  // C list owned by libcurl
          const std::string_view line(e->data);
          if (line.compare(0, 8, "Subject:") == 0) subject.assign(line.substr(8));
          if (line.compare(0, 7, "Issuer:") == 0) issuer.assign(line.substr(7));
        }
        out.chain.emplace_back(std::move(subject), std::move(issuer));
      }
    }
  }
  return SRESULT::Ok;
}

/**
 * @brief Appends a capped excerpt of a command's output.
 * @param[in] argv Command.
 * @param[in] title Section title.
 * @param[in,out] out Text.
 * @return SRESULT::Ok.
 */
SRESULT append_command(const std::vector<std::string>& argv, const std::string& title, std::string& out) {
  std::string text;
  int code = 0;
  const SRESULT r = Subprocess::Run(argv, std::chrono::seconds(10), text, code);
  out += "== " + title + " (exit " + std::to_string(HS_SUCCEEDED(r) ? code : -1) + ")\n" + text + "\n";
  return SRESULT::Ok;
}
}  // namespace

MacosDiagnosticsPlatform::MacosDiagnosticsPlatform(std::filesystem::path scratch_dir, ProbeConfig probes)
    : scratch_(std::move(scratch_dir)), probes_(std::move(probes)) {}

SRESULT MacosDiagnosticsPlatform::effective_proxy(std::string& out) {
  out.clear();
  if (!probes_.demo_proxy.empty()) {
    out = probes_.demo_proxy;
    return SRESULT::Ok;
  }
  CfRef<CFDictionaryRef> settings(CFNetworkCopySystemProxySettings());
  if (!settings) return SRESULT::Ok;
  const auto enabled = static_cast<CFNumberRef>(CFDictionaryGetValue(*settings, kCFNetworkProxiesHTTPSEnable));
  const auto host = static_cast<CFStringRef>(CFDictionaryGetValue(*settings, kCFNetworkProxiesHTTPSProxy));
  const auto port = static_cast<CFNumberRef>(CFDictionaryGetValue(*settings, kCFNetworkProxiesHTTPSPort));
  int on = 0, p = 0;
  if (enabled != nullptr) CFNumberGetValue(enabled, kCFNumberIntType, &on);
  if (port != nullptr) CFNumberGetValue(port, kCFNumberIntType, &p);
  std::string h;
  if (on != 0 && host != nullptr && to_utf8(host, h) == SRESULT::Ok && !h.empty()) {
    out = "http://" + h + ":" + std::to_string(p);
  }
  return SRESULT::Ok;
}

SRESULT MacosDiagnosticsPlatform::probe_net_config(std::string& out) {
  std::string proxy;
  HS_RETURN_IF_FAILED(effective_proxy(proxy));
  out = "effective_https_proxy: " + (proxy.empty() ? std::string("none") : proxy) +
        (probes_.demo_proxy.empty() ? "" : "  (demo override standing in for the system proxy settings)") + "\n";
  HS_RETURN_IF_FAILED(append_command({"/usr/sbin/scutil", "--proxy"}, "scutil --proxy", out));
  return append_command({"/usr/sbin/scutil", "--dns"}, "scutil --dns", out);
}

SRESULT MacosDiagnosticsPlatform::probe_synthetic_tls(std::string& out) {
  if (probes_.app_backend_url.empty()) return SRESULT::InvalidState;
  std::string proxy;
  HS_RETURN_IF_FAILED(effective_proxy(proxy));
  JsonWriter w;
  HS_RETURN_IF_FAILED(w.begin_object());
  HS_RETURN_IF_FAILED(w.key("target"));
  HS_RETURN_IF_FAILED(w.value(std::string_view(probes_.app_backend_url)));
  HS_RETURN_IF_FAILED(w.key("paths"));
  HS_RETURN_IF_FAILED(w.begin_array());
  const std::vector<std::pair<std::string, std::string>> paths = {{"via_proxy", proxy}, {"direct", ""}};
  for (const auto& [name, via] : paths) {
    if (name == "via_proxy" && via.empty()) continue;  // no proxy configured: only the direct path exists
    TlsObservation o;
    std::string connect_to;
    if (via.empty() && !probes_.direct_address.empty()) {  // "app-backend:9443:localhost:9443"
      const auto scheme = probes_.app_backend_url.find("://");
      const std::string rest = scheme == std::string::npos ? probes_.app_backend_url : probes_.app_backend_url.substr(scheme + 3);
      connect_to = rest.substr(0, rest.find('/')) + ":" + probes_.direct_address;
    }
    HS_RETURN_IF_FAILED(observe_tls(probes_.app_backend_url, via, connect_to, o));
    HS_RETURN_IF_FAILED(w.begin_object());
    HS_RETURN_IF_FAILED(w.key("path"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(name)));
    HS_RETURN_IF_FAILED(w.key("proxy"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(via)));
    HS_RETURN_IF_FAILED(w.key("verify_error_system_trust"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(o.verify_error)));
    HS_RETURN_IF_FAILED(w.key("tls_version"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(o.tls_version)));
    HS_RETURN_IF_FAILED(w.key("http_status"));
    HS_RETURN_IF_FAILED(w.value(static_cast<std::int64_t>(o.http_status)));
    HS_RETURN_IF_FAILED(w.key("error"));
    HS_RETURN_IF_FAILED(w.value(std::string_view(o.error)));
    HS_RETURN_IF_FAILED(w.key("chain"));
    HS_RETURN_IF_FAILED(w.begin_array());
    for (const auto& [subject, issuer] : o.chain) {
      HS_RETURN_IF_FAILED(w.begin_object());
      HS_RETURN_IF_FAILED(w.key("subject"));
      HS_RETURN_IF_FAILED(w.value(std::string_view(subject)));
      HS_RETURN_IF_FAILED(w.key("issuer"));
      HS_RETURN_IF_FAILED(w.value(std::string_view(issuer)));
      HS_RETURN_IF_FAILED(w.end_object());
    }
    HS_RETURN_IF_FAILED(w.end_array());
    HS_RETURN_IF_FAILED(w.end_object());
  }
  HS_RETURN_IF_FAILED(w.end_array());
  HS_RETURN_IF_FAILED(w.end_object());
  return w.str(out);
}

SRESULT MacosDiagnosticsPlatform::run_probe(const std::string& probe_id, std::string& output,
                                            std::int64_t& exit_status) {
  output.clear();
  exit_status = 0;
  SRESULT r = SRESULT::Ok;
  if (probe_id == "net.config") {
    r = probe_net_config(output);
  } else if (probe_id == "net.synthetic_tls") {
    r = probe_synthetic_tls(output);
  } else if (probe_id == "env.extensions") {
    r = append_command({"/usr/bin/systemextensionsctl", "list"}, "systemextensionsctl list", output);
  } else if (probe_id == "svc.launchctl") {
    const std::string label = probes_.launchctl_label.empty() ? "com.ieso.demoapp.helper" : probes_.launchctl_label;
    r = append_command({"/bin/launchctl", "print", "gui/" + std::to_string(getuid()) + "/" + label},
                       "launchctl print " + label, output);
  } else {
    return SRESULT::Unsupported;  // never reached: the actor checks the allowlist first
  }
  if (output.size() > kMaxProbeOutput) {
    output.resize(kMaxProbeOutput);
    output += "\n...[truncated at 8 KB]";
  }
  if (HS_FAILED(r)) exit_status = 1;
  return r;
}

SRESULT MacosDiagnosticsPlatform::capture_stacks(std::int64_t pid, std::chrono::seconds duration, std::string& out) {
  std::error_code ec;
  std::filesystem::create_directories(scratch_, ec);
  const auto file = scratch_ / fmt::format("sample-{}.txt", pid);
  std::string output;
  int code = 0;
  const SRESULT r = Subprocess::Run({"/usr/bin/sample", std::to_string(pid), std::to_string(duration.count()),
                                     "-mayDie", "-file", file.string()},
                                    duration + std::chrono::seconds(20), output, code);
  if (HS_FAILED(r)) return r;
  std::ifstream f(file, std::ios::binary);
  if (code != 0 || !f.is_open()) {
    HS_TRACE_WARNING(kComponent, "sample pid {} failed (exit {}): {}", pid, code, output.substr(0, 200));
    return output.find("ermission") != std::string::npos ? SRESULT::PermissionDenied : SRESULT::IoError;
  }
  out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  if (out.size() > kMaxCaptureBytes) out.resize(kMaxCaptureBytes);
  f.close();
  std::filesystem::remove(file, ec);
  return SRESULT::Ok;
}

SRESULT MacosDiagnosticsPlatform::set_log_mode(const std::string& subsystem, const std::string& mode) {
  if (geteuid() != 0) return SRESULT::PermissionDenied;  // never trigger an auth prompt on the user's screen
  std::string output;
  int code = 0;
  HS_RETURN_IF_FAILED(Subprocess::Run({"/usr/bin/log", "config", "--subsystem", subsystem, "--mode", mode},
                                      std::chrono::seconds(10), output, code));
  return code == 0 ? SRESULT::Ok : SRESULT::PermissionDenied;
}

SRESULT MacosDiagnosticsPlatform::reset_log_mode(const std::string& subsystem) {
  if (geteuid() != 0) return SRESULT::PermissionDenied;
  std::string output;
  int code = 0;
  HS_RETURN_IF_FAILED(Subprocess::Run({"/usr/bin/log", "config", "--subsystem", subsystem, "--reset"},
                                      std::chrono::seconds(10), output, code));
  return code == 0 ? SRESULT::Ok : SRESULT::PermissionDenied;
}

SRESULT MacosDiagnosticsPlatform::environment(Fields& out) {
  struct Key {
    const char* sysctl;  ///< sysctl name.
    const char* field;   ///< Output key.
  };
  const Key keys[] = {{"kern.osproductversion", "os_version"},
                      {"kern.osversion", "os_build"},
                      {"hw.model", "hardware_model"},
                      {"hw.machine", "arch"}};
  for (const auto& k : keys) {
    std::string v;
    if (sysctl_string(k.sysctl, v) == SRESULT::Ok) out.push_back({k.field, FieldValue{v}, false});
  }
  out.push_back({"sensor_euid_root", FieldValue{geteuid() == 0}, false});
  return SRESULT::Ok;
}

}  // namespace ieso::macos
