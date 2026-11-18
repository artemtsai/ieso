/**
 * @file cloud_client.cpp
 * @brief Cloud Client actor and libcurl transport.
 */
#include "cloud_client/cloud_client.hpp"

#include <curl/curl.h>

#include <fstream>
#include <iterator>
#include <mutex>

#include "ieso/core/json_reader.hpp"
#include "ieso/core/runtime.hpp"
#include "ieso/core/sha256.hpp"
#include "ieso/core/trace.hpp"

namespace ieso {
namespace {
constexpr std::string_view kComponent = "cloud";
/// @brief The TLS 1.3 cipher suites (RFC 8446). Offering only these makes TLS 1.2 impossible to negotiate.
constexpr const char* kTls13Suites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
constexpr std::size_t kMaxResponse = 64u << 10;

/// @brief RAII deleter for CURL handles (functor: exempt from the SRESULT rule).
struct CurlEasyDeleter {
  void operator()(CURL* h) const { curl_easy_cleanup(h); }
};
/// @brief RAII deleter for curl header lists.
struct CurlListDeleter {
  void operator()(curl_slist* l) const { curl_slist_free_all(l); }
};

/**
 * @brief libcurl write callback (C API signature; exempt from the SRESULT rule).
 * @param[in] data Received bytes.
 * @param[in] size Element size.
 * @param[in] n Element count.
 * @param[in] user The std::string collecting the body.
 * @return Bytes consumed.
 */
size_t on_curl_write(char* data, size_t size, size_t n, void* user) {
  auto& body = *static_cast<std::string*>(user);  // set via CURLOPT_WRITEDATA
  const size_t len = size * n;
  if (body.size() < kMaxResponse) body.append(data, std::min(len, kMaxResponse - body.size()));
  return len;
}

/**
 * @brief libcurl debug callback (C API signature; exempt from the SRESULT rule). Records the negotiated TLS
 *        protocol from curl's "SSL connection using TLSv1.3 / ..." line.
 * @param[in] type Info type.
 * @param[in] data Text.
 * @param[in] size Length.
 * @param[in] user The std::string receiving the version.
 * @return 0 (required by libcurl).
 */
int on_curl_debug(CURL* /*h*/, curl_infotype type, char* data, size_t size, void* user) {
  if (type != CURLINFO_TEXT) return 0;
  const std::string_view text(data, size);
  constexpr std::string_view kPrefix = "SSL connection using ";
  if (text.compare(0, kPrefix.size(), kPrefix) != 0) return 0;
  const std::string_view rest = text.substr(kPrefix.size());
  auto& version = *static_cast<std::string*>(user);  // set via CURLOPT_DEBUGDATA
  version.assign(rest.substr(0, rest.find_first_of(" /\r\n")));
  return 0;
}

/**
 * @brief True for 2xx.
 * @param[in] status HTTP status.
 * @param[out] out Result.
 * @return SRESULT::Ok.
 */
SRESULT is_success(long status, bool& out) {
  out = status >= 200 && status < 300;
  return SRESULT::Ok;
}

/**
 * @brief True for failures worth retrying (transport errors, 408, 429, 5xx); other 4xx are permanent.
 * @param[in] status HTTP status.
 * @param[out] out Result.
 * @return SRESULT::Ok.
 */
SRESULT is_retriable(long status, bool& out) {
  out = status == 0 || status == 408 || status == 429 || status >= 500;
  return SRESULT::Ok;
}
}  // namespace

// ---------------- CurlTransport ----------------

CurlTransport::CurlTransport(TlsConfig tls, Tls13Policy policy) : tls_(std::move(tls)), policy_(policy) {}

SRESULT CurlTransport::Create(const TlsConfig& tls, std::unique_ptr<CurlTransport>& out) {
  std::error_code ec;
  if (!tls.ca_file.empty() && !std::filesystem::exists(tls.ca_file, ec)) {
    HS_TRACE_ERROR(kComponent, "CA file not found: {}", tls.ca_file);
    return SRESULT::NotFound;
  }
  if (!tls.client_p12.empty() && !std::filesystem::exists(tls.client_p12, ec)) {
    HS_TRACE_ERROR(kComponent, "client identity not found: {}", tls.client_p12);
    return SRESULT::NotFound;
  }
  static std::once_flag once;
  static CURLcode init = CURLE_OK;
  std::call_once(once, [] { init = curl_global_init(CURL_GLOBAL_DEFAULT); });
  if (init != CURLE_OK) return SRESULT::Internal;
  const curl_version_info_data* info = curl_version_info(CURLVERSION_NOW);  // static libcurl data, not owned
  const std::string backend = info != nullptr && info->ssl_version != nullptr ? info->ssl_version : "";
  Tls13Policy policy = Tls13Policy::MinMaxVersion;
  if (backend.find("LibreSSL") != std::string::npos) {
    policy = Tls13Policy::Tls13CiphersOnly;  // LibreSSL libcurl cannot set a minimum version
  } else if (backend.find("OpenSSL") == std::string::npos && backend.find("BoringSSL") == std::string::npos &&
             backend.find("wolfSSL") == std::string::npos && backend.find("quictls") == std::string::npos) {
    HS_TRACE_ERROR(kComponent, "libcurl TLS backend '{}' cannot be restricted to TLS 1.3: refusing (fail closed)",
                   backend);
    return SRESULT::Unsupported;
  }
  out = std::make_unique<CurlTransport>(tls, policy);
  HS_TRACE_INFO(kComponent, "libcurl {} ({}): TLS 1.3 only via {}, mTLS {}", info->version, backend,
                policy == Tls13Policy::Tls13CiphersOnly ? "TLS 1.3-only cipher suites" : "min/max version",
                tls.client_p12.empty() ? "off" : "on");
  return SRESULT::Ok;
}

SRESULT CurlTransport::request(const std::string& method, const std::string& url,
                               const std::vector<std::string>& headers, const std::string& body, HttpResponse& out) {
  if (url.compare(0, 8, "https://") != 0) return SRESULT::InvalidArgument;  // never plain HTTP
  std::unique_ptr<CURL, CurlEasyDeleter> h(curl_easy_init());
  if (!h) return SRESULT::Internal;
  std::unique_ptr<curl_slist, CurlListDeleter> list;
  for (const auto& hdr : headers) {
    curl_slist* grown = curl_slist_append(list.get(), hdr.c_str());  // C API: returns the (possibly new) head
    if (grown == nullptr) return SRESULT::OutOfMemory;                // old list still owned by `list`
    (void)list.release();
    list.reset(grown);
  }
  out = HttpResponse{};
  curl_easy_setopt(h.get(), CURLOPT_URL, url.c_str());
  curl_easy_setopt(h.get(), CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(h.get(), CURLOPT_PROTOCOLS_STR, "https");  // plain HTTP is never used
  // TLS 1.3 only. TLS 1.2 and older are refused; there is no fallback.
  if (policy_ == Tls13Policy::MinMaxVersion) {
    curl_easy_setopt(h.get(), CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_3 | CURL_SSLVERSION_MAX_TLSv1_3);
    curl_easy_setopt(h.get(), CURLOPT_TLS13_CIPHERS, kTls13Suites);
  } else {
    curl_easy_setopt(h.get(), CURLOPT_SSL_CIPHER_LIST, kTls13Suites);
  }
  curl_easy_setopt(h.get(), CURLOPT_VERBOSE, 1L);  // feeds on_curl_debug only (no stderr output)
  curl_easy_setopt(h.get(), CURLOPT_DEBUGFUNCTION, &on_curl_debug);
  curl_easy_setopt(h.get(), CURLOPT_DEBUGDATA, &out.tls_version);
  curl_easy_setopt(h.get(), CURLOPT_CONNECTTIMEOUT_MS, 3000L);
  curl_easy_setopt(h.get(), CURLOPT_TIMEOUT_MS, 10000L);
  curl_easy_setopt(h.get(), CURLOPT_WRITEFUNCTION, &on_curl_write);
  curl_easy_setopt(h.get(), CURLOPT_WRITEDATA, &out.body);
  if (list) curl_easy_setopt(h.get(), CURLOPT_HTTPHEADER, list.get());
  if (!tls_.ca_file.empty()) curl_easy_setopt(h.get(), CURLOPT_CAINFO, tls_.ca_file.c_str());  // only our CA
  if (!tls_.client_p12.empty()) {
    curl_easy_setopt(h.get(), CURLOPT_SSLCERTTYPE, "P12");
    curl_easy_setopt(h.get(), CURLOPT_SSLCERT, tls_.client_p12.c_str());
    curl_easy_setopt(h.get(), CURLOPT_KEYPASSWD, tls_.p12_password.c_str());
  }
  if (method == "POST" || method == "PUT") {
    curl_easy_setopt(h.get(), CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(h.get(), CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(h.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
  }
  const CURLcode rc = curl_easy_perform(h.get());
  if (rc == CURLE_NOT_BUILT_IN || rc == CURLE_UNSUPPORTED_PROTOCOL) {
    static std::once_flag warned;
    std::call_once(warned, [] {
      HS_TRACE_ERROR(kComponent, "this libcurl build cannot enforce TLS 1.3: refusing to connect (fail closed)");
    });
    out.status = 0;
    return SRESULT::Ok;
  }
  if (rc != CURLE_OK) {
    HS_TRACE_DEBUG(kComponent, "{} {} failed: {}", method, url, curl_easy_strerror(rc));
    out.status = 0;
    return SRESULT::Ok;
  }
  curl_easy_getinfo(h.get(), CURLINFO_RESPONSE_CODE, &out.status);
  if (out.tls_version != "TLSv1.3") {  // defense in depth: never accept a response carried over anything else
    HS_TRACE_ERROR(kComponent, "{} negotiated '{}', not TLSv1.3: response rejected", url, out.tls_version);
    out.status = 0;
  }
  return SRESULT::Ok;
}

// ---------------- CloudClientActor ----------------

CloudClientActor::CloudClientActor(EventBus& bus, EventFactory& factory, std::unique_ptr<ITransportClient> transport,
                                   OtlpResource resource, CloudClientOptions opts)
    : Actor("cloud_client"),
      bus_(bus),
      factory_(factory),
      transport_(std::move(transport)),
      resource_(std::move(resource)),
      opts_(std::move(opts)) {}

SRESULT CloudClientActor::on_start(ActorContext& ctx) {
  if (!transport_) return SRESULT::NullPointer;
  HS_RETURN_IF_FAILED(subscribe<CloudEventSanitized>(ctx.bus, [this](const auto& e) { return on_envelope(e); }));
  auto self = shared_from_this();
  TimerId a = 0, b = 0, c = 0;
  HS_RETURN_IF_FAILED(ctx.runtime.schedule_every(self, opts_.flush_period, [this] { return flush(); }, a));
  HS_RETURN_IF_FAILED(ctx.runtime.schedule_every(self, opts_.health_period, [this] { return health(); }, b));
  HS_RETURN_IF_FAILED(ctx.runtime.schedule_every(self, opts_.probe_poll_period, [this] { return poll_probes(); }, c));
  HS_TRACE_INFO(kComponent, "shipping to {} (OTLP) and {} (control plane) as {}", opts_.otlp_base,
                opts_.control_base, resource_.instance_id);
  return SRESULT::Ok;
}

SRESULT CloudClientActor::on_stop() {
  (void)flush();  // best effort: whatever is left goes to the spool or the backend
  return Actor::on_stop();
}

SRESULT CloudClientActor::on_envelope(const std::shared_ptr<const CloudEventSanitized>& env) {
  batch_.push_back(env);
  if (env->hdr.cls == EventClass::Incident || batch_.size() >= opts_.max_batch) return flush();
  return SRESULT::Ok;
}

SRESULT CloudClientActor::post_json(const std::string& url, const std::string& body, long& status) {
  HttpResponse resp;
  HS_RETURN_IF_FAILED(transport_->request("POST", url, {"Content-Type: application/json"}, body, resp));
  status = resp.status;
  bool ok = false;
  HS_RETURN_IF_FAILED(is_success(status, ok));
  if (!ok && status != 0) {
    HS_TRACE_WARNING(kComponent, "POST {} -> HTTP {}: {}", url, status, resp.body.substr(0, 200));
  }
  return SRESULT::Ok;
}

SRESULT CloudClientActor::spool(const Envelopes& envs) {
  for (const auto& env : envs) {
    std::shared_ptr<SpooledEvent> sp;
    HS_RETURN_IF_FAILED(factory_.make<SpooledEvent>(sp));
    sp->envelope = env;
    sp->attempts = 1;
    HS_RETURN_IF_FAILED(bus_.post(std::move(sp)));
  }
  return SRESULT::Ok;
}

SRESULT CloudClientActor::set_online(bool online) {
  if (known_ && online == online_) return SRESULT::NoOp;
  known_ = true;
  online_ = online;
  HS_TRACE_INFO(kComponent, "backend {}", online ? "reachable: online" : "unreachable: offline, spooling");
  std::shared_ptr<NetworkStatusChanged> ev;
  HS_RETURN_IF_FAILED(factory_.make<NetworkStatusChanged>(ev));
  ev->online = online;
  return bus_.post(std::move(ev));
}

SRESULT CloudClientActor::queue_upload(const CloudEventSanitized& env) {
  if (env.type != "com.ieso.IncidentBundleReady") return SRESULT::NoOp;
  std::shared_ptr<const JsonValue> d;
  if (HS_FAILED(JsonValue::Parse(env.data_json, d))) return SRESULT::CorruptData;
  Upload u;
  (void)d->get_string("incident_id", u.incident_id);  // validated below
  (void)d->get_string("upload_ref", u.ref);
  (void)d->get_string("upload_sha256", u.sha256);
  if (u.incident_id.empty() || u.ref.empty() || u.ref.find('/') != std::string::npos ||
      u.ref.find("..") != std::string::npos) {
    HS_TRACE_WARNING(kComponent, "rejecting bundle upload ref '{}'", u.ref);
    return SRESULT::InvalidArgument;
  }
  if (uploads_.size() >= opts_.max_pending_uploads) uploads_.pop_front();  // bounded; oldest bundle is skipped
  uploads_.push_back(std::move(u));
  return SRESULT::Ok;
}

SRESULT CloudClientActor::upload_bundles() {
  while (online_ && !uploads_.empty()) {
    const Upload u = uploads_.front();
    std::ifstream f(opts_.incident_dir / u.ref, std::ios::binary);
    if (!f.is_open()) {
      HS_TRACE_WARNING(kComponent, "bundle {} missing; skipped", u.ref);
      uploads_.pop_front();
      continue;
    }
    const std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string sha;
    HS_RETURN_IF_FAILED(Sha256::hex(data, sha));
    if (sha != u.sha256) {
      HS_TRACE_ERROR(kComponent, "bundle {} hash mismatch; not uploaded", u.ref);
      uploads_.pop_front();
      continue;
    }
    HttpResponse resp;
    HS_RETURN_IF_FAILED(transport_->request(
        "PUT", opts_.control_base + "/v1/bundles/" + u.incident_id,
        {"Content-Type: application/json", "X-Bundle-SHA256: " + sha}, data, resp));
    bool ok = false, retry = false;
    HS_RETURN_IF_FAILED(is_success(resp.status, ok));
    HS_RETURN_IF_FAILED(is_retriable(resp.status, retry));
    if (!ok && retry) {
      HS_RETURN_IF_FAILED(set_online(false));
      return SRESULT::NoOp;  // keep it queued; retried when back online
    }
    if (ok) {
      HS_TRACE_INFO(kComponent, "bundle uploaded: incident {} ({} bytes)", u.incident_id, data.size());
    } else {
      HS_TRACE_ERROR(kComponent, "bundle {} refused: HTTP {}", u.incident_id, resp.status);
    }
    uploads_.pop_front();
  }
  return SRESULT::Ok;
}

SRESULT CloudClientActor::flush() {
  if (!known_) HS_RETURN_IF_FAILED(health());  // establish state before the first send
  if (batch_.empty()) return upload_bundles();
  Envelopes batch;
  batch.swap(batch_);
  if (!online_) return spool(batch);

  Envelopes metrics, logs, incidents;
  for (const auto& env : batch) {
    bool metric = false;
    HS_RETURN_IF_FAILED(otlp_is_metric(*env, metric));
    (metric ? metrics : logs).push_back(env);
    if (env->hdr.cls == EventClass::Incident) incidents.push_back(env);
  }

  long st_metrics = 200, st_logs = 200, st_control = 200;
  if (!metrics.empty()) {
    std::string body;
    HS_RETURN_IF_FAILED(otlp_metrics_json(resource_, metrics, body));
    HS_RETURN_IF_FAILED(post_json(opts_.otlp_base + "/v1/metrics", body, st_metrics));
  }
  if (!logs.empty()) {
    std::string body;
    HS_RETURN_IF_FAILED(otlp_logs_json(resource_, logs, body));
    HS_RETURN_IF_FAILED(post_json(opts_.otlp_base + "/v1/logs", body, st_logs));
  }
  if (!incidents.empty()) {
    std::string body = "[";
    for (std::size_t i = 0; i < incidents.size(); ++i) {
      std::string one;
      HS_RETURN_IF_FAILED(incidents[i]->to_json(one));
      body += (i == 0 ? "" : ",") + one;
    }
    body += "]";
    HS_RETURN_IF_FAILED(post_json(opts_.control_base + "/v1/events", body, st_control));
  }

  // An envelope is delivered when every destination it needs accepted it.
  bool m_ok = false, l_ok = false, c_ok = false, m_retry = false, l_retry = false, c_retry = false;
  HS_RETURN_IF_FAILED(is_success(st_metrics, m_ok));
  HS_RETURN_IF_FAILED(is_success(st_logs, l_ok));
  HS_RETURN_IF_FAILED(is_success(st_control, c_ok));
  HS_RETURN_IF_FAILED(is_retriable(st_metrics, m_retry));
  HS_RETURN_IF_FAILED(is_retriable(st_logs, l_retry));
  HS_RETURN_IF_FAILED(is_retriable(st_control, c_retry));

  std::shared_ptr<TelemetryDelivered> ack;
  HS_RETURN_IF_FAILED(factory_.make<TelemetryDelivered>(ack));
  Envelopes failed;
  bool any_retry = false;
  for (const auto& env : batch) {
    bool metric = false;
    HS_RETURN_IF_FAILED(otlp_is_metric(*env, metric));
    const bool incident = env->hdr.cls == EventClass::Incident;
    const bool ok = (metric ? m_ok : l_ok) && (!incident || c_ok);
    const bool retry = (metric ? m_retry : l_retry) || (incident && c_retry);
    if (ok) {
      ack->ids.push_back(env->hdr.id);
      (void)queue_upload(*env);  // NoOp for non-bundle events
    } else if (retry) {
      failed.push_back(env);
      any_retry = true;
    } else {
      HS_TRACE_ERROR(kComponent, "dropping {} {}: refused by backend (not retriable)", env->type, env->hdr.id);
      ack->ids.push_back(env->hdr.id);  // permanent refusal: remove from the spool, do not loop
    }
  }
  if (!ack->ids.empty()) {
    delivered_ += ack->ids.size();
    HS_TRACE_DEBUG(kComponent, "delivered {} envelopes ({} total)", ack->ids.size(), delivered_);
    HS_RETURN_IF_FAILED(bus_.post(std::move(ack)));
  }
  if (any_retry) {
    HS_RETURN_IF_FAILED(set_online(false));
    HS_RETURN_IF_FAILED(spool(failed));
  }
  return upload_bundles();
}

SRESULT CloudClientActor::poll_probes() {
  if (!online_) return SRESULT::NoOp;
  HttpResponse resp;
  HS_RETURN_IF_FAILED(transport_->request("GET", opts_.control_base + "/v1/probes/pending", {}, "", resp));
  if (resp.status != 200) return SRESULT::NoOp;
  std::shared_ptr<const JsonValue> list;
  if (HS_FAILED(JsonValue::Parse(resp.body, list))) {
    HS_TRACE_WARNING(kComponent, "pending probes: malformed response ignored");
    return SRESULT::NoOp;
  }
  std::size_t n = 0;
  HS_RETURN_IF_FAILED(list->size(n));
  for (std::size_t i = 0; i < n; ++i) {
    std::shared_ptr<const JsonValue> item;
    if (list->at(i, item) != SRESULT::Ok) continue;
    std::shared_ptr<ProbeRequested> req;
    HS_RETURN_IF_FAILED(factory_.make<ProbeRequested>(req));
    // Missing fields stay empty: the Diagnostics actor refuses anything that does not verify.
    (void)item->get_string("probe_id", req->probe_id);
    (void)item->get_string("request_id", req->request_id);
    (void)item->get_string("incident_id", req->incident_id);
    (void)item->get_string("endpoint", req->endpoint);
    (void)item->get_int("issued_at", req->issued_at);
    (void)item->get_int("expires_at", req->expires_at);
    (void)item->get_string("signature", req->signature);
    HS_TRACE_INFO(kComponent, "probe request {} ({}) received for incident {}", req->request_id, req->probe_id,
                  req->incident_id);
    HS_RETURN_IF_FAILED(bus_.post(std::move(req)));
  }
  return SRESULT::Ok;
}

SRESULT CloudClientActor::health() {
  if (known_ && online_) return SRESULT::NoOp;
  HttpResponse a, b;
  HS_RETURN_IF_FAILED(transport_->request("GET", opts_.collector_health, {}, "", a));
  HS_RETURN_IF_FAILED(transport_->request("GET", opts_.control_base + "/healthz", {}, "", b));
  bool ok_a = false, ok_b = false;
  HS_RETURN_IF_FAILED(is_success(a.status, ok_a));
  HS_RETURN_IF_FAILED(is_success(b.status, ok_b));
  if (ok_a && ok_b && !online_) {
    HS_TRACE_INFO(kComponent, "backend handshake: collector {} / control plane {} (mTLS)", a.tls_version,
                  b.tls_version);
  }
  return set_online(ok_a && ok_b);
}

}  // namespace ieso
