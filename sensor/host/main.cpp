/**
 * @file main.cpp
 * @brief ieso-sensor entry point: agent run mode (`--target`) and the core `--selftest`.
 * @details Run mode wires every actor of DESIGN.md §8 against a real target app on macOS. Until the step 3
 *          With --backend, the Cloud Client ships sanitized events over mTLS to the backend (step 3);
 *          without it, they are "delivered" to <data-dir>/outbox.ndjson (offline/dev fallback).
 *          Self-test: offline crash event -> PII filter -> stub Cloud Client fails -> spooled ->
 *          network comes up -> spool replays -> stub delivers -> ack removes it from disk.
 */
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

#include "ieso/core/bus.hpp"
#include "ieso/core/clock.hpp"
#include "ieso/core/codec.hpp"
#include "ieso/core/event_factory.hpp"
#include "ontology/events.hpp"
#include "ieso/core/pools.hpp"
#include "ieso/core/runtime.hpp"
#include "ieso/core/sha256.hpp"
#include "ieso/core/spool.hpp"
#include "ieso/core/trace.hpp"
#include "ieso/core/uuid.hpp"

#include "anomaly/anomaly.hpp"
#include "cloud_client/cloud_client.hpp"
#include "diagnostics/diagnostics.hpp"
#include "outbox/outbox.hpp"
#include "pii_filter/pii_filter.hpp"
#include "spooler/spooler.hpp"
#if IESO_HAVE_MACOS
#include "log_collector/log_collector.hpp"
#include "ieso/macos/ecdsa_probe_verifier.hpp"
#include "ieso/macos/macos_diagnostics_platform.hpp"
#include "process_watcher/process_watcher.hpp"
#include "resource_sampler/resource_sampler.hpp"
#include "ui_observer/ui_observer.hpp"
#endif

namespace {
constexpr std::string_view kComponent = "main";

/**
 * @brief Stand-in for the mTLS Cloud Client (step 3): "sends" by tracing, fails while offline.
 * @note Online: traces the envelope JSON and acks it. Offline: hands it to the spooler.
 */
class StubCloudClient final : public ieso::Actor {
 public:
  /// @brief Binds dependencies. @param[in] bus Bus. @param[in] factory Factory.
  StubCloudClient(ieso::EventBus& bus, ieso::EventFactory& factory)
      : Actor("cloud_client_stub"), bus_(bus), factory_(factory) {}

  /// @copydoc ieso::Actor::on_start
  ieso::SRESULT on_start(ieso::ActorContext& ctx) override {
    HS_RETURN_IF_FAILED(subscribe<ieso::CloudEventSanitized>(ctx.bus, [this](const auto& e) { return send(e); }));
    return subscribe<ieso::NetworkStatusChanged>(ctx.bus, [this](const auto& e) {
      online_.store(e->online);
      return ieso::SRESULT::Ok;
    });
  }

  /// @brief Envelopes acknowledged so far. @param[out] out Count. @return SRESULT::Ok.
  ieso::SRESULT delivered(std::uint64_t& out) const {
    out = delivered_.load();
    return ieso::SRESULT::Ok;
  }

 private:
  /// @brief Sends (traces) or spools one envelope. @param[in] env Envelope. @return Result of post.
  ieso::SRESULT send(const std::shared_ptr<const ieso::CloudEventSanitized>& env) {
    if (!online_.load()) {
      std::shared_ptr<ieso::SpooledEvent> sp;
      HS_RETURN_IF_FAILED(factory_.make<ieso::SpooledEvent>(sp));
      sp->envelope = env;
      sp->attempts = 1;
      HS_TRACE_INFO(kComponent, "offline: spooling {}", env->hdr.id);
      return bus_.post(std::move(sp));
    }
    std::string json;
    HS_RETURN_IF_FAILED(env->to_json(json));
    HS_TRACE_INFO(kComponent, "delivered: {}", json);
    std::shared_ptr<ieso::TelemetryDelivered> ack;
    HS_RETURN_IF_FAILED(factory_.make<ieso::TelemetryDelivered>(ack));
    ack->ids.push_back(env->hdr.id);
    delivered_.fetch_add(1);
    return bus_.post(std::move(ack));
  }

  ieso::EventBus& bus_;                    ///< Bus.
  ieso::EventFactory& factory_;            ///< Factory.
  std::atomic<bool> online_{false};          ///< Simulated network state.
  std::atomic<std::uint64_t> delivered_{0};  ///< Acked envelopes.
};

/**
 * @brief Waits for a condition with a deadline.
 * @tparam F Predicate type.
 * @param[in] pred Condition.
 * @param[in] timeout Deadline.
 * @return SRESULT::Ok or SRESULT::Timeout.
 */
template <class F>
ieso::SRESULT wait_for(F pred, std::chrono::milliseconds timeout) {
  const auto end = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < end) {
    if (pred()) return ieso::SRESULT::Ok;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return ieso::SRESULT::Timeout;
}

/**
 * @brief Posts NetworkStatusChanged.
 * @param[in] bus Bus.
 * @param[in] factory Factory.
 * @param[in] online New state.
 * @return Result of post.
 */
ieso::SRESULT set_network(ieso::EventBus& bus, ieso::EventFactory& factory, bool online) {
  std::shared_ptr<ieso::NetworkStatusChanged> ev;
  HS_RETURN_IF_FAILED(factory.make<ieso::NetworkStatusChanged>(ev));
  ev->online = online;
  return bus.post(std::move(ev));
}

/**
 * @brief Runs the end-to-end self-test.
 * @return SRESULT::Ok if the spooled crash event was replayed, delivered and acked.
 */
ieso::SRESULT selftest() {
  using namespace ieso;
  std::unique_ptr<Pools> pools;
  HS_RETURN_IF_FAILED(Pools::Create(config::kEventPoolBytes, pools));
  SystemClock clock;
  UuidGenerator uuid(clock);
  EventFactory factory(*pools, clock, uuid, "endpoint-selftest");
  EventBus bus;
  Runtime runtime(bus);

  std::error_code ec;
  const auto dir = std::filesystem::temp_directory_path(ec) / "ieso-selftest-spool";
  std::filesystem::remove_all(dir, ec);
  SpoolOptions sopts;
  sopts.dir = dir;
  std::unique_ptr<Spool> spool;
  HS_RETURN_IF_FAILED(Spool::Create(sopts, clock, std::make_shared<IdentityCodec>(), spool));

  auto pii = std::make_shared<PiiFilter>(bus, factory, Redactor("selftest-salt"));
  auto spooler = std::make_shared<SpoolerActor>(bus, factory, clock, std::move(spool));
  auto cloud = std::make_shared<StubCloudClient>(bus, factory);
  HS_RETURN_IF_FAILED(runtime.add(pii));
  HS_RETURN_IF_FAILED(runtime.add(cloud));
  HS_RETURN_IF_FAILED(runtime.add(spooler));
  HS_RETURN_IF_FAILED(runtime.start());

  std::shared_ptr<ProcessCrashDetected> crash;
  HS_RETURN_IF_FAILED(factory.make<ProcessCrashDetected>(crash));
  crash->pid = 4242;
  crash->exception_type = "EXC_BAD_ACCESS";
  crash->signal = "SIGSEGV";
  crash->termination_reason = "Namespace SIGNAL, Code 11; user alice@corp.example from 10.1.2.3";
  crash->faulting_module = "libfoo.dylib";
  crash->offset = 0x1a2c;
  crash->report_path = "/Users/alice/Library/Logs/DiagnosticReports/DemoApp-2026-11-17.ips";
  HS_RETURN_IF_FAILED(bus.post(std::move(crash)));

  std::uint64_t delivered = 0;
  const SRESULT spooled = wait_for([&] { return std::filesystem::exists(dir, ec) &&
                                                !std::filesystem::is_empty(dir, ec); },
                                   std::chrono::seconds(3));
  HS_TRACE_INFO(kComponent, "offline phase: spooled to disk = {}", spooled);
  HS_RETURN_IF_FAILED(set_network(bus, factory, true));
  const SRESULT got = wait_for([&] { return HS_SUCCEEDED(cloud->delivered(delivered)) && delivered >= 1; },
                               std::chrono::seconds(5));
  const SRESULT acked = wait_for([&] { return std::filesystem::is_empty(dir, ec); }, std::chrono::seconds(3));

  std::vector<TypeStats> stats;
  HS_RETURN_IF_FAILED(bus.stats(stats));
  for (const auto& s : stats) {
    HS_TRACE_INFO(kComponent, "bus {:<26} subs={} posted={} delivered={} dropped={} spilled={} lost={}", s.type,
                  s.subscribers, s.posted, s.delivered, s.dropped, s.spilled, s.lost);
  }
  HS_RETURN_IF_FAILED(runtime.stop());
  std::filesystem::remove_all(dir, ec);

  if (HS_FAILED(spooled) || HS_FAILED(got) || HS_FAILED(acked)) {
    HS_TRACE_ERROR(kComponent, "selftest FAILED: spooled={} delivered={} acked={}", spooled, got, acked);
    return SRESULT::Internal;
  }
  HS_TRACE_INFO(kComponent, "selftest PASSED");
  return SRESULT::Ok;
}

/// @brief Command-line options.
struct Args {
  bool selftest = false;            ///< Run the core self-test.
  std::string target;               ///< Target app name (run mode).
  std::filesystem::path data_dir;   ///< Spool, outbox, incidents.
  ieso::trace::Level level = ieso::trace::Level::Info;  ///< Trace level.
  std::string backend;              ///< OTLP/HTTP base URL; empty = file outbox.
  std::string control_plane = "https://localhost:8443";      ///< Control plane base URL.
  std::string collector_health = "https://localhost:13133/";  ///< Collector health URL (TLS 1.3 + mTLS).
  std::filesystem::path tls_dir;    ///< ca.pem + endpoint.p12 (backend/certs/out).
  std::string endpoint_id;          ///< Overrides the hostname-derived id (must match the client cert CN).
  std::string probe_key;            ///< Pinned control-plane probe-signing public key (PEM); empty = refuse probes.
  std::string app_backend;          ///< Target of net.synthetic_tls (the app's own backend URL).
  std::string demo_proxy;           ///< Stands in for the system HTTPS proxy in the demo.
  std::string app_backend_direct;   ///< "host:port" for the probe's direct (no-proxy) path.
};

/**
 * @brief Parses argv.
 * @param[in] argc Count.
 * @param[in] argv Arguments.
 * @param[out] out Options.
 * @return SRESULT::Ok or InvalidArgument (usage printed by main).
 */
ieso::SRESULT parse_args(int argc, char** argv, Args& out) {
  using ieso::SRESULT;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    const bool has_value = i + 1 < argc;
    if (a == "--selftest") {
      out.selftest = true;
    } else if (a == "--target" && has_value) {
      out.target = argv[++i];
    } else if (a == "--data-dir" && has_value) {
      out.data_dir = argv[++i];
    } else if (a == "--backend" && has_value) {
      out.backend = argv[++i];
    } else if (a == "--control-plane" && has_value) {
      out.control_plane = argv[++i];
    } else if (a == "--collector-health" && has_value) {
      out.collector_health = argv[++i];
    } else if (a == "--tls-dir" && has_value) {
      out.tls_dir = argv[++i];
    } else if (a == "--endpoint-id" && has_value) {
      out.endpoint_id = argv[++i];
    } else if (a == "--probe-key" && has_value) {
      out.probe_key = argv[++i];
    } else if (a == "--app-backend" && has_value) {
      out.app_backend = argv[++i];
    } else if (a == "--demo-proxy" && has_value) {
      out.demo_proxy = argv[++i];
    } else if (a == "--app-backend-direct" && has_value) {
      out.app_backend_direct = argv[++i];
    } else if (a == "--log-level" && has_value) {
      const std::string l = argv[++i];
      const std::array<std::pair<const char*, ieso::trace::Level>, 6> names = {{{"fatal", ieso::trace::Level::Fatal},
                                                                                  {"error", ieso::trace::Level::Error},
                                                                                  {"warning", ieso::trace::Level::Warning},
                                                                                  {"info", ieso::trace::Level::Info},
                                                                                  {"debug", ieso::trace::Level::Debug},
                                                                                  {"trace", ieso::trace::Level::Trace}}};
      bool found = false;
      for (const auto& [n, lv] : names) {
        if (l == n) {
          out.level = lv;
          found = true;
        }
      }
      if (!found) return SRESULT::InvalidArgument;
    } else {
      return SRESULT::InvalidArgument;
    }
  }
  if (!out.selftest && out.target.empty()) return SRESULT::InvalidArgument;
  if (out.data_dir.empty()) {
    const char* home = std::getenv("HOME");
    out.data_dir = std::filesystem::path(home != nullptr ? home : "/tmp") / "Library/Application Support/ieso";
  }
  return SRESULT::Ok;
}

#if IESO_HAVE_MACOS
/**
 * @brief Stable, non-PII endpoint id: hash of the host name (used when no --endpoint-id / certificate CN is given).
 * @param[out] out Endpoint id.
 * @return SRESULT::Ok.
 */
ieso::SRESULT endpoint_id(std::string& out) {
  std::array<char, 256> host{};
  (void)gethostname(host.data(), host.size() - 1);  // empty name still hashes
  std::string h;
  HS_RETURN_IF_FAILED(ieso::Sha256::hex(host.data(), h));
  out = "ep-" + h.substr(0, 16);
  return ieso::SRESULT::Ok;
}

/**
 * @brief Runs the agent until SIGINT/SIGTERM.
 * @param[in] args Options.
 * @return SRESULT::Ok after a clean shutdown.
 */
ieso::SRESULT run_agent(const Args& args) {
  using namespace ieso;
  // Block termination signals before any thread starts, so only sigwait() below receives them.
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, SIGINT);
  sigaddset(&sigs, SIGTERM);
  pthread_sigmask(SIG_BLOCK, &sigs, nullptr);

  std::unique_ptr<Pools> pools;
  HS_RETURN_IF_FAILED(Pools::Create(config::kEventPoolBytes, pools));
  SystemClock clock;
  UuidGenerator uuid(clock);
  std::string endpoint = args.endpoint_id;
  if (endpoint.empty()) HS_RETURN_IF_FAILED(endpoint_id(endpoint));
  EventFactory factory(*pools, clock, uuid, endpoint);
  EventBus bus;
  Runtime runtime(bus);

  SpoolOptions sopts;
  sopts.dir = args.data_dir / "spool";
  std::unique_ptr<Spool> spool;
  HS_RETURN_IF_FAILED(Spool::Create(sopts, clock, std::make_shared<IdentityCodec>(), spool));
  DiagnosticsOptions dopts;
  dopts.incident_dir = args.data_dir / "incidents";
  dopts.redaction_salt = endpoint;
  dopts.checkpoint_file = args.data_dir / "recorder.ckpt";  // NFR-11: history survives restart / update / reboot
  if (!args.probe_key.empty()) {  // FR-14: remote probes only with a pinned control-plane key
    std::unique_ptr<macos::EcdsaProbeVerifier> verifier;
    HS_RETURN_IF_FAILED(macos::EcdsaProbeVerifier::Create(args.probe_key, verifier));
    dopts.probe_verifier = std::move(verifier);
  }
  macos::ProbeConfig probe_cfg;
  probe_cfg.app_backend_url = args.app_backend;
  probe_cfg.demo_proxy = args.demo_proxy;
  probe_cfg.direct_address = args.app_backend_direct;
  auto platform = std::make_shared<macos::MacosDiagnosticsPlatform>(args.data_dir / "tmp", probe_cfg);
  macos::WatcherOptions wopts;
  wopts.target_name = args.target;

  // Consumers first, producers last: Runtime stops in reverse, so producers stop before their consumers.
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<PiiFilter>(bus, factory, Redactor(endpoint))));
  if (!args.backend.empty()) {
    TlsConfig tls;
    tls.ca_file = (args.tls_dir / "ca.pem").string();
    tls.client_p12 = (args.tls_dir / "endpoint.p12").string();
    tls.p12_password = "ieso";  // demo PKI; production identity lives in the Keychain / Secure Enclave
    std::unique_ptr<CurlTransport> transport;  // the only HTTP client: libcurl, TLS 1.3 + mTLS
    HS_RETURN_IF_FAILED(CurlTransport::Create(tls, transport));
    CloudClientOptions copts;
    copts.otlp_base = args.backend;
    copts.control_base = args.control_plane;
    copts.collector_health = args.collector_health;
    copts.incident_dir = dopts.incident_dir;
    OtlpResource res;
    res.instance_id = endpoint;
    HS_RETURN_IF_FAILED(runtime.add(
        std::make_shared<CloudClientActor>(bus, factory, std::move(transport), res, copts)));
  } else {
    HS_RETURN_IF_FAILED(
        runtime.add(std::make_shared<FileOutboxActor>(bus, factory, args.data_dir / "outbox.ndjson")));
  }
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<SpoolerActor>(bus, factory, clock, std::move(spool))));
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<DiagnosticsActor>(bus, factory, clock, platform, dopts)));
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<AnomalyActor>(bus, factory, clock)));
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<macos::ProcessWatcherActor>(bus, factory, clock, wopts)));
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<macos::ResourceSamplerActor>(bus, factory, clock)));
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<macos::LogCollectorActor>(bus, factory, args.target)));
  HS_RETURN_IF_FAILED(runtime.add(std::make_shared<macos::UiObserverActor>(bus, factory)));
  HS_RETURN_IF_FAILED(runtime.start());
  if (args.backend.empty()) HS_RETURN_IF_FAILED(set_network(bus, factory, true));  // the file outbox is always reachable
  HS_TRACE_INFO(kComponent, "ieso-sensor running: target='{}' endpoint={} data='{}' (Ctrl-C to stop)", args.target,
                endpoint, args.data_dir.string());

  int sig = 0;
  sigwait(&sigs, &sig);
  HS_TRACE_INFO(kComponent, "signal {} received, shutting down", sig);
  std::vector<TypeStats> stats;
  HS_RETURN_IF_FAILED(bus.stats(stats));
  for (const auto& s : stats) {
    if (s.posted == 0) continue;
    HS_TRACE_INFO(kComponent, "bus {:<29} posted={} delivered={} dropped={} spilled={} lost={}", s.type, s.posted,
                  s.delivered, s.dropped, s.spilled, s.lost);
  }
  return runtime.stop();
}
#endif

}  // namespace

/// @brief Entry point (exempt from the SRESULT rule). @return 0 on success, 1 on failure, 2 on usage error.
int main(int argc, char** argv) {
  Args args;
  if (parse_args(argc, argv, args) != ieso::SRESULT::Ok) {
    std::fputs(
        "usage: ieso-sensor --selftest\n"
        "       ieso-sensor --target <AppName> [--data-dir DIR] [--log-level fatal|error|warning|info|debug|trace]\n"
        "                     [--backend https://localhost:4318 --tls-dir backend/certs/out --endpoint-id ep-demo\n"
        "                      --control-plane https://localhost:8443 --collector-health https://localhost:13133/]\n"
        "                     [--probe-key backend/certs/out/probe-signing.pub.pem --app-backend URL --demo-proxy URL\n"
        "                      --app-backend-direct host:port]\n",
        stderr);
    return 2;
  }
  (void)ieso::trace::set_level(args.level);  // always Ok
  if (args.selftest) return HS_SUCCEEDED(selftest()) ? 0 : 1;
#if IESO_HAVE_MACOS
  return HS_SUCCEEDED(run_agent(args)) ? 0 : 1;
#else
  std::fputs("run mode needs macOS collectors (this build has none)\n", stderr);
  return 2;
#endif
}
