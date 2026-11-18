# macOS Endpoint Observability & Remote Diagnostics Agent

Take-home for Palo Alto Networks (AI-assisted coding). Presentation: Thu 2026-11-19, 55 min.
Full design: `docs/DESIGN.md` (exported from the design doc). Architecture: `docs/Ieso.drawio` (SVG export `docs/Ieso-architecture.svg`, embedded in DESIGN.md §4).

## Prompt
A business-critical app runs on macOS endpoints and users report problems. Logs are only
somewhat helpful, and the customer is often unreachable. Judged on: problem exploration,
creativity/novelty, system design, completion.

## Core idea
"Ask the endpoint, not the customer." We do NOT own the target app's source, so everything
is observed from outside the process via OS telemetry. The sensor runs as a separate process
so it survives the app's crash.

## Repo layout (target)
- `sensor/`       C++17 agent (CMake). Actor runtime + event bus + actors.
  - `core/`       portable infrastructure only: bus, mailbox, Actor base, runtime, pmr pools, ring buffers,
                  spool, redactor, JSON, .ips parser. Unit-tested on macOS.
  - `ontology/`   events ontology (DESIGN §7): every event type in one header, `ontology/events.hpp` (+ `events.cpp`);
                  compiled into `ieso_core`. Include as "ontology/events.hpp".
  - `platform/macos/` OS helpers only: libproc, subprocess, CoreFoundation RAII, diagnostics platform (sample, log config).
  - `actors/`     every actor, one flat folder each (`<name>/<name>.hpp` + `<name>.cpp`, include as "<name>/<name>.hpp"):
                  anomaly, cloud_client, diagnostics, outbox, pii_filter, spooler (portable); process_watcher, resource_sampler,
                  log_collector, ui_observer (macOS: libproc, kqueue, FSEvents/.ips, `log stream`, AX probe + AXObserver).
  - `host/`       ieso-sensor host process: builds the runtime, wires all actors, signal handling, `--selftest`.
  - `tests/`      every sensor test, flat (+ `test_util.hpp`, `fixtures/`): `ieso_tests` (portable core + actors),
                  `ieso_macos_tests` (macOS helpers + actors).
- `demo-app/`     small macOS app with fault switches: hang, crash, leak, network block, permission denial.
- `backend/`      docker-compose: OTel Collector (mTLS), nginx mTLS ingress, FastAPI control plane, S3 store
                  (SeaweedFS; MinIO images are no longer published), Prometheus, Loki, Grafana. Local PKI: `backend/certs/gen_certs.sh`.
- `investigator/` Python (`ieso_investigator`): fleet differential diagnosis + hypothesis/probe loop. Reasoners share one
                  JSON schema: Claude (`claude-opus-5-5`, key from ANTHROPIC_API_KEY only, never logged), offline rules
                  (fallback, air-gapped), replay of a recorded Claude session (`recordings/`, labeled as replay).
- `sim/`          simulated fleet (`ieso_sim`, 200 endpoints) with injected root causes (proxy, DLP extension, OS build).
- `scripts/`      `run_tests.py`, `smoke_test.sh`, `e2e_backend.sh` (step 3), `e2e_investigation.sh` (step 4).

## Design rules (keep consistent with DESIGN.md)
- Actors communicate only through the bus; events immutable (`shared_ptr<const Event>`), async post only.
- Typed subscriptions returning RAII tokens. Bounded queue per event class:
  routine telemetry may be sampled/dropped (count drops); incidents/control never dropped.
- Only the PII Filter can construct `CloudEventSanitized`; it subscribes only to egress-eligible types.
- Spool: at-least-once with stable event IDs, backend dedupe, priority drain, backoff + jitter, TTL purge.
- Tiered flight recorder: 5 s @100 ms, 10 min @1 s, 24 h of 1-min aggregates; the 10 min and 24 h tiers are
  mandatorily persisted (crash-safe checkpoint at most every 60 s, restored on start; NFR-11).
- Observer-effect budget: <= 1 sample/spindump per incident, <= 4 per hour.
- Probes = IDs from a signed read-only allowlist, never commands. LLM proposes, policy layer decides.
  Signed with ECDSA P-256 by the control plane; the sensor verifies against a pinned key before running.
  `net.synthetic_tls` uses libcurl directly (not ITransportClient) and may observe non-1.3 TLS: it diagnoses
  the app's third-party path, not an endpoint<->backend hop.
- All HTTP(S) in the sensor goes through libcurl: OTLP/HTTP export, control-plane calls
  (enrollment, policy, probe requests/results) and synthetic network probes. No other HTTP
  client (no NSURLSession, no hand-rolled sockets). Wrap it once behind `ITransportClient`;
  configure mTLS (client cert/key), CA pinning, timeouts and proxy settings there.
- Transport security: **TLS 1.3 + mTLS only, on every endpoint<->backend hop** (sensor -> OTel Collector, control
  plane, health checks). **TLS 1.2 and older are forbidden**: servers refuse them (`min_version: "1.3"`,
  `ssl_protocols TLSv1.3`) and the sensor never negotiates them (libcurl restricted to TLS 1.3 per TLS backend;
  a build that cannot enforce it fails closed). Responses not carried over TLSv1.3 are rejected. No plain HTTP.
- No kexts. Future deep telemetry = Endpoint Security / Network Extension system extensions.
- Budgets: < 1% CPU steady, < 50 MB RSS, spool <= 250 MB.

## Skills (`.claude/skills/`)
- `/build-test` after any change and before reporting done; `/add-actor` for a new sensor actor; `/add-event` for a
  new event type; `/add-probe` for a new remote probe; `macos-collector` (auto) for macOS collector code;
  `/run-demo` and `/stop-demo` (user-invoked) to start and stop the live demo; `/cause-crash|hang|leak|network|permission`
  (user-invoked) to break DemoApp on cue (`scripts/demo_fault.sh`). Keep them in sync when commands or rules change.

## C++ coding rules (mandatory)
All C++ MUST follow `docs/STYLEGUIDE.md`. Read it before writing or reviewing C++. Summary:
0. C++17 only (no C++20 features); formatting via pinned `{fmt}`.
1. Doxygen on every file/class/struct/function (`@file` … `@note`/`@warning`), ≤ 12 short sentences per tag.
2. No explicit `new/delete/malloc/free` outside the memory-pool layer.
3. Every function returns `SRESULT` (type is `[[nodiscard]]`; discard only via `(void)` + comment) (ctors/dtors/operators/`main` exempt; fallible construction via `Create`).
4. Trace via `ieso/core/trace.hpp`: FATAL/ERROR/WARNING/INFO/DEBUG/TRACE; trace failures once at origin.
5. No exceptions (`-fno-exceptions`); non-throwing std APIs only.
6. RTTI on; smart pointers for ownership; no naked owning pointers (non-owning = reference or `weak_ptr`).
7. No explicit recursion: use an explicit bounded stack/queue (iterative), cap depth/size.

## Build order (completion first)
1. sensor/core + unit tests (bus, rings, PII filter, spooler).
2. macOS collectors + demo-app; smoke-test hang and crash detection.
3. backend docker-compose; sensor ships OTLP to it.
4. investigator + sim fleet; end-to-end network-failure demo.
5. README with demo script; slides.
