# sensor

The Ieso endpoint agent: a C++17 actor runtime with macOS collectors, running as a separate process next to
the app it watches. Back to the [README](../README.md) · design: [DESIGN.md](../docs/DESIGN.md) · coding rules:
[STYLEGUIDE.md](../docs/STYLEGUIDE.md).

## Build and test

Run these from the repo root.

Requirements: CMake ≥ 3.24, Ninja, and a C++17 compiler (Apple clang on macOS 14+, or clang/gcc on Linux). On macOS,
install CMake and Ninja with [MacPorts](https://www.macports.org/install.php):
`sudo port selfupdate && sudo port install cmake ninja`. They land in `/opt/local/bin`, which the scripts add to
`PATH` themselves (`scripts/lib/build_tools.sh`). In VS Code, if CMake Tools can't find them, set
`"cmake.cmakePath": "/opt/local/bin/cmake"` in your user settings.
GoogleTest 1.15.2 and {fmt} 11.0.2 are fetched at configure time, pinned by SHA-256.

```sh
cmake --preset debug && cmake --build --preset debug && ctest --preset debug
scripts/run_tests.py                     # compact view: one block per suite + summary table (exit 1 on failure)
scripts/run_tests.py --preset asan --filter 'Spool|Bus'    # sanitizer build, selected suites; --list shows suites
cmake --preset asan  && cmake --build --preset asan  && ctest --preset asan   # ASan + UBSan
cmake --preset tsan  && cmake --build --preset tsan  && ctest --preset tsan   # ThreadSanitizer
./build/debug/sensor/host/ieso-sensor --selftest
```

The self-test runs the whole core end to end:
1. The network starts offline. A crash event containing PII goes through the PII filter.
2. The stub cloud client can't send it, so it goes to the spool on disk.
3. The network comes up. The spool replays the envelope, rate-limited, and the stub delivers it.
4. The ack deletes the record from disk.

The delivered CloudEvent is traced with user name, email and IP redacted.

## `sensor/core` at a glance

| Header | Responsibility | Design ref |
| --- | --- | --- |
| `sresult.hpp`, `trace.hpp` | `[[nodiscard]] SRESULT` everywhere; FATAL..TRACE tracing | STYLEGUIDE §3–4 |
| `bus.hpp`, `mailbox.hpp`, `actor.hpp`, `runtime.hpp` | Typed async bus with RAII subscriptions; per-actor control/incident/routine lanes; one thread per actor; coalescing timers | §3, §8 |
| `bounded_queue.hpp` | DropOldest / Sample / NeverDrop overflow with counters | §3 "Bounded everything" |
| `pools.hpp`, `event_factory.hpp` | Capped `std::pmr` pool for events (the only raw-memory code), header filling | §3 "Memory pooling" |
| `sensor/ontology/events.hpp` | Events ontology in one header: primitives, every event with class/overflow/egress traits, passkey-protected CloudEvents envelope, `AllEvents` | §7, §9.6 |
| `ring.hpp` | Flight recorder: hot 5 s@100 ms, warm 10 min@1 s, cold 24 h of 1-min min/max/avg; per-pid samples; warm/cold checkpointed (`<data-dir>/recorder.ckpt`, every 60 s + on stop) and restored with a gap marker | §9.3, NFR-11 |
| `redactor.hpp` | Edge redaction (home paths, emails, IPs hashed, secrets, free-text truncation) | §9.6, NFR-7 |
| `spool.hpp`, `flow_control.hpp`, `codec.hpp` | Crash-safe disk spool: priority drain, idempotent re-spool, size cap that evicts routine records first, TTL purge, CRC check; token bucket + full-jitter backoff | §9.7, FR-8 |
| `capture_budget.hpp` | Observer-effect budget: ≤ 1 capture per incident, ≤ 4 per hour | NFR-4 |

## `sensor/actors`: one folder per actor (`<name>/<name>.hpp` + `.cpp`)

| Actor folder | Mechanism | Emits |
| --- | --- | --- |
| `pii_filter/` | subscribes only to egress-eligible types; redacts and wraps in CloudEvents (passkey) | `CloudEventSanitized` |
| `spooler/` | disk spool, priority drain, token bucket, full-jitter backoff, spill sink | `SpoolStorageUpdated`, replayed envelopes |
| `cloud_client/` | libcurl, **TLS 1.3 only** + mTLS (pinned local CA + PKCS#12 identity), OTLP/HTTP JSON batches, control-plane index, bundle upload, health probe | `TelemetryDelivered`, `SpooledEvent`, `NetworkStatusChanged` |
| `outbox/` | offline/dev fallback when no `--backend`: NDJSON file + ack | `TelemetryDelivered` |
| `process_watcher/` (macOS) | libproc scan, kqueue `NOTE_EXIT`, FSEvents on DiagnosticReports → `.ips` parser | `TargetLifecycle`, `ProcessCrashDetected` (signature `module+offset EXC_TYPE`) |
| `resource_sampler/` (macOS) | `proc_pidinfo` task info + FD count, `statfs`, at 100 ms | `ResourceSampled` (hot ring), `TelemetrySnapshotCaptured` (1 s) |
| `log_collector/` (macOS) | `/usr/bin/log stream --style ndjson`, app + tccd predicate | `LogRecordObserved` |
| `ui_observer/` (macOS) | AX messaging-timeout probe every 2 s; AXObserver on window/sheet creation | `ResponsivenessProbed`, `UserVisibleErrorObserved` |
| `anomaly/` | 3 probe timeouts in a row, RSS slope, absolute limits, crash loop | `ProcessHangDetected`, `ResourceAnomalyDetected`, `DiagnosticEscalationRequested` |
| `diagnostics/` | freeze rings, budgeted `sample`, `log config` with auto-revert, bundle + SHA-256 | `IncidentBundleReady` |

macOS OS helpers live in `sensor/platform/macos`: `proc_info`, `subprocess`, `cf_ref`, `macos_diagnostics_platform`.

All tests live flat in `sensor/tests/`: `ieso_tests` covers the portable core and actors and also builds on Linux;
`ieso_macos_tests` covers the macOS helpers and actors.

Known gaps:
- Spool compression is an interface only (`IdentityCodec`); zstd comes later.
- Baseline/drift diff (FR-13) and bundle signing aren't built yet.
