---
name: build-test
description: Build the Ieso sensor and run every test suite (C++ GoogleTest, investigator, sim, control plane), with sanitizers when memory or threading changed. Use after any code change, before reporting a task as done, and when a build or test fails and needs diagnosing.
---

# Build and test Ieso

Run from the repo root. Report the pass/fail counts per suite at the end; never report "done" with a failing suite.

## 1. C++ sensor (CMake presets: `debug`, `release`, `asan`, `tsan`)

CMake and Ninja come from MacPorts (`sudo port install cmake ninja`, in `/opt/local/bin`). The scripts add that
folder to `PATH` themselves (`scripts/lib/build_tools.sh`). For a raw `cmake` call, run
`export PATH="$PATH:/opt/local/bin"` first if `cmake` isn't found.

```sh
cmake --preset debug && cmake --build --preset debug     # configure once, then build
scripts/run_tests.py                                     # builds, then one compact block per suite + summary table
```

Useful `scripts/run_tests.py` flags:
- `--filter 'Spool|Bus'`: only suites whose name matches the regex;
- `--list`: list the suites and exit;
- `--no-build`: skip the rebuild;
- `--preset asan|tsan`: run against a sanitizer build.

Sanitizers are required when the change touches memory, pools, ring buffers or threads:

```sh
scripts/run_tests.py --preset asan     # ASan + UBSan (ASAN_OPTIONS=abort_on_error=1:detect_stack_use_after_return=1)
scripts/run_tests.py --preset tsan     # ThreadSanitizer (TSAN_OPTIONS=halt_on_error=1)
```

Other entry points:
- **One test:** `build/debug/sensor/tests/ieso_tests --gtest_filter='Suite.Name'`, or
  `ieso_macos_tests` for the macOS helpers and actors.
- **CTest directly:** `ctest --preset debug --output-on-failure`.
- **Core self-test:** `build/debug/sensor/host/ieso-sensor --selftest`. It runs the PII filter, then the spool,
  then replay, end to end.

## 2. Python suites

```sh
# investigator (venv is gitignored; create once)
python3 -m venv investigator/.venv && investigator/.venv/bin/pip install -r investigator/requirements-dev.txt
(cd investigator && .venv/bin/python -m pytest -q)

# sim (reuses the investigator venv; stdlib only)
(cd sim && ../investigator/.venv/bin/python -m pytest -q)

# control plane (its own venv; create once)
python3 -m venv backend/control-plane/.venv && backend/control-plane/.venv/bin/pip install -r backend/control-plane/requirements-dev.txt
(cd backend/control-plane && IESO_NO_DEFAULT_APP=1 .venv/bin/python -m pytest -q)
```

The Claude reasoner tests use a mocked SDK client. They need no API key and make no network calls.

## 3. End-to-end regressions (when the change crosses process boundaries)

| Changed | Run |
| --- | --- |
| collectors, anomaly or diagnostics actors | `scripts/smoke_test.sh hang crash` (also `leak network permission`) |
| cloud client, transport, backend, PII filter or spool | `scripts/e2e_backend.sh` |
| probes, control-plane policy, investigator | `scripts/e2e_investigation.sh` |

These need Docker Desktop and the Accessibility permission. The `/run-demo` skill covers the setup.

## 4. Reading failures

- **Compact runner output:** it shows only failing assertions, plus the last test that started when a suite crashes or
  times out. Re-run that one test with `--gtest_filter` to get the full output.
- **Warnings are errors:** the build uses `-Werror -Wall -Wextra -Wpedantic -Wshadow -Wconversion`.
  - `-Wshadow`: rename the inner variable.
  - `-Wconversion`: cast explicitly with `static_cast`.
- **Unused result:** `SRESULT` is `[[nodiscard]]`. To discard one, use `(void)call();  // why` with a comment that
  says why. Otherwise propagate it with `HS_RETURN_IF_FAILED`.
- **Exceptions:** `-fno-exceptions` is on, so never add `try` or `throw`. Use the non-throwing std APIs
  (`std::error_code` overloads).
- **ASan:** read the first `ERROR: AddressSanitizer` frame inside `sensor/`. It's usually a lifetime bug: an event
  or buffer outliving its pool, or a raw pointer kept past a callback.
- **TSan:** look for shared state touched outside the mailbox. Actors must only talk through the bus.
- **macOS suites failing on CI-like machines:** most likely the Accessibility permission (AX probe, dialogs) or a
  slow `log stream` start. Re-run the suite on its own before changing code.

## 5. Done when

All suites pass on `debug`, and on `asan` for memory or threading changes. Report the counts in this shape:
"C++ 102/102, investigator 21/21, sim 3/3, control plane 12/12", plus any e2e script you ran.
