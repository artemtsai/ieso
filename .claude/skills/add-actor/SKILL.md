---
name: add-actor
description: Create a new actor in the Ieso C++ sensor (collector, detector, diagnostics or egress component) that talks only through the event bus, follows docs/STYLEGUIDE.md, and is tested and registered in the host. Use whenever a new sensor capability needs its own actor.
---

# Add an actor to the sensor

An actor has one responsibility. It never calls another actor: it only subscribes to events on the bus and posts
events to it. Study an existing actor before writing: `sensor/actors/anomaly/` (portable, timer-driven) or
`sensor/actors/ui_observer/` (macOS, blocking OS loop in an `IEventSource`).

## 1. Read the rules first
- `CLAUDE.md`: design rules.
- `docs/STYLEGUIDE.md`: all 8 rules. They're mandatory.
- `docs/DESIGN.md` §7 (events ontology) and §8 (actor responsibility matrix). Confirm that no existing actor already
  owns this responsibility.

## 2. Files and class
- **Where:** `sensor/actors/<name>/<name>.hpp` and `<name>.cpp`, side by side with no subfolders, included as
  `"<name>/<name>.hpp"`.
- **Portable or macOS:** portable code lives in `namespace ieso`. macOS-only code lives in `namespace ieso::macos`
  and may use the helpers in `sensor/platform/macos/`.
- **Class:** `class <Name>Actor final : public Actor` (from `ieso/core/actor.hpp`).
- **Constructor:** `(EventBus& bus, EventFactory& factory, <deps>…, <Name>Options opts = {})`, with tunables in a
  `<Name>Options` struct that has defaults.
- **Fallible setup:** goes in `on_start(ActorContext& ctx)` or in a static `Create(...)` that returns `SRESULT`.
  Constructors never fail.

## 3. Bus only
- **Subscribing:** in `on_start`, call `subscribe<T>(ctx.bus, [this](const auto& e) { return on_x(e); })`. The base
  class keeps the RAII subscription token, and `on_stop` / `unsubscribe_all()` releases it.
- **Emitting:** `std::shared_ptr<T> ev; HS_RETURN_IF_FAILED(factory_.make<T>(ev));`, fill the fields, then
  `return bus_.post(std::move(ev));`. The factory allocates from the pmr pool, and events are immutable once posted.
- **Handlers:** return `SRESULT`. A routine-event handler must be cheap, because routine telemetry may be sampled or
  dropped under load.

## 4. Events
- Use types from `sensor/ontology/events.hpp` only.
- **A new event type needs:**
  - `IESO_EVENT_TRAITS(Name, Control|Incident|Routine, NeverDrop|DropOldest|Sample, egress)`;
  - a `fields()` implementation in `events.cpp`, where `free_text = true` marks untrusted text;
  - a row in the DESIGN §7 table;
  - a PII filter coverage test when `egress` is `true`.
- **Never dropped:** incidents and control events.
- **Leaving the Mac:** only the PII filter can construct `CloudEventSanitized`.

## 5. Threads and OS loops
- Blocking OS APIs (kqueue, FSEvents, AX run loops, subprocess pipes) go in an `IEventSource` (`start()` / `stop()`)
  owned by the actor. Give it its own thread, a `std::atomic<bool>` stop flag and bounded sleeps or timeouts (≤ 250
  ms), so `stop()` joins quickly.
- Retries are bounded. Use counters and back-off, as in `AxDialogSource`'s attach retry. Never use recursion
  (rule 7): use an explicit, size-capped queue.

## 6. Rules checklist (STYLEGUIDE.md)
- [ ] C++17 only, formatting through `{fmt}`.
- [ ] Doxygen on every file, class, struct and function, with `@file` and `@brief` through `@note`/`@warning`, at
  most 12 short sentences per tag.
- [ ] No `new`, `delete`, `malloc` or `free`; smart pointers own, references or `weak_ptr` observe. Raw pointers
  appear only at C API boundaries, wrapped in RAII (`CfRef`).
- [ ] Every function returns `SRESULT`. Discard only with `(void)` plus a comment.
- [ ] `HS_TRACE_*`, reporting a failure once at its origin.
- [ ] No exceptions, no recursion.
- [ ] All HTTP(S) through `ITransportClient` (libcurl, TLS 1.3 + mTLS); no other client.
- [ ] Budgets: under 1% CPU steady and under 50 MB RSS. Deep captures obey the observer-effect budget.

## 7. Build wiring
Add `<name>/<name>.cpp` to `ieso_actors` (portable) or `ieso_actors_macos` in `sensor/actors/CMakeLists.txt`.

## 8. Tests
- **The test file:** `sensor/tests/<name>_test.cpp`, using `test_util.hpp`: `Rig` (pools, `ManualClock`, factory,
  bus), `Runtime`, `Collector<T>` to capture emitted events, `count_of`, and `TempDir`.
- **Cover at least:**
  - the events it handles;
  - the events it emits, with field values;
  - overflow or drop behaviour of its inputs;
  - start and stop with no leaks (also run under ASan).
- **Register the test:** add it to `sensor/tests/CMakeLists.txt`, under `ieso_tests` (portable) or
  `ieso_macos_tests` (macOS).

## 9. Register and document
- **The host:** in `sensor/host/main.cpp`, add `HS_RETURN_IF_FAILED(runtime.add(std::make_shared<<Name>Actor>(bus,
  factory, …)));`. Add it to the `--selftest` wiring too if it takes part in that path.
- **The docs:** update the DESIGN §8 actor matrix and the actor list under `sensor/actors/` in CLAUDE.md.

## 10. Finish
Run `/build-test`, including `--preset asan` for anything with buffers or threads, and report the counts.
