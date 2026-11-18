---
name: add-event
description: Add a new event type to the Ieso events ontology (sensor/ontology/events.hpp) with the right class, overflow policy and egress flag, PII-safe fields, and every downstream consumer updated (PII filter, cloud client, control plane, investigator, Grafana, DESIGN.md §7). Use whenever an actor needs to emit something no existing event describes.
---

# Add an event type

All events live in one place: `sensor/ontology/events.hpp` (declarations) and `sensor/ontology/events.cpp`
(`fields()`), compiled into `ieso_core` and included as `"ontology/events.hpp"`. Before adding one, check
DESIGN.md §7: an existing event with one more field is often the better change.

## 1. Pick the routing traits (DESIGN §7, CLAUDE.md)
| Trait | Choose |
| --- | --- |
| `EventClass` | `Control` (bootstrap, config, transport; never dropped), `Incident` (anomalies, diagnostics; never dropped), `Routine` (telemetry; may be sampled or dropped, drops are counted) |
| `OverflowPolicy` | `NeverDrop` for Control and Incident; `DropOldest` for snapshots where only the latest matters; `Sample` for high-volume streams like logs |
| egress | `true` only if the data must reach the backend. It then goes through the PII filter; the only way out is `CloudEventSanitized`. |

## 2. Declare it in `events.hpp`
```cpp
/// @brief <One line: what happened, who emits it>.
struct <Name> final : Event {
  IESO_EVENT_TRAITS(<Name>, Incident, NeverDrop, true)
  std::int64_t pid = 0;   ///< Process id.
  std::string detail;     ///< <What it holds; say "free text" if it may contain user data>.
  /// @copydoc Event::fields
  SRESULT fields(Fields& out) const override;
};
```
- Use plain value members (`std::string`, `std::int64_t`, `double`, `bool`) with defaults and Doxygen on each.
- Events are immutable once posted. The `EventFactory` allocates them, and the header (id, ts, class, egress) is set
  for you.
- **Add the type to `AllEvents`**, the `TypeList` at the end of `events.hpp`. The PII filter subscribes at compile
  time to exactly the egress-eligible types in that list, so a type that's missing from it never leaves the Mac.

## 3. Implement `fields()` in `events.cpp`, which decides how the PII filter treats every value
| Helper | Use for | PII filter does |
| --- | --- | --- |
| `add(out, "k", str)` | sensor-collected strings (paths, names, codes) | redact (home paths, user names, emails, IP → hash, secrets) |
| `add(out, "k", str, true)` | **free text** from the user or the app (dialog text, log messages, window titles) | `redact_free_text`: redacts and truncates to 512 chars |
| `add_verbatim(out, "k", str)` | sensor-generated identifiers (hashes, request/incident ids, probe ids, own file refs) | keeps as-is. Never use it for anything a user or app wrote. |
| `add`, `add_u`, `add_d`, `add_b` | numbers and booleans | keeps as-is |

When unsure, use redact, or free text. A field that's redacted by mistake is easy to fix later; a leak can't be
taken back.

## 4. Downstream consumers (egress events)
- **Cloud client:** the event ships as CloudEvent type `com.ieso.<Name>`, and `Incident` class is sent at once,
  not batched. Nothing to change unless it needs special OTLP mapping in `otlp_json`.
- **Control plane:** for a new incident kind, add it to `INCIDENT_TYPES` in `backend/control-plane/app/main.py`.
  Otherwise it's indexed as `other`.
- **Investigator:** if it's a new symptom, extend `classify()` in `investigator/ieso_investigator/fleet_diff.py`,
  and the rules in `reasoners.py`.
- **Grafana:** add the type to the incidents panel's `event_type=~"…"` regex and give it an annotation with a
  root-cause color in `backend/grafana/provisioning/dashboards/ieso-endpoint.json`.
- **Sim fleet:** if the investigator should see it fleet-wide, emit it in `sim/ieso_sim/fleet.py`.

## 5. Tests
- **The emitting actor's test:** posts the event and checks its fields (`Collector<T>`, from `test_util.hpp`).
- **For egress types, `sensor/tests/pii_filter_test.cpp`:**
  - `PiiFilter.SubscribesOnlyToEgressTypes` still holds;
  - add a case showing the free-text fields are redacted and truncated, and the verbatim fields survive unchanged;
  - see `VerbatimFieldsKept` for the pattern.
- **Python:** control plane and investigator tests when those layers changed.

## 6. Docs and finish
- Add a row to the DESIGN.md §7 table: event, category, class/overflow, egress, payload.
- Run `/build-test`. The C++ suites catch a type missing from `AllEvents` through the PII filter tests.
