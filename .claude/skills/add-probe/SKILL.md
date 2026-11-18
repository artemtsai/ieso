---
name: add-probe
description: Add a new remote diagnostic probe to Ieso end to end - read-only implementation on the endpoint, compiled-in and control-plane allowlists, signature/budget enforcement, output parsing and reasoner support in the investigator, tests and docs. Use whenever the investigator needs a new kind of evidence from an endpoint.
---

# Add a remote probe

A probe is an **ID**, never a command. It's read-only and time-boxed, and its output is capped. A request passes
three independent checks: the investigator's pre-check, the control plane's policy and signature, and the
endpoint's own verification. A new probe must be added to **all** of them, or it gets refused somewhere along the
way. That's by design.

## 0. Is it allowed?
- **Read-only:** it changes nothing on the Mac. No writes, installs, kills or config changes.
- **Bounded:** it finishes in seconds (subprocesses run under a timeout; 10 s is the house value) and emits ≤ 8 KB.
- **Privilege:** say what it needs (user, FDA or root) in DESIGN §10.3. A probe that needs root must fail cleanly
  without it (`PermissionDenied`) and never trigger an authorization prompt.
- **Cost:** a costly probe (one that pauses the app or captures a lot) counts against the observer-effect budget.
- **The ID:** pick `<area>.<name>`, e.g. `perm.tcc` or `env.profiles` (DESIGN §10.3 lists planned ones).

## 1. Endpoint (C++)
1. **Allowlist:** add the ID to `kProbeAllowlist` in `sensor/actors/diagnostics/diagnostics.cpp`. It's compiled in,
   and it's the endpoint's own last line of defence.
2. **Implementation:** add it to the `run_probe` dispatch in `sensor/platform/macos/src/macos_diagnostics_platform.cpp`.
   - Shell tools: `append_command({"/usr/bin/<tool>", …}, "<label>", out)`. It uses `Subprocess::Run` with a 10 s
     timeout, absolute paths only, and a fixed argv. Never build the argv from request data.
   - Structured output: use `JsonWriter`. `net.synthetic_tls` is the reference.
   - `run_probe` already caps the output at `kMaxProbeOutput` (8 KB) and sets `exit_status`.
   - Anything taken from the probe request must be validated first.
3. **Tests:** if the probe has a fixed shape, also add it to `FakePlatform::run_probe` in
   `sensor/tests/diagnostics_test.cpp`, and extend `Diagnostics.ProbePolicy` so the new ID is accepted and a
   near-miss ID is refused.

Signature verification (ECDSA P-256, pinned key), the endpoint/expiry/replay checks and the budget (4 per incident,
20 per hour) are handled for every probe by `DiagnosticsActor::check_probe`. Don't add per-probe bypasses.

## 2. Control plane (Python)
- Add the ID to `PROBE_ALLOWLIST` in `backend/control-plane/app/main.py`. The signing, budget and scoping are
  shared by every probe.
- Extend `backend/control-plane/tests/test_probes.py` if the policy treats the new probe differently.

## 3. Investigator (Python)
- **The probe list:** add the ID to `PROBES` in `investigator/ieso_investigator/reasoners.py`. The decision JSON
  schema's enum comes from it, so Claude can only propose IDs on this list.
- **Parser:** add `parse_<name>(output) -> facts` in `evidence.py` and register it in `PARSERS`. Keep the facts small
  and comparable, like `issuer_mismatch`.
- **Trace line:** add a readable one-liner in `facts_text()`, which feeds the Grafana reasoning trace.
- **Rule reasoner:** teach `RuleReasoner` when to ask for the probe and how to read its facts, so the offline mode
  keeps the same capability.
- **Claude:** no prompt change is usually needed, since the context lists `allowed_probes`. If the facts need
  interpreting, add one line to `SYSTEM_PROMPT`.
- **Tests:** add a fixture output to `PROBE_OUTPUTS` in `investigator/tests/conftest.py`, plus a test that the rule
  reasoner requests it and reaches the right cause.

## 4. Docs
- DESIGN.md §10.3 (what it answers, privilege, cost), and the probe list in `docs/AIREASONING.md` and
  `investigator/README.md`.
- If it adds a new kind of finding, add a row to the results table in AIREASONING.md once it has been seen live.

## 5. Verify
1. Run `/build-test` (C++, investigator, control plane).
2. Do one live run. Trigger an incident for which the investigator should pick the probe; `/run-demo` covers the
   setup. Then check:
   - the sensor log shows `running probe <id> … (signature verified)`;
   - the result appears in the reasoning trace;
   - an off-allowlist variant is refused with a reason.
