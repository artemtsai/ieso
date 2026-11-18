---
name: cause-network
description: Break DemoApp's backend connection through the 'CorpGuard' TLS-inspecting proxy during the Ieso demo and follow the remote investigation (fleet diff, signed probes) to its report. Use when the user says /cause-network or wants to show the main remote-investigation story.
disable-model-invocation: true
---

# Cause a network failure (TLS interception)

**What breaks:** `DemoApp` calls its backend `https://app-backend:9443` through the corporate proxy. The proxy re-signs TLS with "CorpGuard TLS Inspection CA", the app (which pins its own backend CA) rejects the certificate, and the user sees *Cannot reach server*.

Needs the demo to be running (`/run-demo`): the sensor, and the backend with the netdemo profile. Run from the repo
root:

```sh
scripts/demo_fault.sh network
```

The script:
1. closes any DemoApp and relaunches it with the fault;
2. waits until the incident reaches the control plane;
3. if `investigator-watch` is running, waits for its report and prints the root cause, then links to the evidence
   chain and the reasoning trace in Grafana.

Add `--no-report` to skip that wait. Report the script's output to the user as is: the incident id, what was
detected, the report line and the Grafana links.

## What to expect
- **Detected:** the error dialog, about 5 s after launch.
- **Investigation:**
  1. The fleet diff finds `proxy=corpguard-swg 5.2` (42 of 49 endpoints affected, lift 3.9x).
  2. Claude asks for `net.config` and `net.synthetic_tls`.
  3. The control plane signs both; the sensor verifies the signatures and runs them.
  4. Through the proxy, the backend's certificate is issued by CorpGuard; direct, it's issued by DemoApp Backend CA.
- **Report:** `tls_interception` at about 0.85, with the fix (bypass the backend in TLS inspection).
- **Grafana:** a purple network marker. The reasoning trace shows the probe results and Claude's thinking summary.

## Notes
- **Netdemo profile:** needs it (`app-backend`, `corp-proxy`), and `ep-demo` registered with the proxy attribute. Both
  are part of `/run-demo`.
- **Probe budget:** each run uses 2 probes of the 20 per hour. If they come back `429`, see `/run-demo`'s pitfalls.
- **Cost:** with the watcher running, each run is one live Claude investigation, within the watcher's cap of 20 per
  hour. Incidents over the cap wait until it frees up.
