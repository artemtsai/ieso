---
name: cause-permission
description: Make DemoApp hit a macOS privacy denial (reading a protected file) during the Ieso demo and follow the incident to its investigation report. Use when the user says /cause-permission or wants to show permission-failure detection.
disable-model-invocation: true
---

# Cause a permission denial

**What breaks:** `DemoApp` tries to read `~/Library/Messages/chat.db`. macOS privacy protection (TCC) refuses it, and the app shows *Permission denied*.

Needs the demo to be running (`/run-demo`): the sensor, and the backend with the netdemo profile. Run from the repo
root:

```sh
scripts/demo_fault.sh permission
```

The script:
1. closes any DemoApp and relaunches it with the fault;
2. waits until the incident reaches the control plane;
3. if `investigator-watch` is running, waits for its report and prints the root cause, then links to the evidence
   chain and the reasoning trace in Grafana.

Add `--no-report` to skip that wait. Report the script's output to the user as is: the incident id, what was
detected, the report line and the Grafana links.

## What to expect
- **Detected:** the error dialog, about 5 s after launch. The home path appears as `/Users/<user>/…`, because the
  PII filter redacts the user name before anything leaves the Mac.
- **Report:** `permission_denied` at about 0.85. It usually uses `env.extensions` to rule out a DLP extension.
- **Grafana:** a yellow permission marker.

## Notes
- **Accessibility:** needs Accessibility for the app that runs the sensor.
- **Full Disk Access:** if your terminal has it, DemoApp may be able to read the file, and nothing fails. The script
  then times out with no incident.
- **Cost:** with the watcher running, each run is one live Claude investigation, within the watcher's cap of 20 per
  hour. Incidents over the cap wait until it frees up.
