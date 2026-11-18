---
name: cause-hang
description: Hang DemoApp's main thread for 30 s during the Ieso demo and follow the incident to its investigation report. Use when the user says /cause-hang or wants to show hang detection.
disable-model-invocation: true
---

# Cause a hang

**What breaks:** `DemoApp` sleeps on its main thread for 30 s (`AppDelegate.faultHang()` → `Thread.sleep`), so the UI stops responding.

Needs the demo to be running (`/run-demo`): the sensor, and the backend with the netdemo profile. Run from the repo
root:

```sh
scripts/demo_fault.sh hang
```

The script:
1. closes any DemoApp and relaunches it with the fault;
2. waits until the incident reaches the control plane;
3. if `investigator-watch` is running, waits for its report and prints the root cause, then links to the evidence
   chain and the reasoning trace in Grafana.

Add `--no-report` to skip that wait. Report the script's output to the user as is: the incident id, what was
detected, the report line and the Grafana links.

## What to expect
- **Detected:** about 7 s after the hang starts, as 3 accessibility-probe timeouts in a row.
- **Stack sample:** the sensor then takes one with `sample`.
- **Report:** `app_bug` at about 0.90, from the hang stack: 2574 of 2574 samples in `AppDelegate.faultHang()`.
- **Grafana:** a light-blue hang marker, and the main-thread stack in the evidence chain. The app recovers by itself
  after 30 s.

## Notes
- **Accessibility:** needs Accessibility for the app that runs the sensor.
- **Sample budget:** the sensor takes at most 4 `sample` captures per hour. Past that, the hang has no stack and the
  report is `unknown`. Restarting the sensor resets the budget.
- **Cost:** with the watcher running, each run is one live Claude investigation, within the watcher's cap of 20 per
  hour. Incidents over the cap wait until it frees up.
