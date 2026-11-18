---
name: cause-crash
description: Crash DemoApp on purpose (EXC_BAD_ACCESS, a NULL-pointer write) during the Ieso demo and follow the incident to its investigation report. Use when the user says /cause-crash or wants to show crash detection.
disable-model-invocation: true
---

# Cause a crash

**What breaks:** `DemoApp` writes through a bad pointer at address 0x8 (`AppDelegate.faultCrash()`), giving `EXC_BAD_ACCESS` and `SIGSEGV`.

Needs the demo to be running (`/run-demo`): the sensor, and the backend with the netdemo profile. Run from the repo
root:

```sh
scripts/demo_fault.sh crash
```

The script:
1. closes any DemoApp and relaunches it with the fault;
2. waits until the incident reaches the control plane;
3. if `investigator-watch` is running, waits for its report and prints the root cause, then links to the evidence
   chain and the reasoning trace in Grafana.

Add `--no-report` to skip that wait. Report the script's output to the user as is: the incident id, what was
detected, the report line and the Grafana links.

## What to expect
- **Detected:** usually as `DemoApp+0x8875 EXC_BAD_ACCESS`, from macOS's crash report, with the full crash dump:
  the faulting frame and a NULL dereference at 0x8.
- **If macOS throttled the report** (after many crashes in a day it stops writing them): detected anyway from the
  exit signal, as `DemoApp SIGSEGV (no crash report)`. The investigation then has no stack and honestly says
  `unknown` with low confidence.
- **Report:** `app_bug` at about 0.90 when there's a crash dump.
- **Grafana:** a red crash marker, and the crash dump in the evidence chain.

## Notes
- **Limit:** don't crash it more than a handful of times before the presentation, or macOS starts throttling reports.
  The throttle eases over the day.
- **Cost:** with the watcher running, each run is one live Claude investigation, within the watcher's cap of 20 per
  hour. Incidents over the cap wait until it frees up.
