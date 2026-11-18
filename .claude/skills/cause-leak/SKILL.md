---
name: cause-leak
description: Make DemoApp leak memory (+20 MB/s) during the Ieso demo until the sensor flags the anomaly, then follow it to its investigation report. Use when the user says /cause-leak or wants to show resource anomaly detection.
disable-model-invocation: true
---

# Cause a memory leak

**What breaks:** `DemoApp` keeps 2 MB every 100 ms (about +20 MB/s, touched so it stays resident). The script closes the app once the sensor has flagged it.

Needs the demo to be running (`/run-demo`): the sensor, and the backend with the netdemo profile. Run from the repo
root:

```sh
scripts/demo_fault.sh leak
```

The script:
1. closes any DemoApp and relaunches it with the fault;
2. waits until the incident reaches the control plane;
3. if `investigator-watch` is running, waits for its report and prints the root cause, then links to the evidence
   chain and the reasoning trace in Grafana.

Add `--no-report` to skip that wait. Report the script's output to the user as is: the incident id, what was
detected, the report line and the Grafana links.

## What to expect
- **Detected:** as `rss_growth` after about 20–30 s, from the RSS slope in the flight recorder.
- **Report:** usually `app_bug` with moderate confidence (about 0.45–0.65). Without a heap capture there's no proof
  of *where* the memory goes, and the report says so.
- **Grafana:** a dark-orange resource marker, and the memory chart climbing to about 500–600 MiB.

## Notes
- **Timing:** takes the longest of the five, up to about 2 minutes including the report.
- **Cost:** with the watcher running, each run is one live Claude investigation, within the watcher's cap of 20 per
  hour. Incidents over the cap wait until it frees up.
