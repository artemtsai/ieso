---
name: stop-demo
description: Stop everything the Ieso demo started - DemoApp instances, every ieso-sensor process, the always-on investigator watcher (no more paid Claude calls) and the whole docker compose stack - then verify nothing is left running. Use after /run-demo, a rehearsal or an e2e session.
disable-model-invocation: true
---

# Stop the Ieso demo

Run from the repo root. Stopping comes in two strengths:
- **Stop** (the default): containers are removed, but their data volumes are kept. Incidents, reports, bundles,
  Loki history and Grafana all survive.
- **Wipe:** also deletes the volumes (`-v`). Only do this when the user asks for a clean slate. It can't be undone.

Shortcut: `scripts/demo_down.sh [--wipe]` runs steps 1–3 in one go.

## 1. App and sensor (local processes)
```sh
pkill -x DemoApp                                  # every DemoApp instance, including any opened by hand
pkill -TERM -f "ieso-sensor --target"           # every sensor; SIGTERM lets it checkpoint the flight recorder
sleep 2; pgrep -fl ieso-sensor && pkill -KILL -f "ieso-sensor --target"   # only if one ignored SIGTERM
```
SIGTERM matters: on a clean shutdown the sensor writes its flight-recorder checkpoint (NFR-11) and flushes the
spool. Use `-KILL` only when a process is still there after 2 s.

## 2. Watcher first, then the stack
The watcher makes live Claude calls for every new incident. Stop it before anything else in the backend, so a late
incident can't start a paid investigation during shutdown.
```sh
cd backend
docker compose --profile watch stop investigator-watch
docker compose --profile netdemo --profile tools --profile watch down --remove-orphans   # add -v only to wipe
cd ..
```
All three profiles must be named. Otherwise `down` leaves the netdemo proxy, the app backend or the watcher running.

## 3. Verify nothing is left
```sh
pgrep -fl "DemoApp|ieso-sensor" || echo "no local processes"
docker compose -f backend/docker-compose.yml --profile netdemo --profile tools --profile watch ps --format '{{.Service}}' | grep . || echo "no containers"
lsof -nP -iTCP:3000,4318,8443,8889,9443 -sTCP:LISTEN 2>/dev/null || echo "demo ports free"
```
Report each line's result. If a port is still in use, name the process holding it. Don't kill anything that the demo
didn't start.

## 4. Optional cleanup (only when asked)
- **Scratch data:** sensor data directories from manual runs and scripts: `/tmp/ieso-demo`, `/tmp/ieso-manual`,
  `/tmp/ieso-e2e.*`, `/tmp/ieso-inv.*`, `/tmp/ieso-smoke.*`. They hold local bundles and spools; delete them
  only if the user agrees.
- **Crash reports:** DemoApp's own reports in `~/Library/Logs/DiagnosticReports/` belong to macOS. Leave them alone.

## Notes
- **Probe limit:** a raised `IESO_PROBES_PER_ENDPOINT_HOUR` disappears with the containers. The next `up` without
  the variable is back at 20 per hour.
- **Bringing it back:** use `/run-demo`. After a plain stop (no wipe), the fleet and earlier reports are still
  there, so re-importing the sim is harmless: events are deduped by ID.
