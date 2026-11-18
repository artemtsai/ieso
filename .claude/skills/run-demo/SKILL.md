---
name: run-demo
description: Run the full Ieso demo by hand - backend stack, sensor, DemoApp faults, Grafana and the AI investigator - then tear it down. Use to rehearse or give the live presentation, or to check a change end to end in the real UI.
disable-model-invocation: true
---

# Run the Ieso demo

This starts Docker containers and the sensor. With an API key set, it also makes paid Claude calls. Run every
command from the repo root unless a step says otherwise.

Shortcut: `scripts/demo_up.sh` runs steps 0–2 (preflight, backend, sensor in the background) in one go.

## 0. Preflight
- [ ] **Docker:** Docker Desktop is running (`docker info`).
- [ ] **Accessibility:** granted to the app running the commands (Terminal or VS Code), under System Settings →
  Privacy & Security → Accessibility. The hang probe and dialog capture need it.
- [ ] **Certificates:** `backend/certs/out/` exists. If it doesn't, run `backend/certs/gen_certs.sh ep-demo` (it's
  idempotent).
- [ ] **Built:** `cmake --build --preset debug` and `demo-app/build.sh`.
- [ ] **No stale sensor:** `pgrep -fl ieso-sensor` prints nothing. Two sensors with the same endpoint ID double
  every incident and compete for probe requests.
- [ ] **API key, optional:** the key is in `backend/.env` (`ANTHROPIC_API_KEY=...`, gitignored). Without it, use the
  rule reasoner or `--reasoner replay`. Check with
  `docker compose -f backend/docker-compose.yml --profile tools run --rm investigator doctor --live`.

## 1. Backend
```sh
cd backend
docker compose --profile netdemo --profile tools up -d --build
docker compose --profile tools run --rm sim                      # import the simulated fleet (200 endpoints)
docker compose exec -T control-plane python -c 'import urllib.request,json; urllib.request.urlopen(urllib.request.Request("http://localhost:8000/v1/admin/endpoints/ep-demo", method="PUT", headers={"Content-Type":"application/json"}, data=json.dumps({"simulated":False,"attributes":{"os_build":"25G83","hardware_model":"Mac15,6","arch":"arm64","proxy":"corpguard-swg 5.2","vpn":"none","dlp_extension":"none","edr_agent":"edr-agent 7.5","locale":"en_US","app_version":"1.4.2"}}).encode()))'
docker compose --profile watch up -d investigator-watch          # optional: investigates every new incident
cd ..
```
Optional: set `IESO_PROBES_PER_ENDPOINT_HOUR=60` before `up` to raise the hourly probe limit for rehearsals. The
default is 20, and any plain `up` without the variable resets it.

## 2. Sensor (its own terminal; Ctrl-C stops it)
```sh
C=backend/certs/out
./build/debug/sensor/host/ieso-sensor --target DemoApp --data-dir /tmp/ieso-demo --log-level info \
  --endpoint-id ep-demo --tls-dir $C --backend https://localhost:4318 --control-plane https://localhost:8443 \
  --probe-key $C/probe-signing.pub.pem --app-backend https://app-backend:9443/health \
  --demo-proxy http://localhost:8889 --app-backend-direct localhost:9443
```
Wait for `backend reachable: online` and `collector TLSv1.3 / control plane TLSv1.3`.

## 3. Faults (one per launch; `pkill -x DemoApp` before the next one)
Shortcut: `/cause-crash`, `/cause-hang`, `/cause-leak`, `/cause-network`, `/cause-permission`, or `scripts/demo_fault.sh <fault>`.
They also wait for the incident and the report.

```sh
APP=build/demo-app/DemoApp.app; C=backend/certs/out
open -n $APP --args --fault network --after 4 --backend https://app-backend:9443/health \
  --backend-ca $C/demo/backend-ca.pem --proxy http://localhost:8889        # TLS interception by "CorpGuard"
open -n $APP --args --fault permission --after 4                           # privacy-protected file
open -n $APP --args --fault crash --after 4                                # EXC_BAD_ACCESS at 0x8
open -n $APP --args --fault hang --after 4                                 # 30 s main-thread sleep
open -n $APP --args --fault leak --after 4                                 # +20 MB/s; pkill after the anomaly
```
The network fault needs all three extra arguments. Without them the app calls an unreachable host instead.

## 4. What to show
- **Grafana** at http://localhost:3000 (no login). Open "Ieso - endpoint timeline" and pick `ep-demo`.
  - **Metric charts:** colored incident markers. Purple is network, yellow is permission, red is crash, light blue is
    hang, dark orange is resource.
  - **Investigation reports table:**
    - root cause and confidence colors;
    - click an **Incident** or **Root cause** for its evidence chain;
    - click a **Reasoner** for the round-by-round trace with Claude's thinking summaries.
  - **Incidents and sanitized events:** what left the Mac. No user names, home paths or IP addresses.
- **Control plane over mTLS:**
  ```sh
  C=backend/certs/out; curl -s --cacert $C/ca.pem --cert-type P12 --cert $C/endpoint.p12:ieso \
    "https://localhost:8443/v1/incidents?endpoint=ep-demo&limit=5" | python3 -m json.tool
  ```
- **The investigator by hand**, when the watcher isn't running (from `backend/`):
  ```sh
  docker compose --profile tools run --rm investigator investigate --latest --endpoint ep-demo                 # Claude
  docker compose --profile tools run --rm investigator investigate --latest --endpoint ep-demo --reasoner rule # offline
  docker compose --profile tools run --rm investigator investigate --incident <id> --reasoner replay           # recording
  ```
  While it runs, the sensor terminal shows `probe request … received` and then `running probe … (signature verified)`.
- **Scripted alternative:** `scripts/e2e_investigation.sh` runs the network scenario through rule, replay and live
  Claude, asserting each one. It pauses the watcher while it runs.

## 5. Pitfalls seen in practice
| Symptom | Cause | Fix |
| --- | --- | --- |
| Probes rejected with `429 probe budget exhausted`, low-confidence report | 20 probes per endpoint per hour used up | wait, or run `IESO_PROBES_PER_ENDPOINT_HOUR=60 docker compose … up -d control-plane` |
| Incidents appear twice, probe checks fail | a second sensor with the same endpoint ID | `pgrep -fl ieso-sensor`; keep one |
| Hang report has no stack | sampling budget (4 per hour) spent | rehearse less, or restart the sensor (the budget is in memory) |
| A loop over `docker compose run` stops after one item | `run` consumes stdin | `docker compose run --rm -T … </dev/null` |
| The dialog isn't detected on the first launch | the app was still launching when AX attached | already retried for 10 s; if it persists, check Accessibility |
| e2e checks fail while the watcher runs | watcher and script race for the same incident | the script pauses `investigator-watch`; don't start it mid-run |

## 6. Teardown (or run `/stop-demo`, which also verifies nothing is left)
```sh
pkill -x DemoApp; pkill -TERM -f "ieso-sensor --target DemoApp"
cd backend && docker compose --profile netdemo --profile tools --profile watch down    # add -v to wipe all data
```

## 7. Presentation rehearsal (Thursday)
1. Start everything 15 minutes early. Check `doctor --live`, then trigger and investigate one network fault to warm
   up (images, Loki, Grafana).
2. Live order:
   - **network:** the main story, about 4 minutes. Show the fleet diff, the signed probes, the CorpGuard vs DemoApp
     issuer evidence, the report, then the trace.
   - **crash**, then **hang**: about 2 minutes each, showing the crash dump and the hang stack.
3. Fallbacks:
   - if the API or credits fail, use `--reasoner replay` (labeled as a replay) or `--reasoner rule`;
   - if a dialog is missed, relaunch the fault;
   - if the backend fails, run `scripts/e2e_investigation.sh` and show its saved reports.
