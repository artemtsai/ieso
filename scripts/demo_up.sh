#!/bin/bash
# Starts the whole Ieso demo on this Mac: the backend (Grafana, control plane, the always-on investigator, the
# demo network), the simulated fleet, this Mac's inventory entry and the sensor, in the background.
#
#   scripts/demo_up.sh            # then click DemoApp's fault buttons, or: scripts/demo_fault.sh <fault>
#   scripts/demo_up.sh --no-app   # same, without opening DemoApp at the end (for scripted runs)
#
# Safe to run again: each step skips what's already done. Stop everything with scripts/demo_down.sh.
# Env: IESO_PROBES_PER_ENDPOINT_HOUR (default 20) raises the control plane's hourly probe limit for rehearsals.
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib/build_tools.sh"   # cmake/ninja from MacPorts (/opt/local/bin) or Homebrew

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SENSOR="$ROOT/build/debug/sensor/host/ieso-sensor"
APP="$ROOT/build/demo-app/DemoApp.app"
CERTS="$ROOT/backend/certs/out"
DATA="/tmp/ieso-demo"
COMPOSE=(docker compose -f "$ROOT/backend/docker-compose.yml" --profile netdemo --profile tools --profile watch)
EP="ep-demo"
OPEN_APP=1
[ "${1:-}" = "--no-app" ] && OPEN_APP=0

step() { printf '\033[1m==> %s\033[0m\n' "$1"; }
die() { printf '\033[31merror:\033[0m %s\n' "$1"; exit 1; }

# ---- 1. preflight
step "Preflight"
if pgrep -f "ieso-sensor --target DemoApp" >/dev/null; then
  die "a sensor is already running (pid $(pgrep -f 'ieso-sensor --target DemoApp' | head -1)). Stop it first: scripts/demo_down.sh"
fi
if ! docker info >/dev/null 2>&1; then
  echo "    starting Docker Desktop..."
  open -a Docker || die "Docker Desktop is not installed"
  for _ in $(seq 1 90); do docker info >/dev/null 2>&1 && break; sleep 1; done
  docker info >/dev/null 2>&1 || die "Docker did not start within 90 s"
fi
echo "    Docker: ok"
if [ ! -x "$SENSOR" ]; then
  need_build_tools || die "install CMake and Ninja first (see above)"
  echo "    building the sensor (first run takes a few minutes)..."
  (cd "$ROOT" && cmake --preset debug >/dev/null && cmake --build --preset debug >/dev/null) || die "sensor build failed"
fi
echo "    sensor: $SENSOR"
[ -d "$APP" ] || "$ROOT/demo-app/build.sh" >/dev/null || die "DemoApp build failed"
echo "    DemoApp: $APP"
[ -f "$CERTS/endpoint.p12" ] && [ -f "$CERTS/probe-signing.pub.pem" ] || "$ROOT/backend/certs/gen_certs.sh" "$EP" >/dev/null || die "certificate generation failed"
echo "    certificates: $CERTS"
echo "    reminder: the app running this script needs Accessibility (System Settings > Privacy & Security >"
echo "    Accessibility) for hang and dialog detection."

# ---- 2. backend
step "Backend (Docker Compose, project 'ieso')"
"${COMPOSE[@]}" up -d --build >/tmp/ieso-demo-compose.log 2>&1 || die "docker compose up failed (see /tmp/ieso-demo-compose.log)"
cp_ok() { curl -sf --max-time 5 --cacert "$CERTS/ca.pem" --cert-type P12 --cert "$CERTS/endpoint.p12:ieso" https://localhost:8443/healthz >/dev/null; }
for _ in $(seq 1 90); do cp_ok && break; sleep 1; done
cp_ok || die "control plane not reachable on https://localhost:8443"
echo "    services up; control plane healthy (mTLS)"

# ---- 3. fleet and this Mac's inventory
step "Fleet: 200 simulated endpoints + this Mac"
"${COMPOSE[@]}" run --rm -T sim </dev/null 2>/dev/null | grep -E "imported|fleet:" | sed 's/^/    /'
"${COMPOSE[@]}" exec -T control-plane python -c 'import urllib.request,json; urllib.request.urlopen(urllib.request.Request("http://localhost:8000/v1/admin/endpoints/ep-demo", method="PUT", headers={"Content-Type":"application/json"}, data=json.dumps({"simulated":False,"attributes":{"os_build":"25G83","hardware_model":"Mac15,6","arch":"arm64","proxy":"corpguard-swg 5.2","vpn":"none","dlp_extension":"none","edr_agent":"edr-agent 7.5","locale":"en_US","app_version":"1.4.2"}}).encode()))' \
  || die "could not register ep-demo in the inventory"
echo "    ep-demo registered (stand-in for the MDM/EDR inventory: behind the CorpGuard proxy)"

# ---- 4. sensor, in the background
step "Sensor"
mkdir -p "$DATA"
nohup "$SENSOR" --target DemoApp --data-dir "$DATA" --log-level info --endpoint-id "$EP" --tls-dir "$CERTS" \
  --backend https://localhost:4318 --control-plane https://localhost:8443 \
  --probe-key "$CERTS/probe-signing.pub.pem" --app-backend https://app-backend:9443/health \
  --demo-proxy http://localhost:8889 --app-backend-direct localhost:9443 >"$DATA/sensor.log" 2>&1 &
echo $! >"$DATA/sensor.pid"
for _ in $(seq 1 30); do grep -q "backend reachable: online" "$DATA/sensor.log" 2>/dev/null && break; sleep 1; done
if ! grep -q "backend reachable: online" "$DATA/sensor.log"; then
  tail -20 "$DATA/sensor.log"; die "the sensor did not come online (log: $DATA/sensor.log)"
fi
echo "    online over TLS 1.3 + mTLS (pid $(cat "$DATA/sensor.pid"), log: $DATA/sensor.log)"

# ---- 5. DemoApp, ready to click
# Launched with the demo-network arguments, so its "Network failure" button goes through the CorpGuard proxy (the
# TLS-interception story) instead of calling an unreachable host. No --fault: nothing breaks until you click.
if [ $OPEN_APP -eq 1 ]; then
  step "DemoApp"
  if pgrep -x DemoApp >/dev/null; then
    echo "    already open"
  else
    open -n "$APP" --args --backend https://app-backend:9443/health --backend-ca "$CERTS/demo/backend-ca.pem" \
      --proxy http://localhost:8889
    echo "    opened: click a button to break it (hang, crash, leak, network, permission)"
  fi
fi

# ---- 6. summary
MODE="$("${COMPOSE[@]}" run --rm -T investigator doctor </dev/null 2>/dev/null | grep "^ANTHROPIC_API_KEY")"
step "Ready"
cat <<EOF
    Grafana:      http://localhost:3000/d/ieso-endpoint/ieso-endpoint-timeline?orgId=1&var-endpoint=$EP&from=now-30m&to=now
    Investigator: always on (investigator-watch). ${MODE:-ANTHROPIC_API_KEY: unknown}
                  (set: live Claude; not set: the offline rule reasoner)
    Break the app: click a button in the DemoApp window, or
                   scripts/demo_fault.sh crash | hang | leak | network | permission
    Sensor log:    tail -f $DATA/sensor.log
    Stop:          scripts/demo_down.sh
EOF
