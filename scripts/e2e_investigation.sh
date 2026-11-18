#!/bin/bash
# End-to-end remote investigation of a network failure (build step 4, DESIGN.md §13 demo step 3).
#
#   scripts/e2e_investigation.sh [--down]
#
# 1. Starts the backend with the netdemo profile (app-backend + "CorpGuard" TLS-inspecting proxy) and the tools.
# 2. Imports the simulated fleet (200 endpoints) and registers this Mac (ep-demo) in the inventory.
# 3. Runs ieso-sensor with probe verification (pinned ECDSA key) and the demo app's network fault through the proxy:
#    the app pins its backend CA, the proxy re-signs TLS, the user sees "Cannot reach server".
# 4. For each reasoner mode, a fresh incident is investigated with no customer involved:
#      rule    always (offline, no key)
#      replay  when investigator/recordings/network-tls-interception.json exists (recorded Claude session)
#      claude  only when ANTHROPIC_API_KEY is set (live); add IESO_RECORD=1 to save a recording for replay
#    Every mode must conclude tls_interception with signed probes verified and executed on the endpoint.
# Needs Docker Desktop and the Accessibility permission (dialog detection), like scripts/e2e_backend.sh.
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib/build_tools.sh"   # cmake/ninja from MacPorts (/opt/local/bin) or Homebrew

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SENSOR="$ROOT/build/debug/sensor/host/ieso-sensor"
APP="$ROOT/build/demo-app/DemoApp.app"
CERTS="$ROOT/backend/certs/out"
EP="ep-demo"
DATA="${IESO_E2E_DIR:-$(mktemp -d /tmp/ieso-inv.XXXXXX)}"
RECORDING="$ROOT/investigator/recordings/network-tls-interception.json"
COMPOSE=(docker compose -f "$ROOT/backend/docker-compose.yml" --profile netdemo --profile tools)
# Optional key file (gitignored): loads ANTHROPIC_API_KEY without it ever being printed.
if [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -f "$ROOT/backend/.env" ]; then set -a; . "$ROOT/backend/.env"; set +a; fi

need_build_tools || exit 2
{ [ -d "$ROOT/build/debug" ] || cmake --preset debug >/dev/null; } && cmake --build --preset debug >/dev/null || exit 2
[ -d "$APP" ] || "$ROOT/demo-app/build.sh" >/dev/null || exit 2
[ -f "$CERTS/probe-signing.pub.pem" ] && [ -f "$CERTS/corpguard/mitmproxy-ca.pem" ] ||
  "$ROOT/backend/certs/gen_certs.sh" "$EP" >/dev/null || exit 2
docker info >/dev/null 2>&1 || { echo "Docker is not running (open -a Docker)"; exit 2; }

cp_api() { curl -s --cacert "$CERTS/ca.pem" --cert-type P12 --cert "$CERTS/endpoint.p12:ieso" "https://localhost:8443$1"; }
cp_admin() {  # cp_admin METHOD PATH [JSON]: internal admin API, reached from inside the backend network only
  "${COMPOSE[@]}" exec -T control-plane python -c '
import sys, urllib.request
m, p = sys.argv[1], sys.argv[2]
body = sys.argv[3].encode() if len(sys.argv) > 3 else None
r = urllib.request.Request("http://localhost:8000" + p, data=body, method=m, headers={"Content-Type": "application/json"})
print(urllib.request.urlopen(r, timeout=30).read().decode())' "$@"
}
wait_for() { local end=$((SECONDS + $1)); shift; while [ $SECONDS -lt $end ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
FAILS=0
check() {
  local d="$1"; shift
  if wait_for "$@"; then printf '  \033[32mPASS\033[0m %s\n' "$d"; else printf '  \033[31mFAIL\033[0m %s\n' "$d"; FAILS=$((FAILS + 1)); fi
}
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
jq_py() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); $1" "$2"; }

network_incidents() {  # newest-first ids of network-looking dialogs on ep-demo
  cp_api "/v1/incidents?endpoint=$EP&kind=user_visible_error&limit=50" |
    python3 -c 'import json,sys; print("\n".join(i["id"] for i in json.load(sys.stdin) if "reach server" in i["data"].get("dialog_text","")))'
}
NEW_INCIDENT=""
new_network_incident() {  # new_network_incident <known ids file>: sets NEW_INCIDENT to an id not in the file
  NEW_INCIDENT=$(network_incidents | grep -vxF -f "$1" | head -1)
  [ -n "$NEW_INCIDENT" ]
}
trigger_network_fault() {
  pkill -x DemoApp 2>/dev/null; sleep 1
  open -n "$APP" --args --fault network --after 4 --backend https://app-backend:9443/health \
    --backend-ca "$CERTS/demo/backend-ca.pem" --proxy http://localhost:8889
}

mkdir -p "$DATA"
echo "data dir: $DATA"
echo "starting backend (netdemo + tools)..."
"${COMPOSE[@]}" up -d --build >"$DATA/compose.log" 2>&1 || { echo "compose failed (see $DATA/compose.log)"; exit 2; }
"${COMPOSE[@]}" build investigator sim >>"$DATA/compose.log" 2>&1 || { echo "tool images failed to build"; exit 2; }
wait_for 60 bash -c "curl -sf --cacert '$CERTS/ca.pem' --cert-type P12 --cert '$CERTS/endpoint.p12:ieso' https://localhost:8443/healthz" ||
  { echo "control plane not healthy"; exit 2; }

# The always-on watcher would investigate the same incidents and race this script for the probe budget.
WATCHER_WAS_UP=$(docker compose -f "$ROOT/backend/docker-compose.yml" --profile watch ps -q investigator-watch 2>/dev/null)
[ -n "$WATCHER_WAS_UP" ] && docker compose -f "$ROOT/backend/docker-compose.yml" --profile watch stop investigator-watch >/dev/null 2>&1

echo "fleet: simulated endpoints + this Mac's inventory"
"${COMPOSE[@]}" run --rm sim | tail -1
# Stand-in for the MDM/EDR inventory feed: this Mac sits behind the CorpGuard proxy like 25% of the fleet.
cp_admin PUT "/v1/admin/endpoints/$EP" '{"tenant": "tenant-demo", "simulated": false, "attributes": {
  "os_build": "25G83", "hardware_model": "Mac15,6", "arch": "arm64", "proxy": "corpguard-swg 5.2", "vpn": "none",
  "dlp_extension": "none", "edr_agent": "edr-agent 7.5", "locale": "en_US", "app_version": "1.4.2"}}' >/dev/null

"$SENSOR" --target DemoApp --data-dir "$DATA" --log-level info --endpoint-id "$EP" --tls-dir "$CERTS" \
  --backend https://localhost:4318 --control-plane https://localhost:8443 \
  --probe-key "$CERTS/probe-signing.pub.pem" --app-backend https://app-backend:9443/health \
  --demo-proxy http://localhost:8889 --app-backend-direct localhost:9443 >"$DATA/sensor.log" 2>&1 &
SENSOR_PID=$!
cleanup() {
  pkill -x DemoApp 2>/dev/null
  kill -TERM "$SENSOR_PID" 2>/dev/null && wait "$SENSOR_PID" 2>/dev/null
  [ "${1:-}" = "--down" ] && "${COMPOSE[@]}" down >/dev/null 2>&1
  [ -n "${WATCHER_WAS_UP:-}" ] && [ "${1:-}" != "--down" ] &&
    docker compose -f "$ROOT/backend/docker-compose.yml" --profile watch start investigator-watch >/dev/null 2>&1
  return 0
}
KEEP_FLAG="${1:-}"
trap 'cleanup "$KEEP_FLAG"' EXIT
check "sensor online" 20 grep -q "backend reachable: online" "$DATA/sensor.log"

MODES=(rule)
if [ -f "$RECORDING" ]; then MODES+=(replay); fi
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then MODES+=(claude); fi

for MODE in "${MODES[@]}"; do
  echo "investigation: --reasoner $MODE"
  network_incidents >"$DATA/known-$MODE.txt"
  trigger_network_fault
  if ! wait_for 40 new_network_incident "$DATA/known-$MODE.txt"; then
    echo "    no dialog seen yet; relaunching DemoApp once"   # first launch after a stack restart can miss it
    trigger_network_fault
  fi
  if ! wait_for 40 new_network_incident "$DATA/known-$MODE.txt"; then
    printf '  \033[31mFAIL\033[0m network incident (\"Cannot reach server\") indexed\n'; FAILS=$((FAILS + 1)); continue
  fi
  new_network_incident "$DATA/known-$MODE.txt"
  printf '  \033[32mPASS\033[0m network incident %s indexed\n' "$NEW_INCIDENT"
  EXTRA=()
  if [ "$MODE" = replay ]; then EXTRA=(--recording /srv/recordings/network-tls-interception.json); fi
  if [ "$MODE" = claude ] && [ -n "${IESO_RECORD:-}" ]; then EXTRA=(--record /srv/recordings/network-tls-interception.json); fi
  "${COMPOSE[@]}" run --rm investigator investigate --incident "$NEW_INCIDENT" --reasoner "$MODE" \
    ${EXTRA[@]+"${EXTRA[@]}"} --json >"$DATA/report-$MODE.out" 2>"$DATA/report-$MODE.err"
  sed -n '/^\[/p' "$DATA/report-$MODE.out" | sed 's/^/    /'
  python3 -c 'import sys; t=open(sys.argv[1]).read(); open(sys.argv[2],"w").write(t[t.index("\n{")+1:])' \
    "$DATA/report-$MODE.out" "$DATA/report-$MODE.json" 2>/dev/null
  R="$DATA/report-$MODE.json"
  check "[$MODE] root cause tls_interception (confidence >= 0.8)" 1 \
    jq_py 'sys.exit(0 if d["root_cause"]=="tls_interception" and d["confidence"]>=0.8 else 1)' "$R"
  check "[$MODE] signed probes verified and executed on the endpoint" 1 \
    jq_py 'sys.exit(0 if d["probes"] and all(p.get("status")=="done" and p.get("exit_status")==0 for p in d["probes"]) else 1)' "$R"
  check "[$MODE] sensor log: signature verified before running" 1 grep -q "for incident $NEW_INCIDENT (signature verified)" "$DATA/sensor.log"
  check "[$MODE] probe result shows the CorpGuard issuer on the proxy path" 10 bash -c \
    "curl -s --cacert '$CERTS/ca.pem' --cert-type P12 --cert '$CERTS/endpoint.p12:ieso' 'https://localhost:8443/v1/incidents?endpoint=$EP&kind=probe_result&limit=50' | grep -q 'CorpGuard TLS Inspection CA'"
  check "[$MODE] top fleet attribute proxy=corpguard-swg 5.2" 1 \
    jq_py 'sys.exit(0 if (d["fleet_impact"] or {}).get("value")=="corpguard-swg 5.2" else 1)' "$R"
  report_stored() { cp_admin GET "/v1/admin/reports?incident_id=$NEW_INCIDENT" | grep -q tls_interception; }
  check "[$MODE] report stored in the control plane" 5 report_stored
  case "$MODE" in
    replay) check "[replay] report is labeled as a replay" 1 jq_py 'sys.exit(0 if "replayed recording" in d["reasoner"] else 1)' "$R" ;;
    claude) check "[claude] answered by Claude (no rule fallback)" 1 jq_py 'sys.exit(0 if "live" in d["reasoner"] else 1)' "$R" ;;
  esac
done
[ -f "$RECORDING" ] || skip "replay: no recording yet (ANTHROPIC_API_KEY=... IESO_RECORD=1 $0)"
[ -n "${ANTHROPIC_API_KEY:-}" ] || skip "claude: ANTHROPIC_API_KEY not set (live Claude mode not exercised)"

echo "reports: $DATA/report-*.json   sensor log: $DATA/sensor.log"
[ $FAILS -eq 0 ] && echo "E2E INVESTIGATION PASSED" || echo "E2E INVESTIGATION FAILED ($FAILS checks)"
exit $FAILS
