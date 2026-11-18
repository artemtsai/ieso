#!/bin/bash
# End-to-end test of sensor -> backend (build step 3).
#
#   scripts/e2e_backend.sh [--down]      --down: stop the stack afterwards (default: leave it up for Grafana)
#
# 1. Generates the local PKI if missing and starts backend/docker-compose.yml.
# 2. Runs ieso-sensor --target DemoApp with --backend (mTLS to the OTel Collector and control plane).
# 3. crash: incident indexed with its fleet signature + uploaded sanitized bundle; event in Loki; metrics in Prometheus.
# 4. hang:  incident indexed; the uploaded bundle holds the `sample` stacks with the user's home path redacted.
# 5. offline drill ("pull the network cable"): stop the ingress points, crash again, events spool to disk;
#    start them again, the spool drains, the new incident appears exactly once.
# Needs Docker Desktop running and the Accessibility permission (hang scenario), like scripts/smoke_test.sh.
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib/build_tools.sh"   # cmake/ninja from MacPorts (/opt/local/bin) or Homebrew

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SENSOR="$ROOT/build/debug/sensor/host/ieso-sensor"
APP="$ROOT/build/demo-app/DemoApp.app"
CERTS="$ROOT/backend/certs/out"
EP="ep-demo"
DATA="${IESO_E2E_DIR:-$(mktemp -d /tmp/ieso-e2e.XXXXXX)}"
COMPOSE=(docker compose -f "$ROOT/backend/docker-compose.yml")
START_NS="$(date +%s)000000000"

[ -x "$SENSOR" ] || { need_build_tools && cmake --preset debug >/dev/null && cmake --build --preset debug >/dev/null; } || exit 2
[ -d "$APP" ] || "$ROOT/demo-app/build.sh" >/dev/null || exit 2
[ -f "$CERTS/endpoint.p12" ] || "$ROOT/backend/certs/gen_certs.sh" "$EP" >/dev/null || exit 2
docker info >/dev/null 2>&1 || { echo "Docker is not running (open -a Docker)"; exit 2; }

cp_api() { curl -s --cacert "$CERTS/ca.pem" --cert-type P12 --cert "$CERTS/endpoint.p12:ieso" "https://localhost:8443$1"; }
loki_count() {
  curl -sG http://localhost:3100/loki/api/v1/query_range --data-urlencode "query=$1" \
    --data-urlencode "start=$START_NS" --data-urlencode "limit=1000" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(len(s["values"]) for s in d.get("data",{}).get("result",[])))' 2>/dev/null || echo 0
}
prom_count() {
  curl -sG http://localhost:9090/api/v1/query --data-urlencode "query=$1" |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin)["data"]["result"]))' 2>/dev/null || echo 0
}
incidents() {  # incidents <kind> -> count; also writes the JSON to $DATA/incidents-<kind>.json
  cp_api "/v1/incidents?kind=$1&endpoint=$EP" | tee "$DATA/incidents-$1.json" |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0
}
wait_for() {  # wait_for <timeout_s> <command...>: polls until the command succeeds
  local end=$((SECONDS + $1)); shift
  while [ $SECONDS -lt $end ]; do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
FAILS=0
check() {  # check <description> <timeout_s> <command...>
  local d="$1"; shift
  if wait_for "$@"; then printf '  \033[32mPASS\033[0m %s\n' "$d"; else printf '  \033[31mFAIL\033[0m %s\n' "$d"; FAILS=$((FAILS + 1)); fi
}
gt() { [ "$("$@")" -gt 0 ]; }                       # gt <cmd> : command prints a number > 0
eq() { local want="$1"; shift; [ "$("$@")" -eq "$want" ]; }
launch() { pkill -x DemoApp 2>/dev/null; sleep 1; open -n "$APP" --args --fault "$1" --after "${2:-4}"; }

mkdir -p "$DATA"
echo "data dir: $DATA"
echo "starting backend..."
"${COMPOSE[@]}" up -d --build >"$DATA/compose.log" 2>&1 || { echo "compose failed (see $DATA/compose.log)"; exit 2; }
wait_for 90 bash -c "curl -sf --cacert '$CERTS/ca.pem' --cert-type P12 --cert '$CERTS/endpoint.p12:ieso' https://localhost:13133/" ||
  { echo "collector not healthy"; exit 2; }
wait_for 90 bash -c '[ "$(curl -s http://localhost:3100/ready)" = ready ]' || { echo "loki not ready"; exit 2; }
wait_for 60 bash -c "curl -sf --cacert '$CERTS/ca.pem' --cert-type P12 --cert '$CERTS/endpoint.p12:ieso' https://localhost:8443/healthz" ||
  { echo "control plane not healthy"; exit 2; }

"$SENSOR" --target DemoApp --data-dir "$DATA" --log-level info --endpoint-id "$EP" --tls-dir "$CERTS" \
  --backend https://localhost:4318 --control-plane https://localhost:8443 >"$DATA/sensor.log" 2>&1 &
SENSOR_PID=$!
cleanup() {
  pkill -x DemoApp 2>/dev/null
  kill -TERM "$SENSOR_PID" 2>/dev/null && wait "$SENSOR_PID" 2>/dev/null
  "${COMPOSE[@]}" start otel-collector ingress >/dev/null 2>&1   # never leave the drill half-done
  [ "${1:-}" = "--down" ] && "${COMPOSE[@]}" down >/dev/null 2>&1
}
trap 'cleanup "${KEEP_FLAG:-}"' EXIT
KEEP_FLAG="${1:-}"
check "sensor online (NetworkStatusChanged)" 20 grep -q "backend reachable: online" "$DATA/sensor.log"

echo "transport: TLS 1.3 + mTLS only"
tls12_refused() {  # every sensor-facing port must refuse a TLS 1.2 handshake (even with a valid client cert)
  for p in 4318 8443 13133; do
    [ "$(curl -s -o /dev/null -w '%{http_code}' --tls-max 1.2 --cacert "$CERTS/ca.pem" --cert-type P12 \
          --cert "$CERTS/endpoint.p12:ieso" "https://localhost:$p/")" = "000" ] || return 1
  done
}
tls13_negotiated() {
  for p in 4318 8443 13133; do
    curl -sv -o /dev/null --cacert "$CERTS/ca.pem" --cert-type P12 --cert "$CERTS/endpoint.p12:ieso" \
      "https://localhost:$p/" 2>&1 | grep -q "SSL connection using TLSv1.3" || return 1
  done
}
no_cert_refused() { [ "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CERTS/ca.pem" https://localhost:4318/v1/logs)" = "000" ]; }
check "backend refuses TLS 1.2 on 4318, 8443, 13133" 5 tls12_refused
check "backend negotiates TLS 1.3 on 4318, 8443, 13133" 5 tls13_negotiated
check "backend refuses clients without a certificate" 5 no_cert_refused
check "sensor handshake is TLSv1.3 on both ingress points" 5 grep -q "collector TLSv1.3 / control plane TLSv1.3" "$DATA/sensor.log"

echo "scenario: crash"
launch crash 4
check "crash indexed in control plane" 60 gt incidents crash
check "fleet signature DemoApp+0x... EXC_BAD_ACCESS" 5 grep -Eq 'DemoApp\+0x[0-9a-f]+ EXC_BAD_ACCESS' "$DATA/incidents-crash.json"
check "crash event in Loki" 30 gt loki_count "{service_instance_id=\"$EP\"} | event_type=\"com.ieso.ProcessCrashDetected\""
check "resource metrics in Prometheus" 30 gt prom_count "process_memory_rss_bytes{service_instance_id=\"$EP\"}"
check "sanitized crash bundle uploaded" 30 bash -c "curl -s --cacert '$CERTS/ca.pem' --cert-type P12 --cert '$CERTS/endpoint.p12:ieso' 'https://localhost:8443/v1/incidents?kind=crash&endpoint=$EP' | grep -q '\"has_bundle\": *true'"

echo "scenario: hang"
launch hang 4
check "hang indexed in control plane" 60 gt incidents hang
HANG_ID=""
get_hang_bundle() {
  incidents hang >/dev/null
  HANG_ID=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next((i["id"] for i in d if i["has_bundle"]), ""))' "$DATA/incidents-hang.json")
  [ -n "$HANG_ID" ] && cp_api "/v1/incidents/$HANG_ID/bundle" >"$DATA/hang-bundle.json" && grep -q "Call graph" "$DATA/hang-bundle.json"
}
check "hang bundle downloadable with sample stacks" 60 get_hang_bundle
check "bundle is the sanitized copy (no raw home path)" 5 bash -c "grep -q 'ieso.incident.v1.sanitized' '$DATA/hang-bundle.json' && ! grep -q '/Users/$(whoami)/' '$DATA/hang-bundle.json'"

echo "scenario: offline drill"
BEFORE=$(incidents crash)
"${COMPOSE[@]}" stop otel-collector ingress >/dev/null 2>&1
launch crash 3
check "sensor went offline" 60 grep -q "unreachable: offline" "$DATA/sensor.log"
check "events spooled to disk while offline" 60 bash -c "ls '$DATA/spool' | grep -q '\.rec$'"
"${COMPOSE[@]}" start otel-collector ingress >/dev/null 2>&1
check "back online, spool drained" 90 bash -c "grep -q 'reachable: online' <(tail -n +1 '$DATA/sensor.log' | sed -n '/unreachable: offline/,\$p') && [ -z \"\$(ls '$DATA/spool' | grep '\.rec$')\" ]"
check "new crash indexed exactly once" 60 eq $((BEFORE + 1)) incidents crash

echo "stats: $(cp_api /v1/stats)"
echo "sensor log: $DATA/sensor.log   Grafana: http://localhost:3000"
[ $FAILS -eq 0 ] && echo "E2E PASSED" || echo "E2E FAILED ($FAILS checks)"
exit $FAILS
