#!/bin/bash
# Breaks DemoApp on purpose while the demo runs, and follows the incident to its investigation report.
#
#   scripts/demo_fault.sh <crash|hang|leak|network|permission> [--no-report]
#
# Needs a running sensor and backend (/run-demo). The script never starts or stops them.
# 1. Launches DemoApp with the fault switch (any running DemoApp is closed first).
# 2. Waits until the sensor's incident reaches the control plane over mTLS. This works however the sensor was
#    started.
# 3. If investigator-watch is running (and --no-report isn't given), waits for its report in Loki and prints the
#    root cause. Otherwise it prints the command to investigate by hand.
# Exit status: 0 when the incident was detected (and reported, if waited for), 1 on timeout, 2 on a setup error.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="$ROOT/build/demo-app/DemoApp.app"
CERTS="$ROOT/backend/certs/out"
EP="ep-demo"
COMPOSE=(docker compose -f "$ROOT/backend/docker-compose.yml")
FAULT="${1:-}"
WAIT_REPORT=1
[ "${2:-}" = "--no-report" ] && WAIT_REPORT=0

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
case "$FAULT" in crash|hang|leak|network|permission) ;; *) usage ;; esac

pgrep -f "ieso-sensor --target DemoApp" >/dev/null || { echo "No sensor is running. Start the demo first (/run-demo)."; exit 2; }
[ -f "$CERTS/endpoint.p12" ] || { echo "No endpoint certificate in $CERTS (run backend/certs/gen_certs.sh ep-demo)."; exit 2; }
[ -d "$APP" ] || "$ROOT/demo-app/build.sh" >/dev/null || { echo "DemoApp build failed."; exit 2; }

cp_api() { curl -s --max-time 10 --cacert "$CERTS/ca.pem" --cert-type P12 --cert "$CERTS/endpoint.p12:ieso" "https://localhost:8443$1"; }
cp_api /healthz | grep -q '"ok"' || { echo "Control plane is not reachable on https://localhost:8443 (is the backend up?)."; exit 2; }

# kind (control-plane index) and an optional dialog-text match for each fault
EXTRA=()
case "$FAULT" in
  crash)      KIND=crash;              MATCH="";                TIMEOUT=75 ;;  # 30 s grace if macOS writes no report
  hang)       KIND=hang;               MATCH="";                TIMEOUT=60 ;;
  leak)       KIND=resource;           MATCH="";                TIMEOUT=120 ;;
  permission) KIND=user_visible_error; MATCH="Permission";      TIMEOUT=60 ;;
  network)    KIND=user_visible_error; MATCH="reach server";    TIMEOUT=60
              EXTRA=(--backend https://app-backend:9443/health --backend-ca "$CERTS/demo/backend-ca.pem"
                     --proxy http://localhost:8889) ;;
esac

incidents() {  # newest-first "id<TAB>summary" lines of matching incidents on ep-demo
  cp_api "/v1/incidents?endpoint=$EP&kind=$KIND&limit=50" | python3 -c '
import json, sys
match = sys.argv[1]
for i in json.load(sys.stdin):
    d = i.get("data", {})
    text = d.get("dialog_text") or ""
    if match and match not in text:
        continue
    unresponsive = str(d.get("duration_ms", "?")) + " ms unresponsive"
    summary = d.get("signature") or d.get("metric") or text[:90] or unresponsive
    print(i["id"] + "\t" + str(summary))' "$MATCH" 2>/dev/null
}
KNOWN="$(mktemp -t ieso-fault)"
trap 'rm -f "$KNOWN"' EXIT
incidents | cut -f1 >"$KNOWN"

pkill -x DemoApp 2>/dev/null; sleep 1
open -n "$APP" --args --fault "$FAULT" --after 3 ${EXTRA[@]+"${EXTRA[@]}"}
echo "DemoApp launched: '$FAULT' fault in 3 s ($(date +%T))"

NEW=""
end=$((SECONDS + TIMEOUT))
while [ $SECONDS -lt $end ]; do
  NEW="$(incidents | grep -v -F -f "$KNOWN" | head -1)"
  [ -n "$NEW" ] && break
  sleep 2
done
if [ -z "$NEW" ]; then
  echo "No new $KIND incident within ${TIMEOUT}s."
  echo "Check the sensor's output, and Accessibility for hang, network and permission."
  exit 1
fi
ID="${NEW%%$'\t'*}"
echo "Detected: incident $ID: ${NEW#*$'\t'}"
[ "$FAULT" = leak ] && { pkill -x DemoApp; echo "Leak stopped (DemoApp closed after the anomaly)."; }

URL="http://localhost:3000/d/ieso-endpoint/ieso-endpoint-timeline?orgId=1&from=now-15m&to=now&var-endpoint=$EP&var-incident=$ID"
if [ $WAIT_REPORT -eq 0 ] || [ -z "$("${COMPOSE[@]}" --profile watch ps -q investigator-watch 2>/dev/null)" ]; then
  echo "Investigate it: (cd backend && docker compose --profile tools run --rm investigator investigate --incident $ID)"
  echo "Grafana: $URL"
  exit 0
fi

echo "Waiting for investigator-watch's report..."
REPORT=""
end=$((SECONDS + 240))
while [ $SECONDS -lt $end ]; do
  REPORT="$(curl -sG --max-time 10 http://localhost:3100/loki/api/v1/query_range \
    --data-urlencode "query={service_name=\"ieso-investigator\"} | event_type=\"com.ieso.InvestigationReport\" |= \"$ID\"" \
    --data-urlencode "start=$(($(date +%s) - 900))000000000" --data-urlencode limit=1 | python3 -c '
import json, sys
for s in json.load(sys.stdin).get("data", {}).get("result", []):
    for _, line in s["values"]:
        d = json.loads(line)
        print("%s (confidence %.2f) by %s" % (d["root_cause"], float(d["confidence"]), d["reasoner"]))
        raise SystemExit' 2>/dev/null)"
  [ -n "$REPORT" ] && break
  sleep 5
done
if [ -z "$REPORT" ]; then
  if "${COMPOSE[@]}" --profile watch logs --since 10m investigator-watch 2>/dev/null | grep -q "cap .*$ID"; then
    echo "No report yet: investigator-watch's hourly cost cap is reached. It investigates this incident once the"
    echo "cap frees up; to do it now: (cd backend && docker compose --profile tools run --rm investigator investigate --incident $ID)"
  else
    echo "No report within 240 s (check: docker compose --profile watch logs investigator-watch)."
  fi
  echo "Grafana: $URL"
  exit 1
fi
echo "Report: $REPORT"
echo "Grafana (evidence chain): $URL&viewPanel=panel-8"
echo "Grafana (reasoning trace): $URL&viewPanel=panel-9"
