#!/bin/bash
# End-to-end smoke test of the macOS sensor against DemoApp (build step 2).
#
#   scripts/smoke_test.sh [scenario ...]      scenarios: hang crash leak network permission (default: hang crash)
#
# Starts ieso-sensor --target DemoApp, launches DemoApp with a fault switch, and checks the sanitized outbox
# (<data>/outbox.ndjson) and incident bundles (<data>/incidents/*.json) for the expected evidence.
# hang / network / permission need the Accessibility permission for the app running this script
# (Terminal, iTerm or VS Code): System Settings > Privacy & Security > Accessibility.
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib/build_tools.sh"   # cmake/ninja from MacPorts (/opt/local/bin) or Homebrew

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SENSOR="$ROOT/build/debug/sensor/host/ieso-sensor"
APP="$ROOT/build/demo-app/DemoApp.app"
DATA="${IESO_SMOKE_DIR:-$(mktemp -d /tmp/ieso-smoke.XXXXXX)}"
OUTBOX="$DATA/outbox.ndjson"
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -eq 0 ] && SCENARIOS=(hang crash)

[ -x "$SENSOR" ] || { need_build_tools && cmake --preset debug >/dev/null && cmake --build --preset debug >/dev/null; } || exit 2
[ -d "$APP" ] || "$ROOT/demo-app/build.sh" >/dev/null || exit 2

mkdir -p "$DATA"
"$SENSOR" --target DemoApp --data-dir "$DATA" --log-level info >"$DATA/sensor.log" 2>&1 &
SENSOR_PID=$!
cleanup() {
  pkill -x DemoApp 2>/dev/null
  kill -TERM "$SENSOR_PID" 2>/dev/null && wait "$SENSOR_PID" 2>/dev/null
}
trap cleanup EXIT
sleep 2

# wait_for <regex> <file> <timeout_s>: polls until a line matches.
wait_for() {
  local end=$((SECONDS + $3))
  while [ $SECONDS -lt $end ]; do
    grep -Eq "$1" "$2" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}

# check <description> <regex> <file> <timeout_s>
FAILS=0
check() {
  if wait_for "$2" "$3" "$4"; then
    printf '  \033[32mPASS\033[0m %s\n' "$1"
  else
    printf '  \033[31mFAIL\033[0m %s\n' "$1"
    FAILS=$((FAILS + 1))
  fi
}

launch() {
  pkill -x DemoApp 2>/dev/null
  sleep 1
  open -n "$APP" --args --fault "$1" --after "${2:-4}"
}

echo "data dir: $DATA"
grep -q "Accessibility not granted" "$DATA/sensor.log" && echo "  NOTE: Accessibility not granted: hang/dialog scenarios will fail"

for s in "${SCENARIOS[@]}"; do
  echo "scenario: $s"
  case "$s" in
    hang)
      launch hang 4
      check "target adopted (TargetLifecycle launch)" '"type":"com.ieso.TargetLifecycle".*"phase":"launch"' "$OUTBOX" 20
      check "hang detected by AX probe (ProcessHangDetected)" '"type":"com.ieso.ProcessHangDetected"' "$OUTBOX" 40
      check "incident bundle announced (symptom=hang)" '"type":"com.ieso.IncidentBundleReady".*"symptom":"hang"' "$OUTBOX" 30
      check "bundle holds main-thread stacks from sample" 'Call graph' "$(ls -t "$DATA"/incidents/*.json 2>/dev/null | head -1)" 5
      ;;
    crash)
      launch crash 4
      check "crash detected from .ips (ProcessCrashDetected)" '"type":"com.ieso.ProcessCrashDetected"' "$OUTBOX" 60
      check "crash signature module+offset+exception" '"signature":"DemoApp\+0x[0-9a-f]+ EXC_BAD_ACCESS"' "$OUTBOX" 5
      check "exit seen by kqueue (TargetLifecycle exit)" '"phase":"exit"' "$OUTBOX" 5
      check "report path redacted" '"report_path":"/Users/<user>/' "$OUTBOX" 5
      check "incident bundle announced (symptom=crash)" '"symptom":"crash"' "$OUTBOX" 10
      ;;
    leak)
      launch leak 2
      check "leak detected (ResourceAnomalyDetected rss_growth)" '"metric":"rss_growth"' "$OUTBOX" 90
      ;;
    network)
      launch network 3
      check "app error log collected (LogRecordObserved)" '"type":"com.ieso.LogRecordObserved".*backend unreachable' "$OUTBOX" 30
      check "user-visible dialog captured" '"type":"com.ieso.UserVisibleErrorObserved".*Cannot reach server' "$OUTBOX" 30
      ;;
    permission)
      launch permission 3
      check "user-visible dialog captured" '"type":"com.ieso.UserVisibleErrorObserved".*Permission denied' "$OUTBOX" 30
      check "home path redacted in dialog text" '/Users/<user>/Library/Messages' "$OUTBOX" 5
      ;;
    *) echo "  unknown scenario $s"; FAILS=$((FAILS + 1)) ;;
  esac
done

echo "sensor log: $DATA/sensor.log"
[ $FAILS -eq 0 ] && echo "SMOKE TEST PASSED" || echo "SMOKE TEST FAILED ($FAILS checks)"
exit $FAILS
