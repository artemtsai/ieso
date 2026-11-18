#!/bin/bash
# Stops everything scripts/demo_up.sh (or /run-demo) started, and checks that nothing is left running.
#
#   scripts/demo_down.sh          # keeps the data (incidents, reports, Grafana and Loki history)
#   scripts/demo_down.sh --wipe   # also deletes the data volumes: a clean slate, cannot be undone
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="/tmp/ieso-demo"
COMPOSE=(docker compose -f "$ROOT/backend/docker-compose.yml" --profile netdemo --profile tools --profile watch)
WIPE=()
[ "${1:-}" = "--wipe" ] && WIPE=(-v)

step() { printf '\033[1m==> %s\033[0m\n' "$1"; }

step "DemoApp and sensor"
pkill -x DemoApp 2>/dev/null && echo "    DemoApp closed" || echo "    DemoApp not running"
pids="$( { cat "$DATA/sensor.pid" 2>/dev/null; pgrep -f "ieso-sensor --target"; } | sort -u)"
if [ -n "$pids" ]; then
  kill -TERM $pids 2>/dev/null          # SIGTERM: the sensor saves its flight-recorder checkpoint and flushes the spool
  for _ in 1 2 3 4; do pgrep -f "ieso-sensor --target" >/dev/null || break; sleep 0.5; done
  pgrep -f "ieso-sensor --target" >/dev/null && pkill -KILL -f "ieso-sensor --target"
  echo "    sensor stopped"
else
  echo "    sensor not running"
fi
rm -f "$DATA/sensor.pid"

if docker info >/dev/null 2>&1; then
  step "Investigator watcher, then the stack"
  "${COMPOSE[@]}" stop investigator-watch >/dev/null 2>&1   # first: no paid Claude call during shutdown
  "${COMPOSE[@]}" down --remove-orphans ${WIPE[@]+"${WIPE[@]}"} >/dev/null 2>&1
  [ ${#WIPE[@]} -gt 0 ] && echo "    stack down, data volumes deleted" || echo "    stack down (data kept)"
else
  step "Docker is not running: nothing to stop there"
fi

step "Check"
pgrep -fl "DemoApp|ieso-sensor" >/dev/null && echo "    still running: $(pgrep -fl 'DemoApp|ieso-sensor')" || echo "    no local processes"
if docker info >/dev/null 2>&1; then
  left="$("${COMPOSE[@]}" ps -q 2>/dev/null)"
  [ -n "$left" ] && echo "    containers still up: $left" || echo "    no containers"
fi
busy="$(lsof -nP -iTCP:3000,4318,8443,8889,9443 -sTCP:LISTEN 2>/dev/null | tail -n +2)"
[ -n "$busy" ] && { echo "    ports still in use:"; echo "$busy" | sed 's/^/      /'; } || echo "    demo ports free"
