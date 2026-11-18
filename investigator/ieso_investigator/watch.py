"""Watch mode: investigate every new incident on real endpoints as it arrives, one at a time.

Each incident is investigated once. Incidents that already have a report (from this watcher, a previous run or a
manual `investigate`) are skipped, so restarts are safe. Only incidents from the last `lookback_s` seconds are
picked up at startup, and an hourly cap bounds the cost of a live Claude reasoner. Incidents held back by the cap
stay pending and are investigated once it frees up (they are not dropped).
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Callable

from .api import ApiError, ControlPlane
from .fleet_diff import classify
from .loop import investigate


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S")


def pending(cp: ControlPlane, since: str, done: set[str], simulated: set[str]) -> list[dict]:
    """Investigable incidents on real endpoints, newer than `since`, not yet handled; oldest first."""
    out = []
    for inc in cp.incidents(limit=200):
        if inc["id"] in done or inc["endpoint"] in simulated or inc.get("time", "") < since:
            continue
        if classify(inc["type"], inc.get("data", {})) is None:
            continue
        out.append(inc)
    return sorted(out, key=lambda i: i.get("time", ""))


def watch(cp: ControlPlane, make_reasoner: Callable[[], object], interval_s: float = 5.0, lookback_s: int = 1800,
          max_per_hour: int = 20, probe_timeout_s: float = 60.0, log: Callable[[str], None] = print,
          iterations: int = 0) -> int:
    """Polls forever (or `iterations` times, for tests); returns the number of reports written."""
    since = _iso(datetime.now(timezone.utc) - timedelta(seconds=lookback_s))
    done: set[str] = set()
    deferred: set[str] = set()  # held back by the hourly cap; investigated once it frees up
    started: deque[float] = deque()
    simulated: set[str] = set()
    fleet_checked = 0.0
    written = 0
    n = 0
    log(f"[watch] watching for incidents since {since}Z (every {interval_s:g}s, at most {max_per_hour}/hour)")
    while iterations == 0 or n < iterations:
        n += 1
        try:
            if time.monotonic() - fleet_checked > 60:  # inventory changes rarely
                simulated = {ep["id"] for ep in cp.fleet() if ep.get("simulated")}
                fleet_checked = time.monotonic()
            for inc in pending(cp, since, done, simulated):
                if cp.reports(inc["id"]):
                    done.add(inc["id"])
                    continue  # already investigated (manual run or before a restart)
                while started and time.monotonic() - started[0] > 3600:
                    started.popleft()
                if len(started) >= max_per_hour:
                    if inc["id"] not in deferred:  # say it once; the incident stays pending and is retried later
                        log(f"[watch] hourly cap of {max_per_hour} reached; {inc['id']} waits until the cap frees up")
                        deferred.add(inc["id"])
                    continue
                done.add(inc["id"])
                deferred.discard(inc["id"])
                started.append(time.monotonic())
                log(f"[watch] new incident {inc['id']} ({inc['kind']}) on {inc['endpoint']}")
                try:
                    report = investigate(cp, inc["id"], make_reasoner(), probe_timeout_s=probe_timeout_s, log=log)
                except (ApiError, ValueError, OSError) as e:
                    log(f"[watch] investigation of {inc['id']} failed: {e}")
                    continue
                cp.post_report(report)
                written += 1
                log(f"[watch] report stored: {report['root_cause']} ({report['confidence']:.2f}) by {report['reasoner']}")
        except (ApiError, OSError) as e:  # control plane restarting: keep watching
            log(f"[watch] control plane unavailable ({e}); retrying")
        if iterations == 0 or n < iterations:
            time.sleep(interval_s)
    return written
