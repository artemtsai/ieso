"""Deterministic fleet generator.

Every endpoint runs DemoApp 1.4.2 with realistic attribute spread. Three root causes are injected so the
investigator's fleet differential diagnosis has something real to find (DESIGN.md §10.1):

  network  ~90% of endpoints behind the "corpguard-swg 5.2" TLS-inspecting proxy fail to reach the backend
  crash    ~85% of endpoints with the "datashield 4.2" DLP extension crash at DemoApp+0x6455 EXC_BAD_ACCESS
  hang     ~70% of endpoints on OS build 24G90 hang on the main thread

plus ~2-3% background noise per symptom everywhere. All names are fictional.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

APP_VERSION = "1.4.2"
ATTRIBUTES = {
    "os_build": [("25G83", 50), ("25F71", 30), ("24G90", 20)],
    "hardware_model": [("Mac14,2", 30), ("Mac15,6", 25), ("MacBookPro18,3", 25), ("MacBookAir10,1", 20)],
    "arch": [("arm64", 85), ("x86_64", 15)],
    "proxy": [("none", 45), ("corpguard-swg 5.2", 25), ("corpguard-swg 5.1", 15), ("pac-direct", 15)],
    "vpn": [("none", 60), ("globalvpn 9.1", 40)],
    "dlp_extension": [("none", 50), ("datashield 4.1", 30), ("datashield 4.2", 20)],
    "edr_agent": [("edr-agent 7.4", 55), ("edr-agent 7.5", 45)],
    "locale": [("en_US", 55), ("de_DE", 20), ("fr_FR", 15), ("ja_JP", 10)],
}
NETWORK_TEXT = ("Cannot reach server | Sync failed: TLS certificate for app-backend is not trusted "
                "(“localhost” certificate is not trusted)")


DLP_BACKTRACE = ("0 DemoApp +0x6455 LedgerStore.didScan(_:) + 133\n"  # innermost first: the DLP hook calls back
                 "1 DataShieldHook +0x3c11 ds_scan_completion + 97\n"
                 "2 libdispatch.dylib +0x178b2 _dispatch_client_callout + 6\n"
                 "3 DataShieldHook +0x2a07 ds_async_scan_worker + 412\n")


def _pick(rng: random.Random, choices: list[tuple[str, int]]) -> str:
    values, weights = zip(*choices)
    return rng.choices(values, weights=weights, k=1)[0]


def _event(ep: str, n: int, etype: str, when: datetime, data: dict) -> dict:
    return {"specversion": "1.0", "id": f"{ep}-evt-{n:03d}", "source": f"ieso://endpoint/{ep}",
            "type": f"com.ieso.{etype}", "time": when.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "datacontenttype": "application/json", "iesoclass": 1, "data": data}


def generate(n: int = 200, seed: int = 7, now: datetime | None = None) -> list[dict]:
    """Returns endpoints as dicts: {id, tenant, simulated, attributes, incidents: [CloudEvent...]}."""
    rng = random.Random(seed)
    now = now or datetime.now(timezone.utc)
    fleet = []
    for i in range(1, n + 1):
        ep = f"sim-{i:03d}"
        attrs = {k: _pick(rng, v) for k, v in ATTRIBUTES.items()}
        attrs["app_version"] = APP_VERSION
        incidents: list[dict] = []

        def when() -> datetime:
            return now - timedelta(minutes=rng.randint(5, 24 * 60))

        if rng.random() < (0.90 if attrs["proxy"] == "corpguard-swg 5.2" else 0.02):
            incidents.append(_event(ep, len(incidents), "UserVisibleErrorObserved", when(),
                                    {"pid": rng.randint(400, 90000), "window_title": "", "dialog_text": NETWORK_TEXT}))
        if rng.random() < (0.85 if attrs["dlp_extension"] == "datashield 4.2" else 0.02):
            incidents.append(_event(ep, len(incidents), "ProcessCrashDetected", when(), {
                "pid": rng.randint(400, 90000), "exception_type": "EXC_BAD_ACCESS", "signal": "SIGSEGV",
                "termination_reason": "SIGNAL: Segmentation fault: 11", "faulting_module": "DemoApp",
                "offset": 0x6455, "signature": "DemoApp+0x6455 EXC_BAD_ACCESS",
                "exception_subtype": "KERN_INVALID_ADDRESS at 0x0000000000000010", "app_version": APP_VERSION,
                "crashed_thread": "0 (com.apple.main-thread)", "backtrace": DLP_BACKTRACE}))
        elif rng.random() < 0.02:
            incidents.append(_event(ep, len(incidents), "ProcessCrashDetected", when(), {
                "pid": rng.randint(400, 90000), "exception_type": "EXC_CRASH", "signal": "SIGABRT",
                "faulting_module": "libsystem_kernel.dylib", "offset": 0x7d3a,
                "signature": "libsystem_kernel.dylib+0x7d3a EXC_CRASH"}))
        if rng.random() < (0.70 if attrs["os_build"] == "24G90" else 0.03):
            incidents.append(_event(ep, len(incidents), "ProcessHangDetected", when(), {
                "pid": rng.randint(400, 90000), "probe_latency_ms": 1000, "duration_ms": rng.randint(7000, 30000)}))
        fleet.append({"id": ep, "tenant": "tenant-demo", "simulated": True, "attributes": attrs,
                      "incidents": incidents})
    return fleet
