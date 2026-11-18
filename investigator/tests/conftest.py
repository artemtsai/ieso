"""Shared fakes: an in-memory control plane whose 'endpoint' answers probes immediately."""

from __future__ import annotations

import json
import os
import sys
import uuid

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(os.path.dirname(ROOT), "sim"))

from ieso_investigator.api import ApiError  # noqa: E402
from ieso_sim.fleet import NETWORK_TEXT, generate  # noqa: E402

PROXY_ISSUER = "CN=CorpGuard TLS Inspection CA,O=CorpGuard SWG"
BACKEND_ISSUER = "CN=DemoApp Backend CA,O=DemoApp Inc"


def tls_output(via_issuer: str = PROXY_ISSUER, direct_issuer: str = BACKEND_ISSUER) -> str:
    def path(name, proxy, issuer, status):
        return {"path": name, "proxy": proxy, "verify_error_system_trust": "unable to get local issuer certificate",
                "tls_version": "TLSv1.3", "http_status": status, "error": "",
                "chain": [{"subject": "CN=localhost,O=DemoApp Inc", "issuer": issuer}]}
    return json.dumps({"target": "https://app-backend:9443/health",
                       "paths": [path("via_proxy", "http://localhost:8889", via_issuer, 200),
                                 path("direct", "", direct_issuer, 200)]})


PROBE_OUTPUTS = {
    "net.config": "effective_https_proxy: http://localhost:8889\nscutil --proxy\n<dictionary> {}\n",
    "net.synthetic_tls": tls_output(),
    "env.extensions": "1 extension(s)\n--- com.apple.system_extension.network_extension\n"
                      "\t*\t*\tABCDE12345\tcom.datashield.filter (4.2/420)\tDataShield\t[activated enabled]\n",
}


class FakeControlPlane:
    """Implements the ControlPlane methods the loop uses; probes are answered as the sensor would."""

    def __init__(self, refuse: bool = False, outputs: dict | None = None) -> None:
        self.fleet_data = generate(200, seed=7)
        self.fleet_data.append({"id": "ep-demo", "tenant": "tenant-demo", "simulated": False,
                                "attributes": {"os_build": "25G83", "hardware_model": "Mac15,6", "arch": "arm64",
                                               "proxy": "corpguard-swg 5.2", "vpn": "none", "dlp_extension": "none",
                                               "edr_agent": "edr-agent 7.5", "locale": "en_US",
                                               "app_version": "1.4.2"},
                                "incidents": [{"id": "ep-demo-net-1", "type": "com.ieso.UserVisibleErrorObserved",
                                               "data": {"pid": 4242, "window_title": "",
                                                        "dialog_text": NETWORK_TEXT}}]})
        self.refuse = refuse
        self.outputs = outputs or PROBE_OUTPUTS
        self.probes: dict[str, dict] = {}
        self.reports_store: list[dict] = []
        self.bundles: dict[str, dict] = {}

    def fleet(self) -> list[dict]:
        return self.fleet_data

    def incident(self, incident_id: str) -> dict:
        for ep in self.fleet_data:
            for i in ep["incidents"]:
                if i["id"] == incident_id:
                    return dict(i, endpoint=ep["id"], time="2026-11-17T10:00:00.000Z")
        raise ApiError(404, "no such incident")

    def incidents(self, endpoint: str = "", limit: int = 100) -> list[dict]:
        return [dict(i, endpoint=ep["id"], time=i.get("time", "2099-01-01T00:00:00.000Z"),
                     kind=i["type"].rsplit(".", 1)[-1]) for ep in self.fleet_data for i in ep["incidents"]
                if not endpoint or ep["id"] == endpoint][:limit]

    def request_probe(self, incident_id: str, probe_id: str, endpoint: str) -> dict:
        if len([p for p in self.probes.values() if p["incident_id"] == incident_id]) >= 4:
            raise ApiError(429, "probe budget exhausted")
        rid = str(uuid.uuid4())
        if self.refuse:
            result = {"probe_id": probe_id, "request_id": rid, "exit_status": -1,
                      "output": "refused: bad signature"}
            status = "refused"
        else:
            result = {"probe_id": probe_id, "request_id": rid, "exit_status": 0, "output": self.outputs[probe_id]}
            status = "done"
        self.probes[rid] = {"request_id": rid, "probe_id": probe_id, "incident_id": incident_id,
                            "endpoint": endpoint, "status": status, "result": result}
        return {"request_id": rid, "probe_id": probe_id, "endpoint": endpoint}

    def probe(self, request_id: str) -> dict:
        return self.probes[request_id]

    def bundle(self, incident_id: str) -> dict:
        if incident_id not in self.bundles:
            raise ApiError(404, "no bundle")
        return self.bundles[incident_id]

    def reports(self, incident_id: str = "") -> list[dict]:
        return [{"report": r} for r in self.reports_list if not incident_id or r["incident_id"] == incident_id]

    @property
    def reports_list(self) -> list[dict]:
        return self.reports_store

    def post_report(self, report: dict) -> str:
        self.reports_store.append(report)
        return report["id"]


@pytest.fixture
def cp() -> FakeControlPlane:
    return FakeControlPlane()


def quiet(_msg: str) -> None:
    pass
