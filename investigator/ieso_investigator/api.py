"""Minimal client for the control plane's internal API (reached on the backend network only)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional


class ApiError(RuntimeError):
    """Non-2xx response; status and detail come from the control plane."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail = status, detail


class ControlPlane:
    """JSON over HTTP to the control plane (internal port 8000; blocked at the public ingress)."""

    def __init__(self, base_url: str, timeout: float = 15.0) -> None:
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def _req(self, method: str, path: str, body: Optional[dict] = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get("detail", "")
            except ValueError:
                detail = e.reason
            raise ApiError(e.code, str(detail)) from None

    def healthz(self) -> bool:
        return bool(self._req("GET", "/healthz").get("ok"))

    def fleet(self) -> list[dict]:
        return self._req("GET", "/v1/admin/fleet")

    def incident(self, incident_id: str) -> dict:
        return self._req("GET", f"/v1/incidents/{urllib.parse.quote(incident_id)}")

    def incidents(self, endpoint: str = "", limit: int = 100) -> list[dict]:
        q = urllib.parse.urlencode({"endpoint": endpoint, "limit": limit})
        return self._req("GET", f"/v1/incidents?{q}")

    def request_probe(self, incident_id: str, probe_id: str, endpoint: str) -> dict:
        return self._req("POST", "/v1/admin/probes",
                         {"incident_id": incident_id, "probe_id": probe_id, "endpoint": endpoint})

    def probe(self, request_id: str) -> dict:
        return self._req("GET", f"/v1/admin/probes/{urllib.parse.quote(request_id)}")

    def bundle(self, incident_id: str) -> dict:
        """Sanitized incident bundle (rings, logs, deep capture); ApiError 404 until it is uploaded."""
        return self._req("GET", f"/v1/admin/incidents/{urllib.parse.quote(incident_id)}/bundle")

    def reports(self, incident_id: str = "") -> list[dict]:
        return self._req("GET", "/v1/admin/reports?" + urllib.parse.urlencode({"incident_id": incident_id}))

    def post_report(self, report: dict) -> str:
        return self._req("POST", "/v1/admin/reports", report)["id"]
