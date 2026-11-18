"""ieso control plane: incident index (FR-17) and sanitized bundle store in S3-compatible storage (FR-4/FR-9).

Sits behind the nginx mTLS ingress, which verifies the endpoint certificate and forwards its CN/O as
X-Client-CN / X-Client-Org. Identity always comes from the certificate, never from the payload (DESIGN.md §11).
Delivery from the sensor is at-least-once; the index dedupes by CloudEvent id (FR-8).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import sqlite3
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Protocol

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response

INCIDENT_TYPES = {
    "com.ieso.ProcessHangDetected": "hang",
    "com.ieso.ProcessCrashDetected": "crash",
    "com.ieso.ResourceAnomalyDetected": "resource",
    "com.ieso.UserVisibleErrorObserved": "user_visible_error",
    "com.ieso.IncidentBundleReady": "bundle",
    "com.ieso.ProbeResultReady": "probe_result",
}


# Probe allowlist (FR-14, NFR-10): IDs only, never commands. Mirrored in the sensor's compiled-in allowlist.
PROBE_ALLOWLIST = {"net.config", "net.synthetic_tls", "env.extensions", "svc.launchctl"}
PROBES_PER_INCIDENT = 4
PROBES_PER_ENDPOINT_HOUR = int(os.environ.get("PROBES_PER_ENDPOINT_HOUR", "20"))  # sensor enforces 20/h too
PROBE_TTL_S = 120


class ProbeSigner:
    """Signs probe requests with the control plane's ECDSA P-256 key (sensor pins the public key)."""

    def __init__(self, key_pem: Optional[bytes]) -> None:
        self._key = None
        if key_pem:
            from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

            self._key = serialization.load_pem_private_key(key_pem, password=None)

    @staticmethod
    def canonical(req: dict) -> str:
        return "|".join(["v1", req["request_id"], req["endpoint"], req["probe_id"], req["incident_id"],
                         str(req["issued_at"]), str(req["expires_at"])])

    def sign(self, req: dict) -> str:
        if self._key is None:
            raise HTTPException(status_code=503, detail="probe signing key not configured")
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

        sig = self._key.sign(self.canonical(req).encode(), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(sig).decode()


class BundleStore(Protocol):
    """Object storage for sanitized incident bundles."""

    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> Optional[bytes]: ...


class MemoryStore:
    """In-process store for tests and local runs without MinIO."""

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    def put(self, key: str, data: bytes) -> None:
        self._data[key] = data

    def get(self, key: str) -> Optional[bytes]:
        return self._data.get(key)


class S3Store:
    """S3-compatible store (SeaweedFS in the demo, S3 at scale). Lazy import so tests need no client library."""

    def __init__(self, endpoint: str, access_key: str, secret_key: str, bucket: str) -> None:
        from minio import Minio  # noqa: PLC0415

        secure = endpoint.startswith("https://")
        host = endpoint.split("://", 1)[-1]
        self._client = Minio(host, access_key=access_key, secret_key=secret_key, secure=secure)
        self._bucket = bucket
        self._ready = False

    def _ensure_bucket(self) -> None:
        if not self._ready:  # the object store may start after us: create the bucket on first use
            if not self._client.bucket_exists(self._bucket):
                self._client.make_bucket(self._bucket)
            self._ready = True

    def put(self, key: str, data: bytes) -> None:
        self._ensure_bucket()
        self._client.put_object(self._bucket, key, io.BytesIO(data), len(data), content_type="application/json")

    def get(self, key: str) -> Optional[bytes]:
        try:
            resp = self._client.get_object(self._bucket, key)
        except Exception:  # noqa: BLE001 - missing object
            return None
        try:
            return resp.read()
        finally:
            resp.close()
            resp.release_conn()


class ReportSink(Protocol):
    def publish(self, report: dict) -> None: ...


def report_line(report: dict) -> dict:
    """Flat JSON line for Grafana: one row per investigation report (table + evidence panels)."""
    fi = report.get("fleet_impact") or {}
    fleet = (f"{fi['attribute']}={fi['value']}: {fi['affected']}/{fi['carriers']} affected, lift {fi['lift']}x, "
             f"{fi.get('endpoints_at_risk', 0)} more at risk") if fi else "no shared attribute stands out"
    probes = ", ".join(f"{p.get('probe_id')} {p.get('status', '?')}" for p in report.get("probes", [])) or "none"
    evidence = report.get("evidence_chain", [])
    return {"incident_id": report.get("incident_id", ""), "endpoint": report.get("endpoint", ""),
            "symptom": report.get("symptom", ""), "reasoner": report.get("reasoner", ""),
            "root_cause": report.get("root_cause", ""), "confidence": report.get("confidence", 0),
            "summary": report.get("summary", ""), "suggested_fix": report.get("suggested_fix", ""),
            "fleet": fleet, "probes": probes, "rounds": len(report.get("rounds", [])),
            "evidence_text": "\n".join(f"{i}. {e}" for i, e in enumerate(evidence, 1)),
            "crash_text": report.get("crash_text") or "", "hang_text": report.get("hang_text") or ""}


def round_lines(report: dict) -> list[dict]:
    """One flat JSON line per investigation round for Grafana's trace view (thinking summary, decision, policy)."""
    rounds = report.get("rounds", [])
    out = []
    for r in rounds:
        c = r.get("conclusion") or {}
        out.append({
            "incident_id": report.get("incident_id", ""), "endpoint": report.get("endpoint", ""),
            "round": r.get("round", 0), "rounds_total": len(rounds), "reasoner": report.get("reasoner", ""),
            "engine": r.get("engine", ""), "model": r.get("model", ""), "request_id": r.get("request_id", ""),
            "thinking": r.get("thinking", ""), "rule": r.get("rule", ""), "fallback": r.get("fallback", ""),
            "hypotheses_text": "\n".join(f"  {h.get('cause')} {h.get('confidence', 0):.2f}: {h.get('rationale', '')}"
                                         for h in r.get("hypotheses", [])),
            "proposed": ", ".join(r.get("proposed", [])) or "none", "approved": ", ".join(r.get("approved", [])) or "none",
            "rejected_text": "; ".join(f"{x.get('probe_id')} ({x.get('reason')})" for x in r.get("rejected", [])),
            "guard": r.get("guard", "") or "",
            "probe_text": "\n".join(f"  {t}" for t in r.get("probe_results", [])),
            "conclusion_text": f"{c.get('root_cause', '?')} {c.get('confidence', 0):.2f}: {c.get('summary', '')}",
        })
    return out


class LokiSink:
    """Pushes each stored report to Loki (push API) so Grafana can show it next to the endpoint's telemetry.

    Best effort: the control plane's report store stays the source of truth; a Loki outage only loses the panel row.
    """

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/") + "/loki/api/v1/push"

    def publish(self, report: dict) -> None:
        line = report_line(report)
        now = time.time_ns()
        rounds = round_lines(report)
        values = [[str(now - (len(rounds) - i) * 1_000_000), json.dumps(r),  # rounds just before the report, in order
                   {"event_type": "com.ieso.InvestigationRound"}] for i, r in enumerate(rounds)]
        values.append([str(now), json.dumps(line),
                       {"event_type": "com.ieso.InvestigationReport", "root_cause": line["root_cause"]}])
        body = {"streams": [{"stream": {"service_name": "ieso-investigator",
                                        "service_instance_id": line["endpoint"] or "unknown"},
                             "values": values}]}
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except (OSError, ValueError) as e:  # URLError/HTTPError are OSErrors
            print(f"control-plane: report not pushed to Loki: {e}", flush=True)


class Index:
    """SQLite incident index. One row per CloudEvent id (dedupe), bundles keyed by incident id."""

    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
              id TEXT PRIMARY KEY, tenant TEXT, endpoint TEXT, type TEXT, kind TEXT, time TEXT,
              signature TEXT, symptom TEXT, incident_id TEXT, data TEXT, received_at TEXT);
            CREATE TABLE IF NOT EXISTS bundles (
              incident_id TEXT PRIMARY KEY, tenant TEXT, endpoint TEXT, key TEXT, sha256 TEXT,
              bytes INTEGER, received_at TEXT);
            CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER);
            CREATE TABLE IF NOT EXISTS endpoints (
              id TEXT PRIMARY KEY, tenant TEXT, attributes TEXT, simulated INTEGER, updated_at TEXT);
            CREATE TABLE IF NOT EXISTS probes (
              request_id TEXT PRIMARY KEY, endpoint TEXT, incident_id TEXT, probe_id TEXT, issued_at INTEGER,
              expires_at INTEGER, signature TEXT, status TEXT, result TEXT, created_ms INTEGER);
            CREATE TABLE IF NOT EXISTS reports (
              id TEXT PRIMARY KEY, incident_id TEXT, created_at TEXT, report TEXT);
            CREATE INDEX IF NOT EXISTS events_by_endpoint ON events(endpoint, time);
            """
        )

    def bump(self, name: str, n: int = 1) -> None:
        self._db.execute(
            "INSERT INTO counters(name, value) VALUES(?, ?) ON CONFLICT(name) DO UPDATE SET value = value + ?",
            (name, n, n),
        )

    def add_event(self, tenant: str, endpoint: str, ev: dict[str, Any]) -> bool:
        data = ev.get("data") or {}
        kind = INCIDENT_TYPES.get(ev["type"], "other")
        signature = data.get("signature") or data.get("metric") or ""
        symptom = data.get("symptom") or kind
        incident_id = data.get("incident_id") or ev["id"]
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (ev["id"], tenant, endpoint, ev["type"], kind, ev.get("time", now), signature, symptom,
                 incident_id, json.dumps(data), now),
            )
            accepted = cur.rowcount == 1
            self.bump("events_accepted" if accepted else "events_duplicate")
            if accepted and ev["type"] == "com.ieso.ProbeResultReady" and data.get("request_id"):
                refused = int(data.get("exit_status", 0)) == -1 and str(data.get("output", "")).startswith("refused")
                self._db.execute("UPDATE probes SET status = ?, result = ? WHERE request_id = ? AND endpoint = ?",
                                 ("refused" if refused else "done", json.dumps(data), data["request_id"], endpoint))
            self._db.commit()
        return accepted

    # ---- fleet inventory ----
    def upsert_endpoint(self, tenant: str, endpoint: str, attributes: dict, simulated: bool) -> None:
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO endpoints VALUES(?,?,?,?,?)",
                             (endpoint, tenant, json.dumps(attributes), int(simulated),
                              datetime.now(timezone.utc).isoformat()))
            self._db.commit()

    def fleet(self) -> list[dict]:
        with self._lock:
            eps = {r["id"]: {"id": r["id"], "tenant": r["tenant"], "attributes": json.loads(r["attributes"]),
                             "simulated": bool(r["simulated"]), "incidents": []}
                   for r in self._db.execute("SELECT * FROM endpoints")}
            for r in self._db.execute("SELECT id, endpoint, type, kind, data FROM events WHERE kind != 'bundle'"):
                ep = eps.setdefault(r["endpoint"], {"id": r["endpoint"], "tenant": "", "attributes": {},
                                                    "simulated": False, "incidents": []})
                ep["incidents"].append({"id": r["id"], "type": r["type"], "kind": r["kind"],
                                        "data": json.loads(r["data"])})
        return list(eps.values())

    # ---- probes ----
    def incident_endpoint(self, incident_id: str) -> Optional[str]:
        with self._lock:
            r = self._db.execute("SELECT endpoint FROM events WHERE id = ?", (incident_id,)).fetchone()
        return r["endpoint"] if r else None

    def probe_counts(self, endpoint: str, incident_id: str, since_ms: int) -> tuple[int, int]:
        with self._lock:
            per_incident = self._db.execute("SELECT COUNT(*) FROM probes WHERE incident_id = ?",
                                            (incident_id,)).fetchone()[0]
            per_hour = self._db.execute("SELECT COUNT(*) FROM probes WHERE endpoint = ? AND created_ms >= ?",
                                        (endpoint, since_ms)).fetchone()[0]
        return per_incident, per_hour

    def add_probe(self, req: dict) -> None:
        with self._lock:
            self._db.execute("INSERT INTO probes VALUES(?,?,?,?,?,?,?,?,?,?)",
                             (req["request_id"], req["endpoint"], req["incident_id"], req["probe_id"],
                              req["issued_at"], req["expires_at"], req["signature"], "queued", None,
                              int(time.time() * 1000)))
            self._db.commit()

    def take_pending(self, endpoint: str, now_ms: int) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM probes WHERE endpoint = ? AND status = 'queued' AND expires_at > ? ORDER BY created_ms",
                (endpoint, now_ms)).fetchall()
            for r in rows:  # handed out once; the sensor dedupes replays by request_id as well
                self._db.execute("UPDATE probes SET status = 'sent' WHERE request_id = ?", (r["request_id"],))
            self._db.commit()
        return [{k: r[k] for k in ("request_id", "endpoint", "incident_id", "probe_id", "issued_at", "expires_at",
                                   "signature")} for r in rows]

    def probe(self, request_id: str) -> Optional[dict]:
        with self._lock:
            r = self._db.execute("SELECT * FROM probes WHERE request_id = ?", (request_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["result"] = json.loads(d["result"]) if d["result"] else None
        return d

    # ---- reports ----
    def add_report(self, incident_id: str, report: dict) -> str:
        rid = report.get("id") or str(uuid.uuid4())
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO reports VALUES(?,?,?,?)",
                             (rid, incident_id, datetime.now(timezone.utc).isoformat(), json.dumps(report)))
            self._db.commit()
        return rid

    def reports(self, incident_id: str = "") -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM reports WHERE (? = '' OR incident_id = ?) ORDER BY created_at DESC",
                (incident_id, incident_id)).fetchall()
        return [{"id": r["id"], "incident_id": r["incident_id"], "created_at": r["created_at"],
                 "report": json.loads(r["report"])} for r in rows]

    def add_bundle(self, tenant: str, endpoint: str, incident_id: str, key: str, sha: str, size: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO bundles VALUES(?,?,?,?,?,?,?)",
                (incident_id, tenant, endpoint, key, sha, size, datetime.now(timezone.utc).isoformat()),
            )
            self.bump("bundles_stored")
            self._db.commit()

    def incidents(self, endpoint: str = "", kind: str = "", signature: str = "", limit: int = 100) -> list[dict]:
        sql = ("SELECT e.*, b.key AS bundle_key, b.sha256 AS bundle_sha256 FROM events e "
               "LEFT JOIN bundles b ON b.incident_id = e.id WHERE e.kind != 'bundle'")
        args: list[Any] = []
        for col, val in (("e.endpoint", endpoint), ("e.kind", kind), ("e.signature", signature)):
            if val:
                sql += f" AND {col} = ?"
                args.append(val)
        sql += " ORDER BY e.time DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [_row(r) for r in rows]

    def incident(self, incident_id: str) -> Optional[dict]:
        with self._lock:
            r = self._db.execute(
                "SELECT e.*, b.key AS bundle_key, b.sha256 AS bundle_sha256 FROM events e "
                "LEFT JOIN bundles b ON b.incident_id = e.id WHERE e.id = ?", (incident_id,)).fetchone()
        return _row(r) if r else None

    def bundle(self, incident_id: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._db.execute("SELECT * FROM bundles WHERE incident_id = ?", (incident_id,)).fetchone()

    def stats(self) -> dict[str, int]:
        with self._lock:
            counters = {r["name"]: r["value"] for r in self._db.execute("SELECT * FROM counters")}
            counters["incidents"] = self._db.execute(
                "SELECT COUNT(*) FROM events WHERE kind != 'bundle'").fetchone()[0]
        return counters


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["data"] = json.loads(d["data"]) if d.get("data") else {}
    d["has_bundle"] = bool(d.get("bundle_key"))
    return d


class Identity:
    """Endpoint identity proven by the client certificate (forwarded by the mTLS ingress)."""

    def __init__(self, endpoint: str, tenant: str) -> None:
        self.endpoint = endpoint
        self.tenant = tenant


def identity(x_client_cn: str = Header(default=""), x_client_org: str = Header(default="")) -> Identity:
    if not x_client_cn:
        raise HTTPException(status_code=401, detail="client certificate required")
    return Identity(x_client_cn, x_client_org or "default")


def create_app(index: Index, store: BundleStore, signer: Optional[ProbeSigner] = None,
               report_sink: Optional[ReportSink] = None) -> FastAPI:
    app = FastAPI(title="ieso control plane", version="0.4.0")
    signer = signer or ProbeSigner(None)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    @app.post("/v1/events")
    async def post_events(request: Request, who: Identity = Depends(identity)) -> dict:
        body = await request.json()
        events = body if isinstance(body, list) else [body]
        accepted = duplicates = 0
        for ev in events:
            if not isinstance(ev, dict) or "id" not in ev or "type" not in ev:
                raise HTTPException(status_code=400, detail="not a CloudEvent")
            claimed = str(ev.get("source", "")).rsplit("/", 1)[-1]
            if claimed and claimed != who.endpoint:
                raise HTTPException(status_code=403, detail=f"source endpoint {claimed} != certificate {who.endpoint}")
            if index.add_event(who.tenant, who.endpoint, ev):
                accepted += 1
            else:
                duplicates += 1
        return {"accepted": accepted, "duplicates": duplicates}

    @app.put("/v1/bundles/{incident_id}")
    async def put_bundle(incident_id: str, request: Request, x_bundle_sha256: str = Header(default=""),
                         who: Identity = Depends(identity)) -> dict:
        data = await request.body()
        digest = hashlib.sha256(data).hexdigest()
        if not x_bundle_sha256 or digest != x_bundle_sha256.lower():
            raise HTTPException(status_code=400, detail="bundle hash mismatch")
        try:
            json.loads(data)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="bundle is not JSON") from exc
        if "/" in incident_id or ".." in incident_id:
            raise HTTPException(status_code=400, detail="bad incident id")
        key = f"bundles/{who.tenant}/{who.endpoint}/{incident_id}.json"
        store.put(key, data)
        index.add_bundle(who.tenant, who.endpoint, incident_id, key, digest, len(data))
        return {"stored": key, "sha256": digest}

    @app.get("/v1/incidents")
    def list_incidents(endpoint: str = "", kind: str = "", signature: str = "", limit: int = 100) -> list[dict]:
        return index.incidents(endpoint, kind, signature, limit)

    @app.get("/v1/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict:
        inc = index.incident(incident_id)
        if not inc:
            raise HTTPException(status_code=404, detail="no such incident")
        return inc

    @app.get("/v1/incidents/{incident_id}/bundle")
    def get_bundle(incident_id: str) -> Response:
        row = index.bundle(incident_id)
        data = store.get(row["key"]) if row else None
        if data is None:
            raise HTTPException(status_code=404, detail="no bundle")
        return Response(content=data, media_type="application/json", headers={"X-Bundle-SHA256": row["sha256"]})

    @app.get("/v1/stats")
    def stats() -> dict:
        return index.stats()

    # ---- endpoint side: signed probe requests (mTLS through the ingress, scoped to the certificate CN) ----
    @app.get("/v1/probes/pending")
    def pending_probes(who: Identity = Depends(identity)) -> list[dict]:
        return index.take_pending(who.endpoint, int(time.time() * 1000))

    # ---- internal admin API (blocked at the ingress; reached only on the backend network) ----
    @app.post("/v1/admin/import")
    async def admin_import(request: Request) -> dict:
        body = await request.json()
        n_eps = n_events = 0
        for ep in body.get("endpoints", []):
            tenant = ep.get("tenant", "tenant-demo")
            index.upsert_endpoint(tenant, ep["id"], ep.get("attributes", {}), bool(ep.get("simulated", True)))
            n_eps += 1
            for ev in ep.get("incidents", []):
                n_events += int(index.add_event(tenant, ep["id"], ev))
        return {"endpoints": n_eps, "events": n_events}

    @app.put("/v1/admin/endpoints/{endpoint}")
    async def admin_endpoint(endpoint: str, request: Request) -> dict:
        body = await request.json()
        index.upsert_endpoint(body.get("tenant", "tenant-demo"), endpoint, body.get("attributes", {}),
                              bool(body.get("simulated", False)))
        return {"ok": True}

    @app.get("/v1/admin/fleet")
    def admin_fleet() -> list[dict]:
        return index.fleet()

    @app.post("/v1/admin/probes")
    async def admin_request_probe(request: Request) -> dict:
        """Policy layer (DESIGN §10.2 step 3): the investigator proposes, this decides and signs."""
        body = await request.json()
        probe_id, incident_id = body.get("probe_id", ""), body.get("incident_id", "")
        if probe_id not in PROBE_ALLOWLIST:
            raise HTTPException(status_code=403, detail=f"probe {probe_id!r} is not on the allowlist")
        endpoint = index.incident_endpoint(incident_id)
        if endpoint is None:
            raise HTTPException(status_code=404, detail="unknown incident")
        if body.get("endpoint") and body["endpoint"] != endpoint:
            raise HTTPException(status_code=403, detail="probes may only target the incident's own endpoint")
        now_ms = int(time.time() * 1000)
        per_incident, per_hour = index.probe_counts(endpoint, incident_id, now_ms - 3600_000)
        if per_incident >= PROBES_PER_INCIDENT or per_hour >= PROBES_PER_ENDPOINT_HOUR:
            raise HTTPException(status_code=429, detail="probe budget exhausted")
        req = {"request_id": str(uuid.uuid4()), "endpoint": endpoint, "incident_id": incident_id,
               "probe_id": probe_id, "issued_at": now_ms, "expires_at": now_ms + PROBE_TTL_S * 1000}
        req["signature"] = signer.sign(req)
        index.add_probe(req)
        return req

    @app.get("/v1/admin/probes/{request_id}")
    def admin_probe(request_id: str) -> dict:
        p = index.probe(request_id)
        if not p:
            raise HTTPException(status_code=404, detail="no such probe request")
        return p

    @app.get("/v1/admin/incidents/{incident_id}/bundle")
    def admin_bundle(incident_id: str) -> Response:
        return get_bundle(incident_id)

    @app.post("/v1/admin/reports")
    async def admin_post_report(request: Request) -> dict:
        body = await request.json()
        rid = index.add_report(body.get("incident_id", ""), body)
        if report_sink is not None:
            report_sink.publish(body)
        return {"id": rid}

    @app.get("/v1/admin/reports")
    def admin_reports(incident_id: str = "") -> list[dict]:
        return index.reports(incident_id)

    return app


def _default_app() -> FastAPI:
    db_path = os.environ.get("DB_PATH", "incidents.db")
    if os.environ.get("S3_ENDPOINT"):
        store: BundleStore = S3Store(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"],
                                        os.environ["S3_SECRET_KEY"], os.environ.get("S3_BUCKET", "ieso-bundles"))
    else:
        store = MemoryStore()
    key_path = os.environ.get("PROBE_SIGNING_KEY", "")
    key = open(key_path, "rb").read() if key_path and os.path.exists(key_path) else None
    loki = os.environ.get("LOKI_URL", "")
    return create_app(Index(db_path), store, ProbeSigner(key), LokiSink(loki) if loki else None)


app = _default_app() if os.environ.get("IESO_NO_DEFAULT_APP") is None else None
