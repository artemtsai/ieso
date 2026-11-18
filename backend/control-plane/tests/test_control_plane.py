"""Control plane API: identity from the ingress headers, dedupe by event id, bundle hash, index queries."""

import hashlib
import json
import os

os.environ["IESO_NO_DEFAULT_APP"] = "1"

import pytest
from fastapi.testclient import TestClient

from app.main import Index, MemoryStore, create_app

CERT = {"X-Client-CN": "ep-demo", "X-Client-Org": "tenant-demo"}


def event(eid: str, etype: str = "com.ieso.ProcessCrashDetected", source: str = "ieso://endpoint/ep-demo",
          **data):
    return {"specversion": "1.0", "id": eid, "source": source, "type": etype, "time": "2026-11-18T00:00:00.000Z",
            "datacontenttype": "application/json", "data": data}


@pytest.fixture()
def client(tmp_path):
    return TestClient(create_app(Index(str(tmp_path / "i.db")), MemoryStore()))


def test_requires_certificate_identity(client):
    assert client.post("/v1/events", json=[event("a")]).status_code == 401


def test_dedupe_by_event_id(client):
    batch = [event("a", signature="DemoApp+0x6455 EXC_BAD_ACCESS"), event("b", "com.ieso.ProcessHangDetected")]
    assert client.post("/v1/events", json=batch, headers=CERT).json() == {"accepted": 2, "duplicates": 0}
    assert client.post("/v1/events", json=batch, headers=CERT).json() == {"accepted": 0, "duplicates": 2}
    stats = client.get("/v1/stats").json()
    assert stats["incidents"] == 2 and stats["events_duplicate"] == 2


def test_source_must_match_certificate(client):
    r = client.post("/v1/events", json=[event("x", source="ieso://endpoint/ep-other")], headers=CERT)
    assert r.status_code == 403


def test_bundle_hash_and_download(client):
    client.post("/v1/events", json=[event("inc1", "com.ieso.ProcessHangDetected")], headers=CERT)
    body = json.dumps({"incident_id": "inc1", "symptom": "hang"}).encode()
    bad = client.put("/v1/bundles/inc1", content=body, headers={**CERT, "X-Bundle-SHA256": "00"})
    assert bad.status_code == 400
    sha = hashlib.sha256(body).hexdigest()
    ok = client.put("/v1/bundles/inc1", content=body, headers={**CERT, "X-Bundle-SHA256": sha})
    assert ok.status_code == 200 and ok.json()["stored"] == "bundles/tenant-demo/ep-demo/inc1.json"
    inc = client.get("/v1/incidents/inc1").json()
    assert inc["has_bundle"] and inc["kind"] == "hang" and inc["endpoint"] == "ep-demo"
    got = client.get("/v1/incidents/inc1/bundle")
    assert got.status_code == 200 and got.content == body


def test_index_queries(client):
    client.post("/v1/events", headers=CERT, json=[
        event("c1", signature="libfoo+0x1 EXC_BAD_ACCESS"), event("c2", signature="libbar+0x2 EXC_CRASH"),
        event("h1", "com.ieso.ProcessHangDetected"),
        event("b1", "com.ieso.IncidentBundleReady", incident_id="h1", symptom="hang")])
    assert {i["id"] for i in client.get("/v1/incidents?kind=crash").json()} == {"c1", "c2"}
    assert [i["id"] for i in client.get("/v1/incidents?signature=libfoo%2B0x1%20EXC_BAD_ACCESS").json()] == ["c1"]
    assert "b1" not in {i["id"] for i in client.get("/v1/incidents").json()}  # bundle announcements aren't incidents
    assert client.get("/v1/incidents/nope").status_code == 404
