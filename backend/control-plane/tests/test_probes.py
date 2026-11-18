"""Probe queue + policy layer + signing, fleet import and reports."""

import base64
import os

os.environ["IESO_NO_DEFAULT_APP"] = "1"

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.main import Index, MemoryStore, ProbeSigner, create_app

CERT = {"X-Client-CN": "ep-demo", "X-Client-Org": "tenant-demo"}


@pytest.fixture()
def env(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    client = TestClient(create_app(Index(str(tmp_path / "i.db")), MemoryStore(), ProbeSigner(pem)))
    crash = {"specversion": "1.0", "id": "inc-1", "source": "ieso://endpoint/ep-demo",
             "type": "com.ieso.UserVisibleErrorObserved", "time": "2026-11-18T00:00:00.000Z",
             "data": {"dialog_text": "Cannot reach server"}}
    assert client.post("/v1/events", json=[crash], headers=CERT).status_code == 200
    return client, key.public_key()


def test_probe_is_signed_over_canonical_request(env):
    client, pub = env
    req = client.post("/v1/admin/probes", json={"probe_id": "net.config", "incident_id": "inc-1"}).json()
    assert req["endpoint"] == "ep-demo" and req["expires_at"] > req["issued_at"]
    msg = "|".join(["v1", req["request_id"], "ep-demo", "net.config", "inc-1", str(req["issued_at"]),
                    str(req["expires_at"])]).encode()
    pub.verify(base64.b64decode(req["signature"]), msg, ec.ECDSA(hashes.SHA256()))  # raises if invalid


def test_policy_layer_rejects(env):
    client, _ = env
    assert client.post("/v1/admin/probes", json={"probe_id": "shell.exec", "incident_id": "inc-1"}).status_code == 403
    assert client.post("/v1/admin/probes", json={"probe_id": "net.config", "incident_id": "nope"}).status_code == 404
    other = client.post("/v1/admin/probes", json={"probe_id": "net.config", "incident_id": "inc-1",
                                                   "endpoint": "ep-other"})
    assert other.status_code == 403
    for _ in range(4):
        assert client.post("/v1/admin/probes", json={"probe_id": "net.config", "incident_id": "inc-1"}).status_code == 200
    assert client.post("/v1/admin/probes", json={"probe_id": "net.config", "incident_id": "inc-1"}).status_code == 429


def test_pending_is_scoped_and_handed_out_once(env):
    client, _ = env
    req = client.post("/v1/admin/probes", json={"probe_id": "net.synthetic_tls", "incident_id": "inc-1"}).json()
    other = {"X-Client-CN": "ep-other"}
    assert client.get("/v1/probes/pending", headers=other).json() == []
    got = client.get("/v1/probes/pending", headers=CERT).json()
    assert [p["request_id"] for p in got] == [req["request_id"]]
    assert client.get("/v1/probes/pending", headers=CERT).json() == []
    assert client.get("/v1/probes/pending").status_code == 401


def test_result_is_linked_by_request_id(env):
    client, _ = env
    req = client.post("/v1/admin/probes", json={"probe_id": "net.config", "incident_id": "inc-1"}).json()
    result = {"specversion": "1.0", "id": "res-1", "source": "ieso://endpoint/ep-demo",
              "type": "com.ieso.ProbeResultReady", "time": "2026-11-18T00:00:01.000Z",
              "data": {"probe_id": "net.config", "request_id": req["request_id"], "output": "HTTPSProxy : localhost",
                       "exit_status": 0}}
    client.post("/v1/events", json=[result], headers=CERT)
    p = client.get(f"/v1/admin/probes/{req['request_id']}").json()
    assert p["status"] == "done" and p["result"]["output"].startswith("HTTPSProxy")
    refused = client.post("/v1/admin/probes", json={"probe_id": "env.extensions", "incident_id": "inc-1"}).json()
    client.post("/v1/events", headers=CERT, json=[{**result, "id": "res-2", "data": {
        "probe_id": "env.extensions", "request_id": refused["request_id"], "output": "refused: bad signature",
        "exit_status": -1}}])
    assert client.get(f"/v1/admin/probes/{refused['request_id']}").json()["status"] == "refused"


def test_fleet_import_and_reports(env):
    client, _ = env
    body = {"endpoints": [{"id": "sim-001", "attributes": {"proxy": "corpguard-swg 5.2"}, "incidents": [
        {"specversion": "1.0", "id": "sim-001-i1", "source": "ieso://endpoint/sim-001",
         "type": "com.ieso.UserVisibleErrorObserved", "time": "2026-11-17T10:00:00.000Z",
         "data": {"dialog_text": "Cannot reach server"}}]}, {"id": "sim-002", "attributes": {"proxy": "none"}}]}
    assert client.post("/v1/admin/import", json=body).json() == {"endpoints": 2, "events": 1}
    fleet = {e["id"]: e for e in client.get("/v1/admin/fleet").json()}
    assert fleet["sim-001"]["attributes"]["proxy"] == "corpguard-swg 5.2"
    assert len(fleet["sim-001"]["incidents"]) == 1 and fleet["sim-002"]["incidents"] == []
    assert "ep-demo" in fleet  # the real endpoint appears through its incidents
    rid = client.post("/v1/admin/reports", json={"incident_id": "inc-1", "root_cause": "tls_interception"}).json()["id"]
    assert client.get("/v1/admin/reports?incident_id=inc-1").json()[0]["id"] == rid


def test_reports_are_published_to_the_sink(tmp_path):
    from app.main import report_line

    published = []

    class Sink:
        def publish(self, report):
            published.append(report_line(report))

    client = TestClient(create_app(Index(str(tmp_path / "r.db")), MemoryStore(), None, Sink()))
    report = {"incident_id": "inc-9", "endpoint": "ep-demo", "reasoner": "rule (offline)",
              "root_cause": "tls_interception", "confidence": 0.95, "summary": "s", "suggested_fix": "f",
              "evidence_chain": ["a", "b"], "crash_text": "EXC_BAD_ACCESS (SIGSEGV)\n  0 DemoApp +0x8875", "probes": [{"probe_id": "net.config", "status": "done"}],
              "fleet_impact": {"attribute": "proxy", "value": "corpguard-swg 5.2", "affected": 42, "carriers": 49,
                               "lift": 3.92, "endpoints_at_risk": 7}, "rounds": [{}, {}]}
    assert client.post("/v1/admin/reports", json=report).status_code == 200
    assert client.get("/v1/admin/reports?incident_id=inc-9").json()[0]["report"]["root_cause"] == "tls_interception"
    line = published[0]
    assert line["evidence_text"] == "1. a\n2. b" and line["probes"] == "net.config done" and line["rounds"] == 2
    assert line["fleet"].startswith("proxy=corpguard-swg 5.2: 42/49 affected")
    assert line["crash_text"].startswith("EXC_BAD_ACCESS")


def test_round_lines_carry_the_reasoning_trace():
    from app.main import round_lines

    report = {"incident_id": "inc-9", "endpoint": "ep-demo", "reasoner": "claude (m, live)", "rounds": [
        {"round": 1, "engine": "claude (live)", "model": "m", "thinking": "Proxy cohort; compare chains.",
         "hypotheses": [{"cause": "tls_interception", "confidence": 0.6, "rationale": "cohort"}],
         "proposed": ["net.config", "net.synthetic_tls"], "approved": ["net.config", "net.synthetic_tls"],
         "rejected": [], "guard": "", "probe_results": ["net.config: effective HTTPS proxy http://p:1"],
         "conclusion": {"root_cause": "tls_interception", "confidence": 0.6, "summary": "suspected"}},
        {"round": 2, "engine": "claude (live)", "hypotheses": [], "proposed": [], "approved": [],
         "rejected": [{"probe_id": "env.extensions", "reason": "budget"}],
         "conclusion": {"root_cause": "tls_interception", "confidence": 0.9, "summary": "confirmed"}}]}
    lines = round_lines(report)
    assert [x["round"] for x in lines] == [1, 2] and lines[0]["rounds_total"] == 2
    assert lines[0]["thinking"] == "Proxy cohort; compare chains."
    assert lines[0]["hypotheses_text"] == "  tls_interception 0.60: cohort"
    assert lines[0]["probe_text"] == "  net.config: effective HTTPS proxy http://p:1"
    assert lines[1]["rejected_text"] == "env.extensions (budget)" and lines[1]["proposed"] == "none"
    assert lines[1]["conclusion_text"] == "tls_interception 0.90: confirmed"
