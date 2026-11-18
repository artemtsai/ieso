"""ClaudeReasoner with a mocked SDK client (no key, no network), recording and replay."""

from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest
from conftest import quiet

from ieso_investigator.loop import investigate
from ieso_investigator.reasoners import ClaudeReasoner, InvalidDecision, Recorder, ReplayReasoner, validate

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "replay_fixture.json")


def decision(cause, conf, probes, done, evidence=("x",)):
    return {"hypotheses": [{"cause": cause, "confidence": conf, "rationale": "r"}], "next_probes": probes,
            "conclusion": {"root_cause": cause, "confidence": conf, "summary": "s", "evidence": list(evidence),
                           "suggested_fix": "f"}, "done": done}


class FakeMessages:
    """Stands in for client.beta.messages; returns scripted texts and records the request kwargs."""

    def __init__(self, texts, stop_reason="end_turn"):
        self.texts = list(texts)
        self.stop_reason = stop_reason
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        text = self.texts.pop(0)
        return SimpleNamespace(stop_reason=self.stop_reason, model="claude-opus-5-5", _request_id="req_test",
                               usage=SimpleNamespace(input_tokens=1200, output_tokens=300),
                               content=[SimpleNamespace(type="thinking", thinking=f"summary of round {len(self.calls)}"),
                                        SimpleNamespace(type="text", text=text)])


def client(texts, stop_reason="end_turn"):
    return SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages(texts, stop_reason)))


SCRIPT = [json.dumps(decision("tls_interception", 0.6, ["net.config", "net.synthetic_tls"], False)),
          json.dumps(decision("tls_interception", 0.93, [], True, ["issuer differs: CorpGuard vs DemoApp"]))]


def test_claude_reasoner_drives_the_loop(cp):
    c = client(SCRIPT)
    reasoner = ClaudeReasoner(model="claude-opus-5-5", client=c, log=quiet)
    report = investigate(cp, "ep-demo-net-1", reasoner, log=quiet)
    assert report["root_cause"] == "tls_interception" and report["confidence"] == 0.93
    assert report["reasoner"] == "claude (claude-opus-5-5, live)"
    call = c.beta.messages.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["output_config"]["effort"] == "high"
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert call["fallbacks"] == "default" and call["betas"] == ["server-side-fallback-2026-07-01"]
    assert call["thinking"] == {"type": "adaptive", "display": "summarized"}  # summary for the trace; no budget
    r1, r2 = report["rounds"]
    assert r1["thinking"] == "summary of round 1" and r2["thinking"] == "summary of round 2"
    assert r1["engine"] == "claude (live)" and r1["request_id"] == "req_test" and r1["tokens"]["output"] == 300
    assert [t.split(":")[0] for t in r1["probe_results"]] == ["net.config", "net.synthetic_tls"]
    assert r2["probe_results"] == []
    # round 2 saw the probe facts collected in round 1
    ctx2 = json.loads(c.beta.messages.calls[1]["messages"][0]["content"].split("\n", 1)[1].rsplit("\n\n", 1)[0])
    assert {p["probe_id"] for p in ctx2["probe_results"]} == {"net.config", "net.synthetic_tls"}


@pytest.mark.parametrize("texts,stop", [(["{not json"], "end_turn"),
                                        ([json.dumps({"hypotheses": []})], "end_turn"),
                                        (["{}"], "refusal")])
def test_claude_bad_output_falls_back_to_rules(cp, texts, stop):
    reasoner = ClaudeReasoner(client=client(texts * 3, stop), log=quiet)
    report = investigate(cp, "ep-demo-net-1", reasoner, log=quiet)
    assert report["root_cause"] == "tls_interception"  # rule reasoner reached the same answer
    assert reasoner.fallbacks_used >= 1 and "rule fallback" in report["reasoner"]
    assert report["rounds"][0]["engine"] == "rules (fallback from Claude)" and report["rounds"][0]["fallback"]


def test_record_then_replay_reaches_the_same_conclusion(cp, tmp_path):
    path = str(tmp_path / "rec.json")
    rec = Recorder(path, "network-tls-interception")
    investigate(cp, "ep-demo-net-1", ClaudeReasoner(client=client(SCRIPT), recorder=rec, log=quiet), log=quiet)
    rec.save()
    replay = ReplayReasoner(path)
    assert replay.label.startswith("claude (replayed recording, claude-opus-5-5")
    from conftest import FakeControlPlane
    report = investigate(FakeControlPlane(), "ep-demo-net-1", replay, log=quiet)
    assert report["root_cause"] == "tls_interception"
    assert [p["probe_id"] for p in report["probes"]] == ["net.config", "net.synthetic_tls"]  # probes ran live
    assert report["rounds"][0]["thinking"] == "summary of round 1"  # the recorded thinking summary replays too
    assert report["rounds"][0]["engine"] == "claude (replayed recording)"


def test_replay_fixture(cp):
    report = investigate(cp, "ep-demo-net-1", ReplayReasoner(FIXTURE), log=quiet)
    assert report["root_cause"] == "tls_interception" and "replayed recording" in report["reasoner"]


def test_replay_rejects_invalid_files(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"format": "other"}))
    with pytest.raises(InvalidDecision):
        ReplayReasoner(str(bad))
    with pytest.raises(InvalidDecision):
        validate(decision("not-a-cause", 0.5, [], True))
    with pytest.raises(InvalidDecision):
        validate(decision("unknown", 1.5, [], True))
    with pytest.raises(InvalidDecision):
        validate(decision("unknown", 0.5, ["shell.exec"], True))
