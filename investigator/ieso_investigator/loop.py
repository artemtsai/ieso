"""The investigation loop (DESIGN.md §10.2): triage -> hypothesize -> policy -> probe -> update -> stop.

Stops at confidence >= 0.8, when the reasoner is done, when no approved probe remains, or after max_rounds.
The reasoner only proposes probes. The local policy pre-check rejects anything off the allowlist, repeated or over
budget; the control plane re-checks and signs; the endpoint verifies the signature and its own budget again.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Callable

from .api import ApiError, ControlPlane
from .evidence import crash_dump, crash_text, hang_dump, hang_text, facts_text, stack_shows_network, summarize
from .fleet_diff import classify, fleet_diff
from .reasoners import PROBES, Reasoner, validate

CONFIDENCE_TARGET = 0.8
NETWORK_CAUSES = {"tls_interception", "proxy_misconfiguration", "dns_failure", "backend_outage"}
BUNDLE_WAIT_S = 45  # a hang's `sample` capture and upload take a few seconds after the incident
PROBE_BUDGET = 4  # per incident, same as the control plane and the endpoint


def policy_check(proposed: list[str], already: set[str], budget_left: int) -> tuple[list[str], list[dict]]:
    """Local pre-check of the reasoner's proposals; returns (approved, rejected with reasons)."""
    approved, rejected = [], []
    for p in proposed:
        if p not in PROBES:
            rejected.append({"probe_id": p, "reason": "not on the signed allowlist"})
        elif p in already or p in approved:
            rejected.append({"probe_id": p, "reason": "already collected for this incident"})
        elif len(approved) >= budget_left:
            rejected.append({"probe_id": p, "reason": "probe budget for this incident exhausted"})
        else:
            approved.append(p)
    return approved, rejected


def fetch_hang_dump(cp: ControlPlane, incident: dict, wait_s: float, log: Callable[[str], None]) -> dict:
    """Main-thread stack from the hang's sanitized bundle (`sample` capture); {} when none was captured."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            bundle = cp.bundle(incident["id"])
            break
        except ApiError as e:
            if e.status != 404 or time.monotonic() >= deadline:
                log(f"[hang] no bundle for {incident['id']} ({e.status}); investigating without a stack sample")
                return {}
            time.sleep(2)
    capture = bundle.get("deep_capture") or {}
    if capture.get("status") != "Ok" or not capture.get("text"):
        log(f"[hang] bundle has no stack sample (capture {capture.get('status', 'missing')}, e.g. observer budget)")
        return {}
    return hang_dump(capture["text"], int(incident.get("data", {}).get("duration_ms", 0)))


def guard(decision: dict, kind: str, crash: dict, hang: dict) -> str:
    """Policy check of a conclusion: a hang or crash is blamed on the network only if its stack shows network code.

    Facts that are true of the endpoint (an inspecting proxy, say) are not evidence for an unrelated symptom. A
    conclusion that fails the check is downgraded to `unknown` and the reason is fed back to the reasoner.
    """
    c = decision["conclusion"]
    if kind not in ("hang", "crash") or c["root_cause"] not in NETWORK_CAUSES or stack_shows_network(crash, hang):
        return ""
    where = "hung main thread" if kind == "hang" else "crashed thread"
    note = (f"policy: {c['root_cause']} rejected for a {kind}: no frame of the {where} is in network code "
            f"(CFNetwork, libnetwork, TLS, sockets); a network finding about this endpoint does not explain the {kind}")
    c["evidence"] = list(c["evidence"]) + [note]
    c["root_cause"], c["confidence"] = "unknown", min(c["confidence"], 0.3)
    c["summary"] = f"Unexplained {kind}: the proposed network cause is not supported by the stack. " + c["summary"]
    decision["done"] = False
    return note


def _incident_view(incident: dict) -> dict:
    """The incident as the reasoner sees it: sanitized fields only."""
    return {"id": incident["id"], "type": incident["type"], "time": incident.get("time", ""),
            "endpoint": incident["endpoint"], "data": incident.get("data", {})}


def wait_for(cp: ControlPlane, request_id: str, timeout_s: float, poll_s: float = 1.0) -> dict:
    """Polls a probe request until the endpoint reported a result (done/refused) or the timeout passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        p = cp.probe(request_id)
        if p.get("status") in ("done", "refused") or time.monotonic() >= deadline:
            return p
        time.sleep(poll_s)


def investigate(cp: ControlPlane, incident_id: str, reasoner: Reasoner, max_rounds: int = 3,
                probe_timeout_s: float = 60.0, log: Callable[[str], None] = print,
                bundle_wait_s: float = BUNDLE_WAIT_S) -> dict:
    """Runs the loop for one incident and returns the report (also stored in the control plane by the CLI)."""
    incident = cp.incident(incident_id)
    symptom = classify(incident["type"], incident.get("data", {}))
    if symptom is None:
        raise ValueError(f"{incident_id} ({incident['type']}) is not an investigable incident")
    endpoint = incident["endpoint"]
    fleet = cp.fleet()
    diff = fleet_diff(fleet, symptom, endpoint)
    log(f"[triage] incident {incident_id} on {endpoint}: symptom {symptom.label()}")
    log(f"[fleet] {diff.affected}/{diff.total} endpoints show the same symptom")
    for a in diff.ranked[:3]:
        log(f"[fleet]   {a.attribute}={a.value}: {a.affected}/{a.carriers} affected, lift {a.lift:.1f}x"
            f"{'  <- this endpoint' if a.endpoint_has_it else ''}")

    dump = crash_dump(incident.get("data", {})) if symptom.kind == "crash" else {}
    if dump:
        log(f"[crash] {dump['exception']} ({dump['signal']}) {dump['subtype']}; faulting frame: {dump['faulting_frame'] or '?'}")
    hdump = fetch_hang_dump(cp, incident, bundle_wait_s, log) if symptom.kind == "hang" else {}
    if hdump:
        log(f"[hang] main thread {hdump['blocking']}; innermost app frame: {hdump['app_frame'] or 'none'}")
    feedback: list[str] = []
    probe_results: list[dict] = []
    probe_log: list[dict] = []
    rounds: list[dict] = []
    decision: dict = {}
    for rnd in range(1, max_rounds + 1):
        context = {"round": rnd, "max_rounds": max_rounds, "incident": _incident_view(incident),
                   "symptom": {"kind": symptom.kind, "key": symptom.key}, "fleet_diff": diff.as_dict(),
                   "probe_results": probe_results, "allowed_probes": PROBES,
                   "probe_budget_left": PROBE_BUDGET - len(probe_log)}
        if dump:
            context["crash_dump"] = dump
        if hdump:
            context["hang_dump"] = hdump
        if feedback:
            context["policy_feedback"] = feedback
        decision_raw = reasoner.decide(context)
        decision = validate(decision_raw)
        note = guard(decision, symptom.kind, dump, hdump)
        if note:
            log(f"[policy] {note}")
            feedback.append(note)
        c = decision["conclusion"]
        log(f"[round {rnd}] {reasoner.label}: " + ", ".join(
            f"{h['cause']} {h['confidence']:.2f}" for h in decision["hypotheses"]) +
            f" -> proposes {decision['next_probes'] or 'no probes'}")
        last = rnd == max_rounds
        approved, rejected = policy_check([] if last else decision["next_probes"],
                                          {p["probe_id"] for p in probe_log}, PROBE_BUDGET - len(probe_log))
        for r in rejected:
            log(f"[policy] rejected {r['probe_id']}: {r['reason']}")
        trace = dict(getattr(reasoner, "last_trace", {}) or {})
        rounds.append({"round": rnd, "engine": trace.get("engine", reasoner.label), "model": trace.get("model", ""),
                       "request_id": trace.get("request_id", ""), "thinking": trace.get("thinking", ""),
                       "rule": trace.get("rule", ""), "fallback": trace.get("fallback", ""),
                       "tokens": trace.get("tokens", {}), "guard": note,
                       "hypotheses": decision["hypotheses"], "proposed": decision["next_probes"],
                       "approved": approved, "rejected": rejected, "conclusion": c, "probe_results": []})
        if decision["done"] or c["confidence"] >= CONFIDENCE_TARGET or not approved:
            break
        for probe_id in approved:
            try:
                req = cp.request_probe(incident_id, probe_id, endpoint)
            except ApiError as e:
                log(f"[policy] control plane rejected {probe_id}: {e}")
                rounds[-1]["rejected"].append({"probe_id": probe_id, "reason": f"control plane: {e.detail}"})
                continue
            log(f"[probe] {probe_id} signed by the control plane (request {req['request_id'][:8]}), waiting for {endpoint}")
            probe_log.append({"probe_id": probe_id, "request_id": req["request_id"]})
        for entry in probe_log[len(probe_results):]:
            summary = summarize(wait_for(cp, entry["request_id"], probe_timeout_s))
            entry.update(status=summary["status"], exit_status=summary["exit_status"])
            verdict = {"done": "signature verified on the endpoint, executed",
                       "refused": f"refused by the endpoint: {summary['raw']}"}.get(summary["status"],
                                                                                   "no result (timeout)")
            log(f"[probe] {entry['probe_id']}: {verdict} (exit {summary['exit_status']})")
            probe_results.append(summary)
            rounds[-1]["probe_results"].append(facts_text(summary))

    top = diff.top()
    fleet_impact = None
    if top:
        at_risk = sum(1 for ep in fleet if str((ep.get("attributes") or {}).get(top.attribute)) == top.value) - top.affected
        fleet_impact = dict(top.as_dict(), affected_endpoints=diff.affected, fleet_size=diff.total,
                            endpoints_at_risk=max(at_risk, 0))
    c = decision["conclusion"]
    return {"id": str(uuid.uuid4()), "incident_id": incident_id, "endpoint": endpoint, "symptom": symptom.label(),
            "reasoner": reasoner.label, "root_cause": c["root_cause"], "confidence": c["confidence"],
            "summary": c["summary"], "evidence_chain": c["evidence"], "suggested_fix": c["suggested_fix"],
            "fleet_impact": fleet_impact, "fleet_diff": diff.as_dict(),
            "crash_dump": dump or None, "crash_text": crash_text(dump),
            "hang_dump": hdump or None, "hang_text": hang_text(hdump), "policy_feedback": feedback, "probes": probe_log, "rounds": rounds,
            "generated_at": datetime.now(timezone.utc).isoformat()}
