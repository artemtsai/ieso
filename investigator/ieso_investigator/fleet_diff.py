"""Symptom classification and fleet differential diagnosis (DESIGN.md §10.1).

An endpoint is "affected" when one of its incidents has the same symptom as the incident under investigation
(for crashes: the same crash signature). For every attribute value we compute the lift
P(affected | value) / P(affected) with a minimum support, so rare values cannot dominate by chance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

NETWORK_WORDS = re.compile(r"cannot reach|can't reach|network|offline|timed out|connection|certificate|tls|ssl|"
                           r"server|sync failed", re.IGNORECASE)
PERMISSION_WORDS = re.compile(r"permission|denied|not permitted|operation not allowed", re.IGNORECASE)

MIN_SUPPORT = 5   # endpoints carrying the attribute value
MIN_LIFT = 1.5


@dataclass(frozen=True)
class Symptom:
    """What the user saw, normalized: kind in {network, permission, ui_error, crash, hang, resource}."""

    kind: str
    key: str = ""  # crash signature, or "" when the kind alone identifies the symptom

    def label(self) -> str:
        return f"{self.kind} ({self.key})" if self.key else self.kind


def classify(event_type: str, data: dict) -> Optional[Symptom]:
    """Maps one incident event (CloudEvent type + sanitized data) to a symptom; None for non-incidents."""
    short = event_type.rsplit(".", 1)[-1]
    if short == "ProcessCrashDetected":
        return Symptom("crash", data.get("signature", ""))
    if short == "ProcessHangDetected":
        return Symptom("hang")
    if short == "ResourceAnomalyDetected":
        return Symptom("resource", data.get("metric", ""))
    if short == "UserVisibleErrorObserved":
        text = f"{data.get('window_title', '')} {data.get('dialog_text', '')}"
        if PERMISSION_WORDS.search(text):
            return Symptom("permission")
        if NETWORK_WORDS.search(text):
            return Symptom("network")
        return Symptom("ui_error")
    return None


@dataclass
class AttributeLift:
    """One attribute value's association with the symptom."""

    attribute: str
    value: str
    affected: int       # affected endpoints with this value
    carriers: int       # endpoints with this value
    lift: float
    endpoint_has_it: bool  # the investigated endpoint carries this value

    def as_dict(self) -> dict:
        return {"attribute": self.attribute, "value": self.value, "affected": self.affected,
                "carriers": self.carriers, "rate": round(self.affected / self.carriers, 3) if self.carriers else 0,
                "lift": round(self.lift, 2), "endpoint_has_it": self.endpoint_has_it}


@dataclass
class FleetDiff:
    """Result of the differential diagnosis over the whole fleet."""

    symptom: Symptom
    total: int
    affected: int
    ranked: list[AttributeLift] = field(default_factory=list)

    def top(self) -> Optional[AttributeLift]:
        """Strongest association the investigated endpoint shares, else the strongest overall."""
        shared = [a for a in self.ranked if a.endpoint_has_it]
        return (shared or self.ranked or [None])[0]

    def as_dict(self, limit: int = 5) -> dict:
        return {"symptom": self.symptom.label(), "fleet_size": self.total, "affected_endpoints": self.affected,
                "baseline_rate": round(self.affected / self.total, 3) if self.total else 0,
                "top_attributes": [a.as_dict() for a in self.ranked[:limit]]}


def affected_by(endpoint: dict, symptom: Symptom) -> bool:
    """True when any incident of the endpoint matches the symptom."""
    return any(classify(i.get("type", ""), i.get("data") or {}) == symptom for i in endpoint.get("incidents", []))


def fleet_diff(fleet: list[dict], symptom: Symptom, endpoint_id: str) -> FleetDiff:
    """Ranks attribute values by lift; only endpoints with an attribute inventory take part."""
    inventoried = [ep for ep in fleet if ep.get("attributes")]
    me = next((ep for ep in fleet if ep.get("id") == endpoint_id), {})
    my_attrs = me.get("attributes") or {}
    hit = {ep["id"] for ep in inventoried if affected_by(ep, symptom)}
    total, affected = len(inventoried), len(hit)
    diff = FleetDiff(symptom, total, affected)
    if not total or not affected:
        return diff
    base = affected / total
    counts: dict[tuple[str, str], list[int]] = {}
    for ep in inventoried:
        for attr, value in ep["attributes"].items():
            c = counts.setdefault((attr, str(value)), [0, 0])
            c[1] += 1
            c[0] += int(ep["id"] in hit)
    for (attr, value), (aff, carriers) in counts.items():
        if carriers < MIN_SUPPORT or aff < MIN_SUPPORT:
            continue
        lift = (aff / carriers) / base
        if lift >= MIN_LIFT:
            diff.ranked.append(AttributeLift(attr, value, aff, carriers, lift, str(my_attrs.get(attr)) == value))
    diff.ranked.sort(key=lambda a: (a.lift, a.affected), reverse=True)
    return diff
