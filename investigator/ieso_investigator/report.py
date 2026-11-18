"""Markdown rendering of an investigation report."""

from __future__ import annotations


def to_markdown(r: dict) -> str:
    lines = [f"# Investigation report: {r['incident_id']}", "",
             f"- **Endpoint:** {r['endpoint']}  ",
             f"- **Symptom:** {r['symptom']}  ",
             f"- **Reasoner:** {r['reasoner']}  ",
             f"- **Root cause:** `{r['root_cause']}` (confidence {r['confidence']:.2f})", "",
             r["summary"], "", "## Evidence chain"]
    lines += [f"{i}. {e}" for i, e in enumerate(r["evidence_chain"], 1)]
    if r.get("hang_text"):
        lines += ["", "## Hang stack (main thread, heaviest path)", "```", r["hang_text"], "```"]
    if r.get("crash_text"):
        lines += ["", "## Crash dump", "```", r["crash_text"], "```"]
    fi = r.get("fleet_impact")
    lines += ["", "## Fleet impact"]
    if fi:
        lines += [f"- {fi['affected']}/{fi['carriers']} endpoints with `{fi['attribute']}={fi['value']}` affected "
                  f"(lift {fi['lift']}x); {fi['affected_endpoints']}/{fi['fleet_size']} affected fleet-wide.",
                  f"- {fi['endpoints_at_risk']} more endpoints carry `{fi['attribute']}={fi['value']}` and are at risk."]
    else:
        lines.append("- No attribute of this endpoint is over-represented among affected endpoints.")
    lines += ["", "## Suggested fix", r["suggested_fix"], "", "## Probes"]
    lines += [f"- `{p['probe_id']}` ({p['request_id'][:8]}): {p.get('status', '?')}, exit {p.get('exit_status')}"
              for p in r["probes"]] or ["- none"]
    lines += ["", "## Rounds"]
    for rd in r["rounds"]:
        hyps = ", ".join(f"{h['cause']} {h['confidence']:.2f}" for h in rd["hypotheses"])
        lines.append(f"- round {rd['round']}: {hyps}; approved {rd['approved'] or '-'}"
                     + (f"; rejected {[x['probe_id'] for x in rd['rejected']]}" if rd["rejected"] else ""))
    return "\n".join(lines) + "\n"
