"""CLI.

  python -m ieso_investigator investigate (--incident ID | --latest [--endpoint EP])
                                           [--reasoner auto|claude|rule|replay] [--recording FILE] [--record FILE]
  python -m ieso_investigator watch [--reasoner auto|claude|rule] [--interval 5] [--max-per-hour 20]
  python -m ieso_investigator doctor [--live]

The Claude API key is read from ANTHROPIC_API_KEY only and is never printed or stored.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .api import ApiError, ControlPlane
from .fleet_diff import classify
from .loop import investigate
from .reasoners import DEFAULT_MODEL, ClaudeReasoner, InvalidDecision, Recorder, ReplayReasoner, RuleReasoner
from .report import to_markdown

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RECORDING = os.path.join(HERE, "recordings", "network-tls-interception.json")


def _model() -> str:
    return (os.environ.get("IESO_CLAUDE_MODEL") or DEFAULT_MODEL)


def _has_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def build_reasoner(args) -> tuple[object, str]:
    """Picks the reasoner and the banner line that tells the user which mode is active."""
    choice = args.reasoner
    if choice == "auto":
        choice = "claude" if _has_key() else "rule"
        if choice == "rule":
            return RuleReasoner(), ("Claude reasoner: DISABLED: no ANTHROPIC_API_KEY (offline rule reasoner; "
                                    "set the key or use --reasoner replay)")
    if choice == "claude":
        if not _has_key():
            raise SystemExit("--reasoner claude needs ANTHROPIC_API_KEY (see investigator/README.md)")
        recorder = Recorder(args.record, args.scenario) if args.record else None
        return ClaudeReasoner(model=_model(), recorder=recorder), f"Claude reasoner: ENABLED ({_model()})"
    if choice == "replay":
        r = ReplayReasoner(args.recording)
        return r, f"Claude reasoner: REPLAY (recording from {r.recorded_at}, {r.model}; no API call is made)"
    return RuleReasoner(), "Claude reasoner: DISABLED (offline rule reasoner selected)"


def latest_incident(cp: ControlPlane, endpoint: str) -> str:
    """Newest investigable incident on a real (non-simulated) endpoint, or on the given endpoint."""
    simulated = {ep["id"] for ep in cp.fleet() if ep.get("simulated")}
    for inc in cp.incidents(endpoint=endpoint, limit=500):
        if (endpoint or inc["endpoint"] not in simulated) and classify(inc["type"], inc.get("data", {})):
            return inc["id"]
    raise SystemExit("no investigable incident found" + (f" on {endpoint}" if endpoint else ""))


def cmd_investigate(args) -> int:
    cp = ControlPlane(args.control_plane)
    try:
        reasoner, banner = build_reasoner(args)
    except (InvalidDecision, OSError) as e:
        print(f"cannot load reasoner: {e}", file=sys.stderr)
        return 2
    print(f"[investigator] {banner}")
    incident_id = args.incident or latest_incident(cp, args.endpoint)
    try:
        report = investigate(cp, incident_id, reasoner, max_rounds=args.rounds, probe_timeout_s=args.probe_timeout)
    except ApiError as e:
        print(f"control plane error: {e}", file=sys.stderr)
        return 1
    rec = getattr(reasoner, "recorder", None)
    if rec is not None and rec.rounds:
        rec.save()
        print(f"[investigator] recorded {len(rec.rounds)} Claude round(s) to {rec.path}")
    report_id = cp.post_report(report)
    print(f"[investigator] report {report_id} stored in the control plane\n")
    print(json.dumps(report, indent=1) if args.json else to_markdown(report))
    return 0


def cmd_watch(args) -> int:
    from .watch import watch

    if args.reasoner == "replay":
        print("watch mode cannot replay a recording; use auto, claude or rule", file=sys.stderr)
        return 2
    args.record = ""
    _, banner = build_reasoner(args)
    print(f"[investigator] {banner}", flush=True)
    watch(ControlPlane(args.control_plane), lambda: build_reasoner(args)[0], interval_s=args.interval,
          lookback_s=args.lookback, max_per_hour=args.max_per_hour, probe_timeout_s=args.probe_timeout,
          log=lambda m: print(m, flush=True))
    return 0


def cmd_doctor(args) -> int:
    ok = True
    try:
        import anthropic

        print(f"anthropic SDK: {anthropic.__version__}")
    except ImportError:
        print("anthropic SDK: NOT INSTALLED (pip install -r requirements.txt)")
        ok = False
    print(f"ANTHROPIC_API_KEY: {'set' if _has_key() else 'not set (offline rule reasoner or --reasoner replay)'}")
    print(f"model: {_model()}")
    print(f"recording: {DEFAULT_RECORDING if os.path.exists(DEFAULT_RECORDING) else 'none yet (create one with --record)'}")
    try:
        print(f"control plane {args.control_plane}: {'ok' if ControlPlane(args.control_plane).healthz() else 'unhealthy'}")
    except (OSError, ApiError) as e:
        print(f"control plane {args.control_plane}: unreachable ({e.__class__.__name__})")
    if args.live and _has_key() and ok:
        try:
            resp = anthropic.Anthropic().messages.create(
                model=_model(), max_tokens=64, output_config={"effort": "low"},
                messages=[{"role": "user", "content": "Reply with the single word: ok"}])
            print(f"live call: ok (stop_reason {resp.stop_reason}, request {resp._request_id})")
        except anthropic.APIStatusError as e:
            body = e.body if isinstance(e.body, dict) else {}
            print(f"live call: FAILED (HTTP {e.status_code}: {body.get('error', {}).get('message', e.message)})")
            ok = False
        except anthropic.APIConnectionError:
            print("live call: FAILED (cannot reach the API)")
            ok = False
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ieso_investigator", description=__doc__.splitlines()[0])
    ap.add_argument("--control-plane", default=os.environ.get("CONTROL_PLANE", "http://control-plane:8000"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("investigate", help="investigate one incident")
    g = inv.add_mutually_exclusive_group(required=True)
    g.add_argument("--incident")
    g.add_argument("--latest", action="store_true", help="newest incident on a real (non-simulated) endpoint")
    inv.add_argument("--endpoint", default="", help="with --latest: restrict to this endpoint")
    inv.add_argument("--reasoner", choices=["auto", "claude", "rule", "replay"], default="auto")
    inv.add_argument("--recording", default=DEFAULT_RECORDING, help="replay mode: recorded Claude session")
    inv.add_argument("--record", default="", help="claude mode: save the session for replay")
    inv.add_argument("--scenario", default="network-tls-interception", help="name stored in a recording")
    inv.add_argument("--rounds", type=int, default=3)
    inv.add_argument("--probe-timeout", type=float, default=60.0)
    inv.add_argument("--json", action="store_true", help="print the report as JSON instead of Markdown")
    w = sub.add_parser("watch", help="investigate every new incident on real endpoints, continuously")
    w.add_argument("--reasoner", choices=["auto", "claude", "rule"], default="auto")
    w.add_argument("--scenario", default="", help=argparse.SUPPRESS)
    w.add_argument("--interval", type=float, default=5.0, help="seconds between polls")
    w.add_argument("--lookback", type=int, default=1800, help="at startup, pick up incidents this many seconds old")
    w.add_argument("--max-per-hour", type=int, default=20, help="cost guard for a live Claude reasoner")
    w.add_argument("--probe-timeout", type=float, default=60.0)
    doc = sub.add_parser("doctor", help="check SDK, key presence, model and control plane (never prints the key)")
    doc.add_argument("--live", action="store_true", help="also make one minimal API call")
    args = ap.parse_args(argv)
    return {"investigate": cmd_investigate, "watch": cmd_watch, "doctor": cmd_doctor}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
