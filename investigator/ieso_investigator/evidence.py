"""Turns raw probe results (sanitized ProbeResultReady payloads) into small, comparable facts."""

from __future__ import annotations

import json
import re
from typing import Any

MAX_RAW = 3000  # characters of raw probe output passed on to a reasoner


def _leaf_issuer(path: dict) -> str:
    chain = path.get("chain") or []
    return str(chain[0].get("issuer", "")) if chain else ""


def _leaf_subject(path: dict) -> str:
    chain = path.get("chain") or []
    return str(chain[0].get("subject", "")) if chain else ""


def parse_synthetic_tls(output: str) -> dict[str, Any]:
    """net.synthetic_tls: per-path leaf issuer, TLS version, status; flags an issuer mismatch (interception)."""
    try:
        doc = json.loads(output)
    except ValueError:
        return {"parse_error": "net.synthetic_tls output is not JSON"}
    paths = {}
    for p in doc.get("paths", []):
        paths[p.get("path", "?")] = {
            "proxy": p.get("proxy", ""), "leaf_subject": _leaf_subject(p), "leaf_issuer": _leaf_issuer(p),
            "chain_length": len(p.get("chain") or []), "tls_version": p.get("tls_version", ""),
            "http_status": int(p.get("http_status") or 0), "error": p.get("error", ""),
            "verify_error_system_trust": p.get("verify_error_system_trust", ""),
        }
    facts: dict[str, Any] = {"target": doc.get("target", ""), "paths": paths}
    via, direct = paths.get("via_proxy"), paths.get("direct")
    if via and direct:
        facts["issuer_mismatch"] = bool(via["leaf_issuer"] and direct["leaf_issuer"]
                                        and via["leaf_issuer"] != direct["leaf_issuer"])
        facts["direct_reachable"] = direct["http_status"] > 0 or bool(direct["leaf_issuer"])
        facts["proxy_reachable"] = via["http_status"] > 0 or bool(via["leaf_issuer"])
    elif direct:
        facts["direct_reachable"] = direct["http_status"] > 0 or bool(direct["leaf_issuer"])
    return facts


def parse_net_config(output: str) -> dict[str, Any]:
    """net.config: the effective HTTPS proxy plus a hint whether DNS resolvers are configured."""
    m = re.search(r"effective_https_proxy:\s*(\S+)", output)
    return {"effective_https_proxy": m.group(1) if m else "unknown",
            "dns_resolvers_present": "nameserver" in output}


def parse_extensions(output: str) -> dict[str, Any]:
    """env.extensions: the lines of `systemextensionsctl list` that name an extension."""
    lines = [ln.strip() for ln in output.splitlines() if "\t" in ln or "[activated" in ln]
    return {"extensions": lines[:20]}


PARSERS = {"net.synthetic_tls": parse_synthetic_tls, "net.config": parse_net_config, "env.extensions": parse_extensions}


def summarize(probe: dict) -> dict[str, Any]:
    """Probe record from the control plane -> {probe_id, status, exit_status, facts, raw (truncated)}."""
    result = probe.get("result") or {}
    output = str(result.get("output", ""))
    exit_status = int(result.get("exit_status", 0)) if result else None
    status = probe.get("status", "unknown")
    facts: dict[str, Any] = {}
    if status == "done" and exit_status == 0 and probe.get("probe_id") in PARSERS:
        facts = PARSERS[probe["probe_id"]](output)
    return {"probe_id": probe.get("probe_id", ""), "request_id": probe.get("request_id", ""), "status": status,
            "exit_status": exit_status, "facts": facts, "raw": output[:MAX_RAW]}


PAGE_ZERO = 0x1000  # macOS maps nothing below 4 KB: faults there are NULL-pointer dereferences


def crash_dump(data: dict) -> dict[str, Any]:
    """Crash details from a sanitized ProcessCrashDetected payload (parsed from the endpoint's .ips report)."""
    frames = [ln.strip() for ln in str(data.get("backtrace", "")).splitlines() if ln.strip()]
    subtype = str(data.get("exception_subtype", ""))
    m = re.search(r"at (0x[0-9a-fA-F]+)", subtype)
    address = int(m.group(1), 16) if m else None
    if address is None:
        access = ""
    elif address < PAGE_ZERO:
        access = f"NULL-pointer dereference (address {address:#x} lies in the unmapped page zero)"
    else:
        access = f"invalid memory access at {address:#x}"
    in_app = [f for f in frames if f.split(" ")[1:2] == [data.get("faulting_module", "")]]
    return {"signature": data.get("signature", ""), "exception": data.get("exception_type", ""),
            "signal": data.get("signal", ""), "subtype": subtype, "codes": data.get("exception_codes", ""),
            "termination": data.get("termination_reason", ""), "app_version": data.get("app_version", ""),
            "crashed_thread": data.get("crashed_thread", ""), "faulting_address": address, "access": access,
            "faulting_frame": frames[0] if frames else "", "frames": frames,
            "symbolicated": bool(frames) and " + " in frames[0], "app_frames": len(in_app)}


def crash_text(dump: dict) -> str:
    """Multi-line rendering of crash_dump() for reports and Grafana."""
    if not dump:
        return ""
    lines = [f"{dump['exception']} ({dump['signal']}) {dump['subtype']}".strip()]
    if dump.get("access"):
        lines.append(dump["access"])
    if dump.get("codes"):
        lines.append(f"codes: {dump['codes']}")
    lines.append(f"crashed thread {dump.get('crashed_thread') or '?'}, app {dump.get('app_version') or '?'}")
    lines += [f"  {f}" for f in dump.get("frames", [])[:8]] or ["  (no backtrace in the report)"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------- hang dump (sample)
MAX_HANG_FRAMES = 12
NETWORK_IMAGES = ("CFNetwork", "libnetwork.dylib", "Network", "libboringssl.dylib", "libcurl", "libcoretls")
NETWORK_SYMBOLS = re.compile(r"NSURLSession|NSURLConnection|nw_|tcp_|SSL|tls_|curl_|SecTrustEvaluate|getaddrinfo|"
                             r"connect\b|recv|send\b|DNSService", re.IGNORECASE)
_LINE = re.compile(r"^(?P<prefix>[\s+!:|]*?)(?P<count>\d+) (?P<rest>.+)$")
_FRAME = re.compile(r"^(?P<symbol>.+?)\s+\(in (?P<image>[^)]+)\)(?: \+ (?P<off>\d+))?\s+\[0x[0-9a-f]+\](?:\s+(?P<src>\S+:\d+))?")
_BLOCKING = [(re.compile(r"__semwait_signal|nanosleep|usleep|sleepForTimeInterval"), "sleeping (Thread.sleep / nanosleep)"),
             (re.compile(r"__psynch_mutexwait|__psynch_cvwait|_pthread_mutex|os_unfair_lock"), "waiting on a lock"),
             (re.compile(r"mach_msg"), "waiting on an IPC reply (mach_msg)"),
             (re.compile(r"\bread\b|\bwrite\b|recvfrom|sendto|poll|select|kevent|__open"), "blocked in I/O")]


def _heaviest_path(lines: list[str]) -> list[str]:
    """First root-to-leaf chain of `sample`'s call graph: `sample` sorts children by count, so it is the heaviest."""
    path: list[str] = []
    last_depth = -1
    for ln in lines:
        m = _LINE.match(ln)
        if not m:
            break
        depth = len(m.group("prefix"))
        if depth <= last_depth:
            break  # first leaf reached
        path.append(m.group("rest").strip())
        last_depth = depth
    return path


def hang_dump(sample_text: str, duration_ms: int = 0) -> dict[str, Any]:
    """Main-thread heaviest stack from a sanitized `sample` capture; {} when no capture is available."""
    i = sample_text.find("Call graph:")
    if i < 0:
        return {}
    body = sample_text[i:].splitlines()[1:]
    threads: list[tuple[str, list[str]]] = []
    for ln in body:
        if re.match(r"^\s{4}\d+ Thread_", ln):
            threads.append((ln.strip(), []))
        elif not ln.strip():
            break  # end of the call graph
        elif threads:
            threads[-1][1].append(ln)
    if not threads:
        return {}
    header, lines = next((t for t in threads if "com.apple.main-thread" in t[0]), threads[0])
    samples = int(header.split(" ", 1)[0])
    chain = _heaviest_path(lines)
    leaf_samples = 0
    frames: list[dict] = []
    for raw in chain:
        m = _FRAME.match(raw)
        if m:
            frames.append({"symbol": m.group("symbol"), "image": m.group("image"), "offset": int(m.group("off") or 0),
                           "src": m.group("src") or ""})
    for ln in lines:  # sample count of the leaf of the heaviest path
        m = _LINE.match(ln)
        if m and chain and m.group("rest").strip() == chain[-1]:
            leaf_samples = int(m.group("count"))
            break
    frames.reverse()  # innermost first, like a crash backtrace
    proc = re.search(r"^Process:\s+(\S+)", sample_text, re.MULTILINE)
    app = proc.group(1) if proc else ""
    app_frames = [f for f in frames if f["image"] == app]
    leaf = frames[0]["symbol"] if frames else ""
    blocking = next((why for rx, why in _BLOCKING if rx.search(leaf)), "running (CPU-bound)" if leaf else "")
    network = [f for f in frames if f["image"] in NETWORK_IMAGES or NETWORK_SYMBOLS.search(f["symbol"])]

    def fmt(n: int, f: dict) -> str:
        return f"{n} {f['image']} {f['symbol']} + {f['offset']}" + (f" ({f['src']})" if f["src"] else "")

    return {"thread": header.split("  ", 1)[-1].strip() if "  " in header else header, "samples": samples,
            "heaviest_samples": leaf_samples, "duration_ms": duration_ms, "app": app,
            "frames": [fmt(n, f) for n, f in enumerate(frames[:MAX_HANG_FRAMES])],
            "blocking": blocking, "app_frame": fmt(frames.index(app_frames[0]), app_frames[0]) if app_frames else "",
            "network_frames": [f"{f['image']} {f['symbol']}" for f in network]}


def hang_text(dump: dict) -> str:
    """Multi-line rendering of hang_dump() for reports and Grafana."""
    if not dump:
        return ""
    share = f"{dump['heaviest_samples']}/{dump['samples']} samples" if dump.get("samples") else ""
    lines = [f"main thread {dump.get('blocking') or 'blocked'} for {dump.get('duration_ms', 0)} ms ({share})",
             f"thread: {dump.get('thread', '?')}",
             f"innermost app frame: {dump.get('app_frame') or 'none (blocked outside the app code)'}",
             f"network frames on the stack: {', '.join(dump['network_frames']) if dump.get('network_frames') else 'none'}"]
    lines += [f"  {f}" for f in dump.get("frames", [])[:8]]
    return "\n".join(lines)


def stack_shows_network(crash: dict, hang: dict) -> bool:
    """True when the crashed/hung thread is in network code: the precondition for blaming a network cause."""
    if hang.get("network_frames"):
        return True
    return any(any(img in f for img in NETWORK_IMAGES) or NETWORK_SYMBOLS.search(f) for f in crash.get("frames", []))


def facts_text(summary: dict) -> str:
    """One readable line per probe result for the reasoning trace."""
    pid, status, facts = summary.get("probe_id", ""), summary.get("status", ""), summary.get("facts") or {}
    if status != "done":
        return f"{pid}: {status} {summary.get('raw', '')[:160]}".strip()
    if pid == "net.synthetic_tls" and facts.get("paths"):
        parts = [f"{name}: issuer '{p.get('leaf_issuer') or '?'}', HTTP {p.get('http_status')}"
                 for name, p in facts["paths"].items()]
        return f"{pid}: " + " | ".join(parts) + f" | issuer_mismatch={facts.get('issuer_mismatch')}"
    if pid == "net.config":
        return f"{pid}: effective HTTPS proxy {facts.get('effective_https_proxy')}"
    if pid == "env.extensions":
        return f"{pid}: {len(facts.get('extensions', []))} system extension(s)"
    return f"{pid}: {summary.get('raw', '')[:200]}"
