#!/usr/bin/env python3
"""Compact sensor test runner: one process per GoogleTest suite, quiet output, summary table.

    scripts/run_tests.py [--preset debug|asan|tsan|release] [--filter REGEX] [--timeout SEC] [--no-build]
                         [--list] [--binary PATH ...]

Output:
    platform: ...
    [  3%] ===== Bus =====
    [==========] 7 tests from 1 test suite ran. (35 ms total)
    [  PASSED  ] 7 tests.
    ...failure details only when a test fails...
    table: suite / ran / passed / failed / fail% / result, then total and the platform line.

Sensor trace lines (FATAL..TRACE) and gtest per-test chatter are dropped; assertion failures are kept.
Exit code: 0 if every suite passed, 1 otherwise, 2 on setup errors.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# CMake and Ninja from MacPorts (/opt/local/bin) or Homebrew, even when the caller's PATH lacks them (apps launched
# from the Dock or VS Code). Appended, so the tools macOS ships keep precedence. Mirrors scripts/lib/build_tools.sh.
for _d in ("/opt/local/bin", "/opt/local/sbin", "/opt/homebrew/bin", "/usr/local/bin"):
    if os.path.isdir(_d) and _d not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _d
BINARIES = ["sensor/tests/ieso_tests", "sensor/tests/ieso_macos_tests"]

TRACE_LINE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z (FATAL|ERROR|WARNING|INFO|DEBUG|TRACE)\s")
SUMMARY_RAN = re.compile(r"^\[=+\] (\d+) tests? from (\d+) test suites? ran\.")
SUMMARY_PASSED = re.compile(r"^\[  PASSED  \] (\d+) tests?\.")
FAILED_TEST = re.compile(r"^\[  FAILED  \] (\S+)")
NOISE = re.compile(r"^(Running main\(\) from|Note: Google Test filter|\[----------\]|\[ RUN      \]|\[       OK \]|"
                   r"\[==========\] Running|\s*YOU HAVE \d+ DISABLED)")


@dataclass
class Result:
    """Outcome of one suite run."""
    suite: str
    ran: int = 0
    passed: int = 0
    failed: int = 0
    result: str = "ok"


def run(cmd: list[str], timeout: float | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                          timeout=timeout, errors="replace")


def platform_line() -> str:
    os_name = "macOS " + platform.mac_ver()[0] if sys.platform == "darwin" else platform.system()
    kernel = platform.release()
    arch = platform.machine()
    virt = "bare metal"
    if sys.platform == "darwin":
        out = run(["/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"]).stdout.strip()
        virt = "virtual machine" if out == "1" else "bare metal"
    elif os.path.exists("/proc/cpuinfo") and "hypervisor" in open("/proc/cpuinfo").read():
        virt = "virtual machine"
    debugger = "lldb" if shutil.which("lldb") else ("gdb" if shutil.which("gdb") else "none")
    return f"platform: {os_name}, kernel {kernel}, {arch}, {virt}, host {socket.gethostname()}, debugger {debugger}"


def list_suites(binary: str) -> list[tuple[str, int]]:
    """Returns (suite, number of tests) in declaration order."""
    suites: list[tuple[str, int]] = []
    for line in run([binary, "--gtest_list_tests"], timeout=60).stdout.splitlines():
        if line and not line.startswith(" ") and line.endswith("."):
            suites.append((line[:-1], 0))
        elif line.startswith("  ") and suites:
            suites[-1] = (suites[-1][0], suites[-1][1] + 1)
    return suites


def filter_output(text: str) -> list[str]:
    """Keeps gtest summaries and failure details; drops sensor traces and per-test chatter."""
    kept = []
    for line in text.splitlines():
        if TRACE_LINE.match(line) or NOISE.match(line) or not line.strip():
            continue
        if line.startswith("[  FAILED  ] ") and "listed below" in line:
            break  # the trailing recap repeats what was already printed
        kept.append(line)
    return kept


def last_started(text: str) -> str:
    """Name of the last test gtest started (the one running when a process died)."""
    name = ""
    for line in text.splitlines():
        if line.startswith("[ RUN      ] "):
            name = line[len("[ RUN      ] "):].strip()
        elif line.startswith(("[       OK ] ", "[  FAILED  ] ")):
            name = ""
    return name


def run_suite(binary: str, suite: str, count: int, timeout: float) -> tuple[Result, list[str], int]:
    res = Result(suite)
    started = time.monotonic()
    try:
        proc = run([binary, f"--gtest_filter={suite}.*", "--gtest_color=no"], timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        text = exc.output if isinstance(exc.output, str) else ""
        lines = filter_output(text)
        hung = last_started(text)
        lines.append(f"timed out after {timeout:.0f} s" + (f" in {hung}" if hung else ""))
        res.result = "TIMEOUT"
        res.ran = res.failed = count
        return res, lines, -1
    lines = filter_output(proc.stdout)
    for line in lines:
        if m := SUMMARY_RAN.match(line):
            res.ran = int(m.group(1))
        elif m := SUMMARY_PASSED.match(line):
            res.passed = int(m.group(1))
        elif FAILED_TEST.match(line) and "(" in line:
            res.failed += 1
    if proc.returncode != 0:
        if res.ran == 0:  # died before the summary (abort, signal, sanitizer report, ...)
            res.result = "CRASHED"
            res.ran, res.passed = count, proc.stdout.count("[       OK ] ")
            res.failed = count - res.passed
            crashed = last_started(proc.stdout)
            lines = [line for line in proc.stdout.splitlines()[-40:] if not NOISE.match(line) and line.strip()]
            if crashed:
                lines.append(f"crashed in {crashed}")
        else:
            res.result = "FAILED"
            res.failed = max(res.failed, res.ran - res.passed)
        lines.append(f"Process exited with status = {proc.returncode} (after {time.monotonic() - started:.1f} s)")
    return res, lines, proc.returncode


def table(results: list[Result]) -> list[str]:
    width = max([len("suite"), len("total")] + [len(r.suite) for r in results])
    head = f"  {'suite':<{width}}  {'ran':>5}  {'passed':>6}  {'failed':>6}  {'fail%':>6}  {'result':<8}"
    rule = f"  {'-' * width}  {'-' * 5}  {'-' * 6}  {'-' * 6}  {'-' * 6}  {'-' * 8}"

    def row(name: str, ran: int, passed: int, failed: int, result: str) -> str:
        pct = f"{(100 * failed // ran) if ran else (100 if failed else 0)}%"
        return f"  {name:<{width}}  {ran:>5}  {passed:>6}  {failed:>6}  {pct:>6}  {result:<8}"

    out = [head, rule] + [row(r.suite, r.ran, r.passed, r.failed, r.result) for r in results]
    ran = sum(r.ran for r in results)
    passed = sum(r.passed for r in results)
    failed = sum(r.failed for r in results)
    bad = any(r.result != "ok" for r in results)
    out += [rule, row("total", ran, passed, failed, "FAILED" if bad else "ok")]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preset", default="debug", help="CMake preset / build dir (default: debug)")
    ap.add_argument("--filter", default="", help="only suites whose name matches this regex")
    ap.add_argument("--timeout", type=float, default=300, help="per-suite timeout in seconds (default 300)")
    ap.add_argument("--no-build", action="store_true", help="do not (re)build before running")
    ap.add_argument("--list", action="store_true", help="print the suite names and exit")
    ap.add_argument("--binary", action="append", default=[],
                    help="run this gtest binary instead of the sensor test binaries (repeatable; implies --no-build)")
    args = ap.parse_args()
    if args.binary:
        args.no_build = True

    if not args.no_build:
        missing = [t for t in ("cmake", "ninja") if shutil.which(t) is None]
        if missing:
            print(f"missing build tools: {' '.join(missing)}. Install MacPorts (https://www.macports.org/install.php), then:\n"
                  "    sudo port selfupdate && sudo port install cmake ninja")
            return 2
        if not os.path.isdir(os.path.join(ROOT, "build", args.preset)):
            c = run(["cmake", "--preset", args.preset])
            if c.returncode != 0:
                print(c.stdout[-4000:])
                print(f"configure failed (preset {args.preset})")
                return 2
        b = run(["cmake", "--build", "--preset", args.preset])
        if b.returncode != 0:
            print(b.stdout[-4000:])
            print(f"build failed (preset {args.preset})")
            return 2

    binaries = [os.path.abspath(b) for b in args.binary] or [os.path.join(ROOT, "build", args.preset, r) for r in BINARIES]
    jobs: list[tuple[str, str]] = []
    for binary in binaries:
        if os.path.exists(binary):
            jobs += [(binary, s, n) for s, n in list_suites(binary) if re.search(args.filter, s)]
    if not jobs:
        print(f"no test suites found under build/{args.preset} (configure with: cmake --preset {args.preset})")
        return 2
    if args.list:
        for binary, suite, n in jobs:
            print(f"{suite:<20} {n:>3} tests  {os.path.relpath(binary, ROOT)}")
        return 0

    plat = platform_line()
    print(plat)

    results: list[Result] = []
    for i, (binary, suite, n) in enumerate(jobs, 1):
        print(f"[{100 * i // len(jobs):3d}%] ===== {suite} =====", flush=True)
        res, lines, _ = run_suite(binary, suite, n, args.timeout)
        for line in lines:
            print(line)
        results.append(res)

    print()
    for line in table(results):
        print(line)
    print(f"  {plat}")
    return 0 if all(r.result == "ok" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
