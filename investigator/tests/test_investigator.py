"""Fleet diff, policy, rule reasoner and the full loop against the fake control plane."""

from __future__ import annotations

from conftest import FakeControlPlane, quiet, tls_output

from ieso_investigator.evidence import parse_synthetic_tls
from ieso_investigator.fleet_diff import Symptom, classify, fleet_diff
from ieso_investigator.loop import investigate, policy_check
from ieso_investigator.reasoners import RuleReasoner
from ieso_investigator.report import to_markdown


def test_classify():
    assert classify("com.ieso.UserVisibleErrorObserved", {"dialog_text": "Cannot reach server"}) == Symptom("network")
    assert classify("com.ieso.UserVisibleErrorObserved", {"dialog_text": "Permission denied"}) == Symptom("permission")
    assert classify("com.ieso.ProcessCrashDetected", {"signature": "X+0x1"}) == Symptom("crash", "X+0x1")
    assert classify("com.ieso.ProcessHangDetected", {}) == Symptom("hang")
    assert classify("com.ieso.ProbeResultReady", {}) is None


def test_fleet_diff_finds_each_injected_cause(cp):
    net = fleet_diff(cp.fleet(), Symptom("network"), "ep-demo")
    assert (net.top().attribute, net.top().value, net.top().endpoint_has_it) == ("proxy", "corpguard-swg 5.2", True)
    crash = fleet_diff(cp.fleet(), Symptom("crash", "DemoApp+0x6455 EXC_BAD_ACCESS"), "sim-001")
    assert (crash.ranked[0].attribute, crash.ranked[0].value) == ("dlp_extension", "datashield 4.2")
    hang = fleet_diff(cp.fleet(), Symptom("hang"), "sim-001")
    assert (hang.ranked[0].attribute, hang.ranked[0].value) == ("os_build", "24G90")


def test_policy_check_rejects_offlist_repeats_and_over_budget():
    approved, rejected = policy_check(["net.config", "shell.exec", "net.config", "net.synthetic_tls"], {"env.extensions"}, 1)
    assert approved == ["net.config"]
    assert [r["probe_id"] for r in rejected] == ["shell.exec", "net.config", "net.synthetic_tls"]


def test_synthetic_tls_issuer_mismatch():
    assert parse_synthetic_tls(tls_output())["issuer_mismatch"] is True
    same = tls_output(via_issuer="CN=DemoApp Backend CA,O=DemoApp Inc")
    assert parse_synthetic_tls(same)["issuer_mismatch"] is False
    assert "parse_error" in parse_synthetic_tls("not json")


def test_rule_loop_concludes_tls_interception(cp):
    report = investigate(cp, "ep-demo-net-1", RuleReasoner(), log=quiet)
    assert report["root_cause"] == "tls_interception"
    assert report["confidence"] >= 0.8
    assert [p["probe_id"] for p in report["probes"]] == ["net.config", "net.synthetic_tls"]
    assert all(p["status"] == "done" for p in report["probes"])
    assert any("CorpGuard TLS Inspection CA" in e for e in report["evidence_chain"])
    assert report["fleet_impact"]["value"] == "corpguard-swg 5.2"
    assert report["rounds"][0]["rule"] == "network: proxy/TLS path comparison"
    assert "issuer_mismatch=True" in report["rounds"][0]["probe_results"][1]
    assert report["fleet_impact"]["endpoints_at_risk"] >= 0
    md = to_markdown(report)
    assert "tls_interception" in md and "Evidence chain" in md


def test_refused_probes_yield_low_confidence_unknown():
    report = investigate(FakeControlPlane(refuse=True), "ep-demo-net-1", RuleReasoner(), log=quiet)
    assert report["root_cause"] == "unknown"
    assert report["confidence"] < 0.8
    assert all(p["status"] == "refused" for p in report["probes"])


def test_crash_rule_probes_extensions():
    cp = FakeControlPlane()
    victim = next(ep for ep in cp.fleet() if ep["attributes"]["dlp_extension"] == "datashield 4.2"
                  and any(i["type"].endswith("ProcessCrashDetected") for i in ep["incidents"]))
    inc = next(i["id"] for i in victim["incidents"] if i["type"].endswith("ProcessCrashDetected"))
    report = investigate(cp, inc, RuleReasoner(), log=quiet)
    assert report["root_cause"] == "dlp_extension_conflict"
    assert [p["probe_id"] for p in report["probes"]] == ["env.extensions"]


def test_app_bug_report_carries_the_crash_dump():
    cp = FakeControlPlane()
    cp.fleet_data[-1]["incidents"].append({
        "id": "ep-demo-crash-1", "type": "com.ieso.ProcessCrashDetected",
        "data": {"pid": 85583, "exception_type": "EXC_BAD_ACCESS", "signal": "SIGSEGV",
                 "termination_reason": "SIGNAL: Segmentation fault: 11", "faulting_module": "DemoApp",
                 "offset": 0x8875, "signature": "DemoApp+0x8875 EXC_BAD_ACCESS",
                 "exception_subtype": "KERN_INVALID_ADDRESS at 0x0000000000000008",
                 "exception_codes": "0x0000000000000001, 0x0000000000000008", "app_version": "1.4.2",
                 "crashed_thread": "0 (com.apple.main-thread)",
                 "backtrace": "0 DemoApp +0x8875 AppDelegate.faultCrash() + 949\n"
                              "1 DemoApp +0x76a2 closure #1 in AppDelegate.scheduleFaultFromArguments() + 610\n"
                              "2 libdispatch.dylib +0x178b2 _dispatch_client_callout + 6\n"}})
    report = investigate(cp, "ep-demo-crash-1", RuleReasoner(), log=quiet)
    assert report["root_cause"] == "app_bug" and report["confidence"] >= 0.8
    dump = report["crash_dump"]
    assert dump["faulting_address"] == 8 and dump["access"].startswith("NULL-pointer dereference")
    assert dump["faulting_frame"].startswith("0 DemoApp +0x8875 AppDelegate.faultCrash()")
    assert any("AppDelegate.faultCrash()" in e for e in report["evidence_chain"])
    assert "AppDelegate.faultCrash()" in report["suggested_fix"]
    md = to_markdown(report)
    assert "## Crash dump" in md and "crashed thread 0 (com.apple.main-thread)" in md


def test_watch_investigates_each_real_incident_once():
    from ieso_investigator.watch import watch

    cp = FakeControlPlane()
    n = watch(cp, RuleReasoner, interval_s=0, iterations=3, log=quiet)
    assert n == 1  # only ep-demo is real; simulated endpoints' incidents are ignored
    assert [r["incident_id"] for r in cp.reports_store] == ["ep-demo-net-1"]
    assert cp.reports_store[0]["root_cause"] == "tls_interception"
    assert watch(cp, RuleReasoner, interval_s=0, iterations=1, log=quiet) == 0  # restart: already reported


def test_watch_respects_the_hourly_cap_and_keeps_the_incident():
    from ieso_investigator.watch import watch

    cp = FakeControlPlane()
    logs: list[str] = []
    assert watch(cp, RuleReasoner, interval_s=0, iterations=3, max_per_hour=0, log=logs.append) == 0
    assert sum("hourly cap" in m for m in logs) == 1  # said once, not every poll
    assert cp.reports_store == []
    # the capped incident was not dropped: once the cap allows it, it is investigated
    assert watch(cp, RuleReasoner, interval_s=0, iterations=1, max_per_hour=5, log=quiet) == 1


HANG_SAMPLE = open(__import__("os").path.join(__import__("os").path.dirname(__file__), "fixtures", "hang_sample.txt")).read()


def _hang_cp(with_sample: bool = True) -> FakeControlPlane:
    cp = FakeControlPlane()
    cp.fleet_data[-1]["incidents"].append({"id": "ep-demo-hang-1", "type": "com.ieso.ProcessHangDetected",
                                           "data": {"pid": 9447, "probe_latency_ms": 1000, "duration_ms": 7063}})
    if with_sample:
        cp.bundles["ep-demo-hang-1"] = {"deep_capture": {"kind": "sample", "status": "Ok", "text": HANG_SAMPLE}}
    return cp


def test_hang_dump_parses_the_main_thread_heaviest_path():
    from ieso_investigator.evidence import hang_dump

    d = hang_dump(HANG_SAMPLE, 7063)
    assert d["thread"].startswith("DispatchQueue_1: com.apple.main-thread")
    assert d["frames"][0].startswith("0 libsystem_kernel.dylib __semwait_signal")
    assert d["app_frame"] == "3 DemoApp AppDelegate.faultHang() + 890 (main.swift:140)"
    assert d["blocking"].startswith("sleeping") and d["network_frames"] == []
    assert d["heaviest_samples"] == d["samples"] > 0
    assert hang_dump("no call graph here") == {}


def test_hang_in_app_code_is_an_app_bug_with_its_stack():
    report = investigate(_hang_cp(), "ep-demo-hang-1", RuleReasoner(), log=quiet, bundle_wait_s=0)
    assert report["root_cause"] == "app_bug" and report["confidence"] >= 0.8
    assert "AppDelegate.faultHang()" in report["hang_text"] and "AppDelegate.faultHang()" in report["suggested_fix"]
    assert "## Hang stack" in to_markdown(report)


def test_policy_rejects_network_blame_for_a_hang_without_network_frames():
    class Overreach:
        label = "test"

        def decide(self, context):
            return {"hypotheses": [{"cause": "tls_interception", "confidence": 0.9, "rationale": "proxy"}],
                    "next_probes": [], "done": True,
                    "conclusion": {"root_cause": "tls_interception", "confidence": 0.9, "summary": "proxy",
                                   "evidence": ["interception seen"], "suggested_fix": "bypass"}}

    report = investigate(_hang_cp(), "ep-demo-hang-1", Overreach(), log=quiet, bundle_wait_s=0)
    assert report["root_cause"] == "unknown" and report["confidence"] <= 0.3
    assert report["policy_feedback"] and "no frame of the hung main thread" in report["policy_feedback"][0]


def test_hang_without_a_sample_stays_unknown():
    report = investigate(_hang_cp(with_sample=False), "ep-demo-hang-1", RuleReasoner(), log=quiet, bundle_wait_s=0)
    assert report["root_cause"] == "unknown" and report["hang_dump"] is None
