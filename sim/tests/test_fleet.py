"""The generator is deterministic and the injected causes are visible in the data."""

from ieso_sim.fleet import generate


def rate(fleet, attr, value, etype):
    eps = [e for e in fleet if e["attributes"][attr] == value]
    hit = [e for e in eps if any(i["type"].endswith(etype) for i in e["incidents"])]
    return len(hit) / max(1, len(eps))


def test_deterministic():
    assert generate(50, seed=3)[7]["attributes"] == generate(50, seed=3)[7]["attributes"]


def test_injected_causes_dominate():
    f = generate(200, seed=7)
    assert len(f) == 200 and all(e["attributes"]["app_version"] == "1.4.2" for e in f)
    assert rate(f, "proxy", "corpguard-swg 5.2", "UserVisibleErrorObserved") > 0.75
    assert rate(f, "proxy", "none", "UserVisibleErrorObserved") < 0.1
    assert rate(f, "dlp_extension", "datashield 4.2", "ProcessCrashDetected") > 0.7
    assert rate(f, "os_build", "24G90", "ProcessHangDetected") > 0.5


def test_events_are_cloudevents_from_their_endpoint():
    for ep in generate(30, seed=1):
        for ev in ep["incidents"]:
            assert ev["source"] == f"ieso://endpoint/{ep['id']}" and ev["id"].startswith(ep["id"])
