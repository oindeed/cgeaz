"""Reports: pin to the latest succeeded run, include every source, show run history."""

import datetime

NOW = datetime.datetime.now(datetime.timezone.utc)


def _iso(delta_hours):
    return (NOW - datetime.timedelta(hours=delta_hours)).isoformat()


def _store(fakes):
    Container, _ = fakes
    runs = Container([
        {"id": "r-old", "runId": "r-old", "status": "succeeded", "trigger": "timer",
         "startedAt": _iso(48), "collectedAt": _iso(48), "written": 2},
        {"id": "r-good", "runId": "r-good", "status": "succeeded", "trigger": "timer",
         "startedAt": _iso(24), "collectedAt": _iso(24), "written": 2},
        {"id": "r-bad", "runId": "r-bad", "status": "failed", "trigger": "http",
         "startedAt": _iso(1), "collectedAt": _iso(1), "written": 1},
        {"id": "r-ancient", "runId": "r-ancient", "status": "succeeded", "trigger": "timer",
         "startedAt": _iso(24 * 30), "collectedAt": _iso(24 * 30), "written": 9},
    ])
    assessments = Container([
        {"id": "a", "runId": "r-good", "collectedAt": _iso(24), "status": "Unhealthy",
         "source": "defender", "severity": "High", "displayName": "D finding",
         "resourceId": "/x", "assessmentId": "assess-1"},
        {"id": "b", "runId": "r-good", "collectedAt": _iso(24), "status": "Unhealthy",
         "source": "azure-policy", "severity": "Medium", "displayName": "Classify it",
         "resourceId": "/seed", "assessmentId": "cge-require-data-classification"},
        # Newer document from the failed run: must NOT be reported.
        {"id": "c", "runId": "r-bad", "collectedAt": _iso(1), "status": "Unhealthy",
         "source": "defender", "severity": "Low", "displayName": "partial",
         "resourceId": "/y", "assessmentId": "assess-2"},
    ])
    return assessments, runs


class FakeBlobs:
    def __init__(self):
        self.uploaded = {}

    def upload_blob(self, name, data, overwrite=False):
        assert not overwrite and name not in self.uploaded
        self.uploaded[name] = data


def test_latest_run_skips_failed_sweeps(reports, fakes):
    assessments, runs = _store(fakes)
    run_id, _ = reports._latest_run(assessments, runs)
    assert run_id == "r-good"


def test_latest_run_falls_back_when_ledger_empty(reports, fakes):
    Container, _ = fakes
    assessments, _ = _store(fakes)
    run_id, _ = reports._latest_run(assessments, Container())
    assert run_id == "r-bad"  # starter behavior: newest document wins


def test_run_history_window(reports, fakes):
    _, runs = _store(fakes)
    h = reports._run_history(runs, days=7)
    assert h["total"] == 3
    assert h["byStatus"] == {"succeeded": 2, "failed": 1}
    assert h["byTrigger"] == {"timer": 2, "http": 1}


def test_sar_includes_both_sources_and_history(reports, fakes, monkeypatch):
    assessments, runs = _store(fakes)
    blobs = FakeBlobs()
    monkeypatch.setattr(reports, "_clients", lambda: (assessments, runs, blobs))
    result = reports.generate_sar()

    assert result == {"findings": 2, "runId": "r-good", "path": result["path"], "sweeps7d": 3}
    sar = blobs.uploaded[result["path"]]
    assert "**By source:** azure-policy: 1, defender: 1" in sar
    assert "**Sweeps recorded:** 3" in sar
    assert "Classify it" in sar and "partial" not in sar


def test_poam_rows_carry_source_and_control(reports, fakes, monkeypatch):
    import json
    assessments, runs = _store(fakes)
    blobs = FakeBlobs()
    monkeypatch.setattr(reports, "_clients", lambda: (assessments, runs, blobs))
    result = reports.generate_poam()

    assert result["items"] == 2 and result["runId"] == "r-good"
    items = json.loads(blobs.uploaded[result["json"]])["items"]
    policy = next(i for i in items if i["source"] == "azure-policy")
    assert policy["controlId"] == "cge-require-data-classification"
    assert policy["severity"] == "Medium"
    assert set(blobs.uploaded) == {result["xlsx"], result["json"]}
