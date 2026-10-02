"""Collector: one sweep, two sources, one runId, and a ledger record either way."""

import pytest

SUB = "00000000-0000-0000-0000-000000000000"
SEED = f"/subscriptions/{SUB}/resourcegroups/rg-grc-sandbox-dev/providers/microsoft.storage/storageaccounts/stgrcseed1"
STATE = f"/subscriptions/{SUB}/resourcegroups/rg-grc-tfstate/providers/microsoft.storage/storageaccounts/stgrctfstate1"

DEFENDER_PAGE = {
    "value": [{
        "name": "assess-1",
        "properties": {
            "displayName": "Storage accounts should restrict network access",
            "status": {"code": "Unhealthy", "cause": "x"},
            "metadata": {"severity": "Medium", "categories": ["Data"]},
            "resourceDetails": {"Id": SEED},
        },
    }],
}

POLICY_PAGE_1 = {
    "value": [{
        "resourceId": SEED,
        "policyAssignmentName": "cge-grc-baseline",
        "policyDefinitionName": "cge-require-data-classification",
        "policySetDefinitionName": "cge-grc-baseline",
        "policyDefinitionAction": "audit",
        "complianceState": "NonCompliant",
        "timestamp": "2026-10-02T12:59:24Z",
    }],
    "@odata.nextLink": "https://management.azure.com/next?$skiptoken=abc",
}
POLICY_PAGE_2 = {
    "value": [{
        "resourceId": STATE,
        "policyAssignmentName": "cge-grc-baseline",
        "policyDefinitionName": "cge-require-data-classification",
        "complianceState": "Compliant",
        "timestamp": "2026-10-02T12:59:24Z",
    }],
}

MAPPING = {
    "id": "azure-policy.cge-require-data-classification",
    "frameworkId": "nist-csf-2.0",
    "type": "control-mapping",
    "controlSource": "azure-policy",
    "controlId": "cge-require-data-classification",
    "displayName": "Data stores must carry a valid data-classification tag",
    "severity": "Medium",
    "categories": ["ID.AM"],
}


def _run(collector, fakes, post_status=200, mappings=(MAPPING,)):
    Container, Session = fakes
    session = Session([DEFENDER_PAGE], [POLICY_PAGE_1, POLICY_PAGE_2], post_status)
    assessments, mapping_c, runs = Container(), Container(list(mappings)), Container()
    kwargs = dict(session=session, token="t", subscription_id=SUB,
                  assignments=["cge-grc-baseline", "cge-fix-public-blob"],
                  assessments=assessments, mappings_container=mapping_c,
                  runs=runs, trigger="http")
    return session, assessments, runs, kwargs


def test_one_sweep_collects_both_sources_under_one_run(collector, fakes):
    session, assessments, runs, kw = _run(collector, fakes)
    result = collector.run_collection(**kw)

    docs = list(assessments.items.values())
    assert result["sources"] == {"defender": 1, "azurePolicy": 2}
    assert {d["runId"] for d in docs} == {result["runId"]}
    assert {d["collectedAt"] for d in docs} == {result["collectedAt"]}
    assert {d["source"] for d in docs} == {"defender", "azure-policy"}


def test_policy_states_normalize_and_enrich_from_mappings(collector, fakes):
    _, assessments, _, kw = _run(collector, fakes)
    collector.run_collection(**kw)

    by_resource = {d["resourceId"]: d for d in assessments.items.values()
                   if d["source"] == "azure-policy"}
    seed, state = by_resource[SEED], by_resource[STATE]
    assert seed["status"] == "Unhealthy" and seed["complianceState"] == "NonCompliant"
    assert state["status"] == "Healthy"
    assert seed["displayName"] == MAPPING["displayName"]
    assert seed["severity"] == "Medium" and seed["categories"] == ["ID.AM"]
    assert seed["mappingId"] == MAPPING["id"]
    assert seed["assessmentId"] == "cge-require-data-classification"


def test_unmapped_policy_still_lands_with_defaults(collector, fakes):
    _, assessments, _, kw = _run(collector, fakes, mappings=())
    collector.run_collection(**kw)
    seed = next(d for d in assessments.items.values()
                if d["source"] == "azure-policy" and d["resourceId"] == SEED)
    assert seed["displayName"] == "cge-require-data-classification"
    assert seed["severity"] == collector.DEFAULT_SEVERITY
    assert seed["mappingId"] is None


def test_policy_query_is_filtered_and_paged_by_post(collector, fakes):
    session, _, _, kw = _run(collector, fakes)
    collector.run_collection(**kw)

    posts = [c for c in session.calls if c[0] == "POST"]
    assert len(posts) == 2
    first_url, first_params = posts[0][1], posts[0][2]
    assert first_url.endswith("/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults")
    assert first_params["$filter"] == (
        "policyAssignmentName eq 'cge-grc-baseline' or "
        "policyAssignmentName eq 'cge-fix-public-blob'"
    )
    # nextLink already carries the query; parameters are not re-sent.
    assert posts[1][1] == POLICY_PAGE_1["@odata.nextLink"] and posts[1][2] is None


def test_rerun_upserts_instead_of_duplicating(collector, fakes):
    Container, Session = fakes
    _, assessments, runs, kw = _run(collector, fakes)
    collector.run_collection(**kw)
    kw["session"] = Session([DEFENDER_PAGE], [POLICY_PAGE_1, POLICY_PAGE_2])
    second = collector.run_collection(**kw)

    assert len(assessments.items) == 3  # same findings, refreshed in place
    assert {d["runId"] for d in assessments.items.values()} == {second["runId"]}
    assert len(runs.items) == 2  # but the ledger keeps both sweeps


def test_ledger_records_success(collector, fakes):
    _, _, runs, kw = _run(collector, fakes)
    result = collector.run_collection(**kw)
    record = runs.items[result["runId"]]
    assert record["status"] == "succeeded"
    assert record["sources"] == {"defender": 1, "azurePolicy": 2}
    assert record["written"] == 3 and record["trigger"] == "http"
    assert record["completedAt"] >= record["startedAt"]


def test_ledger_records_failure_and_reraises(collector, fakes):
    _, _, runs, kw = _run(collector, fakes, post_status=403)
    with pytest.raises(RuntimeError, match="403"):
        collector.run_collection(**kw)
    (record,) = runs.items.values()
    assert record["status"] == "failed"
    assert "403" in record["error"]
    assert record["sources"] == {"defender": 1}


def test_defender_doc_id_unchanged_from_starter(collector):
    import hashlib
    doc = collector.defender_doc(DEFENDER_PAGE["value"][0], SUB, "r", "t")
    assert doc["id"] == hashlib.sha256(f"assess-1|{SEED}".encode()).hexdigest()[:32]
