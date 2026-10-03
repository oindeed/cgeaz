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
    from conftest import FakeSnapshots
    Container, Session = fakes
    session = Session([DEFENDER_PAGE], [POLICY_PAGE_1, POLICY_PAGE_2], post_status)
    assessments, mapping_c, runs = Container(), Container(list(mappings)), Container()
    kwargs = dict(session=session, token="t", subscription_id=SUB,
                  assignments=["cge-grc-baseline", "cge-fix-public-blob"],
                  assessments=assessments, snapshots=FakeSnapshots(),
                  mappings_container=mapping_c, runs=runs, trigger="http")
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


def test_arm_session_retries_transient_failures(collector):
    adapter = collector.arm_session().get_adapter("https://management.azure.com")
    retry = adapter.max_retries
    assert retry.total == 5 and retry.backoff_factor == 2
    assert {429, 500, 502, 503, 504} <= set(retry.status_forcelist)
    assert {"GET", "POST"} <= set(retry.allowed_methods)
    assert retry.respect_retry_after_header and not retry.raise_on_status


def test_arm_session_recovers_from_one_500(collector):
    """End to end through urllib3: a 500 then a 200 yields the 200, on the real adapter."""
    import http.server, json, threading

    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            code, body = (500, b"{}") if len(hits) == 1 else (200, json.dumps({"value": []}).encode())
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        session = collector.arm_session()
        session.trust_env = False  # talk to the local server directly, never via a proxy
        session.mount("http://", session.get_adapter("https://x"))
        retry = session.get_adapter("http://x").max_retries
        session.get_adapter("http://x").max_retries = retry.new(backoff_factor=0)
        resp = session.get(f"http://127.0.0.1:{server.server_port}/assessments", timeout=10)
        assert resp.status_code == 200 and len(hits) == 2
    finally:
        server.shutdown()


def test_each_sweep_writes_an_immutable_snapshot_partition(collector, fakes):
    Container, Session = fakes
    _, _, _, kw = _run(collector, fakes)
    snaps = kw["snapshots"]
    first = collector.run_collection(**kw)
    before = {k: dict(v) for k, v in snaps.partition(first["runId"]).items()}
    kw["session"] = Session([DEFENDER_PAGE], [POLICY_PAGE_1, POLICY_PAGE_2])
    second = collector.run_collection(**kw)

    assert len(before) == 3 and len(snaps.partition(second["runId"])) == 3
    # The second sweep never touched the first sweep's partition.
    assert snaps.partition(first["runId"]) == before
    assert {d["runId"] for d in before.values()} == {first["runId"]}


def test_failed_sweep_leaves_the_last_good_partition_whole(collector, fakes):
    Container, Session = fakes
    _, _, runs, kw = _run(collector, fakes)
    good = collector.run_collection(**kw)
    kw["session"] = Session([DEFENDER_PAGE], [], post_status=500)
    with pytest.raises(RuntimeError):
        collector.run_collection(**kw)

    assert len(kw["snapshots"].partition(good["runId"])) == 3
    assert runs.items[good["runId"]]["status"] == "succeeded"


def test_first_seen_carries_forward_while_unhealthy_and_resets_when_cleared(collector, fakes):
    Container, Session = fakes
    _, assessments, _, kw = _run(collector, fakes)
    first = collector.run_collection(**kw)
    seed_id = next(d["id"] for d in assessments.items.values()
                   if d["source"] == "azure-policy" and d["status"] == "Unhealthy")
    kw["session"] = Session([DEFENDER_PAGE], [POLICY_PAGE_1, POLICY_PAGE_2])
    collector.run_collection(**kw)
    assert assessments.items[seed_id]["firstSeenAt"] == first["collectedAt"]

    healthy = {"value": [dict(POLICY_PAGE_1["value"][0], complianceState="Compliant")]}
    kw["session"] = Session([DEFENDER_PAGE], [healthy])
    collector.run_collection(**kw)
    assert assessments.items[seed_id]["firstSeenAt"] is None

    kw["session"] = Session([DEFENDER_PAGE], [POLICY_PAGE_1, POLICY_PAGE_2])
    recur = collector.run_collection(**kw)
    assert assessments.items[seed_id]["firstSeenAt"] == recur["collectedAt"]


def test_snapshot_write_is_create_only_and_redelivery_is_idempotent(collector, fakes):
    from conftest import FakeSnapshots
    Container, _ = fakes
    snaps = FakeSnapshots()
    write = collector.evidence_writer(Container(), snaps)
    doc = {"id": "x", "runId": "r1", "subscriptionId": SUB, "status": "Healthy",
           "collectedAt": "2026-10-04T05:00:00+00:00"}
    write(dict(doc))
    write(dict(doc))  # re-delivered inside the same sweep: 409, skipped
    assert len(snaps.items) == 1
