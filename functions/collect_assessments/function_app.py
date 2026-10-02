"""CGE-AZ pipeline — Stage 3 collector.

Timer fires nightly -> managed identity -> two evidence sources -> Cosmos.

  1. Defender for Cloud assessments (the starter's source).
  2. Azure Policy compliance states for this pipeline's own assignments
     (cge-grc-baseline, cge-fix-public-blob), so the custom controls'
     findings land in the same evidence store as Defender's.

Both sources share ONE runId per sweep, because the report generators pin to a
single run: a report is a statement about one known moment, not a blend of two.

One document per finding, upserted on a deterministic ID so re-runs refresh instead
of duplicate. Each sweep also writes one record to the `runs` ledger (started,
completed, per-source counts, outcome), because upserts keep only the latest state
of each finding and the ledger is what proves the collection ran, every night.

Deliberately boring: if you can read this file, you can defend this pipeline's
data lineage.
"""

import datetime
import hashlib
import logging
import os
import uuid

import azure.functions as func
import requests
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

app = func.FunctionApp()

ARM = "https://management.azure.com"
API_VERSION = "2021-06-01"  # Microsoft.Security/assessments
POLICY_API_VERSION = "2019-10-01"  # Microsoft.PolicyInsights/policyStates

# Azure Policy compliance -> the store's normalized status vocabulary, so the
# reports' `status = 'Unhealthy'` query covers both sources without special cases.
POLICY_STATUS = {
    "NonCompliant": "Unhealthy",
    "Compliant": "Healthy",
}

DEFAULT_SEVERITY = "Medium"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _doc_id(*parts: str) -> str:
    """Deterministic ID: the same finding on the same resource upserts, never duplicates."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


# --- Source 1: Defender for Cloud assessments --------------------------------------


def defender_doc(assessment: dict, subscription_id: str, run_id: str, collected_at: str) -> dict:
    props = assessment.get("properties", {})
    resource_id = (
        props.get("resourceDetails", {}).get("Id")
        or props.get("resourceDetails", {}).get("id", "")
    )
    return {
        # ID formula unchanged from the starter, so existing documents keep their identity.
        "id": _doc_id(assessment["name"], resource_id),
        "subscriptionId": subscription_id,
        "source": "defender",
        "assessmentId": assessment["name"],
        "displayName": props.get("displayName"),
        "status": props.get("status", {}).get("code"),
        "statusCause": props.get("status", {}).get("cause"),
        "severity": props.get("metadata", {}).get("severity"),
        "categories": props.get("metadata", {}).get("categories"),
        "resourceId": resource_id,
        "collectedAt": collected_at,
        "runId": run_id,
    }


def collect_defender(session, token, subscription_id, write, run_id, collected_at) -> int:
    url = (
        f"{ARM}/subscriptions/{subscription_id}"
        f"/providers/Microsoft.Security/assessments?api-version={API_VERSION}"
    )
    written = 0
    while url:
        resp = session.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=60)
        resp.raise_for_status()
        payload = resp.json()
        for assessment in payload.get("value", []):
            write(defender_doc(assessment, subscription_id, run_id, collected_at))
            written += 1
        url = payload.get("nextLink")
    return written


# --- Source 2: Azure Policy compliance states -------------------------------------


def policy_filter(assignments: list[str]) -> str:
    return " or ".join(f"policyAssignmentName eq '{a}'" for a in assignments)


def policy_doc(
    state: dict, mappings: dict, subscription_id: str, run_id: str, collected_at: str
) -> dict:
    """One policy compliance state -> one evidence document.

    Display name, severity, and CSF categories come from the `mappings` container
    (crosswalk as data). A policy with no mapping row still lands, with its definition
    name and the default severity, so an unmapped control is visible rather than lost.
    """
    definition = state.get("policyDefinitionName", "")
    assignment = state.get("policyAssignmentName", "")
    resource_id = state.get("resourceId", "")
    compliance = state.get("complianceState") or (
        "Compliant" if state.get("isCompliant") else "NonCompliant"
    )
    mapping = mappings.get(definition, {})
    return {
        "id": _doc_id("azure-policy", assignment, definition, resource_id.lower()),
        "subscriptionId": subscription_id,
        "source": "azure-policy",
        "assessmentId": definition,
        "displayName": mapping.get("displayName") or definition,
        "status": POLICY_STATUS.get(compliance, "NotApplicable"),
        "statusCause": compliance,
        "complianceState": compliance,
        "severity": mapping.get("severity") or DEFAULT_SEVERITY,
        "categories": mapping.get("categories"),
        "policyAssignmentName": assignment,
        "policySetDefinitionName": state.get("policySetDefinitionName"),
        "policyDefinitionAction": state.get("policyDefinitionAction"),
        "policyEvaluatedAt": state.get("timestamp"),
        "mappingId": mapping.get("id"),
        "resourceId": resource_id,
        "collectedAt": collected_at,
        "runId": run_id,
    }


def collect_policy(
    session, token, subscription_id, assignments, mappings, write, run_id, collected_at
) -> int:
    if not assignments:
        return 0
    # queryResults is a POST; its nextLink is POSTed as-is (it already carries the filter).
    url = (
        f"{ARM}/subscriptions/{subscription_id}"
        "/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
    )
    params = {"api-version": POLICY_API_VERSION, "$filter": policy_filter(assignments)}
    written = 0
    while url:
        resp = session.post(
            url, params=params, headers={"Authorization": f"Bearer {token}"}, timeout=60
        )
        resp.raise_for_status()
        payload = resp.json()
        for state in payload.get("value", []):
            write(policy_doc(state, mappings, subscription_id, run_id, collected_at))
            written += 1
        url = payload.get("@odata.nextLink")
        params = None
    return written


def load_policy_mappings(mappings_container) -> dict:
    """Policy definition name -> mapping row (seeded by labs/04-evidence/seed_frameworks.py)."""
    rows = mappings_container.query_items(
        "SELECT * FROM c WHERE c.type = 'control-mapping' AND c.controlSource = 'azure-policy'",
        enable_cross_partition_query=True,
    )
    return {r["controlId"]: r for r in rows}


# --- The sweep ---------------------------------------------------------------------


def run_collection(
    *, session, token, subscription_id, assignments, assessments, mappings_container, runs, trigger
) -> dict:
    run_id = str(uuid.uuid4())
    started_at = _now()
    # Every document in the sweep carries the same collectedAt: one run, one moment.
    collected_at = started_at
    record = {
        "id": run_id,
        "runId": run_id,
        "subscriptionId": subscription_id,
        "trigger": trigger,
        "startedAt": started_at,
        "collectedAt": collected_at,
        "policyAssignments": assignments,
        "status": "running",
        "sources": {},
    }
    runs.upsert_item(record)

    try:
        mappings = load_policy_mappings(mappings_container)
        record["sources"]["defender"] = collect_defender(
            session, token, subscription_id, assessments.upsert_item, run_id, collected_at
        )
        record["sources"]["azurePolicy"] = collect_policy(
            session, token, subscription_id, assignments, mappings,
            assessments.upsert_item, run_id, collected_at,
        )
        record["mappingsLoaded"] = len(mappings)
        record["status"] = "succeeded"
    except Exception as exc:  # recorded, then re-raised: a failed run is evidence too
        record["status"] = "failed"
        record["error"] = f"{type(exc).__name__}: {exc}"[:2000]
        raise
    finally:
        record["completedAt"] = _now()
        record["written"] = sum(record["sources"].values())
        runs.upsert_item(record)
        logging.info(
            "collection run %s %s: %s", run_id, record["status"], record["sources"]
        )

    return {
        "runId": run_id,
        "written": record["written"],
        "sources": record["sources"],
        "collectedAt": collected_at,
    }


def _collect(trigger: str) -> dict:
    subscription_id = os.environ["SUBSCRIPTION_ID"]
    assignments = [
        a.strip()
        for a in os.environ.get("POLICY_ASSIGNMENTS", "cge-grc-baseline,cge-fix-public-blob").split(",")
        if a.strip()
    ]

    # DefaultAzureCredential resolves to the Function App's managed identity in Azure
    # (and to your `az login` session when run locally). No keys, anywhere.
    credential = DefaultAzureCredential()
    token = credential.get_token(f"{ARM}/.default").token
    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential).get_database_client(
        os.environ["COSMOS_DATABASE"]
    )
    with requests.Session() as session:
        return run_collection(
            session=session,
            token=token,
            subscription_id=subscription_id,
            assignments=assignments,
            assessments=db.get_container_client("assessments"),
            mappings_container=db.get_container_client("mappings"),
            runs=db.get_container_client("runs"),
            trigger=trigger,
        )


@app.timer_trigger(schedule="0 0 5 * * *", arg_name="timer", run_on_startup=False)
def collect_nightly(timer: func.TimerRequest) -> None:
    """Nightly sweep at 05:00 UTC — midnight-ish US Eastern."""
    _collect("timer")


@app.route(route="collect", auth_level=func.AuthLevel.FUNCTION)
def collect_now(req: func.HttpRequest) -> func.HttpResponse:
    """Manual trigger for labs and demos: hit the endpoint, get the run summary."""
    result = _collect("http")
    sources = ", ".join(f"{k} {v}" for k, v in result["sources"].items())
    return func.HttpResponse(
        f"run {result['runId']}: {result['written']} documents ({sources}) at {result['collectedAt']}\n",
        status_code=200,
    )
