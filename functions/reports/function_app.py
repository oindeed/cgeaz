"""CGE-AZ pipeline — Stage 4 report generators.

Reports read from Cosmos ONLY — never from live services. Every number in every
artifact resolves to a stored, timestamped document. A report that reads live data
is a report whose numbers can't be reproduced tomorrow; a report that reads the
store is a fact with a receipt.

Generators here: POA&M (xlsx + json, daily) and SAR (markdown, weekly), both with
HTTP triggers for labs and demos.

Both pin to the latest SUCCEEDED run in the collector's `runs` ledger, so a report
never reads a sweep that is still writing or one that failed partway. Findings come
from every source the collector records (Defender assessments and Azure Policy
compliance), and each finding names its source.
"""

import datetime
import io
import json
import logging
import os
from collections import Counter

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from openpyxl import Workbook

app = func.FunctionApp()

# Severity-based SLAs: a POA&M is a plan, not a list.
SLA_DAYS = {"High": 30, "Medium": 90, "Low": 180}


def _clients():
    credential = DefaultAzureCredential()
    db = CosmosClient(os.environ["COSMOS_ENDPOINT"], credential).get_database_client(
        os.environ["COSMOS_DATABASE"]
    )
    blobs = BlobServiceClient(
        account_url=os.environ["REPORTS_ACCOUNT_URL"], credential=credential
    ).get_container_client(os.environ["REPORTS_CONTAINER"])
    return db.get_container_client("assessments"), db.get_container_client("runs"), blobs


def _latest_run(cosmos, runs):
    """Pin the report to a specific collection sweep — a statement about a known moment.

    The ledger's latest succeeded run wins. If the ledger is empty (a store written
    before the ledger existed), fall back to the newest assessment document.
    """
    rows = list(
        runs.query_items(
            "SELECT TOP 1 c.runId, c.collectedAt FROM c WHERE c.status = 'succeeded' "
            "ORDER BY c.collectedAt DESC",
            enable_cross_partition_query=True,
        )
    )
    if not rows:
        rows = list(
            cosmos.query_items(
                "SELECT TOP 1 c.runId, c.collectedAt FROM c ORDER BY c.collectedAt DESC",
                enable_cross_partition_query=True,
            )
        )
    return (rows[0]["runId"], rows[0]["collectedAt"]) if rows else (None, None)


def _run_history(runs, days: int = 7) -> dict:
    """Every sweep in the window, from the ledger: the receipt for continuous monitoring."""
    since = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    ).isoformat()
    rows = list(
        runs.query_items(
            "SELECT c.runId, c.status, c.trigger, c.startedAt, c.written FROM c "
            "WHERE c.startedAt >= @since ORDER BY c.startedAt ASC",
            parameters=[{"name": "@since", "value": since}],
            enable_cross_partition_query=True,
        )
    )
    return {
        "days": days,
        "total": len(rows),
        "byStatus": dict(Counter(r.get("status") for r in rows)),
        "byTrigger": dict(Counter(r.get("trigger") for r in rows)),
        "first": rows[0]["startedAt"] if rows else None,
        "last": rows[-1]["startedAt"] if rows else None,
    }


def _unhealthy(cosmos, run_id):
    return list(
        cosmos.query_items(
            "SELECT * FROM c WHERE c.runId = @run AND c.status = 'Unhealthy'",
            parameters=[{"name": "@run", "value": run_id}],
            enable_cross_partition_query=True,
        )
    )


def _dated_path(prefix: str, ext: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return f"{prefix}/{now:%Y/%m}/{prefix}-{now:%Y-%m-%d}.{ext}"


def generate_poam() -> dict:
    cosmos, runs, blobs = _clients()
    run_id, collected_at = _latest_run(cosmos, runs)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    today = datetime.date.today()

    wb = Workbook()
    ws = wb.active
    ws.title = "POA&M"
    ws.append(
        ["POA&M ID", "Weakness", "Affected Resource", "Severity",
         "Detected (run)", "Scheduled Completion", "Owner", "Status", "Source", "Control ID"]
    )
    rows = []
    for i, f in enumerate(sorted(findings, key=lambda x: x.get("severity") or ""), 1):
        severity = f.get("severity") or "Medium"
        due = today + datetime.timedelta(days=SLA_DAYS.get(severity, 90))
        row = {
            "poamId": f"POAM-{today:%Y%m%d}-{i:03d}",
            "weakness": f.get("displayName"),
            "resourceId": f.get("resourceId"),
            "severity": severity,
            "detectedRun": run_id,
            "scheduledCompletion": due.isoformat(),
            "owner": "resource-group owner tag",  # resolved during Domain 5's lab extension
            "status": "Open",
            "source": f.get("source") or "defender",
            "controlId": f.get("assessmentId"),
        }
        rows.append(row)
        ws.append(list(row.values()))

    xlsx = io.BytesIO()
    wb.save(xlsx)
    xlsx_path = _dated_path("poam", "xlsx")
    json_path = _dated_path("poam", "json")
    blobs.upload_blob(xlsx_path, xlsx.getvalue(), overwrite=False)
    blobs.upload_blob(
        json_path,
        json.dumps({"runId": run_id, "collectedAt": collected_at, "items": rows}, indent=2),
        overwrite=False,
    )
    logging.info("POA&M: %d items -> %s", len(rows), xlsx_path)
    return {"items": len(rows), "runId": run_id, "xlsx": xlsx_path, "json": json_path}


def generate_sar() -> dict:
    cosmos, runs, blobs = _clients()
    run_id, collected_at = _latest_run(cosmos, runs)
    findings = _unhealthy(cosmos, run_id) if run_id else []
    by_severity = Counter(f.get("severity") or "Unknown" for f in findings)
    by_source = Counter(f.get("source") or "defender" for f in findings)
    history = _run_history(runs)

    lines = [
        "# Security Assessment Report (SAR)",
        "",
        f"- **Collection run:** `{run_id}`",
        f"- **Collected at:** {collected_at}",
        f"- **Open findings:** {len(findings)}",
        f"- **By severity:** " + (", ".join(f"{k}: {v}" for k, v in sorted(by_severity.items())) or "none"),
        f"- **By source:** " + (", ".join(f"{k}: {v}" for k, v in sorted(by_source.items())) or "none"),
        "",
        f"## Collection history (last {history['days']} days)",
        "",
        f"- **Sweeps recorded:** {history['total']}",
        f"- **By outcome:** " + (", ".join(f"{k}: {v}" for k, v in sorted(history['byStatus'].items())) or "none"),
        f"- **By trigger:** " + (", ".join(f"{k}: {v}" for k, v in sorted(history['byTrigger'].items())) or "none"),
        f"- **First / last:** {history['first']} / {history['last']}",
        "- Trace: query the `runs` container for `startedAt >= ` the window start.",
        "",
        "## Findings",
        "",
    ]
    for f in sorted(findings, key=lambda x: x.get("severity") or ""):
        lines += [
            f"### {f.get('displayName')}",
            f"- Severity: {f.get('severity')}",
            f"- Source: {f.get('source') or 'defender'}",
            f"- Resource: `{f.get('resourceId')}`",
            f"- Assessment ID: `{f.get('assessmentId')}` (trace: query the assessments container)",
            "",
        ]

    path = _dated_path("sar", "md")
    blobs.upload_blob(path, "\n".join(lines), overwrite=False)
    logging.info("SAR: %d findings -> %s", len(findings), path)
    return {"findings": len(findings), "runId": run_id, "path": path, "sweeps7d": history["total"]}


@app.timer_trigger(schedule="0 0 6 * * *", arg_name="timer", run_on_startup=False)
def poam_daily(timer: func.TimerRequest) -> None:
    generate_poam()


@app.timer_trigger(schedule="0 0 7 * * 1", arg_name="timer", run_on_startup=False)
def sar_weekly(timer: func.TimerRequest) -> None:
    generate_sar()


@app.route(route="poam", auth_level=func.AuthLevel.FUNCTION)
def poam_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_poam()) + "\n", status_code=200)


@app.route(route="sar", auth_level=func.AuthLevel.FUNCTION)
def sar_now(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(generate_sar()) + "\n", status_code=200)
