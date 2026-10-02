#!/usr/bin/env python3
"""Seed the frameworks container with the NIST CSF 2.0 structure, and the mappings
container with the crosswalk for every Azure Policy control this pipeline deploys.

Run once after deploying stages/03-evidence-store:

    pip install azure-cosmos azure-identity
    COSMOS_ENDPOINT=$(cd ../../stages/03-evidence-store && terraform output -raw cosmos_endpoint) \
        python3 seed_frameworks.py

Authenticates as YOU (az login) — the deployer's Cosmos data role comes from the stage.

The mapping rows are the crosswalk as data: the collector reads them to give each Azure
Policy finding its display name, severity (which sets the POA&M SLA), and CSF 2.0
categories. They mirror docs/CONTROLS.md; change both in the same PR. Re-running this
script is safe: every write is an upsert on a fixed ID.
"""

import os
import sys

from azure.cosmos import CosmosClient
from azure.identity import DefaultAzureCredential

CSF2_FUNCTIONS = {
    "GV": ("Govern", ["GV.OC", "GV.RM", "GV.RR", "GV.PO", "GV.OV", "GV.SC"]),
    "ID": ("Identify", ["ID.AM", "ID.RA", "ID.IM"]),
    "PR": ("Protect", ["PR.AA", "PR.AT", "PR.DS", "PR.PS", "PR.IR"]),
    "DE": ("Detect", ["DE.CM", "DE.AE"]),
    "RS": ("Respond", ["RS.MA", "RS.AN", "RS.CO", "RS.MI"]),
    "RC": ("Recover", ["RC.RP", "RC.CO"]),
}


# Azure Policy controls deployed by stages/01-foundation and stages/06-enforcement.
# controlId is the policy definition name, as it appears in policy compliance states.
POLICY_CONTROLS = [
    ("cge-require-env-tag-rg", "Resource groups must carry an env tag", "Low", ["ID.AM"]),
    ("cge-deny-public-blob", "Storage accounts must not allow public blob access", "High", ["PR.DS"]),
    ("cge-dine-storage-diagnostics", "Storage accounts must route diagnostics to the GRC workspace", "Medium", ["PR.PS", "DE.CM"]),
    ("cge-require-data-classification", "Data stores must carry a valid data-classification tag", "Medium", ["ID.AM"]),
    ("cge-deny-public-network-restricted", "Restricted-class data stores must disable public network access", "High", ["PR.DS", "PR.IR"]),
    ("cge-fix-public-blob", "Remediate: disable public blob access on storage accounts", "High", ["PR.DS", "RS.MI"]),
]


def seed_mappings(db) -> int:
    container = db.get_container_client("mappings")
    for control_id, display_name, severity, categories in POLICY_CONTROLS:
        container.upsert_item(
            {
                "id": f"azure-policy.{control_id}",
                "frameworkId": "nist-csf-2.0",
                "type": "control-mapping",
                "controlSource": "azure-policy",
                "controlId": control_id,
                "displayName": display_name,
                "severity": severity,
                "categories": categories,
            }
        )
    return len(POLICY_CONTROLS)


def main() -> int:
    endpoint = os.environ.get("COSMOS_ENDPOINT")
    if not endpoint:
        print("Set COSMOS_ENDPOINT (see docstring).", file=sys.stderr)
        return 1

    db = CosmosClient(endpoint, DefaultAzureCredential()).get_database_client(
        os.environ.get("COSMOS_DATABASE", "grc")
    )
    container = db.get_container_client("frameworks")

    written = 0
    for func_id, (name, categories) in CSF2_FUNCTIONS.items():
        container.upsert_item(
            {
                "id": f"csf2-{func_id}",
                "frameworkId": "nist-csf-2.0",
                "type": "function",
                "functionId": func_id,
                "name": name,
                "categories": categories,
            }
        )
        written += 1

    container.upsert_item(
        {
            "id": "nist-csf-2.0",
            "frameworkId": "nist-csf-2.0",
            "type": "framework",
            "name": "NIST Cybersecurity Framework 2.0",
            "functions": list(CSF2_FUNCTIONS.keys()),
        }
    )
    mapped = seed_mappings(db)
    print(f"seeded {written + 1} framework documents and {mapped} control mappings into {endpoint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
