# Control Mappings

Every policy, collector, and gate rule in this repo, mapped to the NIST CSF 2.0
category it serves. This file is what turns the repo from code into a control catalog —
and it's a first-class criterion on the capstone rubric.

## Stage 01 — Foundation

| Component | What it does | CSF 2.0 |
|---|---|---|
| Management group hierarchy + initiative assignment | Controls inherit to every current and future subscription — compliance by design | GV.PO, GV.OC |
| `cge-require-env-tag-rg` (Audit) | Inventory hygiene; owner accountability feeds the POA&M | ID.AM |
| `cge-deny-public-blob` (Deny) | Prevents public blob exposure at the API, before the resource exists | PR.DS |
| `cge-dine-storage-diagnostics` (DeployIfNotExists) | Logging that enforces its own coverage | PR.PS, DE.CM |
| Remediation identity (user-assigned, whitelist roles) | Every automated change has a named, auditable author | PR.AA, GV.RR |
| Log Analytics workspace + Activity Log routing | Central audit trail beyond the 90-day default | DE.CM, PR.PS |
| `cge-require-data-classification` (Audit) | **Custom.** Every storage and Cosmos account declares what it holds (`public`, `internal`, `confidential`, `restricted`); an unlabeled store shows up as a non-compliant policy state instead of hiding in the inventory | ID.AM |
| `cge-deny-public-network-restricted` (Deny) | **Custom.** A `restricted`-class (PHI-class) store cannot be created or updated with public network access enabled; binary rule on a self-declared label, so Deny is earned on day one | PR.DS, PR.IR |

## Classification of the pipeline's own stores

The pipeline holds itself to its own custom controls. The Cosmos evidence store, the WORM
reports account, and the Terraform state account are `confidential`; the two Functions
runtime scratch accounts are `internal`. Nothing in this sandbox is `restricted`: only
synthetic data ever lives here, and the `restricted` tier exists to prove the guardrail.

## Stage 03 — Evidence Store

| Component | What it does | CSF 2.0 |
|---|---|---|
| Cosmos DB (assessments / frameworks / mappings) | Owned evidence schema; collect once, crosswalk to every framework | GV.OV, ID.RA |
| WORM immutability policy on `reports` | Artifacts tamper-proof by platform guarantee | PR.DS |
| Shared keys disabled + data-plane RBAC | Identity or nothing; no credentials to steal or rotate | PR.AA |
| Collector Function (Security Reader + GRC Policy State Reader + Cosmos write only) | Continuous control-test capture with lineage from two sources, Defender assessments and Azure Policy compliance for this pipeline's own assignments, under one `runId` per sweep; cannot alter what it observes | DE.CM, ID.RA |
| GRC Policy State Reader (custom role) | The collector can query policy compliance and nothing else: no scans, exemptions, or assignment changes | PR.AA |
| `runs` ledger container | One record per sweep with start, completion, per-source counts, and outcome, including failures; the accumulating run history | DE.CM, GV.OV |
| `mappings` control rows (seeded by `seed_frameworks.py`) | The crosswalk as data: display name, severity (sets the POA&M SLA), and CSF 2.0 categories for every policy in this file | GV.OV, ID.RA |
| `evidence_blob_logs` diagnostic setting | Every read, write, and delete against evidence blobs is logged and attributed in the GRC workspace; the WORM failed-delete proof is a queryable event | DE.CM, PR.PS |
| Collector/reporter identity split | The recorder of facts cannot author the narrative — SoD by role scopes | PR.AA, GV.RR |

## Stage 04 — Reporting

| Component | What it does | CSF 2.0 |
|---|---|---|
| POA&M generator (daily, SLA-dated) | Weakness management with owners and dates for both sources, pinned to the latest succeeded run | ID.IM, GV.RM |
| SAR generator (weekly) | Assessment reporting where every number traces to a stored document, including a 7-day collection history read from the `runs` ledger | ID.RA, GV.OV |

## Stage 06 — Enforcement

| Component | What it does | CSF 2.0 |
|---|---|---|
| `cge-fix-public-blob` (Modify, mode ladder) | Auto-remediation through the dedicated identity; human-approved in dry-run | PR.DS, RS.MI |
| `remediation_mode` variable | Escalation is a reviewed diff — automation acts, humans authorize | GV.PO, GV.RR |

## Repo gates (policy/)

| Rule | Mistake it makes unmergeable | CSF 2.0 |
|---|---|---|
| `storage.rego` | Pipeline storage below the pipeline's own standard | PR.DS |
| `policy_identity.rego` | Remediation that silently never runs | PR.PS |
| `broad_roles.rego` | Owner/Contributor grants in governance code | PR.AA |
| `classification.rego` (+ 9 unit tests) | **Custom.** A data store with no classification, an unrecognized classification, or a `restricted` store with public network access | ID.AM, PR.DS |
| `tier0.yml`: fmt, validate, tflint, checkov | Unformatted, invalid, or misconfigured IaC; every checkov waiver is inline with a reason (register: [CHECKOV-WAIVERS.md](CHECKOV-WAIVERS.md)) | PR.PS, ID.RA |
| `tier0.yml`: gitleaks (full history) | A stored secret anywhere in the repo's history | PR.AA, PR.DS |
| `tier0.yml`: conftest verify | Gate rules that do not do what they claim | PR.PS |
| GRC Pipeline Planner role (`labs/06-loop/ci-planner-role.json`) | CI that could change the environment it is only meant to inspect; replaces Contributor on the CI identity | PR.AA, GV.RR |
| Pinned, checksum-verified conftest in `gate.yml` | A mutable third-party action executing inside a job that holds a cloud token | GV.SC, PR.PS |
| `drift.yml` + KQL tripwire | Out-of-band change going unnoticed | DE.CM, DE.AE |
