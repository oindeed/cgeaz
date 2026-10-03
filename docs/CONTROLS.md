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
| Log Analytics workspace + Activity Log routing (`azurerm_monitor_diagnostic_setting.activity_log`) | Central audit trail beyond the 90-day default; the tripwire's input, in code and drift-covered | DE.CM, PR.PS |
| Hourly out-of-band change alert (`tripwire.tf`) | Names every administrative write or delete by a caller other than the remediation identity and emails the owner; the second drift detector | DE.CM, DE.AE |
| `cge-require-data-classification` (Audit) | **Custom.** Every storage and Cosmos account declares what it holds (`public`, `internal`, `confidential`, `restricted`); an unlabeled store shows up as a non-compliant policy state instead of hiding in the inventory | ID.AM |
| `cge-deny-public-network-restricted` (Deny) | **Custom.** A `restricted`-class (PHI-class) store cannot be created or updated with public network access enabled; binary rule on a self-declared label, so Deny is earned on day one | PR.DS, PR.IR |

## Stage 02 — Activation

| Component | What it does | CSF 2.0 |
|---|---|---|
| Defender plan discovery (`azapi_resource.pricing`, read-only) | Measures the current tier of every baseline plan before anything is declared; the gap is an output | ID.AM, ID.RA |
| Defender plans at Standard (`azurerm_security_center_subscription_pricing`) | Continuous assessment of storage and key vaults; the source of the collector's Defender findings | DE.CM, ID.RA |
| NIST CSF 2.0 regulatory initiative (`nist_csf_20`), with identity | The standard assessed as code, posture visible in Defender's regulatory compliance view | GV.OV, ID.IM |

## Classification of the pipeline's own stores

The pipeline holds itself to its own custom controls. The Cosmos evidence store, the WORM
reports account, and the Terraform state account are `confidential`; the two Functions
runtime scratch accounts are `internal`. Nothing in this sandbox is `restricted`: only
synthetic data ever lives here, and the `restricted` tier exists to prove the guardrail.

## Stage 03 — Evidence Store

| Component | What it does | CSF 2.0 |
|---|---|---|
| Cosmos DB (assessments / frameworks / mappings) | Owned evidence schema; collect once, crosswalk to every framework | GV.OV, ID.RA |
| `snapshots` container (partition `/runId`) + `GRC Snapshot Writer` custom Cosmos role (create + read, no replace or upsert) | Every finding copied per sweep, append-only by RBAC: a past run's partition cannot be rewritten, so every report reproduces from its `runId` and a failed sweep cannot disturb the last good run | PR.DS, GV.OV |
| `firstSeenAt` on latest-state findings | Start of the current unhealthy streak; POA&M due dates run from detection, and a recurrence restarts the clock | ID.IM, GV.RM |
| Deployer data-plane grants (`deployer_blob_data`, `deployer_cosmos_write`) | The named human deployer can seed the crosswalk and prove WORM; granted to `deployer_object_id`, never inferred from whoever runs the plan | PR.AA |
| WORM immutability policy on `reports` | Artifacts tamper-proof by platform guarantee | PR.DS |
| Shared keys disabled + data-plane RBAC | Identity or nothing; no credentials to steal or rotate | PR.AA |
| Collector Function (Security Reader + GRC Policy State Reader; Cosmos access per container) | Continuous control-test capture with lineage from two sources, Defender assessments and Azure Policy compliance for this pipeline's own assignments, under one `runId` per sweep; cannot alter what it observes | DE.CM, ID.RA |
| GRC Policy State Reader (custom role) | The collector can query policy compliance and nothing else: no scans, exemptions, or assignment changes | PR.AA |
| `runs` ledger container | One record per sweep with start, completion, per-source counts, and outcome, including failures; the accumulating run history | DE.CM, GV.OV |
| `mappings` control rows (seeded by `seed_frameworks.py`) | The crosswalk as data: display name, severity (sets the POA&M SLA), and CSF 2.0 categories for every policy in this file | GV.OV, ID.RA |
| `evidence_blob_logs` diagnostic setting | Every read, write, and delete against evidence blobs is logged and attributed in the GRC workspace; the WORM failed-delete proof is a queryable event | DE.CM, PR.PS |
| Collector/reporter identity split | The recorder of facts cannot author the narrative — SoD by role scopes | PR.AA, GV.RR |

## Stage 04 — Reporting

| Component | What it does | CSF 2.0 |
|---|---|---|
| POA&M generator (daily, SLA-dated) | Weakness management for both sources from the pinned run's snapshot: first-seen date, due date (first seen + severity SLA), and an owner role (`poam_owner`) on every item | ID.IM, GV.RM |
| Reporter identity (Cosmos Data Reader + Blob Data Contributor on the `reports` container only) | Can narrate the evidence and write reports, nothing else: no platform read, no evidence write, no other container | PR.AA, GV.RR |
| SAR generator (weekly) | Assessment reporting where every number traces to a stored document, including a 7-day collection history read from the `runs` ledger | ID.RA, GV.OV |

## Stage 06 — Enforcement

| Component | What it does | CSF 2.0 |
|---|---|---|
| `cge-fix-public-blob` (Modify, mode ladder) | Auto-remediation through the dedicated identity; human-approved in dry-run | PR.DS, RS.MI |
| `remediation_mode` variable | Escalation is a reviewed diff — automation acts, humans authorize | GV.PO, GV.RR |

## Repo gates (policy/)

| Rule | Mistake it makes unmergeable | CSF 2.0 |
|---|---|---|
| `storage.rego` (+ 4 unit tests) | Pipeline storage below the pipeline's own standard | PR.DS |
| `policy_identity.rego` (+ 5 unit tests) | Remediation that silently never runs. Counts identity entries, because plan JSON renders an absent block as an empty list | PR.PS |
| `broad_roles.rego` (+ 5 unit tests) | Owner, Contributor, or User Access Administrator grants in governance code, by name or by role ID | PR.AA |
| `classification.rego` (+ 9 unit tests) | **Custom.** A data store with no classification, an unrecognized classification, or a `restricted` store with public network access | ID.AM, PR.DS |
| `tier0.yml`: fmt, validate, tflint, checkov | Unformatted, invalid, or misconfigured IaC; every checkov waiver is inline with a reason (register: [CHECKOV-WAIVERS.md](CHECKOV-WAIVERS.md)) | PR.PS, ID.RA |
| `tier0.yml`: gitleaks (full history) | A stored secret anywhere in the repo's history | PR.AA, PR.DS |
| `tier0.yml`: conftest verify | Gate rules that do not do what they claim (23 unit tests across all four rules) | PR.PS |
| `tier0.yml`: functions (compile + 23 pytest tests with fakes) | Collector or reporter changes that break run lineage, snapshot immutability, the ledger, or report pinning | DE.CM, PR.DS |
| Every workflow action pinned to a commit SHA; tier0 binaries checksum-verified | A moved tag or swapped binary executing inside CI | GV.SC, PR.PS |
| GRC Pipeline Planner role (`labs/06-loop/ci-planner-role.json`) | CI that could change the environment it is only meant to inspect; replaces Contributor on the CI identity | PR.AA, GV.RR |
| Pinned, checksum-verified conftest in `gate.yml` | A mutable third-party action executing inside a job that holds a cloud token | GV.SC, PR.PS |
| `gate.yml` matrix: all five stages | A stage escaping plan review | PR.PS, GV.PO |
| `drift.yml` (nightly plan on all five stages; fails the run and opens an issue on drift or detector error) | Reality diverging from code goes unnoticed | DE.CM, DE.AE |

## Risk acceptances

A finding I choose not to fix stays on the POA&M, with the reason written down here.
It is not suppressed or exempted. A POA&M that shows an accepted risk and its rationale
is stronger evidence than one that has been cleaned up for the assessor.

| Finding | Source | Decision | Rationale | Compensating controls | Review |
|---|---|---|---|---|---|
| There should be more than one owner assigned to subscriptions | Defender for Cloud (traced store-to-live in [EVIDENCE.md](EVIDENCE.md#4-every-report-number-traces-to-a-stored-document)) | Accept | Single-operator sandbox. A second Owner would be a second standing privileged identity created only to clear the finding, which raises risk instead of lowering it. In a production subscription this is a fix, through a break-glass account held under dual control | Activity Log routed to the GRC workspace; the hourly tripwire names every administrative write by a non-automation caller; all change goes through PRs gated by 11 required checks, enforced for administrators | 2026-11-01, or earlier if a second operator joins |
| Storage and Cosmos accounts must carry a valid data-classification tag, on the Lab 2 seed account | `cge-require-data-classification` (Audit) | Keep open on purpose | The seed account is the standing test that the Audit control reports what it should. Tagging it would remove the only live proof that the control detects | None needed: synthetic data only, no public access | Teardown |

Evidence for every control in this file: [EVIDENCE.md](EVIDENCE.md).
