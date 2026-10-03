# Evidence

Receipts for every operational claim in the README, one section per rubric question.
Each entry names what happened, when (UTC), and where to reproduce it. Run IDs and
PR numbers are real; subscription IDs, account suffixes, and personal identifiers are
left out on purpose. Every Cosmos query below runs in the portal's Data Explorer against
database `grc`.

## 1. The gate blocks a non-compliant plan

| Item | Value |
|---|---|
| Test PR | [#8](https://github.com/oindeed/cgeaz/pull/8) `[GATE PROOF, do not merge] Non-compliant storage account`, closed unmerged 2026-10-03 12:44 UTC |
| The change | One storage account in stage 04 with public nested items, shared keys on, and no `data-classification` tag (`stages/04-reporting/gate-proof.tf` on branch `gate-proof/noncompliant-storage`) |
| Compliance gate run | `gate (04-reporting)` **failed at `OPA gate (conftest)`**; `gate (01-foundation)`, `gate (03-evidence-store)`, `gate (06-enforcement)` passed. The plan itself succeeded under the plan-only CI role; the rules stopped it |
| Tier 0 on the same PR | `checkov` failed; the other five Tier 0 jobs passed |
| Why the other stages passed | `fail-fast: false` (PR #9): every stage reports on its own, so one violation cannot hide or mask another |

Since 2026-10-03, `main` requires a pull request and every gate stage plus fmt +
validate, tflint, checkov, conftest verify, gitleaks, and the function tests (10 checks,
11 once stage 02 joined the gate in PR #13), enforced for administrators, so a PR like #8
cannot merge. PR #10 was the first PR to pass all of them, including all four
gate plans then in the matrix; the stage 02 gate first runs on the PR #13 merge.

The rules themselves are tested: 23 conftest unit tests run on every push. Writing the
tests for `policy_identity.rego` exposed that it could never fire (plan JSON renders an
absent block as an empty list, which Rego treats as present); fixed in PR #13.

## 2. Guardrails deny at the API

| When | Action | Result |
|---|---|---|
| Lab 3 | Create a storage account with public blob access in the sandbox | `RequestDisallowedByPolicy` (`cge-deny-public-blob`) |
| 2026-10-03 ~13:45 UTC | After Lab 6 restored `publicBlobEffect` to Deny (stage 01 apply: 0 added, 1 changed, 0 destroyed), `az storage account update --allow-blob-public-access true` on the seed account | `RequestDisallowedByPolicy` |

Reproduce: the first row of the README's verify table.

## 3. Collection is continuous, and the record includes failures

The `runs` container holds one record per sweep: trigger, start, completion, per-source
counts, outcome, and the error if it failed. The SAR prints the last 7 days of it.

| Item | Value |
|---|---|
| SAR `sar-2026-10-03.md` (generated before PR #7 added timestamps to report paths), collection history | 5 sweeps: 4 succeeded, 1 failed; 4 manual (`http`) during the labs, 1 nightly `timer` (05:00 UTC Oct 3) |
| The failed sweep | Defender assessments API returned HTTP 500 once; the identical call succeeded about a minute later. Recorded in the ledger with its error, then fixed by retry with backoff (PR #4) |
| Timer schedule | Collector daily 05:00 UTC; POA&M daily 06:00 UTC; SAR Mondays 07:00 UTC |

Reproduce:

```sql
-- container: runs
SELECT c.startedAt, c.trigger, c.status, c.sources, c.error FROM c ORDER BY c.startedAt DESC
```

From 2026-10-04 on, this returns one `timer` row per night with no manual runs; the
nightly cadence is the operations evidence. **Pending, Oct 7 and Oct 11:** the nightly
run IDs are recorded below.

| Night (05:00 UTC) | runId | Outcome | Documents |
|---|---|---|---|
| 2026-10-03 | (first nightly timer run) | succeeded | see SAR |

## 4. Every report number traces to a stored document

**Store to live (Lab 4 trace), 2026-10-03.** Run `b3a15e0b-f4b0-47ee-989c-6bcdb1afe494`
wrote 32 documents (Defender 2, Azure Policy 30). One Defender document from that run,
checked against the live Defender API:

| Field | Evidence store (Cosmos) | Live (`Microsoft.Security/assessments`) |
|---|---|---|
| displayName | There should be more than one owner assigned to subscriptions | There should be more than one owner assigned to subscriptions |
| status | Unhealthy | Unhealthy |

```sql
-- container: assessments
SELECT c.assessmentId, c.displayName, c.status, c.resourceId, c.collectedAt FROM c
WHERE c.runId = "b3a15e0b-f4b0-47ee-989c-6bcdb1afe494" AND c.source = "defender"
```

**Report to store.** Each POA&M and SAR names the `runId` it was generated from, and the
reporter's only data source is Cosmos: it holds no role that can read the platform. From
PR #12 on, every sweep also writes an append-only copy of each finding into `snapshots`,
partitioned by `runId`, and the reports read only that partition. Any count in a report
reproduces, on any later day, with:

```sql
-- container: snapshots (partition key = the runId)
SELECT VALUE COUNT(1) FROM c WHERE c.runId = "<runId in the report header>" AND c.status = "Unhealthy"
```

Runs collected before PR #12, including `b3a15e0b`, exist only in the latest-state
`assessments` container, where the next sweep re-stamps each finding with its own
`runId`. The trace above is recorded as observed on 2026-10-03. That gap is the reason
snapshots exist; the first sweep after PR #12 deploys is the first run that reproduces
indefinitely.

**First reproducible run, 2026-10-03 19:52 UTC** (after PR #12 deployed):

| Artifact | runId | Count |
|---|---|---|
| Collection | `6b565546-3422-40b9-a34e-4cf1f7911dc9` | 32 documents (Defender 2, Azure Policy 30) |
| `poam-2026-10-03T195304Z.json` | same | 2 items |
| `sar-2026-10-03T195307Z.md` | same | 2 findings; 8 sweeps in the 7-day history |
| `snapshots`, `COUNT(1) ... status = "Unhealthy"` for that runId | same | **2**, run 19:56 UTC |

Re-run of the same snapshot query after at least four nightly sweeps: recorded in section 3.

## 5. Past reports cannot be changed

| Item | Value |
|---|---|
| Lab 4 failed-delete proof | Upload to `reports` succeeded; delete failed with `BlobImmutableDueToPolicy` for the deployer, who holds Owner and Blob Data Contributor. Policy, not permissions |
| Designed around, not loosened | Report paths were dated per day and written with `overwrite=False` into the immutable container, so the Lab 6 same-day POA&M rerun would have been refused. Found in a pre-flight review; the fix timestamps every path to the second (PR #7), with a unit test that runs two same-day generations through a WORM-style fake. The 13:24 and 13:27 POA&Ms in section 6 are two same-day artifacts side by side |
| Audit trail | Every read, write, and delete on evidence blobs is logged to the GRC workspace (`evidence_blob_logs`), so a failed delete is a queryable event |

Reproduce the failed delete: [Lab 4](../labs/04-evidence/README.md), step 7. Query the
attempt:

```kusto
StorageBlobLogs
| where OperationName == "DeleteBlob" and Uri has "/reports/"
| project TimeGenerated, StatusCode, StatusText, CallerIpAddress, AuthenticationType
```

## 6. Remediation is automated, human-approved, and attributable (Lab 6)

On 2026-10-03, in order:

| UTC | Actor | Event |
|---|---|---|
| before 12:57 | Deployer (human), via Terraform | Public-blob effect de-escalated to Audit for the exercise (`-var`; in production this would be a reviewed PR) |
| 12:57 | Deployer (human), via CLI | Out-of-band change: public blob access enabled on the seed storage account. The change succeeded, which is the point of the exercise |
| 13:00 | `id-grc-remediation-dev` | Diagnostic settings write (the baseline's DeployIfNotExists policy, triggered by the updated account) |
| 13:00 to 13:10 | Deployer (human) | After the compliance scan marked the account NonCompliant, remediation task created against `cge-fix-public-blob`, which runs in dry-run mode. This is the human approval |
| 13:10 | `id-grc-remediation-dev` | Storage account write: public blob access set back to `false` |
| 13:24 and 13:27 | Reporter | POA&M regenerated as new WORM artifacts (see trail below) |
| ~13:43 | Deployer (human), via Terraform | Effect restored to Deny from code; the blocked update in section 2 followed |

The Activity Log caller on both automated writes is the remediation identity, not a
person. Filtering by that one identity returns the complete history of automated change.

**POA&M trail** (all in `reports/poam/2026/10/`, none overwritten):

| File | Run | Items |
|---|---|---|
| Morning POA&M | `d99a91de-075d-4596-86c7-16fb9f5ee0f3` | 3 |
| `poam-2026-10-03T132416Z` | `eaafd45d-…` | 2 |
| `poam-2026-10-03T132718Z` | `b3a15e0b-f4b0-47ee-989c-6bcdb1afe494` | 2: one `cge-require-data-classification` finding, one Defender finding |

Both remaining items are deliberate standing findings: the seed storage account carries
no `data-classification` tag (it proves the Audit control reports), and the single-owner
Defender finding is a documented risk acceptance ([CONTROLS.md](CONTROLS.md#risk-acceptances)).

## 7. Drift detection in both directions

| Detector | Question | Evidence |
|---|---|---|
| `drift.yml` (all five stages from PR #13) | Does reality match the code? | Found and fixed one real drift in stage 03 (an app setting that the zip deploy deletes; PR #5). On 2026-10-03 13:07 UTC it ran green during the Lab 6 out-of-band change, which it should have caught; root cause and fix in PR #10. **Proof after the fix:** with PRs #10 to #13 merged and nothing yet applied, the [18:04 UTC run](https://github.com/oindeed/cgeaz/actions/runs/37142810901) went red on exactly the four stages whose code was ahead of reality and opened issues [#14](https://github.com/oindeed/cgeaz/issues/14) (01: 3 to add), [#15](https://github.com/oindeed/cgeaz/issues/15) (02: 1 to add, 1 to destroy), [#16](https://github.com/oindeed/cgeaz/issues/16) (03: 6 to add, 1 to destroy) and [#17](https://github.com/oindeed/cgeaz/issues/17) (04: 1 to add, 1 to change, 1 to destroy); stage 06, unchanged, stayed green. Each issue's plan matched the apply that followed. After the applies, the [19:41 UTC run](https://github.com/oindeed/cgeaz/actions/runs/37148806618) was green on all five stages |
| `tripwire.tf` | Who is touching reality? | Hourly alert on administrative writes by any caller other than the remediation identity (PR #10). **Pending, next Cloud Shell session:** the stage 01 apply that deploys it is itself a human administrative write, so the first evaluation after it must fire and name the caller. Alert time and caller are recorded here when done |

## 8. The CI identity can plan but not change anything

The CI app holds `GRC Pipeline Planner` (`labs/06-loop/ci-planner-role.json`), a custom
role with read and refresh-list actions only, plus blob data access on the state resource
group. Validated live: every gate plan on PRs #8 and #10 and every drift plan since
2026-10-03 ran under it without a single 403. It holds no write action on any resource
and cannot assign roles.
