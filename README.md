# GRC Evidence Pipeline on Azure

An automated governance, risk, and compliance pipeline for one Azure subscription,
deployed entirely as Terraform from this repo. It governs the subscription with Azure
Policy, collects control evidence every night from two sources into a store that keeps an
append-only snapshot of every run, generates the POA&M and the SAR from those snapshots
alone, writes them where nothing can alter them, fixes one class of
misconfiguration through one named identity, only after a human approves, and blocks any change to
its own code that would break its own rules.

This is my CGE-AZ capstone (GRC Engineering Club). It started from the course starter
repo; what I changed and why is in [What I built beyond the starter](#what-i-built-beyond-the-starter).
Every claim below has a receipt in [docs/EVIDENCE.md](docs/EVIDENCE.md).

```
01 Foundation ──► 02 Activation ──► 03 Evidence store ──► 04 Reporting      06 Enforcement
mgmt groups       discover first,   Cosmos + WORM Blob     POA&M daily       Modify policy,
5-policy          then enable only  collector, nightly     SAR weekly        dry-run, human
initiative        the measured gap  Defender + Policy      from the store    approves each
tripwire alert                      one runId per sweep    only              fix
       ▲                                                                          │
       └──────────── the fix shows up in the next collection, with a new runId ◄──┘
```

Stage flow, identity boundaries, and the reasoning behind each non-obvious choice:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Every policy, collector, and gate rule
mapped to NIST CSF 2.0: [docs/CONTROLS.md](docs/CONTROLS.md).

## What it proves

| Question an assessor asks | Where the answer lives |
|---|---|
| Are the controls inherited by everything, including subscriptions added later? | One initiative assigned at `mg-grc-sandbox` (stage 01) |
| Does every data store declare what it holds, and is a restricted store kept off the internet? | Two custom policies of my own, `cge-require-data-classification` (Audit) and `cge-deny-public-network-restricted` (Deny) |
| Did collection actually run every night, including the nights it failed? | The `runs` ledger in Cosmos, one record per sweep; the SAR prints the last 7 days of it |
| Can any number in a report be reproduced, next week as well as today? | Reports read only the pinned run's partition of the append-only `snapshots` container; every figure is a stored query against that `runId` |
| Can anyone alter or delete a past report? | No. The `reports` container is WORM-locked; same-day reruns write new timestamped files beside the old ones |
| Who changed what, and was it automation or a person? | Remediation writes carry one named identity; the hourly tripwire names every other caller |
| Can a bad change reach the environment? | Not through `main`: a PR plus 11 required checks, including a plan-and-conftest gate on all five stages, enforced for admins too |
| When does the remediation clock start? | When the finding was first seen unhealthy (`firstSeenAt`), not when the report runs |

## What I built beyond the starter

| Change | Why | PR |
|---|---|---|
| Data classification controls: 2 custom Azure Policies, a matching conftest rule with 9 unit tests, and classification tags on the pipeline's own stores | In healthcare the first assessor question about a data store is what it holds and who can reach it | #1 |
| Tier 0 CI: fmt, validate, tflint, checkov with an inline waiver register, conftest verify, gitleaks over full history, function unit tests | IaC quality floor plus the two auto-fail risks, checked on every push | #1 |
| CI identity reduced from Contributor to a custom plan-only role (`GRC Pipeline Planner`) | CI only plans, so it should not be able to apply | #1, #9 |
| Collector reads Azure Policy compliance alongside Defender, under one `runId`, enriched from the crosswalk | Findings from my own controls must reach the evidence store and the POA&M, not stay in the portal | #3 |
| `runs` ledger container; reports pin to the latest succeeded run | Upserts keep only the latest state of each finding; the ledger is what proves the timers ran | #3 |
| Collector retries transient ARM failures (429, 5xx) with backoff | A one-off Defender 500 failed a real sweep on Oct 3; the identical call worked a minute later | #4 |
| Terraform never opens the storage data plane | Deployable from Azure Cloud Shell, whose identity cannot get storage data-plane tokens | #6 |
| Report paths timestamped to the second | Per-day paths plus the WORM lock would have refused any same-day rerun; every generation is now its own immutable artifact | #7 |
| ID-pinned OIDC subjects, gate stages report independently | GitHub issues the ID-pinned subject form; one failing stage must not hide another stage's violation | #9 |
| Both drift detectors made real: the nightly plan can now fail, and an hourly out-of-band change alert (`tripwire.tf`) is in code | The nightly drift run stayed green through a deliberate out-of-band change; detector 2 existed only as a manual query | #10 |
| Append-only `snapshots` per run; POA&M clocks start at `firstSeenAt`; owner role on every item; reporter's blob write scoped to one container | Each sweep overwrote the previous run's `runId`, so older reports could not be reproduced and a failed sweep could drop findings from the next one | #12 |
| Gate rules that can fire (identity rule fixed, role rule matches IDs, 14 new unit tests); stage 02 under the gate and drift; Activity Log routing in Terraform; every action SHA-pinned, binaries checksum-verified | An independent pre-submission review found the identity rule could never fire and stage 02 escaped review | #13 |

## Deploy from an empty subscription

Everything below runs in **Azure Cloud Shell (Bash)**, with nothing installed locally.
Cloud Shell already has the Azure CLI, Terraform, Python 3, and `zip`. A local shell with
`az login` works the same way. Allow about 90 minutes of hands-on time, plus up to 24
hours for Defender's first assessment cycle on a new subscription.

**Prerequisites:** Owner on the subscription, rights to create management groups and app
registrations in the tenant, and a GitHub fork of this repo.

### 0. Sign in, register providers, set variables

```bash
az account set --subscription <subscription-id>
for p in Management Security OperationalInsights DocumentDB Web Storage Insights PolicyInsights; do
  az provider register --namespace Microsoft.$p
done
git clone https://github.com/<you>/cgeaz.git && cd cgeaz

export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export TF_VAR_owner_email=<owner-email>        # tag value and tripwire alert address; never committed
export TF_VAR_functions_location=centralus     # a region with Linux Consumption quota (labs/00-setup/probe-quota.sh)
```

Provider registration takes 2 to 3 minutes. Region quirks and cost guardrails:
[docs/SETUP.md](docs/SETUP.md).

### 1. Remote state

```bash
cd labs/03-foundation && ./bootstrap.sh && cd ../..
export TF_VAR_state_storage_account=$(az storage account list -g rg-grc-tfstate --query "[0].name" -o tsv)
```

Creates a versioned state account with no public access, grants the deployer blob data
rights, and writes `backend.hcl` for every stage. If the first `terraform init` returns
403, the role grant is still propagating: wait 2 to 3 minutes and retry.

### 2. Stage 01: foundation

```bash
cd stages/01-foundation
terraform init -backend-config=../../labs/03-foundation/backend.hcl
terraform plan          # read it: hierarchy, 5 policies, initiative, remediation identity,
terraform apply         # Activity Log routing, tripwire alert
cd ../..
```

On an empty subscription this creates `mg-grc` and `mg-grc-sandbox`, moves the
subscription under them, assigns the `cge-grc-baseline` initiative, and routes the
Activity Log to the GRC workspace. If the hierarchy
was built by hand first (Labs 1 and 2), import it instead of recreating it:
[labs/03-foundation](labs/03-foundation/README.md), step 2.

### 3. Stage 02: discovery, then activation

```bash
cd stages/02-activation
terraform init -backend-config=../../labs/03-foundation/backend.hcl
terraform plan          # discovery reads current Defender tiers; activation closes only the gap
terraform apply
cd ../..
```

### 4. Stage 03: evidence store and collector

```bash
cd stages/03-evidence-store
terraform init -backend-config=../../labs/03-foundation/backend.hcl
terraform apply         # Cosmos takes several minutes
APP=$(terraform output -raw collector_function_app)
cd ../../functions/collect_assessments && zip -qr /tmp/collector.zip . && cd ../..
az functionapp deployment source config-zip --name $APP -g rg-grc-evidence-dev \
  --src /tmp/collector.zip --build-remote true --timeout 600
```

Seed the framework crosswalk (writes the NIST CSF 2.0 catalog as 7 documents, plus 6
control mappings). This step
writes to the Cosmos data plane, which Cloud Shell's managed identity cannot reach, so
run it from any shell signed in with `az login` as the deployer:

```bash
pip install azure-cosmos azure-identity
COSMOS_ENDPOINT=$(cd stages/03-evidence-store && terraform output -raw cosmos_endpoint) \
  python3 labs/04-evidence/seed_frameworks.py
```

### 5. Stage 04: reporting

```bash
cd stages/04-reporting
terraform init -backend-config=../../labs/03-foundation/backend.hcl
terraform apply
RAPP=$(terraform output -raw reporting_function_app)
cd ../../functions/reports && zip -qr /tmp/reports.zip . && cd ../..
az functionapp deployment source config-zip --name $RAPP -g rg-grc-evidence-dev \
  --src /tmp/reports.zip --build-remote true --timeout 600
```

### 6. Stage 06: enforcement in dry-run

```bash
cd stages/06-enforcement
terraform init -backend-config=../../labs/03-foundation/backend.hcl
terraform apply         # remediation_mode = "dry-run": findings appear, fixes wait for human approval
cd ../..
```

### 7. Arm CI on the fork

```bash
cd labs/06-loop && ./arm-your-fork.sh <github-user> && cd ../..
```

Run it once; each run creates a new app registration. Add the six repository variables
it prints (Settings, Secrets and variables, Actions, Variables). They are variables, not
secrets: OIDC stores no credential. Enable Issues on the fork (forks ship with Issues
off, and drift detection opens one per drifted stage). Then protect `main`: require a pull request, include administrators, and require
these 11 checks: `gate (01-foundation)`, `gate (02-activation)`, `gate (03-evidence-store)`,
`gate (04-reporting)`, `gate (06-enforcement)`, `terraform fmt + validate`,
`tflint (azurerm ruleset)`, `checkov`, `gate rules (conftest verify)`,
`secret scan (gitleaks)`, `functions (compile + unit tests)`. In a single-maintainer repo,
set required approvals to 0: GitHub does not let an author approve their own PR, so the
required checks are the reviewer.

### 8. Verify end to end

| Check | Command or place | Pass |
|---|---|---|
| Guardrail denies | `az storage account create -n stgrcdeny$RANDOM -g rg-grc-sandbox-dev --allow-blob-public-access true` | `RequestDisallowedByPolicy` |
| Collection runs | `curl "https://$APP.azurewebsites.net/api/collect?code=<function key>"` | `run <uuid>: N documents (defender D, azurePolicy P)` |
| Reports generate | `/api/poam` and `/api/sar` on `$RAPP` | JSON naming the `runId` and a dated path in `reports` |
| WORM holds | Upload then delete a blob in `reports` ([Lab 4](labs/04-evidence/README.md), step 7) | Delete fails with `BlobImmutableDueToPolicy` |
| Gate blocks | Open a PR adding a public storage account; close it unmerged | `gate (<stage>)` fails at conftest |
| Timers accumulate | Cosmos Data Explorer, `runs`: `SELECT c.startedAt, c.trigger, c.status FROM c ORDER BY c.startedAt DESC` | One `timer` row per night at 05:00 UTC |
| Reports reproduce | `snapshots`: `SELECT VALUE COUNT(1) FROM c WHERE c.runId = "<runId in a POA&M>" AND c.status = "Unhealthy"` | Equals that POA&M's item count, whenever it is run |

Full checklist of the mechanical rubric items: `./self-check.sh`.

## Operating it

| What | When | Identity |
|---|---|---|
| Collector sweep (Defender + Policy, one `runId`) | Daily 05:00 UTC | Collector managed identity, read-only on the platform |
| POA&M (xlsx + json, SLA-dated) | Daily 06:00 UTC | Reporter managed identity, read-only on evidence |
| SAR (markdown, with 7-day collection history) | Mondays 07:00 UTC | Reporter managed identity |
| Drift plan on all five stages; a red run plus an issue on drift | Daily 08:00 UTC | CI OIDC identity, plan-only role |
| Out-of-band change alert | Hourly | Azure Monitor, emails the owner |
| Compliance gate (plan + conftest on all five stages) | Every PR to `main` | CI OIDC identity |
| Remediation of public blob access | Only when a human creates the remediation task | `id-grc-remediation-dev` |

Escalation from `dry-run` to `enforce` is a one-line change to `remediation_mode`,
merged through a PR like everything else. Changes go through the repo, never the portal;
the tripwire reports anything that does not.

## Repository layout

```
stages/     one Terraform root module per stage, each with its own state and output contract
functions/  collector and report generators (Python, timer-triggered, managed identity)
policy/     conftest rules that gate this repo's own Terraform, with unit tests
tests/      function unit tests with fakes for ARM and Cosmos (no credentials, no network)
labs/       the course lab guides and helper scripts (bootstrap, CI arming)
docs/       architecture, control mappings, evidence, checkov waivers, setup
.github/    tier 0, compliance gate, drift detection
```

## Cost and teardown

Built and run on an Azure free account. The running cost is Cosmos serverless (the
snapshots grow by a few dozen small documents per night), two
Linux Consumption function apps, a few storage accounts, one Log Analytics workspace,
and one hourly alert rule. Teardown is the reverse stage order (06, 04, 03, 02, 01),
`terraform destroy` in each. The WORM policy on `reports` (90-day retention) is left
unlocked in this sandbox so teardown is possible: blobs still cannot be modified or
deleted while it stands, but an Owner can remove the policy itself. In production it is
locked, after which no one can shorten or remove it.

All data in this environment is synthetic. Nothing here has ever held real patient data.
