# Checkov Waiver Register

`tier0.yml` runs checkov on every push, and a finding without a waiver fails the build.
Every waiver lives inline on the resource it applies to (`#checkov:skip=ID:reason`), so
the reason sits in the same diff as the code it excuses. This file is the register: the
same waivers grouped by root cause, each with its compensating control and the
production path that would retire it.

**Measured at PR #9: 57 passed, 0 failed, 27 waived across all five stage directories (01, 02, 03, 04, 06).** Later PRs add resources; the gate is the same either way: 0 failed, or the build is red.

## How the starter's 36 findings were resolved

The starter produced 36 findings, and checkov was silently skipping three files. That
included the foundation and enforcement stages, where every policy and role assignment
lives. The cause was the `if = {}` key inside `jsonencode()` policy rules: Terraform
accepts it, but checkov's HCL parser does not. Quoting the key (`"if" = {}`) brought
every stage under scan, taking coverage from 32 resources to 42.

| Outcome | Findings | What changed |
|---|---|---|
| Fixed | 9 | Cosmos metadata writes locked to ARM (CKV_AZURE_132); HTTPS only on both Function Apps (CKV_AZURE_70 ×2); evidence storage moved to GRS (CKV_AZURE_206); blob and container soft delete on all three accounts (CKV2_AZURE_38 ×3); SAS expiration policy on both runtime accounts (CKV2_AZURE_41 ×2) |
| Waived with reason | 27 | Grouped below |
| Added beyond checkov | 1 | Blob read, write, and delete logs on the evidence account, routed to the GRC workspace (`evidence_blob_logs`), so the WORM failed-delete proof is a logged, attributed event |

## Waivers by root cause

### A. Consumption plan networking (10)

| Check | Resources | Compensating control |
|---|---|---|
| CKV_AZURE_59, CKV2_AZURE_33 | evidence storage, both runtime accounts | Shared keys off on evidence storage; Entra ID data-plane RBAC only; no anonymous access; TLS 1.2 minimum |
| CKV_AZURE_101, CKV_AZURE_99 | Cosmos evidence account | Local auth off; key-based metadata writes off; Entra ID data-plane RBAC only |
| CKV_AZURE_221 | both Function Apps | HTTPS only; timer triggers plus function-key HTTP triggers for manual runs (AuthLevel.FUNCTION); system-assigned identity |

**Root cause.** Y1 Consumption Functions have no VNet integration, so private
endpoints and IP filters would cut the collectors off from the stores they write to.
The design makes identity the boundary instead of the network.

**Coherence with the custom controls.** The pipeline's stores are classified
`confidential`. `cge-deny-public-network-restricted` requires private networking only at
`restricted`, so these waivers are consistent with the pipeline's own policy rather than
an exception to it.

**Production path.** Move to Flex Consumption or Premium plans with VNet integration,
add private endpoints for Cosmos and Blob, then disable public network access. That
also becomes mandatory the moment any store is reclassified to `restricted`.

### B. Platform-managed encryption keys (4)

| Check | Resources | Compensating control |
|---|---|---|
| CKV_AZURE_100 | Cosmos evidence account | Microsoft-managed encryption at rest (always on) |
| CKV2_AZURE_1 | evidence storage, both runtime accounts | Microsoft-managed encryption at rest (always on) |

**Root cause.** Customer-managed keys add a Key Vault, a rotation process, and a new
failure mode (a revoked key makes evidence unreadable). The sandbox holds synthetic
data at `confidential`, which does not justify that overhead.

**Production path.** CMK in a dedicated Key Vault for any `restricted` store, with the
key vault itself under the classification policy.

### C. Consumption plan availability (4)

| Check | Resources | Compensating control |
|---|---|---|
| CKV_AZURE_225, CKV_AZURE_212 | both service plans | Missed timer runs show up as gaps in run history. Evidence is never lost, only delayed until the next run |

**Root cause.** Y1 scales from zero and supports neither zone redundancy nor minimum
instance counts.

### D. Runtime storage shared key (2)

| Check | Resources | Compensating control |
|---|---|---|
| CKV2_AZURE_40 | both runtime accounts | Stated explicitly as `shared_access_key_enabled = true`; allowed by name in `policy/storage.rego`; holds runtime scratch only (`internal`); SAS expiration policy flags long-lived tokens |

**Root cause.** Y1 Consumption requires a key-based `AzureWebJobsStorage` connection.
This is the one documented shared-key exception in the pipeline. The evidence store
itself disables shared keys entirely.

**Production path.** Identity-based `AzureWebJobsStorage` on Flex Consumption or
Premium, then remove the exception from `storage.rego`.

### E. Runtime storage replication (2)

| Check | Resources | Compensating control |
|---|---|---|
| CKV_AZURE_206 | both runtime accounts | Runtime scratch is regenerated on redeploy; the evidence account itself is GRS |

### F. Classic logging rules (4)

| Check | Resources | Compensating control |
|---|---|---|
| CKV_AZURE_33 | evidence storage, both runtime accounts | Queue service unused on the evidence account; runtime account metrics route to the GRC workspace via `cge-dine-storage-diagnostics` |
| CKV2_AZURE_21 | `reports` container | Blob read, write, and delete logging via `azurerm_monitor_diagnostic_setting.evidence_blob_logs` |

**Root cause.** These rules look for classic Storage Analytics or Storage Insights.
The pipeline uses diagnostic settings, which Azure recommends in their place.

### G. False positive (1)

| Check | Resource | Why it is wrong |
|---|---|---|
| CKV_AZURE_140 | Cosmos evidence account | Local auth **is** disabled, via `local_authentication_enabled = false`. azurerm v4 renamed the attribute and the rule still reads the deprecated one |

## Rules for adding a waiver

1. Fix it if the fix fits the sandbox's cost and plan constraints. A waiver is the
   exception, not the default.
2. Put the waiver on the resource, with a reason a reviewer can check against the code.
3. Name the compensating control. A waiver with no compensating control is an accepted
   risk, and it goes on the POA&M instead.
4. Add it to this register in the same PR.
