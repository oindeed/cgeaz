#!/usr/bin/env bash
# Arm YOUR fork's CI workflows against YOUR sandbox subscription.
#
# Creates an OIDC app registration federated to your fork, grants it the roles the
# plan-only workflows need, and prints the five repository VARIABLES to add in your
# fork's UI: Settings -> Secrets and variables -> Actions -> Variables tab.
#
# Why variables and not secrets? With OIDC there is no credential to protect —
# client/tenant/subscription IDs are identifiers, and possessing them grants nothing
# without a matching federation subject. The security boundary is the federation:
# it names YOUR fork, so only workflows running in YOUR fork can exchange tokens.
#
# Why never arm the upstream repo? On a public repo, the pull_request OIDC subject
# matches PRs from ANY fork, and pull_request runs the workflow file AS MODIFIED BY
# THE PR. Arming a public upstream hands every fork PR a path toward the subscription
# behind it. Your fork is low-traffic and yours; the course subscription is neither.
# (This reasoning is exam-relevant. You just read a trust-boundary analysis.)
set -euo pipefail

GH_USER="${1:?usage: ./arm-your-fork.sh <your-github-username-or-org>}"
REPO="${2:-cgeaz}"
SUB_ID=$(az account show --query id -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)

echo ">> App registration: github-${REPO}-${GH_USER}"
APP_ID=$(az ad app create --display-name "github-${REPO}-${GH_USER}" --query appId -o tsv)
APP_OBJ=$(az ad app show --id "$APP_ID" --query id -o tsv)
az ad sp create --id "$APP_ID" --output none 2>/dev/null || true
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

# GitHub's OIDC subject comes in two shapes. The legacy one names the repo
# (repo:OWNER/REPO:...). The current one also pins the immutable owner and repo IDs
# (repo:OWNER@OWNER_ID/REPO@REPO_ID:...), so a renamed or deleted-and-recreated repo
# with the same name can never satisfy the federation. Validated 2026-10-03: this fork's
# tokens arrived in the ID-pinned shape and the name-only credential was rejected
# (AADSTS700213). Register both; Entra matches whichever GitHub presents.
IDS=$(curl -fsS "https://api.github.com/repos/${GH_USER}/${REPO}" 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['owner']['id'], d['id'])" 2>/dev/null || true)
OWNER_ID=${IDS% *}; REPO_ID=${IDS#* }
SUBJECTS=("repo:${GH_USER}/${REPO}:pull_request|pr" "repo:${GH_USER}/${REPO}:ref:refs/heads/main|main")
if [ -n "$IDS" ]; then
  SUBJECTS+=("repo:${GH_USER}@${OWNER_ID}/${REPO}@${REPO_ID}:pull_request|pr-ids"
             "repo:${GH_USER}@${OWNER_ID}/${REPO}@${REPO_ID}:ref:refs/heads/main|main-ids")
else
  echo "   !! could not read repo IDs from the GitHub API; only name-based subjects registered"
fi

echo ">> Federated credentials for ${GH_USER}/${REPO} (pull_request + main, name and ID forms)"
for sub in "${SUBJECTS[@]}"; do
  SUBJECT="${sub%|*}"; NAME="${sub#*|}"
  az ad app federated-credential create --id "$APP_OBJ" --parameters "{
    \"name\": \"${REPO}-${NAME}\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"${SUBJECT}\",
    \"audiences\": [\"api://AzureADTokenExchange\"]
  }" --output none 2>/dev/null || echo "   (${REPO}-${NAME} already exists)"
done

# The CI identity only ever runs `terraform plan`. It gets a custom plan-only role
# (ci-planner-role.json): read everything, plus the handful of list actions a refresh
# needs. It cannot create, change, or delete a resource, so a compromised workflow
# dependency holding its token can look but not touch.
#
# Residual risk, stated: listKeys lets the planner read keys for the two Functions
# runtime accounts (classification internal). It cannot use keys against evidence:
# the evidence account disables shared keys and Cosmos disables local auth, so any
# listed key authenticates nothing there.
#
# Fallback: CI_ROLE=contributor ./arm-your-fork.sh <user> restores the starter's grant.
# If an armed plan 403s, the error names the one missing action. Add it to
# ci-planner-role.json by PR rather than widening to Contributor.
CI_ROLE="${CI_ROLE:-planner}"
MG_SCOPE="/providers/Microsoft.Management/managementGroups/mg-grc"
if [ "$CI_ROLE" = "contributor" ]; then
  echo ">> Roles: Contributor at mg-grc (fallback requested) + blob data on the state RG"
  ROLE_NAME="Contributor"
else
  ROLE_NAME="GRC Pipeline Planner"
  ROLE_FILE="$(dirname "$0")/ci-planner-role.json"
  echo ">> Roles: '${ROLE_NAME}' (plan-only custom role) at mg-grc + blob data on the state RG"
  if az role definition list --custom-role-only true --scope "$MG_SCOPE" \
       --query "[?roleName=='${ROLE_NAME}'] | length(@)" -o tsv | grep -q '^1$'; then
    az role definition update --role-definition "$ROLE_FILE" --output none
  else
    az role definition create --role-definition "$ROLE_FILE" --output none
  fi
  echo "   (new custom roles can take a minute or two to become assignable)"
  sleep 30
fi
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "$ROLE_NAME" --scope "$MG_SCOPE" --output none \
  || echo "   !! assignment failed: if the custom role was just created, wait a minute and re-run"
az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/$SUB_ID/resourceGroups/rg-grc-tfstate" --output none 2>/dev/null || true

# The human who applies stage 03 holds its deployer data-plane grants. CI plans with
# this ID so it does not try to hand those grants to itself (a false nightly drift).
DEPLOYER_OID=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || echo "<your Entra object ID>")

STATE_SA=$(grep storage_account_name "$(dirname "$0")/../03-foundation/backend.hcl" 2>/dev/null | tr -d ' "' | cut -d= -f2 || echo "<from backend.hcl>")

cat <<EOF

Done. Add these six VARIABLES (not secrets — see header comment) in YOUR fork:
Settings -> Secrets and variables -> Actions -> Variables -> New repository variable

  AZURE_CLIENT_ID        $APP_ID
  AZURE_TENANT_ID        $TENANT_ID
  AZURE_SUBSCRIPTION_ID  $SUB_ID
  STATE_STORAGE_ACCOUNT  $STATE_SA
  OWNER_EMAIL            <your email>
  DEPLOYER_OBJECT_ID     $DEPLOYER_OID

Then enable the two workflows in your fork's Actions tab. Never add these to the
upstream GRCEngClub/cgeaz repo — its workflows are intentionally unarmed.
EOF
