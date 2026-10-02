# --- The collector Function App: timer-triggered Python, managed identity, zero keys. ---
# One app for collectors, a separate app (stage 04) for reporting: the Function App is
# the identity boundary, and no identity both writes evidence and generates reports.

# Internal plumbing storage for the Functions runtime (NOT the evidence store —
# that account has shared keys disabled; this one is the app's own scratch space).
resource "azurerm_storage_account" "func_internal" {
  #checkov:skip=CKV2_AZURE_40:Y1 Consumption requires a key-based AzureWebJobsStorage connection. Documented exception, also allowed by name in policy/storage.rego. Holds runtime scratch only.
  #checkov:skip=CKV_AZURE_59:Functions runtime scratch space (classification internal). Consumption plan requires public reachability.
  #checkov:skip=CKV2_AZURE_33:Consumption plan cannot use private endpoints for its runtime storage.
  #checkov:skip=CKV2_AZURE_1:Runtime scratch, classification internal. No evidence or sensitive data lives here.
  #checkov:skip=CKV_AZURE_206:Runtime scratch is regenerable on redeploy; LRS is sufficient.
  #checkov:skip=CKV_AZURE_33:Classic queue analytics logging. The runtime's queues carry no evidence; account metrics route to the GRC workspace via cge-dine-storage-diagnostics.
  name                            = "stgrcfunc${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  # The one documented shared-key exception in the pipeline, stated rather than defaulted.
  shared_access_key_enabled = true

  # Any SAS issued against runtime storage (e.g. a run-from-package URL) is flagged past 7 days. (CKV2_AZURE_41)
  sas_policy {
    expiration_period = "7.00:00:00"
    expiration_action = "Log"
  }

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  tags = local.runtime_tags
}

resource "azurerm_service_plan" "collectors" {
  #checkov:skip=CKV_AZURE_225:Y1 Consumption does not support zone redundancy. A missed timer run is caught by run-history gaps, not lost evidence.
  #checkov:skip=CKV_AZURE_212:Y1 Consumption scales from zero; minimum instance counts do not apply.
  name                = "asp-grc-collectors-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1" # Consumption: pay per execution. Pennies.
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "collectors" {
  #checkov:skip=CKV_AZURE_221:Y1 Consumption cannot disable public network access. The app exposes timer triggers plus function-key HTTP triggers for manual runs, and HTTPS only is enforced.
  name                       = "func-grc-collectors-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.collectors.id
  storage_account_name       = azurerm_storage_account.func_internal.name
  storage_account_access_key = azurerm_storage_account.func_internal.primary_access_key

  # Plain HTTP never reaches the app. (CKV_AZURE_70)
  https_only = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    "COSMOS_ENDPOINT"                = azurerm_cosmosdb_account.evidence.endpoint
    "COSMOS_DATABASE"                = azurerm_cosmosdb_sql_database.grc.name
    "SUBSCRIPTION_ID"                = local.subscription
    "POLICY_ASSIGNMENTS"             = join(",", var.collected_policy_assignments)
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "ENABLE_ORYX_BUILD"              = "true"
  }

  tags = local.common_tags
}

# --- The collector identity's whitelist: read posture, write evidence. Nothing else. ---

# Security Reader at the subscription: read Defender assessments, change nothing.
resource "azurerm_role_assignment" "collector_security_reader" {
  scope                = "/subscriptions/${local.subscription}"
  role_definition_name = "Security Reader"
  principal_id         = azurerm_linux_function_app.collectors.identity[0].principal_id
}

# Cosmos data-plane write. "Cosmos DB Built-in Data Contributor" (00000000-0000-0000-0000-000000000002)
# is a Cosmos-native data-plane role, not an ARM role — control plane vs data plane, again.
resource "azurerm_cosmosdb_sql_role_assignment" "collector_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = azurerm_linux_function_app.collectors.identity[0].principal_id
  scope               = azurerm_cosmosdb_account.evidence.id
}

# --- Policy compliance: read-only, policy states only. ---
# Security Reader covers Defender but not Policy Insights. Rather than widen the collector
# to Reader (read everything), it gets a custom role holding exactly one capability:
# query policy compliance results. It cannot trigger scans, write exemptions, or change
# any assignment, so the recorder still cannot alter what it observes.

# blast radius: none. Read-only role, no write, delete, or data actions.
# rollback: remove the assignment; the collector's next sweep fails closed and the
# failure is recorded in the runs ledger.
resource "azurerm_role_definition" "policy_state_reader" {
  name        = "GRC Policy State Reader (${var.environment})"
  scope       = "/subscriptions/${local.subscription}"
  description = "Query Azure Policy compliance states. Nothing else. Held by the CGE-AZ collector."

  permissions {
    actions = ["Microsoft.PolicyInsights/policyStates/*/read"]
  }

  assignable_scopes = ["/subscriptions/${local.subscription}"]
}

# A brand-new custom role can take a minute to become assignable. If the first apply
# fails here with RoleDefinitionDoesNotExist, wait a minute and re-run apply.
resource "azurerm_role_assignment" "collector_policy_states" {
  scope              = "/subscriptions/${local.subscription}"
  role_definition_id = azurerm_role_definition.policy_state_reader.role_definition_resource_id
  principal_id       = azurerm_linux_function_app.collectors.identity[0].principal_id
}
