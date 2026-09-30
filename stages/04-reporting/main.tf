locals {
  evidence_rg      = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  cosmos_endpoint  = data.terraform_remote_state.evidence.outputs.cosmos_endpoint
  cosmos_id        = data.terraform_remote_state.evidence.outputs.cosmos_account_id
  cosmos_name      = data.terraform_remote_state.evidence.outputs.cosmos_account_name
  evidence_storage = data.terraform_remote_state.evidence.outputs.evidence_storage_account
  common_tags = {
    env     = var.environment
    purpose = "grc-reporting"
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

data "azurerm_storage_account" "evidence" {
  name                = local.evidence_storage
  resource_group_name = local.evidence_rg
}

resource "azurerm_storage_account" "func_internal" {
  #checkov:skip=CKV2_AZURE_40:Y1 Consumption requires a key-based AzureWebJobsStorage connection. Documented exception, also allowed by name in policy/storage.rego. Holds runtime scratch only.
  #checkov:skip=CKV_AZURE_59:Functions runtime scratch space (classification internal). Consumption plan requires public reachability.
  #checkov:skip=CKV2_AZURE_33:Consumption plan cannot use private endpoints for its runtime storage.
  #checkov:skip=CKV2_AZURE_1:Runtime scratch, classification internal. No evidence or sensitive data lives here.
  #checkov:skip=CKV_AZURE_206:Runtime scratch is regenerable on redeploy; LRS is sufficient.
  #checkov:skip=CKV_AZURE_33:Classic queue analytics logging. The runtime's queues carry no evidence; account metrics route to the GRC workspace via cge-dine-storage-diagnostics.
  name                            = "stgrcrpt${random_string.suffix.result}"
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

  tags = merge(local.common_tags, { "data-classification" = "internal" })
}

resource "azurerm_service_plan" "reporting" {
  #checkov:skip=CKV_AZURE_225:Y1 Consumption does not support zone redundancy. A missed timer run is caught by run-history gaps, not lost evidence.
  #checkov:skip=CKV_AZURE_212:Y1 Consumption scales from zero; minimum instance counts do not apply.
  name                = "asp-grc-reporting-${var.environment}"
  resource_group_name = local.evidence_rg
  location            = var.functions_location
  os_type             = "Linux"
  sku_name            = "Y1"
  tags                = local.common_tags
}

resource "azurerm_linux_function_app" "reporting" {
  #checkov:skip=CKV_AZURE_221:Y1 Consumption cannot disable public network access. The app exposes timer triggers plus function-key HTTP triggers for manual runs, and HTTPS only is enforced.
  name                       = "func-grc-reporting-${random_string.suffix.result}"
  resource_group_name        = local.evidence_rg
  location                   = var.functions_location
  service_plan_id            = azurerm_service_plan.reporting.id
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
    "COSMOS_ENDPOINT"                = local.cosmos_endpoint
    "COSMOS_DATABASE"                = "grc"
    "REPORTS_ACCOUNT_URL"            = data.azurerm_storage_account.evidence.primary_blob_endpoint
    "REPORTS_CONTAINER"              = "reports"
    "SCM_DO_BUILD_DURING_DEPLOYMENT" = "true"
    "ENABLE_ORYX_BUILD"              = "true"
  }

  tags = local.common_tags
}

# --- The reporting identity's whitelist — the mirror image of the collector's. ---
# Cosmos READ (built-in Data Reader), Blob WRITE into the WORM container. No path to
# live platform data: no Security Reader, no Cosmos write. SoD, enforced by scopes.

resource "azurerm_cosmosdb_sql_role_assignment" "reporter_cosmos_read" {
  resource_group_name = local.evidence_rg
  account_name        = local.cosmos_name
  role_definition_id  = "${local.cosmos_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"
  principal_id        = azurerm_linux_function_app.reporting.identity[0].principal_id
  scope               = local.cosmos_id
}

resource "azurerm_role_assignment" "reporter_blob_write" {
  scope                = data.azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_function_app.reporting.identity[0].principal_id
}

output "reporting_function_app" {
  value = azurerm_linux_function_app.reporting.name
}

output "reporter_principal_id" {
  value = azurerm_linux_function_app.reporting.identity[0].principal_id
}
