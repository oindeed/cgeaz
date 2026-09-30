locals {
  evidence_rg  = data.terraform_remote_state.foundation.outputs.evidence_resource_group_name
  subscription = data.terraform_remote_state.foundation.outputs.subscription_id
  common_tags = {
    env     = var.environment
    purpose = "grc-evidence-plane"
  }

  # Every data store declares what it holds (cge-require-data-classification, classification.rego).
  # Evidence and its lineage: confidential. Functions runtime scratch space: internal.
  evidence_tags = merge(local.common_tags, { "data-classification" = "confidential" })
  runtime_tags  = merge(local.common_tags, { "data-classification" = "internal" })
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# --- Cosmos DB: the evidence database we OWN. Serverless; pennies at lab scale. ---

resource "azurerm_cosmosdb_account" "evidence" {
  #checkov:skip=CKV_AZURE_140:False positive. Local auth IS disabled via local_authentication_enabled = false (azurerm v4 rename); the rule still reads the deprecated attribute.
  #checkov:skip=CKV_AZURE_101:Y1 Consumption Functions cannot reach a private endpoint. Compensating: local auth off, Entra ID data-plane RBAC only, classification = confidential (private networking is required at restricted).
  #checkov:skip=CKV_AZURE_99:Same constraint as CKV_AZURE_101. Consumption outbound IPs are shared and change, so an IP filter adds no real boundary; identity is the boundary.
  #checkov:skip=CKV_AZURE_100:Platform-managed keys at the confidential tier. CMK adds Key Vault and rotation operations the sandbox does not justify; restricted-tier production stores would use CMK.
  name                = "cosmos-grc-evidence-${random_string.suffix.result}"
  location            = var.location
  resource_group_name = local.evidence_rg
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  # Identity-only access: no key-based auth against the evidence database.
  # local_authentication_disabled was deprecated in favour of local_authentication_enabled
  # (removed in azurerm v5.0); the boolean inverts, so disabled=true becomes enabled=false.
  local_authentication_enabled = false

  # Account keys cannot change account metadata either (containers, throughput, indexing).
  # Every schema change goes through ARM, as an identity, in the Activity Log. (CKV_AZURE_132)
  access_key_metadata_writes_enabled = false

  capabilities {
    name = "EnableServerless"
  }

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  tags = local.evidence_tags
}

resource "azurerm_cosmosdb_sql_database" "grc" {
  name                = "grc"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
}

# assessments: one document per finding per run. Partitioned by subscription+date query pattern.
resource "azurerm_cosmosdb_sql_container" "assessments" {
  name                = "assessments"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/subscriptionId"]
}

# frameworks: CSF 2.0 / 800-53 catalogs as records we own.
resource "azurerm_cosmosdb_sql_container" "frameworks" {
  name                = "frameworks"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# mappings: the crosswalk — which assessment satisfies which control in which framework.
resource "azurerm_cosmosdb_sql_container" "mappings" {
  name                = "mappings"
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  database_name       = azurerm_cosmosdb_sql_database.grc.name
  partition_key_paths = ["/frameworkId"]
}

# --- Evidence artifact storage: WORM reports container, zero shared keys. ---

resource "azurerm_storage_account" "evidence" {
  #checkov:skip=CKV_AZURE_59:Reporter Function (Y1 Consumption) writes over the public endpoint; Consumption has no VNet integration. Compensating: shared keys off, Entra ID only, no anonymous access, TLS 1.2.
  #checkov:skip=CKV2_AZURE_33:Same constraint as CKV_AZURE_59. Private endpoints are the production move alongside Flex Consumption or Premium plans.
  #checkov:skip=CKV2_AZURE_1:Platform-managed keys at the confidential tier; see CKV_AZURE_100 on the Cosmos account for the same reasoning.
  #checkov:skip=CKV_AZURE_33:Queue service is unused on the evidence account. Blob access logging is on via azurerm_monitor_diagnostic_setting.evidence_blob_logs.
  name                     = "stgrcevid${random_string.suffix.result}"
  resource_group_name      = local.evidence_rg
  location                 = var.location
  account_tier             = "Standard"
  # Evidence outlives a regional outage. GRS at lab scale costs pennies. (CKV_AZURE_206)
  account_replication_type = "GRS"
  min_tls_version          = "TLS1_2"

  # The store's front door has one kind of lock: identity.
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false

  blob_properties {
    versioning_enabled = true

    # Belt and braces behind WORM: anything outside the immutable container is still
    # recoverable for 14 days after a delete. (CKV2_AZURE_38)
    delete_retention_policy {
      days = 14
    }
    container_delete_retention_policy {
      days = 14
    }
  }

  tags = local.evidence_tags
}

# Who read, wrote, or tried to delete evidence, routed to the GRC workspace. This is where
# the failed-delete WORM proof shows up as a logged, attributed event, not a screenshot.
resource "azurerm_monitor_diagnostic_setting" "evidence_blob_logs" {
  name                       = "ds-evidence-blob-to-grc"
  target_resource_id         = "${azurerm_storage_account.evidence.id}/blobServices/default"
  log_analytics_workspace_id = data.terraform_remote_state.foundation.outputs.log_analytics_workspace_id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  enabled_log {
    category = "StorageDelete"
  }
}

resource "azurerm_storage_container" "reports" {
  #checkov:skip=CKV2_AZURE_21:Rule looks for classic Storage Insights. Blob read/write/delete logging is on via azurerm_monitor_diagnostic_setting.evidence_blob_logs.
  name               = "reports"
  storage_account_id = azurerm_storage_account.evidence.id
}

# WORM: write once, read many. Not access control — a platform guarantee.
resource "azurerm_storage_container_immutability_policy" "reports_worm" {
  # resource_manager_id was deprecated on azurerm_storage_container; id now returns the
  # resource-manager ID this argument expects.
  storage_container_resource_manager_id = azurerm_storage_container.reports.id
  immutability_period_in_days           = var.reports_retention_days
  # Unlocked for the course so teardown works. Production locks it — after which
  # nobody, including Microsoft, can shorten or remove it.
}

# The deployer needs blob DATA-plane access to verify WORM behavior and upload seeds —
# Owner is control-plane only (the 01_02 lesson, in production form).
data "azurerm_client_config" "current" {}

resource "azurerm_role_assignment" "deployer_blob_data" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.current.object_id
}

# The deployer also seeds the frameworks/mappings containers (labs/04's seed script),
# so it gets the Cosmos data-plane contributor role. Same reasoning as the blob role above.
resource "azurerm_cosmosdb_sql_role_assignment" "deployer_cosmos_write" {
  resource_group_name = local.evidence_rg
  account_name        = azurerm_cosmosdb_account.evidence.name
  role_definition_id  = "${azurerm_cosmosdb_account.evidence.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = data.azurerm_client_config.current.object_id
  scope               = azurerm_cosmosdb_account.evidence.id
}
