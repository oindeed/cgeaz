# DELIBERATELY NON-COMPLIANT. This file exists only to prove the compliance gate blocks
# it. The PR that adds it is closed unmerged; it is never applied.
#
# Expected gate failures (policy/):
#   storage.rego         allow_nested_items_to_be_public = true
#   storage.rego         shared_access_key_enabled = true on a non-runtime account
#   classification.rego  no data-classification tag
resource "azurerm_storage_account" "gate_proof" {
  name                            = "stgrcgate${random_string.suffix.result}"
  resource_group_name             = local.evidence_rg
  location                        = var.functions_location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  shared_access_key_enabled       = true
}
