# Data classification guardrails: my own controls, beyond the starter baseline.
#
# Why these two: in a healthcare environment the first question an assessor asks about
# any data store is "what's in it, and who can reach it?" The starter answers the
# second question for blobs only. These two answer both questions for every storage
# account and Cosmos DB account under the sandbox management group.
#
#   1. cge-require-data-classification (Audit)
#        Every data store declares what it holds. An unlabeled store is an unowned risk, and it
#        surfaces as a non-compliant policy state instead of hiding in inventory. (CSF: ID.AM)
#   2. cge-deny-public-network-restricted (Deny, earned)
#        A store labeled `restricted` (PHI-class data) cannot be reachable from the
#        public internet. The rule is binary and the label is self-declared, so there is
#        no judgment call to get wrong: Deny is earned on day one. (CSF: PR.DS, PR.IR)
#
# Both join the cge-grc-baseline initiative in policies.tf, so every current and future
# subscription under mg-grc-sandbox inherits them from one assignment.
#
# Only synthetic data ever lives in this sandbox. The `restricted` tier exists to prove
# the guardrail works, not to hold real patient data.

locals {
  # One vocabulary, shared with the repo gate (policy/classification.rego).
  # Change it here and there in the same PR, or the gate and the platform disagree.
  classification_tag    = "data-classification"
  classification_values = ["public", "internal", "confidential", "restricted"]
}

# --- 4. Data stores must declare a classification (Audit: new control, observe first) ---

# blast radius: Audit only. Writes compliance state, changes no resource, blocks no
# deployment. rollback: set classification_tag_effect = "Disabled" and merge.
resource "azurerm_policy_definition" "require_data_classification" {
  name                = "cge-require-data-classification"
  display_name        = "Storage and Cosmos DB accounts must carry a valid data-classification tag"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({
    category = "CGE-AZ Custom"
    csf      = ["ID.AM"]
  })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Audit"
    }
    allowedClassifications = {
      type         = "Array"
      defaultValue = local.classification_values
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field = "type"
          in    = ["Microsoft.Storage/storageAccounts", "Microsoft.DocumentDB/databaseAccounts"]
        },
        {
          anyOf = [
            { field = "tags['${local.classification_tag}']", exists = "false" },
            { field = "tags['${local.classification_tag}']", notIn = "[parameters('allowedClassifications')]" }
          ]
        }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}

# --- 5. Restricted data stores must not be reachable from the public internet (earned Deny) ---

# blast radius: blocks create/update of a storage or Cosmos account that is tagged
# `restricted` while public network access is enabled (or unset, which Azure treats as
# enabled). Touches no existing resource, deletes nothing, reads no data. Existing
# non-compliant stores surface as findings; they are not modified.
# rollback: set restricted_network_policy_effect = "Audit" and merge.
resource "azurerm_policy_definition" "deny_public_network_restricted" {
  name                = "cge-deny-public-network-restricted"
  display_name        = "Restricted-class data stores must disable public network access"
  policy_type         = "Custom"
  mode                = "Indexed"
  management_group_id = azurerm_management_group.sandbox.id

  metadata = jsonencode({
    category = "CGE-AZ Custom"
    csf      = ["PR.DS", "PR.IR"]
  })

  parameters = jsonencode({
    effect = {
      type          = "String"
      allowedValues = ["Audit", "Deny", "Disabled"]
      defaultValue  = "Deny"
    }
  })

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "tags['${local.classification_tag}']", equals = "restricted" },
        {
          anyOf = [
            {
              allOf = [
                { field = "type", equals = "Microsoft.Storage/storageAccounts" },
                { field = "Microsoft.Storage/storageAccounts/publicNetworkAccess", notEquals = "Disabled" }
              ]
            },
            {
              allOf = [
                { field = "type", equals = "Microsoft.DocumentDB/databaseAccounts" },
                { field = "Microsoft.DocumentDB/databaseAccounts/publicNetworkAccess", notEquals = "Disabled" }
              ]
            }
          ]
        }
      ]
    }
    then = { effect = "[parameters('effect')]" }
  })
}
