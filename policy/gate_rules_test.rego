# Unit tests for policy_identity.rego, broad_roles.rego and storage.rego.
# Run: conftest verify --policy policy/
package main

import rego.v1

change(type, name, actions, after) := {"resource_changes": [{
	"address": sprintf("%s.%s", [type, name]),
	"type": type,
	"name": name,
	"change": {"actions": actions, "after": after},
}]}

# --- policy_identity.rego ---

test_assignment_without_identity_denied if {
	count(deny) == 1 with input as change("azurerm_management_group_policy_assignment", "a", ["create"], {"identity": []})
}

test_assignment_with_identity_absent_key_denied if {
	count(deny) == 1 with input as change("azurerm_subscription_policy_assignment", "a", ["update"], {})
}

test_assignment_with_identity_passes if {
	count(deny) == 0 with input as change("azurerm_subscription_policy_assignment", "a", ["create"], {"identity": [{"type": "SystemAssigned"}]})
}

test_assignment_delete_ignored if {
	count(deny) == 0 with input as change("azurerm_management_group_policy_assignment", "a", ["delete"], null)
}

test_replace_without_identity_denied if {
	count(deny) == 1 with input as change("azurerm_management_group_policy_assignment", "a", ["delete", "create"], {"identity": []})
}

# --- broad_roles.rego ---

test_owner_by_name_denied if {
	count(deny) == 1 with input as change("azurerm_role_assignment", "r", ["create"], {"role_definition_name": "Owner"})
}

test_contributor_by_id_denied if {
	count(deny) == 1 with input as change("azurerm_role_assignment", "r", ["create"], {"role_definition_id": "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"})
}

test_user_access_admin_denied if {
	count(deny) == 1 with input as change("azurerm_role_assignment", "r", ["create"], {"role_definition_name": "User Access Administrator"})
}

test_granular_role_passes if {
	count(deny) == 0 with input as change("azurerm_role_assignment", "r", ["create"], {"role_definition_name": "Monitoring Contributor"})
}

test_storage_account_contributor_passes if {
	count(deny) == 0 with input as change("azurerm_role_assignment", "r", ["create"], {"role_definition_name": "Storage Account Contributor"})
}

# --- storage.rego (tags set so classification.rego stays quiet) ---

classified := {"data-classification": "internal"}

test_public_blob_denied if {
	count(deny) == 1 with input as change("azurerm_storage_account", "evidence", ["create"], {"tags": classified, "allow_nested_items_to_be_public": true, "shared_access_key_enabled": false, "public_network_access_enabled": true})
}

test_shared_keys_denied if {
	count(deny) == 1 with input as change("azurerm_storage_account", "evidence", ["create"], {"tags": classified, "allow_nested_items_to_be_public": false, "shared_access_key_enabled": true, "public_network_access_enabled": true})
}

test_func_runtime_shared_keys_exempt if {
	count(deny) == 0 with input as change("azurerm_storage_account", "func_internal", ["create"], {"tags": classified, "allow_nested_items_to_be_public": false, "shared_access_key_enabled": true, "public_network_access_enabled": true})
}

test_hardened_storage_passes if {
	count(deny) == 0 with input as change("azurerm_storage_account", "evidence", ["create"], {"tags": classified, "allow_nested_items_to_be_public": false, "shared_access_key_enabled": false, "public_network_access_enabled": true})
}
