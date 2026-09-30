# Unit tests for classification.rego. Run: conftest verify --policy policy/
package main

import rego.v1

store(type, tags, public) := {"resource_changes": [{
	"address": sprintf("%s.test", [type]),
	"type": type,
	"name": "test",
	"change": {
		"actions": ["create"],
		"after": {"tags": tags, "public_network_access_enabled": public},
	},
}]}

test_classified_store_passes if {
	count(deny) == 0 with input as store("azurerm_storage_account", {"data-classification": "confidential"}, true)
}

test_unclassified_storage_denied if {
	count(deny) == 1 with input as store("azurerm_storage_account", {"env": "dev"}, true)
}

test_unclassified_cosmos_denied if {
	count(deny) == 1 with input as store("azurerm_cosmosdb_account", {}, true)
}

test_null_tags_denied if {
	count(deny) == 1 with input as store("azurerm_storage_account", null, true)
}

test_unknown_classification_denied if {
	count(deny) == 1 with input as store("azurerm_storage_account", {"data-classification": "secret-ish"}, true)
}

test_restricted_public_denied if {
	count(deny) == 1 with input as store("azurerm_cosmosdb_account", {"data-classification": "restricted"}, true)
}

test_restricted_private_passes if {
	count(deny) == 0 with input as store("azurerm_storage_account", {"data-classification": "restricted"}, false)
}

test_delete_is_ignored if {
	plan := {"resource_changes": [{
		"address": "azurerm_storage_account.old",
		"type": "azurerm_storage_account",
		"name": "old",
		"change": {"actions": ["delete"], "after": null},
	}]}
	count(deny) == 0 with input as plan
}

test_other_resource_types_ignored if {
	count(deny) == 0 with input as store("azurerm_resource_group", {}, true)
}
