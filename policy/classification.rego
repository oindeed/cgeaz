# Gate rule: every data store in a plan declares what it holds, and a restricted-class
# store cannot be born reachable from the public internet.
#
# Same vocabulary as the platform control (stages/01-foundation/policies-classification.tf).
# The platform catches out-of-band changes; this gate catches them before merge, so the
# pipeline's own code is held to the standard it enforces on everything else.
package main

import rego.v1

classification_tag := "data-classification"

allowed_classifications := {"public", "internal", "confidential", "restricted"}

data_store_types := {"azurerm_storage_account", "azurerm_cosmosdb_account"}

live_data_stores contains rc if {
	some rc in input.resource_changes
	rc.type in data_store_types
	some action in rc.change.actions
	action in {"create", "update"}
}

classification(rc) := rc.change.after.tags[classification_tag]

deny contains msg if {
	some rc in live_data_stores
	not classification(rc)
	msg := sprintf("%s: data stores must carry a %q tag (one of %v)", [rc.address, classification_tag, sort(allowed_classifications)])
}

deny contains msg if {
	some rc in live_data_stores
	value := classification(rc)
	not value in allowed_classifications
	msg := sprintf("%s: %q is not a recognized classification (one of %v)", [rc.address, value, sort(allowed_classifications)])
}

deny contains msg if {
	some rc in live_data_stores
	classification(rc) == "restricted"
	not rc.change.after.public_network_access_enabled == false
	msg := sprintf("%s: restricted-class data stores must set public_network_access_enabled = false", [rc.address])
}
