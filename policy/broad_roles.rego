# Gate rule: no broad role grants sneak into governance code, by name or by ID.
package main

import rego.v1

broad_role_names := {"Owner", "Contributor", "User Access Administrator"}

# Built-in role definition GUIDs for the same three roles.
broad_role_guids := {
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
	"b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", # User Access Administrator
}

broad(after) := after.role_definition_name if {
	after.role_definition_name in broad_role_names
}

broad(after) := guid if {
	id := lower(object.get(after, "role_definition_id", ""))
	some guid in broad_role_guids
	endswith(id, guid)
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "azurerm_role_assignment"
	some action in rc.change.actions
	action != "delete"
	role := broad(rc.change.after)
	msg := sprintf("%s: %s at any scope is not a whitelist; use a granular role", [rc.address, role])
}
