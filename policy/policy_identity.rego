# Gate rule: a policy assignment carrying remediation effects without an identity
# applies cleanly and then silently never remediates. Make that mistake unmergeable.
#
# In plan JSON a nested block that is absent renders as an empty list, and an empty
# list is truthy in Rego, so `not after.identity` never fires. Count the entries.
package main

import rego.v1

assignment_types := {
	"azurerm_management_group_policy_assignment",
	"azurerm_subscription_policy_assignment",
	"azurerm_resource_group_policy_assignment",
	"azurerm_resource_policy_assignment",
}

deny contains msg if {
	some rc in input.resource_changes
	rc.type in assignment_types
	some action in rc.change.actions
	action != "delete"
	count(object.get(rc.change.after, "identity", [])) == 0
	msg := sprintf("%s: policy assignments must carry an identity block (remediation effects silently no-op without one)", [rc.address])
}
