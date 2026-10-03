# Drift detector 2 of 2: who is touching reality?
#
# Detector 1 (.github/workflows/drift.yml) asks whether reality still matches the code.
# It runs nightly and only sees the end state. This one watches the Activity Log for the
# act itself: any successful administrative write or delete in the governed subscription
# by an identity that is not one of the pipeline's automation identities. A portal click,
# an ad hoc CLI change, or a terraform apply run outside a merged PR all land here, with
# the caller's name on them, within the hour.
#
# The allowlist is the remediation identity only. Human terraform applies also fire the
# alert on purpose: the alert is the prompt to match each change to a merged PR. A change
# with no PR behind it is the finding. (CSF: DE.CM, DE.AE)
#
# blast radius: read-only. Runs one KQL query per hour against the GRC workspace and
# emails the owner when it returns rows. Changes no resource, blocks nothing.
# rollback: set tripwire_enabled = false and merge.

# The tripwire's input: the subscription Activity Log, routed to the GRC workspace.
# This used to be a lab script (labs/02-toolkit/route-activity-log.sh), which put the
# drift detector's own data feed outside the code and outside drift detection.
# Existing deployments that ran the script adopt it once:
#   terraform import azurerm_monitor_diagnostic_setting.activity_log "/subscriptions/<id>|ds-activity-to-law"
# blast radius: routes four Activity Log categories to the workspace; changes no
# resource and blocks nothing. rollback: delete this block and merge (logging stops).
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "ds-activity-to-law"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.grc.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Policy"
  }
  enabled_log {
    category = "Alert"
  }
}

locals {
  # Identities whose writes are expected without a human in the loop. AzureActivity
  # records a managed identity's writes under its principal (object) ID.
  tripwire_allowed_callers = [
    azurerm_user_assigned_identity.remediation.principal_id,
  ]
}

resource "azurerm_monitor_action_group" "grc_owner" {
  name                = "ag-grc-owner-${var.environment}"
  resource_group_name = azurerm_resource_group.sandbox.name
  short_name          = "grcowner"

  email_receiver {
    name                    = "grc-owner"
    email_address           = var.owner_email
    use_common_alert_schema = true
  }

  tags = {
    env     = var.environment
    purpose = "drift-tripwire"
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "out_of_band_change" {
  name                = "alert-grc-out-of-band-change-${var.environment}"
  description         = "An identity outside the pipeline's automation made an administrative write or delete. Match it to a merged PR; a change with no PR is the finding."
  resource_group_name = azurerm_resource_group.sandbox.name
  location            = var.location
  scopes              = [azurerm_log_analytics_workspace.grc.id]
  enabled             = var.tripwire_enabled

  severity                = 2
  evaluation_frequency    = "PT1H"
  window_duration         = "PT1H"
  auto_mitigation_enabled = true

  # On a brand-new workspace the AzureActivity table appears only after the first rows
  # land (30 to 60 minutes after routing), and query validation would fail the apply.
  skip_query_validation = true

  criteria {
    query = <<-KQL
      AzureActivity
      | where CategoryValue == "Administrative"
      | where ActivityStatusValue in ("Success", "Succeeded")
      | where OperationNameValue endswith "/WRITE" or OperationNameValue endswith "/DELETE"
      | where isnotempty(Caller)
      | where Caller !in (dynamic(${jsonencode(local.tripwire_allowed_callers)}))
      | project TimeGenerated, Caller, OperationNameValue, ResourceGroup, _ResourceId
    KQL

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.grc_owner.id]
  }

  # The query reads AzureActivity, which exists only once routing has delivered rows.
  depends_on = [azurerm_monitor_diagnostic_setting.activity_log]

  tags = {
    env     = var.environment
    purpose = "drift-tripwire"
  }
}
