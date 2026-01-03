# Azure Monitoring Module for Mantissa Stance
#
# Creates Azure Monitor workbook, action groups for alerts,
# and Log Analytics workspace for observability.

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "stance" {
  name                = "${var.name_prefix}-logs"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days

  tags = var.tags
}

# Application Insights for function monitoring
resource "azurerm_application_insights" "stance" {
  name                = "${var.name_prefix}-insights"
  resource_group_name = var.resource_group_name
  location            = var.location
  workspace_id        = azurerm_log_analytics_workspace.stance.id
  application_type    = "web"

  tags = var.tags
}

# Action Group for email notifications
resource "azurerm_monitor_action_group" "email" {
  count = var.notification_email != null ? 1 : 0

  name                = "stance-email-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "stanceemail"

  email_receiver {
    name          = "email-receiver"
    email_address = var.notification_email
  }

  tags = var.tags
}

# Action Group for critical alerts (can include PagerDuty, webhooks, etc.)
resource "azurerm_monitor_action_group" "critical" {
  count = var.notification_email != null ? 1 : 0

  name                = "stance-critical-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "stancecrit"

  email_receiver {
    name                    = "critical-email"
    email_address           = var.notification_email
    use_common_alert_schema = true
  }

  tags = var.tags
}

# Metric Alert: Function execution failures
resource "azurerm_monitor_metric_alert" "function_failures" {
  count = var.enable_alerts && var.function_app_id != null ? 1 : 0

  name                = "stance-function-failures"
  resource_group_name = var.resource_group_name
  scopes              = [var.function_app_id]
  description         = "Alert when Stance function executions fail"
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "FunctionExecutionCount"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0

    dimension {
      name     = "FunctionName"
      operator = "Include"
      values   = ["*"]
    }
  }

  action {
    action_group_id = var.notification_email != null ? azurerm_monitor_action_group.email[0].id : null
  }

  tags = var.tags
}

# Log Alert: Critical findings detected
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "critical_findings" {
  count = var.enable_alerts ? 1 : 0

  name                = "stance-critical-findings"
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Alert when critical security findings are detected"
  severity            = 0

  scopes                    = [azurerm_log_analytics_workspace.stance.id]
  evaluation_frequency      = "PT5M"
  window_duration           = "PT5M"
  auto_mitigation_enabled   = true
  workspace_alerts_storage_enabled = false

  criteria {
    query = <<-QUERY
      customEvents
      | where name == "finding_generated"
      | where customDimensions.severity == "critical"
      | summarize count() by bin(timestamp, 5m)
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = var.notification_email != null ? [azurerm_monitor_action_group.critical[0].id] : []
  }

  tags = var.tags
}

# Log Alert: No scan activity
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "no_activity" {
  count = var.enable_alerts ? 1 : 0

  name                = "stance-no-scan-activity"
  resource_group_name = var.resource_group_name
  location            = var.location
  description         = "Alert when no scan activity is detected within expected timeframe"
  severity            = 2

  scopes               = [azurerm_log_analytics_workspace.stance.id]
  evaluation_frequency = "PT1H"
  window_duration      = "P1D"

  criteria {
    query = <<-QUERY
      customEvents
      | where name == "scan_completed"
      | summarize count() by bin(timestamp, 1h)
      | where count_ == 0
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = var.no_activity_threshold_hours

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = var.notification_email != null ? [azurerm_monitor_action_group.email[0].id] : []
  }

  tags = var.tags
}

# Azure Monitor Workbook
resource "azurerm_application_insights_workbook" "stance" {
  name                = "stance-security-dashboard"
  resource_group_name = var.resource_group_name
  location            = var.location
  display_name        = "Mantissa Stance Security Dashboard"
  source_id           = azurerm_application_insights.stance.id

  data_json = jsonencode({
    version = "Notebook/1.0"
    items = [
      {
        type = 1
        content = {
          json = "# Mantissa Stance Security Dashboard\n\nThis dashboard provides an overview of your cloud security posture across all monitored accounts."
        }
        name = "header"
      },
      {
        type = 3
        content = {
          version    = "KqlItem/1.0"
          query      = <<-QUERY
            customEvents
            | where name == "scan_completed"
            | summarize Scans = count() by bin(timestamp, 1h)
            | order by timestamp desc
          QUERY
          size           = 0
          title          = "Scan Activity (Last 24 Hours)"
          timeContext = {
            durationMs = 86400000
          }
          queryType      = 0
          visualization  = "linechart"
        }
        name = "scan-activity"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = <<-QUERY
            customEvents
            | where name == "finding_generated"
            | summarize Count = count() by tostring(customDimensions.severity)
            | order by Count desc
          QUERY
          size          = 1
          title         = "Findings by Severity"
          timeContext = {
            durationMs = 86400000
          }
          queryType     = 0
          visualization = "piechart"
        }
        name = "findings-by-severity"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = <<-QUERY
            customEvents
            | where name == "finding_generated"
            | where customDimensions.severity in ("critical", "high")
            | project
                timestamp,
                Severity = tostring(customDimensions.severity),
                Title = tostring(customDimensions.title),
                Asset = tostring(customDimensions.asset_id)
            | order by timestamp desc
            | take 20
          QUERY
          size          = 0
          title         = "Recent Critical/High Findings"
          timeContext = {
            durationMs = 86400000
          }
          queryType     = 0
          visualization = "table"
        }
        name = "recent-findings"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = <<-QUERY
            customEvents
            | where name == "asset_discovered"
            | summarize Assets = dcount(tostring(customDimensions.asset_id)) by tostring(customDimensions.cloud_provider)
          QUERY
          size          = 1
          title         = "Assets by Cloud Provider"
          timeContext = {
            durationMs = 86400000
          }
          queryType     = 0
          visualization = "piechart"
        }
        name = "assets-by-provider"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = <<-QUERY
            customEvents
            | where name == "asset_discovered"
            | where customDimensions.network_exposure == "internet_facing"
            | summarize InternetFacing = dcount(tostring(customDimensions.asset_id)) by tostring(customDimensions.resource_type)
            | order by InternetFacing desc
            | take 10
          QUERY
          size          = 0
          title         = "Internet-Facing Assets by Type"
          timeContext = {
            durationMs = 86400000
          }
          queryType     = 0
          visualization = "barchart"
        }
        name = "internet-facing-assets"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = <<-QUERY
            customEvents
            | where name == "finding_generated"
            | summarize Findings = count() by bin(timestamp, 1d), tostring(customDimensions.severity)
            | order by timestamp asc
          QUERY
          size          = 0
          title         = "Finding Trend (30 Days)"
          timeContext = {
            durationMs = 2592000000
          }
          queryType     = 0
          visualization = "areachart"
        }
        name = "finding-trend"
      },
      {
        type = 3
        content = {
          version = "KqlItem/1.0"
          query   = <<-QUERY
            exceptions
            | where cloud_RoleName contains "stance"
            | summarize Errors = count() by bin(timestamp, 1h)
            | order by timestamp desc
          QUERY
          size          = 0
          title         = "Function Errors"
          timeContext = {
            durationMs = 86400000
          }
          queryType     = 0
          visualization = "linechart"
        }
        name = "function-errors"
      }
    ]
    isLocked = false
    fallbackResourceIds = [
      azurerm_application_insights.stance.id
    ]
  })

  tags = var.tags
}

# Diagnostic settings for function app (if provided)
resource "azurerm_monitor_diagnostic_setting" "function_app" {
  count = var.function_app_id != null ? 1 : 0

  name                       = "stance-function-diagnostics"
  target_resource_id         = var.function_app_id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.stance.id

  enabled_log {
    category = "FunctionAppLogs"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
