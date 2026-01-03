# Azure Scheduling Module for Mantissa Stance
#
# Creates Timer triggers for Azure Functions and Event Grid
# for scheduled scans and notifications.

# Timer trigger is configured in the Function App code
# This module sets up supporting infrastructure for notifications

# Event Grid Custom Topic for scan events
resource "azurerm_eventgrid_topic" "stance" {
  name                = "${var.name_prefix}-events"
  resource_group_name = var.resource_group_name
  location            = var.location

  identity {
    type = "SystemAssigned"
  }

  input_schema = "EventGridSchema"

  tags = var.tags
}

# Event Grid subscription for critical findings
resource "azurerm_eventgrid_event_subscription" "critical_findings" {
  count = var.enable_notifications ? 1 : 0

  name  = "${var.name_prefix}-critical-findings"
  scope = azurerm_eventgrid_topic.stance.id

  included_event_types = [
    "Stance.Finding.Critical",
    "Stance.Finding.High",
  ]

  # Send to webhook if configured
  dynamic "webhook_endpoint" {
    for_each = var.notification_webhook_url != "" ? [1] : []
    content {
      url = var.notification_webhook_url
    }
  }

  # Or send to Azure Function
  dynamic "azure_function_endpoint" {
    for_each = var.notification_function_id != "" ? [1] : []
    content {
      function_id = var.notification_function_id
    }
  }

  retry_policy {
    max_delivery_attempts = 30
    event_time_to_live    = 1440 # 24 hours
  }
}

# Event Grid subscription for scan completion
resource "azurerm_eventgrid_event_subscription" "scan_complete" {
  count = var.enable_notifications ? 1 : 0

  name  = "${var.name_prefix}-scan-complete"
  scope = azurerm_eventgrid_topic.stance.id

  included_event_types = [
    "Stance.Scan.Completed",
    "Stance.Scan.Failed",
  ]

  dynamic "webhook_endpoint" {
    for_each = var.notification_webhook_url != "" ? [1] : []
    content {
      url = var.notification_webhook_url
    }
  }

  retry_policy {
    max_delivery_attempts = 10
    event_time_to_live    = 60
  }
}

# Action Group for alerts
resource "azurerm_monitor_action_group" "stance" {
  count = var.enable_notifications ? 1 : 0

  name                = "${var.name_prefix}-alerts"
  resource_group_name = var.resource_group_name
  short_name          = "stance"

  dynamic "email_receiver" {
    for_each = var.alert_email_addresses
    content {
      name                    = "email-${email_receiver.key}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }

  dynamic "webhook_receiver" {
    for_each = var.alert_webhook_url != "" ? [1] : []
    content {
      name                    = "webhook"
      service_uri             = var.alert_webhook_url
      use_common_alert_schema = true
    }
  }

  tags = var.tags
}

# Metric Alert for scan failures
resource "azurerm_monitor_metric_alert" "scan_failures" {
  count = var.enable_notifications && var.function_app_id != "" ? 1 : 0

  name                = "${var.name_prefix}-scan-failures"
  resource_group_name = var.resource_group_name
  scopes              = [var.function_app_id]
  description         = "Alert when Stance scans fail"

  criteria {
    metric_namespace = "Microsoft.Web/sites"
    metric_name      = "FunctionExecutionCount"
    aggregation      = "Total"
    operator         = "GreaterThan"
    threshold        = 0

    dimension {
      name     = "FunctionName"
      operator = "Include"
      values   = ["collect", "evaluate"]
    }

    dimension {
      name     = "Success"
      operator = "Include"
      values   = ["false"]
    }
  }

  action {
    action_group_id = azurerm_monitor_action_group.stance[0].id
  }

  frequency   = "PT5M"
  window_size = "PT15M"
  severity    = 2

  tags = var.tags
}
