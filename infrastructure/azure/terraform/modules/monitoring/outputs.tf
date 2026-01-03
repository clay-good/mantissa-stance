# Outputs for Azure Monitoring Module

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.stance.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.stance.name
}

output "log_analytics_primary_key" {
  description = "Primary shared key for the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.stance.primary_shared_key
  sensitive   = true
}

output "log_analytics_workspace_id_output" {
  description = "Workspace ID for the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.stance.workspace_id
}

output "application_insights_id" {
  description = "ID of the Application Insights resource"
  value       = azurerm_application_insights.stance.id
}

output "application_insights_instrumentation_key" {
  description = "Instrumentation key for Application Insights"
  value       = azurerm_application_insights.stance.instrumentation_key
  sensitive   = true
}

output "application_insights_connection_string" {
  description = "Connection string for Application Insights"
  value       = azurerm_application_insights.stance.connection_string
  sensitive   = true
}

output "action_group_email_id" {
  description = "ID of the email action group"
  value       = var.notification_email != null ? azurerm_monitor_action_group.email[0].id : null
}

output "action_group_critical_id" {
  description = "ID of the critical alerts action group"
  value       = var.notification_email != null ? azurerm_monitor_action_group.critical[0].id : null
}

output "workbook_id" {
  description = "ID of the Azure Monitor Workbook"
  value       = azurerm_application_insights_workbook.stance.id
}

output "workbook_name" {
  description = "Display name of the workbook"
  value       = azurerm_application_insights_workbook.stance.display_name
}
