# Outputs for Azure Compute Module

output "function_app_name" {
  description = "Name of the Function App"
  value       = azurerm_linux_function_app.stance.name
}

output "function_app_id" {
  description = "ID of the Function App"
  value       = azurerm_linux_function_app.stance.id
}

output "function_app_url" {
  description = "URL of the Function App"
  value       = "https://${azurerm_linux_function_app.stance.default_hostname}"
}

output "application_insights_key" {
  description = "Instrumentation key for Application Insights"
  value       = azurerm_application_insights.stance.instrumentation_key
  sensitive   = true
}

output "service_plan_id" {
  description = "ID of the App Service Plan"
  value       = azurerm_service_plan.stance.id
}
