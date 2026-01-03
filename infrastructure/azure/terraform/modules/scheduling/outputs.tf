# Azure Scheduling Module Outputs

output "event_grid_topic_id" {
  description = "Event Grid topic ID"
  value       = azurerm_eventgrid_topic.stance.id
}

output "event_grid_topic_endpoint" {
  description = "Event Grid topic endpoint"
  value       = azurerm_eventgrid_topic.stance.endpoint
}

output "event_grid_topic_key" {
  description = "Event Grid topic primary access key"
  value       = azurerm_eventgrid_topic.stance.primary_access_key
  sensitive   = true
}

output "action_group_id" {
  description = "Monitor action group ID"
  value       = var.enable_notifications ? azurerm_monitor_action_group.stance[0].id : ""
}
