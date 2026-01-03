# Outputs for Azure IAM Module

output "managed_identity_id" {
  description = "ID of the managed identity"
  value       = azurerm_user_assigned_identity.stance.id
}

output "managed_identity_client_id" {
  description = "Client ID of the managed identity"
  value       = azurerm_user_assigned_identity.stance.client_id
}

output "managed_identity_principal_id" {
  description = "Principal ID of the managed identity"
  value       = azurerm_user_assigned_identity.stance.principal_id
}

output "collector_role_id" {
  description = "ID of the custom collector role"
  value       = azurerm_role_definition.stance_collector.id
}
