# Outputs for Azure Catalog Module

output "synapse_workspace_id" {
  description = "ID of the Synapse workspace"
  value       = azurerm_synapse_workspace.stance.id
}

output "synapse_workspace_name" {
  description = "Name of the Synapse workspace"
  value       = azurerm_synapse_workspace.stance.name
}

output "synapse_sql_endpoint" {
  description = "Synapse serverless SQL endpoint"
  value       = azurerm_synapse_workspace.stance.connectivity_endpoints["sqlOnDemand"]
}

output "synapse_dev_endpoint" {
  description = "Synapse development endpoint"
  value       = azurerm_synapse_workspace.stance.connectivity_endpoints["dev"]
}

output "data_lake_filesystem_id" {
  description = "ID of the Data Lake Gen2 filesystem"
  value       = azurerm_storage_data_lake_gen2_filesystem.stance.id
}

output "synapse_identity_principal_id" {
  description = "Principal ID of the Synapse workspace managed identity"
  value       = azurerm_synapse_workspace.stance.identity[0].principal_id
}

output "synapse_identity_tenant_id" {
  description = "Tenant ID of the Synapse workspace managed identity"
  value       = azurerm_synapse_workspace.stance.identity[0].tenant_id
}
