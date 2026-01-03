# Outputs for Azure Storage Module

output "storage_account_name" {
  description = "Name of the storage account"
  value       = azurerm_storage_account.stance.name
}

output "storage_account_id" {
  description = "ID of the storage account"
  value       = azurerm_storage_account.stance.id
}

output "storage_account_primary_connection_string" {
  description = "Primary connection string for the storage account"
  value       = azurerm_storage_account.stance.primary_connection_string
  sensitive   = true
}

output "storage_account_primary_blob_endpoint" {
  description = "Primary blob endpoint"
  value       = azurerm_storage_account.stance.primary_blob_endpoint
}

output "data_container_name" {
  description = "Name of the data container"
  value       = azurerm_storage_container.data.name
}

output "functions_container_name" {
  description = "Name of the functions container"
  value       = azurerm_storage_container.functions.name
}
