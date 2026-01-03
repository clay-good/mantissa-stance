# Outputs for Mantissa Stance Azure infrastructure

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.stance.name
}

output "storage_account_name" {
  description = "Name of the storage account"
  value       = module.storage.storage_account_name
}

output "data_container_name" {
  description = "Name of the data container"
  value       = module.storage.data_container_name
}

output "managed_identity_client_id" {
  description = "Client ID of the managed identity"
  value       = module.iam.managed_identity_client_id
}

output "managed_identity_principal_id" {
  description = "Principal ID of the managed identity"
  value       = module.iam.managed_identity_principal_id
}

output "function_app_name" {
  description = "Name of the Function App"
  value       = module.compute.function_app_name
}

output "function_app_url" {
  description = "URL of the Function App"
  value       = module.compute.function_app_url
}
