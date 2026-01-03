# Variables for Azure Compute Module

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "storage_account_name" {
  description = "Name of the storage account for Stance data"
  type        = string
}

variable "storage_container" {
  description = "Name of the container for Stance data"
  type        = string
}

variable "managed_identity_id" {
  description = "ID of the managed identity for the function app"
  type        = string
}

variable "managed_identity_client_id" {
  description = "Client ID of the managed identity"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

variable "enable_scheduled_scans" {
  description = "Enable scheduled security scans"
  type        = bool
  default     = true
}

variable "scan_schedule" {
  description = "CRON schedule for security scans"
  type        = string
  default     = "0 0 * * * *"
}
