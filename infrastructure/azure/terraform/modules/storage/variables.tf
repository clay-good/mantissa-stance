# Variables for Azure Storage Module

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

variable "retention_days" {
  description = "Number of days to retain data"
  type        = number
  default     = 90
}

variable "enable_synapse" {
  description = "Enable Azure Synapse workspace"
  type        = bool
  default     = false
}
