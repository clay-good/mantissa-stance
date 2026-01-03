# Variables for Azure Monitoring Module

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

variable "notification_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = null
}

variable "enable_alerts" {
  description = "Whether to enable alert rules"
  type        = bool
  default     = true
}

variable "function_app_id" {
  description = "ID of the Azure Function App for monitoring"
  type        = string
  default     = null
}

variable "no_activity_threshold_hours" {
  description = "Hours without scan activity before alerting"
  type        = number
  default     = 25
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
