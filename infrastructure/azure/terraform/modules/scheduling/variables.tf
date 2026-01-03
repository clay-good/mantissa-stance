# Azure Scheduling Module Variables

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region"
  type        = string
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "enable_notifications" {
  description = "Enable Event Grid notifications"
  type        = bool
  default     = true
}

variable "notification_webhook_url" {
  description = "Webhook URL for notifications"
  type        = string
  default     = ""
}

variable "notification_function_id" {
  description = "Azure Function ID for notifications"
  type        = string
  default     = ""
}

variable "alert_email_addresses" {
  description = "Email addresses for alert notifications"
  type        = list(string)
  default     = []
}

variable "alert_webhook_url" {
  description = "Webhook URL for Azure Monitor alerts"
  type        = string
  default     = ""
}

variable "function_app_id" {
  description = "Function App ID for metric alerts"
  type        = string
  default     = ""
}
