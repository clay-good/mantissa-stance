# Variables for Mantissa Stance Azure infrastructure

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "eastus"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "enable_scheduled_scans" {
  description = "Enable scheduled security scans"
  type        = bool
  default     = true
}

variable "scan_schedule" {
  description = "CRON schedule for security scans (Azure Timer Trigger format)"
  type        = string
  default     = "0 0 * * * *" # Every hour
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

variable "enable_synapse" {
  description = "Enable Azure Synapse for analytics"
  type        = bool
  default     = false # Synapse is expensive, disabled by default
}

variable "synapse_sql_admin_login" {
  description = "SQL administrator login for Synapse"
  type        = string
  default     = "sqladmin"
}

variable "synapse_sql_admin_password" {
  description = "SQL administrator password for Synapse"
  type        = string
  sensitive   = true
  default     = null
}

variable "deploy_synapse_sql_objects" {
  description = "Deploy SQL database objects to Synapse via Azure CLI"
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = null
}

variable "enable_alerts" {
  description = "Enable Azure Monitor alert rules"
  type        = bool
  default     = true
}

variable "no_activity_threshold_hours" {
  description = "Hours without scan activity before alerting"
  type        = number
  default     = 25
}
