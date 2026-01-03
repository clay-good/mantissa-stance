# Variables for Mantissa Stance GCP infrastructure

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
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
  description = "Cron schedule for security scans (Cloud Scheduler format)"
  type        = string
  default     = "0 * * * *" # Every hour
}

variable "log_retention_days" {
  description = "Number of days to retain logs"
  type        = number
  default     = 30
}

variable "enable_bigquery" {
  description = "Enable BigQuery dataset for analytics"
  type        = bool
  default     = true
}

variable "enable_scheduled_queries" {
  description = "Enable scheduled queries for data aggregation"
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = null
}

variable "enable_alerts" {
  description = "Enable Cloud Monitoring alert policies"
  type        = bool
  default     = true
}

variable "scan_failure_threshold" {
  description = "Number of scan failures to trigger alert"
  type        = number
  default     = 1
}

variable "no_activity_threshold_hours" {
  description = "Hours without scan activity before alerting"
  type        = number
  default     = 25
}
