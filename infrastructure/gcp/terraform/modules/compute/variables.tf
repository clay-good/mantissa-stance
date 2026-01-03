# Variables for GCP Compute Module

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default     = {}
}

variable "storage_bucket" {
  description = "Name of the Cloud Storage bucket for Stance data"
  type        = string
}

variable "service_account_email" {
  description = "Email of the service account for Cloud Functions"
  type        = string
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
  description = "Cron schedule for security scans"
  type        = string
  default     = "0 * * * *"
}
