# Variables for GCP Catalog Module

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "dataset_id" {
  description = "BigQuery dataset ID for Stance data"
  type        = string
}

variable "location" {
  description = "BigQuery dataset location"
  type        = string
  default     = "US"
}

variable "deletion_protection" {
  description = "Whether to enable deletion protection on tables"
  type        = bool
  default     = true
}

variable "enable_scheduled_queries" {
  description = "Whether to create scheduled queries for aggregations"
  type        = bool
  default     = true
}

variable "service_account_email" {
  description = "Service account email for scheduled queries"
  type        = string
  default     = null
}

variable "labels" {
  description = "Labels to apply to all resources"
  type        = map(string)
  default     = {}
}
