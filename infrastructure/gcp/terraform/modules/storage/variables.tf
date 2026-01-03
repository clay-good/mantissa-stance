# Variables for GCP Storage Module

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

variable "retention_days" {
  description = "Number of days to retain data"
  type        = number
  default     = 90
}

variable "enable_bigquery" {
  description = "Enable BigQuery dataset"
  type        = bool
  default     = true
}
