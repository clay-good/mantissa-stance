# Variables for GCP IAM Module

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "storage_bucket" {
  description = "Name of the Cloud Storage bucket for Stance data"
  type        = string
}

variable "bigquery_dataset" {
  description = "ID of the BigQuery dataset for Stance data"
  type        = string
  default     = null
}
