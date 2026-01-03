# Mantissa Stance - Storage Module Variables

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "bucket_name" {
  description = "Name for the S3 bucket"
  type        = string
}

variable "retention_days" {
  description = "Number of days to retain data before expiration"
  type        = number
  default     = 90
}

variable "enable_athena" {
  description = "Enable Athena workgroup and Glue catalog for querying"
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
