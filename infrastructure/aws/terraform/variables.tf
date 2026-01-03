# Mantissa Stance - Terraform Variables

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
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

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "mantissa-stance"
}

variable "s3_bucket_name" {
  description = "S3 bucket name for data storage. If empty, auto-generated."
  type        = string
  default     = ""
}

variable "retention_days" {
  description = "Number of days to retain data before expiration"
  type        = number
  default     = 90
}

variable "enable_athena" {
  description = "Enable Athena for querying stored data"
  type        = bool
  default     = true
}

variable "enable_scheduled_scans" {
  description = "Enable scheduled scans via EventBridge"
  type        = bool
  default     = true
}

variable "scan_schedule" {
  description = "Schedule expression for automated scans (rate or cron)"
  type        = string
  default     = "rate(1 hour)"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "enable_notifications" {
  description = "Enable SNS notifications for critical findings"
  type        = bool
  default     = false
}
