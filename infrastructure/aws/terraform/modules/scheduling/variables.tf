# Mantissa Stance - Scheduling Module Variables

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "enable_scheduled_scans" {
  description = "Enable scheduled scan runs"
  type        = bool
  default     = true
}

variable "scan_schedule" {
  description = "Schedule expression for scans (rate or cron)"
  type        = string
  default     = "rate(1 hour)"
}

variable "collector_function_arn" {
  description = "ARN of the collector Lambda function"
  type        = string
}

variable "enable_notifications" {
  description = "Enable SNS notifications for findings"
  type        = bool
  default     = false
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
