# Variables for GCP Monitoring Module

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "notification_email" {
  description = "Email address for alert notifications"
  type        = string
  default     = null
}

variable "enable_alerts" {
  description = "Whether to enable alert policies"
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

variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default     = {}
}
