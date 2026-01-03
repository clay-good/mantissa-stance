# GCP Scheduling Module Variables

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default     = {}
}

variable "enable_notifications" {
  description = "Enable Pub/Sub notifications and alerts"
  type        = bool
  default     = true
}

variable "notification_webhook_url" {
  description = "Webhook URL for push notifications"
  type        = string
  default     = ""
}

variable "alert_email_addresses" {
  description = "Email addresses for alert notifications"
  type        = list(string)
  default     = []
}

variable "alert_webhook_url" {
  description = "Webhook URL for Cloud Monitoring alerts"
  type        = string
  default     = ""
}

variable "collector_function_name" {
  description = "Name of the collector Cloud Function for monitoring"
  type        = string
  default     = ""
}
