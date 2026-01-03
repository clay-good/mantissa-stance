# Outputs for GCP Monitoring Module

output "dashboard_id" {
  description = "The ID of the Cloud Monitoring dashboard"
  value       = google_monitoring_dashboard.stance.id
}

output "dashboard_name" {
  description = "The display name of the dashboard"
  value       = "Mantissa Stance Security Dashboard"
}

output "notification_channel_id" {
  description = "The ID of the email notification channel"
  value       = var.notification_email != null ? google_monitoring_notification_channel.email[0].id : null
}

output "alert_policy_scan_failure_id" {
  description = "The ID of the scan failure alert policy"
  value       = google_monitoring_alert_policy.scan_failure.id
}

output "alert_policy_critical_findings_id" {
  description = "The ID of the critical findings alert policy"
  value       = google_monitoring_alert_policy.critical_findings.id
}

output "alert_policy_no_activity_id" {
  description = "The ID of the no activity alert policy"
  value       = google_monitoring_alert_policy.no_scan_activity.id
}

output "log_metric_scan_executions" {
  description = "Name of the scan executions log metric"
  value       = google_logging_metric.scan_executions.name
}

output "log_metric_scan_failures" {
  description = "Name of the scan failures log metric"
  value       = google_logging_metric.scan_failures.name
}

output "log_metric_findings_generated" {
  description = "Name of the findings generated log metric"
  value       = google_logging_metric.findings_generated.name
}

output "log_metric_critical_findings" {
  description = "Name of the critical findings log metric"
  value       = google_logging_metric.critical_findings.name
}
