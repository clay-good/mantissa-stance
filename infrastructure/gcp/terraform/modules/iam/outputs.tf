# Outputs for GCP IAM Module

output "service_account_email" {
  description = "Email of the Stance service account"
  value       = google_service_account.stance.email
}

output "service_account_id" {
  description = "ID of the Stance service account"
  value       = google_service_account.stance.id
}

output "service_account_name" {
  description = "Fully qualified name of the service account"
  value       = google_service_account.stance.name
}

output "collector_role_id" {
  description = "ID of the custom collector role"
  value       = google_project_iam_custom_role.stance_collector.id
}
