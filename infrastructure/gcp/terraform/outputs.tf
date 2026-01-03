# Outputs for Mantissa Stance GCP infrastructure

output "storage_bucket_name" {
  description = "Name of the Cloud Storage bucket for Stance data"
  value       = module.storage.bucket_name
}

output "storage_bucket_url" {
  description = "URL of the Cloud Storage bucket"
  value       = module.storage.bucket_url
}

output "bigquery_dataset_id" {
  description = "ID of the BigQuery dataset"
  value       = module.storage.bigquery_dataset_id
}

output "service_account_email" {
  description = "Email of the Stance service account"
  value       = module.iam.service_account_email
}

output "collector_function_url" {
  description = "URL of the collector Cloud Function"
  value       = module.compute.collector_function_url
}

output "evaluator_function_url" {
  description = "URL of the evaluator Cloud Function"
  value       = module.compute.evaluator_function_url
}

output "scheduler_job_name" {
  description = "Name of the Cloud Scheduler job"
  value       = module.compute.scheduler_job_name
}
