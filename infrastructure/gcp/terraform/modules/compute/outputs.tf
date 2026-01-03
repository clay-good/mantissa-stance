# Outputs for GCP Compute Module

output "collector_function_url" {
  description = "URL of the collector Cloud Function"
  value       = google_cloudfunctions2_function.collector.url
}

output "collector_function_name" {
  description = "Name of the collector Cloud Function"
  value       = google_cloudfunctions2_function.collector.name
}

output "evaluator_function_url" {
  description = "URL of the evaluator Cloud Function"
  value       = google_cloudfunctions2_function.evaluator.url
}

output "evaluator_function_name" {
  description = "Name of the evaluator Cloud Function"
  value       = google_cloudfunctions2_function.evaluator.name
}

output "scheduler_job_name" {
  description = "Name of the Cloud Scheduler job"
  value       = var.enable_scheduled_scans ? google_cloud_scheduler_job.stance_scan[0].name : null
}

output "functions_source_bucket" {
  description = "Name of the bucket containing function source"
  value       = google_storage_bucket.functions_source.name
}
