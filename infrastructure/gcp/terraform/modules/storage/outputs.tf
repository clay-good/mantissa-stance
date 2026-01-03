# Outputs for GCP Storage Module

output "bucket_name" {
  description = "Name of the Cloud Storage bucket"
  value       = google_storage_bucket.stance.name
}

output "bucket_url" {
  description = "URL of the Cloud Storage bucket"
  value       = google_storage_bucket.stance.url
}

output "bucket_self_link" {
  description = "Self link of the bucket"
  value       = google_storage_bucket.stance.self_link
}

output "bigquery_dataset_id" {
  description = "ID of the BigQuery dataset"
  value       = var.enable_bigquery ? google_bigquery_dataset.stance[0].dataset_id : null
}

output "bigquery_dataset_self_link" {
  description = "Self link of the BigQuery dataset"
  value       = var.enable_bigquery ? google_bigquery_dataset.stance[0].self_link : null
}
