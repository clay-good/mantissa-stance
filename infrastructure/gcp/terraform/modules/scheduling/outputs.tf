# GCP Scheduling Module Outputs

output "scan_events_topic_id" {
  description = "Pub/Sub topic ID for scan events"
  value       = google_pubsub_topic.scan_events.id
}

output "scan_events_topic_name" {
  description = "Pub/Sub topic name for scan events"
  value       = google_pubsub_topic.scan_events.name
}

output "findings_topic_id" {
  description = "Pub/Sub topic ID for findings"
  value       = google_pubsub_topic.findings.id
}

output "findings_topic_name" {
  description = "Pub/Sub topic name for findings"
  value       = google_pubsub_topic.findings.name
}

output "dead_letter_topic_id" {
  description = "Pub/Sub dead letter topic ID"
  value       = google_pubsub_topic.dead_letter.id
}
