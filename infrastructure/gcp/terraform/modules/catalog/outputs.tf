# Outputs for GCP Catalog Module

output "assets_table_id" {
  description = "Full table ID for assets table"
  value       = google_bigquery_table.assets.id
}

output "assets_table_name" {
  description = "Table name for assets"
  value       = google_bigquery_table.assets.table_id
}

output "findings_table_id" {
  description = "Full table ID for findings table"
  value       = google_bigquery_table.findings.id
}

output "findings_table_name" {
  description = "Table name for findings"
  value       = google_bigquery_table.findings.table_id
}

output "compliance_summary_view_id" {
  description = "Full view ID for compliance summary"
  value       = google_bigquery_table.compliance_summary_view.id
}

output "asset_inventory_view_id" {
  description = "Full view ID for asset inventory"
  value       = google_bigquery_table.asset_inventory_view.id
}

output "severity_trend_view_id" {
  description = "Full view ID for severity trend"
  value       = google_bigquery_table.severity_trend_view.id
}

output "exposed_assets_view_id" {
  description = "Full view ID for exposed assets"
  value       = google_bigquery_table.exposed_assets_view.id
}

output "daily_summary_table_id" {
  description = "Full table ID for daily summary (if enabled)"
  value       = var.enable_scheduled_queries ? google_bigquery_table.daily_summary[0].id : null
}

output "daily_aggregation_transfer_id" {
  description = "Data transfer config ID for daily aggregation (if enabled)"
  value       = var.enable_scheduled_queries ? google_bigquery_data_transfer_config.daily_aggregation[0].id : null
}
