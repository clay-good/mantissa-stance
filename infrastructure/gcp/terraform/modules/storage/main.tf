# GCP Storage Module for Mantissa Stance
#
# Creates Cloud Storage bucket for assets/findings and BigQuery dataset
# for analytics queries.

# Cloud Storage bucket for Stance data
resource "google_storage_bucket" "stance" {
  name     = "${var.name_prefix}-data-${var.project_id}"
  location = var.region
  project  = var.project_id

  # Enable versioning for data protection
  versioning {
    enabled = true
  }

  # Lifecycle rules
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = var.retention_days
    }
    action {
      type = "Delete"
    }
  }

  # Enforce uniform bucket-level access (recommended)
  uniform_bucket_level_access = true

  # Labels
  labels = var.labels

  # Prevent accidental deletion in production
  force_destroy = var.labels["environment"] != "prod"
}

# BigQuery dataset for analytics
resource "google_bigquery_dataset" "stance" {
  count = var.enable_bigquery ? 1 : 0

  dataset_id    = replace("${var.name_prefix}_data", "-", "_")
  friendly_name = "Mantissa Stance Data"
  description   = "Security posture and findings data from Mantissa Stance"
  location      = var.region
  project       = var.project_id

  # Default table expiration (optional)
  default_table_expiration_ms = var.retention_days * 24 * 60 * 60 * 1000

  labels = var.labels
}

# BigQuery external table for assets
resource "google_bigquery_table" "assets" {
  count = var.enable_bigquery ? 1 : 0

  dataset_id = google_bigquery_dataset.stance[0].dataset_id
  table_id   = "assets"
  project    = var.project_id

  external_data_configuration {
    autodetect    = true
    source_format = "NEWLINE_DELIMITED_JSON"
    source_uris   = ["gs://${google_storage_bucket.stance.name}/stance/assets/*/assets.jsonl"]
  }

  labels = var.labels
}

# BigQuery external table for findings
resource "google_bigquery_table" "findings" {
  count = var.enable_bigquery ? 1 : 0

  dataset_id = google_bigquery_dataset.stance[0].dataset_id
  table_id   = "findings"
  project    = var.project_id

  external_data_configuration {
    autodetect    = true
    source_format = "NEWLINE_DELIMITED_JSON"
    source_uris   = ["gs://${google_storage_bucket.stance.name}/stance/findings/*/findings.jsonl"]
  }

  labels = var.labels
}
