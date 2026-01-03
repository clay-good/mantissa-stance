# GCP Compute Module for Mantissa Stance
#
# Creates Cloud Functions for collection and evaluation,
# with Cloud Scheduler for automated scans.

# Cloud Storage bucket for function source code
resource "google_storage_bucket" "functions_source" {
  name     = "${var.name_prefix}-functions-${var.project_id}"
  location = var.region
  project  = var.project_id

  uniform_bucket_level_access = true

  labels = var.labels
}

# Placeholder source archive (will be replaced by CI/CD)
data "archive_file" "function_source" {
  type        = "zip"
  output_path = "${path.module}/function-source.zip"

  source {
    content  = <<-EOF
      def handler(request):
          """Placeholder function - deploy actual code via CI/CD."""
          return "OK", 200
    EOF
    filename = "main.py"
  }

  source {
    content  = "# No dependencies in placeholder"
    filename = "requirements.txt"
  }
}

resource "google_storage_bucket_object" "function_source" {
  name   = "source/stance-${filemd5(data.archive_file.function_source.output_path)}.zip"
  bucket = google_storage_bucket.functions_source.name
  source = data.archive_file.function_source.output_path
}

# Collector Cloud Function
resource "google_cloudfunctions2_function" "collector" {
  name     = "${var.name_prefix}-collector"
  location = var.region
  project  = var.project_id

  build_config {
    runtime     = "python311"
    entry_point = "collect"

    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    min_instance_count    = 0
    available_memory      = "256M"
    timeout_seconds       = 300
    service_account_email = var.service_account_email

    environment_variables = {
      GCS_BUCKET  = var.storage_bucket
      PROJECT_ID  = var.project_id
      LOG_LEVEL   = "INFO"
    }
  }

  labels = var.labels
}

# Evaluator Cloud Function
resource "google_cloudfunctions2_function" "evaluator" {
  name     = "${var.name_prefix}-evaluator"
  location = var.region
  project  = var.project_id

  build_config {
    runtime     = "python311"
    entry_point = "evaluate"

    source {
      storage_source {
        bucket = google_storage_bucket.functions_source.name
        object = google_storage_bucket_object.function_source.name
      }
    }
  }

  service_config {
    max_instance_count    = 1
    min_instance_count    = 0
    available_memory      = "512M"
    timeout_seconds       = 300
    service_account_email = var.service_account_email

    environment_variables = {
      GCS_BUCKET  = var.storage_bucket
      PROJECT_ID  = var.project_id
      LOG_LEVEL   = "INFO"
    }
  }

  labels = var.labels
}

# Cloud Scheduler for automated scans
resource "google_cloud_scheduler_job" "stance_scan" {
  count = var.enable_scheduled_scans ? 1 : 0

  name        = "${var.name_prefix}-scheduled-scan"
  description = "Trigger Stance security scan"
  schedule    = var.scan_schedule
  time_zone   = "UTC"
  project     = var.project_id
  region      = var.region

  http_target {
    http_method = "POST"
    uri         = google_cloudfunctions2_function.collector.url

    oidc_token {
      service_account_email = var.service_account_email
    }
  }

  retry_config {
    retry_count          = 3
    min_backoff_duration = "5s"
    max_backoff_duration = "60s"
  }
}

# Allow Cloud Scheduler to invoke the function
resource "google_cloud_run_service_iam_member" "collector_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloudfunctions2_function.collector.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.service_account_email}"
}

resource "google_cloud_run_service_iam_member" "evaluator_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloudfunctions2_function.evaluator.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${var.service_account_email}"
}
