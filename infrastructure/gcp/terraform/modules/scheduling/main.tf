# GCP Scheduling Module for Mantissa Stance
#
# Creates Cloud Scheduler jobs and Pub/Sub topics for
# scheduled scans and notifications.

# Pub/Sub topic for scan events
resource "google_pubsub_topic" "scan_events" {
  name    = "${var.name_prefix}-scan-events"
  project = var.project_id

  labels = var.labels
}

# Pub/Sub topic for findings notifications
resource "google_pubsub_topic" "findings" {
  name    = "${var.name_prefix}-findings"
  project = var.project_id

  labels = var.labels
}

# Dead letter topic for failed messages
resource "google_pubsub_topic" "dead_letter" {
  name    = "${var.name_prefix}-dead-letter"
  project = var.project_id

  labels = var.labels
}

# Subscription for processing critical findings
resource "google_pubsub_subscription" "critical_findings" {
  count = var.enable_notifications ? 1 : 0

  name    = "${var.name_prefix}-critical-findings-sub"
  topic   = google_pubsub_topic.findings.name
  project = var.project_id

  # Filter for critical and high severity findings
  filter = "attributes.severity = \"critical\" OR attributes.severity = \"high\""

  # Push to webhook if configured
  dynamic "push_config" {
    for_each = var.notification_webhook_url != "" ? [1] : []
    content {
      push_endpoint = var.notification_webhook_url

      attributes = {
        x-goog-version = "v1"
      }
    }
  }

  # Dead letter policy
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 5
  }

  # Retry policy
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  ack_deadline_seconds = 20

  labels = var.labels
}

# Subscription for scan completion notifications
resource "google_pubsub_subscription" "scan_complete" {
  count = var.enable_notifications ? 1 : 0

  name    = "${var.name_prefix}-scan-complete-sub"
  topic   = google_pubsub_topic.scan_events.name
  project = var.project_id

  filter = "attributes.event_type = \"scan.completed\" OR attributes.event_type = \"scan.failed\""

  dynamic "push_config" {
    for_each = var.notification_webhook_url != "" ? [1] : []
    content {
      push_endpoint = var.notification_webhook_url
    }
  }

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.dead_letter.id
    max_delivery_attempts = 5
  }

  ack_deadline_seconds = 20

  labels = var.labels
}

# Cloud Monitoring notification channel for email
resource "google_monitoring_notification_channel" "email" {
  for_each = toset(var.alert_email_addresses)

  display_name = "Stance Alert - ${each.value}"
  type         = "email"
  project      = var.project_id

  labels = {
    email_address = each.value
  }
}

# Cloud Monitoring notification channel for webhook
resource "google_monitoring_notification_channel" "webhook" {
  count = var.alert_webhook_url != "" ? 1 : 0

  display_name = "Stance Alert Webhook"
  type         = "webhook_tokenauth"
  project      = var.project_id

  labels = {
    url = var.alert_webhook_url
  }
}

# Alert policy for function errors
resource "google_monitoring_alert_policy" "function_errors" {
  count = var.enable_notifications && var.collector_function_name != "" ? 1 : 0

  display_name = "Stance Function Errors"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Function Execution Errors"

    condition_threshold {
      filter = <<-EOT
        resource.type="cloud_function"
        AND resource.labels.function_name="${var.collector_function_name}"
        AND metric.type="cloudfunctions.googleapis.com/function/execution_count"
        AND metric.labels.status!="ok"
      EOT

      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = concat(
    [for ch in google_monitoring_notification_channel.email : ch.id],
    var.alert_webhook_url != "" ? [google_monitoring_notification_channel.webhook[0].id] : []
  )

  alert_strategy {
    auto_close = "604800s" # 7 days
  }
}

# Alert policy for scan duration
resource "google_monitoring_alert_policy" "scan_duration" {
  count = var.enable_notifications && var.collector_function_name != "" ? 1 : 0

  display_name = "Stance Scan Duration Warning"
  project      = var.project_id
  combiner     = "OR"

  conditions {
    display_name = "Function Execution Duration"

    condition_threshold {
      filter = <<-EOT
        resource.type="cloud_function"
        AND resource.labels.function_name="${var.collector_function_name}"
        AND metric.type="cloudfunctions.googleapis.com/function/execution_times"
      EOT

      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 240000000000 # 240 seconds in nanoseconds

      aggregations {
        alignment_period     = "300s"
        per_series_aligner   = "ALIGN_PERCENTILE_99"
        cross_series_reducer = "REDUCE_MAX"
      }
    }
  }

  notification_channels = concat(
    [for ch in google_monitoring_notification_channel.email : ch.id],
    var.alert_webhook_url != "" ? [google_monitoring_notification_channel.webhook[0].id] : []
  )

  alert_strategy {
    auto_close = "86400s" # 1 day
  }
}
