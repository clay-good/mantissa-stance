# GCP Monitoring Module for Mantissa Stance
#
# Creates Cloud Monitoring dashboard, alert policies for scan failures,
# and log-based metrics for observability.

# Notification channel for alerts
resource "google_monitoring_notification_channel" "email" {
  count = var.notification_email != null ? 1 : 0

  display_name = "stance-email-notifications"
  project      = var.project_id
  type         = "email"

  labels = {
    email_address = var.notification_email
  }
}

# Log-based metric for scan executions
resource "google_logging_metric" "scan_executions" {
  project     = var.project_id
  name        = "stance/scan_executions"
  description = "Count of Stance scan executions"

  filter = <<-EOT
    resource.type="cloud_function"
    AND resource.labels.function_name=~"stance-.*"
    AND textPayload=~"Scan (started|completed)"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "status"
      value_type  = "STRING"
      description = "Scan status (started, completed, failed)"
    }
  }

  label_extractors = {
    "status" = "REGEXP_EXTRACT(textPayload, \"Scan (started|completed|failed)\")"
  }
}

# Log-based metric for scan failures
resource "google_logging_metric" "scan_failures" {
  project     = var.project_id
  name        = "stance/scan_failures"
  description = "Count of Stance scan failures"

  filter = <<-EOT
    resource.type="cloud_function"
    AND resource.labels.function_name=~"stance-.*"
    AND severity>=ERROR
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Log-based metric for findings generated
resource "google_logging_metric" "findings_generated" {
  project     = var.project_id
  name        = "stance/findings_generated"
  description = "Count of security findings generated"

  filter = <<-EOT
    resource.type="cloud_function"
    AND resource.labels.function_name=~"stance-.*"
    AND jsonPayload.event="finding_generated"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "severity"
      value_type  = "STRING"
      description = "Finding severity level"
    }
  }

  label_extractors = {
    "severity" = "EXTRACT(jsonPayload.severity)"
  }
}

# Log-based metric for critical findings
resource "google_logging_metric" "critical_findings" {
  project     = var.project_id
  name        = "stance/critical_findings"
  description = "Count of critical severity findings"

  filter = <<-EOT
    resource.type="cloud_function"
    AND resource.labels.function_name=~"stance-.*"
    AND jsonPayload.event="finding_generated"
    AND jsonPayload.severity="critical"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy for scan failures
resource "google_monitoring_alert_policy" "scan_failure" {
  project      = var.project_id
  display_name = "Stance Scan Failure"
  combiner     = "OR"
  enabled      = var.enable_alerts

  conditions {
    display_name = "Scan failure rate exceeded"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/stance/scan_failures\" AND resource.type=\"cloud_function\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.scan_failure_threshold
      duration        = "300s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = var.notification_email != null ? [google_monitoring_notification_channel.email[0].id] : []

  alert_strategy {
    auto_close = "604800s"
  }

  documentation {
    content   = "Stance security scan failure rate has exceeded the threshold. Please check Cloud Functions logs for details."
    mime_type = "text/markdown"
  }
}

# Alert policy for critical findings
resource "google_monitoring_alert_policy" "critical_findings" {
  project      = var.project_id
  display_name = "Stance Critical Findings Detected"
  combiner     = "OR"
  enabled      = var.enable_alerts

  conditions {
    display_name = "Critical findings detected"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/stance/critical_findings\" AND resource.type=\"cloud_function\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  notification_channels = var.notification_email != null ? [google_monitoring_notification_channel.email[0].id] : []

  alert_strategy {
    auto_close = "604800s"
  }

  documentation {
    content   = "Critical security findings have been detected. Immediate attention required."
    mime_type = "text/markdown"
  }
}

# Alert policy for no scan activity
resource "google_monitoring_alert_policy" "no_scan_activity" {
  project      = var.project_id
  display_name = "Stance No Scan Activity"
  combiner     = "OR"
  enabled      = var.enable_alerts

  conditions {
    display_name = "No scan activity detected"

    condition_absent {
      filter   = "metric.type=\"logging.googleapis.com/user/stance/scan_executions\" AND resource.type=\"cloud_function\""
      duration = "${var.no_activity_threshold_hours * 3600}s"

      aggregations {
        alignment_period   = "3600s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  notification_channels = var.notification_email != null ? [google_monitoring_notification_channel.email[0].id] : []

  alert_strategy {
    auto_close = "604800s"
  }

  documentation {
    content   = "No Stance scan activity has been detected in the expected timeframe. Please verify scheduled scans are running."
    mime_type = "text/markdown"
  }
}

# Cloud Monitoring Dashboard
resource "google_monitoring_dashboard" "stance" {
  project        = var.project_id
  dashboard_json = jsonencode({
    displayName = "Mantissa Stance Security Dashboard"
    labels = {
      stance = ""
    }
    mosaicLayout = {
      columns = 12
      tiles = [
        # Row 1: Overview metrics
        {
          width  = 4
          height = 4
          widget = {
            title = "Scan Executions (24h)"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"logging.googleapis.com/user/stance/scan_executions\" resource.type=\"cloud_function\""
                  aggregation = {
                    alignmentPeriod  = "86400s"
                    perSeriesAligner = "ALIGN_SUM"
                  }
                }
              }
            }
          }
        },
        {
          xPos   = 4
          width  = 4
          height = 4
          widget = {
            title = "Scan Failures (24h)"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"logging.googleapis.com/user/stance/scan_failures\" resource.type=\"cloud_function\""
                  aggregation = {
                    alignmentPeriod  = "86400s"
                    perSeriesAligner = "ALIGN_SUM"
                  }
                }
              }
              thresholds = [
                {
                  color = "RED"
                  value = 1
                }
              ]
            }
          }
        },
        {
          xPos   = 8
          width  = 4
          height = 4
          widget = {
            title = "Critical Findings (24h)"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"logging.googleapis.com/user/stance/critical_findings\" resource.type=\"cloud_function\""
                  aggregation = {
                    alignmentPeriod  = "86400s"
                    perSeriesAligner = "ALIGN_SUM"
                  }
                }
              }
              thresholds = [
                {
                  color = "RED"
                  value = 1
                }
              ]
            }
          }
        },
        # Row 2: Scan activity chart
        {
          yPos   = 4
          width  = 12
          height = 4
          widget = {
            title = "Scan Activity Over Time"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/stance/scan_executions\" resource.type=\"cloud_function\""
                      aggregation = {
                        alignmentPeriod    = "3600s"
                        perSeriesAligner   = "ALIGN_SUM"
                        crossSeriesReducer = "REDUCE_SUM"
                      }
                    }
                  }
                  plotType   = "LINE"
                  legendTemplate = "Scans"
                }
              ]
              yAxis = {
                scale = "LINEAR"
              }
            }
          }
        },
        # Row 3: Findings by severity
        {
          yPos   = 8
          width  = 6
          height = 4
          widget = {
            title = "Findings by Severity"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/stance/findings_generated\" resource.type=\"cloud_function\""
                      aggregation = {
                        alignmentPeriod    = "3600s"
                        perSeriesAligner   = "ALIGN_SUM"
                        crossSeriesReducer = "REDUCE_SUM"
                        groupByFields      = ["metric.label.severity"]
                      }
                    }
                  }
                  plotType = "STACKED_BAR"
                }
              ]
              yAxis = {
                scale = "LINEAR"
              }
            }
          }
        },
        # Row 3: Failure rate
        {
          xPos   = 6
          yPos   = 8
          width  = 6
          height = 4
          widget = {
            title = "Scan Failure Rate"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"logging.googleapis.com/user/stance/scan_failures\" resource.type=\"cloud_function\""
                      aggregation = {
                        alignmentPeriod  = "3600s"
                        perSeriesAligner = "ALIGN_RATE"
                      }
                    }
                  }
                  plotType   = "LINE"
                  legendTemplate = "Failure Rate"
                }
              ]
              yAxis = {
                scale = "LINEAR"
              }
              thresholds = [
                {
                  value     = var.scan_failure_threshold
                  color     = "RED"
                  direction = "ABOVE"
                }
              ]
            }
          }
        },
        # Row 4: Cloud Function execution times
        {
          yPos   = 12
          width  = 12
          height = 4
          widget = {
            title = "Cloud Function Execution Times"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"cloudfunctions.googleapis.com/function/execution_times\" resource.type=\"cloud_function\" resource.labels.function_name=monitoring.regex.full_match(\"stance-.*\")"
                      aggregation = {
                        alignmentPeriod    = "300s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_99"
                        crossSeriesReducer = "REDUCE_MEAN"
                        groupByFields      = ["resource.labels.function_name"]
                      }
                    }
                  }
                  plotType = "LINE"
                }
              ]
              yAxis = {
                scale = "LINEAR"
                label = "Execution Time (ns)"
              }
            }
          }
        }
      ]
    }
  })
}
