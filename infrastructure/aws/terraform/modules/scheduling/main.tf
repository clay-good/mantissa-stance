# Mantissa Stance - Scheduling Module
#
# Creates EventBridge rules for scheduled scans.

# EventBridge rule for scheduled scans
resource "aws_cloudwatch_event_rule" "scan_schedule" {
  count = var.enable_scheduled_scans ? 1 : 0

  name                = "${var.project_name}-${var.environment}-scan-schedule"
  description         = "Trigger Stance collector on schedule"
  schedule_expression = var.scan_schedule

  tags = {
    Name = "${var.project_name}-${var.environment}-scan-schedule"
  }
}

# EventBridge target - invoke collector Lambda
resource "aws_cloudwatch_event_target" "collector" {
  count = var.enable_scheduled_scans ? 1 : 0

  rule      = aws_cloudwatch_event_rule.scan_schedule[0].name
  target_id = "StanceCollector"
  arn       = var.collector_function_arn

  input = jsonencode({
    source      = "scheduled"
    environment = var.environment
    full_scan   = true
  })
}

# EventBridge rule for on-demand scans via API
resource "aws_cloudwatch_event_rule" "on_demand" {
  name        = "${var.project_name}-${var.environment}-on-demand"
  description = "Trigger Stance collector on demand"

  event_pattern = jsonencode({
    source      = ["stance.trigger"]
    detail-type = ["Scan Request"]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-on-demand"
  }
}

# EventBridge target for on-demand scans
resource "aws_cloudwatch_event_target" "on_demand" {
  rule      = aws_cloudwatch_event_rule.on_demand.name
  target_id = "StanceCollectorOnDemand"
  arn       = var.collector_function_arn
}

# SNS topic for scan notifications (optional)
resource "aws_sns_topic" "scan_notifications" {
  count = var.enable_notifications ? 1 : 0

  name = "${var.project_name}-${var.environment}-notifications"

  tags = {
    Name = "${var.project_name}-${var.environment}-notifications"
  }
}

# SNS topic policy
resource "aws_sns_topic_policy" "scan_notifications" {
  count = var.enable_notifications ? 1 : 0

  arn = aws_sns_topic.scan_notifications[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.scan_notifications[0].arn
      }
    ]
  })
}

# EventBridge rule for critical findings alerts
resource "aws_cloudwatch_event_rule" "critical_findings" {
  count = var.enable_notifications ? 1 : 0

  name        = "${var.project_name}-${var.environment}-critical-findings"
  description = "Alert on critical security findings"

  event_pattern = jsonencode({
    source      = ["stance.evaluator"]
    detail-type = ["Finding Generated"]
    detail = {
      severity = ["critical"]
    }
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-critical-findings"
  }
}

# EventBridge target for critical findings - send to SNS
resource "aws_cloudwatch_event_target" "critical_findings_sns" {
  count = var.enable_notifications ? 1 : 0

  rule      = aws_cloudwatch_event_rule.critical_findings[0].name
  target_id = "CriticalFindingsSNS"
  arn       = aws_sns_topic.scan_notifications[0].arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      title       = "$.detail.title"
      asset_id    = "$.detail.asset_id"
      description = "$.detail.description"
    }
    input_template = "\"[Stance Alert] <severity> finding: <title> on <asset_id>. <description>\""
  }
}
