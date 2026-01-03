# Mantissa Stance - Scheduling Module Outputs

output "scan_schedule_rule_arn" {
  description = "ARN of the scheduled scan EventBridge rule"
  value       = var.enable_scheduled_scans ? aws_cloudwatch_event_rule.scan_schedule[0].arn : null
}

output "scan_schedule_rule_name" {
  description = "Name of the scheduled scan EventBridge rule"
  value       = var.enable_scheduled_scans ? aws_cloudwatch_event_rule.scan_schedule[0].name : null
}

output "on_demand_rule_arn" {
  description = "ARN of the on-demand scan EventBridge rule"
  value       = aws_cloudwatch_event_rule.on_demand.arn
}

output "sns_topic_arn" {
  description = "ARN of the notifications SNS topic (if enabled)"
  value       = var.enable_notifications ? aws_sns_topic.scan_notifications[0].arn : null
}
