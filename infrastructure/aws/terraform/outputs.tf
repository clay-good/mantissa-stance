# Mantissa Stance - Terraform Outputs

output "s3_bucket_name" {
  description = "Name of the S3 bucket for data storage"
  value       = module.storage.bucket_name
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = module.storage.bucket_arn
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB state table"
  value       = module.storage.dynamodb_table_name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB state table"
  value       = module.storage.dynamodb_table_arn
}

output "collector_function_arn" {
  description = "ARN of the collector Lambda function"
  value       = module.compute.collector_function_arn
}

output "evaluator_function_arn" {
  description = "ARN of the evaluator Lambda function"
  value       = module.compute.evaluator_function_arn
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup (if enabled)"
  value       = module.storage.athena_workgroup_name
}

output "scan_schedule_rule_arn" {
  description = "ARN of the EventBridge rule for scheduled scans"
  value       = module.scheduling.scan_schedule_rule_arn
}
