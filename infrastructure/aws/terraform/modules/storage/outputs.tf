# Mantissa Stance - Storage Module Outputs

output "bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.data.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.data.arn
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB state table"
  value       = aws_dynamodb_table.state.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB state table"
  value       = aws_dynamodb_table.state.arn
}

output "athena_workgroup_name" {
  description = "Name of the Athena workgroup (if enabled)"
  value       = var.enable_athena ? aws_athena_workgroup.main[0].name : null
}

output "glue_database_name" {
  description = "Name of the Glue database (if enabled)"
  value       = var.enable_athena ? aws_glue_catalog_database.main[0].name : null
}
