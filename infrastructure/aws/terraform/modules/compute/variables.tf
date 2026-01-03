# Mantissa Stance - Compute Module Variables

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name for data storage"
  type        = string
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name for state management"
  type        = string
}

variable "lambda_role_arn" {
  description = "IAM role ARN for Lambda functions"
  type        = string
}

variable "lambda_package_path" {
  description = "Path to the Lambda deployment package"
  type        = string
  default     = "lambda.zip"
}

variable "lambda_package_hash" {
  description = "Base64-encoded SHA256 hash of the deployment package"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "log_level" {
  description = "Logging level for Lambda functions"
  type        = string
  default     = "INFO"
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}
