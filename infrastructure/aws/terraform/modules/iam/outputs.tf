# Mantissa Stance - IAM Module Outputs

output "lambda_role_arn" {
  description = "ARN of the Lambda execution role"
  value       = aws_iam_role.lambda.arn
}

output "lambda_role_name" {
  description = "Name of the Lambda execution role"
  value       = aws_iam_role.lambda.name
}

output "collector_iam_policy_arn" {
  description = "ARN of the IAM collector policy"
  value       = aws_iam_policy.collector_iam.arn
}

output "collector_s3_policy_arn" {
  description = "ARN of the S3 collector policy"
  value       = aws_iam_policy.collector_s3.arn
}

output "collector_ec2_policy_arn" {
  description = "ARN of the EC2 collector policy"
  value       = aws_iam_policy.collector_ec2.arn
}

output "collector_security_policy_arn" {
  description = "ARN of the security services collector policy"
  value       = aws_iam_policy.collector_security.arn
}

output "storage_policy_arn" {
  description = "ARN of the storage access policy"
  value       = aws_iam_policy.storage.arn
}
