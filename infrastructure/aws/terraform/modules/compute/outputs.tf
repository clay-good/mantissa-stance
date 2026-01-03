# Mantissa Stance - Compute Module Outputs

output "collector_function_name" {
  description = "Name of the collector Lambda function"
  value       = aws_lambda_function.collector.function_name
}

output "collector_function_arn" {
  description = "ARN of the collector Lambda function"
  value       = aws_lambda_function.collector.arn
}

output "collector_invoke_arn" {
  description = "Invoke ARN of the collector Lambda function"
  value       = aws_lambda_function.collector.invoke_arn
}

output "evaluator_function_name" {
  description = "Name of the evaluator Lambda function"
  value       = aws_lambda_function.evaluator.function_name
}

output "evaluator_function_arn" {
  description = "ARN of the evaluator Lambda function"
  value       = aws_lambda_function.evaluator.arn
}

output "evaluator_invoke_arn" {
  description = "Invoke ARN of the evaluator Lambda function"
  value       = aws_lambda_function.evaluator.invoke_arn
}
