# Mantissa Stance - Compute Module
#
# Creates Lambda functions for collection and evaluation.

# Data source for current AWS account
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# CloudWatch Log Group for collector
resource "aws_cloudwatch_log_group" "collector" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-collector"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-collector-logs"
  }
}

# CloudWatch Log Group for evaluator
resource "aws_cloudwatch_log_group" "evaluator" {
  name              = "/aws/lambda/${var.project_name}-${var.environment}-evaluator"
  retention_in_days = var.log_retention_days

  tags = {
    Name = "${var.project_name}-${var.environment}-evaluator-logs"
  }
}

# Lambda function for collector
resource "aws_lambda_function" "collector" {
  function_name = "${var.project_name}-${var.environment}-collector"
  description   = "Mantissa Stance - Cloud resource collector"

  runtime       = "python3.11"
  handler       = "handler.collect"
  memory_size   = 256
  timeout       = 300

  role = var.lambda_role_arn

  # Placeholder for deployment package
  filename         = var.lambda_package_path
  source_code_hash = var.lambda_package_hash

  environment {
    variables = {
      S3_BUCKET       = var.s3_bucket_name
      DYNAMODB_TABLE  = var.dynamodb_table_name
      LOG_LEVEL       = var.log_level
      ENVIRONMENT     = var.environment
    }
  }

  depends_on = [aws_cloudwatch_log_group.collector]

  tags = {
    Name = "${var.project_name}-${var.environment}-collector"
  }
}

# Lambda function for evaluator
resource "aws_lambda_function" "evaluator" {
  function_name = "${var.project_name}-${var.environment}-evaluator"
  description   = "Mantissa Stance - Policy evaluator"

  runtime       = "python3.11"
  handler       = "handler.evaluate"
  memory_size   = 512
  timeout       = 300

  role = var.lambda_role_arn

  # Placeholder for deployment package
  filename         = var.lambda_package_path
  source_code_hash = var.lambda_package_hash

  environment {
    variables = {
      S3_BUCKET       = var.s3_bucket_name
      DYNAMODB_TABLE  = var.dynamodb_table_name
      LOG_LEVEL       = var.log_level
      ENVIRONMENT     = var.environment
    }
  }

  depends_on = [aws_cloudwatch_log_group.evaluator]

  tags = {
    Name = "${var.project_name}-${var.environment}-evaluator"
  }
}

# Permission for EventBridge to invoke collector
# Uses account-level wildcard to avoid circular dependency with scheduling module
resource "aws_lambda_permission" "collector_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/${var.project_name}-${var.environment}-*"
}

# Permission for collector to invoke evaluator
resource "aws_lambda_permission" "evaluator_lambda" {
  statement_id  = "AllowLambdaInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evaluator.function_name
  principal     = "lambda.amazonaws.com"
  source_arn    = aws_lambda_function.collector.arn
}
