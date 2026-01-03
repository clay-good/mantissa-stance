# Mantissa Stance - AWS Infrastructure
#
# This Terraform configuration deploys the Stance CSPM tool
# as a serverless application on AWS.
#
# Components:
# - S3 bucket for asset and finding storage
# - DynamoDB table for state management
# - Lambda functions for collection and evaluation
# - EventBridge rules for scheduled scans
# - IAM roles with minimal read-only permissions

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

locals {
  # Common tags applied to all resources
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  # Resource naming prefix
  name_prefix = "${var.project_name}-${var.environment}"
}

# Storage module - S3 bucket and DynamoDB table
module "storage" {
  source = "./modules/storage"

  project_name   = var.project_name
  environment    = var.environment
  bucket_name    = var.s3_bucket_name != "" ? var.s3_bucket_name : "${local.name_prefix}-data"
  retention_days = var.retention_days
  enable_athena  = var.enable_athena
}

# IAM module - roles and policies for Lambda functions
module "iam" {
  source = "./modules/iam"

  project_name       = var.project_name
  environment        = var.environment
  s3_bucket_arn      = module.storage.bucket_arn
  dynamodb_table_arn = module.storage.dynamodb_table_arn
}

# Compute module - Lambda functions
module "compute" {
  source = "./modules/compute"

  project_name        = var.project_name
  environment         = var.environment
  s3_bucket_name      = module.storage.bucket_name
  dynamodb_table_name = module.storage.dynamodb_table_name
  lambda_role_arn     = module.iam.lambda_role_arn
  log_retention_days  = var.log_retention_days
}

# Scheduling module - EventBridge rules for automated scans
module "scheduling" {
  source = "./modules/scheduling"

  project_name           = var.project_name
  environment            = var.environment
  enable_scheduled_scans = var.enable_scheduled_scans
  scan_schedule          = var.scan_schedule
  collector_function_arn = module.compute.collector_function_arn
  enable_notifications   = var.enable_notifications
}
