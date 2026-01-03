# Mantissa Stance - Storage Module
#
# Creates S3 bucket and DynamoDB table for storing
# assets, findings, and state management.

# S3 Bucket for data storage
resource "aws_s3_bucket" "data" {
  bucket = var.bucket_name

  tags = {
    Name = var.bucket_name
  }
}

# Enable versioning for data protection
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption with S3-managed keys
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle rules for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.retention_days
    }

    filter {
      prefix = ""
    }
  }
}

# DynamoDB table for state management
resource "aws_dynamodb_table" "state" {
  name         = "${var.project_name}-${var.environment}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  # Enable server-side encryption
  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-state"
  }
}

# Athena workgroup for querying data
resource "aws_athena_workgroup" "main" {
  count = var.enable_athena ? 1 : 0

  name = "${var.project_name}-${var.environment}"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.data.bucket}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = {
    Name = "${var.project_name}-${var.environment}-athena"
  }
}

# Glue database for table definitions
resource "aws_glue_catalog_database" "main" {
  count = var.enable_athena ? 1 : 0

  name = replace("${var.project_name}_${var.environment}", "-", "_")

  description = "Database for Mantissa Stance posture data"
}

# Glue table for assets
resource "aws_glue_catalog_table" "assets" {
  count = var.enable_athena ? 1 : 0

  name          = "assets"
  database_name = aws_glue_catalog_database.main[0].name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "json"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.data.bucket}/assets/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "id"
      type = "string"
    }
    columns {
      name = "cloud_provider"
      type = "string"
    }
    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "region"
      type = "string"
    }
    columns {
      name = "resource_type"
      type = "string"
    }
    columns {
      name = "name"
      type = "string"
    }
    columns {
      name = "network_exposure"
      type = "string"
    }
    columns {
      name = "tags"
      type = "map<string,string>"
    }
  }

  partition_keys {
    name = "snapshot_id"
    type = "string"
  }
}

# Glue table for findings
resource "aws_glue_catalog_table" "findings" {
  count = var.enable_athena ? 1 : 0

  name          = "findings"
  database_name = aws_glue_catalog_database.main[0].name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification" = "json"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.data.bucket}/findings/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "id"
      type = "string"
    }
    columns {
      name = "asset_id"
      type = "string"
    }
    columns {
      name = "finding_type"
      type = "string"
    }
    columns {
      name = "severity"
      type = "string"
    }
    columns {
      name = "status"
      type = "string"
    }
    columns {
      name = "title"
      type = "string"
    }
    columns {
      name = "description"
      type = "string"
    }
    columns {
      name = "rule_id"
      type = "string"
    }
    columns {
      name = "cve_id"
      type = "string"
    }
    columns {
      name = "cvss_score"
      type = "double"
    }
  }

  partition_keys {
    name = "snapshot_id"
    type = "string"
  }
}
