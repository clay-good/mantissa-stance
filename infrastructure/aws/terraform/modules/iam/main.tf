# Mantissa Stance - IAM Module
#
# Creates IAM roles and policies for Lambda functions.
# All collector policies are READ-ONLY by design.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# IAM role for Lambda functions
resource "aws_iam_role" "lambda" {
  name = "${var.project_name}-${var.environment}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-lambda-role"
  }
}

# Attach basic Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# IAM collector policy - READ ONLY
resource "aws_iam_policy" "collector_iam" {
  name        = "${var.project_name}-${var.environment}-collector-iam"
  description = "Read-only IAM access for Stance collector"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        Action = [
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
          "iam:GetCredentialReport",
          "iam:GenerateCredentialReport",
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:ListUserPolicies",
          "iam:ListAttachedUserPolicies",
          "iam:ListGroupsForUser",
          "iam:ListRoles",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListGroups",
          "iam:ListGroupPolicies",
          "iam:ListAttachedGroupPolicies",
          "iam:GetGroup",
          "iam:ListPolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-collector-iam"
  }
}

# S3 collector policy - READ ONLY
resource "aws_iam_policy" "collector_s3" {
  name        = "${var.project_name}-${var.environment}-collector-s3"
  description = "Read-only S3 access for Stance collector"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketAcl",
          "s3:GetBucketEncryption",
          "s3:GetBucketVersioning",
          "s3:GetBucketLogging",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetAccountPublicAccessBlock",
          "s3:ListAllMyBuckets",
          "s3:ListBucket",
          "s3:GetBucketTagging",
          "s3:GetLifecycleConfiguration",
          "s3:GetReplicationConfiguration"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-collector-s3"
  }
}

# EC2 collector policy - READ ONLY
resource "aws_iam_policy" "collector_ec2" {
  name        = "${var.project_name}-${var.environment}-collector-ec2"
  description = "Read-only EC2 access for Stance collector"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSecurityGroupRules",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeRouteTables",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:DescribeImages",
          "ec2:DescribeAddresses",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-collector-ec2"
  }
}

# Security services collector policy - READ ONLY
resource "aws_iam_policy" "collector_security" {
  name        = "${var.project_name}-${var.environment}-collector-security"
  description = "Read-only access to security services for Stance collector"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecurityHubReadOnly"
        Effect = "Allow"
        Action = [
          "securityhub:GetFindings",
          "securityhub:GetEnabledStandards",
          "securityhub:DescribeHub",
          "securityhub:DescribeStandards",
          "securityhub:DescribeStandardsControls"
        ]
        Resource = "*"
      },
      {
        Sid    = "InspectorReadOnly"
        Effect = "Allow"
        Action = [
          "inspector2:ListFindings",
          "inspector2:ListCoverage",
          "inspector2:GetFindingsReportStatus",
          "inspector2:ListAccountPermissions"
        ]
        Resource = "*"
      },
      {
        Sid    = "GuardDutyReadOnly"
        Effect = "Allow"
        Action = [
          "guardduty:ListFindings",
          "guardduty:GetFindings",
          "guardduty:ListDetectors",
          "guardduty:GetDetector"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-collector-security"
  }
}

# Storage policy for Lambda to read/write data
resource "aws_iam_policy" "storage" {
  name        = "${var.project_name}-${var.environment}-storage"
  description = "S3 and DynamoDB access for Stance data storage"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3DataAccess"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.s3_bucket_arn,
          "${var.s3_bucket_arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          var.dynamodb_table_arn,
          "${var.dynamodb_table_arn}/index/*"
        ]
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-${var.environment}-storage"
  }
}

# Attach all policies to Lambda role
resource "aws_iam_role_policy_attachment" "collector_iam" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.collector_iam.arn
}

resource "aws_iam_role_policy_attachment" "collector_s3" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.collector_s3.arn
}

resource "aws_iam_role_policy_attachment" "collector_ec2" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.collector_ec2.arn
}

resource "aws_iam_role_policy_attachment" "collector_security" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.collector_security.arn
}

resource "aws_iam_role_policy_attachment" "storage" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.storage.arn
}
