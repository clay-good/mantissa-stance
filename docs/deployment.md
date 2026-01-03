# Deployment Guide

This document covers deployment options for Mantissa Stance, from local development to production serverless deployments.

## Prerequisites

Before deploying Stance, ensure you have:

- **AWS Account**: With appropriate permissions for scanning
- **Python 3.11+**: Required for running Stance
- **AWS CLI**: Configured with credentials (`aws configure`)
- **Terraform 1.0+**: Required for serverless deployment (optional)

## Local Installation

### Install from PyPI

```bash
pip install mantissa-stance
```

### Install from Source

```bash
git clone https://github.com/clay-good/mantissa-stance.git
cd mantissa-stance
pip install -e ".[dev]"
```

### Verify Installation

```bash
stance version
stance --help
```

### Configure AWS Credentials

Stance uses standard AWS credential resolution:

```bash
# Option 1: AWS CLI configuration
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Option 3: IAM role (for EC2/Lambda)
# Credentials are automatically retrieved from instance metadata
```

## Environment Variables

Configure Stance behavior using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `STANCE_AWS_REGION` | AWS region to scan | `us-east-1` |
| `STANCE_S3_BUCKET` | S3 bucket for cloud storage | None (local storage) |
| `STANCE_DYNAMODB_TABLE` | DynamoDB table for state | None |
| `STANCE_LLM_PROVIDER` | LLM provider for queries | `anthropic` |
| `ANTHROPIC_API_KEY` | Anthropic API key | None |
| `OPENAI_API_KEY` | OpenAI API key | None |
| `GOOGLE_API_KEY` | Google AI API key | None |
| `STANCE_LOG_LEVEL` | Logging verbosity | `INFO` |
| `STANCE_STORAGE_BACKEND` | Storage backend type | `local` |
| `STANCE_DB_PATH` | Path to local SQLite database | `~/.stance/stance.db` |

### Example Configuration

```bash
# Production configuration
export STANCE_AWS_REGION=us-west-2
export STANCE_S3_BUCKET=my-company-stance-data
export STANCE_STORAGE_BACKEND=s3
export STANCE_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-...
export STANCE_LOG_LEVEL=WARNING
```

## AWS Serverless Deployment

For production deployments, Stance can run as a serverless application using Lambda and EventBridge.

### Architecture Overview

```
EventBridge (Schedule)
        |
        v
Lambda (Collector) --> S3 (Assets/Findings)
        |                    |
        v                    v
Lambda (Evaluator)      Athena (Queries)
        |
        v
   DynamoDB (State)
```

### Terraform Deployment

```bash
cd infrastructure/aws/terraform

# Initialize Terraform
terraform init

# Review the plan
terraform plan -var="project_name=stance" -var="environment=prod"

# Apply the configuration
terraform apply -var="project_name=stance" -var="environment=prod"
```

### Terraform Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `project_name` | Resource naming prefix | `mantissa-stance` |
| `environment` | Deployment environment | `dev` |
| `aws_region` | AWS region | `us-east-1` |
| `enable_scheduled_scans` | Enable EventBridge schedule | `true` |
| `scan_schedule` | Scan frequency | `rate(1 hour)` |
| `log_retention_days` | CloudWatch log retention | `30` |

### Estimated Costs

Monthly cost estimates for a typical deployment (single account, hourly scans):

| Resource | Estimated Cost |
|----------|---------------|
| Lambda (collector) | $1-5 |
| Lambda (evaluator) | $1-5 |
| S3 storage | $1-10 |
| DynamoDB | $1-5 |
| Athena queries | $1-10 |
| CloudWatch Logs | $1-5 |
| **Total** | **$6-40/month** |

Costs vary based on account size, scan frequency, and query volume.

## IAM Permissions

Stance requires read-only access to AWS services. Use this minimal IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IAMReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",
        "iam:GetUser",
        "iam:GetRole",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "iam:GetUserPolicy",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:ListGroups",
        "iam:ListAccessKeys",
        "iam:ListMFADevices",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListGroupsForUser"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadOnly",
      "Effect": "Allow",
      "Action": [
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
        "s3:ListBucket"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2ReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses"
      ],
      "Resource": "*"
    },
    {
      "Sid": "SecurityServicesReadOnly",
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:GetEnabledStandards",
        "securityhub:DescribeHub",
        "inspector2:ListFindings",
        "inspector2:ListCoverage",
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ConfigReadOnly",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:SelectResourceConfig"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

### Storage Permissions (for S3 backend)

If using S3 storage, add these permissions for the Stance S3 bucket:

```json
{
  "Sid": "StanceStorageAccess",
  "Effect": "Allow",
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListBucket"
  ],
  "Resource": [
    "arn:aws:s3:::YOUR-STANCE-BUCKET",
    "arn:aws:s3:::YOUR-STANCE-BUCKET/*"
  ]
}
```

### DynamoDB Permissions (for state management)

```json
{
  "Sid": "StanceStateAccess",
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:Query"
  ],
  "Resource": "arn:aws:dynamodb:*:*:table/stance-*"
}
```

## Scheduled Scanning

### EventBridge Configuration

Configure scheduled scans using EventBridge:

```hcl
# Terraform example
resource "aws_cloudwatch_event_rule" "stance_scan" {
  name                = "stance-scheduled-scan"
  description         = "Trigger Stance scan"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "stance_lambda" {
  rule      = aws_cloudwatch_event_rule.stance_scan.name
  target_id = "stance-collector"
  arn       = aws_lambda_function.stance_collector.arn
}
```

### Recommended Scan Frequencies

| Environment | Frequency | Rationale |
|-------------|-----------|-----------|
| Development | On-demand | Manual scanning during development |
| Staging | Every 4 hours | Catch issues before production |
| Production | Every 1 hour | Near real-time visibility |
| Compliance | Every 15 minutes | Critical environments |

### Incremental vs Full Scans

- **Full Scan**: Collects all resources, compares against all policies
- **Incremental Scan**: Only collects resources changed since last scan

```bash
# Full scan (default)
stance scan

# Incremental scan
stance scan --incremental
```

Incremental scans are faster but may miss some changes. Use full scans for compliance reporting.

## Multi-Account Setup

For organizations with multiple AWS accounts, use cross-account IAM roles.

### Cross-Account Role

In each target account, create a role that trusts the scanning account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::SCANNING_ACCOUNT_ID:role/stance-scanner"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Attach the read-only policy from above to this role.

### Scanning Multiple Accounts

```bash
# Scan with assumed role
stance scan --role-arn arn:aws:iam::TARGET_ACCOUNT:role/stance-scanner

# Scan multiple accounts sequentially
for account in 111111111111 222222222222 333333333333; do
  stance scan --role-arn arn:aws:iam::$account:role/stance-scanner
done
```

### Centralized Storage

Store findings from all accounts in a central S3 bucket:

```bash
export STANCE_S3_BUCKET=central-security-findings
export STANCE_STORAGE_BACKEND=s3

# Findings are partitioned by account
# s3://central-security-findings/stance/findings/account=111111111111/...
```

## Monitoring

### CloudWatch Metrics

Stance publishes metrics to CloudWatch when running in Lambda:

| Metric | Description |
|--------|-------------|
| `AssetsCollected` | Number of assets discovered |
| `FindingsGenerated` | Number of findings created |
| `ScanDuration` | Time to complete scan (seconds) |
| `ScanErrors` | Number of errors during scan |

### Log Aggregation

Lambda logs are automatically sent to CloudWatch Logs:

```
/aws/lambda/stance-collector
/aws/lambda/stance-evaluator
```

Configure log retention:

```hcl
resource "aws_cloudwatch_log_group" "stance" {
  name              = "/aws/lambda/stance-collector"
  retention_in_days = 30
}
```

### Alerting on Failures

Create CloudWatch alarms for scan failures:

```hcl
resource "aws_cloudwatch_metric_alarm" "scan_failures" {
  alarm_name          = "stance-scan-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Stance scan encountered errors"

  dimensions = {
    FunctionName = "stance-collector"
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
}
```

## Docker Deployment

Run Stance in a container:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY policies/ policies/

RUN pip install --no-cache-dir .

ENTRYPOINT ["stance"]
CMD ["--help"]
```

Build and run:

```bash
docker build -t stance .

# Run a scan
docker run -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
  stance scan --region us-west-2

# Start dashboard
docker run -p 8080:8080 -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY \
  stance dashboard --host 0.0.0.0
```

## Troubleshooting

### Common Issues

**Access Denied errors**
- Verify IAM policy is attached to the role/user
- Check that all required permissions are included
- Ensure the correct region is configured

**No findings generated**
- Verify policies are enabled (`stance policies list`)
- Check that resources match policy `resource_type`
- Run with `--verbose` for detailed output

**LLM queries failing**
- Verify API key is set correctly
- Check API key has sufficient quota
- Try a different provider with `--llm-provider`

**Database locked (local storage)**
- Only one Stance process can use local storage at a time
- Use S3 storage for concurrent access

### Debug Mode

Enable verbose logging:

```bash
export STANCE_LOG_LEVEL=DEBUG
stance scan --verbose
```

### Support

For issues, file a bug report at:
https://github.com/clay-good/mantissa-stance/issues
