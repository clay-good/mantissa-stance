# AWS Security Scanning Tutorial

Comprehensive guide to scanning your AWS infrastructure with Mantissa Stance.

## Overview

Stance provides deep security scanning for AWS services including:
- IAM (users, roles, policies, access keys)
- S3 (buckets, encryption, public access)
- EC2 (instances, security groups, EBS volumes)
- RDS (databases, encryption, public access)
- Lambda (functions, permissions)
- EKS (Kubernetes clusters, node groups)
- And many more...

## Prerequisites

- AWS credentials with read access to services
- Recommended: Use a role with `SecurityAudit` managed policy

## IAM Permissions

Create an IAM policy for Stance scanning:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountPasswordPolicy",
                "iam:GetAccountSummary",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListPolicies",
                "iam:ListAccessKeys",
                "iam:GetUser",
                "iam:GetRole",
                "iam:ListMFADevices",
                "s3:ListAllMyBuckets",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketEncryption",
                "s3:GetBucketPublicAccessBlock",
                "ec2:DescribeInstances",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeVolumes",
                "rds:DescribeDBInstances",
                "lambda:ListFunctions",
                "eks:ListClusters",
                "eks:DescribeCluster"
            ],
            "Resource": "*"
        }
    ]
}
```

## Running Scans

### Basic Scan

```bash
# Scan AWS account in specific region
stance scan --provider aws --region us-east-1

# Scan specific AWS account
stance scan --provider aws --account-id 123456789012 --region us-east-1
```

### Targeted Scans

```bash
# Scan only IAM
stance scan --provider aws --region us-east-1 --collectors aws_iam

# Scan storage services
stance scan --provider aws --region us-east-1 --collectors aws_s3,aws_rds,aws_dynamodb

# Scan compute services
stance scan --provider aws --region us-east-1 --collectors aws_ec2,aws_lambda,aws_eks
```

### Available Collectors

| Collector | Description |
|-----------|-------------|
| `aws_iam` | IAM users, roles, policies, access keys |
| `aws_s3` | S3 buckets, encryption, public access |
| `aws_ec2` | EC2 instances, security groups, EBS |
| `aws_security` | SecurityHub, GuardDuty findings |
| `aws_rds` | RDS instances, snapshots |
| `aws_lambda` | Lambda functions, permissions |
| `aws_dynamodb` | DynamoDB tables |
| `aws_apigateway` | API Gateway APIs |
| `aws_ecr` | ECR repositories, images |
| `aws_eks` | EKS clusters, node groups |
| `aws_sagemaker` | SageMaker endpoints, notebooks |
| `aws_bedrock` | Bedrock models, guardrails, agents |

## Understanding Results

### Severity Levels

| Severity | Description |
|----------|-------------|
| CRITICAL | Immediate action required (e.g., public database) |
| HIGH | Serious issue requiring prompt attention |
| MEDIUM | Should be addressed in near term |
| LOW | Minor issue, best practice violation |
| INFO | Informational finding |

### Example Findings

**Critical: Public S3 Bucket**
```
Rule: aws-s3-002
Severity: CRITICAL
Asset: arn:aws:s3:::my-public-bucket
Description: S3 bucket allows public access
Remediation: Enable Block Public Access settings
```

**High: Root Account MFA**
```
Rule: aws-iam-001
Severity: HIGH
Asset: arn:aws:iam::123456789012:root
Description: Root account does not have MFA enabled
Remediation: Enable MFA on root account
```

## Filtering Findings

```bash
# By severity
stance findings --severity critical
stance findings --severity high,critical

# By policy/rule
stance findings --policy aws-s3-001

# By asset
stance findings --asset arn:aws:s3:::my-bucket

# Combined filters
stance findings --severity high --status open
```

## Compliance Mapping

Stance maps findings to compliance frameworks:

```bash
# View CIS AWS Foundations compliance
stance report --framework cis-aws-foundations

# View all compliance scores
stance report --format json | jq '.compliance'
```

Supported frameworks:
- CIS AWS Foundations Benchmark v2.0
- PCI DSS v4.0
- SOC 2 Type II
- HIPAA Security Rule
- NIST 800-53

## Scheduling Scans

```bash
# Add a scheduled scan
stance schedule add --name daily-scan --schedule "0 6 * * *"

# List scheduled scans
stance schedule list

# Run a scheduled scan immediately
stance schedule run daily-scan
```

## Storing Results

```bash
# Use local SQLite storage (default)
stance scan --provider aws --region us-east-1 --storage local

# Use S3 for storage
stance scan --provider aws --region us-east-1 --storage s3 --s3-bucket my-stance-bucket

# View stored snapshots
stance history list
```

## Best Practices

1. **Regular Scanning**: Schedule daily scans to catch issues early
2. **Start Small**: Begin with critical services (IAM, S3) then expand
3. **Track Progress**: Compare scans over time with `stance diff`
4. **Automate Alerts**: Configure notifications for new critical findings
5. **Document Exceptions**: Use policy exceptions for accepted risks

## Troubleshooting

### Slow Scans
- Reduce the number of regions scanned
- Use targeted collectors instead of scanning everything
- Consider parallel scanning with `--parallel`

### Missing Findings
- Check IAM permissions for the scanning role
- Verify resources exist in the scanned region
- Enable verbose logging with `-v`

### Rate Limiting
- AWS may throttle API calls during large scans
- Stance automatically retries with exponential backoff
- Consider scanning regions sequentially

## Next Steps

- [Multi-Cloud Scanning](03-multi-cloud.md) - Add GCP and Azure
- [Custom Policies](04-custom-policies.md) - Write organization-specific rules
- [IaC Scanning](05-iac-scanning.md) - Scan Terraform before deployment
