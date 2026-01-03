# Quick Start Guide

Get up and running with Mantissa Stance in 5 minutes.

## Prerequisites

- Python 3.9 or higher
- AWS credentials configured (for AWS scanning)
- pip package manager

## Installation

```bash
# Install from PyPI
pip install mantissa-stance

# Verify installation
stance --version
```

## Step 1: Configure AWS Credentials

Stance uses boto3 for AWS access. Configure your credentials:

```bash
# Option 1: AWS CLI configuration
aws configure

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-east-1
```

## Step 2: Run Your First Scan

```bash
# Basic scan of your AWS account
stance scan

# Scan specific region
stance scan --region us-east-1

# Scan with specific collectors
stance scan --collectors iam,s3,ec2
```

## Step 3: View Findings

```bash
# List all findings
stance findings

# Filter by severity
stance findings --severity critical
stance findings --severity high

# Filter by status
stance findings --status open

# Output as JSON
stance findings --output json
```

## Step 4: View Assets

```bash
# List all assets
stance assets

# Filter by type
stance assets --type aws_s3_bucket

# Filter by region
stance assets --region us-east-1
```

## Step 5: Query with Natural Language

If you have an LLM API key configured:

```bash
# Set your API key
export ANTHROPIC_API_KEY=your-key

# Ask questions about your security posture
stance query "What are my most critical security issues?"
stance query "Show me all public S3 buckets"
stance query "Which IAM users don't have MFA enabled?"
```

## Step 6: Start the Dashboard

```bash
# Start the web dashboard
stance dashboard

# Dashboard will be available at http://localhost:8080
```

Open your browser to http://localhost:8080 to see:
- Security posture summary
- Findings by severity
- Asset inventory
- Compliance scores

## Step 7: Generate Reports

```bash
# Generate compliance report
stance report --format json > report.json

# Generate HTML report
stance report --format html > report.html
```

## Next Steps

- [AWS Scanning Tutorial](02-aws-scanning.md) - Deep dive into AWS security scanning
- [Custom Policies](04-custom-policies.md) - Write your own security policies
- [Alerting Setup](06-alerting.md) - Configure notifications

## Common Commands Reference

| Command | Description |
|---------|-------------|
| `stance scan` | Run security scan |
| `stance findings` | List findings |
| `stance assets` | List assets |
| `stance query` | Natural language query |
| `stance dashboard` | Start web dashboard |
| `stance report` | Generate report |
| `stance policies` | List policies |
| `stance shell` | Interactive shell |

## Troubleshooting

### No credentials found
```
Error: Unable to locate credentials
```
Solution: Configure AWS credentials using `aws configure` or environment variables.

### Permission denied
```
Error: Access Denied
```
Solution: Ensure your IAM user/role has read permissions for the services being scanned.

### No findings
If a scan completes with no findings, your resources may already be compliant! Run with verbose output to see what was scanned:
```bash
stance scan -v
```
