# Infrastructure as Code Scanning

Scan Terraform, CloudFormation, and ARM templates for security issues before deployment.

## Overview

Mantissa Stance can scan infrastructure code to find security issues before resources are deployed. This "shift-left" approach catches misconfigurations early in the development cycle.

Supported formats:
- **Terraform** (`.tf` files)
- **CloudFormation** (`.yaml`, `.json` templates)
- **Azure ARM Templates** (`.json` templates)

## Quick Start

```bash
# Scan current directory
stance iac-scan .

# Scan specific file
stance iac-scan main.tf

# Scan with specific severity threshold
stance iac-scan . --severity high
```

## Terraform Scanning

### Example Terraform File

```hcl
# main.tf
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false  # Issue: Should be true
  block_public_policy     = false  # Issue: Should be true
  ignore_public_acls      = false  # Issue: Should be true
  restrict_public_buckets = false  # Issue: Should be true
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Issue: Public SSH access
  }
}
```

### Scan the Terraform

```bash
stance iac-scan main.tf
```

Output:
```
IaC Scan Results
================
Files scanned: 1
Files with issues: 1
Total issues found: 5

CRITICAL (1):
  - [main.tf:17] aws_security_group.web allows SSH from 0.0.0.0/0
    Rule: iac-aws-sg-001
    Remediation: Restrict SSH access to specific IP ranges

HIGH (4):
  - [main.tf:8] S3 bucket public access block disabled
    Rule: iac-aws-s3-001
    Remediation: Enable all public access block settings
```

## CloudFormation Scanning

### Example CloudFormation Template

```yaml
# template.yaml
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
      # Missing: BucketEncryption

  MyDatabase:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.micro
      Engine: mysql
      MasterUsername: admin
      MasterUserPassword: password123  # Issue: Hardcoded password
      PubliclyAccessible: true          # Issue: Public database
```

### Scan the Template

```bash
stance iac-scan template.yaml
```

Output:
```
IaC Scan Results
================
Files scanned: 1
Files with issues: 1
Total issues found: 3

CRITICAL (2):
  - [template.yaml:14] RDS instance is publicly accessible
  - [template.yaml:13] Hardcoded password in template

HIGH (1):
  - [template.yaml:5] S3 bucket lacks encryption configuration
```

## ARM Template Scanning

### Example ARM Template

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "name": "mystorageaccount",
      "properties": {
        "supportsHttpsTrafficOnly": false,
        "minimumTlsVersion": "TLS1_0"
      }
    }
  ]
}
```

### Scan the Template

```bash
stance iac-scan arm-template.json
```

## Output Formats

### Table Output (default)

```bash
stance iac-scan . --format table
```

### JSON Output

```bash
stance iac-scan . --format json > findings.json
```

### SARIF Output (for IDE integration)

```bash
stance iac-scan . --format sarif > results.sarif
```

SARIF format is compatible with:
- VS Code (SARIF Viewer extension)
- GitHub Code Scanning
- Azure DevOps

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yaml
name: Security Scan

on: [push, pull_request]

jobs:
  iac-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Stance
        run: pip install mantissa-stance

      - name: Scan IaC
        run: stance iac-scan . --format sarif > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security-scan:
  image: python:3.11
  script:
    - pip install mantissa-stance
    - stance iac-scan . --format json > iac-findings.json
    - stance iac-scan . --fail-on high  # Fail pipeline on high severity
  artifacts:
    reports:
      codequality: iac-findings.json
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install mantissa-stance'
                sh 'stance iac-scan . --format json > findings.json'
                sh 'stance iac-scan . --fail-on critical'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'findings.json'
        }
    }
}
```

## Failing Builds

Use `--fail-on` to fail the scan if issues at or above a severity are found:

```bash
# Fail on critical issues only
stance iac-scan . --fail-on critical

# Fail on high and above
stance iac-scan . --fail-on high

# Fail on any issue
stance iac-scan . --fail-on info
```

Exit codes:
- `0`: No issues at or above the threshold
- `1`: Issues found at or above the threshold
- `2`: Scan error

## Custom IaC Policies

Create IaC-specific policies:

```yaml
# iac-policies/require-tags.yaml
id: iac-tags-001
name: Require Resource Tags
description: All Terraform resources must have required tags
enabled: true
severity: medium
resource_type: terraform_*

check:
  type: expression
  expression: |
    resource.tags != null &&
    resource.tags.Environment != null &&
    resource.tags.Owner != null

remediation:
  guidance: Add Environment and Owner tags to the resource
```

Load custom policies:

```bash
stance iac-scan . --policy-dir ./iac-policies
```

## Secrets Detection

IaC scanning includes secrets detection:

```bash
# Scan for secrets in IaC files
stance iac-scan . --secrets

# Or use dedicated secrets scanner
stance secrets-scan .
```

Detected secret types:
- AWS access keys
- API keys
- Database passwords
- Private keys
- OAuth tokens

## Best Practices

1. **Scan Early**: Integrate scanning in pre-commit hooks
2. **Block Merges**: Require clean scans before merging PRs
3. **Document Exceptions**: Use inline comments for accepted risks
4. **Baseline First**: Start with warnings, then enforce over time
5. **Keep Policies Updated**: Regularly update security policies

## Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: iac-scan
        name: IaC Security Scan
        entry: stance iac-scan
        language: system
        types: [terraform, yaml, json]
        pass_filenames: true
```

## Troubleshooting

### Parse Errors

```
Error: Failed to parse main.tf
```
- Check for syntax errors in the file
- Ensure HCL syntax is valid

### Missing Findings

If expected issues aren't found:
- Check that the policy exists for the resource type
- Verify the policy is enabled
- Use `-v` for verbose output

### Performance

For large codebases:
- Use `--exclude` to skip irrelevant directories
- Scan specific directories instead of root
- Consider parallel scanning

## Next Steps

- [Alerting](06-alerting.md) - Get notified about IaC issues
- [Custom Policies](04-custom-policies.md) - Write IaC-specific policies
