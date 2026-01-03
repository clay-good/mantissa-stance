# Writing Security Policies

This document explains how to write custom security policies for Mantissa Stance.

## Policy Format Overview

Stance uses YAML-based security policies that are:

- **One policy per file**: Each `.yaml` file contains a single policy definition
- **Stored in /policies directory**: Organized by cloud provider and service (e.g., `policies/aws/iam/`)
- **Version controlled**: Policies are code and should be tracked in git
- **Human readable**: Clear structure with descriptive fields

## Policy Schema

Every policy follows this schema:

```yaml
# Required fields
id: string                    # Unique identifier (e.g., aws-iam-001)
name: string                  # Human-readable name
severity: string              # critical | high | medium | low | info
resource_type: string         # AWS resource type to evaluate
check:                        # Evaluation logic
  type: string                # expression | sql
  expression: string          # For expression checks
  query: string               # For SQL checks

# Optional fields
description: string           # Detailed explanation of what this checks
enabled: boolean              # true (default) | false
compliance:                   # Framework mappings
  - framework: string         # e.g., cis-aws-foundations
    version: string           # e.g., 1.5.0
    control: string           # e.g., 1.5
remediation:
  guidance: string            # Steps to fix the issue
  automation_supported: bool  # Always false (read-only design)
tags:                         # Categorization
  - string
references:                   # External documentation
  - string (URL)
```

### Field Descriptions

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier following pattern `{provider}-{service}-{number}` |
| `name` | Yes | Short, descriptive name (under 80 characters) |
| `description` | No | Detailed explanation of what the policy checks and why |
| `enabled` | No | Whether to evaluate this policy (default: true) |
| `severity` | Yes | Impact level: critical, high, medium, low, or info |
| `resource_type` | Yes | The type of resource this policy applies to |
| `check` | Yes | The evaluation logic (expression or SQL) |
| `compliance` | No | Mappings to compliance framework controls |
| `remediation` | No | Guidance for fixing non-compliant resources |
| `tags` | No | List of tags for categorization and filtering |
| `references` | No | URLs to external documentation |

## Check Types

Stance supports two types of checks: expression-based and SQL-based.

### Expression Checks

Expression checks use a simple, secure expression language to evaluate resource properties.

#### Supported Operators

| Category | Operators | Example |
|----------|-----------|---------|
| Comparison | `==`, `!=`, `>`, `<`, `>=`, `<=` | `resource.age > 90` |
| Membership | `in`, `not_in` | `"0.0.0.0/0" not_in resource.cidrs` |
| String | `contains`, `starts_with`, `ends_with` | `resource.name contains "prod"` |
| Regex | `matches` | `resource.name matches "^prod-.*"` |
| Existence | `exists`, `not_exists` | `resource.mfa_device exists` |
| Boolean | `and`, `or`, `not` | `resource.encrypted == true and resource.public == false` |

#### Path Notation

Access nested fields using dot notation:

```yaml
check:
  type: expression
  expression: "resource.encryption.kms_key_id exists"
```

For arrays, use membership operators:

```yaml
check:
  type: expression
  expression: "'Admin' not_in resource.attached_policies"
```

### SQL Checks

SQL checks are for complex logic that requires joins or aggregations. The query must:

- Be a SELECT statement only
- Return resource IDs that are non-compliant
- Not contain INSERT, UPDATE, DELETE, or other modifying statements

```yaml
check:
  type: sql
  query: |
    SELECT sg.id
    FROM security_groups sg
    JOIN security_group_rules sgr ON sg.id = sgr.group_id
    WHERE sgr.cidr = '0.0.0.0/0'
      AND sgr.direction = 'ingress'
      AND sgr.port_range_start <= 22
      AND sgr.port_range_end >= 22
```

## Examples

### Example 1: S3 Bucket Encryption

A simple expression check for S3 bucket encryption:

```yaml
id: aws-s3-001
name: S3 bucket encryption enabled
description: |
  Ensure all S3 buckets have default encryption enabled. Server-side
  encryption protects data at rest and is a fundamental security control.

enabled: true
severity: high
resource_type: aws_s3_bucket

check:
  type: expression
  expression: "resource.encryption.enabled == true"

compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "2.1.1"
  - framework: pci-dss
    version: "4.0"
    control: "3.4.1"

remediation:
  guidance: |
    1. Open the S3 console
    2. Select the bucket
    3. Go to Properties > Default encryption
    4. Enable server-side encryption with SSE-S3 or SSE-KMS
  automation_supported: false

tags:
  - s3
  - encryption
  - data-protection

references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
```

### Example 2: IAM Password Policy

An expression check with multiple conditions:

```yaml
id: aws-iam-002
name: IAM password policy meets minimum requirements
description: |
  Ensure the account password policy requires strong passwords with
  minimum length, complexity, and rotation requirements.

enabled: true
severity: high
resource_type: aws_iam_account_password_policy

check:
  type: expression
  expression: |
    resource.minimum_password_length >= 14
    and resource.require_symbols == true
    and resource.require_numbers == true
    and resource.require_uppercase_characters == true
    and resource.require_lowercase_characters == true
    and resource.max_password_age <= 90
    and resource.password_reuse_prevention >= 24

compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "1.8"
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "1.9"
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "1.10"
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "1.11"

remediation:
  guidance: |
    1. Open the IAM console
    2. Navigate to Account settings > Password policy
    3. Set minimum length to 14 or greater
    4. Enable all complexity requirements
    5. Set maximum age to 90 days or less
    6. Set password reuse prevention to 24 or greater
  automation_supported: false

tags:
  - iam
  - password
  - authentication
  - access-control

references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
```

### Example 3: Security Groups with Open Access

A SQL check for complex logic:

```yaml
id: aws-ec2-003
name: Security groups do not allow unrestricted SSH access
description: |
  Ensure no security group allows inbound SSH (port 22) from 0.0.0.0/0.
  Unrestricted SSH access exposes instances to brute force attacks.

enabled: true
severity: critical
resource_type: aws_security_group

check:
  type: sql
  query: |
    SELECT DISTINCT sg.id
    FROM assets sg
    WHERE sg.resource_type = 'aws_security_group'
      AND EXISTS (
        SELECT 1 FROM json_each(sg.raw_config, '$.ingress_rules') rule
        WHERE json_extract(rule.value, '$.cidr') = '0.0.0.0/0'
          AND json_extract(rule.value, '$.from_port') <= 22
          AND json_extract(rule.value, '$.to_port') >= 22
      )

compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "5.2"
  - framework: pci-dss
    version: "4.0"
    control: "1.3.1"

remediation:
  guidance: |
    1. Open the EC2 console
    2. Navigate to Security Groups
    3. Select the security group
    4. Edit inbound rules
    5. Remove or restrict rules allowing SSH from 0.0.0.0/0
    6. Use specific IP ranges or security group references
  automation_supported: false

tags:
  - ec2
  - security-group
  - network
  - ssh

references:
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules.html
```

## Compliance Mappings

Policies can be mapped to multiple compliance frameworks to enable compliance reporting.

### Supported Frameworks

| Framework ID | Name | Example Control |
|--------------|------|-----------------|
| `cis-aws-foundations` | CIS AWS Foundations Benchmark | 1.5, 2.1.1 |
| `pci-dss` | PCI Data Security Standard | 3.4.1, 8.3.1 |
| `soc2` | SOC 2 Trust Services Criteria | CC6.1, CC7.2 |
| `aws-foundational-security` | AWS Foundational Security Best Practices | IAM.6, S3.1 |
| `nist-800-53` | NIST 800-53 Security Controls | AC-2, IA-5 |

### Mapping Format

```yaml
compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "1.5"
  - framework: pci-dss
    version: "4.0"
    control: "8.3.1"
```

### Control ID Format

- Use the exact control ID from the framework documentation
- Include sub-controls when applicable (e.g., "2.1.1" not just "2.1")
- Version is optional but recommended for clarity

## Testing Policies

### Validate Policy Syntax

Check all policies for syntax errors and schema compliance:

```bash
stance policies validate
```

Validate a specific policy:

```bash
stance policies validate --policy-id aws-iam-001
```

### List Policies

List all enabled policies:

```bash
stance policies list
```

Filter by severity:

```bash
stance policies list --severity critical
```

Filter by framework:

```bash
stance policies list --framework cis-aws-foundations
```

### Dry Run

Test policies against collected assets without storing findings:

```bash
stance scan --dry-run
```

This shows what findings would be generated without persisting them.

## Built-in Policies

Stance includes policies covering common security best practices:

### IAM Policies

- Root account MFA enabled
- IAM users have MFA enabled
- Password policy requirements
- Access key rotation (90 days)
- No inline policies on users
- No policies with admin access

### S3 Policies

- Bucket encryption enabled
- Public access blocked
- Bucket logging enabled
- Versioning enabled for critical buckets
- No public bucket policies
- SSL-only access enforced

### EC2/Network Policies

- No unrestricted SSH (port 22)
- No unrestricted RDP (port 3389)
- EBS volumes encrypted
- IMDSv2 required
- Default security group has no rules
- No unrestricted database ports

### Security Service Policies

- SecurityHub enabled
- GuardDuty enabled
- CloudTrail enabled in all regions
- Config enabled
- Inspector enabled (for vulnerability scanning)

## Policy Directory Structure

Organize policies by provider and service:

```
policies/
  aws/
    iam/
      aws-iam-001-root-mfa.yaml
      aws-iam-002-password-policy.yaml
      aws-iam-003-access-key-rotation.yaml
    s3/
      aws-s3-001-encryption.yaml
      aws-s3-002-public-access.yaml
    ec2/
      aws-ec2-001-ebs-encryption.yaml
      aws-ec2-002-imdsv2.yaml
      aws-ec2-003-security-group-ssh.yaml
```

## Best Practices

1. **Use descriptive IDs**: Follow the `{provider}-{service}-{number}` pattern
2. **Write clear descriptions**: Explain what the policy checks and why it matters
3. **Include remediation**: Help users fix issues, not just find them
4. **Map to frameworks**: Enable compliance reporting by mapping to standards
5. **Test before deploying**: Use `stance policies validate` to catch errors
6. **Version control policies**: Track changes alongside your infrastructure code
7. **Start with built-in policies**: Customize rather than starting from scratch
