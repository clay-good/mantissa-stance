# Writing Custom Policies

Create organization-specific security policies for Mantissa Stance.

## Overview

Stance policies are written in YAML and use a simple expression language to evaluate resource configurations. Custom policies allow you to:

- Enforce organization-specific security requirements
- Implement compliance controls not covered by default policies
- Create tagging and naming convention checks
- Define environment-specific rules

## Policy Structure

```yaml
# policy-id.yaml
id: my-org-s3-001                    # Unique identifier
name: S3 Bucket Naming Convention     # Human-readable name
description: |                        # Detailed description
  Ensure S3 buckets follow the organization naming convention:
  {env}-{team}-{purpose}

enabled: true                         # Enable/disable the policy
severity: medium                      # critical, high, medium, low, info

resource_type: aws_s3_bucket          # Resource type to evaluate

check:                                # Evaluation logic
  type: expression
  expression: "resource.name matches '^(prod|dev|staging)-[a-z]+-[a-z]+$'"

compliance:                           # Optional: Compliance mappings
  - framework: internal
    version: "1.0"
    control: "SEC-001"

remediation:                          # Remediation guidance
  guidance: |
    Rename the bucket to follow the naming convention:
    {environment}-{team}-{purpose}
    Example: prod-security-logs
  automation_supported: false

tags:                                 # Categorization tags
  - s3
  - naming
  - organization
```

## Expression Language

### Basic Comparisons

```yaml
# Equality
expression: "resource.encryption.enabled == true"

# Inequality
expression: "resource.public_access != true"

# Greater/less than
expression: "resource.min_password_length >= 14"
```

### Boolean Logic

```yaml
# AND
expression: "resource.encrypted == true && resource.versioning == true"

# OR
expression: "resource.storage_class == 'STANDARD' || resource.storage_class == 'STANDARD_IA'"

# NOT
expression: "!resource.publicly_accessible"
```

### String Operations

```yaml
# Contains
expression: "resource.name contains 'prod'"

# Starts with
expression: "resource.name startswith 'app-'"

# Ends with
expression: "resource.arn endswith '-logs'"

# Regex match
expression: "resource.name matches '^[a-z0-9-]+$'"
```

### List Operations

```yaml
# List contains value
expression: "resource.tags contains 'Environment'"

# List length
expression: "len(resource.security_groups) <= 5"

# Any/all (pseudo)
expression: "resource.ingress_rules all(rule => rule.cidr != '0.0.0.0/0')"
```

### Nested Access

```yaml
# Dot notation for nested properties
expression: "resource.encryption.sse_algorithm == 'aws:kms'"

# Safe navigation (returns null if missing)
expression: "resource.tags?.Environment == 'production'"
```

## Example Policies

### Require Encryption

```yaml
id: my-org-encrypt-001
name: Require KMS Encryption
description: All S3 buckets must use KMS encryption
enabled: true
severity: high
resource_type: aws_s3_bucket

check:
  type: expression
  expression: "resource.encryption.sse_algorithm == 'aws:kms'"

remediation:
  guidance: Enable KMS encryption on the S3 bucket
  automation_supported: true
```

### Require Tags

```yaml
id: my-org-tags-001
name: Required Tags
description: All EC2 instances must have required tags
enabled: true
severity: medium
resource_type: aws_ec2_instance

check:
  type: expression
  expression: |
    resource.tags.Environment != null &&
    resource.tags.Owner != null &&
    resource.tags.CostCenter != null

remediation:
  guidance: |
    Add the following tags to the instance:
    - Environment: prod/staging/dev
    - Owner: team email
    - CostCenter: cost center code
  automation_supported: false
```

### Network Restrictions

```yaml
id: my-org-network-001
name: No Public SSH
description: Security groups must not allow SSH from 0.0.0.0/0
enabled: true
severity: critical
resource_type: aws_security_group

check:
  type: expression
  expression: |
    resource.ingress_rules all(
      rule => !(rule.from_port <= 22 && rule.to_port >= 22 && rule.cidr == '0.0.0.0/0')
    )

remediation:
  guidance: |
    Remove or restrict the SSH ingress rule.
    Use a bastion host or VPN instead of public SSH access.
  automation_supported: false
```

### Database Security

```yaml
id: my-org-rds-001
name: RDS Multi-AZ for Production
description: Production RDS instances must have Multi-AZ enabled
enabled: true
severity: high
resource_type: aws_rds_instance

check:
  type: expression
  expression: |
    resource.tags.Environment != 'production' ||
    resource.multi_az == true

remediation:
  guidance: Enable Multi-AZ deployment for the RDS instance
  automation_supported: true
```

### Cross-Cloud Policies

```yaml
id: my-org-storage-001
name: Storage Encryption Required
description: All cloud storage must be encrypted
enabled: true
severity: high
resource_type: "*_storage_*"  # Matches aws_s3_bucket, gcp_storage_bucket, azure_storage_account

check:
  type: expression
  expression: "resource.encryption.enabled == true"

remediation:
  guidance: Enable encryption on the storage resource
  automation_supported: false
```

## Policy Files Location

Place custom policies in:

```
policies/
├── aws/
│   └── my-org-s3.yaml
├── gcp/
│   └── my-org-storage.yaml
├── azure/
│   └── my-org-blob.yaml
└── custom/
    └── my-org-common.yaml
```

## Loading Custom Policies

```bash
# Load policies from default directory
stance scan

# Load from custom directory
stance scan --policy-dir ./my-policies

# Load specific policy file
stance policies load ./my-policy.yaml
```

## Validating Policies

```bash
# Validate policy syntax
stance policies validate ./my-policy.yaml

# Test policy against sample resource
stance policies test ./my-policy.yaml --resource ./sample-resource.json
```

## Policy Testing

Create test cases for your policies:

```yaml
# my-policy-test.yaml
policy: my-org-s3-001
tests:
  - name: Compliant bucket
    resource:
      name: prod-security-logs
    expected: pass

  - name: Non-compliant bucket
    resource:
      name: my-random-bucket
    expected: fail
```

Run tests:

```bash
stance policies test my-policy-test.yaml
```

## Best Practices

1. **Unique IDs**: Use a consistent naming convention (e.g., `{org}-{service}-{number}`)
2. **Clear Descriptions**: Explain why the policy exists, not just what it checks
3. **Actionable Remediation**: Provide specific steps to fix issues
4. **Version Control**: Store policies in git with your infrastructure code
5. **Gradual Rollout**: Start with `severity: info` and escalate over time
6. **Test Thoroughly**: Create test cases for both pass and fail scenarios

## Debugging

```bash
# Enable verbose policy evaluation
stance scan -v --policy-debug

# Test expression syntax
stance policies eval 'resource.name contains "prod"' --resource '{"name": "prod-bucket"}'
```

## Next Steps

- [IaC Scanning](05-iac-scanning.md) - Apply policies to infrastructure code
- [Alerting](06-alerting.md) - Get notified about policy violations
