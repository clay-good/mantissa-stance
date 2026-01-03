# CIS Benchmark Mappings

This document describes how Mantissa Stance maps security policies to CIS Benchmark controls.

## Supported Benchmarks

Stance includes mappings for CIS security benchmarks:

| Benchmark | ID | Latest Version |
|-----------|-------|----------------|
| CIS AWS Foundations Benchmark | `cis-aws` | 1.5.0 |
| CIS GCP Foundations Benchmark | `cis-gcp` | 1.3.0 |
| CIS Azure Foundations Benchmark | `cis-azure` | 1.5.0 |

> **Note**: For compliance framework support (SOC 2, PCI-DSS, HIPAA, NIST 800-53, FedRAMP, ISO 27001), see [Attestful](https://github.com/clay-good/attestful).

## How Benchmark Scoring Works

### Control Evaluation

Each CIS control is linked to one or more Stance policies. A control is considered:

- **Passing**: All linked policies have no open findings
- **Failing**: At least one linked policy has open findings
- **Not Applicable**: No resources exist for the linked policies

### Score Calculation

Benchmark scores are calculated as:

```
Benchmark Score = (Passing Controls / Total Applicable Controls) * 100
```

Overall posture score is the weighted average of all benchmark scores.

### Example

If CIS AWS Foundations has 50 controls and:
- 40 controls are passing
- 8 controls are failing
- 2 controls are not applicable

Score = (40 / 48) * 100 = 83.3%

## CIS AWS Foundations Benchmark

The CIS AWS Foundations Benchmark provides prescriptive guidance for configuring AWS accounts.

### Coverage

| Section | Controls | Stance Coverage |
|---------|----------|-----------------|
| 1. Identity and Access Management | 22 | 18 |
| 2. Storage | 6 | 6 |
| 3. Logging | 11 | 8 |
| 4. Monitoring | 15 | 10 |
| 5. Networking | 6 | 6 |
| **Total** | **60** | **48 (80%)** |

### Key Controls

| Control | Policy ID | Description |
|---------|-----------|-------------|
| 1.4 | aws-iam-001 | Root account MFA enabled |
| 1.5 | aws-iam-002 | Root account has no access keys |
| 1.8-1.11 | aws-iam-003 | Password policy requirements |
| 1.14 | aws-iam-004 | Access keys rotated within 90 days |
| 2.1.1 | aws-s3-001 | S3 bucket encryption enabled |
| 2.1.5 | aws-s3-002 | S3 public access blocked |
| 5.2 | aws-ec2-001 | No unrestricted SSH access |
| 5.3 | aws-ec2-002 | No unrestricted RDP access |

## CIS GCP Foundations Benchmark

### Coverage

| Section | Controls | Stance Coverage |
|---------|----------|-----------------|
| 1. Identity and Access Management | 18 | 14 |
| 2. Logging and Monitoring | 12 | 9 |
| 3. Networking | 10 | 8 |
| 4. Virtual Machines | 11 | 9 |
| 5. Storage | 6 | 6 |
| 6. Cloud SQL | 8 | 6 |
| 7. BigQuery | 3 | 2 |
| **Total** | **68** | **54 (79%)** |

### Key Controls

| Control | Policy ID | Description |
|---------|-----------|-------------|
| 1.4 | gcp-iam-001 | Service account key rotation |
| 1.5 | gcp-iam-002 | No default service account usage |
| 1.6 | gcp-iam-003 | No overly permissive IAM bindings |
| 3.1 | gcp-network-001 | No default network |
| 3.6 | gcp-network-002 | SSH access restricted |
| 5.1 | gcp-storage-001 | Uniform bucket-level access |

## CIS Azure Foundations Benchmark

### Coverage

| Section | Controls | Stance Coverage |
|---------|----------|-----------------|
| 1. Identity and Access Management | 23 | 18 |
| 2. Security Center | 15 | 12 |
| 3. Storage Accounts | 11 | 9 |
| 4. Database Services | 15 | 11 |
| 5. Logging and Monitoring | 6 | 5 |
| 6. Networking | 6 | 6 |
| 7. Virtual Machines | 7 | 5 |
| 8. Other Security | 5 | 4 |
| **Total** | **88** | **70 (80%)** |

### Key Controls

| Control | Policy ID | Description |
|---------|-----------|-------------|
| 1.1 | azure-iam-001 | MFA enabled for privileged users |
| 1.22 | azure-iam-002 | No custom subscription owner roles |
| 3.1 | azure-storage-001 | Secure transfer required |
| 3.2 | azure-storage-002 | Storage account encryption |
| 6.1 | azure-network-001 | NSG flow logs enabled |
| 6.2 | azure-network-002 | SSH access restricted |

## Generating Benchmark Reports

### Command Line

```bash
# All benchmarks
stance report --format html --output benchmark-report.html

# Specific benchmark
stance report --benchmark cis-aws --format html

# JSON for integration
stance report --benchmark cis-gcp --format json
```

### Report Contents

HTML reports include:

1. **Executive Summary**: Overall scores by benchmark
2. **Benchmark Details**: Per-control status with findings
3. **Remediation Priority**: Critical items requiring attention
4. **Evidence**: Asset and finding details

### Example Report Output

```
CIS Benchmark Report - 2024-01-15

EXECUTIVE SUMMARY
-----------------
CIS AWS Foundations 1.5.0: 83% (40/48 controls passing)
CIS GCP Foundations 1.3.0: 79% (43/54 controls passing)
Overall Posture Score: 81%

FAILING CONTROLS
----------------
CIS AWS 1.4 - Root account MFA not enabled
  Findings: 1
  Severity: Critical
  Remediation: Enable MFA on root account

CIS AWS 5.2 - Security group allows SSH from 0.0.0.0/0
  Findings: 3
  Severity: High
  Remediation: Restrict SSH access to known IPs
```

## Custom Benchmark Extensions

Extend CIS benchmarks with additional organization-specific controls:

```yaml
# policies/aws/iam/aws-iam-custom.yaml
id: aws-iam-custom-001
name: IAM Users Must Have Tags
description: Ensure all IAM users have required tags
severity: medium
resource_type: aws_iam_user
check:
  type: expression
  expression: "'Environment' in resource.tags and 'Owner' in resource.tags"
benchmark:
  - cis-aws-custom: "ORG-1.1"
```

### Defining Custom Benchmark Extensions

Create a benchmark extension in `policies/benchmarks/`:

```yaml
# policies/benchmarks/cis-aws-custom.yaml
id: cis-aws-custom
name: CIS AWS Custom Extensions
version: "1.0"
description: Organization-specific extensions to CIS AWS
extends: cis-aws

controls:
  - id: ORG-1.1
    name: IAM users must have required tags
    description: All IAM users must have Environment and Owner tags

  - id: ORG-2.1
    name: S3 buckets must have cost allocation tags
    description: All S3 buckets must have cost allocation tags
```

## Exporting Findings for Attestful

If you use [Attestful](https://github.com/clay-good/attestful) for compliance evidence collection, you can export Stance findings for import:

```bash
# Export findings in a format compatible with Attestful
stance findings --format json --output stance-findings.json

# Export asset inventory
stance assets --format json --output stance-assets.json
```

Attestful can ingest these findings as evidence for compliance frameworks.
