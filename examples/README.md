# Mantissa Stance Examples

This directory contains example configurations, tutorials, and sample code to help you get started with Mantissa Stance.

## Directory Structure

```
examples/
├── configs/           # Configuration file examples
│   ├── scan-config.yaml       # Scan configuration
│   ├── alerting-config.yaml   # Alert routing configuration
│   └── storage-config.yaml    # Storage backend configuration
├── tutorials/         # Step-by-step tutorials
│   ├── 01-quick-start.md      # Getting started guide
│   ├── 02-aws-scanning.md     # AWS security scanning
│   ├── 03-multi-cloud.md      # Multi-cloud setup
│   ├── 04-custom-policies.md  # Writing custom policies
│   ├── 05-iac-scanning.md     # Infrastructure as Code scanning
│   └── 06-alerting.md         # Alert configuration
├── policies/          # Example custom policies
│   └── custom-s3-policy.yaml  # Custom S3 security policy
└── terraform/         # Terraform examples for deployment
    └── aws-deployment/        # AWS deployment example
```

## Quick Start

1. **Install Stance:**
   ```bash
   pip install mantissa-stance
   ```

2. **Run your first scan:**
   ```bash
   stance scan --region us-east-1
   ```

3. **View findings:**
   ```bash
   stance findings --severity high
   ```

4. **Start the dashboard:**
   ```bash
   stance dashboard
   ```

## Tutorials

| Tutorial | Description |
|----------|-------------|
| [Quick Start](tutorials/01-quick-start.md) | Get up and running in 5 minutes |
| [AWS Scanning](tutorials/02-aws-scanning.md) | Comprehensive AWS security scanning |
| [Multi-Cloud](tutorials/03-multi-cloud.md) | Scan AWS, GCP, and Azure together |
| [Custom Policies](tutorials/04-custom-policies.md) | Write your own security policies |
| [IaC Scanning](tutorials/05-iac-scanning.md) | Scan Terraform, CloudFormation, ARM |
| [Alerting](tutorials/06-alerting.md) | Configure Slack, PagerDuty, email alerts |

## Configuration Examples

See the [configs/](configs/) directory for example configuration files:

- **scan-config.yaml**: Configure which collectors to run, regions to scan
- **alerting-config.yaml**: Set up alert destinations and routing rules
- **storage-config.yaml**: Configure local, S3, GCS, or Azure Blob storage

## Custom Policies

See the [policies/](policies/) directory for example custom policies.

Policies are written in YAML and use a simple expression language to evaluate resource configurations.
