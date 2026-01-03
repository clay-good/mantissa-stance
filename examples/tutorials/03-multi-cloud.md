# Multi-Cloud Security Scanning

Scan AWS, Google Cloud Platform, and Microsoft Azure with a unified approach.

## Overview

Mantissa Stance provides consistent security scanning across:
- **AWS**: IAM, S3, EC2, RDS, Lambda, EKS, and more
- **GCP**: IAM, Cloud Storage, Compute Engine, Cloud SQL, GKE, and more
- **Azure**: Azure AD, Blob Storage, Virtual Machines, SQL, AKS, and more

## Prerequisites

### AWS Credentials
```bash
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-east-1
```

### GCP Credentials
```bash
# Option 1: Service account key
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Option 2: Default credentials (if running on GCP)
gcloud auth application-default login
```

### Azure Credentials
```bash
# Option 1: Service principal
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-client-secret
export AZURE_TENANT_ID=your-tenant-id
export AZURE_SUBSCRIPTION_ID=your-subscription-id

# Option 2: Azure CLI login
az login
```

## Scanning Multiple Clouds

### Sequential Scanning

```bash
# Scan AWS
stance scan --cloud aws --region us-east-1

# Scan GCP
stance scan --cloud gcp --project my-gcp-project

# Scan Azure
stance scan --cloud azure --subscription my-subscription
```

### Combined Report

All findings are stored in the same database, allowing unified reporting:

```bash
# View all findings across clouds
stance findings

# Filter by cloud provider
stance findings --cloud aws
stance findings --cloud gcp
stance findings --cloud azure

# View assets by cloud
stance assets --cloud aws
stance assets --cloud gcp
```

## GCP Collectors

| Collector | Description |
|-----------|-------------|
| `gcp_iam` | Service accounts, IAM policies |
| `gcp_storage` | Cloud Storage buckets |
| `gcp_compute` | Compute Engine instances, firewalls |
| `gcp_cloudsql` | Cloud SQL instances |
| `gcp_functions` | Cloud Functions |
| `gcp_bigquery` | BigQuery datasets |
| `gcp_cloudrun` | Cloud Run services |
| `gcp_artifactregistry` | Artifact Registry |
| `gcp_gke` | GKE clusters |

### GCP Example Scan

```bash
# Full GCP scan
stance scan --cloud gcp --project my-project

# Targeted GCP scan
stance scan --cloud gcp --project my-project --collectors gcp_iam,gcp_storage,gcp_gke
```

## Azure Collectors

| Collector | Description |
|-----------|-------------|
| `azure_identity` | Azure AD users, service principals |
| `azure_storage` | Storage accounts, blob containers |
| `azure_compute` | Virtual machines, NSGs |
| `azure_sql` | Azure SQL databases |
| `azure_functions` | Azure Functions |
| `azure_cosmosdb` | Cosmos DB accounts |
| `azure_logicapps` | Logic Apps workflows |
| `azure_containerregistry` | Azure Container Registry |
| `azure_aks` | AKS clusters |

### Azure Example Scan

```bash
# Full Azure scan
stance scan --cloud azure --subscription my-sub-id

# Targeted Azure scan
stance scan --cloud azure --collectors azure_identity,azure_storage,azure_aks
```

## Cross-Cloud Comparison

### Unified Dashboard

Start the dashboard to see all clouds in one view:

```bash
stance dashboard
```

The dashboard shows:
- Total assets by cloud provider
- Findings distribution across clouds
- Compliance scores per cloud
- Trend analysis

### Compliance Mapping

Stance maps findings to cloud-agnostic frameworks:

| Framework | AWS | GCP | Azure |
|-----------|-----|-----|-------|
| CIS Benchmarks | Yes | Yes | Yes |
| PCI DSS | Yes | Yes | Yes |
| SOC 2 | Yes | Yes | Yes |
| HIPAA | Yes | Yes | Yes |
| NIST 800-53 | Yes | Yes | Yes |

### Cross-Cloud Queries

```bash
# Query across all clouds
stance query "Show me all public storage buckets across all clouds"

# Compare cloud security posture
stance query "Which cloud has the most critical findings?"

# Find internet-facing resources
stance query "List all internet-exposed databases"
```

## Multi-Account/Project Scanning

### AWS Organizations

```bash
# Scan multiple AWS accounts
stance scan --cloud aws --accounts 111111111111,222222222222,333333333333
```

### GCP Projects

```bash
# Scan multiple GCP projects
stance scan --cloud gcp --projects project-a,project-b,project-c
```

### Azure Subscriptions

```bash
# Scan multiple Azure subscriptions
stance scan --cloud azure --subscriptions sub-1,sub-2,sub-3
```

## Storage Configuration

For multi-cloud environments, use cloud storage:

```bash
# AWS S3 storage
stance scan --storage s3 --s3-bucket my-stance-bucket

# GCP Cloud Storage
stance scan --storage gcs --gcs-bucket my-stance-bucket

# Azure Blob Storage
stance scan --storage azure --azure-container my-stance-container
```

## Best Practices

1. **Consistent Naming**: Use consistent tags/labels across clouds
2. **Centralized Storage**: Store all findings in one location
3. **Unified Alerting**: Configure alerts for all clouds
4. **Regular Comparison**: Compare security posture across clouds
5. **Document Differences**: Note cloud-specific security features

## Example: Full Multi-Cloud Scan

```bash
#!/bin/bash
# multi-cloud-scan.sh

# Set credentials (use secure methods in production)
export AWS_PROFILE=security-scanner
export GOOGLE_APPLICATION_CREDENTIALS=./gcp-sa.json
export AZURE_CLIENT_ID=$AZURE_CLIENT_ID

# Scan AWS
echo "Scanning AWS..."
stance scan --cloud aws --region us-east-1,us-west-2

# Scan GCP
echo "Scanning GCP..."
stance scan --cloud gcp --project my-project

# Scan Azure
echo "Scanning Azure..."
stance scan --cloud azure

# Generate combined report
echo "Generating report..."
stance report --format html > multi-cloud-report.html

# Show summary
stance findings --severity critical,high
```

## Troubleshooting

### Cloud-Specific Errors

**AWS: Access Denied**
- Check IAM permissions for the scanning role
- Verify the correct AWS profile is being used

**GCP: Permission Denied**
- Ensure service account has required roles
- Verify project ID is correct

**Azure: Authorization Failed**
- Check service principal permissions
- Verify subscription ID is correct

### Credential Issues

```bash
# Test AWS credentials
aws sts get-caller-identity

# Test GCP credentials
gcloud auth list

# Test Azure credentials
az account show
```

## Next Steps

- [Custom Policies](04-custom-policies.md) - Write cloud-agnostic policies
- [IaC Scanning](05-iac-scanning.md) - Scan infrastructure code
- [Alerting](06-alerting.md) - Configure cross-cloud alerts
