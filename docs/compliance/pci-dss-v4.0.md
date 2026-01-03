# PCI DSS v4.0 Compliance Mapping

This document maps Mantissa Stance policy IDs to Payment Card Industry Data Security Standard (PCI DSS) v4.0 requirements.

## Overview

- **Framework**: PCI DSS
- **Version**: 4.0
- **Total Requirements**: 12 main requirements with ~250 sub-requirements
- **Covered by Stance**: 75+ policies across all three clouds

## Applicability

PCI DSS applies to any organization that stores, processes, or transmits cardholder data. Stance helps validate cloud infrastructure security controls required for PCI DSS compliance.

## Requirement Mappings

### Requirement 1: Install and Maintain Network Security Controls

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 1.2.1 | Restrict traffic to that which is necessary | aws-ec2-007, gcp-compute-007, azure-compute-006, azure-compute-009 | All |
| 1.3.1 | Restrict inbound traffic | aws-ec2-006, aws-ec2-012, aws-lambda-002, aws-rds-005 | AWS |
| 1.3.1 | Restrict inbound traffic | gcp-compute-003, gcp-compute-004, gcp-compute-006, gcp-sql-002, gcp-sql-007 | GCP |
| 1.3.1 | Restrict inbound traffic | azure-compute-001, azure-compute-002, azure-compute-004, azure-compute-005, azure-compute-010, azure-sql-005 | Azure |
| 1.3.1 | Private endpoints for services | azure-functions-003, azure-functions-005, azure-network-006, gcp-functions-001, gcp-functions-002, gcp-network-006 | All |
| 1.3.2 | Restrict outbound traffic | aws-ec2-010 | AWS |
| 1.3.4 | Egress rules reviewed | aws-ec2-011 | AWS |

**Coverage: 25+ policies**

### Requirement 3: Protect Stored Account Data

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 3.4 | Render PAN unreadable (encryption) | aws-s3-001, aws-ec2-004, aws-rds-001, aws-rds-003, aws-lambda-001 | AWS |
| 3.4 | Render PAN unreadable (encryption) | gcp-functions-005 | GCP |
| 3.4 | Render PAN unreadable (encryption) | azure-compute-011, azure-sql-001, azure-storage-011 | Azure |
| 3.4 | Kubernetes secrets protection | k8s-rbac-003 | Kubernetes |
| 3.5.1 | Protect cryptographic keys | aws-cloudtrail-003, gcp-storage-004 | AWS, GCP |
| 3.6.1 | Customer-managed encryption keys | aws-s3-003, aws-rds-002, gcp-compute-011, gcp-sql-001, gcp-functions-007, gcp-iam-007 | AWS, GCP |
| 3.6.1 | Customer-managed encryption keys | azure-sql-002, azure-storage-005 | Azure |

**Coverage: 20+ policies**

### Requirement 4: Protect Cardholder Data with Strong Cryptography

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 4.2.1 | TLS/SSL for transmission | aws-apigateway-003, aws-elb-002 | AWS |
| 4.2.1 | TLS/SSL for transmission | gcp-network-002, gcp-network-003, gcp-sql-003 | GCP |
| 4.2.1 | TLS/SSL for transmission | azure-storage-001, azure-storage-002, azure-functions-001, azure-functions-006, azure-sql-007 | Azure |

**Coverage: 10+ policies**

### Requirement 5: Protect All Systems Against Malware

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 5.2 | Anti-malware solutions | azure-sql-004 (Advanced Threat Protection) | Azure |
| 5.2.1 | Protect against malware | gcp-compute-005 (Shielded VM) | GCP |

**Coverage: 2 policies**

### Requirement 6: Develop and Maintain Secure Systems

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 6.2.4 | Secure coding practices | IaC scanning policies | All |
| 6.3.3 | Secure development lifecycle | IaC scanning policies | All |
| 6.4.1 | Separate dev/test from production | vpc policies | All |
| 6.6 | WAF for public-facing apps | azure-network-001, azure-network-002, aws-apigateway-002 | AWS, Azure |

**Coverage: 5+ policies**

### Requirement 7: Restrict Access to System Components

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 7.1 | Access control model | aws-iam-006, gcp-iam-003, azure-identity-001 | All |
| 7.1.1 | Least privilege | gcp-iam-004, azure-identity-002 | GCP, Azure |
| 7.2.1 | Role-based access | aws-iam-007, aws-iam-008, gcp-iam-006, azure-identity-003 | All |

**Coverage: 10+ policies**

### Requirement 8: Identify Users and Authenticate Access

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 8.2.1 | Unique user IDs | gcp-iam-002 | GCP |
| 8.3.1 | MFA for admin access | aws-iam-001, aws-iam-004, azure-identity-006, azure-identity-007 | AWS, Azure |
| 8.3.6 | Password complexity | aws-iam-002, aws-iam-009, aws-iam-010 | AWS |
| 8.3.7 | Password history | aws-iam-009 | AWS |
| 8.3.9 | Credential rotation | aws-iam-003, gcp-iam-001, azure-identity-005 | All |

**Coverage: 12+ policies**

### Requirement 10: Log and Monitor All Access

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 10.2.1 | Audit log enabled | aws-cloudtrail-001, aws-cloudtrail-005, gcp-logging-001, azure-monitor-001, azure-monitor-002, azure-monitor-003 | All |
| 10.2.2 | User actions logged | gcp-logging-004, gcp-logging-005, gcp-logging-006, azure-monitor-005 | GCP, Azure |
| 10.2.4 | Invalid access attempts | aws-cloudwatch-002, gcp-logging-008, azure-monitor-006 | All |
| 10.2.5 | Privilege changes logged | aws-cloudwatch-003, gcp-logging-007, azure-monitor-007 | All |
| 10.2.6 | Audit log initialization | gcp-logging-009 | GCP |
| 10.2.7 | Creation/deletion logged | gcp-logging-010, azure-monitor-008, azure-monitor-009 | GCP, Azure |
| 10.5.1 | Audit log integrity | aws-cloudtrail-002, aws-cloudtrail-004 | AWS |
| 10.5.5 | Log encryption | aws-cloudtrail-003 | AWS |
| 10.6.1 | Audit log review | All alerting policies | All |
| 10.7 | Log retention | aws-cloudwatch-005, gcp-logging-002, gcp-logging-003, azure-monitor-001, azure-monitor-010 | All |

**Coverage: 25+ policies**

### Requirement 11: Test Security Systems Regularly

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 11.3 | Vulnerability scanning | Trivy integration, IaC scanning | All |
| 11.5 | Change detection | Drift detection policies | All |

**Coverage: 5+ policies**

### Requirement 12: Information Security Policy

| Control ID | Control Description | Policy ID(s) | Cloud |
|------------|---------------------|--------------|-------|
| 12.10.1 | Incident response | Alert routing (Slack, PagerDuty, Jira) | All |

**Coverage: Alert routing system**

## Coverage Summary

| PCI Requirement | Controls Covered | Coverage |
|-----------------|------------------|----------|
| 1. Network Security | 25+ policies | Good |
| 2. Secure Configuration | 5+ policies | Partial |
| 3. Protect Stored Data | 20+ policies | Good |
| 4. Encrypt Transmission | 10+ policies | Good |
| 5. Protect from Malware | 2 policies | Limited |
| 6. Secure Systems | 5+ policies | Partial |
| 7. Restrict Access | 10+ policies | Good |
| 8. Identify and Authenticate | 12+ policies | Good |
| 9. Restrict Physical Access | N/A | N/A |
| 10. Log and Monitor | 25+ policies | Excellent |
| 11. Test Security Systems | 5+ policies | Partial |
| 12. Information Security Policy | Alert system | Partial |

**Total: 75+ policies mapped to PCI DSS v4.0**

## Running PCI Compliance Checks

```bash
# Scan all clouds for PCI compliance
stance scan --framework pci-dss

# Generate PCI compliance report
stance report --framework pci-dss --format html

# Query specific requirement status
stance query "show PCI findings by requirement"

# Export evidence for auditors
stance findings --framework pci-dss --format csv --output pci-evidence.csv
```

## References

- [PCI DSS v4.0 Documentation](https://www.pcisecuritystandards.org/document_library/)
- [AWS PCI DSS Compliance](https://aws.amazon.com/compliance/pci-dss-level-1-faqs/)
- [GCP PCI DSS Compliance](https://cloud.google.com/security/compliance/pci-dss)
- [Azure PCI DSS Compliance](https://docs.microsoft.com/en-us/azure/compliance/offerings/offering-pci-dss)
