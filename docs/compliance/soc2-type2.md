# SOC 2 Type II Compliance Mapping

This document maps Mantissa Stance policy IDs to SOC 2 Type II Trust Services Criteria (TSC).

## Overview

- **Framework**: SOC 2 Type II
- **Standard**: AICPA Trust Services Criteria
- **Trust Service Categories**: Security, Availability, Processing Integrity, Confidentiality, Privacy
- **Covered by Stance**: Security and Confidentiality categories

## Trust Services Criteria Categories

SOC 2 is organized around five Trust Services Categories:

1. **Security** (Common Criteria): Protection against unauthorized access
2. **Availability**: System availability for operation and use
3. **Processing Integrity**: System processing is complete and accurate
4. **Confidentiality**: Information designated as confidential is protected
5. **Privacy**: Personal information is collected and used appropriately

Stance primarily addresses **Security** and **Confidentiality** criteria.

## Control Mappings

### CC1: Control Environment

| Criteria | Description | Policy ID(s) | Cloud |
|----------|-------------|--------------|-------|
| CC1.3 | Management oversight | azure-identity-001 | Azure |
| CC1.4 | Accountability structures | gcp-iam-003, azure-identity-002 | GCP, Azure |

### CC5: Control Activities

| Criteria | Description | Policy ID(s) | Cloud |
|----------|-------------|--------------|-------|
| CC5.1 | Control activities defined | All policies | All |
| CC5.2 | Technology controls in place | All policies | All |

### CC6: Logical and Physical Access Controls

| Criteria | Description | Policy ID(s) | Cloud |
|----------|-------------|--------------|-------|
| CC6.1 | Logical access security software | aws-iam-001, aws-iam-002 | AWS |
| CC6.2 | New logical access provisioned | azure-identity-003 | Azure |
| CC6.3 | Logical access removed when no longer needed | azure-identity-001 | Azure |
| CC6.6 | Restrictions on access | All IAM policies | All |
| CC6.7 | Transmission encryption | azure-storage-001, azure-storage-002 | Azure |
| CC6.8 | Malicious software prevention | aws-ec2-003 | AWS |

### CC7: System Operations

| Criteria | Description | Policy ID(s) | Cloud |
|----------|-------------|--------------|-------|
| CC7.1 | Vulnerabilities detected and monitored | aws-ec2-001, aws-ec2-002, gcp-compute-003, gcp-compute-004 | AWS, GCP |
| CC7.2 | System components monitored | gcp-storage-003 | GCP |

### CC8: Change Management

| Criteria | Description | Policy ID(s) | Cloud |
|----------|-------------|--------------|-------|
| CC8.1 | Changes authorized, designed, developed, tested | - | Not Covered |

### C1: Confidentiality

| Criteria | Description | Policy ID(s) | Cloud |
|----------|-------------|--------------|-------|
| C1.1 | Confidential information identified | All encryption policies | All |
| C1.2 | Confidential information destroyed | - | Not Covered |

## Cross-Cloud Policy Mapping by SOC 2 Criteria

### CC6: Logical Access Controls

| SOC 2 Criteria | AWS Policy | GCP Policy | Azure Policy |
|----------------|------------|------------|--------------|
| CC6.1 Authentication | aws-iam-001, aws-iam-002 | gcp-iam-001 | - |
| CC6.3 Access Removal | - | gcp-iam-002 | azure-identity-001 |
| CC6.6 Access Restrictions | aws-ec2-001, aws-ec2-002 | gcp-compute-003, gcp-compute-004 | azure-compute-001, azure-compute-002 |
| CC6.7 Encryption | aws-s3-001 | gcp-storage-004 | azure-storage-001 |

### CC7: System Operations

| SOC 2 Criteria | AWS Policy | GCP Policy | Azure Policy |
|----------------|------------|------------|--------------|
| CC7.1 Detection | aws-ec2-001, aws-ec2-002 | gcp-compute-003, gcp-compute-004 | azure-compute-001, azure-compute-002 |
| CC7.2 Monitoring | - | gcp-storage-003 | - |

## Policy Details by SOC 2 Criteria

### CC6.1: Logical Access Security

#### aws-iam-001: Root Account MFA
- **SOC 2 Criteria**: CC6.1
- **Evidence Type**: Configuration screenshot, audit log
- **Evidence Collection**:
  1. Run Stance scan to capture MFA status
  2. Export finding with timestamp
  3. Document MFA device registration
  4. Provide configuration evidence to auditors

#### aws-iam-002: Password Policy
- **SOC 2 Criteria**: CC6.1
- **Evidence Type**: Policy configuration
- **Evidence Collection**:
  1. Run Stance scan to capture password policy
  2. Document complexity requirements
  3. Export policy configuration snapshot
  4. Track policy changes over time

### CC6.6: Access Restrictions

#### aws-ec2-001, aws-ec2-002: Security Group Restrictions
- **SOC 2 Criteria**: CC6.6
- **Evidence Type**: Firewall rules, access control lists
- **Evidence Collection**:
  1. Run Stance scan to capture security groups
  2. Document authorized access paths
  3. Flag unauthorized access configurations
  4. Export network access inventory

#### gcp-compute-003, gcp-compute-004: Firewall Restrictions
- **SOC 2 Criteria**: CC6.6
- **Evidence Type**: Firewall rules
- **Evidence Collection**:
  1. Run Stance scan to capture firewall rules
  2. Validate network segmentation
  3. Document allowed connections
  4. Export firewall configuration

### CC6.7: Encryption in Transit and at Rest

#### aws-s3-001: S3 Bucket Encryption
- **SOC 2 Criteria**: CC6.7, C1.1
- **Evidence Type**: Encryption configuration
- **Evidence Collection**:
  1. Run Stance scan to verify encryption
  2. Document encryption algorithm (AES-256)
  3. Track encryption key management
  4. Export encryption status report

#### azure-storage-001: Secure Transfer Required
- **SOC 2 Criteria**: CC6.7
- **Evidence Type**: Transport security configuration
- **Evidence Collection**:
  1. Run Stance scan to verify HTTPS enforcement
  2. Document TLS version requirements
  3. Flag insecure transfer settings
  4. Export transport security configuration

### CC7.1: Vulnerability Detection

#### Network Access Policies
- **SOC 2 Criteria**: CC7.1
- **Evidence Type**: Security scan results
- **Evidence Collection**:
  1. Run Stance scan to detect misconfigurations
  2. Document network exposure findings
  3. Track remediation status
  4. Export vulnerability report

## Auditor Evidence Package

### Required Evidence for SOC 2 Type II

1. **Population Lists**
   - All cloud assets discovered by Stance
   - All users and service accounts
   - All network access rules

2. **Configuration Evidence**
   - Stance finding reports
   - Policy compliance status
   - Encryption configuration

3. **Control Testing Evidence**
   - Scan results over the audit period
   - Remediation timelines
   - Exception documentation

### Generating Evidence

```bash
# Generate comprehensive SOC 2 evidence package
stance scan --all-clouds
stance report --framework soc2 --format html --output soc2-report.html
stance findings --format csv --output soc2-findings.csv

# Query specific criteria
stance query "show CC6.6 findings"
stance query "show encryption compliance status"
```

## Coverage Summary

| Trust Service Category | Criteria Covered | Total Criteria | Coverage |
|------------------------|------------------|----------------|----------|
| CC1: Control Environment | 2 | 5 | 40% |
| CC2: Communication | 0 | 3 | 0% |
| CC3: Risk Assessment | 0 | 4 | 0% |
| CC4: Monitoring | 0 | 2 | 0% |
| CC5: Control Activities | 2 | 3 | 67% |
| CC6: Logical Access | 5 | 8 | 63% |
| CC7: System Operations | 2 | 5 | 40% |
| CC8: Change Management | 0 | 1 | 0% |
| CC9: Risk Mitigation | 0 | 2 | 0% |
| C1: Confidentiality | 1 | 2 | 50% |
| **Total Security Criteria** | **12** | **35** | **34%** |

## Gaps and Recommendations

### Critical Gaps

1. **CC2-CC4**: Communication, risk assessment, and monitoring criteria
2. **CC8**: Change management validation
3. **A1-A3**: Availability criteria (system resilience)
4. **PI1**: Processing integrity criteria

### Recommendations

1. Implement CloudTrail/Audit Logs validation for CC7.2
2. Add backup and recovery policy validation for A1
3. Integrate with change management systems for CC8
4. Add data retention policy validation for C1.2

## SOC 2 Audit Preparation Checklist

- [ ] Run Stance scans weekly during audit period
- [ ] Export all findings to evidence repository
- [ ] Document remediation for all high-severity findings
- [ ] Generate trend reports showing control effectiveness
- [ ] Prepare exception documentation for any gaps
- [ ] Schedule walkthrough with auditors

## References

- [AICPA Trust Services Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/trustdataintegritytaskforce)
- [SOC 2 Compliance Guide](https://www.aicpa.org/resources/download/soc-2-reporting-on-an-examination-of-controls)
- [AWS SOC 2 Reports](https://aws.amazon.com/compliance/soc-faqs/)
- [GCP SOC 2 Compliance](https://cloud.google.com/security/compliance/soc-2)
- [Azure SOC 2 Compliance](https://docs.microsoft.com/en-us/azure/compliance/offerings/offering-soc-2)
