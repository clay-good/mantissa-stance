# HIPAA Security Rule Compliance Mapping

This document maps Mantissa Stance policy IDs to HIPAA Security Rule requirements for protecting electronic Protected Health Information (ePHI).

## Overview

- **Framework**: HIPAA Security Rule
- **Regulation**: 45 CFR Part 160 and Subparts A and C of Part 164
- **Applicability**: Covered Entities and Business Associates handling ePHI
- **Covered by Stance**: Technical Safeguards

## HIPAA Security Rule Structure

The HIPAA Security Rule is organized into three safeguard categories:

1. **Administrative Safeguards** (164.308): Policies and procedures
2. **Physical Safeguards** (164.310): Physical access controls
3. **Technical Safeguards** (164.312): Technology-based protections

Stance primarily addresses **Technical Safeguards** requirements.

## Control Mappings

### 164.308 Administrative Safeguards

| Standard | Implementation Spec | Policy ID(s) | Cloud |
|----------|---------------------|--------------|-------|
| 164.308(a)(1)(ii)(B) | Risk Management | All policies | All |
| 164.308(a)(3)(ii)(A) | Authorization/Supervision | azure-identity-001 | Azure |
| 164.308(a)(4)(ii)(B) | Access Authorization | gcp-iam-003, azure-identity-002 | GCP, Azure |
| 164.308(a)(4)(ii)(C) | Access Establishment and Modification | azure-identity-003 | Azure |

### 164.312 Technical Safeguards

| Standard | Implementation Spec | Policy ID(s) | Cloud |
|----------|---------------------|--------------|-------|
| 164.312(a)(1) | Access Control | All IAM policies | All |
| 164.312(a)(2)(i) | Unique User Identification | aws-iam-001, aws-iam-002 | AWS |
| 164.312(a)(2)(iii) | Automatic Logoff | - | Not Covered |
| 164.312(a)(2)(iv) | Encryption and Decryption | aws-s3-001, gcp-storage-004, azure-storage-001 | All |
| 164.312(b) | Audit Controls | gcp-storage-003 | GCP |
| 164.312(c)(1) | Integrity | aws-s3-001 | AWS |
| 164.312(d) | Person or Entity Authentication | aws-iam-001 | AWS |
| 164.312(e)(1) | Transmission Security | azure-storage-001, azure-storage-002 | Azure |
| 164.312(e)(2)(i) | Integrity Controls | - | Not Covered |
| 164.312(e)(2)(ii) | Encryption | All encryption policies | All |

## Cross-Cloud Policy Mapping by HIPAA Standard

### 164.312(a)(1) Access Control

| HIPAA Requirement | AWS Policy | GCP Policy | Azure Policy |
|-------------------|------------|------------|--------------|
| Unique User ID | aws-iam-001, aws-iam-002 | gcp-iam-001, gcp-iam-002 | azure-identity-001 |
| Emergency Access | - | - | - |
| Automatic Logoff | - | - | - |
| Encryption | aws-s3-001, aws-ec2-004 | gcp-storage-004 | azure-storage-001 |

### 164.312(e)(1) Transmission Security

| HIPAA Requirement | AWS Policy | GCP Policy | Azure Policy |
|-------------------|------------|------------|--------------|
| Integrity Controls | - | - | - |
| Encryption | - | - | azure-storage-001, azure-storage-002 |
| Network Protection | aws-ec2-001, aws-ec2-002 | gcp-compute-003, gcp-compute-004 | azure-compute-001, azure-compute-002 |

## Policy Details by HIPAA Standard

### 164.312(a)(2)(i) Unique User Identification

#### aws-iam-001: Root Account MFA
- **HIPAA Standard**: 164.312(a)(2)(i), 164.312(d)
- **Requirement**: Assign a unique name and/or number for identifying and tracking user identity
- **Evidence Collection**:
  1. Run Stance scan to verify MFA on root account
  2. Document authentication mechanisms
  3. Export user identity configuration
  4. Maintain audit trail of access attempts

#### aws-iam-002: Password Policy
- **HIPAA Standard**: 164.312(a)(2)(i)
- **Requirement**: Procedures for creating, changing, and safeguarding passwords
- **Evidence Collection**:
  1. Run Stance scan to capture password policy
  2. Document password complexity requirements
  3. Verify password rotation policies
  4. Export password policy configuration

### 164.312(a)(2)(iv) Encryption and Decryption

#### aws-s3-001: S3 Bucket Encryption
- **HIPAA Standard**: 164.312(a)(2)(iv), 164.312(e)(2)(ii)
- **Requirement**: Implement mechanism to encrypt and decrypt ePHI
- **Evidence Collection**:
  1. Run Stance scan to verify encryption at rest
  2. Document encryption algorithm (AES-256)
  3. Verify key management procedures
  4. Export encryption configuration

#### gcp-storage-004: Customer-Managed Encryption
- **HIPAA Standard**: 164.312(a)(2)(iv)
- **Requirement**: Encryption of ePHI at rest
- **Evidence Collection**:
  1. Run Stance scan to verify CMEK configuration
  2. Document key rotation schedule
  3. Verify key access controls
  4. Export key management configuration

#### azure-storage-001: Secure Transfer Required
- **HIPAA Standard**: 164.312(e)(2)(ii)
- **Requirement**: Encryption mechanism to guard against unauthorized access during transmission
- **Evidence Collection**:
  1. Run Stance scan to verify HTTPS enforcement
  2. Document TLS version requirements
  3. Verify encryption in transit settings
  4. Export transport security configuration

### 164.312(b) Audit Controls

#### gcp-storage-003: Bucket Logging Enabled
- **HIPAA Standard**: 164.312(b)
- **Requirement**: Implement mechanisms to record and examine activity in systems containing ePHI
- **Evidence Collection**:
  1. Run Stance scan to verify logging configuration
  2. Document log retention periods
  3. Verify log integrity protection
  4. Export logging configuration status

### 164.312(e)(1) Transmission Security

#### Network Access Policies
- **HIPAA Standard**: 164.312(e)(1)
- **Requirement**: Technical security measures to guard against unauthorized access during transmission
- **Evidence Collection**:
  1. Run Stance scan for network exposure
  2. Document firewall rules and NSG configurations
  3. Verify network segmentation
  4. Export network security configuration

## ePHI Protection Checklist

### Data at Rest
- [ ] S3 buckets containing ePHI encrypted (aws-s3-001)
- [ ] EBS volumes encrypted (aws-ec2-004)
- [ ] Cloud Storage buckets encrypted with CMEK (gcp-storage-004)
- [ ] Azure Storage accounts encrypted (azure-storage-001)

### Data in Transit
- [ ] HTTPS required for storage access (azure-storage-001)
- [ ] TLS 1.2 minimum enforced (azure-storage-002)
- [ ] Network access restricted to authorized sources (all network policies)

### Access Control
- [ ] MFA enabled for privileged accounts (aws-iam-001)
- [ ] Strong password policies enforced (aws-iam-002)
- [ ] Service account keys rotated (gcp-iam-001)
- [ ] Least privilege access enforced (gcp-iam-003, gcp-iam-004, azure-identity-002)

### Audit and Monitoring
- [ ] Storage access logging enabled (gcp-storage-003)
- [ ] Audit trails maintained
- [ ] Access reviews conducted (azure-identity-001)

## Coverage Summary

| HIPAA Standard | Specification | Covered | Total | Coverage |
|----------------|---------------|---------|-------|----------|
| 164.308 Administrative | Implementation Specs | 4 | 22 | 18% |
| 164.310 Physical | Implementation Specs | 0 | 10 | 0% |
| 164.312 Technical | Implementation Specs | 7 | 13 | 54% |
| **Total** | | **11** | **45** | **24%** |

## Gaps and Recommendations

### Critical Gaps

1. **164.312(a)(2)(ii)**: Emergency access procedures
2. **164.312(a)(2)(iii)**: Automatic logoff configuration
3. **164.312(c)(2)**: Mechanism to authenticate ePHI
4. **164.312(e)(2)(i)**: Integrity controls for transmission

### Required But Not Implemented

1. Automatic session timeout validation
2. Data integrity verification (checksums, hashes)
3. Backup and disaster recovery validation
4. Workstation security policies

### Recommendations

1. Integrate with AWS CloudTrail for comprehensive audit logging
2. Add session management policy validation
3. Implement backup encryption verification
4. Add data classification tagging validation

## Business Associate Considerations

When using cloud services for ePHI:

1. Ensure Business Associate Agreement (BAA) is in place with cloud provider
2. Document shared responsibility for security controls
3. Maintain evidence of cloud provider compliance (SOC 2, HITRUST)
4. Regularly review cloud provider security controls

## Running HIPAA Compliance Checks

```bash
# Scan for HIPAA compliance
stance scan --framework hipaa

# Generate HIPAA compliance report
stance report --framework hipaa --format html --output hipaa-report.html

# Query ePHI protection status
stance query "show encryption status for all storage"
stance query "show access control findings"

# Export findings for compliance review
stance findings --framework hipaa --severity high --format csv
```

## HIPAA Risk Assessment Support

Stance findings can support your HIPAA risk assessment:

1. **Asset Inventory**: Identify all systems that may contain ePHI
2. **Vulnerability Identification**: Detect misconfigurations that could expose ePHI
3. **Risk Quantification**: Severity ratings help prioritize remediation
4. **Control Validation**: Verify technical safeguards are in place

## References

- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [HIPAA Security Rule Guidance](https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html)
- [AWS HIPAA Compliance](https://aws.amazon.com/compliance/hipaa-compliance/)
- [GCP HIPAA Compliance](https://cloud.google.com/security/compliance/hipaa)
- [Azure HIPAA Compliance](https://docs.microsoft.com/en-us/azure/compliance/offerings/offering-hipaa-us)
