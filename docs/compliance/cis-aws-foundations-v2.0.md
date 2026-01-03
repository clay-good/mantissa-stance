# CIS AWS Foundations Benchmark v2.0 Mapping

This document maps Mantissa Stance policy IDs to CIS AWS Foundations Benchmark v2.0 controls.

## Overview

- **Framework**: CIS AWS Foundations Benchmark
- **Version**: 2.0.0
- **Total CIS Controls**: 63
- **Covered by Stance**: 43 controls
- **Coverage**: 68%

## Control Mappings

### Section 1: Identity and Access Management

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 1.4 | Ensure no 'root' user account access key exists | aws-iam-005 | Critical | Covered |
| 1.5 | Ensure MFA is enabled for the 'root' user account | aws-iam-001 | Critical | Covered |
| 1.8 | Ensure IAM password policy requires minimum length of 14 | aws-iam-002 | High | Covered |
| 1.9 | Ensure IAM password policy prevents password reuse | aws-iam-002 | High | Covered |
| 1.10 | Ensure MFA is enabled for all IAM users with console access | aws-iam-004 | High | Covered |
| 1.11 | Ensure IAM password policy expires passwords within 90 days | aws-iam-010 | Low | Covered |
| 1.12 | Ensure IAM password policy prevents password reuse | aws-iam-009 | Medium | Covered |
| 1.14 | Ensure access keys are rotated every 90 days or less | aws-iam-003 | Medium | Covered |
| 1.16 | Ensure IAM policies are attached only to groups or roles | aws-iam-006 | Low | Covered |
| 1.17 | Ensure a support role has been created for incident handling | aws-iam-007, aws-iam-008 | Medium | Covered |

**Section 1 Coverage: 10/22 controls (45%)**

### Section 2: Storage

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 2.1.1 | Ensure S3 bucket policy is set to deny HTTP requests | aws-s3-001 | High | Covered |
| 2.1.2 | Ensure S3 bucket uses KMS encryption / MFA Delete | aws-s3-003, aws-s3-005 | Medium/High | Covered |
| 2.1.3 | Ensure S3 bucket versioning is enabled | aws-s3-004 | Medium | Covered |
| 2.1.5 | Ensure S3 bucket public access is blocked | aws-s3-002 | Critical | Covered |
| 2.1.5 | Ensure S3 bucket requires SSL/TLS | aws-s3-007 | High | Covered |
| 2.2.1 | Ensure EBS volume encryption is enabled | aws-ec2-004 | Medium | Covered |
| 2.3.1 | Ensure RDS instances have encryption enabled | aws-rds-001 | High | Covered |
| 2.3.1 | Ensure RDS snapshots are encrypted | aws-rds-003 | High | Covered |
| 2.3.2 | Ensure RDS instances are not publicly accessible | aws-rds-005 | Critical | Covered |
| 2.3.3 | Ensure RDS backup retention is at least 7 days | aws-rds-007 | High | Covered |

**Section 2 Coverage: 10/10 controls (100%)**

### Section 3: Logging

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 3.1 | Ensure CloudTrail is enabled in all regions | aws-cloudtrail-001 | Critical | Covered |
| 3.2 | Ensure CloudTrail log file validation is enabled | aws-cloudtrail-002 | High | Covered |
| 3.3 | Ensure CloudTrail S3 bucket is not publicly accessible | aws-cloudtrail-004 | Critical | Covered |
| 3.4 | Ensure CloudTrail logs are integrated with CloudWatch | aws-cloudtrail-005 | Medium | Covered |
| 3.4 | Ensure CloudWatch log groups have retention configured | aws-cloudwatch-005 | Low | Covered |
| 3.6 | Ensure S3 bucket access logging is enabled | aws-s3-006 | Medium | Covered |
| 3.6 | Ensure ALB access logging is enabled | aws-elb-001 | Medium | Covered |
| 3.7 | Ensure CloudTrail logs are encrypted with KMS CMK | aws-cloudtrail-003 | High | Covered |
| 3.7 | Ensure ALB uses HTTPS listeners | aws-elb-002 | High | Covered |
| 3.9 | Ensure VPC flow logging is enabled in all VPCs | aws-ec2-005 | Medium | Covered |
| 3.9 | Ensure API Gateway REST API logging is enabled | aws-apigateway-001 | Medium | Covered |
| 3.10 | Ensure API Gateway authorization is configured | aws-apigateway-004 | Critical | Covered |

**Section 3 Coverage: 11/11 controls (100%)**

### Section 4: Monitoring

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 4.1 | Ensure alarm for unauthorized API calls | aws-cloudwatch-002 | Medium | Covered |
| 4.3 | Ensure alarm for root account usage | aws-cloudwatch-001 | High | Covered |
| 4.4 | Ensure alarm for IAM policy changes | aws-cloudwatch-003 | Medium | Covered |
| 4.10 | Ensure alarm for security group changes | aws-cloudwatch-004 | Medium | Covered |

**Section 4 Coverage: 4/16 controls (25%)**

### Section 5: Networking

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 5.1 | Ensure no security groups allow unrestricted inbound | aws-ec2-007, aws-ec2-012 | Critical/High | Covered |
| 5.2 | Ensure no security groups allow ingress 0.0.0.0/0 to SSH | aws-ec2-001 | High | Covered |
| 5.3 | Ensure no security groups allow ingress 0.0.0.0/0 to RDP | aws-ec2-002 | High | Covered |
| 5.4 | Ensure database ports are not exposed to internet | aws-ec2-006 | Critical | Covered |
| 5.5 | Ensure default VPC is not used for production | aws-ec2-008 | Low | Covered |
| 5.6 | Ensure subnet auto-assign public IP is disabled | aws-ec2-009 | Medium | Covered |

**Section 5 Coverage: 6/6 controls (100%)**

## Policy Details

### IAM Policies

#### aws-iam-001: Root account MFA enabled
- **CIS Controls**: 1.5
- **Severity**: Critical
- **Resource Type**: aws_iam_account_summary
- **Evidence Collection**:
  1. Run Stance scan to collect IAM account summary
  2. Check `account_mfa_enabled` field in scan results
  3. Export finding with timestamp for audit trail

#### aws-iam-002: IAM password policy strength
- **CIS Controls**: 1.8, 1.9
- **Severity**: High
- **Resource Type**: aws_iam_account_password_policy
- **Evidence Collection**:
  1. Run Stance scan to collect password policy
  2. Verify minimum_password_length >= 14
  3. Verify require_symbols, require_numbers, require_uppercase, require_lowercase
  4. Export policy configuration snapshot

#### aws-iam-003: Access keys rotated within 90 days
- **CIS Controls**: 1.14
- **Severity**: Medium
- **Resource Type**: aws_iam_user
- **Evidence Collection**:
  1. Run Stance scan to collect IAM users
  2. Check access key age for each user
  3. Flag keys older than 90 days

#### aws-iam-004: MFA enabled for IAM users
- **CIS Controls**: 1.10
- **Severity**: High
- **Resource Type**: aws_iam_user
- **Evidence Collection**:
  1. Run Stance scan to collect IAM users
  2. Check mfa_enabled field for users with console access
  3. Export list of users without MFA

#### aws-iam-005: No root access keys
- **CIS Controls**: 1.4
- **Severity**: Critical
- **Resource Type**: aws_iam_account_summary
- **Evidence Collection**:
  1. Run Stance scan to collect IAM account summary
  2. Check for presence of root access keys
  3. Export finding if root keys exist

#### aws-iam-006: No inline policies on users
- **CIS Controls**: 1.16
- **Severity**: Low
- **Resource Type**: aws_iam_user
- **Evidence Collection**:
  1. Run Stance scan to collect IAM users
  2. Check for inline policies attached to users
  3. Recommend using groups or roles instead

#### aws-iam-007: Cross-account trust reviewed
- **CIS Controls**: 1.17
- **Severity**: Medium
- **Resource Type**: aws_iam_role
- **Evidence Collection**:
  1. Run Stance scan to collect IAM roles
  2. Identify roles with cross-account trust policies
  3. Review trust relationships for appropriateness

#### aws-iam-008: External trust reviewed
- **CIS Controls**: 1.17
- **Severity**: Medium
- **Resource Type**: aws_iam_role
- **Evidence Collection**:
  1. Run Stance scan to collect IAM roles
  2. Identify roles with external account trust
  3. Verify external accounts are authorized

#### aws-iam-009: Password reuse prevention
- **CIS Controls**: 1.12
- **Severity**: Medium
- **Resource Type**: aws_iam_account_password_policy
- **Evidence Collection**:
  1. Run Stance scan to collect password policy
  2. Verify password_reuse_prevention >= 24

#### aws-iam-010: Password expiration
- **CIS Controls**: 1.11
- **Severity**: Low
- **Resource Type**: aws_iam_account_password_policy
- **Evidence Collection**:
  1. Run Stance scan to collect password policy
  2. Verify max_password_age <= 90 days

### Storage Policies

#### aws-s3-001: S3 bucket encryption enabled
- **CIS Controls**: 2.1.1
- **Severity**: High
- **Resource Type**: aws_s3_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect S3 bucket configurations
  2. Check encryption.enabled field for each bucket
  3. Document encryption type (SSE-S3 or SSE-KMS)

#### aws-s3-002: S3 public access blocked
- **CIS Controls**: 2.1.5
- **Severity**: Critical
- **Resource Type**: aws_s3_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect S3 bucket configurations
  2. Verify public_access_block settings are enabled

#### aws-s3-003: S3 bucket uses KMS encryption
- **CIS Controls**: 2.1.2
- **Severity**: Medium
- **Resource Type**: aws_s3_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect S3 buckets
  2. Verify KMS CMK encryption is configured

#### aws-s3-004: S3 versioning enabled
- **CIS Controls**: 2.1.3
- **Severity**: Medium
- **Resource Type**: aws_s3_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect S3 buckets
  2. Verify versioning is enabled for each bucket

#### aws-s3-005: S3 MFA delete enabled
- **CIS Controls**: 2.1.2
- **Severity**: High
- **Resource Type**: aws_s3_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect S3 buckets
  2. Verify MFA delete is enabled

#### aws-s3-006: S3 access logging enabled
- **CIS Controls**: 3.6
- **Severity**: Medium
- **Resource Type**: aws_s3_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect S3 buckets
  2. Verify access logging is configured

#### aws-s3-007: S3 SSL/TLS required
- **CIS Controls**: 2.1.5
- **Severity**: High
- **Resource Type**: aws_s3_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect S3 buckets
  2. Verify bucket policy requires SSL

### CloudTrail Policies

#### aws-cloudtrail-001: CloudTrail enabled in all regions
- **CIS Controls**: 3.1
- **Severity**: Critical
- **Resource Type**: aws_cloudtrail
- **Evidence Collection**:
  1. Run Stance scan to collect CloudTrail configuration
  2. Verify multi-region trail is enabled and logging

#### aws-cloudtrail-002: Log file validation enabled
- **CIS Controls**: 3.2
- **Severity**: High
- **Resource Type**: aws_cloudtrail
- **Evidence Collection**:
  1. Run Stance scan to collect CloudTrail configuration
  2. Verify log_file_validation_enabled is true

#### aws-cloudtrail-003: CloudTrail logs encrypted
- **CIS Controls**: 3.7
- **Severity**: High
- **Resource Type**: aws_cloudtrail
- **Evidence Collection**:
  1. Run Stance scan to collect CloudTrail configuration
  2. Verify KMS key is configured for log encryption

#### aws-cloudtrail-004: CloudTrail S3 bucket not public
- **CIS Controls**: 3.3
- **Severity**: Critical
- **Resource Type**: aws_cloudtrail
- **Evidence Collection**:
  1. Run Stance scan to collect CloudTrail configuration
  2. Verify S3 bucket is not publicly accessible

#### aws-cloudtrail-005: CloudWatch integration
- **CIS Controls**: 3.4
- **Severity**: Medium
- **Resource Type**: aws_cloudtrail
- **Evidence Collection**:
  1. Run Stance scan to collect CloudTrail configuration
  2. Verify CloudWatch Logs group is configured

### CloudWatch Policies

#### aws-cloudwatch-001: Alarm for root account usage
- **CIS Controls**: 4.3
- **Severity**: High
- **Resource Type**: aws_cloudwatch_metric_alarm
- **Evidence Collection**:
  1. Run Stance scan to collect CloudWatch alarms
  2. Verify alarm for root login exists

#### aws-cloudwatch-002: Alarm for unauthorized API calls
- **CIS Controls**: 4.1
- **Severity**: Medium
- **Resource Type**: aws_cloudwatch_metric_alarm
- **Evidence Collection**:
  1. Run Stance scan to collect CloudWatch alarms
  2. Verify alarm for unauthorized API calls exists

#### aws-cloudwatch-003: Alarm for IAM policy changes
- **CIS Controls**: 4.4
- **Severity**: Medium
- **Resource Type**: aws_cloudwatch_metric_alarm
- **Evidence Collection**:
  1. Run Stance scan to collect CloudWatch alarms
  2. Verify alarm for IAM changes exists

#### aws-cloudwatch-004: Alarm for security group changes
- **CIS Controls**: 4.10
- **Severity**: Medium
- **Resource Type**: aws_cloudwatch_metric_alarm
- **Evidence Collection**:
  1. Run Stance scan to collect CloudWatch alarms
  2. Verify alarm for security group changes exists

#### aws-cloudwatch-005: Log group retention configured
- **CIS Controls**: 3.4
- **Severity**: Low
- **Resource Type**: aws_cloudwatch_log_group
- **Evidence Collection**:
  1. Run Stance scan to collect CloudWatch log groups
  2. Verify retention policy is configured

### EC2 / Networking Policies

#### aws-ec2-001: SSH access restricted
- **CIS Controls**: 5.2
- **Severity**: High
- **Resource Type**: aws_security_group
- **Evidence Collection**:
  1. Run Stance scan to collect security groups
  2. Check for 0.0.0.0/0 on port 22

#### aws-ec2-002: RDP access restricted
- **CIS Controls**: 5.3
- **Severity**: High
- **Resource Type**: aws_security_group
- **Evidence Collection**:
  1. Run Stance scan to collect security groups
  2. Check for 0.0.0.0/0 on port 3389

#### aws-ec2-004: EBS encryption enabled
- **CIS Controls**: 2.2.1
- **Severity**: Medium
- **Resource Type**: aws_ebs_volume
- **Evidence Collection**:
  1. Run Stance scan to collect EBS volumes
  2. Verify encryption is enabled

#### aws-ec2-005: VPC flow logs enabled
- **CIS Controls**: 3.9
- **Severity**: Medium
- **Resource Type**: aws_vpc
- **Evidence Collection**:
  1. Run Stance scan to collect VPCs
  2. Verify flow logs are enabled

#### aws-ec2-006: Database ports not exposed
- **CIS Controls**: 5.4
- **Severity**: Critical
- **Resource Type**: aws_security_group
- **Evidence Collection**:
  1. Run Stance scan to collect security groups
  2. Check for exposed database ports (3306, 5432, 1433, etc.)

#### aws-ec2-007: No unrestricted inbound
- **CIS Controls**: 5.1
- **Severity**: Critical
- **Resource Type**: aws_security_group
- **Evidence Collection**:
  1. Run Stance scan to collect security groups
  2. Check for 0.0.0.0/0 with all protocols

#### aws-ec2-008: Default VPC not used
- **CIS Controls**: 5.5
- **Severity**: Low
- **Resource Type**: aws_vpc
- **Evidence Collection**:
  1. Run Stance scan to collect VPCs
  2. Identify resources in default VPC

#### aws-ec2-009: Subnet auto-assign public IP disabled
- **CIS Controls**: 5.6
- **Severity**: Medium
- **Resource Type**: aws_subnet
- **Evidence Collection**:
  1. Run Stance scan to collect subnets
  2. Verify auto-assign public IP is disabled

#### aws-ec2-012: Network ACL unrestricted inbound
- **CIS Controls**: 5.1
- **Severity**: High
- **Resource Type**: aws_network_acl
- **Evidence Collection**:
  1. Run Stance scan to collect network ACLs
  2. Check for unrestricted inbound rules

### RDS Policies

#### aws-rds-001: RDS storage encryption
- **CIS Controls**: 2.3.1
- **Severity**: High
- **Resource Type**: aws_rds_instance
- **Evidence Collection**:
  1. Run Stance scan to collect RDS instances
  2. Verify storage encryption is enabled

#### aws-rds-003: RDS snapshot encryption
- **CIS Controls**: 2.3.1
- **Severity**: High
- **Resource Type**: aws_rds_snapshot
- **Evidence Collection**:
  1. Run Stance scan to collect RDS snapshots
  2. Verify snapshots are encrypted

#### aws-rds-005: RDS not publicly accessible
- **CIS Controls**: 2.3.2
- **Severity**: Critical
- **Resource Type**: aws_rds_instance
- **Evidence Collection**:
  1. Run Stance scan to collect RDS instances
  2. Verify publicly_accessible is false

#### aws-rds-007: RDS backup retention
- **CIS Controls**: 2.3.3
- **Severity**: High
- **Resource Type**: aws_rds_instance
- **Evidence Collection**:
  1. Run Stance scan to collect RDS instances
  2. Verify backup_retention_period >= 7

### Load Balancer Policies

#### aws-elb-001: ALB access logging enabled
- **CIS Controls**: 3.6
- **Severity**: Medium
- **Resource Type**: aws_alb
- **Evidence Collection**:
  1. Run Stance scan to collect ALBs
  2. Verify access logs are enabled

#### aws-elb-002: ALB HTTPS only
- **CIS Controls**: 3.7
- **Severity**: High
- **Resource Type**: aws_alb
- **Evidence Collection**:
  1. Run Stance scan to collect ALBs
  2. Verify HTTPS listeners are configured

### API Gateway Policies

#### aws-apigateway-001: API Gateway logging enabled
- **CIS Controls**: 3.9
- **Severity**: Medium
- **Resource Type**: aws_apigateway_rest_api
- **Evidence Collection**:
  1. Run Stance scan to collect API Gateways
  2. Verify logging is enabled

#### aws-apigateway-004: API Gateway authorization
- **CIS Controls**: 3.10
- **Severity**: Critical
- **Resource Type**: aws_apigateway_rest_api
- **Evidence Collection**:
  1. Run Stance scan to collect API Gateways
  2. Verify authorization is configured

## Coverage Summary

| Section | Controls Covered | Total Controls | Coverage |
|---------|------------------|----------------|----------|
| 1. Identity and Access Management | 10 | 22 | 45% |
| 2. Storage | 10 | 10 | 100% |
| 3. Logging | 11 | 11 | 100% |
| 4. Monitoring | 4 | 16 | 25% |
| 5. Networking | 6 | 6 | 100% |
| **Total** | **41** | **65** | **63%** |

## Gaps and Recommendations

### Covered Controls Summary

The following CIS controls are fully covered by Mantissa Stance:

**Section 1 (Partial)**: 1.4, 1.5, 1.8, 1.9, 1.10, 1.11, 1.12, 1.14, 1.16, 1.17

**Section 2 (Full)**: 2.1.1, 2.1.2, 2.1.3, 2.1.5, 2.2.1, 2.3.1, 2.3.2, 2.3.3

**Section 3 (Full)**: 3.1, 3.2, 3.3, 3.4, 3.6, 3.7, 3.9, 3.10

**Section 4 (Partial)**: 4.1, 4.3, 4.4, 4.10

**Section 5 (Full)**: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6

### Not Covered Controls

The following high-priority CIS controls are not yet covered:

**Section 1 (IAM)**:
- 1.1-1.3: Credential report and initial account setup
- 1.6-1.7: Hardware MFA and access analyzer
- 1.13: Certificate rotation
- 1.15: Organizations SCP
- 1.18-1.22: Additional IAM hardening

**Section 4 (Monitoring)**:
- 4.2, 4.5-4.9, 4.11-4.16: Additional CloudWatch alarms for:
  - Console sign-in without MFA
  - Network gateway changes
  - Route table changes
  - VPC changes
  - AWS Organizations changes
  - Config changes

### Roadmap

Future Stance releases may add policies for:
- AWS Organizations and SCP policies
- Additional CloudWatch monitoring alarms
- AWS Config rule compliance
- Hardware MFA verification
- IAM Access Analyzer integration

## Running Compliance Checks

```bash
# Scan AWS account for CIS compliance
stance scan --account-id YOUR_ACCOUNT

# Generate CIS compliance report
stance report --framework cis-aws-foundations --format html

# Query specific control status
stance query "show findings for CIS control 1.5"

# Export compliance evidence
stance export --framework cis-aws-foundations --format json --output evidence.json
```

## References

- [CIS AWS Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
