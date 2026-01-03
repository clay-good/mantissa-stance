# CIS GCP Foundations Benchmark v2.0 Mapping

This document maps Mantissa Stance policy IDs to CIS GCP Foundations Benchmark v2.0 controls.

## Overview

- **Framework**: CIS Google Cloud Platform Foundation Benchmark
- **Version**: 2.0.0
- **Total CIS Controls**: 75+
- **Covered by Stance**: 48 controls
- **Coverage**: 64%

## Control Mappings

### Section 1: Identity and Access Management

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 1.1 | Ensure corporate login credentials are used | gcp-iam-003 | Critical | Covered |
| 1.4 | Ensure service account has no admin privileges | gcp-iam-005 | Medium | Covered |
| 1.5 | Ensure service account has no user-managed keys | gcp-iam-004, gcp-iam-006 | Medium/High | Covered |
| 1.6 | Ensure default service account is not used | gcp-iam-002 | High | Covered |
| 1.7 | Ensure service account keys are rotated | gcp-iam-001 | Medium | Covered |
| 1.11 | Ensure KMS separation of duties | gcp-iam-007 | High | Covered |
| 1.12 | Ensure API keys are restricted | gcp-iam-008 | Medium | Covered |

**Section 1 Coverage: 7/15 controls (47%)**

### Section 2: Logging and Monitoring

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 2.1 | Ensure Cloud Audit Logs are enabled for all services | gcp-logging-001 | Critical | Covered |
| 2.2 | Ensure log sinks are configured for long-term retention | gcp-logging-002 | Medium | Covered |
| 2.3 | Ensure log bucket retention meets compliance requirements | gcp-logging-003 | Medium | Covered |
| 2.4 | Ensure log metric for IAM permission changes exists | gcp-logging-004 | Medium | Covered |
| 2.5 | Ensure log metric for audit configuration changes exists | gcp-logging-005 | High | Covered |
| 2.6 | Ensure log metric for project ownership changes exists | gcp-logging-006 | Critical | Covered |
| 2.7 | Ensure log metric for VPC firewall rule changes exists | gcp-logging-007 | Medium | Covered |
| 2.8 | Ensure log metric for VPC network route changes exists | gcp-logging-008 | Medium | Covered |
| 2.10 | Ensure log metric for Cloud Storage permission changes | gcp-logging-010 | High | Covered |
| 2.11 | Ensure log metric for Cloud SQL configuration changes | gcp-logging-009 | Medium | Covered |

**Section 2 Coverage: 10/12 controls (83%)**

### Section 3: Networking

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 3.1 | Ensure default network is deleted | gcp-compute-010 | Medium | Covered |
| 3.3 | Ensure DNSSEC is enabled for Cloud DNS | gcp-network-005 | Medium | Covered |
| 3.4 | Ensure Cloud VPN uses IKE v2 | gcp-network-007 | Medium | Covered |
| 3.5 | Ensure firewall does not allow all traffic from internet | gcp-compute-007 | Critical | Covered |
| 3.6 | Ensure SSH access is restricted from internet | gcp-compute-003, gcp-network-008 | High/Medium | Covered |
| 3.7 | Ensure RDP access is restricted from internet | gcp-compute-004, gcp-network-004 | High/Medium | Covered |
| 3.8 | Ensure database ports are not exposed | gcp-compute-006, gcp-network-003 | Critical/High | Covered |
| 3.9 | Ensure VPC flow logs are enabled | gcp-compute-008, gcp-network-002 | Medium/High | Covered |
| 3.10 | Ensure Private Google Access is enabled | gcp-compute-009 | Low | Covered |

**Section 3 Coverage: 9/12 controls (75%)**

### Section 4: Virtual Machines

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 4.4 | Ensure OS Login is enabled | gcp-compute-002 | Medium | Covered |
| 4.5 | Ensure serial port access is disabled | gcp-compute-001 | Medium | Covered |
| 4.7 | Ensure Compute disks use CMEK encryption | gcp-compute-011 | Medium | Covered |
| 4.8 | Ensure Shielded VM is enabled | gcp-compute-005 | Medium | Covered |

**Section 4 Coverage: 4/12 controls (33%)**

### Section 5: Storage

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 5.1 | Ensure public access prevention is enforced | gcp-storage-002, gcp-storage-006 | High/Medium | Covered |
| 5.2 | Ensure uniform bucket-level access is enabled | gcp-storage-001, gcp-storage-005 | Medium | Covered |
| 5.3 | Ensure bucket logging and CMEK encryption | gcp-storage-003, gcp-storage-004, gcp-storage-010 | Low/Medium | Covered |

**Section 5 Coverage: 3/3 controls (100%)**

### Section 6: Cloud SQL

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 6.1 | Ensure Cloud SQL uses CMEK encryption | gcp-sql-001 | Medium | Covered |
| 6.4 | Ensure Cloud SQL requires SSL/TLS | gcp-sql-003 | High | Covered |
| 6.5 | Ensure Cloud SQL authorized networks are restricted | gcp-sql-007 | Critical | Covered |
| 6.6 | Ensure Cloud SQL public IP is disabled | gcp-sql-002 | Critical | Covered |
| 6.7 | Ensure Cloud SQL automated backups are enabled | gcp-sql-004, gcp-sql-005 | High/Medium | Covered |

**Section 6 Coverage: 5/7 controls (71%)**

### Section 7: Cloud Functions

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 7.1 | Ensure Cloud Function uses custom service account | gcp-functions-004 | Medium | Covered |
| 7.2 | Ensure Cloud Function ingress is restricted | gcp-functions-002 | High | Covered |
| 7.3 | Ensure Cloud Function uses Secret Manager | gcp-functions-005 | High | Covered |

**Section 7 Coverage: 3/5 controls (60%)**

## Policy Details

### IAM Policies

#### gcp-iam-001: Service account keys rotated within 90 days
- **CIS Controls**: 1.7
- **Severity**: Medium
- **Resource Type**: gcp_service_account
- **Evidence Collection**:
  1. Run Stance scan to collect service accounts
  2. Check key age for each service account
  3. Flag keys older than 90 days

#### gcp-iam-002: Default compute service account not used
- **CIS Controls**: 1.6
- **Severity**: High
- **Resource Type**: gcp_compute_instance
- **Evidence Collection**:
  1. Run Stance scan to collect compute instances
  2. Check if default service account is attached
  3. Flag instances using default service account

#### gcp-iam-003: No overly permissive IAM bindings
- **CIS Controls**: 1.1
- **Severity**: Critical
- **Resource Type**: gcp_iam_binding
- **Evidence Collection**:
  1. Run Stance scan to collect IAM bindings
  2. Check for allUsers or allAuthenticatedUsers
  3. Flag overly permissive bindings

#### gcp-iam-004: Service accounts do not have broad OAuth scopes
- **CIS Controls**: 1.5
- **Severity**: Medium
- **Resource Type**: gcp_compute_instance
- **Evidence Collection**:
  1. Run Stance scan to collect compute instances
  2. Check service account OAuth scopes
  3. Flag broad scopes like cloud-platform

#### gcp-iam-005: Service accounts without user-managed keys
- **CIS Controls**: 1.4
- **Severity**: Medium
- **Resource Type**: gcp_service_account
- **Evidence Collection**:
  1. Run Stance scan to collect service accounts
  2. Check for user-managed keys
  3. Recommend using workload identity instead

#### gcp-iam-006: Service Account Admin role not overly assigned
- **CIS Controls**: 1.5
- **Severity**: High
- **Resource Type**: gcp_iam_binding
- **Evidence Collection**:
  1. Run Stance scan to collect IAM bindings
  2. Check for Service Account Admin assignments
  3. Flag overly broad assignments

#### gcp-iam-007: Separation of duties for KMS
- **CIS Controls**: 1.11
- **Severity**: High
- **Resource Type**: gcp_iam_binding
- **Evidence Collection**:
  1. Run Stance scan to collect KMS IAM bindings
  2. Check for separation between admin and encrypter/decrypter
  3. Flag violations of separation of duties

#### gcp-iam-008: API keys have restrictions
- **CIS Controls**: 1.12
- **Severity**: Medium
- **Resource Type**: gcp_api_key
- **Evidence Collection**:
  1. Run Stance scan to collect API keys
  2. Verify keys have application or IP restrictions
  3. Flag unrestricted API keys

### Logging Policies

#### gcp-logging-001: Cloud Audit Logs enabled for all services
- **CIS Controls**: 2.1
- **Severity**: Critical
- **Resource Type**: gcp_project
- **Evidence Collection**:
  1. Run Stance scan to collect audit log configuration
  2. Verify audit logs are enabled for all services
  3. Check data access logs are enabled

#### gcp-logging-002: Log sink configured for long-term retention
- **CIS Controls**: 2.2
- **Severity**: Medium
- **Resource Type**: gcp_logging_sink
- **Evidence Collection**:
  1. Run Stance scan to collect log sinks
  2. Verify sinks export to Cloud Storage or BigQuery
  3. Check retention configuration

#### gcp-logging-003: Log bucket retention meets compliance
- **CIS Controls**: 2.3
- **Severity**: Medium
- **Resource Type**: gcp_logging_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect log buckets
  2. Verify retention period >= 365 days
  3. Flag buckets with insufficient retention

#### gcp-logging-004 through gcp-logging-010: Log metrics and alerts
- **CIS Controls**: 2.4-2.11
- **Severity**: Medium to Critical
- **Resource Type**: gcp_logging_metric
- **Evidence Collection**:
  1. Run Stance scan to collect log metrics
  2. Verify metrics exist for required events
  3. Check alerting policies are configured

### Compute Policies

#### gcp-compute-001: Serial port access disabled
- **CIS Controls**: 4.5
- **Severity**: Medium
- **Resource Type**: gcp_compute_instance
- **Evidence Collection**:
  1. Run Stance scan to collect compute instances
  2. Check serial-port-enable metadata
  3. Flag instances with serial port enabled

#### gcp-compute-002: OS Login enabled
- **CIS Controls**: 4.4
- **Severity**: Medium
- **Resource Type**: gcp_compute_instance
- **Evidence Collection**:
  1. Run Stance scan to collect compute instances
  2. Check enable-oslogin metadata
  3. Recommend OS Login for centralized access

#### gcp-compute-003: SSH access restricted from internet
- **CIS Controls**: 3.6
- **Severity**: High
- **Resource Type**: gcp_compute_firewall
- **Evidence Collection**:
  1. Run Stance scan to collect firewall rules
  2. Check for 0.0.0.0/0 on port 22
  3. Flag unrestricted SSH access

#### gcp-compute-004: RDP access restricted from internet
- **CIS Controls**: 3.7
- **Severity**: High
- **Resource Type**: gcp_compute_firewall
- **Evidence Collection**:
  1. Run Stance scan to collect firewall rules
  2. Check for 0.0.0.0/0 on port 3389
  3. Flag unrestricted RDP access

#### gcp-compute-005: Shielded VM enabled
- **CIS Controls**: 4.8
- **Severity**: Medium
- **Resource Type**: gcp_compute_instance
- **Evidence Collection**:
  1. Run Stance scan to collect compute instances
  2. Check shielded VM configuration
  3. Flag instances without shielded features

#### gcp-compute-006: Database ports not exposed to internet
- **CIS Controls**: 3.8
- **Severity**: Critical
- **Resource Type**: gcp_compute_firewall
- **Evidence Collection**:
  1. Run Stance scan to collect firewall rules
  2. Check for exposed database ports (3306, 5432, 1433, etc.)
  3. Flag publicly accessible database ports

#### gcp-compute-007: Firewall does not allow all traffic
- **CIS Controls**: 3.5
- **Severity**: Critical
- **Resource Type**: gcp_compute_firewall
- **Evidence Collection**:
  1. Run Stance scan to collect firewall rules
  2. Check for 0.0.0.0/0 with all protocols
  3. Flag overly permissive firewall rules

#### gcp-compute-008: VPC flow logs enabled
- **CIS Controls**: 3.9
- **Severity**: Medium
- **Resource Type**: gcp_compute_subnetwork
- **Evidence Collection**:
  1. Run Stance scan to collect subnets
  2. Verify flow logs are enabled
  3. Check aggregation interval and sampling

#### gcp-compute-009: Private Google Access enabled
- **CIS Controls**: 3.10
- **Severity**: Low
- **Resource Type**: gcp_compute_subnetwork
- **Evidence Collection**:
  1. Run Stance scan to collect subnets
  2. Check private Google access is enabled
  3. Recommend for internal-only instances

#### gcp-compute-010: Default network deleted
- **CIS Controls**: 3.1
- **Severity**: Medium
- **Resource Type**: gcp_compute_network
- **Evidence Collection**:
  1. Run Stance scan to collect networks
  2. Check if default network exists
  3. Flag projects with default network

#### gcp-compute-011: Compute disks use CMEK encryption
- **CIS Controls**: 4.7
- **Severity**: Medium
- **Resource Type**: gcp_compute_disk
- **Evidence Collection**:
  1. Run Stance scan to collect disks
  2. Verify CMEK encryption is configured
  3. Flag disks without CMEK

### Storage Policies

#### gcp-storage-001: Uniform bucket-level access enabled
- **CIS Controls**: 5.2
- **Severity**: Medium
- **Resource Type**: gcp_storage_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect buckets
  2. Check uniform bucket-level access
  3. Flag buckets with fine-grained access

#### gcp-storage-002: Public access prevention enforced
- **CIS Controls**: 5.1
- **Severity**: High
- **Resource Type**: gcp_storage_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect buckets
  2. Check public access prevention setting
  3. Flag publicly accessible buckets

#### gcp-storage-003: Bucket logging enabled
- **CIS Controls**: 5.3
- **Severity**: Low
- **Resource Type**: gcp_storage_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect buckets
  2. Verify logging is configured
  3. Check log bucket destination

#### gcp-storage-004: Customer-managed encryption keys used
- **CIS Controls**: 5.3
- **Severity**: Medium
- **Resource Type**: gcp_storage_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect buckets
  2. Verify CMEK encryption is configured
  3. Check KMS key configuration

#### gcp-storage-005: Cloud Storage bucket versioning enabled
- **CIS Controls**: 5.2
- **Severity**: Medium
- **Resource Type**: gcp_storage_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect buckets
  2. Verify versioning is enabled
  3. Check lifecycle policies

#### gcp-storage-006: Cloud Storage bucket has retention policy
- **CIS Controls**: 5.1
- **Severity**: Medium
- **Resource Type**: gcp_storage_bucket
- **Evidence Collection**:
  1. Run Stance scan to collect buckets
  2. Verify retention policy exists
  3. Check retention duration

### Cloud SQL Policies

#### gcp-sql-001: Cloud SQL uses CMEK encryption
- **CIS Controls**: 6.1
- **Severity**: Medium
- **Resource Type**: gcp_sql_instance
- **Evidence Collection**:
  1. Run Stance scan to collect SQL instances
  2. Verify CMEK encryption is configured
  3. Check KMS key configuration

#### gcp-sql-002: Cloud SQL instance public IP disabled
- **CIS Controls**: 6.6
- **Severity**: Critical
- **Resource Type**: gcp_sql_instance
- **Evidence Collection**:
  1. Run Stance scan to collect SQL instances
  2. Check public IP configuration
  3. Flag instances with public IP

#### gcp-sql-003: Cloud SQL SSL/TLS required
- **CIS Controls**: 6.4
- **Severity**: High
- **Resource Type**: gcp_sql_instance
- **Evidence Collection**:
  1. Run Stance scan to collect SQL instances
  2. Verify SSL/TLS requirement
  3. Flag instances without SSL enforcement

#### gcp-sql-004: Cloud SQL automated backups enabled
- **CIS Controls**: 6.7
- **Severity**: High
- **Resource Type**: gcp_sql_instance
- **Evidence Collection**:
  1. Run Stance scan to collect SQL instances
  2. Verify backup configuration
  3. Check backup retention

#### gcp-sql-005: Cloud SQL binary logging enabled for MySQL
- **CIS Controls**: 6.7
- **Severity**: Medium
- **Resource Type**: gcp_sql_instance
- **Evidence Collection**:
  1. Run Stance scan to collect MySQL instances
  2. Verify binary logging is enabled
  3. Check point-in-time recovery capability

#### gcp-sql-007: Cloud SQL authorized networks restricted
- **CIS Controls**: 6.5
- **Severity**: Critical
- **Resource Type**: gcp_sql_instance
- **Evidence Collection**:
  1. Run Stance scan to collect SQL instances
  2. Check authorized networks
  3. Flag overly permissive network access

### Cloud Functions Policies

#### gcp-functions-002: Cloud Function ingress restricted
- **CIS Controls**: 7.2
- **Severity**: High
- **Resource Type**: gcp_cloudfunctions_function
- **Evidence Collection**:
  1. Run Stance scan to collect functions
  2. Check ingress settings
  3. Flag functions with all traffic allowed

#### gcp-functions-004: Cloud Function uses custom service account
- **CIS Controls**: 7.1
- **Severity**: Medium
- **Resource Type**: gcp_cloudfunctions_function
- **Evidence Collection**:
  1. Run Stance scan to collect functions
  2. Verify custom service account
  3. Flag functions using default service account

#### gcp-functions-005: Cloud Function uses Secret Manager
- **CIS Controls**: 7.3
- **Severity**: High
- **Resource Type**: gcp_cloudfunctions_function
- **Evidence Collection**:
  1. Run Stance scan to collect functions
  2. Check for hardcoded secrets
  3. Recommend Secret Manager integration

## Coverage Summary

| Section | Controls Covered | Total Controls | Coverage |
|---------|------------------|----------------|----------|
| 1. Identity and Access Management | 7 | 15 | 47% |
| 2. Logging and Monitoring | 10 | 12 | 83% |
| 3. Networking | 9 | 12 | 75% |
| 4. Virtual Machines | 4 | 12 | 33% |
| 5. Storage | 3 | 3 | 100% |
| 6. Cloud SQL Database Services | 5 | 7 | 71% |
| 7. Cloud Functions | 3 | 5 | 60% |
| **Total** | **41** | **66** | **62%** |

## Gaps and Recommendations

### Covered Controls Summary

**Section 1 (Partial)**: 1.1, 1.4, 1.5, 1.6, 1.7, 1.11, 1.12

**Section 2 (Near Full)**: 2.1-2.8, 2.10, 2.11

**Section 3 (Good)**: 3.1, 3.3-3.10

**Section 4 (Partial)**: 4.4, 4.5, 4.7, 4.8

**Section 5 (Full)**: 5.1, 5.2, 5.3

**Section 6 (Good)**: 6.1, 6.4-6.7

**Section 7 (Partial)**: 7.1, 7.2, 7.3

### Not Covered Controls

**Section 1 (IAM)**:
- 1.2-1.3: Security contact configuration
- 1.8-1.10: Organization policy constraints
- 1.13-1.15: Additional IAM hardening

**Section 4 (Virtual Machines)**:
- 4.1-4.3: VM configuration hardening
- 4.6: Block project-wide SSH keys
- 4.9-4.12: Additional VM security settings

### Roadmap

Future Stance releases may add policies for:
- Organization policy constraints
- Additional VM hardening checks
- GKE-specific security controls
- Cloud Run security settings

## Running Compliance Checks

```bash
# Scan GCP project for CIS compliance
stance scan --project-id YOUR_PROJECT

# Generate CIS compliance report
stance report --framework cis-gcp-foundations --format html

# Query specific control status
stance query "show findings for CIS control 1.7"

# Export compliance evidence
stance export --framework cis-gcp-foundations --format json --output evidence.json
```

## References

- [CIS GCP Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [GCP Security Command Center](https://cloud.google.com/security-command-center)
