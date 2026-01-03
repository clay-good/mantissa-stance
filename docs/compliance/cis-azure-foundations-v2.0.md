# CIS Azure Foundations Benchmark v2.0 Mapping

This document maps Mantissa Stance policy IDs to CIS Microsoft Azure Foundations Benchmark v2.0 controls.

## Overview

- **Framework**: CIS Microsoft Azure Foundations Benchmark
- **Version**: 2.0.0
- **Total CIS Controls**: 100+
- **Covered by Stance**: 55 controls
- **Coverage**: 55%

## Control Mappings

### Section 1: Identity and Access Management

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 1.1.1 | Ensure MFA is required for all users | azure-identity-006 | Critical | Covered |
| 1.1.2 | Ensure MFA is required for admin roles | azure-identity-007 | Critical | Covered |
| 1.1.3 | Ensure legacy authentication is blocked | azure-identity-009 | High | Covered |
| 1.11 | Ensure service principal secrets are rotated | azure-identity-005 | Medium | Covered |
| 1.13 | Ensure guest user access is restricted | azure-identity-004 | Medium | Covered |
| 1.21 | Ensure custom roles do not have wildcard permissions | azure-identity-002 | High | Covered |
| 1.22 | Ensure role assignments are scoped appropriately | azure-identity-003, azure-identity-008 | Medium | Covered |
| 1.23 | Ensure privileged role assignments are reviewed | azure-identity-001 | High | Covered |

**Section 1 Coverage: 8/25 controls (32%)**

### Section 3: Storage Accounts

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 3.1 | Ensure secure transfer required is enabled | azure-storage-001 | High | Covered |
| 3.3 | Ensure storage infrastructure encryption is enabled | azure-storage-011 | Medium | Covered |
| 3.5 | Ensure public blob access is disabled | azure-storage-003 | Critical | Covered |
| 3.6 | Ensure network access is restricted | azure-storage-004 | High | Covered |
| 3.9 | Ensure storage account uses customer-managed keys | azure-storage-005 | Medium | Covered |
| 3.10 | Ensure soft delete is enabled | azure-storage-007 | High | Covered |
| 3.11 | Ensure blob versioning is enabled | azure-storage-006 | Medium | Covered |
| 3.12 | Ensure minimum TLS version is 1.2 | azure-storage-002, azure-storage-010 | High/Medium | Covered |

**Section 3 Coverage: 8/15 controls (53%)**

### Section 4: Database Services

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 4.1.1 | Ensure SQL auditing is enabled | azure-sql-003 | High | Covered |
| 4.1.2 | Ensure SQL TDE is enabled | azure-sql-001, azure-sql-005 | High/Critical | Covered |
| 4.1.3 | Ensure SQL uses customer-managed TDE key | azure-sql-002, azure-sql-007 | Medium/High | Covered |
| 4.2.1 | Ensure Advanced Threat Protection is enabled | azure-sql-004 | High | Covered |
| 4.2.2 | Ensure vulnerability assessment is enabled | azure-sql-008 | Medium | Covered |
| 4.4 | Ensure Azure AD administrator is configured | azure-sql-006 | High | Covered |

**Section 4 Coverage: 6/15 controls (40%)**

### Section 5: Logging and Monitoring

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 5.1.1 | Ensure Log Analytics workspace retention >= 90 days | azure-monitor-010 | Medium | Covered |
| 5.1.2 | Ensure Activity Log retention >= 365 days | azure-monitor-001 | Medium | Covered |
| 5.1.3 | Ensure Activity Log captures all regions | azure-monitor-002 | Medium | Covered |
| 5.1.4 | Ensure Activity Log exports all categories | azure-monitor-003 | Medium | Covered |
| 5.1.5 | Ensure Key Vault diagnostic settings are enabled | azure-monitor-004 | High | Covered |
| 5.2.1 | Ensure alert for policy assignment changes | azure-monitor-005 | High | Covered |
| 5.2.2 | Ensure alert for NSG changes | azure-monitor-006 | High | Covered |
| 5.2.3 | Ensure alert for Security Solution changes | azure-monitor-007 | Critical | Covered |
| 5.2.4 | Ensure alert for SQL Server firewall rule changes | azure-monitor-008 | High | Covered |
| 5.2.5 | Ensure alert for Security Center policy changes | azure-monitor-009 | High | Covered |
| 5.4 | Ensure Load Balancer diagnostic settings are enabled | azure-network-003 | Medium | Covered |

**Section 5 Coverage: 11/12 controls (92%)**

### Section 6: Networking

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 6.1 | Ensure SSH access is restricted from internet | azure-compute-001, azure-compute-006, azure-network-009 | High/Critical/Medium | Covered |
| 6.2 | Ensure RDP access is restricted from internet | azure-compute-002, azure-compute-010, azure-network-010 | High | Covered |
| 6.3 | Ensure database ports are not exposed | azure-compute-004, azure-compute-005, azure-network-006 | Medium/Critical | Covered |
| 6.4 | Ensure VPN Gateway uses IKEv2 | azure-compute-007, azure-network-004 | Medium | Covered |
| 6.5 | Ensure DDoS Protection is enabled | azure-compute-008, azure-network-008 | Medium/High | Covered |
| 6.6 | Ensure NSG is attached to all subnets | azure-compute-009, azure-network-001 | Medium/High | Covered |
| 6.7 | Ensure Azure Front Door WAF is enabled | azure-network-002 | High | Covered |

**Section 6 Coverage: 7/8 controls (88%)**

### Section 7: Virtual Machines

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 7.2 | Ensure VM disk encryption is enabled | azure-compute-011 | High | Covered |
| 7.4 | Ensure VMs use managed identity | azure-compute-003 | Medium | Covered |

**Section 7 Coverage: 2/7 controls (29%)**

### Section 9: AppService

| Control ID | Control Description | Policy ID | Severity | Status |
|------------|---------------------|-----------|----------|--------|
| 9.1 | Ensure Azure Function minimum TLS version is 1.2 | azure-functions-006 | High | Covered |
| 9.2 | Ensure Azure Function HTTPS only is enabled | azure-functions-001 | High | Covered |
| 9.3 | Ensure Azure Function VNet integration is configured | azure-functions-003 | Medium | Covered |
| 9.4 | Ensure Azure Function private endpoints are configured | azure-functions-005 | High | Covered |
| 9.5 | Ensure Azure Function managed identity is enabled | azure-functions-002 | Medium | Covered |

**Section 9 Coverage: 5/10 controls (50%)**

## Policy Details

### Identity Policies

#### azure-identity-001: Privileged role assignments reviewed
- **CIS Controls**: 1.23
- **Severity**: High
- **Resource Type**: azure_role_assignment
- **Evidence Collection**:
  1. Run Stance scan to collect role assignments
  2. Identify Owner, Contributor, User Access Administrator roles
  3. Check scope of privileged assignments

#### azure-identity-002: Custom role wildcard actions
- **CIS Controls**: 1.21
- **Severity**: High
- **Resource Type**: azure_role_definition
- **Evidence Collection**:
  1. Run Stance scan to collect custom role definitions
  2. Check for wildcard (*) actions in permissions
  3. Document overly permissive custom roles

#### azure-identity-003: Subscription scope limited
- **CIS Controls**: 1.22
- **Severity**: Medium
- **Resource Type**: azure_role_assignment
- **Evidence Collection**:
  1. Run Stance scan to analyze role assignment scopes
  2. Identify roles assigned at subscription level
  3. Recommend resource group level assignments

#### azure-identity-004: Guest user access restricted
- **CIS Controls**: 1.13
- **Severity**: Medium
- **Resource Type**: azure_guest_user
- **Evidence Collection**:
  1. Run Stance scan to collect guest users
  2. Review guest user permissions
  3. Check external collaboration settings

#### azure-identity-005: Service principal secrets rotation
- **CIS Controls**: 1.11
- **Severity**: Medium
- **Resource Type**: azure_service_principal
- **Evidence Collection**:
  1. Run Stance scan to collect service principals
  2. Check secret expiration dates
  3. Flag secrets older than 90 days

#### azure-identity-006: MFA required for all users
- **CIS Controls**: 1.1.1
- **Severity**: Critical
- **Resource Type**: azure_conditional_access_policy
- **Evidence Collection**:
  1. Run Stance scan to collect conditional access policies
  2. Verify MFA requirement for all users
  3. Check for excluded groups

#### azure-identity-007: MFA required for admin roles
- **CIS Controls**: 1.1.2
- **Severity**: Critical
- **Resource Type**: azure_conditional_access_policy
- **Evidence Collection**:
  1. Run Stance scan to collect conditional access policies
  2. Verify MFA requirement for admin roles
  3. Check admin role assignments

#### azure-identity-008: Managed Identity preferred
- **CIS Controls**: 1.22
- **Severity**: Medium
- **Resource Type**: azure_application
- **Evidence Collection**:
  1. Run Stance scan to collect applications
  2. Check for service principal credential usage
  3. Recommend managed identity

#### azure-identity-009: Legacy authentication blocked
- **CIS Controls**: 1.1.3
- **Severity**: High
- **Resource Type**: azure_conditional_access_policy
- **Evidence Collection**:
  1. Run Stance scan to collect conditional access policies
  2. Verify legacy authentication is blocked
  3. Check for exceptions

### Storage Policies

#### azure-storage-001: Secure transfer required
- **CIS Controls**: 3.1
- **Severity**: High
- **Resource Type**: azure_storage_account
- **Evidence Collection**:
  1. Run Stance scan to collect storage account settings
  2. Verify supportsHttpsTrafficOnly is enabled
  3. Document accounts allowing HTTP

#### azure-storage-002: Minimum TLS version
- **CIS Controls**: 3.12
- **Severity**: High
- **Resource Type**: azure_storage_account
- **Evidence Collection**:
  1. Run Stance scan to check TLS configuration
  2. Verify minimumTlsVersion is TLS1_2
  3. Document accounts with outdated TLS

#### azure-storage-003: Public access disabled
- **CIS Controls**: 3.5
- **Severity**: Critical
- **Resource Type**: azure_storage_account
- **Evidence Collection**:
  1. Run Stance scan to check public access settings
  2. Verify allowBlobPublicAccess is disabled
  3. Check individual container access levels

#### azure-storage-004: Network rules enabled
- **CIS Controls**: 3.6
- **Severity**: High
- **Resource Type**: azure_storage_account
- **Evidence Collection**:
  1. Run Stance scan to check network rules
  2. Verify default action is Deny
  3. Document allowed networks and IPs

#### azure-storage-005: Customer-managed keys
- **CIS Controls**: 3.9
- **Severity**: Medium
- **Resource Type**: azure_storage_account
- **Evidence Collection**:
  1. Run Stance scan to check encryption settings
  2. Verify CMK encryption is configured
  3. Check Key Vault integration

#### azure-storage-006: Blob versioning enabled
- **CIS Controls**: 3.11
- **Severity**: Medium
- **Resource Type**: azure_storage_account
- **Evidence Collection**:
  1. Run Stance scan to check versioning settings
  2. Verify blob versioning is enabled
  3. Check lifecycle management policies

#### azure-storage-007: Soft delete enabled
- **CIS Controls**: 3.10
- **Severity**: High
- **Resource Type**: azure_storage_account
- **Evidence Collection**:
  1. Run Stance scan to check soft delete settings
  2. Verify blob and container soft delete is enabled
  3. Check retention period

### Database Policies

#### azure-sql-001: TDE enabled
- **CIS Controls**: 4.1.2
- **Severity**: High
- **Resource Type**: azure_sql_database
- **Evidence Collection**:
  1. Run Stance scan to collect SQL databases
  2. Verify TDE is enabled
  3. Check encryption key type

#### azure-sql-002: Customer-managed TDE key
- **CIS Controls**: 4.1.3
- **Severity**: Medium
- **Resource Type**: azure_sql_database
- **Evidence Collection**:
  1. Run Stance scan to collect SQL databases
  2. Verify BYOK TDE is configured
  3. Check Key Vault integration

#### azure-sql-003: SQL auditing enabled
- **CIS Controls**: 4.1.1
- **Severity**: High
- **Resource Type**: azure_sql_server
- **Evidence Collection**:
  1. Run Stance scan to collect SQL servers
  2. Verify auditing is enabled
  3. Check audit log destination

#### azure-sql-004: Advanced Threat Protection
- **CIS Controls**: 4.2.1
- **Severity**: High
- **Resource Type**: azure_sql_server
- **Evidence Collection**:
  1. Run Stance scan to collect SQL servers
  2. Verify ATP is enabled
  3. Check alert notifications

#### azure-sql-005: Public network access disabled
- **CIS Controls**: 4.1.2
- **Severity**: Critical
- **Resource Type**: azure_sql_server
- **Evidence Collection**:
  1. Run Stance scan to collect SQL servers
  2. Verify public network access is disabled
  3. Check private endpoint configuration

#### azure-sql-006: Azure AD administrator configured
- **CIS Controls**: 4.4
- **Severity**: High
- **Resource Type**: azure_sql_server
- **Evidence Collection**:
  1. Run Stance scan to collect SQL servers
  2. Verify Azure AD admin is configured
  3. Check SQL authentication settings

### Monitoring Policies

#### azure-monitor-001 through azure-monitor-010: Logging and Alerts
- **CIS Controls**: 5.1.1 - 5.2.5
- **Severity**: Medium to Critical
- **Resource Type**: azure_activity_log, azure_alert_rule
- **Evidence Collection**:
  1. Run Stance scan to collect diagnostic settings
  2. Verify all required alerts are configured
  3. Check retention periods and destinations

### Networking Policies

#### azure-compute-001: SSH access restricted
- **CIS Controls**: 6.1
- **Severity**: High
- **Resource Type**: azure_network_security_group
- **Evidence Collection**:
  1. Run Stance scan to collect NSG rules
  2. Check for rules allowing 0.0.0.0/0 on port 22
  3. Document unrestricted SSH access

#### azure-compute-002: RDP access restricted
- **CIS Controls**: 6.2
- **Severity**: High
- **Resource Type**: azure_network_security_group
- **Evidence Collection**:
  1. Run Stance scan to collect NSG rules
  2. Check for rules allowing 0.0.0.0/0 on port 3389
  3. Document unrestricted RDP access

#### azure-compute-003: VM managed identity
- **CIS Controls**: 7.4
- **Severity**: Medium
- **Resource Type**: azure_virtual_machine
- **Evidence Collection**:
  1. Run Stance scan to check VM identity settings
  2. Verify managed identity is assigned
  3. Document VMs without managed identities

#### azure-compute-004: VM public IP restricted
- **CIS Controls**: 6.3
- **Severity**: Medium
- **Resource Type**: azure_virtual_machine
- **Evidence Collection**:
  1. Run Stance scan to identify public IPs
  2. Check for VMs with directly assigned public IPs
  3. Document internet-exposed resources

### Functions Policies

#### azure-functions-001 through azure-functions-006: App Service Security
- **CIS Controls**: 9.1 - 9.5
- **Severity**: Medium to High
- **Resource Type**: azure_function_app
- **Evidence Collection**:
  1. Run Stance scan to collect function apps
  2. Verify HTTPS, TLS, VNet integration settings
  3. Check managed identity configuration

## Coverage Summary

| Section | Controls Covered | Total Controls | Coverage |
|---------|------------------|----------------|----------|
| 1. Identity and Access Management | 8 | 25 | 32% |
| 2. Security Center | 0 | 15 | 0% |
| 3. Storage Accounts | 8 | 15 | 53% |
| 4. Database Services | 6 | 15 | 40% |
| 5. Logging and Monitoring | 11 | 12 | 92% |
| 6. Networking | 7 | 8 | 88% |
| 7. Virtual Machines | 2 | 7 | 29% |
| 8. Other Security | 0 | 5 | 0% |
| 9. AppService | 5 | 10 | 50% |
| **Total** | **47** | **112** | **42%** |

## Gaps and Recommendations

### Covered Controls Summary

**Section 1 (Partial)**: 1.1.1, 1.1.2, 1.1.3, 1.11, 1.13, 1.21, 1.22, 1.23

**Section 3 (Good)**: 3.1, 3.3, 3.5, 3.6, 3.9, 3.10, 3.11, 3.12

**Section 4 (Partial)**: 4.1.1, 4.1.2, 4.1.3, 4.2.1, 4.2.2, 4.4

**Section 5 (Near Full)**: 5.1.1-5.1.5, 5.2.1-5.2.5, 5.4

**Section 6 (Near Full)**: 6.1-6.7

**Section 7 (Partial)**: 7.2, 7.4

**Section 9 (Partial)**: 9.1-9.5

### Not Covered Controls

**Section 2 (Security Center)**:
- 2.1-2.15: Microsoft Defender for Cloud settings

**Section 8 (Other Security)**:
- 8.1-8.5: Key Vault, Azure Policy configuration

### Roadmap

Future Stance releases may add policies for:
- Microsoft Defender for Cloud configuration
- Azure Key Vault access policies
- Additional VM hardening checks
- Container security settings

## Running Compliance Checks

```bash
# Scan Azure subscription for CIS compliance
stance scan --subscription-id YOUR_SUBSCRIPTION

# Generate CIS compliance report
stance report --framework cis-azure-foundations --format html

# Query specific control status
stance query "show findings for CIS control 1.23"

# Export compliance evidence
stance export --framework cis-azure-foundations --format json --output evidence.json
```

## References

- [CIS Microsoft Azure Foundations Benchmark v2.0](https://www.cisecurity.org/benchmark/azure)
- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/)
- [Azure Security Center Documentation](https://docs.microsoft.com/en-us/azure/security-center/)
