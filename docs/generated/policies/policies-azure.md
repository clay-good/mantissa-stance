# AZURE Policies

Security policies for AZURE resources.

## Critical Severity

### azure-compute-005

**Name:** Database ports not exposed to internet

Ensure Network Security Groups do not allow database port access
from the internet. Exposing database ports like SQL Server (1433),
MySQL (3306), PostgreSQL (5432) creates significant security risks.


**Resource Type:** `azure_network_security_group`

**Compliance:**
- cis-azure-foundations 6.3
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Network Security Groups in Azure Portal
2. Select the NSG with exposed database ports
3. Go to Inbound security rules
4. Identify rules allowing database ports from Any/Internet:
   - Port 1433 (SQL Server)
   - Port 3306 (MySQL)
   - Port 5432 (PostgreSQL)
   - Port 6379 (Redis)
   - Port 27017 (MongoDB)
5. Modify rules to restrict source to specific VNet/subnet
6. Consider using Private Endpoints for database access


### azure-compute-006

**Name:** NSG does not allow all traffic from internet

Ensure no Network Security Group rule allows all traffic from
the internet. Overly permissive rules that allow all protocols
and ports from Any source create severe security vulnerabilities.


**Resource Type:** `azure_network_security_group`

**Compliance:**
- cis-azure-foundations 6.1
- pci-dss 1.2.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Network Security Groups in Azure Portal
2. Select the NSG with overly permissive rules
3. Go to Inbound security rules
4. Identify rules with:
   - Source: Any or Internet
   - Protocol: Any (*)
   - Destination port ranges: Any (*) or 0-65535
5. Delete or modify these rules to:
   - Specify required ports only
   - Restrict source IP ranges
   - Use Application Security Groups
6. Verify application functionality after changes


### azure-identity-006

**Name:** MFA required for all users

Ensure multi-factor authentication is required for all users.
MFA significantly reduces the risk of account compromise from
phishing and credential theft attacks.


**Resource Type:** `azure_conditional_access_policy`

**Compliance:**
- cis-azure-foundations 1.1.1
- pci-dss 8.4.1
- nist-800-53 IA-2(1)

**Remediation:**
1. Navigate to Azure Active Directory > Security > Conditional Access
2. Create a new policy or edit existing
3. Under "Assignments > Users":
   - Include "All users"
   - Exclude emergency access accounts
4. Under "Cloud apps or actions":
   - Include "All cloud apps"
5. Under "Access controls > Grant":
   - Select "Require multi-factor authentication"
6. Enable the policy
7. Consider Security Defaults if you don't have Azure AD Premium


### azure-identity-007

**Name:** MFA required for admin roles

Ensure multi-factor authentication is required for administrative
roles. Compromised admin accounts can lead to complete tenant
compromise, making MFA critical for privileged access.


**Resource Type:** `azure_conditional_access_policy`

**Compliance:**
- cis-azure-foundations 1.1.2
- pci-dss 8.4.1
- nist-800-53 IA-2(1)
- soc2 CC6.1

**Remediation:**
1. Navigate to Azure Active Directory > Security > Conditional Access
2. Create a new policy named "Require MFA for admins"
3. Under "Assignments > Users":
   - Include "Directory roles"
   - Select all admin roles (Global admin, Security admin, etc.)
4. Under "Cloud apps or actions":
   - Include "All cloud apps"
5. Under "Access controls > Grant":
   - Select "Require multi-factor authentication"
6. Set "Enable policy" to "On"
7. Create emergency access accounts without MFA (break-glass)


### azure-monitor-007

**Name:** Alert for Security Solution changes

Ensure an alert exists for creating, updating, or deleting Security Solutions.
Security Solutions include Azure Defender, Sentinel, and third-party security
tools. Changes should be monitored to prevent security gaps.


**Resource Type:** `azure_monitor_alert_rule`

**Compliance:**
- cis-azure-foundations 5.2.3
- pci-dss 10.2.6
- nist-800-53 AU-6

**Remediation:**
1. Navigate to Azure Monitor > Alerts
2. Click Create > Alert rule
3. Select subscription as target
4. Configure condition:
   - Signal type: Activity Log
   - Category: Security
   - Resource type: Security solutions
   - Operations: Create/Update/Delete
5. Configure action group with immediate notification
6. Set alert rule name and severity (Critical)
7. Create alert rule


### azure-sql-005

**Name:** Azure SQL public network access disabled

Ensure Azure SQL Server public network access is disabled. Disabling
public network access forces all connections through private endpoints,
reducing the attack surface.


**Resource Type:** `azure_sql_server`

**Compliance:**
- cis-azure-foundations 4.1.2
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to SQL Server in Azure Portal
2. Under Security, select Networking
3. Set "Public network access" to Disabled
4. Configure Private endpoints:
   - Create private endpoint in your VNet
   - Configure DNS for private link
5. Save changes

Note: Ensure applications can connect through private
endpoints before disabling public access.


### azure-storage-003

**Name:** Public blob access disabled

Ensure public access to blobs is disabled on storage accounts.
Public blob access can lead to unintended data exposure. Access
should be controlled through authentication and authorization.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.5
- pci-dss 7.2.1
- nist-800-53 AC-3

**Remediation:**
1. Navigate to Storage accounts in Azure Portal
2. Select the storage account
3. Go to Configuration under Settings
4. Set "Allow Blob public access" to Disabled
5. Save the configuration
6. Review and update any applications that relied on public access
7. Use SAS tokens or Azure AD for authorized access


## High Severity

### azure-compute-001

**Name:** SSH access restricted from internet

Ensure Network Security Groups do not allow SSH (port 22) access from
the internet (*/Internet). Unrestricted SSH access exposes VMs to
brute force attacks and should be limited to specific trusted IPs.


**Resource Type:** `azure_network_security_group`

**Compliance:**
- cis-azure-foundations 6.1
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Network security groups in Azure Portal
2. Select the NSG with SSH allowed from internet
3. Go to Inbound security rules
4. Edit or delete the rule allowing SSH from Any/*
5. Create a rule allowing SSH only from specific IP ranges
6. Consider using Azure Bastion for secure SSH access
7. Or use Just-In-Time VM access through Defender for Cloud


### azure-compute-002

**Name:** RDP access restricted from internet

Ensure Network Security Groups do not allow RDP (port 3389) access from
the internet (*/Internet). Unrestricted RDP access exposes Windows VMs
to brute force attacks and should be limited to specific trusted IPs.


**Resource Type:** `azure_network_security_group`

**Compliance:**
- cis-azure-foundations 6.2
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Network security groups in Azure Portal
2. Select the NSG with RDP allowed from internet
3. Go to Inbound security rules
4. Edit or delete the rule allowing RDP from Any/*
5. Create a rule allowing RDP only from specific IP ranges
6. Consider using Azure Bastion for secure RDP access
7. Or use Just-In-Time VM access through Defender for Cloud


### azure-compute-010

**Name:** Management ports restricted from internet

Ensure management ports (SSH 22, RDP 3389, WinRM 5985/5986) are
not exposed to the internet. Use Azure Bastion, VPN, or jump
boxes for secure remote management access.


**Resource Type:** `azure_network_security_group`

**Compliance:**
- cis-azure-foundations 6.2
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Network Security Groups in Azure Portal
2. Select the NSG with exposed management ports
3. Go to Inbound security rules
4. Remove or modify rules allowing from Internet:
   - Port 22 (SSH)
   - Port 3389 (RDP)
   - Port 5985/5986 (WinRM)
5. Implement secure alternatives:
   - Azure Bastion for browser-based access
   - VPN Gateway for site-to-site access
   - Jump box in a secured subnet
   - Just-in-time VM access


### azure-compute-011

**Name:** VM disk encryption enabled

Ensure Azure VM disks are encrypted using Azure Disk Encryption
or server-side encryption with customer-managed keys. Disk
encryption protects data at rest from unauthorized access.


**Resource Type:** `azure_vm`

**Compliance:**
- cis-azure-foundations 7.2
- pci-dss 3.4
- nist-800-53 SC-28

**Remediation:**
Option 1: Azure Disk Encryption (ADE)
1. Create a Key Vault with appropriate permissions
2. Navigate to the VM > Disks
3. Select "Encryption"
4. Enable Azure Disk Encryption
5. Select the Key Vault and key

Option 2: Server-side encryption with CMK
1. Create a disk encryption set
2. Associate with Key Vault key
3. Apply to VM disks

Note: Azure encrypts all managed disks by default with
platform-managed keys. Consider CMK for enhanced control.


### azure-functions-001

**Name:** Azure Function HTTPS only enabled

Ensure Azure Functions only accept HTTPS requests. HTTP traffic is
unencrypted and vulnerable to eavesdropping and man-in-the-middle
attacks. All function traffic should use TLS.


**Resource Type:** `azure_function_app`

**Compliance:**
- cis-azure-foundations 9.2
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Function App in Azure Portal
2. Under Settings, select Configuration
3. Go to General settings tab
4. Set "HTTPS Only" to On
5. Save changes

Note: Ensure all clients use HTTPS URLs after enabling.


### azure-functions-004

**Name:** Azure Function uses supported runtime

Ensure Azure Functions use a supported runtime version. Deprecated
runtimes do not receive security patches and may have known vulnerabilities.
Upgrade to supported versions for continued security updates.


**Resource Type:** `azure_function_app`

**Compliance:**
- nist-800-53 SI-2
- pci-dss 6.3.3

**Remediation:**
1. Navigate to Function App in Azure Portal
2. Under Settings, select Configuration
3. Go to General settings
4. Select supported runtime version:
   - .NET: 6.0, 8.0
   - Node.js: 18, 20
   - Python: 3.9, 3.10, 3.11
   - Java: 11, 17, 21
5. Also update Functions runtime version if needed
6. Save and restart the function app

Test thoroughly after runtime upgrade.


### azure-functions-005

**Name:** Azure Function private endpoints configured

Ensure Azure Functions use private endpoints for inbound traffic.
Private endpoints allow clients in virtual networks to access functions
over private IP addresses, eliminating public internet exposure.


**Resource Type:** `azure_function_app`

**Compliance:**
- cis-azure-foundations 9.4
- nist-800-53 SC-7
- pci-dss 1.3.1

**Remediation:**
1. Navigate to Function App in Azure Portal
2. Under Settings, select Networking
3. Under Inbound traffic:
   - Click Private endpoints
   - Add private endpoint
   - Select subscription, resource group, name
   - Select virtual network and subnet
   - Configure private DNS integration
4. Consider disabling public network access after configuration
5. Save changes

Note: Private endpoints require Premium or Elastic Premium plan.


### azure-functions-006

**Name:** Azure Function minimum TLS version 1.2

Ensure Azure Functions enforce TLS 1.2 as the minimum version.
TLS 1.0 and 1.1 have known vulnerabilities and should not be used
for function traffic.


**Resource Type:** `azure_function_app`

**Compliance:**
- cis-azure-foundations 9.1
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Function App in Azure Portal
2. Under Settings, select Configuration
3. Go to General settings tab
4. Set "Minimum TLS Version" to 1.2
5. Save changes

Note: Verify that all clients support TLS 1.2 before
making this change.


### azure-identity-001

**Name:** Privileged role assignments reviewed

Ensure privileged role assignments (Owner, Contributor, User Access
Administrator) are limited and regularly reviewed. Excessive privileged
access increases the risk of security breaches and insider threats.


**Resource Type:** `azure_role_assignment`

**Compliance:**
- cis-azure-foundations 1.23
- nist-800-53 AC-6(7)
- pci-dss 7.2.2

**Remediation:**
1. Navigate to Subscriptions > Access control (IAM) in Azure Portal
2. Review all Owner, Contributor, and User Access Administrator assignments
3. Remove unnecessary privileged role assignments
4. Use Azure Privileged Identity Management (PIM) for just-in-time access
5. Assign roles at the most restrictive scope possible
6. Enable access reviews for privileged roles


### azure-identity-002

**Name:** Custom roles do not have wildcard permissions

Ensure custom role definitions do not include wildcard (*) permissions.
Wildcard permissions grant overly broad access and violate the
principle of least privilege.


**Resource Type:** `azure_role_definition`

**Compliance:**
- cis-azure-foundations 1.21
- nist-800-53 AC-6
- pci-dss 7.1.1

**Remediation:**
1. Navigate to Subscriptions > Access control (IAM) > Roles
2. Filter by "Custom" role type
3. Review each custom role's permissions
4. Replace wildcard actions with specific required actions
5. Test the updated role to ensure functionality
6. Update role assignments if role definition changes


### azure-identity-009

**Name:** Legacy authentication blocked

Ensure legacy authentication protocols are blocked. Legacy protocols
like POP, IMAP, SMTP auth, and older Office clients do not support
MFA and are commonly exploited in password spray attacks.


**Resource Type:** `azure_conditional_access_policy`

**Compliance:**
- cis-azure-foundations 1.1.3
- nist-800-53 IA-2
- pci-dss 8.3.1

**Remediation:**
1. Navigate to Azure Active Directory > Security > Conditional Access
2. Create a new policy named "Block legacy authentication"
3. Under "Assignments > Users":
   - Include "All users"
   - Exclude service accounts that require legacy auth
4. Under "Cloud apps or actions":
   - Include "All cloud apps"
5. Under "Conditions > Client apps":
   - Configure "Yes"
   - Select "Exchange ActiveSync clients" and "Other clients"
6. Under "Access controls > Grant":
   - Select "Block access"
7. Enable the policy


### azure-monitor-004

**Name:** Key Vault diagnostic settings enabled

Ensure diagnostic settings are enabled for Azure Key Vault to capture audit
events. Key Vault stores sensitive secrets, keys, and certificates. Logging
all access is critical for security monitoring and compliance.


**Resource Type:** `azure_key_vault`

**Compliance:**
- cis-azure-foundations 5.1.5
- pci-dss 10.2.2
- nist-800-53 AU-2

**Remediation:**
1. Navigate to the Key Vault in Azure Portal
2. Under Monitoring, select Diagnostic settings
3. Click Add diagnostic setting
4. Configure:
   - Name: Descriptive name
   - Logs: Enable AuditEvent category
   - Metrics: Enable AllMetrics (optional)
   - Destination: Log Analytics workspace (recommended)
5. Set retention to at least 90 days
6. Save configuration


### azure-monitor-005

**Name:** Alert for policy assignment changes

Ensure an alert exists for Azure Policy assignment creation or deletion.
Policy changes can weaken security posture if not properly reviewed.
Alerting enables rapid detection of unauthorized policy modifications.


**Resource Type:** `azure_monitor_alert_rule`

**Compliance:**
- cis-azure-foundations 5.2.1
- pci-dss 10.2.6
- nist-800-53 AU-6

**Remediation:**
1. Navigate to Azure Monitor > Alerts
2. Click Create > Alert rule
3. Select subscription as target
4. Configure condition:
   - Signal type: Activity Log
   - Category: Administrative
   - Operation: Create policy assignment
   - Also add: Delete policy assignment
5. Configure action group for notifications
6. Set alert rule name and severity
7. Create alert rule


### azure-monitor-006

**Name:** Alert for Network Security Group changes

Ensure an alert exists for creating, updating, or deleting Network Security
Groups and their rules. NSG changes can expose resources to unauthorized
network access and should be monitored.


**Resource Type:** `azure_monitor_alert_rule`

**Compliance:**
- cis-azure-foundations 5.2.2
- pci-dss 10.2.7
- nist-800-53 AU-6

**Remediation:**
1. Navigate to Azure Monitor > Alerts
2. Click Create > Alert rule
3. Select subscription as target
4. Configure condition:
   - Signal type: Activity Log
   - Category: Administrative
   - Resource type: Network security groups
   - Operations: Create/Update/Delete
5. Configure action group for notifications
6. Set alert rule name and severity (High)
7. Create alert rule


### azure-monitor-008

**Name:** Alert for SQL Server firewall rule changes

Ensure an alert exists for creating, updating, or deleting SQL Server firewall
rules. SQL firewall changes can expose databases to unauthorized access
and should trigger immediate investigation.


**Resource Type:** `azure_monitor_alert_rule`

**Compliance:**
- cis-azure-foundations 5.2.4
- pci-dss 10.2.7
- nist-800-53 AU-6

**Remediation:**
1. Navigate to Azure Monitor > Alerts
2. Click Create > Alert rule
3. Select subscription as target
4. Configure condition:
   - Signal type: Activity Log
   - Category: Administrative
   - Resource type: SQL servers
   - Operations:
     - Create/Update SQL Server Firewall Rule
     - Delete SQL Server Firewall Rule
5. Configure action group for database team
6. Set alert rule name and severity (High)
7. Create alert rule


### azure-monitor-009

**Name:** Alert for Security Center policy changes

Ensure an alert exists for updates to Microsoft Defender for Cloud policies.
Security Center policy changes affect security recommendations and compliance
posture and should be reviewed.


**Resource Type:** `azure_monitor_alert_rule`

**Compliance:**
- cis-azure-foundations 5.2.5
- pci-dss 10.2.6
- nist-800-53 AU-6

**Remediation:**
1. Navigate to Azure Monitor > Alerts
2. Click Create > Alert rule
3. Select subscription as target
4. Configure condition:
   - Signal type: Activity Log
   - Category: Security
   - Resource provider: Security Center
   - Operations: Security policies updates
5. Configure action group for security team
6. Set alert rule name and severity (High)
7. Create alert rule


### azure-network-001

**Name:** Application Gateway WAF enabled

Ensure Azure Application Gateway has Web Application Firewall (WAF)
enabled. WAF protects web applications from common vulnerabilities
like SQL injection and cross-site scripting.


**Resource Type:** `azure_application_gateway`

**Compliance:**
- cis-azure-foundations 6.6
- pci-dss 6.4.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Application Gateway in Azure Portal
2. Select Web application firewall
3. Enable WAF:
   - Tier: WAF_v2 (recommended)
   - Mode: Prevention
   - Ruleset: OWASP 3.2 or latest
4. Configure exclusions if needed
5. Enable bot protection (optional)
6. Save configuration


### azure-network-002

**Name:** Azure Front Door WAF enabled

Ensure Azure Front Door has Web Application Firewall policy attached.
WAF at the edge provides global protection against web vulnerabilities
and DDoS attacks.


**Resource Type:** `azure_front_door`

**Compliance:**
- cis-azure-foundations 6.7
- pci-dss 6.4.1
- nist-800-53 SC-7

**Remediation:**
1. Create WAF Policy:
   - Navigate to Web Application Firewall policies
   - Create new policy for Front Door
   - Configure managed rules (OWASP, Bot protection)
   - Set policy mode to Prevention
2. Associate with Front Door:
   - Navigate to Front Door
   - Select WAF policy in settings
   - Apply to endpoints/routes
3. Save configuration


### azure-network-007

**Name:** ExpressRoute uses MACsec encryption

Ensure ExpressRoute Direct connections use MACsec encryption.
MACsec provides link-layer encryption for data in transit between
on-premises and Azure.


**Resource Type:** `azure_express_route`

**Compliance:**
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to ExpressRoute Direct in Azure Portal
2. Select the ExpressRoute Direct resource
3. Enable MACsec:
   - Configure MACsec cipher (GcmAes256)
   - Generate and configure CAK/CKN
   - Apply to both ports
4. Configure on-premises router:
   - Match cipher and keys
   - Enable MACsec on interface
5. Verify encrypted traffic

Note: MACsec available on ExpressRoute Direct only.
Standard ExpressRoute uses provider's encryption.


### azure-network-008

**Name:** Azure Firewall threat intelligence enabled

Ensure Azure Firewall has threat intelligence-based filtering enabled.
This feature blocks traffic to/from known malicious IP addresses and
domains based on Microsoft Threat Intelligence.


**Resource Type:** `azure_firewall`

**Compliance:**
- cis-azure-foundations 6.5
- pci-dss 5.2.1
- nist-800-53 SI-4

**Remediation:**
1. Navigate to Azure Firewall in Azure Portal
2. Select Threat intelligence
3. Configure mode:
   - Alert: Log only (for testing)
   - Deny: Block traffic (recommended)
4. Configure allowlist if needed:
   - Add trusted IPs/FQDNs
5. Save configuration

Monitor logs for threat intelligence hits in
Log Analytics or Azure Sentinel.


### azure-sql-001

**Name:** SQL Database TDE enabled

Ensure Transparent Data Encryption (TDE) is enabled for Azure
SQL databases. TDE encrypts data at rest and is enabled by
default for new databases but should be verified.


**Resource Type:** `azure_sql_database`

**Compliance:**
- cis-azure-foundations 4.1.2
- pci-dss 3.4
- nist-800-53 SC-28

**Remediation:**
1. Navigate to Azure SQL Database in Azure Portal
2. Select the database
3. Go to Security > Transparent data encryption
4. Set "Data encryption" to ON
5. Save changes

Note: TDE is enabled by default for new databases created
after 2017. Verify existing databases have TDE enabled.


### azure-sql-003

**Name:** Azure SQL auditing enabled

Ensure Azure SQL Server auditing is enabled. Auditing tracks database
events and writes them to an audit log for security analysis, compliance
reporting, and forensic investigation.


**Resource Type:** `azure_sql_server`

**Compliance:**
- cis-azure-foundations 4.1.1
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Navigate to SQL Server in Azure Portal
2. Under Security, select Auditing
3. Enable auditing
4. Configure storage destination:
   - Storage account (recommended)
   - Log Analytics workspace
   - Event Hub
5. Set retention period (at least 90 days)
6. Save configuration


### azure-sql-004

**Name:** Azure SQL Advanced Threat Protection enabled

Ensure Azure SQL Advanced Threat Protection is enabled. This provides
a layer of security intelligence that detects anomalous activities
indicating potential threats to the database.


**Resource Type:** `azure_sql_server`

**Compliance:**
- cis-azure-foundations 4.2.1
- pci-dss 11.5
- nist-800-53 SI-4

**Remediation:**
1. Navigate to SQL Server in Azure Portal
2. Under Security, select Microsoft Defender for Cloud
3. Enable "Microsoft Defender for SQL"
4. Configure alert notifications:
   - Email recipients
   - Send alerts to admins and subscription owners
5. Configure Vulnerability Assessment settings
6. Save configuration


### azure-sql-006

**Name:** Azure SQL Azure AD administrator configured

Ensure an Azure Active Directory administrator is configured for SQL Server.
AAD authentication provides centralized identity management, MFA support,
and eliminates the need for SQL authentication.


**Resource Type:** `azure_sql_server`

**Compliance:**
- cis-azure-foundations 4.4
- pci-dss 8.3.1
- nist-800-53 IA-2

**Remediation:**
1. Navigate to SQL Server in Azure Portal
2. Under Settings, select Azure Active Directory
3. Click "Set admin"
4. Select a user or group from Azure AD
5. Save configuration

Best practice: Use an Azure AD group as the admin
to allow for multiple administrators.


### azure-sql-007

**Name:** Azure SQL minimum TLS version 1.2

Ensure Azure SQL Server enforces TLS 1.2 as the minimum version.
TLS 1.0 and 1.1 have known vulnerabilities and should not be used
for database connections.


**Resource Type:** `azure_sql_server`

**Compliance:**
- cis-azure-foundations 4.1.3
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to SQL Server in Azure Portal
2. Under Security, select Networking
3. Under TLS version:
   - Set "Minimum TLS version" to 1.2
4. Save changes

Note: Verify that all client applications support TLS 1.2
before making this change.


### azure-storage-001

**Name:** Secure transfer required

Ensure storage accounts require secure transfer (HTTPS). This setting
ensures all requests to the storage account are made over HTTPS,
protecting data in transit from eavesdropping and man-in-the-middle attacks.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.1
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Storage accounts in Azure Portal
2. Select the storage account
3. Go to Configuration under Settings
4. Set "Secure transfer required" to Enabled
5. Save the configuration
6. Update any applications using HTTP to use HTTPS


### azure-storage-002

**Name:** Minimum TLS version 1.2

Ensure storage accounts enforce TLS 1.2 as the minimum version.
Older TLS versions (1.0, 1.1) have known vulnerabilities and should
not be allowed for secure communications.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.12
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Storage accounts in Azure Portal
2. Select the storage account
3. Go to Configuration under Settings
4. Set "Minimum TLS version" to Version 1.2
5. Save the configuration
6. Test applications to ensure TLS 1.2 compatibility


### azure-storage-004

**Name:** Network access restricted

Ensure storage accounts restrict network access. By default, storage
accounts accept connections from all networks. Configuring network
rules to deny access by default improves security posture.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.6
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Storage accounts in Azure Portal
2. Select the storage account
3. Go to Networking under Security + networking
4. Under Firewalls and virtual networks, select "Enabled from selected
   virtual networks and IP addresses"
5. Add allowed virtual networks and IP ranges
6. Consider using private endpoints for secure access
7. Save the configuration


### azure-storage-007

**Name:** Azure Storage soft delete enabled

Ensure Azure Storage accounts have soft delete enabled for blobs and
containers. Soft delete retains deleted data for a specified period,
enabling recovery from accidental deletions.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.10
- pci-dss 9.5.1
- nist-800-53 CP-9

**Remediation:**
1. Navigate to Storage Account in Azure Portal
2. Under Data management, select Data protection
3. Under Recovery:
   - Enable "Enable soft delete for blobs"
   - Set retention period (7-365 days)
   - Enable "Enable soft delete for containers"
   - Set retention period (1-365 days)
4. Save changes

Recommended retention: At least 7 days for blobs,
7 days for containers.


## Medium Severity

### azure-compute-003

**Name:** VMs use managed identity

Ensure Virtual Machines use managed identities for Azure resources.
Managed identities eliminate the need to store credentials in code
and provide automatic credential rotation.


**Resource Type:** `azure_virtual_machine`

**Compliance:**
- cis-azure-foundations 7.4
- nist-800-53 IA-5

**Remediation:**
1. Navigate to Virtual machines in Azure Portal
2. Select the VM
3. Go to Identity under Settings
4. Enable System assigned managed identity
5. Or configure a User assigned managed identity
6. Grant the managed identity appropriate RBAC roles
7. Update applications to use managed identity for authentication


### azure-compute-004

**Name:** VMs do not have public IP addresses

Ensure Virtual Machines do not have public IP addresses unless required.
Public IP addresses expose VMs directly to the internet, increasing
attack surface. Use Azure Bastion, VPN, or private endpoints instead.


**Resource Type:** `azure_virtual_machine`

**Compliance:**
- cis-azure-foundations 6.3
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Evaluate if the VM requires a public IP address
2. If not required, navigate to Virtual machines > Networking
3. Remove or dissociate the public IP address
4. Configure Azure Bastion for secure remote access
5. Or use VPN Gateway for site-to-site connectivity
6. Use private endpoints for accessing Azure services
7. Configure NSG rules for any remaining public-facing VMs


### azure-compute-007

**Name:** NSG flow logs enabled

Ensure NSG flow logs are enabled for all Network Security Groups.
Flow logs provide visibility into network traffic for security
monitoring, compliance auditing, and troubleshooting.


**Resource Type:** `azure_network_security_group`

**Compliance:**
- cis-azure-foundations 6.4
- pci-dss 10.2.1
- nist-800-53 AU-12

**Remediation:**
1. Navigate to Network Watcher in Azure Portal
2. Select "NSG flow logs"
3. Select the NSG to enable flow logs
4. Configure flow log settings:
   - Status: On
   - Flow Logs version: Version 2 (recommended)
   - Storage account: Select or create
   - Retention: Set appropriate retention (days)
5. Optionally enable Traffic Analytics
6. Save configuration


### azure-compute-008

**Name:** DDoS Protection enabled for VNet

Ensure Azure DDoS Protection Standard is enabled for Virtual
Networks with public-facing resources. DDoS Protection provides
enhanced mitigation capabilities against volumetric attacks.


**Resource Type:** `azure_virtual_network`

**Compliance:**
- cis-azure-foundations 6.5
- pci-dss 6.6
- nist-800-53 SC-5

**Remediation:**
1. Navigate to Virtual Networks in Azure Portal
2. Select the VNet to protect
3. Go to "DDoS protection"
4. Select "Standard" protection plan
5. Select or create a DDoS Protection Plan
6. Save changes

Note: DDoS Protection Standard has associated costs.
Consider enabling for VNets with internet-facing resources.
Basic DDoS protection is free but provides limited capabilities.


### azure-compute-009

**Name:** NSG attached to all subnets

Ensure all subnets have a Network Security Group attached.
NSGs provide network-level access control and should be
configured for all subnets to enforce security policies.


**Resource Type:** `azure_subnet`

**Compliance:**
- cis-azure-foundations 6.6
- nist-800-53 SC-7
- pci-dss 1.2.1

**Remediation:**
1. Navigate to Virtual Networks in Azure Portal
2. Select the VNet containing the subnet
3. Go to Subnets
4. Select the subnet without an NSG
5. Click "Network security group"
6. Select an existing NSG or create a new one
7. Save changes

Note: Some special-purpose subnets (like GatewaySubnet)
may not support NSGs. Verify subnet type before remediation.


### azure-functions-002

**Name:** Azure Function managed identity enabled

Ensure Azure Functions use managed identity for authentication to
Azure services. Managed identities eliminate the need for credentials
in code and provide automatic credential rotation.


**Resource Type:** `azure_function_app`

**Compliance:**
- cis-azure-foundations 9.5
- nist-800-53 IA-2
- pci-dss 8.3.1

**Remediation:**
1. Navigate to Function App in Azure Portal
2. Under Settings, select Identity
3. On System assigned tab:
   - Set Status to On
   - Save
4. Or use User assigned identity:
   - Click Add under User assigned
   - Select or create managed identity
5. Grant the identity access to required resources

Best practice: Use system-assigned for single-purpose
functions, user-assigned for shared identities.


### azure-functions-003

**Name:** Azure Function VNet integration configured

Ensure Azure Functions that access private resources have VNet
integration configured. VNet integration enables functions to access
resources in private networks without public exposure.


**Resource Type:** `azure_function_app`

**Compliance:**
- cis-azure-foundations 9.3
- nist-800-53 SC-7
- pci-dss 1.3.1

**Remediation:**
1. Navigate to Function App in Azure Portal
2. Under Settings, select Networking
3. Under Outbound traffic:
   - Click VNet integration
   - Add VNet integration
   - Select VNet and subnet
4. Configure route all traffic through VNet if needed
5. Save changes

Note: VNet integration requires Premium or Elastic Premium
plan, or App Service Plan.


### azure-identity-003

**Name:** Role assignments scoped appropriately

Ensure role assignments are scoped to resource groups or resources
rather than at the subscription level. Subscription-level assignments
grant broader access than typically necessary.


**Resource Type:** `azure_role_assignment`

**Compliance:**
- cis-azure-foundations 1.22
- nist-800-53 AC-6(3)

**Remediation:**
1. Review role assignments at subscription level
2. Identify assignments that could be scoped to resource groups
3. Create new assignments at the appropriate resource group level
4. Remove overly broad subscription-level assignments
5. Use management groups for cross-subscription governance only
6. Document justification for any required subscription-level access


### azure-identity-004

**Name:** Guest user access restricted

Ensure guest user access is restricted and regularly reviewed.
Guest users from external organizations can access Azure AD
resources. Their access should be limited and monitored to
prevent unauthorized data exposure.


**Resource Type:** `azure_directory_settings`

**Compliance:**
- cis-azure-foundations 1.13
- nist-800-53 AC-2(7)
- pci-dss 7.2.3

**Remediation:**
1. Navigate to Azure Active Directory > External identities
2. Select "External collaboration settings"
3. Configure "Guest user access restrictions":
   - Set to "Guest users have limited access" or more restrictive
4. Configure "Guest invite settings":
   - Limit who can invite guests
   - Consider "Only admins and users in the guest inviter role"
5. Enable "Enable guest self-service sign up" only if needed
6. Review and limit "Collaboration restrictions"
7. Implement regular access reviews for guest users


### azure-identity-005

**Name:** Service principal secrets rotation

Ensure service principal secrets (client secrets) are rotated
regularly and have appropriate expiration. Long-lived secrets
increase the risk of credential compromise.


**Resource Type:** `azure_service_principal`

**Compliance:**
- cis-azure-foundations 1.11
- nist-800-53 IA-5(1)
- pci-dss 8.3.9

**Remediation:**
1. Navigate to Azure Active Directory > App registrations
2. Select the application with old secrets
3. Go to "Certificates & secrets"
4. Create a new client secret with appropriate expiration
5. Update applications to use the new secret
6. Delete old secrets after confirming new secret works
7. Consider using certificates instead of secrets
8. Consider using Managed Identity where possible


### azure-identity-008

**Name:** Managed Identity used for Azure resources

Ensure Azure resources use Managed Identity instead of service
principals with secrets. Managed Identity eliminates the need
for credential management and reduces the risk of credential
exposure.


**Resource Type:** `azure_vm`

**Compliance:**
- cis-azure-foundations 1.22
- nist-800-53 IA-5(7)

**Remediation:**
1. Navigate to the Azure resource (VM, App Service, etc.)
2. Go to "Identity" in the left menu
3. Enable System-assigned or User-assigned managed identity:
   - System-assigned: Tied to resource lifecycle
   - User-assigned: Can be shared across resources
4. Grant the managed identity necessary permissions
5. Update application code to use DefaultAzureCredential
6. Remove any stored service principal credentials
7. Delete unused service principal secrets


### azure-monitor-001

**Name:** Activity Log retention at least 365 days

Ensure Activity Log retention is set for at least 365 days. The Activity Log
contains subscription-level events including security events. Adequate retention
ensures audit data is available for forensic investigations and compliance.


**Resource Type:** `azure_monitor_log_profile`

**Compliance:**
- cis-azure-foundations 5.1.2
- pci-dss 10.7
- nist-800-53 AU-11

**Remediation:**
1. Navigate to Azure Monitor in Azure Portal
2. Select Activity log
3. Click "Export Activity Logs"
4. Configure diagnostic settings:
   - Select subscription
   - Choose destination (Log Analytics, Storage, Event Hub)
   - For Storage, set retention to at least 365 days
5. Save configuration


### azure-monitor-002

**Name:** Activity Log captures all regions

Ensure Activity Log profile is configured to capture events from all regions
including Global. This ensures complete visibility into Azure activities
regardless of where resources are deployed.


**Resource Type:** `azure_monitor_log_profile`

**Compliance:**
- cis-azure-foundations 5.1.3
- pci-dss 10.2.1
- nist-800-53 AU-3

**Remediation:**
1. Navigate to Azure Monitor in Azure Portal
2. Select Activity log
3. Click "Export Activity Logs"
4. In diagnostic settings, ensure all regions are selected:
   - Select "All Regions" or individually select each region
   - Include "Global" for subscription-level events
5. Configure destination (Log Analytics recommended)
6. Save configuration


### azure-monitor-003

**Name:** Activity Log exports all categories

Ensure the Activity Log profile is configured to export all categories of
events including Administrative, Security, ServiceHealth, Alert, Recommendation,
Policy, Autoscale, and ResourceHealth.


**Resource Type:** `azure_monitor_log_profile`

**Compliance:**
- cis-azure-foundations 5.1.4
- pci-dss 10.2.1
- nist-800-53 AU-12

**Remediation:**
1. Navigate to Azure Monitor in Azure Portal
2. Select Activity log > Export Activity Logs
3. Create or edit diagnostic setting
4. Enable all log categories:
   - Administrative
   - Security
   - ServiceHealth
   - Alert
   - Recommendation
   - Policy
   - Autoscale
   - ResourceHealth
5. Configure destination workspace or storage
6. Save configuration


### azure-monitor-010

**Name:** Log Analytics workspace retention at least 90 days

Ensure Log Analytics workspace data retention is set to at least 90 days.
Log Analytics stores security and operational data. Adequate retention
ensures data availability for investigations and compliance audits.


**Resource Type:** `azure_log_analytics_workspace`

**Compliance:**
- cis-azure-foundations 5.1.1
- pci-dss 10.7
- nist-800-53 AU-11

**Remediation:**
1. Navigate to Log Analytics workspace in Azure Portal
2. Under Settings, select Usage and estimated costs
3. Click Data Retention
4. Set retention period to at least 90 days
   - Consider 365 days for compliance requirements
   - Free tier allows 30 days, paid required for longer
5. Review cost implications
6. Save configuration


### azure-network-003

**Name:** Load Balancer diagnostic settings enabled

Ensure Azure Load Balancers have diagnostic settings configured.
Diagnostic logs capture health probe and load balancer events
for monitoring and troubleshooting.


**Resource Type:** `azure_load_balancer`

**Compliance:**
- cis-azure-foundations 5.4
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Navigate to Load Balancer in Azure Portal
2. Under Monitoring, select Diagnostic settings
3. Add diagnostic setting:
   - Enable LoadBalancerAlertEvent
   - Enable LoadBalancerProbeHealthStatus
   - Enable AllMetrics
4. Select destination:
   - Log Analytics workspace (recommended)
   - Storage account
   - Event Hub
5. Save configuration


### azure-network-004

**Name:** VPN Gateway uses IKEv2

Ensure Azure VPN Gateways use IKEv2 for site-to-site connections.
IKEv2 provides improved security and faster reconnection compared
to IKEv1.


**Resource Type:** `azure_vpn_gateway_connection`

**Compliance:**
- cis-azure-foundations 6.4
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Virtual Network Gateway in Azure Portal
2. Select Connections
3. For each S2S connection:
   - Click on the connection
   - Go to Configuration
   - Verify IKE Version is IKEv2
4. If using IKEv1:
   - Create new connection with IKEv2
   - Update on-premises VPN device
   - Migrate traffic
   - Delete old connection


### azure-network-005

**Name:** Azure DNS zone DNSSEC enabled

Ensure Azure DNS public zones have DNSSEC signing enabled.
DNSSEC provides authentication of DNS responses, protecting
against DNS spoofing attacks.


**Resource Type:** `azure_dns_zone`

**Compliance:**
- nist-800-53 SC-20

**Remediation:**
1. Navigate to DNS Zone in Azure Portal
2. Select DNSSEC (preview/GA depending on region)
3. Enable DNSSEC signing:
   - Click Enable
   - Note the DS records
4. Add DS records to parent zone:
   - Contact domain registrar
   - Add DS records for validation
5. Verify DNSSEC is working

Note: DNSSEC is for public zones only.
Private zones use Azure-provided security.


### azure-network-006

**Name:** Private Link used for Azure services

Ensure Private Link is used for accessing Azure PaaS services.
Private Link keeps traffic on Microsoft's network and eliminates
exposure to the public internet.


**Resource Type:** `azure_private_endpoint`

**Compliance:**
- cis-azure-foundations 6.3
- nist-800-53 SC-7
- pci-dss 1.3.1

**Remediation:**
1. Navigate to Private Link Center
2. Create Private Endpoint:
   - Select resource type (Storage, SQL, etc.)
   - Select target resource
   - Select virtual network and subnet
3. Configure DNS:
   - Enable private DNS zone integration
   - Or configure custom DNS
4. Disable public access on target resource
5. Verify connectivity from VNet

Supported services: Storage, SQL, Cosmos DB,
Key Vault, and many more.


### azure-network-009

**Name:** Azure Bastion used for VM access

Ensure Azure Bastion is deployed for secure VM access. Bastion provides
secure RDP/SSH access without exposing VMs to the public internet,
eliminating the need for public IPs or jump boxes.


**Resource Type:** `azure_virtual_network`

**Compliance:**
- cis-azure-foundations 6.1
- nist-800-53 AC-17
- pci-dss 8.2.1

**Remediation:**
1. Create AzureBastionSubnet:
   - Navigate to Virtual Network
   - Add subnet named "AzureBastionSubnet"
   - Minimum size /26
2. Deploy Bastion:
   - Navigate to Bastion
   - Create new Bastion host
   - Select VNet and subnet
   - Choose SKU (Basic or Standard)
3. Remove public IPs from VMs
4. Access VMs through Portal:
   - Select VM > Connect > Bastion
   - Enter credentials


### azure-network-010

**Name:** Network Watcher enabled in all regions

Ensure Network Watcher is enabled in all regions with deployed resources.
Network Watcher provides network monitoring, diagnostics, and logging
capabilities essential for security and troubleshooting.


**Resource Type:** `azure_network_watcher`

**Compliance:**
- cis-azure-foundations 6.2
- pci-dss 10.2.1
- nist-800-53 AU-6

**Remediation:**
1. Navigate to Network Watcher in Azure Portal
2. Check enabled regions
3. For each region with resources:
   - If not enabled, click to enable
   - Network Watcher is auto-created in NetworkWatcherRG
4. Configure monitoring features:
   - NSG Flow Logs
   - Connection Monitor
   - Traffic Analytics
5. Verify all regions are covered

Note: Network Watcher is required for NSG flow logs
and packet capture functionality.


### azure-sql-002

**Name:** SQL Database uses customer-managed TDE key

Ensure Azure SQL databases use customer-managed keys (CMK) for
Transparent Data Encryption instead of service-managed keys.
CMK provides full control over key lifecycle and access.


**Resource Type:** `azure_sql_database`

**Compliance:**
- cis-azure-foundations 4.1.3
- pci-dss 3.6.1
- nist-800-53 SC-12

**Remediation:**
1. Create a key in Azure Key Vault:
   a. Create or select a Key Vault
   b. Create a new RSA 2048 key
   c. Enable soft delete and purge protection
2. Grant SQL Server access to Key Vault:
   a. Navigate to the SQL Server
   b. Enable system-assigned managed identity
   c. Grant Key Vault key permissions
3. Configure TDE with customer-managed key:
   a. Go to SQL Server > Transparent data encryption
   b. Select "Customer-managed key"
   c. Select the Key Vault and key
   d. Save changes


### azure-sql-008

**Name:** Azure SQL vulnerability assessment enabled

Ensure vulnerability assessment is enabled for Azure SQL databases.
Vulnerability assessment scans databases for security issues and
provides actionable remediation guidance.


**Resource Type:** `azure_sql_server`

**Compliance:**
- cis-azure-foundations 4.2.2
- pci-dss 11.3
- nist-800-53 RA-5

**Remediation:**
1. Navigate to SQL Server in Azure Portal
2. Under Security, select Microsoft Defender for Cloud
3. Enable "Microsoft Defender for SQL"
4. Configure Vulnerability Assessment:
   - Select storage account for scan results
   - Enable periodic recurring scans
   - Configure email notifications
5. Save configuration


### azure-storage-005

**Name:** Storage account uses customer-managed keys

Ensure Azure Storage accounts use customer-managed keys (CMK)
for encryption instead of Microsoft-managed keys. CMK provides
full control over encryption keys stored in Azure Key Vault.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.9
- pci-dss 3.6.1
- nist-800-53 SC-12

**Remediation:**
1. Create a key in Azure Key Vault:
   a. Create or use an existing Key Vault
   b. Enable soft delete and purge protection
   c. Create an RSA 2048 key
2. Grant Storage Account access to Key Vault:
   a. Enable managed identity for storage account
   b. Assign Key Vault Crypto Service Encryption User role
3. Configure customer-managed keys:
   a. Navigate to Storage account > Encryption
   b. Select "Customer-managed keys"
   c. Select the Key Vault and key
   d. Save changes


### azure-storage-006

**Name:** Azure Storage blob versioning enabled

Ensure Azure Storage accounts have blob versioning enabled. Versioning
automatically maintains previous versions of blobs, enabling recovery
from accidental modifications or deletions.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.11
- pci-dss 9.5.1
- nist-800-53 CP-9

**Remediation:**
1. Navigate to Storage Account in Azure Portal
2. Under Data management, select Data protection
3. Under Tracking:
   - Enable "Enable versioning for blobs"
4. Save changes

Using Azure CLI:
az storage account blob-service-properties update \
  --account-name ACCOUNT_NAME \
  --enable-versioning true

Note: Configure lifecycle management to control
version retention and costs.


### azure-storage-008

**Name:** Azure Storage immutability policy for compliance

Ensure Azure Storage containers storing compliance data have immutability
policies configured. Immutable storage provides WORM protection, preventing
modification or deletion of blobs.


**Resource Type:** `azure_storage_container`

**Compliance:**
- pci-dss 9.5.1
- nist-800-53 AU-9

**Remediation:**
1. Navigate to Storage Account in Azure Portal
2. Go to Containers
3. Select the container
4. Access policy > Add policy:
   - Time-based retention: Set retention interval
   - Legal hold: For indefinite retention
5. Lock the policy (irreversible for time-based)

Note: Locked policies cannot be deleted. Objects
cannot be modified or deleted during retention.


### azure-storage-010

**Name:** Azure Storage diagnostic logging enabled

Ensure Azure Storage accounts have diagnostic logging enabled.
Storage Analytics logs capture detailed request information for
security analysis, auditing, and troubleshooting.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.12
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Navigate to Storage Account in Azure Portal
2. Under Monitoring, select Diagnostic settings
3. Add diagnostic setting:
   - Enable StorageRead, StorageWrite, StorageDelete
   - Enable AllMetrics
   - Select destination:
     - Log Analytics workspace (recommended)
     - Storage account (for long-term)
     - Event Hub
4. Set retention period
5. Save changes


### azure-storage-011

**Name:** Azure Storage infrastructure encryption enabled

Ensure Azure Storage accounts have infrastructure encryption (double
encryption) enabled. This provides an additional layer of encryption
using a different algorithm at the infrastructure level.


**Resource Type:** `azure_storage_account`

**Compliance:**
- cis-azure-foundations 3.3
- pci-dss 3.4
- nist-800-53 SC-28

**Remediation:**
Infrastructure encryption must be enabled at creation:

1. When creating a new storage account:
   - Advanced tab
   - Enable "Enable infrastructure encryption"
2. Using Azure CLI:
   az storage account create \
     --name ACCOUNT_NAME \
     --require-infrastructure-encryption true

Note: Cannot be enabled on existing accounts.
Create new account and migrate data if required.


### azure-storage-012

**Name:** Azure Storage geo-redundant replication

Ensure critical Azure Storage accounts use geo-redundant storage (GRS)
or geo-zone-redundant storage (GZRS). Geo-redundancy provides disaster
recovery by replicating data to a secondary region.


**Resource Type:** `azure_storage_account`

**Compliance:**
- nist-800-53 CP-9
- pci-dss 9.5.1

**Remediation:**
1. Navigate to Storage Account in Azure Portal
2. Under Settings, select Configuration
3. Under Replication:
   - Select GRS or RA-GRS (with read access)
   - Or GZRS/RA-GZRS for zone + geo redundancy
4. Save changes

Replication options:
- GRS: 6 copies (3 primary, 3 secondary region)
- RA-GRS: Read access to secondary
- GZRS: Zone redundant + geo redundant
- RA-GZRS: Zone + geo with read access


## Low Severity

### azure-storage-009

**Name:** Azure Storage lifecycle management configured

Ensure Azure Storage accounts have lifecycle management policies.
Lifecycle policies automate blob transitions to cooler tiers and
deletion, optimizing storage costs.


**Resource Type:** `azure_storage_account`

**Compliance:**
- nist-800-53 AU-11
- pci-dss 9.5.1

**Remediation:**
1. Navigate to Storage Account in Azure Portal
2. Under Data management, select Lifecycle management
3. Add a rule:
   - Name the rule
   - Select scope (all or filtered by prefix/tags)
   - Add conditions:
     - Move to Cool tier after X days
     - Move to Archive tier after Y days
     - Delete after Z days
4. Save rule

Example: Move to Cool after 30 days, Archive after
90 days, delete after 365 days.

