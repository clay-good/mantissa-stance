# GCP Policies

Security policies for GCP resources.

## Critical Severity

### gcp-compute-006

**Name:** Database ports not exposed to internet

Ensure firewall rules do not allow database port access from the
internet (0.0.0.0/0). Exposing database ports like MySQL (3306),
PostgreSQL (5432), Redis (6379), MongoDB (27017) creates significant
security risks.


**Resource Type:** `gcp_compute_firewall`

**Compliance:**
- cis-gcp-foundations 3.8
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to VPC Network > Firewall in GCP Console
2. Identify rules allowing database ports from 0.0.0.0/0:
   - Port 3306 (MySQL)
   - Port 5432 (PostgreSQL)
   - Port 6379 (Redis)
   - Port 27017 (MongoDB)
   - Port 9200 (Elasticsearch)
3. Edit rules to restrict source ranges
4. Use service accounts or tags for source filtering
5. Consider Private Service Connect for database access


### gcp-compute-007

**Name:** Firewall does not allow all traffic from internet

Ensure no firewall rule allows all traffic from the internet
(0.0.0.0/0 with all protocols/ports). This is an extremely
dangerous configuration that exposes all services.


**Resource Type:** `gcp_compute_firewall`

**Compliance:**
- cis-gcp-foundations 3.5
- pci-dss 1.2.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to VPC Network > Firewall in GCP Console
2. Identify rules allowing all traffic from 0.0.0.0/0
3. Delete or modify these rules to:
   - Specify required protocols and ports only
   - Restrict source IP ranges
   - Use service accounts for source filtering
   - Apply network tags for targeting
4. Review the implicit deny-all ingress rule
5. Document required exceptions


### gcp-iam-003

**Name:** No overly permissive IAM bindings

Ensure IAM policies do not grant overly permissive access. Policies
granting roles like Owner, Editor, or primitive roles to allUsers or
allAuthenticatedUsers expose resources to unauthorized access.


**Resource Type:** `gcp_project_iam_policy`

**Compliance:**
- cis-gcp-foundations 1.1
- pci-dss 7.1.1
- nist-800-53 AC-3

**Remediation:**
1. Navigate to IAM & Admin > IAM in GCP Console
2. Review all bindings with allUsers or allAuthenticatedUsers
3. Remove public bindings unless explicitly required
4. Replace primitive roles (Owner, Editor, Viewer) with predefined roles
5. Apply the principle of least privilege
6. Consider using VPC Service Controls for additional protection


### gcp-logging-001

**Name:** Cloud Audit Logs enabled for all services

Ensure Cloud Audit Logs are enabled for all services. Audit logs record
administrative activities and accesses within GCP resources, providing
crucial visibility for security monitoring and compliance.


**Resource Type:** `gcp_project`

**Compliance:**
- cis-gcp-foundations 2.1
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Go to the GCP Console > IAM & Admin > Audit Logs
2. For each service, configure audit log types:
   - Admin Activity (enabled by default)
   - Data Access (may need to be enabled)
   - System Event (enabled by default)
   - Policy Denied
3. Consider enabling Data Access logs for sensitive services
4. Review and save the configuration


### gcp-logging-006

**Name:** Log metric and alert for project ownership changes

Ensure a log-based metric and alert exist for project ownership changes.
Changes to project owners grant unrestricted access to project resources
and should be monitored and authorized through proper change management.


**Resource Type:** `gcp_logging_metric`

**Compliance:**
- cis-gcp-foundations 2.6
- pci-dss 10.2.2
- nist-800-53 AU-6

**Remediation:**
1. Go to GCP Console > Logging > Log-based Metrics
2. Click Create Metric
3. Set filter:
   (protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND
   (ProjectOwnership OR projectOwnerInvitee) OR
   (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND
    protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR
   (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND
    protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
4. Create the metric
5. Create alerting policy with immediate notification


### gcp-sql-002

**Name:** Cloud SQL instance public IP disabled

Ensure Cloud SQL database instances do not have public IP addresses.
Public IPs expose the database to internet-based attacks. Use private
IP with VPC peering or Cloud SQL Proxy for secure access.


**Resource Type:** `gcp_cloudsql_instance`

**Compliance:**
- cis-gcp-foundations 6.6
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Cloud SQL in Google Cloud Console
2. Select the instance
3. Click Edit
4. Under Connectivity:
   - Disable "Public IP"
   - Enable "Private IP" if not already enabled
   - Configure VPC network for private access
5. Save changes

Note: Ensure applications use Cloud SQL Proxy or VPC peering
to connect to the private IP.


### gcp-sql-007

**Name:** Cloud SQL authorized networks restricted

Ensure Cloud SQL instances do not allow connections from any IP (0.0.0.0/0).
Unrestricted authorized networks expose the database to brute force attacks
and unauthorized access attempts from the internet.


**Resource Type:** `gcp_cloudsql_instance`

**Compliance:**
- cis-gcp-foundations 6.5
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Cloud SQL in Google Cloud Console
2. Select the instance
3. Click Edit
4. Under Connectivity > Authorized networks:
   - Remove any entries with 0.0.0.0/0
   - Add specific IP ranges that need access
   - Consider using Cloud SQL Proxy instead
5. Save changes

Best practice: Use private IP with VPC peering or Cloud SQL
Proxy instead of authorized networks.


## High Severity

### gcp-compute-003

**Name:** SSH access restricted from internet

Ensure firewall rules do not allow SSH (port 22) access from the
internet (0.0.0.0/0). Unrestricted SSH access exposes instances to
brute force attacks and should be limited to specific trusted IPs.


**Resource Type:** `gcp_compute_firewall`

**Compliance:**
- cis-gcp-foundations 3.6
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to VPC Network > Firewall in GCP Console
2. Identify rules allowing SSH from 0.0.0.0/0
3. Edit the rule to restrict source ranges to trusted IPs
4. Consider using Identity-Aware Proxy (IAP) for SSH access
5. Or use Cloud VPN/Interconnect for secure access
6. Delete or disable unnecessary SSH rules


### gcp-compute-004

**Name:** RDP access restricted from internet

Ensure firewall rules do not allow RDP (port 3389) access from the
internet (0.0.0.0/0). Unrestricted RDP access exposes Windows instances
to brute force attacks and should be limited to specific trusted IPs.


**Resource Type:** `gcp_compute_firewall`

**Compliance:**
- cis-gcp-foundations 3.7
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to VPC Network > Firewall in GCP Console
2. Identify rules allowing RDP from 0.0.0.0/0
3. Edit the rule to restrict source ranges to trusted IPs
4. Consider using Identity-Aware Proxy (IAP) for RDP access
5. Or use Cloud VPN/Interconnect for secure access
6. Delete or disable unnecessary RDP rules


### gcp-functions-002

**Name:** Cloud Function ingress restricted

Ensure Cloud Functions have ingress settings configured to restrict
access. Functions should only allow internal traffic or traffic through
load balancers unless public access is required.


**Resource Type:** `gcp_cloud_function`

**Compliance:**
- cis-gcp-foundations 7.2
- nist-800-53 SC-7
- pci-dss 1.3.1

**Remediation:**
1. Navigate to Cloud Functions in Google Cloud Console
2. Select the function
3. Click Edit
4. Under Networking > Ingress settings:
   - Select "Allow internal traffic only" or
   - Select "Allow internal traffic and traffic from Cloud Load Balancing"
5. Deploy the function

Consider using Cloud Load Balancing with Cloud Armor for
public-facing functions.


### gcp-functions-003

**Name:** Cloud Function uses supported runtime

Ensure Cloud Functions use a supported runtime version. Deprecated
runtimes do not receive security patches and may have known vulnerabilities.
Upgrade to supported versions for continued security updates.


**Resource Type:** `gcp_cloud_function`

**Compliance:**
- nist-800-53 SI-2
- pci-dss 6.3.3

**Remediation:**
1. Navigate to Cloud Functions in Google Cloud Console
2. Select the function
3. Click Edit
4. Under Runtime, select a supported version:
   - Python: 3.9, 3.10, 3.11, 3.12
   - Node.js: 18, 20, 22
   - Go: 1.21, 1.22
   - Java: 11, 17, 21
5. Test the function with the new runtime
6. Deploy the function

Check deprecation schedule in Google Cloud documentation.


### gcp-functions-005

**Name:** Cloud Function uses Secret Manager for secrets

Ensure Cloud Functions use Secret Manager for sensitive data instead
of environment variables. Secret Manager provides encryption, access
control, and audit logging for secrets.


**Resource Type:** `gcp_cloud_function`

**Compliance:**
- cis-gcp-foundations 7.3
- nist-800-53 SC-12
- pci-dss 3.4

**Remediation:**
1. Store secrets in Secret Manager:
   - gcloud secrets create SECRET_NAME --data-file=SECRET_FILE
2. Grant function service account access:
   - gcloud secrets add-iam-policy-binding SECRET_NAME \
     --member="serviceAccount:FUNCTION_SA@PROJECT.iam.gserviceaccount.com" \
     --role="roles/secretmanager.secretAccessor"
3. Configure function to use secrets:
   - Using secret volumes, or
   - Using secret environment variables (Cloud Functions Gen2)
4. Remove plain text secrets from environment variables
5. Deploy the function


### gcp-iam-002

**Name:** Default compute service account not used

Ensure the default Compute Engine service account is not used for VMs.
The default service account has broad permissions that violate the
principle of least privilege. Use dedicated service accounts instead.


**Resource Type:** `gcp_compute_instance`

**Compliance:**
- cis-gcp-foundations 1.6
- nist-800-53 AC-6

**Remediation:**
1. Create a new service account with minimal required permissions
2. Navigate to Compute Engine > VM instances
3. Stop the VM instance
4. Edit the instance configuration
5. Under "Identity and API access", change the service account
6. Select the new dedicated service account
7. Restart the VM instance


### gcp-iam-006

**Name:** Service Account Admin role not overly assigned

Ensure the Service Account Admin role is not broadly assigned.
This role allows managing service accounts and their keys, which
can lead to privilege escalation. Limit this role to designated
administrators only.


**Resource Type:** `gcp_project_iam_binding`

**Compliance:**
- cis-gcp-foundations 1.5
- nist-800-53 AC-6(7)

**Remediation:**
1. Navigate to IAM & Admin > IAM in GCP Console
2. Filter for the Service Account Admin role
3. Review all members with this role
4. Remove the role from users who don't need it
5. Consider using Service Account User role instead
   for users who only need to run workloads as service accounts
6. Use conditional IAM bindings to limit scope
7. Implement approval workflows for this role


### gcp-iam-007

**Name:** Separation of duties for KMS

Ensure separation of duties is enforced for Cloud KMS. Users should
not have both the ability to manage encryption keys and use them.
This prevents a single user from having complete control over
encrypted data.


**Resource Type:** `gcp_project_iam_policy`

**Compliance:**
- cis-gcp-foundations 1.11
- pci-dss 3.6.1
- nist-800-53 AC-5

**Remediation:**
1. Navigate to IAM & Admin > IAM in GCP Console
2. Identify users with Cloud KMS Admin role
3. Verify these users don't also have:
   - Cloud KMS CryptoKey Encrypter/Decrypter
   - Cloud KMS Encrypter
   - Cloud KMS Decrypter
4. Separate key management from key usage:
   - Key admins manage keys but can't use them
   - Key users can encrypt/decrypt but can't manage keys
5. Document and enforce this separation policy
6. Use IAM Conditions to further restrict access


### gcp-logging-005

**Name:** Log metric and alert for audit configuration changes

Ensure a log-based metric and alert exist for audit configuration changes.
Changes to audit logging configuration could indicate an attempt to hide
malicious activity and should be closely monitored.


**Resource Type:** `gcp_logging_metric`

**Compliance:**
- cis-gcp-foundations 2.5
- pci-dss 10.5.5
- nist-800-53 AU-9

**Remediation:**
1. Go to GCP Console > Logging > Log-based Metrics
2. Click Create Metric
3. Set filter:
   protoPayload.methodName="SetIamPolicy" AND
   protoPayload.serviceData.policyDelta.auditConfigDeltas:*
4. Create the metric
5. Go to Monitoring > Alerting
6. Create alerting policy based on the metric
7. Configure immediate notification for security team


### gcp-logging-010

**Name:** Log metric and alert for Cloud Storage permission changes

Ensure a log-based metric and alert exist for Cloud Storage bucket permission
changes. Storage permission changes can expose sensitive data publicly or
grant unauthorized access and should be monitored.


**Resource Type:** `gcp_logging_metric`

**Compliance:**
- cis-gcp-foundations 2.10
- pci-dss 10.2.5
- nist-800-53 AU-6

**Remediation:**
1. Go to GCP Console > Logging > Log-based Metrics
2. Click Create Metric
3. Set filter:
   resource.type="gcs_bucket" AND
   protoPayload.methodName="storage.setIamPermissions"
4. Create the metric
5. Go to Monitoring > Alerting
6. Create alerting policy based on the metric
7. Configure immediate notification for data protection team


### gcp-network-001

**Name:** Load balancer Cloud Armor protection enabled

Ensure Google Cloud Load Balancers have Cloud Armor security policies
attached. Cloud Armor provides DDoS protection and WAF capabilities
for internet-facing applications.


**Resource Type:** `gcp_compute_backend_service`

**Compliance:**
- pci-dss 6.4.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to Network Security > Cloud Armor
2. Create a security policy:
   - Add preconfigured WAF rules
   - Configure adaptive protection
   - Set default action
3. Navigate to Load Balancing
4. Select the load balancer
5. Edit backend service
6. Under Security:
   - Select the Cloud Armor policy
7. Save configuration


### gcp-network-002

**Name:** Load balancer uses HTTPS frontend

Ensure Google Cloud Load Balancers use HTTPS for frontend connections.
HTTP traffic is unencrypted and vulnerable to interception. Use HTTPS
with managed or custom certificates.


**Resource Type:** `gcp_compute_url_map`

**Compliance:**
- cis-gcp-foundations 3.9
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Load Balancing in Console
2. Select the load balancer
3. Edit configuration
4. In Frontend configuration:
   - Add HTTPS frontend
   - Select or create SSL certificate
   - Set minimum TLS version to 1.2
5. Optionally configure HTTP to HTTPS redirect
6. Save configuration


### gcp-network-003

**Name:** SSL policy uses modern profile

Ensure SSL policies use MODERN or RESTRICTED profile. Legacy SSL
profiles allow weak cipher suites vulnerable to attacks. Modern
profiles enforce TLS 1.2+ with secure ciphers.


**Resource Type:** `gcp_compute_ssl_policy`

**Compliance:**
- cis-gcp-foundations 3.8
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Network Security > SSL Policies
2. Select or create SSL policy
3. Configure:
   - Profile: MODERN (recommended) or RESTRICTED
   - Minimum TLS version: TLS 1.2
4. Apply policy to target proxies:
   - Navigate to Load Balancing
   - Edit load balancer frontend
   - Select the SSL policy
5. Save configuration


### gcp-network-010

**Name:** Cloud Interconnect uses MACsec encryption

Ensure Dedicated Interconnect connections use MACsec encryption.
MACsec provides link-layer encryption for data in transit between
on-premises and Google Cloud.


**Resource Type:** `gcp_compute_interconnect`

**Compliance:**
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Hybrid Connectivity > Interconnect
2. Select the Dedicated Interconnect
3. Enable MACsec:
   - Configure MACsec at both ends
   - Google supports MACsec on 100 Gbps links
4. Configure pre-shared keys:
   - Generate CAK/CKN pairs
   - Configure on both devices
5. Verify encryption is active

Note: MACsec is available for Dedicated Interconnect only.
For Partner Interconnect, use Cloud VPN for encryption.


### gcp-sql-003

**Name:** Cloud SQL SSL/TLS required for connections

Ensure Cloud SQL instances require SSL/TLS for all database connections.
SSL ensures data in transit is encrypted, protecting against eavesdropping
and man-in-the-middle attacks.


**Resource Type:** `gcp_cloudsql_instance`

**Compliance:**
- cis-gcp-foundations 6.4
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Navigate to Cloud SQL in Google Cloud Console
2. Select the instance
3. Click Edit
4. Under Connections:
   - Expand SSL/TLS section
   - Set "Require SSL" to On
5. Save changes

After enabling, create client certificates for applications:
- gcloud sql ssl client-certs create CERT_NAME CERT_FILE --instance=INSTANCE


### gcp-sql-004

**Name:** Cloud SQL automated backups enabled

Ensure Cloud SQL instances have automated backups enabled. Automated
backups provide point-in-time recovery capability and protect against
data loss from accidental deletion or corruption.


**Resource Type:** `gcp_cloudsql_instance`

**Compliance:**
- cis-gcp-foundations 6.7
- pci-dss 9.5.1
- nist-800-53 CP-9

**Remediation:**
1. Navigate to Cloud SQL in Google Cloud Console
2. Select the instance
3. Click Edit
4. Under Backups:
   - Enable "Automated backups"
   - Set backup start time
   - Enable point-in-time recovery (recommended)
   - Set retention period (7-365 days)
5. Save changes


### gcp-sql-008

**Name:** Cloud SQL deletion protection enabled

Ensure Cloud SQL instances have deletion protection enabled.
Deletion protection prevents accidental or unauthorized deletion
of production databases through the console, CLI, or API.


**Resource Type:** `gcp_cloudsql_instance`

**Compliance:**
- nist-800-53 SC-28
- pci-dss 9.4.5

**Remediation:**
1. Navigate to Cloud SQL in Google Cloud Console
2. Select the instance
3. Click Edit
4. Under Data protection:
   - Enable "Enable deletion protection"
5. Save changes

To delete a protected instance, you must first disable
deletion protection.


### gcp-storage-002

**Name:** Public access prevention enforced

Ensure public access prevention is enforced on Cloud Storage buckets.
This setting prevents any accidental public exposure of data by
blocking all public access configurations.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- cis-gcp-foundations 5.1
- pci-dss 7.2.1
- nist-800-53 AC-3

**Remediation:**
1. Navigate to Cloud Storage in GCP Console
2. Select the bucket
3. Go to the Permissions tab
4. Under "Public access prevention", click Edit
5. Select "Enforce public access prevention"
6. Save the changes
Alternatively, set at organization policy level for all buckets


## Medium Severity

### gcp-compute-001

**Name:** Serial port access disabled

Ensure serial port access is disabled on Compute Engine instances.
Serial port access provides a potential entry point for attackers
and should be disabled unless specifically required for debugging.


**Resource Type:** `gcp_compute_instance`

**Compliance:**
- cis-gcp-foundations 4.5
- nist-800-53 AC-17

**Remediation:**
1. Navigate to Compute Engine > VM instances
2. Select the instance
3. Click Edit
4. Under Metadata, remove or set "serial-port-enable" to "false"
5. Save the changes
6. Or set organization policy "compute.disableSerialPortAccess" to true


### gcp-compute-002

**Name:** OS Login enabled

Ensure OS Login is enabled on Compute Engine instances. OS Login
provides centralized SSH key management through Cloud IAM, replacing
metadata-based SSH keys and providing better access control and auditing.


**Resource Type:** `gcp_compute_instance`

**Compliance:**
- cis-gcp-foundations 4.4
- nist-800-53 IA-2

**Remediation:**
1. Navigate to Compute Engine > VM instances
2. Select the instance
3. Click Edit
4. Under Metadata, add "enable-oslogin" = "TRUE"
5. Save the changes
6. Grant users roles/compute.osLogin or roles/compute.osAdminLogin
7. Consider enabling organization-wide via organization policy


### gcp-compute-005

**Name:** Shielded VM enabled

Ensure Shielded VM is enabled on Compute Engine instances. Shielded
VMs provide verifiable integrity using Secure Boot, vTPM, and
Integrity Monitoring to protect against rootkits and bootkits.


**Resource Type:** `gcp_compute_instance`

**Compliance:**
- cis-gcp-foundations 4.8
- nist-800-53 SI-7

**Remediation:**
1. When creating a new instance, enable Shielded VM options
2. For existing instances, Shielded VM cannot be enabled
3. Create a new Shielded VM instance and migrate workloads
4. Enable Secure Boot, vTPM, and Integrity Monitoring
5. Consider using organization policy to enforce Shielded VMs


### gcp-compute-008

**Name:** VPC flow logs enabled

Ensure VPC flow logs are enabled for all subnets. Flow logs
capture network flow information for monitoring, forensics,
and real-time security analysis.


**Resource Type:** `gcp_compute_subnetwork`

**Compliance:**
- cis-gcp-foundations 3.9
- pci-dss 10.2.1
- nist-800-53 AU-12

**Remediation:**
1. Navigate to VPC Network > VPC networks in GCP Console
2. Select the VPC network
3. Click on the subnet name
4. Edit the subnet
5. Enable "Flow logs"
6. Configure:
   - Aggregation interval (5 seconds recommended)
   - Sample rate (50% or higher for security)
   - Include metadata
7. Save changes
8. View logs in Cloud Logging


### gcp-compute-010

**Name:** Default network deleted

Ensure the default VPC network is deleted. The default network
has overly permissive firewall rules and should not be used for
production workloads. Create custom VPC networks instead.


**Resource Type:** `gcp_compute_network`

**Compliance:**
- cis-gcp-foundations 3.1
- nist-800-53 SC-7

**Remediation:**
1. Create custom VPC networks for your workloads
2. Migrate any resources from the default network
3. Navigate to VPC Network > VPC networks in GCP Console
4. Select the "default" network
5. Delete all firewall rules in the default network first
6. Delete the default network
7. Optionally, disable default network creation in
   Organization Policy (constraints/compute.skipDefaultNetworkCreation)


### gcp-compute-011

**Name:** Compute disks use CMEK encryption

Ensure Compute Engine persistent disks use customer-managed
encryption keys (CMEK). While Google encrypts all data by default,
CMEK provides control over key management and rotation.


**Resource Type:** `gcp_compute_disk`

**Compliance:**
- cis-gcp-foundations 4.7
- pci-dss 3.6.1
- nist-800-53 SC-12

**Remediation:**
For new disks:
1. Create a Cloud KMS key ring and key
2. Grant Compute Engine service account access to the key
3. During disk creation, select CMEK encryption
4. Choose the KMS key

For existing disks:
1. Create a snapshot of the disk
2. Create a new disk from snapshot with CMEK
3. Attach the new disk to the instance
4. Detach and delete the old disk

Note: Boot disks require recreating the instance.


### gcp-functions-001

**Name:** Cloud Function VPC connector configured

Ensure Cloud Functions that access private resources use VPC connectors.
VPC connectors enable functions to access resources in private VPCs
without exposing them to the public internet.


**Resource Type:** `gcp_cloud_function`

**Compliance:**
- nist-800-53 SC-7
- pci-dss 1.3.1

**Remediation:**
1. Navigate to Cloud Functions in Google Cloud Console
2. Select the function
3. Click Edit
4. Under Networking:
   - Select "Allow internal traffic only" or
   - Configure VPC connector
5. Choose or create a VPC connector
6. Select egress settings:
   - Route all traffic through VPC connector, or
   - Route only private IP traffic
7. Deploy the function


### gcp-functions-004

**Name:** Cloud Function uses custom service account

Ensure Cloud Functions use custom service accounts instead of the
default compute service account. Custom service accounts enable
least-privilege access control for function permissions.


**Resource Type:** `gcp_cloud_function`

**Compliance:**
- cis-gcp-foundations 7.1
- nist-800-53 AC-6
- pci-dss 7.2.1

**Remediation:**
1. Create a custom service account:
   - gcloud iam service-accounts create FUNCTION_SA
2. Grant only necessary permissions to the service account
3. Navigate to Cloud Functions in Console
4. Select the function
5. Click Edit
6. Under Runtime service account:
   - Select the custom service account
7. Deploy the function

Best practice: Create separate service accounts for each
function or group of related functions.


### gcp-functions-007

**Name:** Cloud Function CMEK encryption enabled

Ensure Cloud Functions use Customer Managed Encryption Keys (CMEK)
for encryption. CMEK provides control over encryption keys and enables
compliance requirements around key management.


**Resource Type:** `gcp_cloud_function`

**Compliance:**
- nist-800-53 SC-12
- pci-dss 3.6.1

**Remediation:**
1. Create a KMS key:
   - gcloud kms keys create KEY_NAME \
     --location=REGION --keyring=KEYRING --purpose=encryption
2. Grant Cloud Functions service agent access:
   - gcloud kms keys add-iam-policy-binding KEY_NAME \
     --location=REGION --keyring=KEYRING \
     --member="serviceAccount:service-PROJECT_NUMBER@gcf-admin-robot.iam.gserviceaccount.com" \
     --role="roles/cloudkms.cryptoKeyEncrypterDecrypter"
3. Deploy function with CMEK:
   - gcloud functions deploy FUNCTION_NAME \
     --kms-key=projects/PROJECT/locations/REGION/keyRings/KEYRING/cryptoKeys/KEY_NAME


### gcp-iam-001

**Name:** Service account keys rotated within 90 days

Ensure service account keys are rotated within 90 days. Long-lived keys
increase the risk of unauthorized access if compromised. Regular rotation
reduces the window of opportunity for attackers.


**Resource Type:** `gcp_service_account`

**Compliance:**
- cis-gcp-foundations 1.7
- nist-800-53 IA-5(1)

**Remediation:**
1. Navigate to IAM & Admin > Service Accounts in GCP Console
2. Select the service account with old keys
3. Go to the Keys tab
4. Create a new key
5. Update applications to use the new key
6. Delete the old key after verifying new key works
7. Consider using Workload Identity instead of keys where possible


### gcp-iam-004

**Name:** Service accounts do not have broad OAuth scopes

Ensure service accounts do not use cloud-platform scope which grants
full access to all GCP APIs. Use specific scopes required by the
application to follow the principle of least privilege.


**Resource Type:** `gcp_compute_instance`

**Compliance:**
- cis-gcp-foundations 1.5
- nist-800-53 AC-6(9)

**Remediation:**
1. Identify the minimal API scopes required by the application
2. Stop the VM instance
3. Edit the instance configuration
4. Under "Identity and API access", select "Set access for each API"
5. Enable only the required scopes
6. Consider using Workload Identity for GKE workloads
7. Restart the VM instance


### gcp-iam-005

**Name:** Service accounts without user-managed keys

Ensure service accounts do not have user-managed keys when possible.
User-managed keys pose security risks as they can be leaked or
compromised. Prefer using Google-managed keys, Workload Identity,
or service account impersonation instead.


**Resource Type:** `gcp_service_account`

**Compliance:**
- cis-gcp-foundations 1.4
- nist-800-53 IA-5(2)

**Remediation:**
1. Navigate to IAM & Admin > Service Accounts in GCP Console
2. Select the service account with user-managed keys
3. Go to the Keys tab
4. Evaluate if keys are necessary:
   - For GKE workloads, use Workload Identity
   - For Cloud Run/Functions, use built-in identity
   - For cross-project access, use service account impersonation
5. Migrate applications away from using keys
6. Delete user-managed keys after migration
7. Monitor for key creation using Cloud Audit Logs


### gcp-iam-008

**Name:** API keys have restrictions

Ensure API keys have application and API restrictions configured.
Unrestricted API keys can be used from any source and access any
enabled API, increasing the risk of abuse if leaked.


**Resource Type:** `gcp_api_key`

**Compliance:**
- cis-gcp-foundations 1.12
- nist-800-53 AC-3

**Remediation:**
1. Navigate to APIs & Services > Credentials in GCP Console
2. Select the API key to restrict
3. Under "Application restrictions":
   - Choose HTTP referrers for web apps
   - Choose IP addresses for servers
   - Choose Android/iOS apps for mobile
4. Under "API restrictions":
   - Select "Restrict key"
   - Choose only the APIs this key needs
5. Consider using service accounts instead of API keys
6. Rotate API keys regularly


### gcp-logging-002

**Name:** Log sink configured for long-term retention

Ensure a log sink is configured to export logs to Cloud Storage, BigQuery,
or Pub/Sub for long-term retention and analysis. Default log retention in
Cloud Logging may not meet compliance requirements.


**Resource Type:** `gcp_logging_sink`

**Compliance:**
- cis-gcp-foundations 2.2
- pci-dss 10.7
- nist-800-53 AU-11

**Remediation:**
1. Go to GCP Console > Logging > Log Router
2. Click Create Sink
3. Configure sink name and destination:
   - Cloud Storage bucket for archival
   - BigQuery dataset for analysis
   - Pub/Sub topic for real-time streaming
4. Set inclusion/exclusion filters as needed
5. Create the sink
6. Grant necessary permissions to sink service account


### gcp-logging-003

**Name:** Log bucket retention meets compliance requirements

Ensure Cloud Logging log buckets have retention periods configured that
meet compliance requirements. The default retention is 30 days which may
not be sufficient for security investigations or regulatory compliance.


**Resource Type:** `gcp_logging_bucket`

**Compliance:**
- cis-gcp-foundations 2.3
- pci-dss 10.7
- nist-800-53 AU-11

**Remediation:**
1. Go to GCP Console > Logging > Log Storage
2. Select the log bucket
3. Click Edit
4. Set retention period (minimum 90 days recommended, or per compliance)
5. Enable locked retention if immutability is required
6. Save changes


### gcp-logging-004

**Name:** Log metric and alert for IAM permission changes

Ensure a log-based metric and alert exist for IAM permission changes.
Unauthorized IAM changes can lead to privilege escalation or loss of
access controls and should be monitored.


**Resource Type:** `gcp_logging_metric`

**Compliance:**
- cis-gcp-foundations 2.4
- pci-dss 10.2.5
- nist-800-53 AU-6

**Remediation:**
1. Go to GCP Console > Logging > Log-based Metrics
2. Click Create Metric
3. Set filter:
   protoPayload.methodName="SetIamPolicy" OR
   protoPayload.methodName="setIamPolicy"
4. Create the metric
5. Go to Monitoring > Alerting
6. Create alerting policy based on the metric
7. Configure notification channels (email, Slack, PagerDuty)


### gcp-logging-007

**Name:** Log metric and alert for VPC firewall rule changes

Ensure a log-based metric and alert exist for VPC firewall rule changes.
Unauthorized firewall modifications can expose resources to network attacks
and should be monitored and investigated.


**Resource Type:** `gcp_logging_metric`

**Compliance:**
- cis-gcp-foundations 2.7
- pci-dss 10.2.5
- nist-800-53 AU-6

**Remediation:**
1. Go to GCP Console > Logging > Log-based Metrics
2. Click Create Metric
3. Set filter:
   resource.type="gce_firewall_rule" AND
   (protoPayload.methodName:"compute.firewalls.patch" OR
    protoPayload.methodName:"compute.firewalls.insert" OR
    protoPayload.methodName:"compute.firewalls.delete")
4. Create the metric
5. Go to Monitoring > Alerting
6. Create alerting policy based on the metric
7. Notify network and security teams


### gcp-logging-008

**Name:** Log metric and alert for VPC network route changes

Ensure a log-based metric and alert exist for VPC network route changes.
Unauthorized route changes can redirect traffic for interception or
disrupt network connectivity and should be monitored.


**Resource Type:** `gcp_logging_metric`

**Compliance:**
- cis-gcp-foundations 2.8
- pci-dss 10.2.5
- nist-800-53 AU-6

**Remediation:**
1. Go to GCP Console > Logging > Log-based Metrics
2. Click Create Metric
3. Set filter:
   resource.type="gce_route" AND
   (protoPayload.methodName:"compute.routes.delete" OR
    protoPayload.methodName:"compute.routes.insert")
4. Create the metric
5. Go to Monitoring > Alerting
6. Create alerting policy based on the metric


### gcp-logging-009

**Name:** Log metric and alert for Cloud SQL configuration changes

Ensure a log-based metric and alert exist for Cloud SQL instance configuration
changes. Database configuration changes can affect security, availability,
and should be tracked and authorized.


**Resource Type:** `gcp_logging_metric`

**Compliance:**
- cis-gcp-foundations 2.11
- pci-dss 10.2.5
- nist-800-53 AU-6

**Remediation:**
1. Go to GCP Console > Logging > Log-based Metrics
2. Click Create Metric
3. Set filter:
   protoPayload.methodName="cloudsql.instances.update"
4. Create the metric
5. Go to Monitoring > Alerting
6. Create alerting policy based on the metric
7. Notify database and security teams


### gcp-network-004

**Name:** Cloud NAT logging enabled

Ensure Cloud NAT gateways have logging enabled. NAT logs capture
connection information for security analysis, troubleshooting,
and compliance auditing.


**Resource Type:** `gcp_compute_router_nat`

**Compliance:**
- cis-gcp-foundations 3.7
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Navigate to Network Services > Cloud NAT
2. Select the NAT gateway
3. Click Edit
4. Under Logging:
   - Enable logging
   - Select filter: All (recommended) or Errors only
5. Save configuration

Logs are sent to Cloud Logging and can be exported
to BigQuery or Cloud Storage.


### gcp-network-005

**Name:** Cloud DNS DNSSEC enabled

Ensure Cloud DNS managed zones have DNSSEC enabled. DNSSEC provides
authentication of DNS responses, protecting against DNS spoofing
and cache poisoning attacks.


**Resource Type:** `gcp_dns_managed_zone`

**Compliance:**
- cis-gcp-foundations 3.3
- nist-800-53 SC-20

**Remediation:**
1. Navigate to Cloud DNS in Console
2. Select the managed zone
3. Click DNSSEC tab
4. Enable DNSSEC:
   - Click Enable
   - Note the DS records
5. Add DS records to parent zone:
   - For domain registrar-managed zones
   - Update registrar with DS records
6. Verify DNSSEC is working

Note: DNSSEC must be configured at registrar for
root domains to be fully protected.


### gcp-network-006

**Name:** Private Service Connect used for Google APIs

Ensure Private Service Connect is used for accessing Google APIs
and services. PSC keeps traffic within Google's network and avoids
exposure to the public internet.


**Resource Type:** `gcp_compute_network`

**Compliance:**
- nist-800-53 SC-7
- pci-dss 1.3.1

**Remediation:**
1. Navigate to VPC Network > Private Service Connect
2. Create endpoint:
   - Select target: All Google APIs or specific bundles
   - Select network and subnetwork
   - Assign IP address
3. Configure DNS:
   - Create private DNS zone for googleapis.com
   - Point to PSC endpoint
4. Verify connectivity from VMs

Traffic to Google APIs now stays on Google's network.


### gcp-network-007

**Name:** Cloud VPN uses IKE v2

Ensure Cloud VPN tunnels use IKE version 2. IKE v2 provides improved
security, faster reconnection, and better NAT traversal compared to
IKE v1.


**Resource Type:** `gcp_compute_vpn_tunnel`

**Compliance:**
- cis-gcp-foundations 3.4
- nist-800-53 SC-8
- pci-dss 4.2.1

**Remediation:**
1. Navigate to Hybrid Connectivity > VPN
2. Note: IKE version cannot be changed on existing tunnels
3. Create new VPN tunnel:
   - Select VPN gateway
   - Configure peer gateway
   - Set IKE version to IKEv2
   - Configure routing and traffic selectors
4. Update peer VPN to match IKE v2
5. Migrate traffic to new tunnel
6. Delete old IKE v1 tunnel


### gcp-network-008

**Name:** Firewall rules have logging enabled

Ensure VPC firewall rules have logging enabled. Firewall logs capture
allowed and denied connections for security monitoring, threat detection,
and compliance auditing.


**Resource Type:** `gcp_compute_firewall`

**Compliance:**
- cis-gcp-foundations 3.6
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Navigate to VPC Network > Firewall
2. Select the firewall rule
3. Click Edit
4. Under Logs:
   - Set to On
   - Select metadata: Include all
5. Save changes

Consider enabling logging for:
- All deny rules (critical)
- Allow rules for sensitive resources
- Rules with 0.0.0.0/0 source

Note: Logging increases costs. Enable selectively.


### gcp-network-009

**Name:** Identity-Aware Proxy enabled for web apps

Ensure Identity-Aware Proxy (IAP) is enabled for web applications.
IAP provides context-aware access control, replacing VPN-based
access with zero-trust security.


**Resource Type:** `gcp_compute_backend_service`

**Compliance:**
- nist-800-53 AC-3
- pci-dss 8.2.1

**Remediation:**
1. Navigate to Security > Identity-Aware Proxy
2. Select the backend service
3. Enable IAP:
   - Toggle IAP on
   - Configure OAuth consent screen if needed
4. Add IAM policy:
   - Grant IAP-secured Web App User role
   - Specify allowed users/groups
5. Configure access levels (optional):
   - Device trust
   - IP restrictions
   - Time-based access


### gcp-sql-001

**Name:** Cloud SQL uses CMEK encryption

Ensure Cloud SQL instances use customer-managed encryption keys
(CMEK) instead of Google-managed keys. CMEK provides full control
over key lifecycle, rotation, and access policies.


**Resource Type:** `gcp_sql_instance`

**Compliance:**
- cis-gcp-foundations 6.1
- pci-dss 3.6.1
- nist-800-53 SC-12

**Remediation:**
Note: CMEK must be configured during instance creation.
To migrate an existing instance:
1. Create a Cloud KMS key ring and key
2. Grant Cloud SQL service account access to the key
3. Create a new instance with CMEK enabled
4. Export data from the old instance
5. Import data into the new encrypted instance
6. Update applications to use the new instance
7. Delete the old instance

For new instances:
1. Create Cloud KMS key with appropriate permissions
2. Select CMEK during instance creation


### gcp-sql-005

**Name:** Cloud SQL binary logging enabled for MySQL

Ensure Cloud SQL MySQL instances have binary logging enabled.
Binary logging is required for point-in-time recovery and replication.
It captures all changes to the database for recovery purposes.


**Resource Type:** `gcp_cloudsql_instance`

**Compliance:**
- cis-gcp-foundations 6.7
- nist-800-53 CP-9
- pci-dss 9.5.1

**Remediation:**
1. Navigate to Cloud SQL in Google Cloud Console
2. Select the MySQL instance
3. Click Edit
4. Under Backups:
   - Enable "Point-in-time recovery"
   - This automatically enables binary logging
5. Save changes

Note: Binary logging increases storage usage. Consider
setting appropriate retention period.


### gcp-sql-006

**Name:** Cloud SQL high availability configured

Ensure Cloud SQL production instances have high availability configured.
High availability provides automatic failover to a standby instance in
a different zone, ensuring business continuity.


**Resource Type:** `gcp_cloudsql_instance`

**Compliance:**
- nist-800-53 CP-10
- pci-dss 12.10.1

**Remediation:**
1. Navigate to Cloud SQL in Google Cloud Console
2. Select the instance
3. Click Edit
4. Under Configuration options:
   - Select "High availability (regional)"
5. Save changes

Note: High availability requires instance restart and
increases costs. Plan migration during maintenance window.


### gcp-storage-001

**Name:** Uniform bucket-level access enabled

Ensure uniform bucket-level access is enabled for Cloud Storage buckets.
This prevents legacy ACLs from being used and ensures all access is
controlled through IAM, providing consistent access control.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- cis-gcp-foundations 5.2
- nist-800-53 AC-3

**Remediation:**
1. Navigate to Cloud Storage in GCP Console
2. Select the bucket
3. Go to the Permissions tab
4. Click "Switch to uniform access"
5. Confirm the switch
Note: This action is irreversible after 90 days


### gcp-storage-004

**Name:** Customer-managed encryption keys used

Ensure Cloud Storage buckets use customer-managed encryption keys (CMEK).
CMEK provides additional control over encryption keys and enables
key rotation and access auditing through Cloud KMS.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- cis-gcp-foundations 5.3
- pci-dss 3.5.1
- nist-800-53 SC-12

**Remediation:**
1. Create a Cloud KMS key ring and key if not exists
2. Grant the Cloud Storage service account permission to use the key
3. Navigate to Cloud Storage in GCP Console
4. Select the bucket or create a new one
5. Under "Default encryption key", select "Customer-managed key"
6. Choose the Cloud KMS key
7. Save the changes


### gcp-storage-005

**Name:** Cloud Storage bucket versioning enabled

Ensure Cloud Storage buckets have object versioning enabled. Versioning
protects against accidental deletions and overwrites by maintaining
historical versions of objects.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- cis-gcp-foundations 5.2
- pci-dss 9.5.1
- nist-800-53 CP-9

**Remediation:**
1. Navigate to Cloud Storage in Console
2. Select the bucket
3. Go to Protection tab
4. Under Object versioning:
   - Click Enable
5. Configure lifecycle rules to manage versions:
   - Delete noncurrent versions after X days
   - Limit number of versions

Using gsutil:
gsutil versioning set on gs://BUCKET_NAME


### gcp-storage-006

**Name:** Cloud Storage bucket has retention policy

Ensure Cloud Storage buckets have retention policies for compliance data.
Retention policies prevent object deletion or modification until the
retention period expires, providing WORM-like protection.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- cis-gcp-foundations 5.1
- pci-dss 9.5.1
- nist-800-53 AU-9

**Remediation:**
1. Navigate to Cloud Storage in Console
2. Select the bucket
3. Go to Protection tab
4. Under Retention policy:
   - Set retention period (seconds)
   - Optionally lock the policy (irreversible)
5. Save changes

Using gsutil:
gsutil retention set DURATION gs://BUCKET_NAME

Note: Locked retention policies cannot be removed
or shortened until all objects expire.


### gcp-storage-009

**Name:** Cloud Storage bucket soft delete enabled

Ensure Cloud Storage buckets have soft delete enabled. Soft delete
retains deleted objects for a configurable period, enabling recovery
from accidental deletions without versioning overhead.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- nist-800-53 CP-9
- pci-dss 9.5.1

**Remediation:**
1. Navigate to Cloud Storage in Console
2. Select the bucket
3. Go to Protection tab
4. Under Soft delete policy:
   - Set retention duration (7-90 days)
5. Save changes

Using gcloud:
gcloud storage buckets update gs://BUCKET_NAME \
  --soft-delete-duration=7d

Default is 7 days. Maximum is 90 days.


### gcp-storage-010

**Name:** Cloud Storage bucket access logs enabled

Ensure Cloud Storage buckets have access logs enabled. Access logs
capture detailed request information for security analysis, auditing,
and troubleshooting.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- cis-gcp-foundations 5.3
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Create a destination bucket for logs
2. Navigate to Cloud Storage in Console
3. Select the source bucket
4. Go to Configuration tab
5. Under Cloud audit logging:
   - Already enabled via Cloud Audit Logs
6. For usage logs (legacy):
   gsutil logging set on -b gs://LOG_BUCKET gs://SOURCE_BUCKET

Recommended: Use Cloud Audit Logs for comprehensive
logging via Admin Activity and Data Access logs.


## Low Severity

### gcp-compute-009

**Name:** Private Google Access enabled

Ensure Private Google Access is enabled for subnets. This allows
VM instances without external IP addresses to reach Google APIs
and services without requiring a NAT gateway.


**Resource Type:** `gcp_compute_subnetwork`

**Compliance:**
- cis-gcp-foundations 3.10
- nist-800-53 SC-7

**Remediation:**
1. Navigate to VPC Network > VPC networks in GCP Console
2. Select the VPC network
3. Click on the subnet name
4. Edit the subnet
5. Enable "Private Google Access"
6. Save changes
7. Consider also enabling Private Service Connect for
   enhanced security and performance


### gcp-functions-006

**Name:** Cloud Function minimum instances configured

Ensure production Cloud Functions have minimum instances configured to
reduce cold start latency. Minimum instances keep containers warm and
ready to handle requests immediately.


**Resource Type:** `gcp_cloud_function`

**Compliance:**
- nist-800-53 SC-5

**Remediation:**
1. Navigate to Cloud Functions in Google Cloud Console
2. Select the function
3. Click Edit
4. Under Runtime, build and connections:
   - Set "Minimum number of instances" to at least 1
5. Deploy the function

Note: Minimum instances incur costs even when idle.
Configure appropriately for latency requirements.


### gcp-storage-003

**Name:** Bucket logging enabled

Ensure Cloud Storage bucket logging is enabled. Access logs provide
visibility into who is accessing the bucket and what operations are
being performed, which is essential for security monitoring and auditing.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- cis-gcp-foundations 5.3
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Create a separate bucket for storing access logs
2. Navigate to Cloud Storage in GCP Console
3. Select the source bucket
4. Click Edit bucket details
5. Under "Access & storage logs", configure logging
6. Specify the log bucket and optional prefix
7. Save the changes


### gcp-storage-007

**Name:** Cloud Storage bucket has lifecycle policy

Ensure Cloud Storage buckets have lifecycle policies configured.
Lifecycle policies automate object transitions to cheaper storage
classes and deletion of old data for cost optimization.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- nist-800-53 AU-11
- pci-dss 9.5.1

**Remediation:**
1. Navigate to Cloud Storage in Console
2. Select the bucket
3. Go to Lifecycle tab
4. Add lifecycle rules:
   - Set storage class transition (e.g., to Nearline)
   - Delete objects after X days
   - Delete noncurrent versions
5. Save rules

Example rule: Transition to Coldline after 90 days,
delete after 365 days.


### gcp-storage-008

**Name:** Cloud Storage bucket requester pays configured

Ensure Cloud Storage buckets with external access have Requester Pays
enabled where appropriate. This prevents unexpected egress charges by
having requesters pay for data transfer costs.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- nist-800-53 SA-9

**Remediation:**
1. Navigate to Cloud Storage in Console
2. Select the bucket
3. Go to Configuration tab
4. Under Requester Pays:
   - Enable requester pays
5. Save changes

Using gsutil:
gsutil requesterpays set on gs://BUCKET_NAME

Note: Requesters must include billing project in
their requests. May break some integrations.


### gcp-storage-011

**Name:** Cloud Storage bucket Autoclass enabled

Ensure Cloud Storage buckets use Autoclass for automatic storage class
management. Autoclass automatically transitions objects between storage
classes based on access patterns, optimizing costs.


**Resource Type:** `gcp_storage_bucket`

**Compliance:**
- nist-800-53 SA-9

**Remediation:**
1. Navigate to Cloud Storage in Console
2. Select the bucket
3. Go to Configuration tab
4. Under Default storage class:
   - Enable Autoclass
   - Select terminal storage class (Nearline or Archive)
5. Save changes

Using gcloud:
gcloud storage buckets update gs://BUCKET_NAME \
  --enable-autoclass

Note: Autoclass cannot be disabled once enabled.
Most effective for buckets with mixed access patterns.

