# AWS Policies

Security policies for AWS resources.

## Critical Severity

### aws-apigateway-004

**Name:** API Gateway authorization configured

Ensure API Gateway routes have authorization configured. APIs without
authorization allow unauthenticated access which may expose sensitive
functionality or data.


**Resource Type:** `aws_api_gateway_method`

**Compliance:**
- cis-aws-foundations 3.10
- pci-dss 8.2.1
- nist-800-53 IA-2

**Remediation:**
1. Navigate to API Gateway in AWS Console
2. Select the API
3. Go to Resources
4. Select the method (GET, POST, etc.)
5. Configure authorization:
   - IAM authorization
   - Cognito User Pool authorizer
   - Lambda authorizer
   - API key requirement
6. Deploy API to apply changes


### aws-cloudtrail-001

**Name:** CloudTrail enabled in all regions

Ensure CloudTrail is enabled in all regions. CloudTrail provides event
history of AWS API calls made in your account, which is essential for
security auditing, compliance, and operational troubleshooting.


**Resource Type:** `aws_cloudtrail`

**Compliance:**
- cis-aws-foundations 3.1
- pci-dss 10.2.1
- nist-800-53 AU-2
- aws-foundational-security CloudTrail.1

**Remediation:**
1. Open the AWS CloudTrail console
2. Choose Trails, then Create trail
3. Enter a trail name
4. Choose Create a new S3 bucket or specify existing bucket
5. Enable multi-region trail
6. Enable log file validation
7. Optionally configure CloudWatch Logs integration
8. Create the trail


### aws-cloudtrail-004

**Name:** CloudTrail S3 bucket not publicly accessible

Ensure the S3 bucket used for CloudTrail logs is not publicly accessible.
CloudTrail logs contain sensitive information about API activity and
should never be exposed to the public internet.


**Resource Type:** `aws_cloudtrail`

**Compliance:**
- cis-aws-foundations 3.3
- pci-dss 10.5.1
- nist-800-53 AC-3
- aws-foundational-security CloudTrail.6

**Remediation:**
1. Open the Amazon S3 console
2. Select the CloudTrail bucket
3. Go to Permissions tab
4. Under Block public access, click Edit
5. Enable all four public access block settings:
   - Block public access to buckets and objects granted through new ACLs
   - Block public access to buckets and objects granted through any ACLs
   - Block public access to buckets and objects granted through new public bucket policies
   - Block public and cross-account access to buckets and objects through any public bucket policies
6. Save changes


### aws-ec2-006

**Name:** Database ports not exposed to internet

Ensure security groups do not allow unrestricted access to database
ports from the internet. Exposing database ports like MySQL (3306),
PostgreSQL (5432), MSSQL (1433), MongoDB (27017) to the internet
creates significant security risks.


**Resource Type:** `aws_security_group`

**Compliance:**
- cis-aws-foundations 5.4
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Open the Amazon EC2 console
2. Navigate to Security Groups
3. Select the security group
4. Choose Inbound rules tab
5. Remove or modify rules that allow database ports from 0.0.0.0/0:
   - Port 3306 (MySQL/MariaDB)
   - Port 5432 (PostgreSQL)
   - Port 1433 (MSSQL)
   - Port 27017 (MongoDB)
6. Restrict source to specific VPC CIDR blocks or security groups
7. Consider using VPC endpoints or private subnets for databases


### aws-ec2-007

**Name:** Security group does not allow all traffic from internet

Ensure no security group allows all traffic from the internet
(0.0.0.0/0 with all ports). This is an extremely dangerous
configuration that exposes all services to potential attacks.


**Resource Type:** `aws_security_group`

**Compliance:**
- cis-aws-foundations 5.1
- pci-dss 1.2.1
- nist-800-53 SC-7
- aws-foundational-security EC2.18

**Remediation:**
1. Open the Amazon EC2 console
2. Navigate to Security Groups
3. Select the security group with dangerous rules
4. Choose Inbound rules tab
5. Identify rules that allow all traffic (protocol -1) from 0.0.0.0/0
6. Delete these rules or modify to:
   - Specify exact ports needed
   - Restrict source IP ranges
   - Use security group references instead
7. Apply principle of least privilege


### aws-iam-001

**Name:** Root account MFA enabled

Ensure MFA is enabled for the root AWS account. The root account has
unrestricted access to all resources and enabling MFA provides an
additional layer of security.


**Resource Type:** `aws_iam_account_summary`

**Compliance:**
- cis-aws-foundations 1.5
- pci-dss 8.3.1
- aws-foundational-security IAM.6

**Remediation:**
1. Sign in to the AWS Console using root credentials
2. Navigate to IAM Dashboard
3. In the Security Status section, expand "Activate MFA on your root account"
4. Click "Manage MFA"
5. Choose the type of MFA device (Virtual, U2F, or Hardware)
6. Follow the wizard to complete MFA setup


### aws-iam-005

**Name:** No access keys for root account

Ensure no access keys exist for the root account. The root account has
unrestricted access to all resources in the AWS account. Using access
keys for programmatic access with root credentials is extremely risky
and should never be done.


**Resource Type:** `aws_iam_account_summary`

**Compliance:**
- cis-aws-foundations 1.4
- pci-dss 8.6.1
- nist-800-53 IA-2(11)
- aws-foundational-security IAM.4

**Remediation:**
1. Sign in to the AWS Console using root credentials
2. Navigate to Security Credentials (top-right dropdown > Security credentials)
3. In the Access keys section, identify any active access keys
4. For each access key:
   a. First, ensure no applications are using it
   b. Deactivate the key
   c. After confirming nothing breaks, delete the key
5. Use IAM users or roles for programmatic access instead
6. Consider using AWS Organizations SCPs to prevent root key creation


### aws-rds-005

**Name:** RDS instance not publicly accessible

Ensure RDS database instances are not publicly accessible. Public RDS
instances can be accessed from the internet, increasing the attack surface.
Databases should be in private subnets with access through VPN or bastion.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- cis-aws-foundations 2.3.2
- pci-dss 1.3.1
- nist-800-53 SC-7
- aws-foundational-security RDS.2

**Remediation:**
1. Open the Amazon RDS console
2. Select the database instance
3. Choose Modify
4. Under Connectivity:
   - Expand Additional configuration
   - Set "Publicly accessible" to No
5. Choose when to apply the modification
6. Click Modify DB Instance

Note: Ensure applications can still reach the database through
VPC, VPN, or AWS Direct Connect.


### aws-s3-002

**Name:** S3 bucket public access blocked

Ensure S3 bucket has public access block settings enabled.
Public access block settings prevent accidental public exposure
of S3 bucket contents.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- cis-aws-foundations 2.1.5
- aws-foundational-security S3.1
- aws-foundational-security S3.2

**Remediation:**
1. Open the Amazon S3 console
2. Select the bucket
3. Choose the Permissions tab
4. Under Block public access, choose Edit
5. Enable all four block public access settings:
   - Block public access to buckets and objects granted through new ACLs
   - Block public access to buckets and objects granted through any ACLs
   - Block public access to buckets and objects granted through new public bucket policies
   - Block public and cross-account access to buckets that have public policies
6. Save changes


## High Severity

### aws-apigateway-002

**Name:** API Gateway WAF protection enabled

Ensure API Gateway REST APIs have AWS WAF protection enabled.
WAF provides protection against common web exploits, SQL injection,
cross-site scripting, and DDoS attacks.


**Resource Type:** `aws_api_gateway_stage`

**Compliance:**
- pci-dss 6.4.1
- nist-800-53 SC-7
- aws-foundational-security APIGateway.4

**Remediation:**
1. Navigate to AWS WAF console
2. Create a Web ACL with appropriate rules:
   - AWS Managed Rules (Core rule set, SQL injection, etc.)
   - Custom rules as needed
3. Navigate to API Gateway
4. Select the REST API
5. Go to Stages > select stage
6. Under Web Application Firewall:
   - Select the WAF Web ACL
7. Save changes


### aws-apigateway-003

**Name:** API Gateway uses ACM certificate

Ensure API Gateway custom domains use ACM certificates for TLS.
ACM certificates are automatically renewed and provide secure
HTTPS connections for API endpoints.


**Resource Type:** `aws_api_gateway_domain_name`

**Compliance:**
- pci-dss 4.2.1
- nist-800-53 SC-8

**Remediation:**
1. Request or import certificate in ACM
2. Navigate to API Gateway > Custom Domain Names
3. Create or edit custom domain
4. Select ACM certificate
5. Set minimum TLS version to TLS 1.2
6. Configure API mappings
7. Update DNS to point to API Gateway endpoint


### aws-cloudtrail-002

**Name:** CloudTrail log file validation enabled

Ensure CloudTrail log file validation is enabled. Log file validation
creates a digitally signed digest file that contains a hash of each log
file, enabling detection of log file modification, deletion, or tampering.


**Resource Type:** `aws_cloudtrail`

**Compliance:**
- cis-aws-foundations 3.2
- pci-dss 10.5.1
- nist-800-53 AU-9
- aws-foundational-security CloudTrail.4

**Remediation:**
1. Open the AWS CloudTrail console
2. Select the trail
3. Choose Edit
4. Under General details, enable Log file validation
5. Save changes


### aws-cloudtrail-003

**Name:** CloudTrail logs encrypted with KMS

Ensure CloudTrail logs are encrypted at rest using AWS KMS. Server-side
encryption with KMS provides additional security controls and audit
capabilities through AWS CloudTrail and AWS KMS key policies.


**Resource Type:** `aws_cloudtrail`

**Compliance:**
- cis-aws-foundations 3.7
- pci-dss 3.5.1
- nist-800-53 SC-28
- aws-foundational-security CloudTrail.2

**Remediation:**
1. Create a KMS key for CloudTrail encryption if not already exists
2. Open the AWS CloudTrail console
3. Select the trail
4. Choose Edit
5. Under Log file SSE-KMS encryption, enable
6. Select or create a KMS key
7. Update KMS key policy to allow CloudTrail to use the key
8. Save changes


### aws-cloudwatch-001

**Name:** CloudWatch alarm for root account usage

Ensure a CloudWatch alarm exists for root account usage. The root account
has unrestricted access to all resources, and its usage should be monitored
closely for unauthorized access or potential compromise.


**Resource Type:** `aws_cloudwatch_metric_alarm`

**Compliance:**
- cis-aws-foundations 4.3
- pci-dss 10.2.2
- nist-800-53 AU-6

**Remediation:**
1. Create a CloudWatch Logs metric filter for root account usage:
   Filter pattern: { $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
2. Create a CloudWatch alarm based on the metric filter
3. Set threshold to >= 1
4. Configure notification via SNS topic
5. Subscribe relevant security personnel to SNS topic


### aws-ec2-001

**Name:** Security group SSH access restricted

Ensure no security group allows unrestricted inbound SSH access.
Security groups that allow SSH from 0.0.0.0/0 expose instances
to potential brute force attacks.


**Resource Type:** `aws_security_group`

**Compliance:**
- cis-aws-foundations 5.2
- aws-foundational-security EC2.19

**Remediation:**
1. Open the Amazon EC2 console
2. Navigate to Security Groups
3. Select the security group
4. Choose Inbound rules tab
5. Edit rules that allow SSH (port 22) from 0.0.0.0/0
6. Restrict source to specific IP ranges or security groups
7. Save rules


### aws-ec2-002

**Name:** Security group RDP access restricted

Ensure no security group allows unrestricted inbound RDP access.
Security groups that allow RDP from 0.0.0.0/0 expose Windows
instances to potential brute force attacks.


**Resource Type:** `aws_security_group`

**Compliance:**
- cis-aws-foundations 5.3
- aws-foundational-security EC2.19

**Remediation:**
1. Open the Amazon EC2 console
2. Navigate to Security Groups
3. Select the security group
4. Choose Inbound rules tab
5. Edit rules that allow RDP (port 3389) from 0.0.0.0/0
6. Restrict source to specific IP ranges or security groups
7. Save rules


### aws-ec2-012

**Name:** Network ACL does not allow unrestricted inbound

Ensure Network ACLs do not allow unrestricted inbound traffic from
0.0.0.0/0 on sensitive ports. Unrestricted access increases the
attack surface of resources in the subnet.


**Resource Type:** `aws_network_acl`

**Compliance:**
- cis-aws-foundations 5.1
- pci-dss 1.3.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to VPC > Network ACLs
2. Select the Network ACL
3. Review Inbound Rules
4. For rules allowing 0.0.0.0/0:
   - Restrict to specific CIDR ranges
   - Remove unnecessary allow rules
   - Use deny rules for sensitive ports
5. Sensitive ports include:
   - 22 (SSH), 3389 (RDP)
   - 3306 (MySQL), 5432 (PostgreSQL)
   - 1433 (MSSQL), 27017 (MongoDB)
6. Save changes


### aws-elb-002

**Name:** ALB uses HTTPS listeners only

Ensure Application Load Balancers use HTTPS listeners for secure
communication. HTTP listeners transmit data unencrypted and should
only redirect to HTTPS.


**Resource Type:** `aws_alb_listener`

**Compliance:**
- cis-aws-foundations 3.7
- pci-dss 4.2.1
- nist-800-53 SC-8
- aws-foundational-security ELB.1

**Remediation:**
1. Navigate to EC2 > Load Balancers
2. Select the Application Load Balancer
3. Go to Listeners tab
4. For HTTP listeners:
   - Edit listener
   - Change default action to redirect to HTTPS
5. For HTTPS listeners:
   - Ensure valid SSL certificate is configured
   - Set security policy to TLS 1.2 minimum
6. Save changes


### aws-elb-003

**Name:** ALB WAF protection enabled

Ensure Application Load Balancers have AWS WAF protection enabled.
WAF protects web applications from common exploits and attacks
at the load balancer layer.


**Resource Type:** `aws_alb`

**Compliance:**
- pci-dss 6.4.1
- nist-800-53 SC-7

**Remediation:**
1. Navigate to AWS WAF console
2. Create a Web ACL:
   - Add AWS Managed Rules (recommended)
   - Add custom rules as needed
   - Set default action (allow/block)
3. Associate Web ACL with ALB:
   - Go to Associated AWS resources
   - Add resources
   - Select the ALB
4. Save configuration


### aws-iam-002

**Name:** IAM password policy strength

Ensure the IAM password policy meets minimum security requirements.
A strong password policy helps prevent brute force attacks and
ensures users create secure passwords.


**Resource Type:** `aws_iam_account_password_policy`

**Compliance:**
- cis-aws-foundations 1.8
- cis-aws-foundations 1.9
- cis-aws-foundations 1.10
- cis-aws-foundations 1.11
- pci-dss 8.3.6

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Account settings
3. Click "Change password policy"
4. Set minimum password length to at least 14 characters
5. Enable all complexity requirements:
   - Require at least one uppercase letter
   - Require at least one lowercase letter
   - Require at least one number
   - Require at least one symbol
6. Click "Save changes"


### aws-iam-004

**Name:** MFA enabled for IAM users with console access

Ensure MFA is enabled for all IAM users that have console access (password).
Multi-factor authentication provides an additional layer of protection
against unauthorized access to AWS accounts.


**Resource Type:** `aws_iam_user`

**Compliance:**
- cis-aws-foundations 1.10
- pci-dss 8.4.2
- nist-800-53 IA-2(1)
- aws-foundational-security IAM.5

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Users
3. Select the user without MFA
4. Go to Security credentials tab
5. In the MFA section, click "Manage"
6. Choose MFA device type:
   - Virtual MFA device (authenticator app)
   - U2F security key
   - Hardware MFA device
7. Follow the wizard to complete MFA setup


### aws-lambda-005

**Name:** Lambda function uses supported runtime

Ensure Lambda functions use a supported runtime version. Deprecated
runtimes do not receive security patches and may have known vulnerabilities.
Upgrade to supported versions for continued security updates.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- aws-foundational-security Lambda.1
- nist-800-53 SI-2
- pci-dss 6.3.3

**Remediation:**
1. Navigate to Lambda in AWS Console
2. Select the function
3. Click "Edit" on the Runtime settings
4. Select a supported runtime version
5. Test the function with the new runtime
6. Save changes

Check AWS documentation for currently supported runtimes:
- Python: 3.9, 3.10, 3.11, 3.12
- Node.js: 18.x, 20.x
- Java: 11, 17, 21
- Go: provided.al2


### aws-lambda-007

**Name:** Lambda function code signing configured

Ensure Lambda functions have code signing configured to verify deployment
packages. Code signing ensures only trusted code is deployed and prevents
unauthorized modifications to function code.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- nist-800-53 CM-14
- pci-dss 6.2.4

**Remediation:**
1. Create a code signing configuration:
   - Navigate to Lambda > Code signing configurations
   - Click "Create configuration"
   - Select signing profiles from AWS Signer
   - Configure untrusted artifact policy
2. Apply to function:
   - Select the Lambda function
   - Go to Configuration > Code signing
   - Click Edit
   - Select the code signing configuration
   - Save changes

Note: All deployment packages must be signed after enabling.


### aws-lambda-008

**Name:** Lambda function URL restricted

Ensure Lambda functions with public URLs have authentication configured.
Function URLs with auth type NONE are publicly accessible without
authentication, which may expose sensitive functionality.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- aws-foundational-security Lambda.4
- nist-800-53 IA-2
- pci-dss 8.2.1

**Remediation:**
1. Navigate to Lambda in AWS Console
2. Select the function
3. Go to Configuration > Function URL
4. If URL exists and auth is NONE:
   - Click Edit
   - Change auth type to AWS_IAM
   - Save changes
5. Or delete the function URL if not needed

Use API Gateway for more advanced authentication options.


### aws-rds-001

**Name:** RDS instance storage encryption enabled

Ensure RDS database instances have storage encryption enabled.
Encryption at rest protects data stored on disk from unauthorized
access and is required by most compliance frameworks.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- cis-aws-foundations 2.3.1
- pci-dss 3.4
- nist-800-53 SC-28
- aws-foundational-security RDS.3

**Remediation:**
Note: You cannot enable encryption on an existing unencrypted RDS instance.
To encrypt an existing database:
1. Create a snapshot of the unencrypted instance
2. Copy the snapshot with encryption enabled
3. Restore a new instance from the encrypted snapshot
4. Update applications to use the new instance endpoint
5. Delete the old unencrypted instance after verification

For new instances:
1. Enable encryption during instance creation
2. Select appropriate KMS key (AWS managed or customer managed)


### aws-rds-003

**Name:** RDS snapshots encrypted

Ensure RDS database snapshots are encrypted. Unencrypted snapshots
can expose sensitive data if shared or accessed inappropriately.
Snapshots inherit encryption from source databases.


**Resource Type:** `aws_rds_snapshot`

**Compliance:**
- cis-aws-foundations 2.3.1
- pci-dss 3.4
- nist-800-53 SC-28

**Remediation:**
For existing unencrypted snapshots:
1. Copy the snapshot with encryption enabled
2. Select appropriate KMS key
3. Delete the unencrypted snapshot after verification

To prevent unencrypted snapshots:
1. Ensure source RDS instances are encrypted
2. Encrypted instances produce encrypted snapshots
3. Use AWS Config rules to detect unencrypted snapshots


### aws-rds-007

**Name:** RDS backup retention at least 7 days

Ensure RDS database instances have backup retention set to at least 7 days.
Adequate backup retention enables point-in-time recovery and protects
against data loss from accidental deletion or corruption.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- cis-aws-foundations 2.3.3
- pci-dss 9.5.1
- nist-800-53 CP-9
- aws-foundational-security RDS.11

**Remediation:**
1. Open the Amazon RDS console
2. Select the database instance
3. Choose Modify
4. Under Backup:
   - Set "Backup retention period" to at least 7 days
   - Consider 14-35 days for production workloads
5. Choose when to apply the modification
6. Click Modify DB Instance

Note: Longer retention periods increase storage costs.


### aws-rds-008

**Name:** RDS deletion protection enabled

Ensure RDS database instances have deletion protection enabled.
Deletion protection prevents accidental or unauthorized deletion
of production databases through the console, CLI, or API.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- aws-foundational-security RDS.8
- nist-800-53 SC-28
- pci-dss 9.4.5

**Remediation:**
1. Open the Amazon RDS console
2. Select the database instance
3. Choose Modify
4. Under Additional configuration:
   - Enable "Deletion protection"
5. Choose when to apply the modification
6. Click Modify DB Instance

To delete a protected database, you must first disable deletion
protection.


### aws-s3-001

**Name:** S3 bucket encryption enabled

Ensure S3 buckets have server-side encryption enabled.
Server-side encryption protects data at rest and is required
for many compliance frameworks.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- cis-aws-foundations 2.1.1
- pci-dss 3.4
- aws-foundational-security S3.4

**Remediation:**
1. Open the Amazon S3 console
2. Select the bucket
3. Choose the Properties tab
4. Under Default encryption, choose Edit
5. Select Enable server-side encryption
6. Choose encryption type (SSE-S3 or SSE-KMS)
7. Save changes


### aws-s3-005

**Name:** S3 bucket MFA delete enabled

Ensure S3 buckets with versioning have MFA delete enabled. MFA delete
requires additional authentication to permanently delete object versions,
protecting against unauthorized or accidental deletions.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- cis-aws-foundations 2.1.2
- nist-800-53 AC-3
- pci-dss 9.4.5

**Remediation:**
MFA delete must be enabled using the root account via CLI:

1. Configure root account MFA
2. Using AWS CLI with root credentials:
   aws s3api put-bucket-versioning \
     --bucket BUCKET_NAME \
     --versioning-configuration Status=Enabled,MFADelete=Enabled \
     --mfa "arn:aws:iam::ACCOUNT:mfa/root-mfa-device MFA_CODE"

Note: Cannot be enabled via console. Requires root account.


### aws-s3-007

**Name:** S3 bucket requires SSL/TLS

Ensure S3 bucket policies require SSL/TLS for all requests. This prevents
unencrypted data transmission and protects against man-in-the-middle
attacks.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- cis-aws-foundations 2.1.5
- pci-dss 4.2.1
- nist-800-53 SC-8
- aws-foundational-security S3.5

**Remediation:**
Add a bucket policy that denies non-SSL requests:

{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "RequireSSL",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::BUCKET_NAME",
      "arn:aws:s3:::BUCKET_NAME/*"
    ],
    "Condition": {
      "Bool": {"aws:SecureTransport": "false"}
    }
  }]
}


## Medium Severity

### aws-apigateway-001

**Name:** API Gateway REST API logging enabled

Ensure API Gateway REST APIs have execution logging enabled. API logging
captures request/response details for security monitoring, debugging,
and compliance auditing.


**Resource Type:** `aws_api_gateway_stage`

**Compliance:**
- cis-aws-foundations 3.9
- pci-dss 10.2.1
- nist-800-53 AU-2

**Remediation:**
1. Navigate to API Gateway in AWS Console
2. Select the REST API
3. Go to Stages
4. Select the stage (e.g., prod)
5. Under Logs/Tracing:
   - Enable CloudWatch Logs
   - Set Log level to INFO or ERROR
   - Enable Access Logging
   - Specify CloudWatch log group ARN
6. Save changes


### aws-cloudtrail-005

**Name:** CloudTrail integrated with CloudWatch Logs

Ensure CloudTrail is configured to send logs to CloudWatch Logs. This
integration enables real-time monitoring of API activity, allows creating
alarms for specific events, and supports automated responses to security events.


**Resource Type:** `aws_cloudtrail`

**Compliance:**
- cis-aws-foundations 3.4
- pci-dss 10.6.1
- nist-800-53 AU-6
- aws-foundational-security CloudTrail.5

**Remediation:**
1. Create a CloudWatch Logs log group for CloudTrail
2. Create an IAM role that allows CloudTrail to write to CloudWatch Logs
3. Open the AWS CloudTrail console
4. Select the trail
5. Choose Edit
6. Under CloudWatch Logs, enable CloudWatch Logs
7. Select the log group and IAM role
8. Save changes


### aws-cloudwatch-002

**Name:** CloudWatch alarm for unauthorized API calls

Ensure a CloudWatch alarm exists for unauthorized API calls. Monitoring
unauthorized API calls helps detect potential reconnaissance, brute force
attacks, or compromised credentials attempting to access resources.


**Resource Type:** `aws_cloudwatch_metric_alarm`

**Compliance:**
- cis-aws-foundations 4.1
- pci-dss 10.2.4
- nist-800-53 AU-6

**Remediation:**
1. Create a CloudWatch Logs metric filter for unauthorized API calls:
   Filter pattern: { ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }
2. Create a CloudWatch alarm based on the metric filter
3. Set appropriate threshold (e.g., >= 5 in 5 minutes)
4. Configure notification via SNS topic
5. Subscribe security team to SNS topic


### aws-cloudwatch-003

**Name:** CloudWatch alarm for IAM policy changes

Ensure a CloudWatch alarm exists for IAM policy changes. Unauthorized
or unintended IAM policy changes can lead to privilege escalation,
unauthorized access, or security policy violations.


**Resource Type:** `aws_cloudwatch_metric_alarm`

**Compliance:**
- cis-aws-foundations 4.4
- pci-dss 10.2.5
- nist-800-53 AU-6

**Remediation:**
1. Create a CloudWatch Logs metric filter for IAM policy changes:
   Filter pattern: { ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }
2. Create a CloudWatch alarm based on the metric filter
3. Set threshold to >= 1
4. Configure notification via SNS topic


### aws-cloudwatch-004

**Name:** CloudWatch alarm for security group changes

Ensure a CloudWatch alarm exists for security group changes. Unauthorized
modifications to security groups can open network access to resources
and should be monitored and investigated promptly.


**Resource Type:** `aws_cloudwatch_metric_alarm`

**Compliance:**
- cis-aws-foundations 4.10
- pci-dss 10.2.5
- nist-800-53 AU-6

**Remediation:**
1. Create a CloudWatch Logs metric filter for security group changes:
   Filter pattern: { ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }
2. Create a CloudWatch alarm based on the metric filter
3. Set threshold to >= 1
4. Configure notification via SNS topic
5. Subscribe network and security teams to SNS topic


### aws-ec2-003

**Name:** EC2 instances require IMDSv2

Ensure EC2 instances are configured to require IMDSv2.
IMDSv2 adds defense in depth against SSRF attacks that
attempt to access the instance metadata service.


**Resource Type:** `aws_ec2_instance`

**Compliance:**
- aws-foundational-security EC2.8

**Remediation:**
1. Open the Amazon EC2 console
2. Select the instance
3. Choose Actions > Instance settings > Modify instance metadata options
4. Set IMDSv2 to Required
5. Save changes

For new instances, configure the launch template to require IMDSv2:
- MetadataOptions.HttpTokens = required


### aws-ec2-004

**Name:** EBS volumes encrypted

Ensure EBS volumes attached to EC2 instances are encrypted.
EBS encryption provides an additional layer of protection for
data at rest on block storage volumes.


**Resource Type:** `aws_ec2_instance`

**Compliance:**
- cis-aws-foundations 2.2.1
- aws-foundational-security EC2.3
- pci-dss 3.4

**Remediation:**
For existing volumes:
1. Create a snapshot of the unencrypted volume
2. Copy the snapshot with encryption enabled
3. Create a new volume from the encrypted snapshot
4. Detach the unencrypted volume and attach the encrypted one

For new instances:
1. Enable EBS encryption by default in EC2 settings
2. Or specify encryption when creating volumes

To enable default encryption:
1. Open the Amazon EC2 console
2. Navigate to EBS > Encryption
3. Choose "Manage" and enable encryption by default


### aws-ec2-005

**Name:** VPC flow logs enabled

Ensure VPC flow logs are enabled for all VPCs. Flow logs capture
information about IP traffic going to and from network interfaces
in VPCs, which is essential for security monitoring and forensics.


**Resource Type:** `aws_vpc`

**Compliance:**
- cis-aws-foundations 3.9
- pci-dss 10.2.1
- nist-800-53 AU-12
- aws-foundational-security EC2.6

**Remediation:**
1. Open the Amazon VPC console
2. Select the VPC
3. Choose Actions > Create flow log
4. Configure flow log settings:
   - Filter: All (or Accept/Reject as needed)
   - Destination: CloudWatch Logs or S3
   - Log format: AWS default or custom
5. Create IAM role if sending to CloudWatch Logs
6. Click Create flow log


### aws-ec2-009

**Name:** Subnet auto-assign public IP disabled

Ensure subnets do not automatically assign public IP addresses
to instances. Automatic public IP assignment can inadvertently
expose instances to the internet.


**Resource Type:** `aws_subnet`

**Compliance:**
- cis-aws-foundations 5.6
- nist-800-53 SC-7
- aws-foundational-security EC2.15

**Remediation:**
1. Open the Amazon VPC console
2. Navigate to Subnets
3. Select the subnet
4. Choose Actions > Modify auto-assign IP settings
5. Uncheck "Enable auto-assign public IPv4 address"
6. Save changes
7. For public-facing resources, explicitly assign Elastic IPs
   or use a load balancer


### aws-ec2-010

**Name:** EC2 instance public IP reviewed

Ensure EC2 instances with public IP addresses are intentional and
reviewed. Instances with public IPs are directly accessible from
the internet and should be limited to those that require it.


**Resource Type:** `aws_ec2_instance`

**Compliance:**
- nist-800-53 SC-7
- pci-dss 1.3.2

**Remediation:**
1. Review if the instance requires direct internet access
2. If not required:
   a. Stop the instance
   b. Modify network settings to remove public IP
   c. Use NAT Gateway for outbound internet access
   d. Use Load Balancer for inbound traffic
3. If required:
   a. Document business justification
   b. Ensure security groups are properly configured
   c. Enable IMDSv2 for metadata protection
   d. Monitor access with VPC Flow Logs


### aws-ec2-013

**Name:** VPC endpoint has restrictive policy

Ensure VPC endpoints have restrictive policies configured. Endpoints
with full access policies may allow unintended access to AWS services
from within the VPC.


**Resource Type:** `aws_vpc_endpoint`

**Compliance:**
- nist-800-53 AC-6
- pci-dss 7.2.1

**Remediation:**
1. Navigate to VPC > Endpoints
2. Select the VPC endpoint
3. Go to Policy tab
4. Click Edit policy
5. Replace full access policy with restrictive policy:
   - Limit to specific principals
   - Limit to specific resources
   - Limit to specific actions
6. Save changes

Example: For S3 endpoint, restrict to specific buckets
and operations needed by workloads.


### aws-elb-001

**Name:** ALB access logging enabled

Ensure Application Load Balancers have access logging enabled.
Access logs capture detailed information about requests for security
analysis, troubleshooting, and compliance auditing.


**Resource Type:** `aws_alb`

**Compliance:**
- cis-aws-foundations 3.6
- pci-dss 10.2.1
- nist-800-53 AU-2
- aws-foundational-security ELB.5

**Remediation:**
1. Navigate to EC2 > Load Balancers
2. Select the Application Load Balancer
3. Go to Attributes tab
4. Click Edit attributes
5. Enable Access logs:
   - Set S3 bucket for log storage
   - Set prefix for log files
6. Save changes

Note: S3 bucket policy must allow ELB to write logs.


### aws-elb-004

**Name:** ALB deletion protection enabled

Ensure Application Load Balancers have deletion protection enabled.
Deletion protection prevents accidental or unauthorized deletion of
production load balancers.


**Resource Type:** `aws_alb`

**Compliance:**
- nist-800-53 SC-28
- aws-foundational-security ELB.6

**Remediation:**
1. Navigate to EC2 > Load Balancers
2. Select the Application Load Balancer
3. Go to Attributes tab
4. Click Edit attributes
5. Enable "Deletion protection"
6. Save changes

To delete a protected ALB, first disable deletion protection.


### aws-iam-003

**Name:** IAM access keys rotated within 90 days

Ensure IAM user access keys are rotated at least every 90 days. Long-lived
access keys increase the risk of unauthorized access if compromised.
Regular rotation limits the window of exposure from a compromised key.


**Resource Type:** `aws_iam_user`

**Compliance:**
- cis-aws-foundations 1.14
- pci-dss 8.3.9
- nist-800-53 IA-5(1)

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Users
3. Select the user with old access keys
4. Go to Security credentials tab
5. Create a new access key
6. Update applications to use the new key
7. Test that applications work with new key
8. Deactivate the old access key
9. After confirming new key works, delete the old key


### aws-iam-007

**Name:** IAM role cross-account trust reviewed

Ensure IAM roles with cross-account trust relationships are reviewed
and intentional. Cross-account access can be legitimate but also
introduces risk if not properly controlled. Roles allowing access
from other AWS accounts should be regularly audited.


**Resource Type:** `aws_iam_role`

**Compliance:**
- cis-aws-foundations 1.17
- nist-800-53 AC-17
- soc2 CC6.1

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Roles
3. Select the role with cross-account trust
4. Review the Trust relationships tab
5. Verify that cross-account access is intentional:
   - Confirm the external account IDs are known and trusted
   - Verify the business need for cross-account access
   - Consider adding conditions to restrict access
6. If cross-account access is not needed:
   a. Edit the trust policy
   b. Remove the external account principals
   c. Save changes
7. Document approved cross-account relationships


### aws-iam-008

**Name:** IAM role external trust reviewed

Ensure IAM roles with external (federated) trust relationships are
reviewed. External trust allows non-AWS identities to assume roles,
which can be a security risk if not properly configured with
appropriate conditions and controls.


**Resource Type:** `aws_iam_role`

**Compliance:**
- cis-aws-foundations 1.17
- nist-800-53 IA-8
- soc2 CC6.3

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Roles
3. Select the role with external/federated trust
4. Review the Trust relationships tab
5. For SAML federation:
   - Verify the identity provider is approved
   - Ensure proper attribute conditions are set
   - Review who has access through the IdP
6. For web identity federation:
   - Verify the OIDC provider is approved
   - Ensure audience conditions are properly set
7. If external trust is not needed:
   a. Edit the trust policy
   b. Remove federated principals
   c. Save changes
8. Consider using AWS SSO/IAM Identity Center instead


### aws-iam-009

**Name:** Password reuse prevention enabled

Ensure the IAM password policy prevents password reuse. Allowing
users to reuse recent passwords increases the risk of compromised
credentials being reused. AWS allows preventing reuse of the last
1 to 24 passwords.


**Resource Type:** `aws_iam_account_password_policy`

**Compliance:**
- cis-aws-foundations 1.12
- pci-dss 8.3.7
- nist-800-53 IA-5(1)

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Account settings
3. Click "Change password policy"
4. Enable "Prevent password reuse"
5. Set "Number of passwords to remember" to at least 12
6. Click "Save changes"


### aws-lambda-001

**Name:** Lambda environment variables encrypted with KMS

Ensure Lambda functions with environment variables use KMS
encryption. By default, Lambda uses AWS managed keys, but
customer managed keys provide better control and auditability.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- pci-dss 3.4
- nist-800-53 SC-12
- aws-foundational-security Lambda.3

**Remediation:**
1. Navigate to Lambda in AWS Console
2. Select the function
3. Go to Configuration > Environment variables
4. Click "Edit"
5. Expand "Encryption configuration"
6. Select "Use a customer master key"
7. Choose or create a KMS key
8. Save changes

Note: The Lambda execution role needs kms:Decrypt permission
for the selected KMS key.


### aws-lambda-002

**Name:** Lambda function VPC configuration

Ensure Lambda functions that access private resources are configured
with VPC settings. VPC configuration enables functions to access
resources in private subnets without exposing them to the internet.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- aws-foundational-security Lambda.2
- nist-800-53 SC-7
- pci-dss 1.3.1

**Remediation:**
1. Navigate to Lambda in AWS Console
2. Select the function
3. Go to Configuration > VPC
4. Click Edit
5. Select the VPC
6. Select at least 2 subnets in different AZs
7. Select security group(s)
8. Save changes

Note: The Lambda execution role needs VPC-related permissions:
ec2:CreateNetworkInterface, ec2:DescribeNetworkInterfaces,
ec2:DeleteNetworkInterface


### aws-lambda-004

**Name:** Lambda function dead letter queue configured

Ensure Lambda functions have a dead letter queue (DLQ) configured for
asynchronous invocations. DLQ captures failed invocations for later
analysis and reprocessing, preventing data loss.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- nist-800-53 AU-6
- pci-dss 10.2.1

**Remediation:**
1. Navigate to Lambda in AWS Console
2. Select the function
3. Go to Configuration > Asynchronous invocation
4. Click Edit
5. Under Dead letter queue service:
   - Select SQS or SNS
   - Choose or create the queue/topic
6. Save changes

Note: The Lambda execution role needs sqs:SendMessage or
sns:Publish permissions for the configured DLQ.


### aws-rds-002

**Name:** RDS uses customer managed KMS key

Ensure RDS instances use customer managed KMS keys for encryption
instead of AWS managed keys. Customer managed keys provide more
control over key rotation, access policies, and audit capabilities.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- pci-dss 3.6.1
- nist-800-53 SC-12

**Remediation:**
1. Create a customer managed KMS key in AWS KMS:
   a. Navigate to KMS in AWS Console
   b. Create a symmetric key
   c. Define key administrators and users
   d. Set up key rotation policy
2. Create an encrypted snapshot of the existing RDS instance
3. Copy the snapshot using the customer managed KMS key
4. Restore a new instance from the copied snapshot
5. Update applications to use the new endpoint
6. Delete old resources after verification


### aws-rds-004

**Name:** RDS instance Multi-AZ enabled for production

Ensure RDS production database instances have Multi-AZ deployment enabled.
Multi-AZ provides high availability with automatic failover to a standby
replica in a different Availability Zone.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- aws-foundational-security RDS.5
- nist-800-53 CP-10
- pci-dss 12.10.1

**Remediation:**
1. Open the Amazon RDS console
2. Select the database instance
3. Choose Modify
4. Under Availability & durability:
   - Select "Create a standby instance"
5. Choose when to apply (immediately or during maintenance)
6. Click Modify DB Instance

Note: Enabling Multi-AZ may cause brief downtime during conversion.


### aws-rds-006

**Name:** RDS auto minor version upgrade enabled

Ensure RDS instances have automatic minor version upgrades enabled.
Minor version upgrades include security patches and bug fixes that
help maintain the security posture of the database.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- aws-foundational-security RDS.13
- nist-800-53 SI-2
- pci-dss 6.3.3

**Remediation:**
1. Open the Amazon RDS console
2. Select the database instance
3. Choose Modify
4. Under Maintenance:
   - Enable "Auto minor version upgrade"
5. Choose when to apply the modification
6. Click Modify DB Instance

Minor version upgrades are applied during the maintenance window.


### aws-rds-009

**Name:** RDS IAM database authentication enabled

Ensure RDS instances support IAM database authentication where applicable.
IAM authentication eliminates the need for database passwords and provides
centralized access control through IAM policies.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- aws-foundational-security RDS.10
- nist-800-53 IA-2
- pci-dss 8.3.1

**Remediation:**
1. Open the Amazon RDS console
2. Select the database instance
3. Choose Modify
4. Under Database authentication:
   - Enable "IAM database authentication"
5. Choose when to apply the modification
6. Click Modify DB Instance

After enabling, configure IAM policies and create database users
that authenticate using IAM.

Supported engines: MySQL, PostgreSQL, MariaDB


### aws-s3-003

**Name:** S3 bucket uses KMS encryption

Ensure S3 buckets use server-side encryption with AWS KMS
(SSE-KMS) instead of S3-managed keys (SSE-S3). KMS provides
additional security controls, audit trails, and key rotation.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- cis-aws-foundations 2.1.2
- pci-dss 3.6.1
- nist-800-53 SC-12

**Remediation:**
1. Open the Amazon S3 console
2. Select the bucket
3. Choose the Properties tab
4. Under Default encryption, choose Edit
5. Select "Server-side encryption with AWS KMS keys (SSE-KMS)"
6. Choose a KMS key:
   - AWS managed key (aws/s3)
   - Customer managed key (recommended)
7. Consider enabling Bucket Key to reduce KMS costs
8. Save changes


### aws-s3-004

**Name:** S3 bucket versioning enabled

Ensure S3 buckets have versioning enabled. Versioning protects against
accidental deletions and overwrites, enabling recovery of previous
versions of objects.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- cis-aws-foundations 2.1.3
- pci-dss 9.5.1
- nist-800-53 CP-9
- aws-foundational-security S3.14

**Remediation:**
1. Open the Amazon S3 console
2. Select the bucket
3. Choose the Properties tab
4. Under Bucket Versioning, click Edit
5. Select Enable
6. Save changes

Note: Once enabled, versioning cannot be disabled,
only suspended. Consider lifecycle policies for cost.


### aws-s3-006

**Name:** S3 bucket access logging enabled

Ensure S3 buckets have server access logging enabled. Access logs capture
detailed records of requests made to the bucket for security analysis,
auditing, and troubleshooting.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- cis-aws-foundations 3.6
- pci-dss 10.2.1
- nist-800-53 AU-2
- aws-foundational-security S3.9

**Remediation:**
1. Create a target bucket for logs (if not exists)
2. Open the Amazon S3 console
3. Select the source bucket
4. Choose the Properties tab
5. Under Server access logging, click Edit
6. Enable logging
7. Select target bucket and prefix
8. Save changes

Note: Target bucket should be in same region.
Consider lifecycle policies for log retention.


### aws-s3-009

**Name:** S3 bucket Object Lock enabled for compliance

Ensure S3 buckets storing compliance data have Object Lock enabled.
Object Lock provides write-once-read-many (WORM) protection, preventing
object deletion or modification for a specified retention period.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- pci-dss 9.5.1
- nist-800-53 AU-9

**Remediation:**
Object Lock can only be enabled at bucket creation:

1. Create new bucket with Object Lock:
   aws s3api create-bucket --bucket BUCKET_NAME \
     --object-lock-enabled-for-bucket

2. Configure default retention:
   - Governance mode (can be overridden with permission)
   - Compliance mode (cannot be overridden)

3. For existing buckets:
   - Create new bucket with Object Lock
   - Copy objects with retention settings
   - Update applications to use new bucket

Note: Cannot be enabled on existing buckets.


### aws-s3-010

**Name:** S3 bucket has cross-region replication for DR

Ensure critical S3 buckets have cross-region replication configured.
CRR provides disaster recovery by automatically replicating objects
to a bucket in a different AWS region.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- nist-800-53 CP-9
- pci-dss 9.5.1

**Remediation:**
1. Enable versioning on source bucket
2. Create destination bucket in different region
3. Enable versioning on destination bucket
4. Open source bucket > Management > Replication rules
5. Create replication rule:
   - Select scope (all or filtered)
   - Choose destination bucket
   - Select IAM role (create new or existing)
   - Configure options (encryption, metrics)
6. Save rule

Note: Versioning required on both buckets.
Consider replication time control (RTC) for SLAs.


## Low Severity

### aws-cloudwatch-005

**Name:** CloudWatch log groups have retention configured

Ensure CloudWatch log groups have retention policies configured.
Without retention policies, logs are kept indefinitely which increases
storage costs. However, retention should meet compliance requirements
for log retention periods (typically 90 days to 1 year).


**Resource Type:** `aws_cloudwatch_log_group`

**Compliance:**
- cis-aws-foundations 3.4
- pci-dss 10.7
- nist-800-53 AU-11

**Remediation:**
1. Open the Amazon CloudWatch console
2. Navigate to Log groups
3. Select the log group
4. Choose Actions > Edit retention setting
5. Set retention period (90 days, 1 year, or as per compliance requirements)
6. Save changes


### aws-ec2-008

**Name:** Default VPC not used for production

Ensure the default VPC is not used for production workloads.
Default VPCs have permissive configurations that may not meet
security requirements. Use custom VPCs with proper network
segmentation instead.


**Resource Type:** `aws_vpc`

**Compliance:**
- cis-aws-foundations 5.5
- nist-800-53 SC-7

**Remediation:**
1. Create a custom VPC with appropriate CIDR ranges
2. Design proper network segmentation:
   - Public subnets for internet-facing resources
   - Private subnets for internal resources
   - Isolated subnets for databases
3. Configure route tables appropriately
4. Migrate resources from default VPC to custom VPC
5. Consider deleting the default VPC if not needed
6. Use Infrastructure as Code for VPC management


### aws-ec2-011

**Name:** Security group egress rules reviewed

Ensure security group egress rules are not overly permissive.
While default egress allows all outbound traffic, restricting
egress can prevent data exfiltration and command-and-control
communications.


**Resource Type:** `aws_security_group`

**Compliance:**
- nist-800-53 SC-7(5)
- pci-dss 1.3.4

**Remediation:**
1. Open the Amazon EC2 console
2. Navigate to Security Groups
3. Select the security group
4. Choose Outbound rules tab
5. Remove the default allow-all egress rule
6. Add specific egress rules for:
   - HTTPS (443) to required destinations
   - DNS (53) to VPC DNS server
   - Other required protocols/ports
7. Consider using VPC endpoints to reduce egress needs
8. Use AWS Network Firewall for advanced egress filtering


### aws-iam-006

**Name:** No inline policies attached directly to users

Ensure IAM users do not have inline policies attached. Inline policies
are harder to manage, audit, and track compared to managed policies.
Using managed policies allows for centralized policy management and
easier compliance auditing.


**Resource Type:** `aws_iam_user`

**Compliance:**
- cis-aws-foundations 1.16
- nist-800-53 AC-6

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Users
3. Select the user with inline policies
4. Go to Permissions tab
5. Expand the inline policy and review its contents
6. Create an equivalent managed policy if needed
7. Attach the managed policy to the user
8. Delete the inline policy
9. Consider using IAM groups instead of direct user policies


### aws-iam-010

**Name:** Password expiration enabled

Ensure the IAM password policy enforces password expiration. While
NIST guidance has evolved on forced rotation, many compliance
frameworks still require periodic password changes. Consider your
organization's requirements when enabling this policy.


**Resource Type:** `aws_iam_account_password_policy`

**Compliance:**
- cis-aws-foundations 1.11
- pci-dss 8.3.9

**Remediation:**
1. Sign in to the AWS Console
2. Navigate to IAM > Account settings
3. Click "Change password policy"
4. Enable "Enable password expiration"
5. Set "Password expiration period" to 90 days or less
6. Click "Save changes"

Note: Modern security guidance (NIST SP 800-63B) suggests not
requiring periodic password changes unless there's evidence of
compromise. Consider using MFA and monitoring for compromised
credentials instead of forced rotation.


### aws-lambda-003

**Name:** Lambda function has reserved concurrency

Ensure Lambda functions have reserved or provisioned concurrency configured.
Reserved concurrency prevents a single function from consuming all available
concurrency and ensures predictable performance.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- nist-800-53 SC-5

**Remediation:**
1. Navigate to Lambda in AWS Console
2. Select the function
3. Go to Configuration > Concurrency
4. Click Edit
5. Choose "Reserve concurrency"
6. Set the reserved concurrent executions
7. Save changes

Consider setting:
- Reserved concurrency for steady workloads
- Provisioned concurrency for latency-sensitive functions


### aws-lambda-006

**Name:** Lambda function X-Ray tracing enabled

Ensure Lambda functions have AWS X-Ray tracing enabled. X-Ray provides
distributed tracing to understand function performance, identify bottlenecks,
and troubleshoot errors in serverless applications.


**Resource Type:** `aws_lambda_function`

**Compliance:**
- nist-800-53 AU-12
- pci-dss 10.2.1

**Remediation:**
1. Navigate to Lambda in AWS Console
2. Select the function
3. Go to Configuration > Monitoring and operations tools
4. Click Edit
5. Enable "Active tracing"
6. Save changes

Note: The Lambda execution role needs xray:PutTraceSegments
and xray:PutTelemetryRecords permissions.


### aws-rds-010

**Name:** RDS enhanced monitoring enabled

Ensure RDS instances have enhanced monitoring enabled. Enhanced monitoring
provides real-time operating system metrics with granular visibility into
database performance and resource utilization.


**Resource Type:** `aws_rds_instance`

**Compliance:**
- aws-foundational-security RDS.6
- nist-800-53 AU-6
- pci-dss 10.2.1

**Remediation:**
1. Open the Amazon RDS console
2. Select the database instance
3. Choose Modify
4. Under Monitoring:
   - Enable "Enhanced monitoring"
   - Select monitoring interval (1, 5, 10, 15, 30, or 60 seconds)
   - Select or create the monitoring IAM role
5. Choose when to apply the modification
6. Click Modify DB Instance

Enhanced monitoring metrics are published to CloudWatch Logs.


### aws-s3-008

**Name:** S3 bucket has lifecycle policy

Ensure S3 buckets have lifecycle policies configured. Lifecycle policies
automate transitioning objects to cheaper storage classes and expiring
old data, optimizing costs and ensuring data retention compliance.


**Resource Type:** `aws_s3_bucket`

**Compliance:**
- nist-800-53 AU-11
- pci-dss 9.5.1

**Remediation:**
1. Open the Amazon S3 console
2. Select the bucket
3. Choose the Management tab
4. Under Lifecycle rules, click Create lifecycle rule
5. Configure rule:
   - Name the rule
   - Apply to all objects or filter by prefix/tags
   - Add transitions (to Standard-IA, Glacier, etc.)
   - Add expiration for old versions or delete markers
6. Save rule

Example: Transition to Glacier after 90 days,
expire noncurrent versions after 365 days.

