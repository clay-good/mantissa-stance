# stance.exposure.certificates

Certificate monitoring for Exposure Management.

Discovers SSL/TLS certificates from cloud resources (load balancers, CDNs,
app services) and generates findings for expiring or misconfigured certificates.

## Contents

### Classes

- [CertificateStatus](#certificatestatus)
- [CertificateType](#certificatetype)
- [CertificateFindingType](#certificatefindingtype)
- [CertificateSeverity](#certificateseverity)
- [CertificateConfig](#certificateconfig)
- [Certificate](#certificate)
- [CertificateFinding](#certificatefinding)
- [CertificateSummary](#certificatesummary)
- [CertificateMonitoringResult](#certificatemonitoringresult)
- [BaseCertificateCollector](#basecertificatecollector)
- [CertificateMonitor](#certificatemonitor)
- [AWSCertificateCollector](#awscertificatecollector)
- [GCPCertificateCollector](#gcpcertificatecollector)
- [AzureCertificateCollector](#azurecertificatecollector)

### Functions

- [monitor_certificates](#monitor_certificates)

## CertificateStatus

**Inherits from:** Enum

Status of a certificate.

## CertificateType

**Inherits from:** Enum

Type of certificate.

## CertificateFindingType

**Inherits from:** Enum

Types of certificate-related findings.

## CertificateSeverity

**Inherits from:** Enum

Severity levels for certificate findings.

### Properties

#### `rank(self) -> int`

Numeric rank for comparison.

**Returns:**

`int`

## CertificateConfig

**Tags:** dataclass

Configuration for certificate monitoring.

Attributes:
    warning_threshold_days: Days before expiration to warn
    critical_threshold_days: Days before expiration for critical
    check_key_strength: Whether to check key strength
    check_algorithm: Whether to check signature algorithm
    min_rsa_key_size: Minimum RSA key size in bits
    min_ecdsa_key_size: Minimum ECDSA key size in bits
    weak_algorithms: Algorithms considered weak
    include_inactive: Whether to include inactive certificates
    cloud_providers: Cloud providers to check

### Attributes

| Name | Type | Default |
|------|------|---------|
| `warning_threshold_days` | `int` | `30` |
| `critical_threshold_days` | `int` | `7` |
| `check_key_strength` | `bool` | `True` |
| `check_algorithm` | `bool` | `True` |
| `min_rsa_key_size` | `int` | `2048` |
| `min_ecdsa_key_size` | `int` | `256` |
| `weak_algorithms` | `list[str]` | `field(...)` |
| `include_inactive` | `bool` | `False` |
| `cloud_providers` | `list[str]` | `field(...)` |

## Certificate

**Tags:** dataclass

Represents an SSL/TLS certificate.

Attributes:
    certificate_id: Unique identifier (ARN, resource ID, etc.)
    name: Human-readable name or domain
    cloud_provider: Cloud provider (aws, gcp, azure)
    account_id: Account/project ID
    region: Region where certificate is located
    certificate_type: Type of certificate
    status: Current status
    domains: List of domains covered
    primary_domain: Primary/common name domain
    not_before: Certificate valid from
    not_after: Certificate expires at
    days_until_expiry: Days until expiration (negative if expired)
    issuer: Certificate issuer
    key_algorithm: Key algorithm (RSA, ECDSA)
    key_size: Key size in bits
    signature_algorithm: Signature algorithm
    is_managed: Whether auto-renewed
    attached_resources: Resources using this certificate
    serial_number: Certificate serial number
    thumbprint: Certificate thumbprint/fingerprint
    detected_at: When certificate was discovered
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `certificate_id` | `str` | - |
| `name` | `str` | - |
| `cloud_provider` | `str` | - |
| `account_id` | `str` | - |
| `region` | `str` | - |
| `certificate_type` | `CertificateType` | - |
| `status` | `CertificateStatus` | - |
| `domains` | `list[str]` | - |
| `primary_domain` | `str` | - |
| `not_before` | `datetime | None` | - |
| `not_after` | `datetime | None` | - |
| `days_until_expiry` | `int` | `0` |
| `issuer` | `str` | `` |
| `key_algorithm` | `str` | `` |
| `key_size` | `int` | `0` |
| `signature_algorithm` | `str` | `` |
| `is_managed` | `bool` | `False` |
| `attached_resources` | `list[str]` | `field(...)` |
| `serial_number` | `str` | `` |
| `thumbprint` | `str` | `` |
| `detected_at` | `datetime` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `is_expired(self) -> bool`

Check if certificate is expired.

**Returns:**

`bool`

#### `is_expiring_soon(self) -> bool`

Check if certificate expires within 30 days.

**Returns:**

`bool`

#### `is_in_use(self) -> bool`

Check if certificate is attached to resources.

**Returns:**

`bool`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## CertificateFinding

**Tags:** dataclass

A finding about a certificate issue.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level
    title: Short title
    description: Detailed description
    certificate_id: Affected certificate ID
    certificate_name: Certificate name/domain
    cloud_provider: Cloud provider
    region: Region
    days_until_expiry: Days until expiration
    attached_resources: Resources using this certificate
    recommended_action: Suggested remediation
    detected_at: When finding was generated
    metadata: Additional context

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `CertificateFindingType` | - |
| `severity` | `CertificateSeverity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `certificate_id` | `str` | - |
| `certificate_name` | `str` | - |
| `cloud_provider` | `str` | - |
| `region` | `str` | - |
| `days_until_expiry` | `int` | `0` |
| `attached_resources` | `list[str]` | `field(...)` |
| `recommended_action` | `str` | `` |
| `detected_at` | `datetime` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## CertificateSummary

**Tags:** dataclass

Summary statistics for certificate monitoring.

Attributes:
    total_certificates: Total number of certificates
    active_certificates: Certificates in active status
    expired_certificates: Expired certificates
    expiring_7_days: Expiring within 7 days
    expiring_14_days: Expiring within 14 days
    expiring_30_days: Expiring within 30 days
    managed_certificates: Auto-renewed certificates
    imported_certificates: User-imported certificates
    certificates_by_cloud: Count by cloud provider
    certificates_by_region: Count by region
    findings_by_severity: Count of findings by severity

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_certificates` | `int` | `0` |
| `active_certificates` | `int` | `0` |
| `expired_certificates` | `int` | `0` |
| `expiring_7_days` | `int` | `0` |
| `expiring_14_days` | `int` | `0` |
| `expiring_30_days` | `int` | `0` |
| `managed_certificates` | `int` | `0` |
| `imported_certificates` | `int` | `0` |
| `certificates_by_cloud` | `dict[(str, int)]` | `field(...)` |
| `certificates_by_region` | `dict[(str, int)]` | `field(...)` |
| `findings_by_severity` | `dict[(str, int)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## CertificateMonitoringResult

**Tags:** dataclass

Result of certificate monitoring.

Attributes:
    result_id: Unique identifier
    config: Configuration used
    started_at: Monitoring start time
    completed_at: Monitoring completion time
    certificates: List of certificates discovered
    findings: List of certificate findings
    summary: Summary statistics
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `result_id` | `str` | - |
| `config` | `CertificateConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `certificates` | `list[Certificate]` | `field(...)` |
| `findings` | `list[CertificateFinding]` | `field(...)` |
| `summary` | `CertificateSummary` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `has_findings(self) -> bool`

Check if monitoring has any findings.

**Returns:**

`bool`

#### `critical_findings(self) -> list[CertificateFinding]`

Get critical severity findings.

**Returns:**

`list[CertificateFinding]`

#### `high_findings(self) -> list[CertificateFinding]`

Get high severity findings.

**Returns:**

`list[CertificateFinding]`

#### `expiring_certificates(self) -> list[Certificate]`

Get certificates expiring within threshold.

**Returns:**

`list[Certificate]`

#### `expired_certificates(self) -> list[Certificate]`

Get expired certificates.

**Returns:**

`list[Certificate]`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## BaseCertificateCollector

**Inherits from:** ABC

Abstract base class for certificate collectors.

Subclasses implement cloud-specific logic for discovering certificates.

### Properties

#### `config(self) -> CertificateConfig`

Get the collection configuration.

**Returns:**

`CertificateConfig`

### Methods

#### `__init__(self, config: CertificateConfig | None)`

Initialize the certificate collector.

**Parameters:**

- `config` (`CertificateConfig | None`) - Optional configuration for collection

#### `collect_certificates(self) -> Iterator[Certificate]`

**Decorators:** @abstractmethod

Collect certificates from the cloud provider.  Yields: Certificates discovered

**Returns:**

`Iterator[Certificate]`

## CertificateMonitor

Monitors certificates across cloud providers.

Aggregates certificates from multiple collectors and generates
findings for expiring or misconfigured certificates.

### Properties

#### `certificates(self) -> list[Certificate]`

Get the list of certificates.

**Returns:**

`list[Certificate]`

#### `config(self) -> CertificateConfig`

Get the configuration.

**Returns:**

`CertificateConfig`

### Methods

#### `__init__(self, certificates: list[Certificate] | None, config: CertificateConfig | None)`

Initialize the certificate monitor.

**Parameters:**

- `certificates` (`list[Certificate] | None`) - List of certificates to monitor
- `config` (`CertificateConfig | None`) - Optional configuration

#### `add_certificates(self, certificates: list[Certificate]) -> None`

Add certificates to monitor.

**Parameters:**

- `certificates` (`list[Certificate]`)

**Returns:**

`None`

#### `analyze(self) -> CertificateMonitoringResult`

Analyze certificates and generate findings.

**Returns:**

`CertificateMonitoringResult` - Certificate monitoring result with findings

#### `get_expiring_certificates(self, within_days: int = 30) -> list[Certificate]`

Get certificates expiring within specified days.

**Parameters:**

- `within_days` (`int`) - default: `30`

**Returns:**

`list[Certificate]`

#### `get_certificates_by_cloud(self, cloud_provider: str) -> list[Certificate]`

Get certificates for a specific cloud provider.

**Parameters:**

- `cloud_provider` (`str`)

**Returns:**

`list[Certificate]`

#### `get_certificates_by_domain(self, domain: str) -> list[Certificate]`

Get certificates covering a specific domain.

**Parameters:**

- `domain` (`str`)

**Returns:**

`list[Certificate]`

## AWSCertificateCollector

**Inherits from:** BaseCertificateCollector

Collects certificates from AWS (ACM, CloudFront, ELB).

Discovers certificates from:
- AWS Certificate Manager (ACM)
- CloudFront distributions
- Classic and Application Load Balancers

### Properties

#### `account_id(self) -> str`

Get the AWS account ID.

**Returns:**

`str`

### Methods

#### `__init__(self, session: Any, region: str = us-east-1, config: CertificateConfig | None)`

Initialize the AWS certificate collector.

**Parameters:**

- `session` (`Any`) - Optional boto3 session
- `region` (`str`) - default: `us-east-1` - AWS region (default: us-east-1)
- `config` (`CertificateConfig | None`) - Optional configuration

#### `collect_certificates(self) -> Iterator[Certificate]`

Collect certificates from ACM.

**Returns:**

`Iterator[Certificate]`

## GCPCertificateCollector

**Inherits from:** BaseCertificateCollector

Collects certificates from GCP (Compute SSL, Certificate Manager).

Discovers certificates from:
- Compute Engine SSL certificates
- Certificate Manager
- Load Balancers

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str | None, credentials: Any, config: CertificateConfig | None)`

Initialize the GCP certificate collector.

**Parameters:**

- `project_id` (`str | None`) - GCP project ID
- `credentials` (`Any`) - Optional GCP credentials
- `config` (`CertificateConfig | None`) - Optional configuration

#### `collect_certificates(self) -> Iterator[Certificate]`

Collect certificates from GCP.

**Returns:**

`Iterator[Certificate]`

## AzureCertificateCollector

**Inherits from:** BaseCertificateCollector

Collects certificates from Azure (App Service, Front Door, Key Vault).

Discovers certificates from:
- App Service certificates
- Azure Front Door
- Key Vault certificates

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str | None, credential: Any, config: CertificateConfig | None)`

Initialize the Azure certificate collector.

**Parameters:**

- `subscription_id` (`str | None`) - Azure subscription ID
- `credential` (`Any`) - Optional Azure credential
- `config` (`CertificateConfig | None`) - Optional configuration

#### `collect_certificates(self) -> Iterator[Certificate]`

Collect certificates from Azure.

**Returns:**

`Iterator[Certificate]`

### `monitor_certificates(certificates: list[Certificate], config: CertificateConfig | None) -> CertificateMonitoringResult`

Monitor certificates for expiration and security issues.  Convenience function for certificate monitoring.

**Parameters:**

- `certificates` (`list[Certificate]`) - List of certificates to monitor
- `config` (`CertificateConfig | None`) - Optional configuration

**Returns:**

`CertificateMonitoringResult` - Certificate monitoring result
