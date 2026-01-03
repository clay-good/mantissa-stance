# stance.exposure.dns

DNS inventory and subdomain monitoring for Exposure Management.

Discovers DNS records from cloud DNS services (Route53, Cloud DNS, Azure DNS)
and detects dangling DNS records that could lead to subdomain takeover.

## Contents

### Classes

- [DNSRecordType](#dnsrecordtype)
- [DNSFindingType](#dnsfindingtype)
- [DNSSeverity](#dnsseverity)
- [DNSConfig](#dnsconfig)
- [DNSZone](#dnszone)
- [DNSRecord](#dnsrecord)
- [DNSFinding](#dnsfinding)
- [DNSSummary](#dnssummary)
- [DNSInventoryResult](#dnsinventoryresult)
- [BaseDNSCollector](#basednscollector)
- [DNSInventory](#dnsinventory)
- [AWSRoute53Collector](#awsroute53collector)
- [GCPCloudDNSCollector](#gcpclouddnscollector)
- [AzureDNSCollector](#azurednscollector)

### Functions

- [scan_dns_inventory](#scan_dns_inventory)

## Constants

### `CLOUD_SERVICE_PATTERNS`

Type: `dict`

Value: `{'aws': ['\\.s3\\.amazonaws\\.com$', '\\.s3-website[.-].*\\.amazonaws\\.com$', '\\.cloudfront\\.net$', '\\.elasticbeanstalk\\.com$', '\\.elb\\.amazonaws\\.com$', '\\.amazonaws\\.com$'], 'azure': ['\\.azurewebsites\\.net$', '\\.cloudapp\\.azure\\.com$', '\\.azure-api\\.net$', '\\.azureedge\\.net$', '\\.blob\\.core\\.windows\\.net$', '\\.trafficmanager\\.net$', '\\.azurefd\\.net$'], 'gcp': ['\\.appspot\\.com$', '\\.cloudfunctions\\.net$', '\\.run\\.app$', '\\.storage\\.googleapis\\.com$', '\\.web\\.app$', '\\.firebaseapp\\.com$'], 'third_party': ['\\.github\\.io$', '\\.herokuapp\\.com$', '\\.pantheonsite\\.io$', '\\.shopify\\.com$', '\\.zendesk\\.com$', '\\.ghost\\.io$', '\\.surge\\.sh$', '\\.bitbucket\\.io$']}`

## DNSRecordType

**Inherits from:** Enum

Types of DNS records.

## DNSFindingType

**Inherits from:** Enum

Types of DNS-related findings.

## DNSSeverity

**Inherits from:** Enum

Severity levels for DNS findings.

### Properties

#### `rank(self) -> int`

Numeric rank for comparison.

**Returns:**

`int`

## DNSConfig

**Tags:** dataclass

Configuration for DNS inventory and monitoring.

Attributes:
    check_dangling: Whether to check for dangling DNS records
    check_caa: Whether to check for CAA records
    check_wildcards: Whether to check wildcard records
    resolve_records: Whether to resolve DNS records
    include_record_types: Record types to include
    exclude_zones: Zones to exclude from scanning
    cloud_providers: Cloud providers to check
    known_assets: Known cloud asset endpoints for correlation

### Attributes

| Name | Type | Default |
|------|------|---------|
| `check_dangling` | `bool` | `True` |
| `check_caa` | `bool` | `True` |
| `check_wildcards` | `bool` | `True` |
| `resolve_records` | `bool` | `True` |
| `include_record_types` | `list[str]` | `field(...)` |
| `exclude_zones` | `list[str]` | `field(...)` |
| `cloud_providers` | `list[str]` | `field(...)` |
| `known_assets` | `list[str]` | `field(...)` |

## DNSZone

**Tags:** dataclass

Represents a DNS zone (hosted zone).

Attributes:
    zone_id: Unique identifier for the zone
    name: Domain name of the zone
    cloud_provider: Cloud provider hosting the zone
    account_id: Account/project ID
    is_private: Whether this is a private zone
    record_count: Number of records in the zone
    nameservers: Nameservers for the zone
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `zone_id` | `str` | - |
| `name` | `str` | - |
| `cloud_provider` | `str` | - |
| `account_id` | `str` | - |
| `is_private` | `bool` | `False` |
| `record_count` | `int` | `0` |
| `nameservers` | `list[str]` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DNSRecord

**Tags:** dataclass

Represents a DNS record.

Attributes:
    record_id: Unique identifier
    zone_id: Parent zone ID
    zone_name: Parent zone name
    name: Full record name (FQDN)
    record_type: Type of DNS record
    values: Record values (IP addresses, CNAMEs, etc.)
    ttl: Time to live in seconds
    cloud_provider: Cloud provider
    account_id: Account/project ID
    is_alias: Whether this is an alias record
    alias_target: Alias target if applicable
    health_check_id: Associated health check if any
    detected_at: When record was discovered
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `record_id` | `str` | - |
| `zone_id` | `str` | - |
| `zone_name` | `str` | - |
| `name` | `str` | - |
| `record_type` | `DNSRecordType` | - |
| `values` | `list[str]` | - |
| `ttl` | `int` | `300` |
| `cloud_provider` | `str` | `` |
| `account_id` | `str` | `` |
| `is_alias` | `bool` | `False` |
| `alias_target` | `str | None` | - |
| `health_check_id` | `str | None` | - |
| `detected_at` | `datetime` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Properties

#### `is_wildcard(self) -> bool`

Check if this is a wildcard record.

**Returns:**

`bool`

#### `subdomain(self) -> str`

Get subdomain portion of the name.

**Returns:**

`str`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DNSFinding

**Tags:** dataclass

A finding about a DNS issue.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level
    title: Short title
    description: Detailed description
    record_name: Affected DNS record name
    record_type: Type of DNS record
    record_values: Record values
    zone_name: Zone containing the record
    cloud_provider: Cloud provider
    target_status: Status of the target (resolved, not_found, etc.)
    takeover_risk: Whether subdomain takeover is possible
    recommended_action: Suggested remediation
    detected_at: When finding was generated
    metadata: Additional context

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `DNSFindingType` | - |
| `severity` | `DNSSeverity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `record_name` | `str` | - |
| `record_type` | `str` | - |
| `record_values` | `list[str]` | - |
| `zone_name` | `str` | - |
| `cloud_provider` | `str` | - |
| `target_status` | `str` | `unknown` |
| `takeover_risk` | `bool` | `False` |
| `recommended_action` | `str` | `` |
| `detected_at` | `datetime` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DNSSummary

**Tags:** dataclass

Summary statistics for DNS inventory.

Attributes:
    total_zones: Total number of DNS zones
    total_records: Total number of DNS records
    records_by_type: Count by record type
    records_by_zone: Count by zone
    public_zones: Number of public zones
    private_zones: Number of private zones
    dangling_records: Number of dangling records
    wildcard_records: Number of wildcard records
    findings_by_severity: Count of findings by severity
    takeover_risks: Number of subdomain takeover risks

### Attributes

| Name | Type | Default |
|------|------|---------|
| `total_zones` | `int` | `0` |
| `total_records` | `int` | `0` |
| `records_by_type` | `dict[(str, int)]` | `field(...)` |
| `records_by_zone` | `dict[(str, int)]` | `field(...)` |
| `public_zones` | `int` | `0` |
| `private_zones` | `int` | `0` |
| `dangling_records` | `int` | `0` |
| `wildcard_records` | `int` | `0` |
| `findings_by_severity` | `dict[(str, int)]` | `field(...)` |
| `takeover_risks` | `int` | `0` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DNSInventoryResult

**Tags:** dataclass

Result of DNS inventory scan.

Attributes:
    result_id: Unique identifier
    config: Configuration used
    started_at: Scan start time
    completed_at: Scan completion time
    zones: List of DNS zones discovered
    records: List of DNS records discovered
    findings: List of DNS findings
    summary: Summary statistics
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `result_id` | `str` | - |
| `config` | `DNSConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `zones` | `list[DNSZone]` | `field(...)` |
| `records` | `list[DNSRecord]` | `field(...)` |
| `findings` | `list[DNSFinding]` | `field(...)` |
| `summary` | `DNSSummary` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `has_findings(self) -> bool`

Check if inventory has any findings.

**Returns:**

`bool`

#### `critical_findings(self) -> list[DNSFinding]`

Get critical severity findings.

**Returns:**

`list[DNSFinding]`

#### `high_findings(self) -> list[DNSFinding]`

Get high severity findings.

**Returns:**

`list[DNSFinding]`

#### `dangling_records(self) -> list[DNSFinding]`

Get dangling DNS findings.

**Returns:**

`list[DNSFinding]`

#### `takeover_risks(self) -> list[DNSFinding]`

Get findings with subdomain takeover risk.

**Returns:**

`list[DNSFinding]`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## BaseDNSCollector

**Inherits from:** ABC

Abstract base class for DNS collectors.

Subclasses implement cloud-specific logic for discovering DNS zones and records.

### Properties

#### `config(self) -> DNSConfig`

Get the collection configuration.

**Returns:**

`DNSConfig`

### Methods

#### `__init__(self, config: DNSConfig | None)`

Initialize the DNS collector.

**Parameters:**

- `config` (`DNSConfig | None`) - Optional configuration for collection

#### `collect_zones(self) -> Iterator[DNSZone]`

**Decorators:** @abstractmethod

Collect DNS zones from the cloud provider.  Yields: DNS zones discovered

**Returns:**

`Iterator[DNSZone]`

#### `collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]`

**Decorators:** @abstractmethod

Collect DNS records from a zone.

**Parameters:**

- `zone` (`DNSZone`) - DNS zone to collect records from

**Returns:**

`Iterator[DNSRecord]`

## DNSInventory

Manages DNS inventory across cloud providers.

Aggregates DNS zones and records from multiple collectors and
analyzes them for dangling records and other security issues.

### Properties

#### `zones(self) -> list[DNSZone]`

Get the list of DNS zones.

**Returns:**

`list[DNSZone]`

#### `records(self) -> list[DNSRecord]`

Get the list of DNS records.

**Returns:**

`list[DNSRecord]`

#### `config(self) -> DNSConfig`

Get the configuration.

**Returns:**

`DNSConfig`

### Methods

#### `__init__(self, zones: list[DNSZone] | None, records: list[DNSRecord] | None, config: DNSConfig | None)`

Initialize the DNS inventory.

**Parameters:**

- `zones` (`list[DNSZone] | None`) - List of DNS zones
- `records` (`list[DNSRecord] | None`) - List of DNS records
- `config` (`DNSConfig | None`) - Optional configuration

#### `add_zones(self, zones: list[DNSZone]) -> None`

Add zones to inventory.

**Parameters:**

- `zones` (`list[DNSZone]`)

**Returns:**

`None`

#### `add_records(self, records: list[DNSRecord]) -> None`

Add records to inventory.

**Parameters:**

- `records` (`list[DNSRecord]`)

**Returns:**

`None`

#### `add_known_assets(self, assets: list[str]) -> None`

Add known cloud asset endpoints for correlation.

**Parameters:**

- `assets` (`list[str]`)

**Returns:**

`None`

#### `analyze(self) -> DNSInventoryResult`

Analyze DNS inventory and generate findings.

**Returns:**

`DNSInventoryResult` - DNS inventory result with findings

#### `get_records_by_zone(self, zone_name: str) -> list[DNSRecord]`

Get records for a specific zone.

**Parameters:**

- `zone_name` (`str`)

**Returns:**

`list[DNSRecord]`

#### `get_records_by_type(self, record_type: DNSRecordType) -> list[DNSRecord]`

Get records of a specific type.

**Parameters:**

- `record_type` (`DNSRecordType`)

**Returns:**

`list[DNSRecord]`

#### `get_zones_by_cloud(self, cloud_provider: str) -> list[DNSZone]`

Get zones for a specific cloud provider.

**Parameters:**

- `cloud_provider` (`str`)

**Returns:**

`list[DNSZone]`

## AWSRoute53Collector

**Inherits from:** BaseDNSCollector

Collects DNS zones and records from AWS Route53.

### Properties

#### `account_id(self) -> str`

Get the AWS account ID.

**Returns:**

`str`

### Methods

#### `__init__(self, session: Any, config: DNSConfig | None)`

Initialize the Route53 collector.

**Parameters:**

- `session` (`Any`) - Optional boto3 session
- `config` (`DNSConfig | None`) - Optional configuration

#### `collect_zones(self) -> Iterator[DNSZone]`

Collect DNS zones from Route53.

**Returns:**

`Iterator[DNSZone]`

#### `collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]`

Collect DNS records from a Route53 zone.

**Parameters:**

- `zone` (`DNSZone`)

**Returns:**

`Iterator[DNSRecord]`

## GCPCloudDNSCollector

**Inherits from:** BaseDNSCollector

Collects DNS zones and records from GCP Cloud DNS.

### Properties

#### `project_id(self) -> str`

Get the GCP project ID.

**Returns:**

`str`

### Methods

#### `__init__(self, project_id: str | None, credentials: Any, config: DNSConfig | None)`

Initialize the Cloud DNS collector.

**Parameters:**

- `project_id` (`str | None`) - GCP project ID
- `credentials` (`Any`) - Optional GCP credentials
- `config` (`DNSConfig | None`) - Optional configuration

#### `collect_zones(self) -> Iterator[DNSZone]`

Collect DNS zones from Cloud DNS.

**Returns:**

`Iterator[DNSZone]`

#### `collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]`

Collect DNS records from a Cloud DNS zone.

**Parameters:**

- `zone` (`DNSZone`)

**Returns:**

`Iterator[DNSRecord]`

## AzureDNSCollector

**Inherits from:** BaseDNSCollector

Collects DNS zones and records from Azure DNS.

### Properties

#### `subscription_id(self) -> str`

Get the Azure subscription ID.

**Returns:**

`str`

### Methods

#### `__init__(self, subscription_id: str | None, credential: Any, config: DNSConfig | None)`

Initialize the Azure DNS collector.

**Parameters:**

- `subscription_id` (`str | None`) - Azure subscription ID
- `credential` (`Any`) - Optional Azure credential
- `config` (`DNSConfig | None`) - Optional configuration

#### `collect_zones(self) -> Iterator[DNSZone]`

Collect DNS zones from Azure DNS.

**Returns:**

`Iterator[DNSZone]`

#### `collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]`

Collect DNS records from an Azure DNS zone.

**Parameters:**

- `zone` (`DNSZone`)

**Returns:**

`Iterator[DNSRecord]`

### `scan_dns_inventory(zones: list[DNSZone], records: list[DNSRecord], config: DNSConfig | None, known_assets: list[str] | None) -> DNSInventoryResult`

Scan DNS inventory for security issues.  Convenience function for DNS inventory analysis.

**Parameters:**

- `zones` (`list[DNSZone]`) - List of DNS zones
- `records` (`list[DNSRecord]`) - List of DNS records
- `config` (`DNSConfig | None`) - Optional configuration
- `known_assets` (`list[str] | None`) - Known cloud asset endpoints

**Returns:**

`DNSInventoryResult` - DNS inventory result
