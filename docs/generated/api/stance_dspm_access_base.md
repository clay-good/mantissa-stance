# stance.dspm.access.base

Base classes for DSPM access review.

Provides abstract base class and common data models for analyzing
cloud access logs to detect stale and unused permissions.

## Contents

### Classes

- [FindingType](#findingtype)
- [AccessReviewConfig](#accessreviewconfig)
- [AccessEvent](#accessevent)
- [AccessSummary](#accesssummary)
- [StaleAccessFinding](#staleaccessfinding)
- [AccessReviewResult](#accessreviewresult)
- [BaseAccessAnalyzer](#baseaccessanalyzer)

## FindingType

**Inherits from:** Enum

Types of access review findings.

## AccessReviewConfig

**Tags:** dataclass

Configuration for access review analysis.

Attributes:
    stale_days: Days without access to consider stale (default: 90)
    include_service_accounts: Whether to include service accounts
    include_roles: Whether to include IAM roles
    include_users: Whether to include users
    lookback_days: Days of logs to analyze (default: 180)
    min_access_count: Minimum accesses to not flag as unused

### Attributes

| Name | Type | Default |
|------|------|---------|
| `stale_days` | `int` | `90` |
| `include_service_accounts` | `bool` | `True` |
| `include_roles` | `bool` | `True` |
| `include_users` | `bool` | `True` |
| `lookback_days` | `int` | `180` |
| `min_access_count` | `int` | `1` |

## AccessEvent

**Tags:** dataclass

A single access event from cloud logs.

Attributes:
    event_id: Unique event identifier
    timestamp: When the event occurred
    principal_id: Who performed the action
    principal_type: Type of principal (user, role, service_account)
    resource_id: Resource being accessed (e.g., bucket/object path)
    action: Action performed (read, write, delete, list, etc.)
    source_ip: Source IP address
    user_agent: User agent string
    success: Whether the action succeeded
    metadata: Additional event metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `event_id` | `str` | - |
| `timestamp` | `datetime` | - |
| `principal_id` | `str` | - |
| `principal_type` | `str` | - |
| `resource_id` | `str` | - |
| `action` | `str` | - |
| `source_ip` | `str | None` | - |
| `user_agent` | `str | None` | - |
| `success` | `bool` | `True` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert event to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## AccessSummary

**Tags:** dataclass

Summary of access patterns for a principal-resource pair.

Attributes:
    principal_id: Principal identifier
    principal_type: Type of principal
    resource_id: Resource identifier
    total_access_count: Total number of accesses
    read_count: Number of read operations
    write_count: Number of write operations
    delete_count: Number of delete operations
    list_count: Number of list operations
    first_access: First recorded access
    last_access: Most recent access
    days_since_last_access: Days since last access
    has_permission: Whether principal currently has permission
    permission_level: Level of permission (read, write, admin)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `principal_id` | `str` | - |
| `principal_type` | `str` | - |
| `resource_id` | `str` | - |
| `total_access_count` | `int` | `0` |
| `read_count` | `int` | `0` |
| `write_count` | `int` | `0` |
| `delete_count` | `int` | `0` |
| `list_count` | `int` | `0` |
| `first_access` | `datetime | None` | - |
| `last_access` | `datetime | None` | - |
| `days_since_last_access` | `int | None` | - |
| `has_permission` | `bool` | `True` |
| `permission_level` | `str` | `unknown` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert summary to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## StaleAccessFinding

**Tags:** dataclass

A finding from access review analysis.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level (critical, high, medium, low)
    title: Short title for the finding
    description: Detailed description
    principal_id: Affected principal
    principal_type: Type of principal
    resource_id: Affected resource
    days_since_last_access: Days since last access
    permission_level: Current permission level
    recommended_action: Suggested action
    metadata: Additional context
    detected_at: When finding was generated

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `FindingType` | - |
| `severity` | `str` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `principal_id` | `str` | - |
| `principal_type` | `str` | - |
| `resource_id` | `str` | - |
| `days_since_last_access` | `int | None` | - |
| `permission_level` | `str` | `unknown` |
| `recommended_action` | `str` | `` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert finding to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## AccessReviewResult

**Tags:** dataclass

Result of an access review analysis.

Attributes:
    review_id: Unique identifier for this review
    resource_id: Resource that was reviewed
    config: Configuration used
    started_at: When review started
    completed_at: When review completed
    total_principals_analyzed: Number of principals analyzed
    total_events_analyzed: Number of access events analyzed
    findings: List of findings generated
    summaries: Access summaries by principal
    errors: Errors encountered during analysis

### Attributes

| Name | Type | Default |
|------|------|---------|
| `review_id` | `str` | - |
| `resource_id` | `str` | - |
| `config` | `AccessReviewConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `total_principals_analyzed` | `int` | `0` |
| `total_events_analyzed` | `int` | `0` |
| `findings` | `list[StaleAccessFinding]` | `field(...)` |
| `summaries` | `list[AccessSummary]` | `field(...)` |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `has_findings(self) -> bool`

Check if review has any findings.

**Returns:**

`bool`

#### `findings_by_type(self) -> dict[(str, int)]`

Get count of findings by type.

**Returns:**

`dict[(str, int)]`

#### `findings_by_severity(self) -> dict[(str, int)]`

Get count of findings by severity.

**Returns:**

`dict[(str, int)]`

#### `stale_principals(self) -> list[str]`

Get list of principals with stale access.

**Returns:**

`list[str]`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert result to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## BaseAccessAnalyzer

**Inherits from:** ABC

Abstract base class for cloud access log analyzers.

Subclasses implement cloud-specific logic for parsing access logs
and correlating with IAM permissions.

### Methods

#### `__init__(self, config: AccessReviewConfig | None)`

Initialize the access analyzer.

**Parameters:**

- `config` (`AccessReviewConfig | None`) - Optional configuration for access review

#### `analyze_resource(self, resource_id: str) -> AccessReviewResult`

**Decorators:** @abstractmethod

Analyze access patterns for a specific resource.

**Parameters:**

- `resource_id` (`str`) - Resource to analyze (e.g., bucket name, container name)

**Returns:**

`AccessReviewResult` - Access review result with findings and summaries

#### `get_access_events(self, resource_id: str, start_time: datetime, end_time: datetime) -> Iterator[AccessEvent]`

**Decorators:** @abstractmethod

Retrieve access events for a resource within a time range.

**Parameters:**

- `resource_id` (`str`) - Resource to get events for
- `start_time` (`datetime`) - Start of time range
- `end_time` (`datetime`) - End of time range

**Returns:**

`Iterator[AccessEvent]`

#### `get_resource_permissions(self, resource_id: str) -> dict[(str, dict[(str, Any)])]`

**Decorators:** @abstractmethod

Get current permissions for a resource.

**Parameters:**

- `resource_id` (`str`) - Resource to get permissions for

**Returns:**

`dict[(str, dict[(str, Any)])]` - Dictionary mapping principal_id to permission details
