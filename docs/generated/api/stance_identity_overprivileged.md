# stance.identity.overprivileged

Over-Privileged Access Detection for Identity Security.

Detects principals with permissions that exceed their actual usage patterns
by comparing granted permissions against access log analysis.

Integrates with:
- Identity data access mappers (Phase 32) for permission information
- DSPM access review (Phase 23-25) for usage patterns from access logs
- Principal exposure analysis (Phase 33) for sensitivity context

## Contents

### Classes

- [OverPrivilegedFindingType](#overprivilegedfindingtype)
- [OverPrivilegedSeverity](#overprivilegedseverity)
- [OverPrivilegedConfig](#overprivilegedconfig)
- [UsagePattern](#usagepattern)
- [OverPrivilegedFinding](#overprivilegedfinding)
- [OverPrivilegedSummary](#overprivilegedsummary)
- [OverPrivilegedResult](#overprivilegedresult)
- [OverPrivilegedAnalyzer](#overprivilegedanalyzer)

### Functions

- [create_usage_patterns_from_access_review](#create_usage_patterns_from_access_review)

## OverPrivilegedFindingType

**Inherits from:** Enum

Types of over-privileged access findings.

## OverPrivilegedSeverity

**Inherits from:** Enum

Severity levels for over-privileged findings.

### Properties

#### `rank(self) -> int`

Numeric rank for comparison (higher = more severe).

**Returns:**

`int`

## OverPrivilegedConfig

**Tags:** dataclass

Configuration for over-privileged detection.

Attributes:
    lookback_days: Days of access logs to analyze
    stale_days: Days without usage to consider permission stale
    sensitive_resource_threshold: Number of sensitive resources to flag broad access
    include_service_accounts: Whether to analyze service accounts
    include_roles: Whether to analyze IAM roles
    include_users: Whether to analyze users
    min_sensitivity_level: Minimum data sensitivity to consider "sensitive"

### Attributes

| Name | Type | Default |
|------|------|---------|
| `lookback_days` | `int` | `90` |
| `stale_days` | `int` | `30` |
| `sensitive_resource_threshold` | `int` | `5` |
| `include_service_accounts` | `bool` | `True` |
| `include_roles` | `bool` | `True` |
| `include_users` | `bool` | `True` |
| `min_sensitivity_level` | `str` | `confidential` |

## UsagePattern

**Tags:** dataclass

Observed usage pattern for a principal-resource pair.

Attributes:
    principal_id: Principal identifier
    resource_id: Resource identifier
    granted_permission: Permission level granted
    observed_read_count: Number of read operations observed
    observed_write_count: Number of write operations observed
    observed_delete_count: Number of delete operations observed
    observed_list_count: Number of list operations observed
    first_access: First observed access
    last_access: Most recent access
    days_since_last_access: Days since last access
    total_access_count: Total number of accesses

### Attributes

| Name | Type | Default |
|------|------|---------|
| `principal_id` | `str` | - |
| `resource_id` | `str` | - |
| `granted_permission` | `PermissionLevel` | - |
| `observed_read_count` | `int` | `0` |
| `observed_write_count` | `int` | `0` |
| `observed_delete_count` | `int` | `0` |
| `observed_list_count` | `int` | `0` |
| `first_access` | `datetime | None` | - |
| `last_access` | `datetime | None` | - |
| `days_since_last_access` | `int | None` | - |
| `total_access_count` | `int` | `0` |

### Properties

#### `highest_observed_permission(self) -> PermissionLevel`

Determine the highest permission level actually used.

**Returns:**

`PermissionLevel`

#### `has_unused_write(self) -> bool`

Check if write permission is unused.

**Returns:**

`bool`

#### `has_unused_delete(self) -> bool`

Check if delete capability is unused (has write but no deletes).

**Returns:**

`bool`

#### `has_unused_admin(self) -> bool`

Check if admin permission is underutilized.

**Returns:**

`bool`

#### `is_stale(self) -> bool`

Check if access is stale (no recent usage).

**Returns:**

`bool`

#### `is_never_used(self) -> bool`

Check if permission has never been used.

**Returns:**

`bool`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## OverPrivilegedFinding

**Tags:** dataclass

A finding of over-privileged access.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of over-privileged finding
    severity: Severity level
    title: Short title
    description: Detailed description
    principal_id: Affected principal
    principal_type: Type of principal
    resource_id: Affected resource
    resource_type: Type of resource
    granted_permission: Permission level granted
    observed_permission: Highest permission level observed in usage
    data_classification: Data sensitivity if known
    usage_pattern: Detailed usage pattern
    recommended_action: Suggested action
    risk_score: Numeric risk score (0-100)
    metadata: Additional context
    detected_at: When finding was generated

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `finding_type` | `OverPrivilegedFindingType` | - |
| `severity` | `OverPrivilegedSeverity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `principal_id` | `str` | - |
| `principal_type` | `PrincipalType` | - |
| `resource_id` | `str` | - |
| `resource_type` | `str` | - |
| `granted_permission` | `PermissionLevel` | - |
| `observed_permission` | `PermissionLevel` | - |
| `data_classification` | `str | None` | - |
| `usage_pattern` | `UsagePattern | None` | - |
| `recommended_action` | `str` | `` |
| `risk_score` | `float` | `0.0` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert finding to dictionary.

**Returns:**

`dict[(str, Any)]`

## OverPrivilegedSummary

**Tags:** dataclass

Summary of over-privileged access for a principal.

Attributes:
    principal_id: Principal identifier
    principal_type: Type of principal
    total_resources_accessed: Number of resources principal can access
    over_privileged_resources: Number of resources with over-privileged access
    unused_write_count: Number of resources with unused write access
    unused_delete_count: Number of resources with unused delete access
    unused_admin_count: Number of resources with unused admin access
    stale_access_count: Number of resources with stale access
    never_used_count: Number of resources with never-used permissions
    sensitive_resource_count: Number of sensitive resources accessible
    average_risk_score: Average risk score across findings
    highest_severity: Highest severity finding

### Attributes

| Name | Type | Default |
|------|------|---------|
| `principal_id` | `str` | - |
| `principal_type` | `PrincipalType` | - |
| `total_resources_accessed` | `int` | `0` |
| `over_privileged_resources` | `int` | `0` |
| `unused_write_count` | `int` | `0` |
| `unused_delete_count` | `int` | `0` |
| `unused_admin_count` | `int` | `0` |
| `stale_access_count` | `int` | `0` |
| `never_used_count` | `int` | `0` |
| `sensitive_resource_count` | `int` | `0` |
| `average_risk_score` | `float` | `0.0` |
| `highest_severity` | `OverPrivilegedSeverity` | `"Attribute(value=Name(id='OverPrivilegedSeverity', ctx=Load()), attr='INFO', ctx=Load())"` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## OverPrivilegedResult

**Tags:** dataclass

Result of over-privileged access analysis.

Attributes:
    analysis_id: Unique identifier
    config: Configuration used
    started_at: Analysis start time
    completed_at: Analysis completion time
    principals_analyzed: Number of principals analyzed
    resources_analyzed: Number of resources analyzed
    findings: List of findings
    summaries: Summaries by principal
    total_over_privileged: Total over-privileged access instances
    findings_by_type: Count of findings by type
    findings_by_severity: Count of findings by severity
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `analysis_id` | `str` | - |
| `config` | `OverPrivilegedConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `principals_analyzed` | `int` | `0` |
| `resources_analyzed` | `int` | `0` |
| `findings` | `list[OverPrivilegedFinding]` | `field(...)` |
| `summaries` | `list[OverPrivilegedSummary]` | `field(...)` |
| `total_over_privileged` | `int` | `0` |
| `errors` | `list[str]` | `field(...)` |

### Properties

#### `has_findings(self) -> bool`

Check if analysis has any findings.

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

#### `critical_findings(self) -> list[OverPrivilegedFinding]`

Get critical severity findings.

**Returns:**

`list[OverPrivilegedFinding]`

#### `high_findings(self) -> list[OverPrivilegedFinding]`

Get high severity findings.

**Returns:**

`list[OverPrivilegedFinding]`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## OverPrivilegedAnalyzer

Analyzer for detecting over-privileged access.

Compares granted permissions from identity mappers with actual usage
patterns from access log analysis to identify principals with more
permissions than they need.

Integrates with:
- Identity data access mappers for permission information
- DSPM access review for access log analysis
- Principal exposure analyzer for sensitivity context

### Properties

#### `config(self) -> OverPrivilegedConfig`

Get the analysis configuration.

**Returns:**

`OverPrivilegedConfig`

### Methods

#### `__init__(self, config: OverPrivilegedConfig | None)`

Initialize the over-privileged analyzer.

**Parameters:**

- `config` (`OverPrivilegedConfig | None`) - Optional configuration for analysis

#### `analyze_principal(self, principal: Principal, resource_accesses: list[ResourceAccess], access_summaries: list[AccessSummary], resource_classifications: dict[(str, str)] | None) -> OverPrivilegedResult`

Analyze a principal for over-privileged access.  Compares granted permissions with actual usage patterns to find unused or underutilized permissions.

**Parameters:**

- `principal` (`Principal`) - Principal to analyze
- `resource_accesses` (`list[ResourceAccess]`) - List of resources principal can access
- `access_summaries` (`list[AccessSummary]`) - Access log summaries for this principal
- `resource_classifications` (`dict[(str, str)] | None`) - Optional mapping of resource_id to classification

**Returns:**

`OverPrivilegedResult` - Over-privileged analysis result

#### `analyze_multiple_principals(self, principals_data: list[tuple[(Principal, list[ResourceAccess], list[AccessSummary])]], resource_classifications: dict[(str, str)] | None) -> OverPrivilegedResult`

Analyze multiple principals for over-privileged access.

**Parameters:**

- `principals_data` (`list[tuple[(Principal, list[ResourceAccess], list[AccessSummary])]]`) - List of (principal, resource_accesses, access_summaries)
- `resource_classifications` (`dict[(str, str)] | None`) - Optional mapping of resource_id to classification

**Returns:**

`OverPrivilegedResult` - Combined over-privileged analysis result

#### `compare_permission_vs_usage(self, granted_permission: PermissionLevel, access_summary: AccessSummary | None) -> tuple[(bool, PermissionLevel)]`

Compare granted permission with observed usage.

**Parameters:**

- `granted_permission` (`PermissionLevel`) - Permission level granted
- `access_summary` (`AccessSummary | None`) - Access log summary (None if no access observed)

**Returns:**

`tuple[(bool, PermissionLevel)]` - Tuple of (is_over_privileged, observed_permission_level)

### `create_usage_patterns_from_access_review(principal_id: str, resource_accesses: list[ResourceAccess], access_summaries: list[AccessSummary]) -> list[UsagePattern]`

Create usage patterns from access review data.  Helper function to convert DSPM access review results into usage patterns for over-privileged analysis.

**Parameters:**

- `principal_id` (`str`) - Principal identifier
- `resource_accesses` (`list[ResourceAccess]`) - List of resources principal can access
- `access_summaries` (`list[AccessSummary]`) - Access log summaries

**Returns:**

`list[UsagePattern]` - List of usage patterns
