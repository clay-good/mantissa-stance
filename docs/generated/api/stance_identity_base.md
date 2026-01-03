# stance.identity.base

Base classes for Identity Security data access mapping.

Provides abstract base class and common data models for mapping
which principals can access which data resources.

## Contents

### Classes

- [PrincipalType](#principaltype)
- [PermissionLevel](#permissionlevel)
- [FindingType](#findingtype)
- [IdentityConfig](#identityconfig)
- [Principal](#principal)
- [ResourceAccess](#resourceaccess)
- [DataAccessMapping](#dataaccessmapping)
- [DataAccessFinding](#dataaccessfinding)
- [DataAccessResult](#dataaccessresult)
- [BaseDataAccessMapper](#basedataaccessmapper)

## PrincipalType

**Inherits from:** Enum

Types of identity principals.

## PermissionLevel

**Inherits from:** Enum

Permission levels for resource access.

### Properties

#### `rank(self) -> int`

Numeric rank for comparison (higher = more privileged).

**Returns:**

`int`

## FindingType

**Inherits from:** Enum

Types of identity security findings.

## IdentityConfig

**Tags:** dataclass

Configuration for identity security analysis.

Attributes:
    include_users: Whether to include user principals
    include_roles: Whether to include IAM roles
    include_service_accounts: Whether to include service accounts
    include_groups: Whether to include groups
    include_inherited: Whether to include inherited permissions (via groups)
    min_sensitivity_level: Minimum data sensitivity to flag
    stale_days: Days without access to consider stale

### Attributes

| Name | Type | Default |
|------|------|---------|
| `include_users` | `bool` | `True` |
| `include_roles` | `bool` | `True` |
| `include_service_accounts` | `bool` | `True` |
| `include_groups` | `bool` | `True` |
| `include_inherited` | `bool` | `True` |
| `min_sensitivity_level` | `str` | `internal` |
| `stale_days` | `int` | `90` |

## Principal

**Tags:** dataclass

An identity principal (user, role, service account, etc.).

Attributes:
    id: Unique identifier (ARN, email, etc.)
    name: Display name
    principal_type: Type of principal
    cloud_provider: Cloud provider (aws, gcp, azure)
    account_id: Cloud account/project ID
    created_at: When the principal was created
    last_authenticated: Last authentication time
    metadata: Additional metadata

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `name` | `str` | - |
| `principal_type` | `PrincipalType` | - |
| `cloud_provider` | `str` | - |
| `account_id` | `str | None` | - |
| `created_at` | `datetime | None` | - |
| `last_authenticated` | `datetime | None` | - |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert principal to dictionary.

**Returns:**

`dict[(str, Any)]`

## ResourceAccess

**Tags:** dataclass

Access to a specific resource.

Attributes:
    resource_id: Resource identifier (bucket name, ARN, etc.)
    resource_type: Type of resource (s3_bucket, gcs_bucket, etc.)
    permission_level: Level of access
    permission_source: How permission is granted (direct, via_group, via_role)
    policy_ids: Policy IDs granting this access
    conditions: Any conditions on the access
    data_classification: DSPM classification if available
    last_accessed: Last access time if available

### Attributes

| Name | Type | Default |
|------|------|---------|
| `resource_id` | `str` | - |
| `resource_type` | `str` | - |
| `permission_level` | `PermissionLevel` | - |
| `permission_source` | `str` | `direct` |
| `policy_ids` | `list[str]` | `field(...)` |
| `conditions` | `dict[(str, Any)]` | `field(...)` |
| `data_classification` | `str | None` | - |
| `last_accessed` | `datetime | None` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DataAccessMapping

**Tags:** dataclass

Mapping of who can access a resource.

Attributes:
    resource_id: Resource being analyzed
    resource_type: Type of resource
    cloud_provider: Cloud provider
    data_classification: DSPM classification if available
    principals: List of principals with access
    total_principals: Total count of principals
    principals_by_type: Count by principal type
    principals_by_level: Count by permission level
    highest_risk_principal: Principal with highest risk

### Attributes

| Name | Type | Default |
|------|------|---------|
| `resource_id` | `str` | - |
| `resource_type` | `str` | - |
| `cloud_provider` | `str` | - |
| `data_classification` | `str | None` | - |
| `principals` | `list[tuple[(Principal, ResourceAccess)]]` | `field(...)` |
| `total_principals` | `int` | `0` |
| `principals_by_type` | `dict[(str, int)]` | `field(...)` |
| `principals_by_level` | `dict[(str, int)]` | `field(...)` |
| `highest_risk_principal` | `str | None` | - |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## DataAccessFinding

**Tags:** dataclass

A finding from identity security analysis.

Attributes:
    finding_id: Unique identifier
    finding_type: Type of finding
    severity: Severity level (critical, high, medium, low)
    title: Short title
    description: Detailed description
    principal_id: Affected principal
    principal_type: Type of principal
    resource_id: Affected resource
    resource_type: Type of resource
    permission_level: Current permission level
    data_classification: Data sensitivity if known
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
| `principal_type` | `PrincipalType` | - |
| `resource_id` | `str` | - |
| `resource_type` | `str` | - |
| `permission_level` | `PermissionLevel` | `"Attribute(value=Name(id='PermissionLevel', ctx=Load()), attr='UNKNOWN', ctx=Load())"` |
| `data_classification` | `str | None` | - |
| `recommended_action` | `str` | `` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `detected_at` | `datetime` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert finding to dictionary.

**Returns:**

`dict[(str, Any)]`

## DataAccessResult

**Tags:** dataclass

Result of data access mapping analysis.

Attributes:
    analysis_id: Unique identifier
    resource_id: Resource analyzed
    config: Configuration used
    started_at: Analysis start time
    completed_at: Analysis completion time
    mapping: Data access mapping
    findings: List of findings
    total_principals: Total principals with access
    principals_with_sensitive_access: Principals accessing sensitive data
    errors: Errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `analysis_id` | `str` | - |
| `resource_id` | `str` | - |
| `config` | `IdentityConfig` | - |
| `started_at` | `datetime` | - |
| `completed_at` | `datetime | None` | - |
| `mapping` | `DataAccessMapping | None` | - |
| `findings` | `list[DataAccessFinding]` | `field(...)` |
| `total_principals` | `int` | `0` |
| `principals_with_sensitive_access` | `int` | `0` |
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

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert result to dictionary.

**Returns:**

`dict[(str, Any)]`

## BaseDataAccessMapper

**Inherits from:** ABC

Abstract base class for data access mappers.

Subclasses implement cloud-specific logic for determining
which principals can access which resources.

All operations are read-only.

### Properties

#### `config(self) -> IdentityConfig`

Get the analysis configuration.

**Returns:**

`IdentityConfig`

### Methods

#### `__init__(self, config: IdentityConfig | None)`

Initialize the data access mapper.

**Parameters:**

- `config` (`IdentityConfig | None`) - Optional configuration for identity analysis

#### `who_can_access(self, resource_id: str) -> DataAccessResult`

**Decorators:** @abstractmethod

Determine who can access a specific resource.

**Parameters:**

- `resource_id` (`str`) - Resource to analyze (bucket name, ARN, etc.)

**Returns:**

`DataAccessResult` - Data access result with mapping and findings

#### `get_principal_access(self, principal_id: str) -> list[ResourceAccess]`

**Decorators:** @abstractmethod

Get all resources a principal can access.

**Parameters:**

- `principal_id` (`str`) - Principal to analyze

**Returns:**

`list[ResourceAccess]` - List of resource access entries

#### `list_principals(self) -> Iterator[Principal]`

**Decorators:** @abstractmethod

List all principals in the account/project.  Yields: Principal objects

**Returns:**

`Iterator[Principal]`

#### `get_resource_policy(self, resource_id: str) -> dict[(str, Any)] | None`

**Decorators:** @abstractmethod

Get the resource-based policy for a resource.

**Parameters:**

- `resource_id` (`str`) - Resource identifier

**Returns:**

`dict[(str, Any)] | None` - Policy document or None
