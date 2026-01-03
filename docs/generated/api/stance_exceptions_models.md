# stance.exceptions.models

Models for Policy Exceptions and Suppressions.

Defines the data structures for managing policy exceptions.

## Contents

### Classes

- [ExceptionType](#exceptiontype)
- [ExceptionScope](#exceptionscope)
- [ExceptionStatus](#exceptionstatus)
- [PolicyException](#policyexception)
- [ExceptionMatch](#exceptionmatch)
- [ExceptionResult](#exceptionresult)

## ExceptionType

**Inherits from:** Enum

Types of policy exceptions.

## ExceptionScope

**Inherits from:** Enum

Scope of the exception.

## ExceptionStatus

**Inherits from:** Enum

Status of an exception.

## PolicyException

**Tags:** dataclass

A policy exception or suppression rule.

Attributes:
    id: Unique exception identifier
    exception_type: Type of exception
    scope: Scope of the exception
    status: Current status
    reason: Human-readable reason
    created_by: Who created the exception
    approved_by: Who approved (if required)
    created_at: When created
    expires_at: When it expires (if temporary)
    policy_id: Target policy ID (if applicable)
    asset_id: Target asset ID (if applicable)
    finding_id: Target finding ID (if applicable)
    resource_type: Target resource type (if applicable)
    account_id: Target account ID (if applicable)
    tag_key: Tag key to match (if scope is TAG)
    tag_value: Tag value to match (if scope is TAG)
    conditions: Additional matching conditions
    metadata: Additional metadata
    jira_ticket: Associated Jira ticket
    notes: Additional notes

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | `field(...)` |
| `exception_type` | `ExceptionType` | `"Attribute(value=Name(id='ExceptionType', ctx=Load()), attr='SUPPRESSION', ctx=Load())"` |
| `scope` | `ExceptionScope` | `"Attribute(value=Name(id='ExceptionScope', ctx=Load()), attr='FINDING', ctx=Load())"` |
| `status` | `ExceptionStatus` | `"Attribute(value=Name(id='ExceptionStatus', ctx=Load()), attr='APPROVED', ctx=Load())"` |
| `reason` | `str` | `` |
| `created_by` | `str` | `` |
| `approved_by` | `str | None` | - |
| `created_at` | `datetime` | `field(...)` |
| `expires_at` | `datetime | None` | - |
| `policy_id` | `str | None` | - |
| `asset_id` | `str | None` | - |
| `finding_id` | `str | None` | - |
| `resource_type` | `str | None` | - |
| `account_id` | `str | None` | - |
| `tag_key` | `str | None` | - |
| `tag_value` | `str | None` | - |
| `conditions` | `dict[(str, Any)]` | `field(...)` |
| `metadata` | `dict[(str, Any)]` | `field(...)` |
| `jira_ticket` | `str | None` | - |
| `notes` | `str` | `` |

### Properties

#### `is_active(self) -> bool`

Check if exception is currently active.

**Returns:**

`bool`

#### `is_expired(self) -> bool`

Check if exception has expired.

**Returns:**

`bool`

#### `days_until_expiry(self) -> int | None`

Get days until expiry.

**Returns:**

`int | None`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> 'PolicyException'`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`'PolicyException'`

## ExceptionMatch

**Tags:** dataclass

Result of matching a finding against an exception.

Attributes:
    exception: The matching exception
    match_reason: Why the exception matched
    match_score: Confidence score (0-100)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `exception` | `PolicyException` | - |
| `match_reason` | `str` | `` |
| `match_score` | `int` | `100` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ExceptionResult

**Tags:** dataclass

Result of checking exceptions for a finding.

Attributes:
    finding_id: The finding that was checked
    is_excepted: Whether finding is excepted
    matches: List of matching exceptions
    applied_exception: The exception that was applied (highest priority)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `is_excepted` | `bool` | `False` |
| `matches` | `list[ExceptionMatch]` | `field(...)` |
| `applied_exception` | `PolicyException | None` | - |

### Properties

#### `exception_type(self) -> ExceptionType | None`

Get the applied exception type.

**Returns:**

`ExceptionType | None`

#### `exception_reason(self) -> str`

Get the applied exception reason.

**Returns:**

`str`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`
