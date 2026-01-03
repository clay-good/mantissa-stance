# stance.exceptions.manager

Exception manager for Mantissa Stance.

High-level management of policy exceptions and suppressions.

## Contents

### Classes

- [ExceptionManager](#exceptionmanager)

### Functions

- [get_exception_manager](#get_exception_manager)

## ExceptionManager

High-level manager for policy exceptions.

Provides a unified interface for creating, managing, and
applying policy exceptions to findings.

### Properties

#### `store(self) -> ExceptionStore`

Get the exception store.

**Returns:**

`ExceptionStore`

### Methods

#### `__init__(self, store: ExceptionStore | None)`

Initialize the manager.

**Parameters:**

- `store` (`ExceptionStore | None`) - Exception store to use

#### `create_suppression(self, scope: ExceptionScope, reason: str, created_by: str, policy_id: str | None, asset_id: str | None, finding_id: str | None, resource_type: str | None, account_id: str | None, tag_key: str | None, tag_value: str | None, conditions: dict | None, jira_ticket: str | None) -> PolicyException`

Create a permanent suppression.

**Parameters:**

- `scope` (`ExceptionScope`) - Scope of the exception
- `reason` (`str`) - Reason for suppression
- `created_by` (`str`) - Who created it
- `policy_id` (`str | None`) - Target policy
- `asset_id` (`str | None`) - Target asset
- `finding_id` (`str | None`) - Target finding
- `resource_type` (`str | None`) - Target resource type
- `account_id` (`str | None`) - Target account
- `tag_key` (`str | None`) - Tag key to match
- `tag_value` (`str | None`) - Tag value to match
- `conditions` (`dict | None`) - Additional conditions
- `jira_ticket` (`str | None`) - Associated Jira ticket

**Returns:**

`PolicyException` - Created PolicyException

#### `create_temporary_exception(self, scope: ExceptionScope, reason: str, created_by: str, days: int = 30, policy_id: str | None, asset_id: str | None, finding_id: str | None, resource_type: str | None, conditions: dict | None, jira_ticket: str | None) -> PolicyException`

Create a temporary (time-limited) exception.

**Parameters:**

- `scope` (`ExceptionScope`) - Scope of the exception
- `reason` (`str`) - Reason for exception
- `created_by` (`str`) - Who created it
- `days` (`int`) - default: `30` - Number of days until expiry
- `policy_id` (`str | None`) - Target policy
- `asset_id` (`str | None`) - Target asset
- `finding_id` (`str | None`) - Target finding
- `resource_type` (`str | None`) - Target resource type
- `conditions` (`dict | None`) - Additional conditions
- `jira_ticket` (`str | None`) - Associated Jira ticket

**Returns:**

`PolicyException` - Created PolicyException

#### `mark_false_positive(self, finding_id: str, reason: str, created_by: str, jira_ticket: str | None) -> PolicyException`

Mark a finding as a false positive.

**Parameters:**

- `finding_id` (`str`) - Finding ID
- `reason` (`str`) - Reason it's a false positive
- `created_by` (`str`) - Who marked it
- `jira_ticket` (`str | None`) - Associated Jira ticket

**Returns:**

`PolicyException` - Created PolicyException

#### `accept_risk(self, scope: ExceptionScope, reason: str, created_by: str, approved_by: str, policy_id: str | None, asset_id: str | None, resource_type: str | None, account_id: str | None, expires_days: int | None = 365, jira_ticket: str | None, notes: str = ) -> PolicyException`

Formally accept a risk.

**Parameters:**

- `scope` (`ExceptionScope`) - Scope of risk acceptance
- `reason` (`str`) - Reason for accepting risk
- `created_by` (`str`) - Who created the request
- `approved_by` (`str`) - Who approved the risk
- `policy_id` (`str | None`) - Target policy
- `asset_id` (`str | None`) - Target asset
- `resource_type` (`str | None`) - Target resource type
- `account_id` (`str | None`) - Target account
- `expires_days` (`int | None`) - default: `365` - Days until needs review (None for permanent)
- `jira_ticket` (`str | None`) - Associated Jira ticket
- `notes` (`str`) - default: `` - Additional notes

**Returns:**

`PolicyException` - Created PolicyException

#### `add_compensating_control(self, scope: ExceptionScope, reason: str, created_by: str, control_description: str, policy_id: str | None, asset_id: str | None, resource_type: str | None, jira_ticket: str | None) -> PolicyException`

Document a compensating control.

**Parameters:**

- `scope` (`ExceptionScope`) - Scope of the control
- `reason` (`str`) - Why the control is sufficient
- `created_by` (`str`) - Who documented it
- `control_description` (`str`) - Description of the compensating control
- `policy_id` (`str | None`) - Target policy
- `asset_id` (`str | None`) - Target asset
- `resource_type` (`str | None`) - Target resource type
- `jira_ticket` (`str | None`) - Associated Jira ticket

**Returns:**

`PolicyException` - Created PolicyException

#### `get_exception(self, exception_id: str) -> PolicyException | None`

Get an exception by ID.

**Parameters:**

- `exception_id` (`str`)

**Returns:**

`PolicyException | None`

#### `update_exception(self, exception: PolicyException) -> bool`

Update an exception.

**Parameters:**

- `exception` (`PolicyException`)

**Returns:**

`bool`

#### `revoke_exception(self, exception_id: str, reason: str = ) -> bool`

Revoke an exception.

**Parameters:**

- `exception_id` (`str`) - Exception to revoke
- `reason` (`str`) - default: `` - Reason for revocation

**Returns:**

`bool` - True if revoked

#### `delete_exception(self, exception_id: str) -> bool`

Delete an exception permanently.

**Parameters:**

- `exception_id` (`str`)

**Returns:**

`bool`

#### `list_exceptions(self, status: ExceptionStatus | None, exception_type: ExceptionType | None, scope: ExceptionScope | None, include_expired: bool = False) -> list[PolicyException]`

List exceptions with filters.

**Parameters:**

- `status` (`ExceptionStatus | None`)
- `exception_type` (`ExceptionType | None`)
- `scope` (`ExceptionScope | None`)
- `include_expired` (`bool`) - default: `False`

**Returns:**

`list[PolicyException]`

#### `get_active_exceptions(self) -> list[PolicyException]`

Get all active exceptions.

**Returns:**

`list[PolicyException]`

#### `get_exceptions_for_asset(self, asset_id: str) -> list[PolicyException]`

Get exceptions for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`list[PolicyException]`

#### `get_exceptions_for_policy(self, policy_id: str) -> list[PolicyException]`

Get exceptions for a policy.

**Parameters:**

- `policy_id` (`str`)

**Returns:**

`list[PolicyException]`

#### `expire_outdated(self) -> int`

Mark expired exceptions as expired.

**Returns:**

`int`

#### `check_finding(self, finding: 'Finding', asset: 'Asset | None') -> ExceptionResult`

Check if a finding is excepted.

**Parameters:**

- `finding` (`'Finding'`) - Finding to check
- `asset` (`'Asset | None'`) - Optional asset for additional matching

**Returns:**

`ExceptionResult` - ExceptionResult with match information

#### `apply_exceptions(self, findings: 'FindingCollection', assets: dict[(str, 'Asset')] | None) -> tuple[('FindingCollection', list[ExceptionResult])]`

Apply exceptions to a collection of findings.  Modifies finding statuses based on matching exceptions.

**Parameters:**

- `findings` (`'FindingCollection'`) - FindingCollection to process
- `assets` (`dict[(str, 'Asset')] | None`) - Optional dict of asset_id -> Asset for matching

**Returns:**

`tuple[('FindingCollection', list[ExceptionResult])]` - Tuple of (modified FindingCollection, list of ExceptionResults)

### `get_exception_manager() -> ExceptionManager`

Get the global exception manager.

**Returns:**

`ExceptionManager` - ExceptionManager instance
