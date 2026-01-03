# stance.exceptions.store

Exception storage for Mantissa Stance.

Provides persistent storage for policy exceptions.

## Contents

### Classes

- [ExceptionStore](#exceptionstore)
- [LocalExceptionStore](#localexceptionstore)

### Functions

- [get_exception_store](#get_exception_store)

## ExceptionStore

**Inherits from:** ABC

Abstract base class for exception storage.

Implementations provide persistent storage for policy exceptions.

### Methods

#### `save(self, exception: PolicyException) -> bool`

**Decorators:** @abstractmethod

Save an exception.

**Parameters:**

- `exception` (`PolicyException`) - Exception to save

**Returns:**

`bool` - True if saved successfully

#### `get(self, exception_id: str) -> PolicyException | None`

**Decorators:** @abstractmethod

Get an exception by ID.

**Parameters:**

- `exception_id` (`str`) - Exception ID

**Returns:**

`PolicyException | None` - PolicyException or None

#### `delete(self, exception_id: str) -> bool`

**Decorators:** @abstractmethod

Delete an exception.

**Parameters:**

- `exception_id` (`str`) - Exception ID to delete

**Returns:**

`bool` - True if deleted

#### `list_all(self, status: ExceptionStatus | None, exception_type: ExceptionType | None, scope: ExceptionScope | None, include_expired: bool = False) -> list[PolicyException]`

**Decorators:** @abstractmethod

List exceptions with optional filters.

**Parameters:**

- `status` (`ExceptionStatus | None`) - Filter by status
- `exception_type` (`ExceptionType | None`) - Filter by type
- `scope` (`ExceptionScope | None`) - Filter by scope
- `include_expired` (`bool`) - default: `False` - Include expired exceptions

**Returns:**

`list[PolicyException]` - List of matching exceptions

#### `get_active(self) -> list[PolicyException]`

**Decorators:** @abstractmethod

Get all active exceptions.

**Returns:**

`list[PolicyException]` - List of active exceptions

#### `find_by_asset(self, asset_id: str) -> list[PolicyException]`

**Decorators:** @abstractmethod

Find exceptions for a specific asset.

**Parameters:**

- `asset_id` (`str`) - Asset ID

**Returns:**

`list[PolicyException]` - List of matching exceptions

#### `find_by_policy(self, policy_id: str) -> list[PolicyException]`

**Decorators:** @abstractmethod

Find exceptions for a specific policy.

**Parameters:**

- `policy_id` (`str`) - Policy ID

**Returns:**

`list[PolicyException]` - List of matching exceptions

#### `expire_outdated(self) -> int`

**Decorators:** @abstractmethod

Mark expired exceptions as expired.

**Returns:**

`int` - Number of exceptions marked as expired

## LocalExceptionStore

**Inherits from:** ExceptionStore

Local file-based exception storage.

Stores exceptions in a JSON file.

### Methods

#### `__init__(self, file_path: str | Path | None)`

Initialize the store.

**Parameters:**

- `file_path` (`str | Path | None`) - Path to storage file

#### `save(self, exception: PolicyException) -> bool`

Save an exception.

**Parameters:**

- `exception` (`PolicyException`)

**Returns:**

`bool`

#### `get(self, exception_id: str) -> PolicyException | None`

Get an exception by ID.

**Parameters:**

- `exception_id` (`str`)

**Returns:**

`PolicyException | None`

#### `delete(self, exception_id: str) -> bool`

Delete an exception.

**Parameters:**

- `exception_id` (`str`)

**Returns:**

`bool`

#### `list_all(self, status: ExceptionStatus | None, exception_type: ExceptionType | None, scope: ExceptionScope | None, include_expired: bool = False) -> list[PolicyException]`

List exceptions with filters.

**Parameters:**

- `status` (`ExceptionStatus | None`)
- `exception_type` (`ExceptionType | None`)
- `scope` (`ExceptionScope | None`)
- `include_expired` (`bool`) - default: `False`

**Returns:**

`list[PolicyException]`

#### `get_active(self) -> list[PolicyException]`

Get all active exceptions.

**Returns:**

`list[PolicyException]`

#### `find_by_asset(self, asset_id: str) -> list[PolicyException]`

Find exceptions for an asset.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`list[PolicyException]`

#### `find_by_policy(self, policy_id: str) -> list[PolicyException]`

Find exceptions for a policy.

**Parameters:**

- `policy_id` (`str`)

**Returns:**

`list[PolicyException]`

#### `expire_outdated(self) -> int`

Mark expired exceptions as expired.

**Returns:**

`int`

#### `clear(self) -> None`

Clear all exceptions (for testing).

**Returns:**

`None`

### `get_exception_store(file_path: str | Path | None) -> ExceptionStore`

Get the exception store.

**Parameters:**

- `file_path` (`str | Path | None`) - Optional custom file path

**Returns:**

`ExceptionStore` - ExceptionStore instance
