# stance.exceptions.matcher

Exception matcher for Mantissa Stance.

Matches findings against policy exceptions based on various criteria.

## Contents

### Classes

- [ExceptionMatcher](#exceptionmatcher)

### Functions

- [match_exception](#match_exception)

## ExceptionMatcher

Matches findings against policy exceptions.

Supports matching by:
- Finding ID
- Asset ID
- Policy/Rule ID
- Asset + Policy combination
- Resource type
- Tags
- Account ID
- Custom conditions

### Properties

#### `exceptions(self) -> list[PolicyException]`

Get list of exceptions.

**Returns:**

`list[PolicyException]`

### Methods

#### `__init__(self, exceptions: list[PolicyException] | None)`

Initialize the matcher.

**Parameters:**

- `exceptions` (`list[PolicyException] | None`) - List of exceptions to match against

#### `add_exception(self, exception: PolicyException) -> None`

Add an exception to the matcher.

**Parameters:**

- `exception` (`PolicyException`) - Exception to add

**Returns:**

`None`

#### `remove_exception(self, exception_id: str) -> bool`

Remove an exception by ID.

**Parameters:**

- `exception_id` (`str`) - ID of exception to remove

**Returns:**

`bool` - True if exception was removed

#### `check_finding(self, finding: 'Finding', asset: 'Asset | None') -> ExceptionResult`

Check if a finding matches any exceptions.

**Parameters:**

- `finding` (`'Finding'`) - Finding to check
- `asset` (`'Asset | None'`) - Optional asset for additional matching

**Returns:**

`ExceptionResult` - ExceptionResult with match information

### `match_exception(finding: 'Finding', exceptions: list[PolicyException], asset: 'Asset | None') -> ExceptionResult`

Check if a finding matches any exceptions.  Convenience function for one-off matching.

**Parameters:**

- `finding` (`'Finding'`) - Finding to check
- `exceptions` (`list[PolicyException]`) - List of exceptions
- `asset` (`'Asset | None'`) - Optional asset

**Returns:**

`ExceptionResult` - ExceptionResult with match information
