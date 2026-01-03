# stance.engine.loader

Policy loader for Mantissa Stance.

Loads and validates security policies from YAML files.

## Contents

### Classes

- [PolicyLoadError](#policyloaderror)
- [PolicyLoader](#policyloader)

## PolicyLoadError

**Inherits from:** Exception

Exception raised when policy loading fails.

### Methods

#### `__init__(self, message: str, source_path: str | None)`

**Parameters:**

- `message` (`str`)
- `source_path` (`str | None`)

## PolicyLoader

Loads and validates security policies from YAML files.

Supports loading individual policy files or discovering all policies
in configured directories.

### Methods

#### `__init__(self, policy_dirs: list[str] | None)`

Initialize the policy loader.

**Parameters:**

- `policy_dirs` (`list[str] | None`) - Directories to search for policies. Defaults to ["policies/"]

#### `load_all(self) -> PolicyCollection`

Load all policies from configured directories.

**Returns:**

`PolicyCollection` - PolicyCollection with all valid policies

**Raises:**

- `PolicyLoadError`: If no policies could be loaded

#### `load_policy(self, path: str) -> Policy`

Load a single policy from file path.

**Parameters:**

- `path` (`str`) - Path to the policy YAML file

**Returns:**

`Policy` - Loaded Policy object

**Raises:**

- `PolicyLoadError`: If policy cannot be loaded

#### `validate_policy(self, policy: Policy) -> list[str]`

Validate policy schema and check logic.

**Parameters:**

- `policy` (`Policy`) - Policy to validate

**Returns:**

`list[str]` - List of validation errors (empty if valid)

#### `discover_policies(self) -> list[str]`

Find all YAML files in policy directories.

**Returns:**

`list[str]` - List of policy file paths
