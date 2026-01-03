# stance.iac.policies

IaC security policies for Mantissa Stance.

Provides policy definitions and evaluation for Infrastructure as Code
security scanning. Supports Terraform, CloudFormation, and other IaC formats.

## Contents

### Classes

- [IaCPolicyCheck](#iacpolicycheck)
- [IaCPolicyCompliance](#iacpolicycompliance)
- [IaCPolicy](#iacpolicy)
- [IaCPolicyCollection](#iacpolicycollection)
- [IaCPolicyLoader](#iacpolicyloader)
- [IaCPolicyEvaluator](#iacpolicyevaluator)

### Functions

- [get_default_iac_policies](#get_default_iac_policies)

## IaCPolicyCheck

**Tags:** dataclass

Check definition for an IaC policy.

Attributes:
    check_type: Type of check (attribute, pattern, exists, custom)
    path: Dot-notation path to the attribute to check
    operator: Comparison operator
    value: Expected value for comparison
    pattern: Regex pattern for pattern checks
    message: Custom message template for findings

### Attributes

| Name | Type | Default |
|------|------|---------|
| `check_type` | `str` | - |
| `path` | `str` | `` |
| `operator` | `str` | `` |
| `value` | `Any` | - |
| `pattern` | `str` | `` |
| `message` | `str` | `` |
| `checks` | `list['IaCPolicyCheck']` | `field(...)` |

## IaCPolicyCompliance

**Tags:** dataclass

Compliance framework mapping for a policy.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `framework` | `str` | - |
| `version` | `str` | - |
| `control` | `str` | - |

## IaCPolicy

**Tags:** dataclass

Security policy for IaC resources.

Attributes:
    id: Unique policy identifier
    name: Human-readable policy name
    description: Detailed description of the security issue
    enabled: Whether the policy is active
    severity: Severity level of findings
    resource_types: List of resource types this policy applies to
    providers: List of cloud providers (aws, gcp, azure)
    formats: List of IaC formats (terraform, cloudformation, arm)
    check: Check definition
    remediation: Remediation guidance
    compliance: Compliance framework mappings
    tags: Policy tags for categorization
    references: External reference URLs

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `name` | `str` | - |
| `description` | `str` | - |
| `enabled` | `bool` | - |
| `severity` | `Severity` | - |
| `resource_types` | `list[str]` | - |
| `check` | `IaCPolicyCheck` | - |
| `providers` | `list[str]` | `field(...)` |
| `formats` | `list[str]` | `field(...)` |
| `remediation` | `str` | `` |
| `compliance` | `list[IaCPolicyCompliance]` | `field(...)` |
| `tags` | `list[str]` | `field(...)` |
| `references` | `list[str]` | `field(...)` |

### Methods

#### `matches_resource(self, resource: IaCResource) -> bool`

Check if this policy applies to a resource.

**Parameters:**

- `resource` (`IaCResource`)

**Returns:**

`bool`

## IaCPolicyCollection

**Tags:** dataclass

Collection of IaC policies.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `policies` | `list[IaCPolicy]` | `field(...)` |

### Methods

#### `add(self, policy: IaCPolicy) -> None`

Add a policy to the collection.

**Parameters:**

- `policy` (`IaCPolicy`)

**Returns:**

`None`

#### `filter_enabled(self) -> 'IaCPolicyCollection'`

Return only enabled policies.

**Returns:**

`'IaCPolicyCollection'`

#### `filter_by_severity(self, severity: Severity) -> 'IaCPolicyCollection'`

Filter policies by severity.

**Parameters:**

- `severity` (`Severity`)

**Returns:**

`'IaCPolicyCollection'`

#### `filter_by_provider(self, provider: str) -> 'IaCPolicyCollection'`

Filter policies by cloud provider.

**Parameters:**

- `provider` (`str`)

**Returns:**

`'IaCPolicyCollection'`

#### `filter_by_resource_type(self, resource_type: str) -> 'IaCPolicyCollection'`

Filter policies that apply to a resource type.

**Parameters:**

- `resource_type` (`str`)

**Returns:**

`'IaCPolicyCollection'`

#### `get_by_id(self, policy_id: str) -> IaCPolicy | None`

Get a policy by ID.

**Parameters:**

- `policy_id` (`str`)

**Returns:**

`IaCPolicy | None`

## IaCPolicyLoader

Loads IaC policies from YAML files.

Searches for policies in specified directories and loads them
into IaCPolicy objects.

### Methods

#### `__init__(self, policy_dirs: list[str | Path] | None) -> None`

Initialize the policy loader.

**Parameters:**

- `policy_dirs` (`list[str | Path] | None`) - Directories to search for policies

**Returns:**

`None`

#### `load_all(self) -> IaCPolicyCollection`

Load all policies from configured directories.

**Returns:**

`IaCPolicyCollection` - IaCPolicyCollection with all loaded policies

#### `load_policy(self, file_path: Path) -> IaCPolicy | None`

Load a single policy from a YAML file.

**Parameters:**

- `file_path` (`Path`) - Path to the YAML file

**Returns:**

`IaCPolicy | None` - IaCPolicy object or None if loading fails

#### `load_from_string(self, content: str) -> IaCPolicy | None`

Load a policy from YAML string content.

**Parameters:**

- `content` (`str`) - YAML content

**Returns:**

`IaCPolicy | None` - IaCPolicy object or None if loading fails

## IaCPolicyEvaluator

Evaluates IaC policies against parsed resources.

Generates findings for resources that violate policy rules.

### Methods

#### `__init__(self, policies: IaCPolicyCollection | None) -> None`

Initialize the policy evaluator.

**Parameters:**

- `policies` (`IaCPolicyCollection | None`) - Collection of policies to evaluate

**Returns:**

`None`

#### `set_policies(self, policies: IaCPolicyCollection) -> None`

Set the policy collection.

**Parameters:**

- `policies` (`IaCPolicyCollection`)

**Returns:**

`None`

#### `evaluate_file(self, iac_file: IaCFile) -> list[IaCFinding]`

Evaluate all policies against resources in an IaC file.

**Parameters:**

- `iac_file` (`IaCFile`) - Parsed IaC file

**Returns:**

`list[IaCFinding]` - List of findings for policy violations

#### `evaluate_resource(self, resource: IaCResource, policies: IaCPolicyCollection | None) -> list[IaCFinding]`

Evaluate policies against a single resource.

**Parameters:**

- `resource` (`IaCResource`) - Resource to evaluate
- `policies` (`IaCPolicyCollection | None`) - Optional policy collection (uses default if None)

**Returns:**

`list[IaCFinding]` - List of findings for policy violations

### `get_default_iac_policies() -> IaCPolicyCollection`

Get the collection of default built-in IaC policies.

**Returns:**

`IaCPolicyCollection` - IaCPolicyCollection with default policies
