# stance.iac.base

Base classes for Infrastructure as Code (IaC) scanning.

Provides abstract base classes and data structures for IaC parsing
and policy evaluation across different IaC formats.

## Contents

### Classes

- [IaCFormat](#iacformat)
- [IaCLocation](#iaclocation)
- [IaCResource](#iacresource)
- [IaCFile](#iacfile)
- [IaCParseResult](#iacparseresult)
- [IaCFinding](#iacfinding)
- [IaCParser](#iacparser)
- [IaCScanner](#iacscanner)

## Constants

### `_MISSING`

Type: `str`

Value: `object(...)`

## IaCFormat

**Inherits from:** Enum

Supported IaC formats.

## IaCLocation

**Tags:** dataclass

Location information for an IaC element.

Attributes:
    file_path: Path to the IaC file
    line_start: Starting line number (1-indexed)
    line_end: Ending line number (1-indexed)
    column_start: Starting column (optional)
    column_end: Ending column (optional)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `file_path` | `str` | - |
| `line_start` | `int` | - |
| `line_end` | `int | None` | - |
| `column_start` | `int | None` | - |
| `column_end` | `int | None` | - |

## IaCResource

**Tags:** dataclass

Represents a resource defined in an IaC file.

Attributes:
    resource_type: Type of the resource (e.g., "aws_s3_bucket")
    name: Name/identifier of the resource in the IaC file
    provider: Cloud provider (aws, gcp, azure, kubernetes)
    config: Resource configuration as a dictionary
    location: Location in the source file
    labels: Resource labels/tags if defined
    dependencies: List of resource references this depends on

### Attributes

| Name | Type | Default |
|------|------|---------|
| `resource_type` | `str` | - |
| `name` | `str` | - |
| `provider` | `str` | - |
| `config` | `dict[(str, Any)]` | - |
| `location` | `IaCLocation` | - |
| `labels` | `dict[(str, str)]` | `field(...)` |
| `dependencies` | `list[str]` | `field(...)` |

### Properties

#### `full_address(self) -> str`

Return the full resource address (e.g., aws_s3_bucket.my_bucket).

**Returns:**

`str`

### Methods

#### `get_config_value(self, path: str, default: Any) -> Any`

Get a nested configuration value using dot notation.

**Parameters:**

- `path` (`str`) - Dot-separated path (e.g., "encryption.enabled")
- `default` (`Any`) - Default value if path not found

**Returns:**

`Any` - Configuration value or default

#### `has_config(self, path: str) -> bool`

Check if a configuration path exists.

**Parameters:**

- `path` (`str`)

**Returns:**

`bool`

## IaCFile

**Tags:** dataclass

Represents a parsed IaC file.

Attributes:
    file_path: Path to the file
    format: IaC format type
    resources: List of resources defined in the file
    variables: Variables defined in the file
    outputs: Outputs defined in the file
    locals: Local values defined in the file
    data_sources: Data sources referenced in the file
    modules: Module references in the file
    providers: Provider configurations
    raw_content: Original file content
    parse_errors: Any parsing errors encountered

### Attributes

| Name | Type | Default |
|------|------|---------|
| `file_path` | `str` | - |
| `format` | `IaCFormat` | - |
| `resources` | `list[IaCResource]` | `field(...)` |
| `variables` | `dict[(str, Any)]` | `field(...)` |
| `outputs` | `dict[(str, Any)]` | `field(...)` |
| `locals` | `dict[(str, Any)]` | `field(...)` |
| `data_sources` | `list[IaCResource]` | `field(...)` |
| `modules` | `dict[(str, Any)]` | `field(...)` |
| `providers` | `dict[(str, Any)]` | `field(...)` |
| `raw_content` | `str` | `` |
| `parse_errors` | `list[str]` | `field(...)` |

### Properties

#### `has_errors(self) -> bool`

Check if parsing had errors.

**Returns:**

`bool`

#### `resource_count(self) -> int`

Get total number of resources.

**Returns:**

`int`

### Methods

#### `get_resources_by_type(self, resource_type: str) -> list[IaCResource]`

Get all resources of a specific type.

**Parameters:**

- `resource_type` (`str`)

**Returns:**

`list[IaCResource]`

#### `get_resources_by_provider(self, provider: str) -> list[IaCResource]`

Get all resources for a specific provider.

**Parameters:**

- `provider` (`str`)

**Returns:**

`list[IaCResource]`

## IaCParseResult

**Tags:** dataclass

Result from parsing IaC files.

Attributes:
    files: List of parsed IaC files
    total_resources: Total number of resources across all files
    total_errors: Total number of parse errors
    duration_seconds: Time taken to parse

### Attributes

| Name | Type | Default |
|------|------|---------|
| `files` | `list[IaCFile]` | `field(...)` |
| `total_resources` | `int` | `0` |
| `total_errors` | `int` | `0` |
| `duration_seconds` | `float` | `0.0` |

### Methods

#### `add_file(self, iac_file: IaCFile) -> None`

Add a parsed file to the result.

**Parameters:**

- `iac_file` (`IaCFile`)

**Returns:**

`None`

#### `get_all_resources(self) -> Iterator[IaCResource]`

Iterate over all resources across all files.

**Returns:**

`Iterator[IaCResource]`

#### `get_resources_by_type(self, resource_type: str) -> list[IaCResource]`

Get all resources of a specific type across all files.

**Parameters:**

- `resource_type` (`str`)

**Returns:**

`list[IaCResource]`

## IaCFinding

**Tags:** dataclass

A security finding in an IaC file.

Attributes:
    rule_id: Policy rule that triggered
    resource: The resource with the issue
    severity: Finding severity
    title: Short description
    description: Detailed explanation
    remediation: How to fix the issue
    expected_value: What the value should be
    actual_value: What the value actually is

### Attributes

| Name | Type | Default |
|------|------|---------|
| `rule_id` | `str` | - |
| `resource` | `IaCResource` | - |
| `severity` | `Severity` | - |
| `title` | `str` | - |
| `description` | `str` | - |
| `remediation` | `str` | `` |
| `expected_value` | `str | None` | - |
| `actual_value` | `str | None` | - |

### Methods

#### `to_finding(self) -> Finding`

Convert to a standard Finding object.

**Returns:**

`Finding`

## IaCParser

**Inherits from:** ABC

Abstract base class for IaC parsers.

All IaC format parsers must inherit from this class and implement
the parse_file and parse_content methods.

### Properties

#### `format(self) -> IaCFormat`

**Decorators:** @property, @abstractmethod

Return the IaC format this parser handles.

**Returns:**

`IaCFormat`

#### `file_extensions(self) -> list[str]`

**Decorators:** @property, @abstractmethod

Return list of file extensions this parser handles.

**Returns:**

`list[str]`

### Methods

#### `parse_file(self, file_path: str | Path) -> IaCFile`

**Decorators:** @abstractmethod

Parse an IaC file.

**Parameters:**

- `file_path` (`str | Path`) - Path to the file to parse

**Returns:**

`IaCFile` - Parsed IaCFile object

#### `parse_content(self, content: str, file_path: str = <string>) -> IaCFile`

**Decorators:** @abstractmethod

Parse IaC content from a string.

**Parameters:**

- `content` (`str`) - The IaC content to parse
- `file_path` (`str`) - default: `<string>` - Virtual file path for error reporting

**Returns:**

`IaCFile` - Parsed IaCFile object

#### `parse_directory(self, directory: str | Path, recursive: bool = True) -> IaCParseResult`

Parse all matching files in a directory.

**Parameters:**

- `directory` (`str | Path`) - Directory to scan
- `recursive` (`bool`) - default: `True` - Whether to scan subdirectories

**Returns:**

`IaCParseResult` - IaCParseResult with all parsed files

#### `can_parse(self, file_path: str | Path) -> bool`

Check if this parser can handle the given file.

**Parameters:**

- `file_path` (`str | Path`)

**Returns:**

`bool`

## IaCScanner

Scans IaC files for security issues.

Combines parsing with policy evaluation to find security
misconfigurations in infrastructure code.

### Methods

#### `__init__(self, parsers: list[IaCParser] | None, policy_evaluator: Any | None) -> None`

Initialize the IaC scanner.

**Parameters:**

- `parsers` (`list[IaCParser] | None`) - List of IaC parsers to use
- `policy_evaluator` (`Any | None`) - Optional policy evaluator instance

**Returns:**

`None`

#### `register_parser(self, parser: IaCParser) -> None`

Register an IaC parser.

**Parameters:**

- `parser` (`IaCParser`)

**Returns:**

`None`

#### `set_policy_evaluator(self, evaluator: Any) -> None`

Set the policy evaluator.

**Parameters:**

- `evaluator` (`Any`)

**Returns:**

`None`

#### `get_parser_for_file(self, file_path: str | Path) -> IaCParser | None`

Get a parser that can handle the given file.

**Parameters:**

- `file_path` (`str | Path`)

**Returns:**

`IaCParser | None`

#### `scan_file(self, file_path: str | Path) -> list[IaCFinding]`

Scan a single IaC file for security issues.

**Parameters:**

- `file_path` (`str | Path`) - Path to the file to scan

**Returns:**

`list[IaCFinding]` - List of findings

#### `scan_directory(self, directory: str | Path, recursive: bool = True) -> tuple[(IaCParseResult, list[IaCFinding])]`

Scan a directory for IaC security issues.

**Parameters:**

- `directory` (`str | Path`) - Directory to scan
- `recursive` (`bool`) - default: `True` - Whether to scan subdirectories

**Returns:**

`tuple[(IaCParseResult, list[IaCFinding])]` - Tuple of (parse result, findings)
