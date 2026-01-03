# stance.iac.cloudformation

CloudFormation template parser for Mantissa Stance.

Provides parsing of AWS CloudFormation templates in both JSON and YAML formats
without external dependencies (uses stdlib json and a minimal YAML parser).

Supported constructs:
- Resources
- Parameters
- Outputs
- Conditions
- Mappings
- Metadata
- Intrinsic functions (parsed but not evaluated)
- Nested stacks (reference extraction)

## Contents

### Classes

- [SimpleYAMLParser](#simpleyamlparser)
- [CloudFormationResource](#cloudformationresource)
- [CloudFormationParser](#cloudformationparser)

### Functions

- [parse_cloudformation_file](#parse_cloudformation_file)
- [parse_cloudformation_content](#parse_cloudformation_content)

## Constants

### `CFN_RESOURCE_PROVIDERS`

Type: `dict`

Value: `{'AWS::': 'aws', 'Alexa::': 'aws', 'Custom::': 'aws'}`

## SimpleYAMLParser

Minimal YAML parser for CloudFormation templates.

This parser handles the subset of YAML needed for CloudFormation:
- Key-value pairs
- Lists
- Nested objects
- Multi-line strings (literal and folded)
- CloudFormation intrinsic functions (!Ref, !Sub, etc.)
- Comments
- Anchors and aliases (basic support)

Note: This is not a full YAML parser. For complex YAML features,
consider using PyYAML if available.

### Properties

#### `errors(self) -> list[str]`

Get parsing errors.

**Returns:**

`list[str]`

### Methods

#### `__init__(self, content: str) -> None`

Initialize the parser with YAML content.

**Parameters:**

- `content` (`str`)

**Returns:**

`None`

#### `parse(self) -> dict[(str, Any)]`

Parse YAML content into a dictionary.

**Returns:**

`dict[(str, Any)]` - Parsed dictionary structure

## CloudFormationResource

**Inherits from:** IaCResource

**Tags:** dataclass

A CloudFormation resource with additional metadata.

Extends IaCResource with CloudFormation-specific attributes.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `logical_id` | `str` | `` |
| `condition` | `str | None` | - |
| `creation_policy` | `dict[(str, Any)] | None` | - |
| `update_policy` | `dict[(str, Any)] | None` | - |
| `deletion_policy` | `str | None` | - |
| `update_replace_policy` | `str | None` | - |
| `metadata` | `dict[(str, Any)]` | `field(...)` |

## CloudFormationParser

**Inherits from:** IaCParser

Parser for AWS CloudFormation templates.

Parses both JSON and YAML format CloudFormation templates and extracts
resources, parameters, outputs, and other template components.

### Properties

#### `format(self) -> IaCFormat`

Return CloudFormation format.

**Returns:**

`IaCFormat`

#### `file_extensions(self) -> list[str]`

Return CloudFormation file extensions.

**Returns:**

`list[str]`

### Methods

#### `parse_file(self, file_path: str | Path) -> IaCFile`

Parse a CloudFormation template file.

**Parameters:**

- `file_path` (`str | Path`) - Path to the template file

**Returns:**

`IaCFile` - Parsed IaCFile object

#### `parse_content(self, content: str, file_path: str = <string>) -> IaCFile`

Parse CloudFormation content from a string.

**Parameters:**

- `content` (`str`) - The template content to parse
- `file_path` (`str`) - default: `<string>` - Virtual file path for error reporting

**Returns:**

`IaCFile` - Parsed IaCFile object

#### `can_parse(self, file_path: str | Path) -> bool`

Check if this parser can handle the given file.  Overridden to check file content for CloudFormation markers.

**Parameters:**

- `file_path` (`str | Path`)

**Returns:**

`bool`

### `parse_cloudformation_file(file_path: str | Path) -> IaCFile`

Convenience function to parse a single CloudFormation template.

**Parameters:**

- `file_path` (`str | Path`) - Path to the template file

**Returns:**

`IaCFile` - Parsed IaCFile object

### `parse_cloudformation_content(content: str, file_path: str = <string>) -> IaCFile`

Convenience function to parse CloudFormation template content.

**Parameters:**

- `content` (`str`) - Template content (JSON or YAML)
- `file_path` (`str`) - default: `<string>` - Virtual file path for error reporting

**Returns:**

`IaCFile` - Parsed IaCFile object
