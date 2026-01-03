# stance.iac.terraform

Terraform HCL parser for Mantissa Stance.

Provides parsing of Terraform (.tf) files without external dependencies.
This is a minimal HCL parser that handles the core syntax needed for
security policy evaluation.

Supported HCL constructs:
- resource blocks
- data blocks
- variable blocks
- output blocks
- locals blocks
- module blocks
- provider blocks
- Nested blocks and attributes
- String interpolation (parsed but not evaluated)
- Comments (single-line # and //, multi-line /* */)

## Contents

### Classes

- [TokenType](#tokentype)
- [Token](#token)
- [HCLLexer](#hcllexer)
- [HCLParser](#hclparser)
- [TerraformResource](#terraformresource)
- [TerraformParser](#terraformparser)

### Functions

- [parse_terraform_file](#parse_terraform_file)
- [parse_terraform_directory](#parse_terraform_directory)

## TokenType

**Inherits from:** Enum

Token types for HCL lexer.

## Token

**Tags:** dataclass

A lexer token.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `type` | `TokenType` | - |
| `value` | `Any` | - |
| `line` | `int` | - |
| `column` | `int` | - |

## HCLLexer

Lexer for HCL (HashiCorp Configuration Language).

Tokenizes HCL content into a stream of tokens for parsing.

### Methods

#### `__init__(self, content: str) -> None`

Initialize the lexer with content.

**Parameters:**

- `content` (`str`)

**Returns:**

`None`

#### `tokenize(self) -> list[Token]`

Tokenize the content and return list of tokens.

**Returns:**

`list[Token]`

## HCLParser

Parser for HCL (HashiCorp Configuration Language).

Parses tokenized HCL content into an AST-like structure.

### Properties

#### `errors(self) -> list[str]`

Get parsing errors.

**Returns:**

`list[str]`

### Methods

#### `__init__(self, tokens: list[Token]) -> None`

Initialize the parser with tokens.

**Parameters:**

- `tokens` (`list[Token]`)

**Returns:**

`None`

#### `parse(self) -> dict[(str, Any)]`

Parse tokens into a structured dictionary.

**Returns:**

`dict[(str, Any)]` - Dictionary with parsed HCL structure

## TerraformResource

**Inherits from:** IaCResource

**Tags:** dataclass

A Terraform resource with additional metadata.

Extends IaCResource with Terraform-specific attributes.

## TerraformParser

**Inherits from:** IaCParser

Parser for Terraform (.tf) files.

Parses HCL syntax and extracts resources, variables, outputs,
and other Terraform constructs.

### Properties

#### `format(self) -> IaCFormat`

Return Terraform format.

**Returns:**

`IaCFormat`

#### `file_extensions(self) -> list[str]`

Return Terraform file extensions.

**Returns:**

`list[str]`

### Methods

#### `parse_file(self, file_path: str | Path) -> IaCFile`

Parse a Terraform file.

**Parameters:**

- `file_path` (`str | Path`) - Path to the .tf file

**Returns:**

`IaCFile` - Parsed IaCFile object

#### `parse_content(self, content: str, file_path: str = <string>) -> IaCFile`

Parse Terraform content from a string.

**Parameters:**

- `content` (`str`) - The HCL content to parse
- `file_path` (`str`) - default: `<string>` - Virtual file path for error reporting

**Returns:**

`IaCFile` - Parsed IaCFile object

### `parse_terraform_file(file_path: str | Path) -> IaCFile`

Convenience function to parse a single Terraform file.

**Parameters:**

- `file_path` (`str | Path`) - Path to the .tf file

**Returns:**

`IaCFile` - Parsed IaCFile object

### `parse_terraform_directory(directory: str | Path, recursive: bool = True) -> IaCParseResult`

Convenience function to parse all Terraform files in a directory.

**Parameters:**

- `directory` (`str | Path`) - Directory to scan
- `recursive` (`bool`) - default: `True` - Whether to scan subdirectories

**Returns:**

`IaCParseResult` - IaCParseResult with all parsed files
