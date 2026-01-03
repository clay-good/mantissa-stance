# stance.docs.generator

Documentation generator for Mantissa Stance.

This module provides tools for automatically generating documentation
from Python source code, including API references, CLI documentation,
and policy documentation.

## Contents

### Classes

- [ParameterInfo](#parameterinfo)
- [FunctionInfo](#functioninfo)
- [ClassInfo](#classinfo)
- [ModuleInfo](#moduleinfo)
- [DocstringParser](#docstringparser)
- [SourceAnalyzer](#sourceanalyzer)
- [MarkdownWriter](#markdownwriter)
- [APIReferenceGenerator](#apireferencegenerator)
- [CLIReferenceGenerator](#clireferencegenerator)
- [PolicyDocGenerator](#policydocgenerator)
- [DocumentationGenerator](#documentationgenerator)

## ParameterInfo

**Tags:** dataclass

Information about a function/method parameter.

Attributes:
    name: Parameter name
    type_hint: Type annotation if present
    default: Default value if present
    description: Parameter description from docstring

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `type_hint` | `Optional[str]` | - |
| `default` | `Optional[str]` | - |
| `description` | `Optional[str]` | - |

## FunctionInfo

**Tags:** dataclass

Information about a function or method.

Attributes:
    name: Function name
    signature: Full signature string
    docstring: Function docstring
    parameters: List of parameter info
    return_type: Return type annotation
    return_description: Return value description from docstring
    is_async: Whether function is async
    is_classmethod: Whether method is a classmethod
    is_staticmethod: Whether method is a staticmethod
    is_property: Whether method is a property
    decorators: List of decorator names
    raises: List of exceptions that can be raised
    examples: Code examples from docstring

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `signature` | `str` | `` |
| `docstring` | `Optional[str]` | - |
| `parameters` | `List[ParameterInfo]` | `field(...)` |
| `return_type` | `Optional[str]` | - |
| `return_description` | `Optional[str]` | - |
| `is_async` | `bool` | `False` |
| `is_classmethod` | `bool` | `False` |
| `is_staticmethod` | `bool` | `False` |
| `is_property` | `bool` | `False` |
| `decorators` | `List[str]` | `field(...)` |
| `raises` | `List[Tuple[(str, str)]]` | `field(...)` |
| `examples` | `List[str]` | `field(...)` |

## ClassInfo

**Tags:** dataclass

Information about a class.

Attributes:
    name: Class name
    docstring: Class docstring
    bases: List of base class names
    methods: List of method info
    class_methods: List of classmethod info
    static_methods: List of staticmethod info
    properties: List of property info
    attributes: List of class attribute info
    is_dataclass: Whether class is a dataclass
    is_abstract: Whether class is abstract

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `docstring` | `Optional[str]` | - |
| `bases` | `List[str]` | `field(...)` |
| `methods` | `List[FunctionInfo]` | `field(...)` |
| `class_methods` | `List[FunctionInfo]` | `field(...)` |
| `static_methods` | `List[FunctionInfo]` | `field(...)` |
| `properties` | `List[FunctionInfo]` | `field(...)` |
| `attributes` | `List[Tuple[(str, str, str)]]` | `field(...)` |
| `is_dataclass` | `bool` | `False` |
| `is_abstract` | `bool` | `False` |

## ModuleInfo

**Tags:** dataclass

Information about a module.

Attributes:
    name: Module name
    path: File path
    docstring: Module docstring
    classes: List of class info
    functions: List of function info
    constants: List of module-level constants
    imports: List of import statements
    submodules: List of submodule names

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `path` | `str` | - |
| `docstring` | `Optional[str]` | - |
| `classes` | `List[ClassInfo]` | `field(...)` |
| `functions` | `List[FunctionInfo]` | `field(...)` |
| `constants` | `List[Tuple[(str, str, Any)]]` | `field(...)` |
| `imports` | `List[str]` | `field(...)` |
| `submodules` | `List[str]` | `field(...)` |

## DocstringParser

Parse docstrings to extract structured information.

### Static Methods

#### `parse(docstring: Optional[str]) -> Dict[(str, Any)]`

**Decorators:** @staticmethod

Parse a docstring into structured sections.

**Parameters:**

- `docstring` (`Optional[str]`) - The docstring to parse

**Returns:**

`Dict[(str, Any)]` - Dictionary with sections like 'description', 'args', 'returns', etc.

#### `_save_section(result: Dict[(str, Any)], section: str, content: List[str], item: Optional[str]) -> None`

**Decorators:** @staticmethod

Save section content to result dictionary.

**Parameters:**

- `result` (`Dict[(str, Any)]`)
- `section` (`str`)
- `content` (`List[str]`)
- `item` (`Optional[str]`)

**Returns:**

`None`

## SourceAnalyzer

Analyze Python source code to extract documentation info.

### Methods

#### `__init__(self, source_path: str)`

Initialize analyzer with source path.

**Parameters:**

- `source_path` (`str`) - Path to the Python source file

#### `analyze(self) -> ModuleInfo`

Analyze the source file and extract module info.

**Returns:**

`ModuleInfo` - ModuleInfo with all extracted information

## MarkdownWriter

Write documentation in Markdown format.

### Methods

#### `__init__(self, output_dir: str)`

Initialize writer with output directory.

**Parameters:**

- `output_dir` (`str`) - Directory to write documentation files

#### `write_module(self, info: ModuleInfo, package_name: str = ) -> str`

Write module documentation to a Markdown file.

**Parameters:**

- `info` (`ModuleInfo`) - Module information to document
- `package_name` (`str`) - default: `` - Parent package name for full module path

**Returns:**

`str` - Path to the generated file

#### `write_index(self, modules: List[ModuleInfo], title: str = API Reference) -> str`

Write an index file listing all modules.

**Parameters:**

- `modules` (`List[ModuleInfo]`) - List of module info objects
- `title` (`str`) - default: `API Reference` - Title for the index page

**Returns:**

`str` - Path to the generated index file

## APIReferenceGenerator

Generate API reference documentation from Python source.

### Methods

#### `__init__(self, source_dir: str, output_dir: str)`

Initialize API reference generator.

**Parameters:**

- `source_dir` (`str`) - Directory containing Python source files
- `output_dir` (`str`) - Directory to write documentation

#### `generate(self, package_name: str = stance) -> List[str]`

Generate API documentation for all modules.

**Parameters:**

- `package_name` (`str`) - default: `stance` - Name of the package being documented

**Returns:**

`List[str]` - List of generated file paths

## CLIReferenceGenerator

Generate CLI command reference documentation.

### Methods

#### `__init__(self, output_dir: str)`

Initialize CLI reference generator.

**Parameters:**

- `output_dir` (`str`) - Directory to write documentation

#### `generate(self) -> str`

Generate CLI reference documentation.

**Returns:**

`str` - Path to generated file

## PolicyDocGenerator

Generate documentation for policy files.

### Methods

#### `__init__(self, policies_dir: str, output_dir: str)`

Initialize policy documentation generator.

**Parameters:**

- `policies_dir` (`str`) - Directory containing policy YAML files
- `output_dir` (`str`) - Directory to write documentation

#### `generate(self) -> List[str]`

Generate policy documentation.

**Returns:**

`List[str]` - List of generated file paths

## DocumentationGenerator

Main documentation generator for Mantissa Stance.

This class coordinates generation of all documentation types:
- API reference from source code docstrings
- CLI command reference
- Policy documentation

### Methods

#### `__init__(self, source_dir: str = src/stance, output_dir: str = docs/generated, policies_dir: Optional[str] = policies)`

Initialize documentation generator.

**Parameters:**

- `source_dir` (`str`) - default: `src/stance` - Directory containing Python source files
- `output_dir` (`str`) - default: `docs/generated` - Base directory for generated documentation
- `policies_dir` (`Optional[str]`) - default: `policies` - Directory containing policy YAML files (optional)

#### `generate_all(self) -> Dict[(str, List[str])]`

Generate all documentation.

**Returns:**

`Dict[(str, List[str])]` - Dictionary mapping documentation type to list of generated files

#### `generate_api(self) -> List[str]`

Generate only API documentation.

**Returns:**

`List[str]` - List of generated file paths

#### `generate_cli(self) -> str`

Generate only CLI documentation.

**Returns:**

`str` - Path to generated file

#### `generate_policies(self) -> List[str]`

Generate only policy documentation.

**Returns:**

`List[str]` - List of generated file paths
