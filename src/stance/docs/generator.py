"""
Documentation generator for Mantissa Stance.

This module provides tools for automatically generating documentation
from Python source code, including API references, CLI documentation,
and policy documentation.
"""

from __future__ import annotations

import ast
import inspect
import importlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Type


@dataclass
class ParameterInfo:
    """Information about a function/method parameter.

    Attributes:
        name: Parameter name
        type_hint: Type annotation if present
        default: Default value if present
        description: Parameter description from docstring
    """

    name: str
    type_hint: Optional[str] = None
    default: Optional[str] = None
    description: Optional[str] = None


@dataclass
class FunctionInfo:
    """Information about a function or method.

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
    """

    name: str
    signature: str = ""
    docstring: Optional[str] = None
    parameters: List[ParameterInfo] = field(default_factory=list)
    return_type: Optional[str] = None
    return_description: Optional[str] = None
    is_async: bool = False
    is_classmethod: bool = False
    is_staticmethod: bool = False
    is_property: bool = False
    decorators: List[str] = field(default_factory=list)
    raises: List[Tuple[str, str]] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)


@dataclass
class ClassInfo:
    """Information about a class.

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
    """

    name: str
    docstring: Optional[str] = None
    bases: List[str] = field(default_factory=list)
    methods: List[FunctionInfo] = field(default_factory=list)
    class_methods: List[FunctionInfo] = field(default_factory=list)
    static_methods: List[FunctionInfo] = field(default_factory=list)
    properties: List[FunctionInfo] = field(default_factory=list)
    attributes: List[Tuple[str, str, str]] = field(default_factory=list)
    is_dataclass: bool = False
    is_abstract: bool = False


@dataclass
class ModuleInfo:
    """Information about a module.

    Attributes:
        name: Module name
        path: File path
        docstring: Module docstring
        classes: List of class info
        functions: List of function info
        constants: List of module-level constants
        imports: List of import statements
        submodules: List of submodule names
    """

    name: str
    path: str
    docstring: Optional[str] = None
    classes: List[ClassInfo] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    constants: List[Tuple[str, str, Any]] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    submodules: List[str] = field(default_factory=list)


class DocstringParser:
    """Parse docstrings to extract structured information."""

    @staticmethod
    def parse(docstring: Optional[str]) -> Dict[str, Any]:
        """Parse a docstring into structured sections.

        Args:
            docstring: The docstring to parse

        Returns:
            Dictionary with sections like 'description', 'args', 'returns', etc.
        """
        if not docstring:
            return {"description": "", "args": {}, "returns": "", "raises": [], "examples": []}

        result = {
            "description": "",
            "args": {},
            "returns": "",
            "raises": [],
            "examples": [],
            "attributes": {},
            "notes": "",
        }

        lines = docstring.strip().split("\n")
        current_section = "description"
        current_content: List[str] = []
        current_item: Optional[str] = None

        section_markers = {
            "Args:": "args",
            "Arguments:": "args",
            "Parameters:": "args",
            "Params:": "args",
            "Returns:": "returns",
            "Return:": "returns",
            "Raises:": "raises",
            "Exceptions:": "raises",
            "Examples:": "examples",
            "Example:": "examples",
            "Attributes:": "attributes",
            "Notes:": "notes",
            "Note:": "notes",
        }

        for line in lines:
            stripped = line.strip()

            # Check for section marker
            if stripped in section_markers:
                # Save previous section content
                DocstringParser._save_section(
                    result, current_section, current_content, current_item
                )
                current_section = section_markers[stripped]
                current_content = []
                current_item = None
                continue

            # Handle section content
            if current_section in ("args", "attributes"):
                # Look for parameter/attribute definition
                match = re.match(r"^(\w+)(?:\s*\(([^)]+)\))?\s*:\s*(.*)$", stripped)
                if match:
                    # Save previous item
                    if current_item and current_content:
                        result[current_section][current_item] = " ".join(current_content).strip()
                    current_item = match.group(1)
                    current_content = [match.group(3)] if match.group(3) else []
                elif current_item:
                    current_content.append(stripped)
            elif current_section == "raises":
                match = re.match(r"^(\w+)(?:Error|Exception)?\s*:\s*(.*)$", stripped)
                if match:
                    result["raises"].append((match.group(1), match.group(2)))
                elif stripped:
                    current_content.append(stripped)
            elif current_section == "examples":
                current_content.append(line)  # Preserve indentation
            else:
                current_content.append(stripped)

        # Save final section
        DocstringParser._save_section(result, current_section, current_content, current_item)

        return result

    @staticmethod
    def _save_section(
        result: Dict[str, Any],
        section: str,
        content: List[str],
        item: Optional[str],
    ) -> None:
        """Save section content to result dictionary."""
        if section == "description":
            result["description"] = " ".join(content).strip()
        elif section in ("args", "attributes"):
            if item and content:
                result[section][item] = " ".join(content).strip()
        elif section == "returns":
            result["returns"] = " ".join(content).strip()
        elif section == "notes":
            result["notes"] = " ".join(content).strip()
        elif section == "examples":
            if content:
                result["examples"].append("\n".join(content))


class SourceAnalyzer:
    """Analyze Python source code to extract documentation info."""

    def __init__(self, source_path: str):
        """Initialize analyzer with source path.

        Args:
            source_path: Path to the Python source file
        """
        self.source_path = source_path
        self.source_code = ""
        self.tree: Optional[ast.Module] = None

    def analyze(self) -> ModuleInfo:
        """Analyze the source file and extract module info.

        Returns:
            ModuleInfo with all extracted information
        """
        with open(self.source_path, "r", encoding="utf-8") as f:
            self.source_code = f.read()

        self.tree = ast.parse(self.source_code)

        module_name = Path(self.source_path).stem
        module_docstring = ast.get_docstring(self.tree)

        info = ModuleInfo(
            name=module_name,
            path=self.source_path,
            docstring=module_docstring,
        )

        for node in ast.iter_child_nodes(self.tree):
            if isinstance(node, ast.ClassDef):
                info.classes.append(self._analyze_class(node))
            elif isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                info.functions.append(self._analyze_function(node))
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        value = self._get_node_value(node.value)
                        info.constants.append((target.id, type(value).__name__, value))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    info.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    info.imports.append(node.module)

        return info

    def _analyze_class(self, node: ast.ClassDef) -> ClassInfo:
        """Analyze a class definition node."""
        info = ClassInfo(
            name=node.name,
            docstring=ast.get_docstring(node),
            bases=[self._get_node_name(base) for base in node.bases],
        )

        # Check for decorators
        for decorator in node.decorator_list:
            dec_name = self._get_node_name(decorator)
            if dec_name == "dataclass":
                info.is_dataclass = True
            elif dec_name in ("abstractmethod", "ABC"):
                info.is_abstract = True

        # Analyze class body
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_info = self._analyze_function(item)

                if func_info.is_property:
                    info.properties.append(func_info)
                elif func_info.is_classmethod:
                    info.class_methods.append(func_info)
                elif func_info.is_staticmethod:
                    info.static_methods.append(func_info)
                else:
                    info.methods.append(func_info)

            elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                # Class attribute with type annotation
                attr_name = item.target.id
                attr_type = self._get_node_name(item.annotation) if item.annotation else ""
                attr_default = self._get_node_value(item.value) if item.value else None
                info.attributes.append((attr_name, attr_type, attr_default))

        return info

    def _analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionInfo:
        """Analyze a function/method definition node."""
        info = FunctionInfo(
            name=node.name,
            docstring=ast.get_docstring(node),
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )

        # Check decorators
        for decorator in node.decorator_list:
            dec_name = self._get_node_name(decorator)
            info.decorators.append(dec_name)
            if dec_name == "property":
                info.is_property = True
            elif dec_name == "classmethod":
                info.is_classmethod = True
            elif dec_name == "staticmethod":
                info.is_staticmethod = True

        # Get return type annotation
        if node.returns:
            info.return_type = self._get_node_name(node.returns)

        # Build signature and parameter info
        params = []
        args = node.args

        # Handle positional args
        num_defaults = len(args.defaults)
        num_args = len(args.args)

        for i, arg in enumerate(args.args):
            param = ParameterInfo(name=arg.arg)
            if arg.annotation:
                param.type_hint = self._get_node_name(arg.annotation)

            # Check for default value
            default_idx = i - (num_args - num_defaults)
            if default_idx >= 0:
                param.default = self._get_node_value(args.defaults[default_idx])

            params.append(param)
            info.parameters.append(param)

        # Handle *args
        if args.vararg:
            param = ParameterInfo(name=f"*{args.vararg.arg}")
            if args.vararg.annotation:
                param.type_hint = self._get_node_name(args.vararg.annotation)
            params.append(param)
            info.parameters.append(param)

        # Handle keyword-only args
        for i, arg in enumerate(args.kwonlyargs):
            param = ParameterInfo(name=arg.arg)
            if arg.annotation:
                param.type_hint = self._get_node_name(arg.annotation)
            if i < len(args.kw_defaults) and args.kw_defaults[i]:
                param.default = self._get_node_value(args.kw_defaults[i])
            params.append(param)
            info.parameters.append(param)

        # Handle **kwargs
        if args.kwarg:
            param = ParameterInfo(name=f"**{args.kwarg.arg}")
            if args.kwarg.annotation:
                param.type_hint = self._get_node_name(args.kwarg.annotation)
            params.append(param)
            info.parameters.append(param)

        # Build signature string
        param_strs = []
        for p in params:
            s = p.name
            if p.type_hint:
                s += f": {p.type_hint}"
            if p.default is not None:
                s += f" = {p.default}"
            param_strs.append(s)

        ret_annotation = f" -> {info.return_type}" if info.return_type else ""
        info.signature = f"({', '.join(param_strs)}){ret_annotation}"

        # Parse docstring for additional info
        if info.docstring:
            parsed = DocstringParser.parse(info.docstring)
            info.return_description = parsed.get("returns", "")
            info.raises = parsed.get("raises", [])
            info.examples = parsed.get("examples", [])

            # Add descriptions to parameters
            args_docs = parsed.get("args", {})
            for param in info.parameters:
                clean_name = param.name.lstrip("*")
                if clean_name in args_docs:
                    param.description = args_docs[clean_name]

        return info

    def _get_node_name(self, node: ast.expr) -> str:
        """Get string representation of an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_node_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Subscript):
            return f"{self._get_node_name(node.value)}[{self._get_node_name(node.slice)}]"
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Call):
            return self._get_node_name(node.func)
        elif isinstance(node, ast.Tuple):
            return f"({', '.join(self._get_node_name(e) for e in node.elts)})"
        elif isinstance(node, ast.List):
            return f"[{', '.join(self._get_node_name(e) for e in node.elts)}]"
        elif isinstance(node, ast.BinOp):
            return f"{self._get_node_name(node.left)} | {self._get_node_name(node.right)}"
        return ""

    def _get_node_value(self, node: Optional[ast.expr]) -> Any:
        """Get the value of a constant node."""
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.List):
            return [self._get_node_value(e) for e in node.elts]
        if isinstance(node, ast.Dict):
            return {
                self._get_node_value(k): self._get_node_value(v)
                for k, v in zip(node.keys, node.values)
            }
        if isinstance(node, ast.Call):
            return f"{self._get_node_name(node.func)}(...)"
        return repr(ast.dump(node))


class MarkdownWriter:
    """Write documentation in Markdown format."""

    def __init__(self, output_dir: str):
        """Initialize writer with output directory.

        Args:
            output_dir: Directory to write documentation files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_module(self, info: ModuleInfo, package_name: str = "") -> str:
        """Write module documentation to a Markdown file.

        Args:
            info: Module information to document
            package_name: Parent package name for full module path

        Returns:
            Path to the generated file
        """
        full_name = f"{package_name}.{info.name}" if package_name else info.name
        filename = full_name.replace(".", "_") + ".md"
        filepath = self.output_dir / filename

        lines = []

        # Module header
        lines.append(f"# {full_name}")
        lines.append("")

        if info.docstring:
            lines.append(info.docstring)
            lines.append("")

        # Table of contents
        if info.classes or info.functions:
            lines.append("## Contents")
            lines.append("")
            if info.classes:
                lines.append("### Classes")
                lines.append("")
                for cls in info.classes:
                    lines.append(f"- [{cls.name}](#{cls.name.lower()})")
                lines.append("")
            if info.functions:
                lines.append("### Functions")
                lines.append("")
                for func in info.functions:
                    if not func.name.startswith("_"):
                        lines.append(f"- [{func.name}](#{func.name.lower()})")
                lines.append("")

        # Constants
        if info.constants:
            lines.append("## Constants")
            lines.append("")
            for name, type_name, value in info.constants:
                lines.append(f"### `{name}`")
                lines.append("")
                lines.append(f"Type: `{type_name}`")
                lines.append("")
                lines.append(f"Value: `{value}`")
                lines.append("")

        # Classes
        for cls in info.classes:
            lines.extend(self._format_class(cls))

        # Functions
        for func in info.functions:
            if not func.name.startswith("_"):
                lines.extend(self._format_function(func, is_method=False))

        # Write file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(filepath)

    def _format_class(self, cls: ClassInfo) -> List[str]:
        """Format class documentation."""
        lines = []

        lines.append(f"## {cls.name}")
        lines.append("")

        # Inheritance
        if cls.bases:
            lines.append(f"**Inherits from:** {', '.join(cls.bases)}")
            lines.append("")

        # Tags
        tags = []
        if cls.is_dataclass:
            tags.append("dataclass")
        if cls.is_abstract:
            tags.append("abstract")
        if tags:
            lines.append(f"**Tags:** {', '.join(tags)}")
            lines.append("")

        if cls.docstring:
            lines.append(cls.docstring)
            lines.append("")

        # Attributes
        if cls.attributes:
            lines.append("### Attributes")
            lines.append("")
            lines.append("| Name | Type | Default |")
            lines.append("|------|------|---------|")
            for name, type_hint, default in cls.attributes:
                default_str = f"`{default}`" if default is not None else "-"
                lines.append(f"| `{name}` | `{type_hint}` | {default_str} |")
            lines.append("")

        # Properties
        if cls.properties:
            lines.append("### Properties")
            lines.append("")
            for prop in cls.properties:
                lines.extend(self._format_function(prop, is_method=True, header_level=4))

        # Methods
        public_methods = [m for m in cls.methods if not m.name.startswith("_") or m.name == "__init__"]
        if public_methods:
            lines.append("### Methods")
            lines.append("")
            for method in public_methods:
                lines.extend(self._format_function(method, is_method=True, header_level=4))

        # Class methods
        if cls.class_methods:
            lines.append("### Class Methods")
            lines.append("")
            for method in cls.class_methods:
                lines.extend(self._format_function(method, is_method=True, header_level=4))

        # Static methods
        if cls.static_methods:
            lines.append("### Static Methods")
            lines.append("")
            for method in cls.static_methods:
                lines.extend(self._format_function(method, is_method=True, header_level=4))

        return lines

    def _format_function(
        self, func: FunctionInfo, is_method: bool = False, header_level: int = 3
    ) -> List[str]:
        """Format function/method documentation."""
        lines = []

        header = "#" * header_level
        prefix = "async " if func.is_async else ""
        lines.append(f"{header} `{prefix}{func.name}{func.signature}`")
        lines.append("")

        # Decorators
        if func.decorators and func.decorators != ["property"]:
            lines.append(f"**Decorators:** {', '.join(f'@{d}' for d in func.decorators)}")
            lines.append("")

        # Docstring (first paragraph)
        if func.docstring:
            # Get just the description part
            parsed = DocstringParser.parse(func.docstring)
            if parsed["description"]:
                lines.append(parsed["description"])
                lines.append("")

        # Parameters
        params = [p for p in func.parameters if p.name != "self" and p.name != "cls"]
        if params:
            lines.append("**Parameters:**")
            lines.append("")
            for param in params:
                type_str = f" (`{param.type_hint}`)" if param.type_hint else ""
                default_str = f" - default: `{param.default}`" if param.default is not None else ""
                desc_str = f" - {param.description}" if param.description else ""
                lines.append(f"- `{param.name}`{type_str}{default_str}{desc_str}")
            lines.append("")

        # Returns
        if func.return_type or func.return_description:
            lines.append("**Returns:**")
            lines.append("")
            ret_type = f"`{func.return_type}`" if func.return_type else ""
            ret_desc = func.return_description or ""
            if ret_type and ret_desc:
                lines.append(f"{ret_type} - {ret_desc}")
            else:
                lines.append(ret_type or ret_desc)
            lines.append("")

        # Raises
        if func.raises:
            lines.append("**Raises:**")
            lines.append("")
            for exc_type, exc_desc in func.raises:
                lines.append(f"- `{exc_type}`: {exc_desc}")
            lines.append("")

        # Examples
        if func.examples:
            lines.append("**Examples:**")
            lines.append("")
            for example in func.examples:
                lines.append("```python")
                lines.append(example.strip())
                lines.append("```")
                lines.append("")

        return lines

    def write_index(self, modules: List[ModuleInfo], title: str = "API Reference") -> str:
        """Write an index file listing all modules.

        Args:
            modules: List of module info objects
            title: Title for the index page

        Returns:
            Path to the generated index file
        """
        filepath = self.output_dir / "index.md"

        lines = []
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # Group by package
        packages: Dict[str, List[ModuleInfo]] = {}
        for mod in modules:
            parts = mod.name.rsplit(".", 1)
            pkg = parts[0] if len(parts) > 1 else ""
            if pkg not in packages:
                packages[pkg] = []
            packages[pkg].append(mod)

        for pkg in sorted(packages.keys()):
            if pkg:
                lines.append(f"## {pkg}")
                lines.append("")
            else:
                lines.append("## Core")
                lines.append("")

            for mod in sorted(packages[pkg], key=lambda m: m.name):
                filename = mod.name.replace(".", "_") + ".md"
                desc = ""
                if mod.docstring:
                    # Get first line of docstring
                    first_line = mod.docstring.split("\n")[0].strip()
                    desc = f" - {first_line}"
                lines.append(f"- [{mod.name}]({filename}){desc}")
            lines.append("")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(filepath)


class APIReferenceGenerator:
    """Generate API reference documentation from Python source."""

    def __init__(self, source_dir: str, output_dir: str):
        """Initialize API reference generator.

        Args:
            source_dir: Directory containing Python source files
            output_dir: Directory to write documentation
        """
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.writer = MarkdownWriter(str(output_dir))
        self.modules: List[ModuleInfo] = []

    def generate(self, package_name: str = "stance") -> List[str]:
        """Generate API documentation for all modules.

        Args:
            package_name: Name of the package being documented

        Returns:
            List of generated file paths
        """
        generated = []

        # Find all Python files
        for py_file in sorted(self.source_dir.rglob("*.py")):
            if py_file.name.startswith("_") and py_file.name != "__init__.py":
                continue
            if "__pycache__" in str(py_file):
                continue

            try:
                analyzer = SourceAnalyzer(str(py_file))
                module_info = analyzer.analyze()

                # Build full module name from path
                rel_path = py_file.relative_to(self.source_dir)
                parts = list(rel_path.parts)
                if parts[-1] == "__init__.py":
                    parts = parts[:-1]
                else:
                    parts[-1] = parts[-1].replace(".py", "")

                full_name = ".".join([package_name] + list(parts)) if parts else package_name
                module_info.name = full_name

                self.modules.append(module_info)
                filepath = self.writer.write_module(module_info, "")
                generated.append(filepath)

            except SyntaxError as e:
                print(f"Syntax error in {py_file}: {e}")
            except Exception as e:
                print(f"Error analyzing {py_file}: {e}")

        # Generate index
        index_path = self.writer.write_index(self.modules)
        generated.append(index_path)

        return generated


class CLIReferenceGenerator:
    """Generate CLI command reference documentation."""

    def __init__(self, output_dir: str):
        """Initialize CLI reference generator.

        Args:
            output_dir: Directory to write documentation
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> str:
        """Generate CLI reference documentation.

        Returns:
            Path to generated file
        """
        filepath = self.output_dir / "cli-reference.md"

        lines = []
        lines.append("# CLI Reference")
        lines.append("")
        lines.append("Command-line interface reference for Mantissa Stance.")
        lines.append("")

        # Try to import and get CLI info
        try:
            from stance.cli import create_parser

            parser = create_parser()
            lines.extend(self._document_parser(parser))
        except ImportError:
            lines.append("*CLI module not available*")
        except Exception as e:
            lines.append(f"*Error generating CLI docs: {e}*")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(filepath)

    def _document_parser(self, parser, level: int = 2) -> List[str]:
        """Document an argument parser and its subparsers."""
        lines = []

        # Document main command
        if parser.description:
            lines.append(parser.description)
            lines.append("")

        # Document arguments
        for action in parser._actions:
            if action.dest == "help":
                continue
            if hasattr(action, "_parser_class"):
                # Subparser
                lines.append(f"{'#' * level} Subcommands")
                lines.append("")
                for name, subparser in action.choices.items():
                    lines.append(f"{'#' * (level + 1)} `stance {name}`")
                    lines.append("")
                    if subparser.description:
                        lines.append(subparser.description)
                        lines.append("")
                    lines.extend(self._document_arguments(subparser, level + 2))
            elif action.option_strings:
                # Optional argument - handled in _document_arguments
                pass

        # Document top-level arguments
        lines.extend(self._document_arguments(parser, level))

        return lines

    def _document_arguments(self, parser, level: int) -> List[str]:
        """Document arguments for a parser."""
        lines = []

        positional = []
        optional = []

        for action in parser._actions:
            if action.dest == "help":
                continue
            if action.option_strings:
                optional.append(action)
            elif action.dest != "subcommand":
                positional.append(action)

        if positional:
            lines.append(f"{'#' * level} Arguments")
            lines.append("")
            for action in positional:
                lines.append(f"**`{action.dest}`**")
                if action.help:
                    lines.append(f"  {action.help}")
                lines.append("")

        if optional:
            lines.append(f"{'#' * level} Options")
            lines.append("")
            for action in optional:
                opts = ", ".join(f"`{o}`" for o in action.option_strings)
                lines.append(f"**{opts}**")
                if action.help:
                    lines.append(f"  {action.help}")
                if action.default is not None and action.default != "==SUPPRESS==":
                    lines.append(f"  Default: `{action.default}`")
                lines.append("")

        return lines


class PolicyDocGenerator:
    """Generate documentation for policy files."""

    def __init__(self, policies_dir: str, output_dir: str):
        """Initialize policy documentation generator.

        Args:
            policies_dir: Directory containing policy YAML files
            output_dir: Directory to write documentation
        """
        self.policies_dir = Path(policies_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self) -> List[str]:
        """Generate policy documentation.

        Returns:
            List of generated file paths
        """
        generated = []

        # Find policy files
        policy_files = list(self.policies_dir.rglob("*.yaml")) + list(
            self.policies_dir.rglob("*.yml")
        )

        if not policy_files:
            return generated

        try:
            import yaml
        except ImportError:
            print("PyYAML not available, skipping policy documentation")
            return generated

        policies_by_provider: Dict[str, List[Dict]] = {}

        for policy_file in policy_files:
            try:
                with open(policy_file, "r", encoding="utf-8") as f:
                    policy = yaml.safe_load(f)
                    if policy:
                        provider = policy.get("resource_type", "").split("_")[0]
                        if provider not in policies_by_provider:
                            policies_by_provider[provider] = []
                        policy["_file"] = str(policy_file)
                        policies_by_provider[provider].append(policy)
            except Exception as e:
                print(f"Error loading policy {policy_file}: {e}")

        # Generate documentation for each provider
        for provider, policies in policies_by_provider.items():
            filepath = self._write_provider_policies(provider, policies)
            generated.append(filepath)

        # Generate index
        index_path = self._write_policy_index(policies_by_provider)
        generated.append(index_path)

        return generated

    def _write_provider_policies(self, provider: str, policies: List[Dict]) -> str:
        """Write policies for a specific provider."""
        filepath = self.output_dir / f"policies-{provider}.md"

        lines = []
        lines.append(f"# {provider.upper()} Policies")
        lines.append("")
        lines.append(f"Security policies for {provider.upper()} resources.")
        lines.append("")

        # Group by severity
        by_severity: Dict[str, List[Dict]] = {}
        for policy in policies:
            sev = policy.get("severity", "unknown")
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(policy)

        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in by_severity:
                lines.append(f"## {severity.title()} Severity")
                lines.append("")

                for policy in sorted(by_severity[severity], key=lambda p: p.get("id", "")):
                    lines.append(f"### {policy.get('id', 'unknown')}")
                    lines.append("")
                    lines.append(f"**Name:** {policy.get('name', 'Unknown')}")
                    lines.append("")
                    if policy.get("description"):
                        lines.append(policy["description"])
                        lines.append("")
                    lines.append(f"**Resource Type:** `{policy.get('resource_type', 'unknown')}`")
                    lines.append("")
                    if policy.get("compliance"):
                        lines.append("**Compliance:**")
                        for mapping in policy["compliance"]:
                            lines.append(
                                f"- {mapping.get('framework', 'unknown')} {mapping.get('control', '')}"
                            )
                        lines.append("")
                    if policy.get("remediation"):
                        lines.append("**Remediation:**")
                        lines.append(policy["remediation"].get("guidance", ""))
                        lines.append("")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(filepath)

    def _write_policy_index(self, policies_by_provider: Dict[str, List[Dict]]) -> str:
        """Write policy index page."""
        filepath = self.output_dir / "policies-index.md"

        lines = []
        lines.append("# Policy Reference")
        lines.append("")
        lines.append("Security policies for cloud resource scanning.")
        lines.append("")

        total = sum(len(p) for p in policies_by_provider.values())
        lines.append(f"**Total Policies:** {total}")
        lines.append("")

        lines.append("## By Cloud Provider")
        lines.append("")

        for provider in sorted(policies_by_provider.keys()):
            count = len(policies_by_provider[provider])
            lines.append(f"- [{provider.upper()}](policies-{provider}.md) ({count} policies)")

        lines.append("")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return str(filepath)


class DocumentationGenerator:
    """Main documentation generator for Mantissa Stance.

    This class coordinates generation of all documentation types:
    - API reference from source code docstrings
    - CLI command reference
    - Policy documentation
    """

    def __init__(
        self,
        source_dir: str = "src/stance",
        output_dir: str = "docs/generated",
        policies_dir: Optional[str] = "policies",
    ):
        """Initialize documentation generator.

        Args:
            source_dir: Directory containing Python source files
            output_dir: Base directory for generated documentation
            policies_dir: Directory containing policy YAML files (optional)
        """
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.policies_dir = Path(policies_dir) if policies_dir else None

        self.api_generator = APIReferenceGenerator(
            str(self.source_dir), str(self.output_dir / "api")
        )
        self.cli_generator = CLIReferenceGenerator(str(self.output_dir / "cli"))
        self.policy_generator = (
            PolicyDocGenerator(str(self.policies_dir), str(self.output_dir / "policies"))
            if self.policies_dir and self.policies_dir.exists()
            else None
        )

    def generate_all(self) -> Dict[str, List[str]]:
        """Generate all documentation.

        Returns:
            Dictionary mapping documentation type to list of generated files
        """
        result = {
            "api": [],
            "cli": [],
            "policies": [],
        }

        print(f"Generating API documentation from {self.source_dir}...")
        result["api"] = self.api_generator.generate()
        print(f"  Generated {len(result['api'])} API documentation files")

        print("Generating CLI reference...")
        result["cli"] = [self.cli_generator.generate()]
        print(f"  Generated CLI reference")

        if self.policy_generator:
            print(f"Generating policy documentation from {self.policies_dir}...")
            result["policies"] = self.policy_generator.generate()
            print(f"  Generated {len(result['policies'])} policy documentation files")

        return result

    def generate_api(self) -> List[str]:
        """Generate only API documentation.

        Returns:
            List of generated file paths
        """
        return self.api_generator.generate()

    def generate_cli(self) -> str:
        """Generate only CLI documentation.

        Returns:
            Path to generated file
        """
        return self.cli_generator.generate()

    def generate_policies(self) -> List[str]:
        """Generate only policy documentation.

        Returns:
            List of generated file paths
        """
        if self.policy_generator:
            return self.policy_generator.generate()
        return []
