"""
CLI commands for documentation management.

Provides commands for generating, viewing, and managing documentation
including API reference, CLI reference, and policy documentation.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def add_docs_parser(subparsers: Any) -> None:
    """Add docs subcommands to the CLI."""
    docs_parser = subparsers.add_parser(
        "docs",
        help="Documentation management commands",
        description="Generate and manage documentation for Mantissa Stance.",
    )

    docs_subparsers = docs_parser.add_subparsers(
        dest="docs_command",
        title="docs commands",
        description="Available documentation commands",
    )

    # Generate documentation
    generate_parser = docs_subparsers.add_parser(
        "generate",
        help="Generate documentation",
        description="Generate API, CLI, and policy documentation.",
    )
    generate_parser.add_argument(
        "--type",
        choices=["all", "api", "cli", "policies"],
        default="all",
        help="Type of documentation to generate (default: all)",
    )
    generate_parser.add_argument(
        "--source-dir",
        default="src/stance",
        help="Source directory for API docs (default: src/stance)",
    )
    generate_parser.add_argument(
        "--output-dir",
        default="docs/generated",
        help="Output directory (default: docs/generated)",
    )
    generate_parser.add_argument(
        "--policies-dir",
        default="policies",
        help="Policies directory (default: policies)",
    )
    generate_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )

    # List generated documentation
    list_parser = docs_subparsers.add_parser(
        "list",
        help="List generated documentation files",
        description="List all generated documentation files.",
    )
    list_parser.add_argument(
        "--output-dir",
        default="docs/generated",
        help="Documentation directory (default: docs/generated)",
    )
    list_parser.add_argument(
        "--type",
        choices=["all", "api", "cli", "policies"],
        default="all",
        help="Type of documentation to list (default: all)",
    )
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show documentation info
    info_parser = docs_subparsers.add_parser(
        "info",
        help="Show documentation information",
        description="Show information about documentation generators.",
    )
    info_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show module documentation
    module_parser = docs_subparsers.add_parser(
        "module",
        help="Show module documentation",
        description="Show documentation for a specific module.",
    )
    module_parser.add_argument(
        "module_name",
        help="Module name to document (e.g., stance.config)",
    )
    module_parser.add_argument(
        "--source-dir",
        default="src",
        help="Source directory (default: src)",
    )
    module_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show class documentation
    class_parser = docs_subparsers.add_parser(
        "class",
        help="Show class documentation",
        description="Show documentation for a specific class.",
    )
    class_parser.add_argument(
        "class_name",
        help="Class name to document (e.g., stance.config.ScanConfiguration)",
    )
    class_parser.add_argument(
        "--source-dir",
        default="src",
        help="Source directory (default: src)",
    )
    class_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show docstring parsers info
    parsers_parser = docs_subparsers.add_parser(
        "parsers",
        help="Show docstring parser information",
        description="Show information about docstring parsers.",
    )
    parsers_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show generator classes
    generators_parser = docs_subparsers.add_parser(
        "generators",
        help="Show documentation generators",
        description="List available documentation generator classes.",
    )
    generators_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show data classes
    dataclasses_parser = docs_subparsers.add_parser(
        "dataclasses",
        help="Show documentation data classes",
        description="List data classes used for documentation.",
    )
    dataclasses_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Documentation status
    status_parser = docs_subparsers.add_parser(
        "status",
        help="Show documentation module status",
        description="Show status of documentation module components.",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Documentation summary
    summary_parser = docs_subparsers.add_parser(
        "summary",
        help="Show comprehensive documentation summary",
        description="Show comprehensive summary of documentation capabilities.",
    )
    summary_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Validate documentation
    validate_parser = docs_subparsers.add_parser(
        "validate",
        help="Validate generated documentation",
        description="Validate generated documentation files.",
    )
    validate_parser.add_argument(
        "--output-dir",
        default="docs/generated",
        help="Documentation directory (default: docs/generated)",
    )
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Clean generated documentation
    clean_parser = docs_subparsers.add_parser(
        "clean",
        help="Clean generated documentation",
        description="Remove generated documentation files.",
    )
    clean_parser.add_argument(
        "--output-dir",
        default="docs/generated",
        help="Documentation directory (default: docs/generated)",
    )
    clean_parser.add_argument(
        "--force",
        action="store_true",
        help="Clean without confirmation",
    )
    clean_parser.add_argument(
        "--type",
        choices=["all", "api", "cli", "policies"],
        default="all",
        help="Type of documentation to clean (default: all)",
    )


def cmd_docs(args: argparse.Namespace) -> int:
    """Handle docs commands."""
    if not hasattr(args, "docs_command") or args.docs_command is None:
        print("Usage: stance docs <command> [options]")
        print("\nAvailable commands:")
        print("  generate    - Generate documentation")
        print("  list        - List generated documentation files")
        print("  info        - Show documentation information")
        print("  module      - Show module documentation")
        print("  class       - Show class documentation")
        print("  parsers     - Show docstring parser information")
        print("  generators  - Show documentation generators")
        print("  dataclasses - Show documentation data classes")
        print("  status      - Show documentation module status")
        print("  summary     - Show comprehensive documentation summary")
        print("  validate    - Validate generated documentation")
        print("  clean       - Clean generated documentation")
        print("\nUse 'stance docs <command> --help' for more information.")
        return 0

    handlers = {
        "generate": _handle_generate,
        "list": _handle_list,
        "info": _handle_info,
        "module": _handle_module,
        "class": _handle_class,
        "parsers": _handle_parsers,
        "generators": _handle_generators,
        "dataclasses": _handle_dataclasses,
        "status": _handle_status,
        "summary": _handle_summary,
        "validate": _handle_validate,
        "clean": _handle_clean,
    }

    handler = handlers.get(args.docs_command)
    if handler:
        return handler(args)

    print(f"Unknown docs command: {args.docs_command}")
    return 1


def _handle_generate(args: argparse.Namespace) -> int:
    """Handle generate command."""
    from stance.docs import DocumentationGenerator

    generator = DocumentationGenerator(
        source_dir=args.source_dir,
        output_dir=args.output_dir,
        policies_dir=args.policies_dir,
    )

    try:
        if args.type == "all":
            result = generator.generate_all()
        elif args.type == "api":
            result = {"api": generator.generate_api(), "cli": [], "policies": []}
        elif args.type == "cli":
            result = {"api": [], "cli": [generator.generate_cli()], "policies": []}
        elif args.type == "policies":
            result = {"api": [], "cli": [], "policies": generator.generate_policies()}
        else:
            result = {"api": [], "cli": [], "policies": []}

        total_files = sum(len(files) for files in result.values())

        if args.json:
            output = {
                "success": True,
                "type": args.type,
                "output_dir": args.output_dir,
                "files": result,
                "total_files": total_files,
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Documentation generated in {args.output_dir}")
            print()
            for doc_type, files in result.items():
                if files:
                    print(f"{doc_type.upper()} Documentation:")
                    for f in files:
                        print(f"  - {f}")
                    print()
            print(f"Total: {total_files} file(s) generated")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"success": False, "error": str(e)}))
        else:
            print(f"Error generating documentation: {e}")
        return 1


def _handle_list(args: argparse.Namespace) -> int:
    """Handle list command."""
    output_dir = Path(args.output_dir)

    if not output_dir.exists():
        if args.json:
            print(json.dumps({"files": [], "total": 0, "error": "Directory not found"}))
        else:
            print(f"Documentation directory not found: {args.output_dir}")
        return 1

    files = {
        "api": [],
        "cli": [],
        "policies": [],
    }

    # Find documentation files
    api_dir = output_dir / "api"
    cli_dir = output_dir / "cli"
    policies_dir = output_dir / "policies"

    if api_dir.exists() and args.type in ("all", "api"):
        files["api"] = [str(f.relative_to(output_dir)) for f in api_dir.glob("*.md")]

    if cli_dir.exists() and args.type in ("all", "cli"):
        files["cli"] = [str(f.relative_to(output_dir)) for f in cli_dir.glob("*.md")]

    if policies_dir.exists() and args.type in ("all", "policies"):
        files["policies"] = [str(f.relative_to(output_dir)) for f in policies_dir.glob("*.md")]

    total = sum(len(f) for f in files.values())

    if args.json:
        output = {
            "output_dir": str(output_dir),
            "files": files,
            "total": total,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Documentation files in {output_dir}:")
        print()
        for doc_type, file_list in files.items():
            if file_list:
                print(f"{doc_type.upper()} ({len(file_list)} files):")
                for f in sorted(file_list):
                    print(f"  - {f}")
                print()
        print(f"Total: {total} file(s)")

    return 0


def _handle_info(args: argparse.Namespace) -> int:
    """Handle info command."""
    info = {
        "module": "stance.docs",
        "description": "Documentation generation for Mantissa Stance",
        "capabilities": [
            "API reference generation from source code",
            "CLI command reference generation",
            "Policy documentation generation",
            "Docstring parsing (Google-style)",
            "AST-based source code analysis",
            "Markdown output format",
        ],
        "generators": {
            "DocumentationGenerator": "Main orchestrator for all documentation",
            "APIReferenceGenerator": "Generates API docs from Python source",
            "CLIReferenceGenerator": "Generates CLI command reference",
            "PolicyDocGenerator": "Generates policy documentation from YAML",
            "MarkdownWriter": "Writes Markdown formatted output",
        },
        "analyzers": {
            "SourceAnalyzer": "Analyzes Python source using AST",
            "DocstringParser": "Parses docstrings into structured data",
        },
        "data_classes": {
            "ModuleInfo": "Stores module-level information",
            "ClassInfo": "Stores class information",
            "FunctionInfo": "Stores function/method information",
            "ParameterInfo": "Stores parameter information",
        },
    }

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print("Documentation Module Information")
        print("=" * 50)
        print()
        print(f"Module: {info['module']}")
        print(f"Description: {info['description']}")
        print()
        print("Capabilities:")
        for cap in info["capabilities"]:
            print(f"  - {cap}")
        print()
        print("Generators:")
        for name, desc in info["generators"].items():
            print(f"  {name}: {desc}")
        print()
        print("Analyzers:")
        for name, desc in info["analyzers"].items():
            print(f"  {name}: {desc}")
        print()
        print("Data Classes:")
        for name, desc in info["data_classes"].items():
            print(f"  {name}: {desc}")

    return 0


def _handle_module(args: argparse.Namespace) -> int:
    """Handle module command."""
    from stance.docs import SourceAnalyzer

    # Convert module name to file path
    module_path = args.module_name.replace(".", os.sep) + ".py"
    full_path = os.path.join(args.source_dir, module_path)

    # Also try as package __init__.py
    init_path = os.path.join(args.source_dir, args.module_name.replace(".", os.sep), "__init__.py")

    if os.path.exists(full_path):
        source_path = full_path
    elif os.path.exists(init_path):
        source_path = init_path
    else:
        if args.json:
            print(json.dumps({"error": f"Module not found: {args.module_name}"}))
        else:
            print(f"Error: Module not found: {args.module_name}")
            print(f"  Tried: {full_path}")
            print(f"  Tried: {init_path}")
        return 1

    try:
        analyzer = SourceAnalyzer(source_path)
        module_info = analyzer.analyze()

        if args.json:
            output = {
                "name": args.module_name,
                "path": source_path,
                "docstring": module_info.docstring,
                "classes": [cls.name for cls in module_info.classes],
                "functions": [func.name for func in module_info.functions if not func.name.startswith("_")],
                "constants": [(name, type_name) for name, type_name, _ in module_info.constants],
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Module: {args.module_name}")
            print("=" * 50)
            print()
            if module_info.docstring:
                print("Description:")
                print(module_info.docstring)
                print()
            if module_info.classes:
                print("Classes:")
                for cls in module_info.classes:
                    bases = f" ({', '.join(cls.bases)})" if cls.bases else ""
                    print(f"  - {cls.name}{bases}")
                print()
            if module_info.functions:
                public_funcs = [f for f in module_info.functions if not f.name.startswith("_")]
                if public_funcs:
                    print("Functions:")
                    for func in public_funcs:
                        print(f"  - {func.name}{func.signature}")
                    print()
            if module_info.constants:
                print("Constants:")
                for name, type_name, value in module_info.constants:
                    print(f"  - {name}: {type_name} = {value}")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error analyzing module: {e}")
        return 1


def _handle_class(args: argparse.Namespace) -> int:
    """Handle class command."""
    from stance.docs import SourceAnalyzer

    # Parse class name to get module and class
    parts = args.class_name.rsplit(".", 1)
    if len(parts) != 2:
        if args.json:
            print(json.dumps({"error": "Class name must be fully qualified (e.g., stance.config.ScanConfiguration)"}))
        else:
            print("Error: Class name must be fully qualified (e.g., stance.config.ScanConfiguration)")
        return 1

    module_name, class_name = parts

    # Find the module file
    module_path = module_name.replace(".", os.sep) + ".py"
    full_path = os.path.join(args.source_dir, module_path)

    init_path = os.path.join(args.source_dir, module_name.replace(".", os.sep), "__init__.py")

    if os.path.exists(full_path):
        source_path = full_path
    elif os.path.exists(init_path):
        source_path = init_path
    else:
        if args.json:
            print(json.dumps({"error": f"Module not found: {module_name}"}))
        else:
            print(f"Error: Module not found: {module_name}")
        return 1

    try:
        analyzer = SourceAnalyzer(source_path)
        module_info = analyzer.analyze()

        # Find the class
        class_info = None
        for cls in module_info.classes:
            if cls.name == class_name:
                class_info = cls
                break

        if not class_info:
            if args.json:
                print(json.dumps({"error": f"Class not found: {class_name}"}))
            else:
                print(f"Error: Class '{class_name}' not found in module '{module_name}'")
            return 1

        if args.json:
            output = {
                "name": class_info.name,
                "module": module_name,
                "bases": class_info.bases,
                "docstring": class_info.docstring,
                "is_dataclass": class_info.is_dataclass,
                "is_abstract": class_info.is_abstract,
                "methods": [m.name for m in class_info.methods if not m.name.startswith("_") or m.name == "__init__"],
                "properties": [p.name for p in class_info.properties],
                "class_methods": [m.name for m in class_info.class_methods],
                "static_methods": [m.name for m in class_info.static_methods],
                "attributes": [(name, type_hint) for name, type_hint, _ in class_info.attributes],
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"Class: {args.class_name}")
            print("=" * 50)
            print()
            if class_info.bases:
                print(f"Inherits from: {', '.join(class_info.bases)}")
            if class_info.is_dataclass:
                print("Type: dataclass")
            if class_info.is_abstract:
                print("Type: abstract")
            print()
            if class_info.docstring:
                print("Description:")
                print(class_info.docstring)
                print()
            if class_info.attributes:
                print("Attributes:")
                for name, type_hint, default in class_info.attributes:
                    default_str = f" = {default}" if default else ""
                    print(f"  - {name}: {type_hint}{default_str}")
                print()
            if class_info.properties:
                print("Properties:")
                for prop in class_info.properties:
                    ret_type = f" -> {prop.return_type}" if prop.return_type else ""
                    print(f"  - {prop.name}{ret_type}")
                print()
            public_methods = [m for m in class_info.methods if not m.name.startswith("_") or m.name == "__init__"]
            if public_methods:
                print("Methods:")
                for method in public_methods:
                    print(f"  - {method.name}{method.signature}")
                print()
            if class_info.class_methods:
                print("Class Methods:")
                for method in class_info.class_methods:
                    print(f"  - {method.name}{method.signature}")
                print()
            if class_info.static_methods:
                print("Static Methods:")
                for method in class_info.static_methods:
                    print(f"  - {method.name}{method.signature}")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error analyzing class: {e}")
        return 1


def _handle_parsers(args: argparse.Namespace) -> int:
    """Handle parsers command."""
    parsers = {
        "DocstringParser": {
            "description": "Parses Python docstrings into structured sections",
            "supported_styles": ["Google-style docstrings"],
            "sections": [
                "description - Main description text",
                "Args/Arguments/Parameters - Parameter documentation",
                "Returns/Return - Return value documentation",
                "Raises/Exceptions - Exception documentation",
                "Examples/Example - Code examples",
                "Attributes - Class attribute documentation",
                "Notes/Note - Additional notes",
            ],
            "output": {
                "description": "str",
                "args": "dict[str, str]",
                "returns": "str",
                "raises": "list[tuple[str, str]]",
                "examples": "list[str]",
                "attributes": "dict[str, str]",
                "notes": "str",
            },
        },
    }

    if args.json:
        print(json.dumps(parsers, indent=2))
    else:
        print("Docstring Parsers")
        print("=" * 50)
        print()
        for name, info in parsers.items():
            print(f"{name}:")
            print(f"  Description: {info['description']}")
            print()
            print("  Supported Styles:")
            for style in info["supported_styles"]:
                print(f"    - {style}")
            print()
            print("  Supported Sections:")
            for section in info["sections"]:
                print(f"    - {section}")
            print()
            print("  Output Structure:")
            for key, type_name in info["output"].items():
                print(f"    {key}: {type_name}")

    return 0


def _handle_generators(args: argparse.Namespace) -> int:
    """Handle generators command."""
    generators = [
        {
            "name": "DocumentationGenerator",
            "description": "Main orchestrator for all documentation generation",
            "methods": ["generate_all", "generate_api", "generate_cli", "generate_policies"],
            "output_format": "Markdown",
        },
        {
            "name": "APIReferenceGenerator",
            "description": "Generates API reference documentation from Python source",
            "methods": ["generate"],
            "output_format": "Markdown",
        },
        {
            "name": "CLIReferenceGenerator",
            "description": "Generates CLI command reference from argparse",
            "methods": ["generate"],
            "output_format": "Markdown",
        },
        {
            "name": "PolicyDocGenerator",
            "description": "Generates policy documentation from YAML files",
            "methods": ["generate"],
            "output_format": "Markdown",
        },
        {
            "name": "MarkdownWriter",
            "description": "Writes documentation in Markdown format",
            "methods": ["write_module", "write_index"],
            "output_format": "Markdown",
        },
    ]

    if args.json:
        print(json.dumps({"generators": generators, "total": len(generators)}, indent=2))
    else:
        print("Documentation Generators")
        print("=" * 50)
        print()
        for gen in generators:
            print(f"{gen['name']}:")
            print(f"  Description: {gen['description']}")
            print(f"  Methods: {', '.join(gen['methods'])}")
            print(f"  Output Format: {gen['output_format']}")
            print()
        print(f"Total: {len(generators)} generator(s)")

    return 0


def _handle_dataclasses(args: argparse.Namespace) -> int:
    """Handle dataclasses command."""
    dataclasses = [
        {
            "name": "ParameterInfo",
            "description": "Information about a function/method parameter",
            "fields": [
                {"name": "name", "type": "str", "description": "Parameter name"},
                {"name": "type_hint", "type": "Optional[str]", "description": "Type annotation"},
                {"name": "default", "type": "Optional[str]", "description": "Default value"},
                {"name": "description", "type": "Optional[str]", "description": "Description from docstring"},
            ],
        },
        {
            "name": "FunctionInfo",
            "description": "Information about a function or method",
            "fields": [
                {"name": "name", "type": "str", "description": "Function name"},
                {"name": "signature", "type": "str", "description": "Full signature string"},
                {"name": "docstring", "type": "Optional[str]", "description": "Function docstring"},
                {"name": "parameters", "type": "List[ParameterInfo]", "description": "List of parameters"},
                {"name": "return_type", "type": "Optional[str]", "description": "Return type annotation"},
                {"name": "is_async", "type": "bool", "description": "Whether function is async"},
                {"name": "decorators", "type": "List[str]", "description": "List of decorators"},
            ],
        },
        {
            "name": "ClassInfo",
            "description": "Information about a class",
            "fields": [
                {"name": "name", "type": "str", "description": "Class name"},
                {"name": "docstring", "type": "Optional[str]", "description": "Class docstring"},
                {"name": "bases", "type": "List[str]", "description": "Base class names"},
                {"name": "methods", "type": "List[FunctionInfo]", "description": "Instance methods"},
                {"name": "properties", "type": "List[FunctionInfo]", "description": "Properties"},
                {"name": "is_dataclass", "type": "bool", "description": "Whether class is a dataclass"},
            ],
        },
        {
            "name": "ModuleInfo",
            "description": "Information about a module",
            "fields": [
                {"name": "name", "type": "str", "description": "Module name"},
                {"name": "path", "type": "str", "description": "File path"},
                {"name": "docstring", "type": "Optional[str]", "description": "Module docstring"},
                {"name": "classes", "type": "List[ClassInfo]", "description": "Module classes"},
                {"name": "functions", "type": "List[FunctionInfo]", "description": "Module functions"},
                {"name": "constants", "type": "List[Tuple]", "description": "Module constants"},
            ],
        },
    ]

    if args.json:
        print(json.dumps({"dataclasses": dataclasses, "total": len(dataclasses)}, indent=2))
    else:
        print("Documentation Data Classes")
        print("=" * 50)
        print()
        for dc in dataclasses:
            print(f"{dc['name']}:")
            print(f"  Description: {dc['description']}")
            print("  Fields:")
            for field in dc["fields"]:
                print(f"    - {field['name']}: {field['type']}")
                print(f"      {field['description']}")
            print()
        print(f"Total: {len(dataclasses)} data class(es)")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    from stance.docs import (
        DocumentationGenerator,
        APIReferenceGenerator,
        CLIReferenceGenerator,
        PolicyDocGenerator,
        MarkdownWriter,
        ModuleInfo,
        ClassInfo,
        FunctionInfo,
        ParameterInfo,
    )

    status = {
        "module": "docs",
        "components": {
            "DocumentationGenerator": DocumentationGenerator is not None,
            "APIReferenceGenerator": APIReferenceGenerator is not None,
            "CLIReferenceGenerator": CLIReferenceGenerator is not None,
            "PolicyDocGenerator": PolicyDocGenerator is not None,
            "MarkdownWriter": MarkdownWriter is not None,
        },
        "data_classes": {
            "ModuleInfo": ModuleInfo is not None,
            "ClassInfo": ClassInfo is not None,
            "FunctionInfo": FunctionInfo is not None,
            "ParameterInfo": ParameterInfo is not None,
        },
        "capabilities": [
            "api_reference",
            "cli_reference",
            "policy_documentation",
            "markdown_output",
            "ast_analysis",
            "docstring_parsing",
        ],
    }

    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print("Documentation Module Status")
        print("=" * 50)
        print()
        print("Module: docs")
        print()
        print("Components:")
        for name, available in status["components"].items():
            status_str = "Available" if available else "Not Available"
            print(f"  {name}: {status_str}")
        print()
        print("Data Classes:")
        for name, available in status["data_classes"].items():
            status_str = "Available" if available else "Not Available"
            print(f"  {name}: {status_str}")
        print()
        print("Capabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = {
        "overview": {
            "description": "Documentation generation system for Mantissa Stance",
            "purpose": "Generate API reference, CLI reference, and policy documentation",
            "output_format": "Markdown",
        },
        "features": [
            "Automatic API documentation from Python docstrings",
            "AST-based source code analysis",
            "Google-style docstring parsing",
            "CLI command reference generation from argparse",
            "Policy documentation from YAML files",
            "Markdown output with table of contents",
            "Class hierarchy and inheritance display",
            "Method signature extraction",
            "Parameter and return type documentation",
            "Example code block extraction",
        ],
        "architecture": {
            "main_class": "DocumentationGenerator",
            "generators": [
                "APIReferenceGenerator",
                "CLIReferenceGenerator",
                "PolicyDocGenerator",
            ],
            "analyzers": [
                "SourceAnalyzer",
                "DocstringParser",
            ],
            "writers": [
                "MarkdownWriter",
            ],
        },
        "usage": {
            "generate_all": "generator.generate_all()",
            "generate_api": "generator.generate_api()",
            "generate_cli": "generator.generate_cli()",
            "generate_policies": "generator.generate_policies()",
        },
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("Documentation Module Summary")
        print("=" * 50)
        print()
        print("Overview:")
        for key, value in summary["overview"].items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        print()
        print("Features:")
        for feature in summary["features"]:
            print(f"  - {feature}")
        print()
        print("Architecture:")
        print(f"  Main Class: {summary['architecture']['main_class']}")
        print("  Generators:")
        for gen in summary["architecture"]["generators"]:
            print(f"    - {gen}")
        print("  Analyzers:")
        for ana in summary["architecture"]["analyzers"]:
            print(f"    - {ana}")
        print("  Writers:")
        for wri in summary["architecture"]["writers"]:
            print(f"    - {wri}")
        print()
        print("Usage Examples:")
        for method, example in summary["usage"].items():
            print(f"  {method}: {example}")

    return 0


def _handle_validate(args: argparse.Namespace) -> int:
    """Handle validate command."""
    output_dir = Path(args.output_dir)

    if not output_dir.exists():
        if args.json:
            print(json.dumps({"valid": False, "error": "Directory not found"}))
        else:
            print(f"Error: Documentation directory not found: {args.output_dir}")
        return 1

    errors = []
    warnings = []
    files_checked = 0

    # Check for expected directories
    for subdir in ["api", "cli", "policies"]:
        subdir_path = output_dir / subdir
        if not subdir_path.exists():
            warnings.append(f"Missing {subdir} directory")

    # Check markdown files
    for md_file in output_dir.rglob("*.md"):
        files_checked += 1
        try:
            with open(md_file, "r", encoding="utf-8") as f:
                content = f.read()
                if not content.strip():
                    errors.append(f"Empty file: {md_file.relative_to(output_dir)}")
                if not content.startswith("#"):
                    warnings.append(f"Missing header: {md_file.relative_to(output_dir)}")
        except Exception as e:
            errors.append(f"Error reading {md_file.relative_to(output_dir)}: {e}")

    is_valid = len(errors) == 0

    if args.json:
        result = {
            "valid": is_valid,
            "output_dir": str(output_dir),
            "files_checked": files_checked,
            "errors": errors,
            "warnings": warnings,
        }
        print(json.dumps(result, indent=2))
    else:
        if is_valid:
            print(f"Documentation is VALID")
            print(f"Checked {files_checked} file(s) in {output_dir}")
            if warnings:
                print("\nWarnings:")
                for w in warnings:
                    print(f"  - {w}")
        else:
            print(f"Documentation is INVALID")
            print(f"Checked {files_checked} file(s) in {output_dir}")
            print("\nErrors:")
            for e in errors:
                print(f"  - {e}")
            if warnings:
                print("\nWarnings:")
                for w in warnings:
                    print(f"  - {w}")

    return 0 if is_valid else 1


def _handle_clean(args: argparse.Namespace) -> int:
    """Handle clean command."""
    import shutil

    output_dir = Path(args.output_dir)

    if not output_dir.exists():
        print(f"Documentation directory not found: {args.output_dir}")
        return 0

    dirs_to_clean = []
    if args.type == "all":
        dirs_to_clean = [output_dir]
    else:
        subdir = output_dir / args.type
        if subdir.exists():
            dirs_to_clean = [subdir]

    if not dirs_to_clean:
        print("No directories to clean.")
        return 0

    if not args.force:
        dir_names = ", ".join(str(d) for d in dirs_to_clean)
        response = input(f"Clean {dir_names}? [y/N]: ")
        if response.lower() != "y":
            print("Cancelled.")
            return 0

    files_removed = 0
    for dir_path in dirs_to_clean:
        if args.type == "all":
            # Remove all generated content
            for subdir in ["api", "cli", "policies"]:
                subdir_path = dir_path / subdir
                if subdir_path.exists():
                    for f in subdir_path.glob("*.md"):
                        f.unlink()
                        files_removed += 1
        else:
            for f in dir_path.glob("*.md"):
                f.unlink()
                files_removed += 1

    print(f"Cleaned {files_removed} file(s)")
    return 0
