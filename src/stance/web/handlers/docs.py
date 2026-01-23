"""
Documentation handlers for the Stance web API.

This module handles all /api/docs/* endpoints for documentation
generation and management.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


def _validate_module_name(module_name: str) -> str:
    """
    Validate a Python module name to prevent path traversal.

    Args:
        module_name: The module name to validate (e.g., "stance.scanner.trivy")

    Returns:
        The validated module name

    Raises:
        ValueError: If module name contains invalid characters
    """
    if not module_name:
        raise ValueError("Module name cannot be empty")

    # Module names should only contain alphanumeric, underscores, and dots
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$", module_name):
        raise ValueError(
            f"Invalid module name: {module_name!r}. "
            "Module names must be valid Python identifiers separated by dots."
        )

    # Block any path traversal attempts
    if ".." in module_name or module_name.startswith("."):
        raise ValueError(f"Invalid module name: path traversal not allowed: {module_name}")

    return module_name


def _validate_path_within_base(path: str, base_dir: str, context: str = "path") -> Path:
    """
    Validate that a path is within the base directory.

    Args:
        path: The path to validate
        base_dir: The base directory that path must be within
        context: Description of the path for error messages

    Returns:
        The resolved, validated Path object

    Raises:
        ValueError: If path escapes the base directory
    """
    # Resolve both paths to absolute, following symlinks
    base_resolved = Path(base_dir).resolve()
    path_resolved = Path(path).resolve()

    # Check if path is within base directory
    try:
        path_resolved.relative_to(base_resolved)
    except ValueError:
        raise ValueError(
            f"Invalid {context}: path escapes base directory. "
            f"Path must be within {base_resolved}"
        )

    return path_resolved


def _validate_safe_directory(directory: str, context: str = "directory") -> Path:
    """
    Validate that a directory path is safe for use.

    Args:
        directory: The directory path to validate
        context: Description of the path for error messages

    Returns:
        The validated Path object

    Raises:
        ValueError: If path contains dangerous characters or traversal
    """
    if not directory:
        raise ValueError(f"{context} cannot be empty")

    # Block path traversal
    if ".." in directory:
        raise ValueError(f"Invalid {context}: path traversal not allowed")

    # Block absolute paths to system directories
    path = Path(directory)
    if path.is_absolute():
        # Only allow specific safe absolute paths
        safe_prefixes = ["/tmp/", "/var/tmp/"]
        home = os.path.expanduser("~")
        safe_prefixes.append(home)

        path_str = str(path)
        if not any(path_str.startswith(prefix) for prefix in safe_prefixes):
            raise ValueError(
                f"Invalid {context}: absolute paths must be under home directory or /tmp"
            )

    # Block shell metacharacters
    dangerous_chars = ["|", ";", "&", "$", "`", "(", ")", "{", "}", "[", "]", "<", ">", "\\", "'", '"']
    for char in dangerous_chars:
        if char in directory:
            raise ValueError(f"Invalid {context}: contains forbidden character '{char}'")

    return path


class DocsHandler(RoutedHandler):
    """
    Handler for documentation API endpoints.

    Handles:
    - Documentation module information
    - Documentation generation
    - Module/class documentation lookup
    - Documentation validation
    """

    base_path = "/api/docs/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("info")
    def docs_info(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get documentation module information."""
        return HandlerResponse.success({
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
        })

    @route("generators")
    def docs_generators(self, params: dict, body: dict | None) -> HandlerResponse:
        """List documentation generators."""
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
        return HandlerResponse.success({"generators": generators, "total": len(generators)})

    @route("dataclasses")
    def docs_dataclasses(self, params: dict, body: dict | None) -> HandlerResponse:
        """List documentation data classes."""
        dataclasses = [
            {
                "name": "ParameterInfo",
                "description": "Information about a function/method parameter",
                "fields": ["name", "type_hint", "default", "description"],
            },
            {
                "name": "FunctionInfo",
                "description": "Information about a function or method",
                "fields": ["name", "signature", "docstring", "parameters", "return_type", "is_async", "decorators"],
            },
            {
                "name": "ClassInfo",
                "description": "Information about a class",
                "fields": ["name", "docstring", "bases", "methods", "properties", "is_dataclass"],
            },
            {
                "name": "ModuleInfo",
                "description": "Information about a module",
                "fields": ["name", "path", "docstring", "classes", "functions", "constants"],
            },
        ]
        return HandlerResponse.success({"dataclasses": dataclasses, "total": len(dataclasses)})

    @route("parsers")
    def docs_parsers(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get docstring parser information."""
        return HandlerResponse.success({
            "parsers": {
                "DocstringParser": {
                    "description": "Parses Python docstrings into structured sections",
                    "supported_styles": ["Google-style docstrings"],
                    "sections": [
                        "description",
                        "Args/Arguments/Parameters",
                        "Returns/Return",
                        "Raises/Exceptions",
                        "Examples/Example",
                        "Attributes",
                        "Notes/Note",
                    ],
                },
            },
        })

    @route("status")
    def docs_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get documentation module status."""
        try:
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

            return HandlerResponse.success({
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
            })
        except ImportError as e:
            return HandlerResponse.success({"module": "docs", "status": "error", "error": str(e)})

    @route("summary")
    def docs_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive docs module summary."""
        return HandlerResponse.success({
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
                "generators": ["APIReferenceGenerator", "CLIReferenceGenerator", "PolicyDocGenerator"],
                "analyzers": ["SourceAnalyzer", "DocstringParser"],
                "writers": ["MarkdownWriter"],
            },
        })

    @route("list")
    def docs_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List generated documentation files."""
        output_dir = self.get_param(params, "output_dir", "docs/generated")
        doc_type = self.get_param(params, "type", "all")

        output_path = Path(output_dir)
        files: dict[str, list[str]] = {"api": [], "cli": [], "policies": []}

        if output_path.exists():
            api_dir = output_path / "api"
            cli_dir = output_path / "cli"
            policies_dir = output_path / "policies"

            if api_dir.exists() and doc_type in ("all", "api"):
                files["api"] = [str(f.relative_to(output_path)) for f in api_dir.glob("*.md")]

            if cli_dir.exists() and doc_type in ("all", "cli"):
                files["cli"] = [str(f.relative_to(output_path)) for f in cli_dir.glob("*.md")]

            if policies_dir.exists() and doc_type in ("all", "policies"):
                files["policies"] = [str(f.relative_to(output_path)) for f in policies_dir.glob("*.md")]

        total = sum(len(f) for f in files.values())
        return HandlerResponse.success({"output_dir": output_dir, "files": files, "total": total})

    @route("module")
    def docs_module(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get module documentation."""
        try:
            from stance.docs import SourceAnalyzer

            module_name = self.get_param(params, "module", "")
            if not module_name:
                return HandlerResponse.error("Missing required parameter: module", HttpStatus.BAD_REQUEST)

            # Validate module name to prevent path traversal
            try:
                validated_module = _validate_module_name(module_name)
            except ValueError as e:
                return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

            source_dir = self.get_param(params, "source_dir", "src")

            module_path = validated_module.replace(".", os.sep) + ".py"
            full_path = os.path.join(source_dir, module_path)
            init_path = os.path.join(source_dir, validated_module.replace(".", os.sep), "__init__.py")

            # Validate paths are within source directory
            try:
                _validate_path_within_base(full_path, source_dir, "module path")
                _validate_path_within_base(init_path, source_dir, "module path")
            except ValueError as e:
                return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

            if os.path.exists(full_path):
                source_path = full_path
            elif os.path.exists(init_path):
                source_path = init_path
            else:
                return HandlerResponse.not_found(f"Module: {validated_module}")

            analyzer = SourceAnalyzer(source_path)
            module_info = analyzer.analyze()

            return HandlerResponse.success({
                "name": validated_module,
                "path": source_path,
                "docstring": module_info.docstring,
                "classes": [cls.name for cls in module_info.classes],
                "functions": [func.name for func in module_info.functions if not func.name.startswith("_")],
                "constants": [(name, type_name) for name, type_name, _ in module_info.constants],
            })
        except ImportError as e:
            return HandlerResponse.error(f"Docs module not available: {e}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("class")
    def docs_class(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get class documentation."""
        try:
            from stance.docs import SourceAnalyzer

            class_name = self.get_param(params, "class", "")
            if not class_name:
                return HandlerResponse.error("Missing required parameter: class", HttpStatus.BAD_REQUEST)

            source_dir = self.get_param(params, "source_dir", "src")

            parts = class_name.rsplit(".", 1)
            if len(parts) != 2:
                return HandlerResponse.error(
                    "Class name must be fully qualified (e.g., stance.config.ScanConfiguration)",
                    HttpStatus.BAD_REQUEST
                )

            module_name, cls_name = parts

            # Validate module name to prevent path traversal
            try:
                validated_module = _validate_module_name(module_name)
            except ValueError as e:
                return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

            # Validate class name is a valid Python identifier
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", cls_name):
                return HandlerResponse.error(f"Invalid class name: {cls_name}", HttpStatus.BAD_REQUEST)

            module_path = validated_module.replace(".", os.sep) + ".py"
            full_path = os.path.join(source_dir, module_path)
            init_path = os.path.join(source_dir, validated_module.replace(".", os.sep), "__init__.py")

            # Validate paths are within source directory
            try:
                _validate_path_within_base(full_path, source_dir, "module path")
                _validate_path_within_base(init_path, source_dir, "module path")
            except ValueError as e:
                return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

            if os.path.exists(full_path):
                source_path = full_path
            elif os.path.exists(init_path):
                source_path = init_path
            else:
                return HandlerResponse.not_found(f"Module: {validated_module}")

            analyzer = SourceAnalyzer(source_path)
            module_info = analyzer.analyze()

            class_info = None
            for cls in module_info.classes:
                if cls.name == cls_name:
                    class_info = cls
                    break

            if not class_info:
                return HandlerResponse.not_found(f"Class: {cls_name}")

            return HandlerResponse.success({
                "name": class_info.name,
                "module": validated_module,
                "bases": class_info.bases,
                "docstring": class_info.docstring,
                "is_dataclass": class_info.is_dataclass,
                "is_abstract": class_info.is_abstract,
                "methods": [m.name for m in class_info.methods if not m.name.startswith("_") or m.name == "__init__"],
                "properties": [p.name for p in class_info.properties],
                "class_methods": [m.name for m in class_info.class_methods],
                "static_methods": [m.name for m in class_info.static_methods],
            })
        except ImportError as e:
            return HandlerResponse.error(f"Docs module not available: {e}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    # =========================================================================
    # POST endpoints
    # =========================================================================

    @route("generate", methods=["POST"])
    def docs_generate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate documentation."""
        try:
            from stance.docs import DocumentationGenerator

            data = body or {}

            source_dir = data.get("source_dir", "src/stance")
            output_dir = data.get("output_dir", "docs/generated")
            policies_dir = data.get("policies_dir", "policies")
            doc_type = data.get("type", "all")

            # Validate directories to prevent path traversal
            try:
                _validate_safe_directory(source_dir, "source_dir")
                _validate_safe_directory(output_dir, "output_dir")
                _validate_safe_directory(policies_dir, "policies_dir")
            except ValueError as e:
                return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

            # Validate doc_type
            if doc_type not in ("all", "api", "cli", "policies"):
                return HandlerResponse.error(
                    f"Invalid type: {doc_type}. Must be one of: all, api, cli, policies",
                    HttpStatus.BAD_REQUEST
                )

            generator = DocumentationGenerator(
                source_dir=source_dir,
                output_dir=output_dir,
                policies_dir=policies_dir,
            )

            if doc_type == "all":
                result = generator.generate_all()
            elif doc_type == "api":
                result = {"api": generator.generate_api(), "cli": [], "policies": []}
            elif doc_type == "cli":
                result = {"api": [], "cli": [generator.generate_cli()], "policies": []}
            elif doc_type == "policies":
                result = {"api": [], "cli": [], "policies": generator.generate_policies()}
            else:
                result = {"api": [], "cli": [], "policies": []}

            total_files = sum(len(files) for files in result.values())

            return HandlerResponse.success({
                "success": True,
                "type": doc_type,
                "output_dir": output_dir,
                "files": result,
                "total_files": total_files,
            })
        except ImportError as e:
            return HandlerResponse.error(f"Docs module not available: {e}")
        except Exception as e:
            return HandlerResponse.success({"success": False, "error": str(e)})

    @route("validate", methods=["POST"])
    def docs_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate generated documentation."""
        data = body or {}
        output_dir_str = data.get("output_dir", "docs/generated")

        # Validate directory path
        try:
            _validate_safe_directory(output_dir_str, "output_dir")
        except ValueError as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

        output_dir = Path(output_dir_str)

        if not output_dir.exists():
            return HandlerResponse.success({"valid": False, "error": "Directory not found"})

        errors: list[str] = []
        warnings: list[str] = []
        files_checked = 0

        for subdir in ["api", "cli", "policies"]:
            subdir_path = output_dir / subdir
            if not subdir_path.exists():
                warnings.append(f"Missing {subdir} directory")

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

        return HandlerResponse.success({
            "valid": len(errors) == 0,
            "output_dir": str(output_dir),
            "files_checked": files_checked,
            "errors": errors,
            "warnings": warnings,
        })

    @route("clean", methods=["POST"])
    def docs_clean(self, params: dict, body: dict | None) -> HandlerResponse:
        """Clean generated documentation."""
        data = body or {}
        output_dir_str = data.get("output_dir", "docs/generated")
        doc_type = data.get("type", "all")

        # Validate directory path
        try:
            _validate_safe_directory(output_dir_str, "output_dir")
        except ValueError as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

        # Validate doc_type to prevent directory traversal via type
        if doc_type not in ("all", "api", "cli", "policies"):
            return HandlerResponse.error(
                f"Invalid type: {doc_type}. Must be one of: all, api, cli, policies",
                HttpStatus.BAD_REQUEST
            )

        output_dir = Path(output_dir_str)

        if not output_dir.exists():
            return HandlerResponse.success({"success": True, "files_removed": 0, "message": "Directory not found"})

        files_removed = 0

        if doc_type == "all":
            for subdir in ["api", "cli", "policies"]:
                subdir_path = output_dir / subdir
                if subdir_path.exists():
                    for f in subdir_path.glob("*.md"):
                        f.unlink()
                        files_removed += 1
        else:
            subdir_path = output_dir / doc_type
            if subdir_path.exists():
                for f in subdir_path.glob("*.md"):
                    f.unlink()
                    files_removed += 1

        return HandlerResponse.success({
            "success": True,
            "output_dir": str(output_dir),
            "type": doc_type,
            "files_removed": files_removed,
        })
