"""
Documentation generation for Mantissa Stance.

This module provides tools for generating API reference documentation,
CLI command documentation, and policy documentation from the codebase.

Key Components:
- DocumentationGenerator: Main class for generating all documentation
- APIReferenceGenerator: Generates API reference from docstrings
- CLIReferenceGenerator: Generates CLI command reference
- PolicyDocGenerator: Generates policy documentation
- MarkdownWriter: Writes documentation in Markdown format

Example:
    from stance.docs import DocumentationGenerator

    generator = DocumentationGenerator(output_dir="docs/api")
    generator.generate_all()
"""

from stance.docs.generator import (
    DocumentationGenerator,
    APIReferenceGenerator,
    CLIReferenceGenerator,
    PolicyDocGenerator,
    MarkdownWriter,
    ModuleInfo,
    ClassInfo,
    FunctionInfo,
    ParameterInfo,
    SourceAnalyzer,
)

__all__ = [
    "DocumentationGenerator",
    "APIReferenceGenerator",
    "CLIReferenceGenerator",
    "PolicyDocGenerator",
    "MarkdownWriter",
    "ModuleInfo",
    "ClassInfo",
    "FunctionInfo",
    "ParameterInfo",
    "SourceAnalyzer",
]
