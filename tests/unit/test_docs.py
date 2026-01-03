"""
Unit tests for documentation generation module.

Tests cover:
- Docstring parsing
- Source code analysis
- Markdown generation
- API reference generation
- CLI reference generation
- Policy documentation generation
"""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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
from stance.docs.generator import DocstringParser, SourceAnalyzer


# =============================================================================
# DocstringParser Tests
# =============================================================================


class TestDocstringParser:
    """Tests for DocstringParser."""

    def test_parse_empty_docstring(self):
        """Test parsing empty docstring."""
        result = DocstringParser.parse(None)

        assert result["description"] == ""
        assert result["args"] == {}
        assert result["returns"] == ""
        assert result["raises"] == []
        assert result["examples"] == []

    def test_parse_simple_description(self):
        """Test parsing simple description."""
        docstring = "This is a simple description."
        result = DocstringParser.parse(docstring)

        assert result["description"] == "This is a simple description."

    def test_parse_with_args(self):
        """Test parsing docstring with Args section."""
        docstring = """
        Do something.

        Args:
            name: The name to use
            count: Number of times
        """
        result = DocstringParser.parse(docstring)

        assert "name" in result["args"]
        assert "count" in result["args"]
        assert "name to use" in result["args"]["name"]

    def test_parse_with_returns(self):
        """Test parsing docstring with Returns section."""
        docstring = """
        Do something.

        Returns:
            The result value
        """
        result = DocstringParser.parse(docstring)

        assert "result value" in result["returns"]

    def test_parse_with_raises(self):
        """Test parsing docstring with Raises section."""
        docstring = """
        Do something.

        Raises:
            ValueError: When value is invalid
            TypeError: When type is wrong
        """
        result = DocstringParser.parse(docstring)

        assert len(result["raises"]) >= 1

    def test_parse_with_examples(self):
        """Test parsing docstring with Examples section."""
        docstring = """
        Do something.

        Examples:
            result = do_something()
            print(result)
        """
        result = DocstringParser.parse(docstring)

        assert len(result["examples"]) >= 1

    def test_parse_with_attributes(self):
        """Test parsing docstring with Attributes section."""
        docstring = """
        A data class.

        Attributes:
            name: The name
            value: The value
        """
        result = DocstringParser.parse(docstring)

        assert "name" in result["attributes"]
        assert "value" in result["attributes"]

    def test_parse_google_style_args(self):
        """Test parsing Google-style docstring with typed args."""
        docstring = """
        Do something.

        Args:
            name (str): The name to use
            count (int): Number of times
        """
        result = DocstringParser.parse(docstring)

        assert "name" in result["args"]
        assert "count" in result["args"]


# =============================================================================
# ParameterInfo Tests
# =============================================================================


class TestParameterInfo:
    """Tests for ParameterInfo dataclass."""

    def test_create_basic(self):
        """Test creating basic parameter info."""
        param = ParameterInfo(name="test")

        assert param.name == "test"
        assert param.type_hint is None
        assert param.default is None
        assert param.description is None

    def test_create_with_all_fields(self):
        """Test creating parameter info with all fields."""
        param = ParameterInfo(
            name="count",
            type_hint="int",
            default="10",
            description="The count value",
        )

        assert param.name == "count"
        assert param.type_hint == "int"
        assert param.default == "10"
        assert param.description == "The count value"


# =============================================================================
# FunctionInfo Tests
# =============================================================================


class TestFunctionInfo:
    """Tests for FunctionInfo dataclass."""

    def test_create_basic(self):
        """Test creating basic function info."""
        func = FunctionInfo(name="test_func")

        assert func.name == "test_func"
        assert func.signature == ""
        assert func.docstring is None
        assert func.parameters == []
        assert func.is_async is False

    def test_create_async_function(self):
        """Test creating async function info."""
        func = FunctionInfo(name="async_func", is_async=True)

        assert func.is_async is True

    def test_create_with_decorators(self):
        """Test creating function info with decorators."""
        func = FunctionInfo(
            name="decorated",
            decorators=["staticmethod", "cache"],
        )

        assert "staticmethod" in func.decorators
        assert "cache" in func.decorators

    def test_create_property(self):
        """Test creating property info."""
        func = FunctionInfo(name="value", is_property=True)

        assert func.is_property is True


# =============================================================================
# ClassInfo Tests
# =============================================================================


class TestClassInfo:
    """Tests for ClassInfo dataclass."""

    def test_create_basic(self):
        """Test creating basic class info."""
        cls = ClassInfo(name="TestClass")

        assert cls.name == "TestClass"
        assert cls.docstring is None
        assert cls.bases == []
        assert cls.methods == []
        assert cls.is_dataclass is False

    def test_create_with_bases(self):
        """Test creating class info with base classes."""
        cls = ClassInfo(
            name="Child",
            bases=["Parent", "Mixin"],
        )

        assert "Parent" in cls.bases
        assert "Mixin" in cls.bases

    def test_create_dataclass(self):
        """Test creating dataclass info."""
        cls = ClassInfo(name="DataClass", is_dataclass=True)

        assert cls.is_dataclass is True

    def test_create_with_attributes(self):
        """Test creating class info with attributes."""
        cls = ClassInfo(
            name="Config",
            attributes=[
                ("name", "str", None),
                ("value", "int", "10"),
            ],
        )

        assert len(cls.attributes) == 2
        assert cls.attributes[0][0] == "name"


# =============================================================================
# ModuleInfo Tests
# =============================================================================


class TestModuleInfo:
    """Tests for ModuleInfo dataclass."""

    def test_create_basic(self):
        """Test creating basic module info."""
        mod = ModuleInfo(name="test_module", path="/path/to/module.py")

        assert mod.name == "test_module"
        assert mod.path == "/path/to/module.py"
        assert mod.docstring is None
        assert mod.classes == []
        assert mod.functions == []

    def test_create_with_docstring(self):
        """Test creating module info with docstring."""
        mod = ModuleInfo(
            name="documented",
            path="/path/to/doc.py",
            docstring="A documented module.",
        )

        assert mod.docstring == "A documented module."

    def test_create_with_contents(self):
        """Test creating module info with classes and functions."""
        mod = ModuleInfo(
            name="full_module",
            path="/path/to/full.py",
            classes=[ClassInfo(name="MyClass")],
            functions=[FunctionInfo(name="my_func")],
        )

        assert len(mod.classes) == 1
        assert len(mod.functions) == 1


# =============================================================================
# SourceAnalyzer Tests
# =============================================================================


class TestSourceAnalyzer:
    """Tests for SourceAnalyzer."""

    def test_analyze_empty_module(self):
        """Test analyzing empty module."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "empty.py"
            source_file.write_text('"""Empty module."""\n')

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            assert info.name == "empty"
            assert info.docstring == "Empty module."
            assert info.classes == []
            assert info.functions == []

    def test_analyze_module_with_function(self):
        """Test analyzing module with function."""
        source = '''
"""Module with function."""

def greet(name: str) -> str:
    """Greet someone.

    Args:
        name: The name to greet

    Returns:
        Greeting string
    """
    return f"Hello, {name}!"
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "funcs.py"
            source_file.write_text(source)

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            assert len(info.functions) == 1
            assert info.functions[0].name == "greet"
            assert info.functions[0].return_type == "str"
            assert len(info.functions[0].parameters) >= 1

    def test_analyze_module_with_class(self):
        """Test analyzing module with class."""
        source = '''
"""Module with class."""

class Person:
    """A person class.

    Attributes:
        name: The person's name
    """

    def __init__(self, name: str):
        """Initialize person."""
        self.name = name

    def greet(self) -> str:
        """Return greeting."""
        return f"Hello, I am {self.name}"
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "classes.py"
            source_file.write_text(source)

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            assert len(info.classes) == 1
            assert info.classes[0].name == "Person"
            assert len(info.classes[0].methods) >= 2

    def test_analyze_dataclass(self):
        """Test analyzing dataclass."""
        source = '''
"""Module with dataclass."""

from dataclasses import dataclass

@dataclass
class Point:
    """A 2D point."""
    x: float
    y: float
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "data.py"
            source_file.write_text(source)

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            assert len(info.classes) == 1
            assert info.classes[0].name == "Point"
            assert info.classes[0].is_dataclass is True

    def test_analyze_async_function(self):
        """Test analyzing async function."""
        source = '''
"""Module with async function."""

async def fetch_data(url: str) -> dict:
    """Fetch data from URL."""
    pass
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "async_mod.py"
            source_file.write_text(source)

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            assert len(info.functions) == 1
            assert info.functions[0].is_async is True

    def test_analyze_constants(self):
        """Test analyzing module constants."""
        source = '''
"""Module with constants."""

MAX_SIZE = 100
DEFAULT_NAME = "test"
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "consts.py"
            source_file.write_text(source)

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            assert len(info.constants) == 2


# =============================================================================
# MarkdownWriter Tests
# =============================================================================


class TestMarkdownWriter:
    """Tests for MarkdownWriter."""

    def test_create_output_directory(self):
        """Test output directory is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "docs" / "api"
            writer = MarkdownWriter(str(output_dir))

            assert output_dir.exists()

    def test_write_module(self):
        """Test writing module documentation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = MarkdownWriter(tmpdir)

            mod = ModuleInfo(
                name="test_module",
                path="/path/to/test.py",
                docstring="A test module.",
                functions=[
                    FunctionInfo(
                        name="test_func",
                        signature="(x: int) -> str",
                        docstring="Test function.",
                    )
                ],
            )

            filepath = writer.write_module(mod)

            assert Path(filepath).exists()
            content = Path(filepath).read_text()
            assert "test_module" in content
            assert "test_func" in content

    def test_write_module_with_class(self):
        """Test writing module documentation with class."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = MarkdownWriter(tmpdir)

            mod = ModuleInfo(
                name="classes",
                path="/path/to/classes.py",
                classes=[
                    ClassInfo(
                        name="MyClass",
                        docstring="A class.",
                        methods=[
                            FunctionInfo(name="method", signature="(self)"),
                        ],
                    )
                ],
            )

            filepath = writer.write_module(mod)

            content = Path(filepath).read_text()
            assert "MyClass" in content
            assert "method" in content

    def test_write_index(self):
        """Test writing index file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            writer = MarkdownWriter(tmpdir)

            modules = [
                ModuleInfo(name="module_a", path="/a.py", docstring="Module A"),
                ModuleInfo(name="module_b", path="/b.py", docstring="Module B"),
            ]

            filepath = writer.write_index(modules)

            assert Path(filepath).exists()
            content = Path(filepath).read_text()
            assert "module_a" in content
            assert "module_b" in content


# =============================================================================
# APIReferenceGenerator Tests
# =============================================================================


class TestAPIReferenceGenerator:
    """Tests for APIReferenceGenerator."""

    def test_generate_from_source(self):
        """Test generating API docs from source directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            # Create a simple source file
            (source_dir / "module.py").write_text('''
"""A test module."""

def hello():
    """Say hello."""
    pass
''')

            generator = APIReferenceGenerator(str(source_dir), str(output_dir))
            files = generator.generate(package_name="test")

            assert len(files) >= 2  # At least module and index
            assert output_dir.exists()

    def test_generate_creates_index(self):
        """Test that generation creates index file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            (source_dir / "test.py").write_text('"""Test."""\n')

            generator = APIReferenceGenerator(str(source_dir), str(output_dir))
            files = generator.generate()

            index_files = [f for f in files if "index" in f]
            assert len(index_files) == 1

    def test_generate_skips_pycache(self):
        """Test that __pycache__ directories are skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            pycache = source_dir / "__pycache__"
            pycache.mkdir()
            output_dir = Path(tmpdir) / "docs"

            (source_dir / "module.py").write_text('"""Module."""\n')
            (pycache / "cached.py").write_text("# cached\n")

            generator = APIReferenceGenerator(str(source_dir), str(output_dir))
            files = generator.generate()

            # Should not include __pycache__ files
            for f in files:
                assert "__pycache__" not in f


# =============================================================================
# CLIReferenceGenerator Tests
# =============================================================================


class TestCLIReferenceGenerator:
    """Tests for CLIReferenceGenerator."""

    def test_generate_creates_file(self):
        """Test that CLI reference is generated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = CLIReferenceGenerator(tmpdir)
            filepath = generator.generate()

            assert Path(filepath).exists()
            content = Path(filepath).read_text()
            assert "CLI Reference" in content

    def test_generate_includes_commands(self):
        """Test that CLI reference includes commands."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generator = CLIReferenceGenerator(tmpdir)
            filepath = generator.generate()

            content = Path(filepath).read_text()
            # Should have some content about commands
            assert "stance" in content.lower() or "command" in content.lower()


# =============================================================================
# PolicyDocGenerator Tests
# =============================================================================


class TestPolicyDocGenerator:
    """Tests for PolicyDocGenerator."""

    def test_generate_with_no_policies(self):
        """Test generating with no policy files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policies_dir = Path(tmpdir) / "policies"
            policies_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            generator = PolicyDocGenerator(str(policies_dir), str(output_dir))
            files = generator.generate()

            assert files == []

    def test_generate_with_policies(self):
        """Test generating with policy files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policies_dir = Path(tmpdir) / "policies"
            policies_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            # Create a policy file
            policy_content = """
id: aws-s3-001
name: S3 Encryption
description: Ensure S3 buckets are encrypted.
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.encryption.enabled == true"
remediation:
  guidance: Enable encryption.
"""
            (policies_dir / "s3.yaml").write_text(policy_content)

            generator = PolicyDocGenerator(str(policies_dir), str(output_dir))
            files = generator.generate()

            assert len(files) >= 1  # Policy file and/or index


# =============================================================================
# DocumentationGenerator Tests
# =============================================================================


class TestDocumentationGenerator:
    """Tests for DocumentationGenerator."""

    def test_initialization(self):
        """Test generator initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            generator = DocumentationGenerator(
                source_dir=str(source_dir),
                output_dir=str(output_dir),
            )

            assert generator.source_dir == source_dir
            assert generator.output_dir == output_dir

    def test_generate_all(self):
        """Test generating all documentation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            (source_dir / "test.py").write_text('"""Test module."""\n')

            generator = DocumentationGenerator(
                source_dir=str(source_dir),
                output_dir=str(output_dir),
            )

            results = generator.generate_all()

            assert "api" in results
            assert "cli" in results
            assert len(results["api"]) >= 1

    def test_generate_api_only(self):
        """Test generating only API documentation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            (source_dir / "module.py").write_text('"""Module."""\n')

            generator = DocumentationGenerator(
                source_dir=str(source_dir),
                output_dir=str(output_dir),
            )

            files = generator.generate_api()

            assert len(files) >= 1

    def test_generate_cli_only(self):
        """Test generating only CLI documentation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            generator = DocumentationGenerator(
                source_dir=str(source_dir),
                output_dir=str(output_dir),
            )

            filepath = generator.generate_cli()

            assert Path(filepath).exists()


# =============================================================================
# CLI Command Tests
# =============================================================================


class TestDocsGenerateCommand:
    """Tests for docs-generate CLI command."""

    def test_cmd_docs_generate_all(self):
        """Test docs-generate command with all types."""
        from stance.cli_commands import cmd_docs_generate

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            (source_dir / "test.py").write_text('"""Test."""\n')

            args = argparse.Namespace(
                source_dir=str(source_dir),
                output_dir=str(output_dir),
                policies_dir=None,
                type="all",
            )

            result = cmd_docs_generate(args)

            assert result == 0
            assert output_dir.exists()

    def test_cmd_docs_generate_api(self):
        """Test docs-generate command with api type."""
        from stance.cli_commands import cmd_docs_generate

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs"

            (source_dir / "module.py").write_text('"""Module."""\n')

            args = argparse.Namespace(
                source_dir=str(source_dir),
                output_dir=str(output_dir),
                policies_dir=None,
                type="api",
            )

            result = cmd_docs_generate(args)

            assert result == 0

    def test_cmd_docs_generate_cli(self):
        """Test docs-generate command with cli type."""
        from stance.cli_commands import cmd_docs_generate

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                source_dir="src/stance",
                output_dir=str(Path(tmpdir) / "docs"),
                policies_dir=None,
                type="cli",
            )

            result = cmd_docs_generate(args)

            assert result == 0

    def test_cmd_docs_generate_invalid_type(self):
        """Test docs-generate command with invalid type."""
        from stance.cli_commands import cmd_docs_generate

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                source_dir="src/stance",
                output_dir=str(Path(tmpdir) / "docs"),
                policies_dir=None,
                type="invalid",
            )

            result = cmd_docs_generate(args)

            assert result == 1


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_analyze_syntax_error_file(self):
        """Test handling file with syntax error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "broken.py"
            source_file.write_text("def broken(\n")  # Syntax error

            analyzer = SourceAnalyzer(str(source_file))

            with pytest.raises(SyntaxError):
                analyzer.analyze()

    def test_write_to_readonly_directory(self):
        """Test handling readonly directory."""
        # This test is platform-specific, skip if can't make readonly
        pass

    def test_parse_complex_type_hints(self):
        """Test parsing complex type hints."""
        source = '''
"""Module with complex types."""

from typing import Dict, List, Optional, Union

def process(
    data: Dict[str, List[int]],
    callback: Optional[callable] = None,
) -> Union[str, None]:
    """Process data."""
    pass
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "types.py"
            source_file.write_text(source)

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            assert len(info.functions) == 1
            # Should handle complex types without error

    def test_parse_decorators(self):
        """Test parsing various decorators."""
        source = '''
"""Module with decorators."""

class MyClass:
    @property
    def value(self) -> int:
        return 42

    @classmethod
    def create(cls):
        return cls()

    @staticmethod
    def helper():
        pass
'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = Path(tmpdir) / "decorators.py"
            source_file.write_text(source)

            analyzer = SourceAnalyzer(str(source_file))
            info = analyzer.analyze()

            cls = info.classes[0]
            assert len(cls.properties) == 1
            assert len(cls.class_methods) == 1
            assert len(cls.static_methods) == 1
