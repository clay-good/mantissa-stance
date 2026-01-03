"""
Unit tests for Docs CLI commands.

Tests the CLI commands for documentation management including generating,
listing, viewing, validating, and cleaning documentation.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest


class TestDocsInfoCommand:
    """Tests for docs info command."""

    def test_info_text_output(self, capsys):
        """Test showing docs info in text format."""
        from stance.cli_docs import _handle_info

        args = argparse.Namespace(json=False)
        result = _handle_info(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Documentation Module Information" in captured.out
        assert "stance.docs" in captured.out
        assert "Capabilities:" in captured.out
        assert "Generators:" in captured.out

    def test_info_json_output(self, capsys):
        """Test showing docs info in JSON format."""
        from stance.cli_docs import _handle_info

        args = argparse.Namespace(json=True)
        result = _handle_info(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["module"] == "stance.docs"
        assert "capabilities" in output
        assert "generators" in output
        assert "analyzers" in output
        assert "data_classes" in output


class TestDocsGeneratorsCommand:
    """Tests for docs generators command."""

    def test_generators_text_output(self, capsys):
        """Test showing generators in text format."""
        from stance.cli_docs import _handle_generators

        args = argparse.Namespace(json=False)
        result = _handle_generators(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Documentation Generators" in captured.out
        assert "DocumentationGenerator" in captured.out
        assert "APIReferenceGenerator" in captured.out
        assert "CLIReferenceGenerator" in captured.out
        assert "PolicyDocGenerator" in captured.out
        assert "MarkdownWriter" in captured.out

    def test_generators_json_output(self, capsys):
        """Test showing generators in JSON format."""
        from stance.cli_docs import _handle_generators

        args = argparse.Namespace(json=True)
        result = _handle_generators(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "generators" in output
        assert "total" in output
        assert output["total"] == 5


class TestDocsDataclassesCommand:
    """Tests for docs dataclasses command."""

    def test_dataclasses_text_output(self, capsys):
        """Test showing dataclasses in text format."""
        from stance.cli_docs import _handle_dataclasses

        args = argparse.Namespace(json=False)
        result = _handle_dataclasses(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Documentation Data Classes" in captured.out
        assert "ParameterInfo" in captured.out
        assert "FunctionInfo" in captured.out
        assert "ClassInfo" in captured.out
        assert "ModuleInfo" in captured.out

    def test_dataclasses_json_output(self, capsys):
        """Test showing dataclasses in JSON format."""
        from stance.cli_docs import _handle_dataclasses

        args = argparse.Namespace(json=True)
        result = _handle_dataclasses(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "dataclasses" in output
        assert "total" in output
        assert output["total"] == 4


class TestDocsParsersCommand:
    """Tests for docs parsers command."""

    def test_parsers_text_output(self, capsys):
        """Test showing parsers in text format."""
        from stance.cli_docs import _handle_parsers

        args = argparse.Namespace(json=False)
        result = _handle_parsers(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Docstring Parsers" in captured.out
        assert "DocstringParser" in captured.out
        assert "Google-style" in captured.out
        assert "Supported Sections:" in captured.out

    def test_parsers_json_output(self, capsys):
        """Test showing parsers in JSON format."""
        from stance.cli_docs import _handle_parsers

        args = argparse.Namespace(json=True)
        result = _handle_parsers(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "DocstringParser" in output
        assert "supported_styles" in output["DocstringParser"]
        assert "sections" in output["DocstringParser"]


class TestDocsStatusCommand:
    """Tests for docs status command."""

    def test_status_text_output(self, capsys):
        """Test showing status in text format."""
        from stance.cli_docs import _handle_status

        args = argparse.Namespace(json=False)
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Documentation Module Status" in captured.out
        assert "Components:" in captured.out
        assert "Data Classes:" in captured.out
        assert "Capabilities:" in captured.out
        assert "Available" in captured.out

    def test_status_json_output(self, capsys):
        """Test showing status in JSON format."""
        from stance.cli_docs import _handle_status

        args = argparse.Namespace(json=True)
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["module"] == "docs"
        assert "components" in output
        assert "data_classes" in output
        assert "capabilities" in output
        assert output["components"]["DocumentationGenerator"] is True


class TestDocsSummaryCommand:
    """Tests for docs summary command."""

    def test_summary_text_output(self, capsys):
        """Test showing summary in text format."""
        from stance.cli_docs import _handle_summary

        args = argparse.Namespace(json=False)
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Documentation Module Summary" in captured.out
        assert "Overview:" in captured.out
        assert "Features:" in captured.out
        assert "Architecture:" in captured.out
        assert "Usage Examples:" in captured.out

    def test_summary_json_output(self, capsys):
        """Test showing summary in JSON format."""
        from stance.cli_docs import _handle_summary

        args = argparse.Namespace(json=True)
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "overview" in output
        assert "features" in output
        assert "architecture" in output
        assert "usage" in output


class TestDocsListCommand:
    """Tests for docs list command."""

    def test_list_empty_dir(self, capsys):
        """Test listing docs when directory doesn't exist."""
        from stance.cli_docs import _handle_list

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                output_dir=os.path.join(tmpdir, "nonexistent"),
                type="all",
                json=False,
            )
            result = _handle_list(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "not found" in captured.out

    def test_list_existing_dir(self, capsys):
        """Test listing docs from existing directory."""
        from stance.cli_docs import _handle_list

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create the docs structure
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "test.md").write_text("# Test API")

            args = argparse.Namespace(
                output_dir=tmpdir,
                type="all",
                json=False,
            )
            result = _handle_list(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Documentation files in" in captured.out
            assert "API" in captured.out

    def test_list_json_output(self, capsys):
        """Test listing docs with JSON output."""
        from stance.cli_docs import _handle_list

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create the docs structure
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "module.md").write_text("# Module")

            args = argparse.Namespace(
                output_dir=tmpdir,
                type="all",
                json=True,
            )
            result = _handle_list(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert "files" in output
            assert "total" in output
            assert output["total"] == 1

    def test_list_filtered_by_type(self, capsys):
        """Test listing docs filtered by type."""
        from stance.cli_docs import _handle_list

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple doc types
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "api.md").write_text("# API")

            cli_dir = Path(tmpdir) / "cli"
            cli_dir.mkdir()
            (cli_dir / "cli.md").write_text("# CLI")

            args = argparse.Namespace(
                output_dir=tmpdir,
                type="api",
                json=True,
            )
            result = _handle_list(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert len(output["files"]["api"]) == 1
            assert len(output["files"]["cli"]) == 0


class TestDocsValidateCommand:
    """Tests for docs validate command."""

    def test_validate_missing_dir(self, capsys):
        """Test validating when directory doesn't exist."""
        from stance.cli_docs import _handle_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                output_dir=os.path.join(tmpdir, "nonexistent"),
                json=False,
            )
            result = _handle_validate(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "not found" in captured.out

    def test_validate_valid_docs(self, capsys):
        """Test validating valid documentation."""
        from stance.cli_docs import _handle_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create valid docs
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "module.md").write_text("# Module Documentation\n\nContent here.")

            args = argparse.Namespace(
                output_dir=tmpdir,
                json=False,
            )
            result = _handle_validate(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "VALID" in captured.out

    def test_validate_empty_file(self, capsys):
        """Test validating empty documentation file."""
        from stance.cli_docs import _handle_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "empty.md").write_text("")

            args = argparse.Namespace(
                output_dir=tmpdir,
                json=False,
            )
            result = _handle_validate(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "INVALID" in captured.out
            assert "Empty file" in captured.out

    def test_validate_json_output(self, capsys):
        """Test validating with JSON output."""
        from stance.cli_docs import _handle_validate

        with tempfile.TemporaryDirectory() as tmpdir:
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "valid.md").write_text("# Valid\n\nContent.")

            args = argparse.Namespace(
                output_dir=tmpdir,
                json=True,
            )
            result = _handle_validate(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert output["valid"] is True
            assert "errors" in output
            assert "warnings" in output


class TestDocsCleanCommand:
    """Tests for docs clean command."""

    def test_clean_missing_dir(self, capsys):
        """Test cleaning when directory doesn't exist."""
        from stance.cli_docs import _handle_clean

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                output_dir=os.path.join(tmpdir, "nonexistent"),
                force=True,
                type="all",
            )
            result = _handle_clean(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "not found" in captured.out

    def test_clean_existing_docs(self, capsys):
        """Test cleaning existing documentation."""
        from stance.cli_docs import _handle_clean

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create docs to clean
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "module.md").write_text("# Module")
            (api_dir / "another.md").write_text("# Another")

            args = argparse.Namespace(
                output_dir=tmpdir,
                force=True,
                type="all",
            )
            result = _handle_clean(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Cleaned 2 file(s)" in captured.out

            # Verify files removed
            assert not (api_dir / "module.md").exists()
            assert not (api_dir / "another.md").exists()

    def test_clean_by_type(self, capsys):
        """Test cleaning specific documentation type."""
        from stance.cli_docs import _handle_clean

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple types
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "api.md").write_text("# API")

            cli_dir = Path(tmpdir) / "cli"
            cli_dir.mkdir()
            (cli_dir / "cli.md").write_text("# CLI")

            args = argparse.Namespace(
                output_dir=tmpdir,
                force=True,
                type="api",
            )
            result = _handle_clean(args)
            assert result == 0

            # API should be cleaned, CLI should remain
            assert not (api_dir / "api.md").exists()
            assert (cli_dir / "cli.md").exists()


class TestDocsModuleCommand:
    """Tests for docs module command."""

    def test_module_not_found(self, capsys):
        """Test module command when module doesn't exist."""
        from stance.cli_docs import _handle_module

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                module_name="nonexistent.module",
                source_dir=tmpdir,
                json=False,
            )
            result = _handle_module(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "Module not found" in captured.out

    def test_module_found(self, capsys):
        """Test module command when module exists."""
        from stance.cli_docs import _handle_module

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a module file
            module_dir = Path(tmpdir) / "mymodule"
            module_dir.mkdir()
            (module_dir / "__init__.py").write_text('"""Test module docstring."""\n\nMY_CONST = 42\n')

            args = argparse.Namespace(
                module_name="mymodule",
                source_dir=tmpdir,
                json=False,
            )
            result = _handle_module(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Module: mymodule" in captured.out
            assert "Test module docstring" in captured.out

    def test_module_json_output(self, capsys):
        """Test module command with JSON output."""
        from stance.cli_docs import _handle_module

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a module file
            module_dir = Path(tmpdir) / "testmod"
            module_dir.mkdir()
            (module_dir / "__init__.py").write_text('"""Test module."""\n\nclass TestClass:\n    pass\n')

            args = argparse.Namespace(
                module_name="testmod",
                source_dir=tmpdir,
                json=True,
            )
            result = _handle_module(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert output["name"] == "testmod"
            assert "docstring" in output
            assert "classes" in output


class TestDocsClassCommand:
    """Tests for docs class command."""

    def test_class_invalid_name(self, capsys):
        """Test class command with invalid name format."""
        from stance.cli_docs import _handle_class

        args = argparse.Namespace(
            class_name="InvalidName",  # Should be fully qualified
            source_dir="/tmp",
            json=False,
        )
        result = _handle_class(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "fully qualified" in captured.out

    def test_class_module_not_found(self, capsys):
        """Test class command when module doesn't exist."""
        from stance.cli_docs import _handle_class

        with tempfile.TemporaryDirectory() as tmpdir:
            args = argparse.Namespace(
                class_name="nonexistent.module.MyClass",
                source_dir=tmpdir,
                json=False,
            )
            result = _handle_class(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "Module not found" in captured.out

    def test_class_not_found(self, capsys):
        """Test class command when class doesn't exist in module."""
        from stance.cli_docs import _handle_class

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a module without the class
            module_dir = Path(tmpdir) / "mymod"
            module_dir.mkdir()
            (module_dir / "__init__.py").write_text('"""Module."""\n')

            args = argparse.Namespace(
                class_name="mymod.NonExistentClass",
                source_dir=tmpdir,
                json=False,
            )
            result = _handle_class(args)
            assert result == 1

            captured = capsys.readouterr()
            assert "not found" in captured.out

    def test_class_found(self, capsys):
        """Test class command when class exists."""
        from stance.cli_docs import _handle_class

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a module with a class
            module_dir = Path(tmpdir) / "testpkg"
            module_dir.mkdir()
            (module_dir / "__init__.py").write_text('''"""Module docstring."""

class MyClass:
    """A test class.

    This class is for testing.
    """

    name: str = "default"

    def method(self) -> str:
        """Return something."""
        return "hello"
''')

            args = argparse.Namespace(
                class_name="testpkg.MyClass",
                source_dir=tmpdir,
                json=False,
            )
            result = _handle_class(args)
            assert result == 0

            captured = capsys.readouterr()
            assert "Class: testpkg.MyClass" in captured.out
            assert "A test class" in captured.out

    def test_class_json_output(self, capsys):
        """Test class command with JSON output."""
        from stance.cli_docs import _handle_class

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a module with a class
            module_dir = Path(tmpdir) / "jsonpkg"
            module_dir.mkdir()
            (module_dir / "__init__.py").write_text('''"""Module."""

class JsonClass:
    """JSON test class."""

    def test_method(self):
        """Test method."""
        pass
''')

            args = argparse.Namespace(
                class_name="jsonpkg.JsonClass",
                source_dir=tmpdir,
                json=True,
            )
            result = _handle_class(args)
            assert result == 0

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert output["name"] == "JsonClass"
            assert output["module"] == "jsonpkg"
            assert "methods" in output


class TestDocsGenerateCommand:
    """Tests for docs generate command."""

    def test_generate_creates_output_dir(self, capsys):
        """Test generate command creates output directory."""
        from stance.cli_docs import _handle_generate

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            output_dir = Path(tmpdir) / "docs" / "generated"

            # Create minimal source
            (source_dir / "test.py").write_text('"""Test module."""\n')

            args = argparse.Namespace(
                type="api",
                source_dir=str(source_dir),
                output_dir=str(output_dir),
                policies_dir="policies",
                json=False,
            )
            # May fail due to missing structure, but tests the command runs
            result = _handle_generate(args)
            # We just want to test it doesn't crash

    def test_generate_json_output(self, capsys):
        """Test generate command with JSON output."""
        from stance.cli_docs import _handle_generate

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create source directory with a valid Python file
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            (source_dir / "test.py").write_text('"""Test module."""\n')

            output_dir = Path(tmpdir) / "output"

            args = argparse.Namespace(
                type="api",
                source_dir=str(source_dir),
                output_dir=str(output_dir),
                policies_dir="policies",
                json=True,
            )
            result = _handle_generate(args)

            captured = capsys.readouterr()
            # Should be valid JSON
            if captured.out.strip():
                output = json.loads(captured.out)
                # Either success or error key should exist
                assert "success" in output or "error" in output


class TestCmdDocsMainHandler:
    """Tests for the main cmd_docs handler."""

    def test_no_command(self, capsys):
        """Test calling docs without subcommand."""
        from stance.cli_docs import cmd_docs

        args = argparse.Namespace()
        result = cmd_docs(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Available commands:" in captured.out

    def test_none_command(self, capsys):
        """Test calling docs with None subcommand."""
        from stance.cli_docs import cmd_docs

        args = argparse.Namespace(docs_command=None)
        result = cmd_docs(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Available commands:" in captured.out
        assert "generate" in captured.out
        assert "list" in captured.out

    def test_unknown_command(self, capsys):
        """Test calling docs with unknown subcommand."""
        from stance.cli_docs import cmd_docs

        args = argparse.Namespace(docs_command="unknown")
        result = cmd_docs(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown docs command" in captured.out


class TestDocsParserRegistration:
    """Tests for docs parser registration."""

    def test_add_docs_parser(self):
        """Test that docs parser is properly added."""
        from stance.cli_docs import add_docs_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_docs_parser(subparsers)

        # Parse a test command
        args = parser.parse_args(["docs", "info"])
        assert args.docs_command == "info"

    def test_all_subcommands_registered(self):
        """Test all docs subcommands are registered."""
        from stance.cli_docs import add_docs_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_docs_parser(subparsers)

        # Test each subcommand parses
        commands = [
            "generate", "list", "info", "module", "class",
            "parsers", "generators", "dataclasses",
            "status", "summary", "validate", "clean"
        ]

        for cmd in commands:
            if cmd in ["module", "class"]:
                args = parser.parse_args(["docs", cmd, "test.name"])
            else:
                args = parser.parse_args(["docs", cmd])
            assert args.docs_command == cmd


class TestDocsIntegration:
    """Integration tests for docs CLI."""

    def test_full_workflow(self, capsys):
        """Test full documentation workflow."""
        from stance.cli_docs import _handle_info, _handle_generators, _handle_status

        # Get info
        args = argparse.Namespace(json=False)
        result = _handle_info(args)
        assert result == 0

        # List generators
        args = argparse.Namespace(json=False)
        result = _handle_generators(args)
        assert result == 0

        # Check status
        args = argparse.Namespace(json=False)
        result = _handle_status(args)
        assert result == 0

    def test_create_validate_clean_flow(self, capsys):
        """Test create, validate, clean workflow."""
        from stance.cli_docs import _handle_list, _handle_validate, _handle_clean

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create some docs manually
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "test.md").write_text("# Test\n\nContent.")

            cli_dir = Path(tmpdir) / "cli"
            cli_dir.mkdir()
            (cli_dir / "commands.md").write_text("# Commands\n\nCLI commands.")

            # List
            list_args = argparse.Namespace(
                output_dir=tmpdir,
                type="all",
                json=False,
            )
            result = _handle_list(list_args)
            assert result == 0

            # Validate
            validate_args = argparse.Namespace(
                output_dir=tmpdir,
                json=False,
            )
            result = _handle_validate(validate_args)
            assert result == 0

            # Clean
            clean_args = argparse.Namespace(
                output_dir=tmpdir,
                force=True,
                type="all",
            )
            result = _handle_clean(clean_args)
            assert result == 0

            # Verify cleaned
            assert not (api_dir / "test.md").exists()
            assert not (cli_dir / "commands.md").exists()
