"""
Unit tests for Web API Docs endpoints.

Tests the REST API endpoints for documentation management including
generating, listing, viewing, validating, and cleaning documentation.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest


class TestDocsInfoEndpoint:
    """Tests for /api/docs/info endpoint."""

    def test_get_info(self):
        """Test getting documentation module info."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_info = StanceRequestHandler._docs_info.__get__(handler)

        result = handler._docs_info({})

        assert result["module"] == "stance.docs"
        assert "description" in result
        assert "capabilities" in result
        assert "generators" in result
        assert "analyzers" in result
        assert len(result["capabilities"]) > 0

    def test_info_contains_generators(self):
        """Test info contains expected generators."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_info = StanceRequestHandler._docs_info.__get__(handler)

        result = handler._docs_info({})

        assert "DocumentationGenerator" in result["generators"]
        assert "APIReferenceGenerator" in result["generators"]
        assert "CLIReferenceGenerator" in result["generators"]
        assert "PolicyDocGenerator" in result["generators"]


class TestDocsGeneratorsEndpoint:
    """Tests for /api/docs/generators endpoint."""

    def test_list_generators(self):
        """Test listing documentation generators."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_generators = StanceRequestHandler._docs_generators.__get__(handler)

        result = handler._docs_generators({})

        assert "generators" in result
        assert "total" in result
        assert result["total"] == 5

        generator_names = [g["name"] for g in result["generators"]]
        assert "DocumentationGenerator" in generator_names
        assert "APIReferenceGenerator" in generator_names
        assert "CLIReferenceGenerator" in generator_names
        assert "PolicyDocGenerator" in generator_names
        assert "MarkdownWriter" in generator_names

    def test_generators_have_expected_fields(self):
        """Test generators have expected fields."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_generators = StanceRequestHandler._docs_generators.__get__(handler)

        result = handler._docs_generators({})

        for gen in result["generators"]:
            assert "name" in gen
            assert "description" in gen
            assert "methods" in gen
            assert "output_format" in gen


class TestDocsDataclassesEndpoint:
    """Tests for /api/docs/dataclasses endpoint."""

    def test_list_dataclasses(self):
        """Test listing documentation dataclasses."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_dataclasses = StanceRequestHandler._docs_dataclasses.__get__(handler)

        result = handler._docs_dataclasses({})

        assert "dataclasses" in result
        assert "total" in result
        assert result["total"] == 4

        dc_names = [dc["name"] for dc in result["dataclasses"]]
        assert "ParameterInfo" in dc_names
        assert "FunctionInfo" in dc_names
        assert "ClassInfo" in dc_names
        assert "ModuleInfo" in dc_names

    def test_dataclasses_have_fields(self):
        """Test dataclasses have fields defined."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_dataclasses = StanceRequestHandler._docs_dataclasses.__get__(handler)

        result = handler._docs_dataclasses({})

        for dc in result["dataclasses"]:
            assert "name" in dc
            assert "description" in dc
            assert "fields" in dc
            assert len(dc["fields"]) > 0


class TestDocsParsersEndpoint:
    """Tests for /api/docs/parsers endpoint."""

    def test_get_parsers(self):
        """Test getting docstring parsers info."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_parsers = StanceRequestHandler._docs_parsers.__get__(handler)

        result = handler._docs_parsers({})

        assert "parsers" in result
        assert "DocstringParser" in result["parsers"]

    def test_parser_has_sections(self):
        """Test parser info includes sections."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_parsers = StanceRequestHandler._docs_parsers.__get__(handler)

        result = handler._docs_parsers({})

        parser = result["parsers"]["DocstringParser"]
        assert "description" in parser
        assert "supported_styles" in parser
        assert "sections" in parser
        assert "Google-style docstrings" in parser["supported_styles"]


class TestDocsStatusEndpoint:
    """Tests for /api/docs/status endpoint."""

    def test_get_status(self):
        """Test getting docs module status."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_status = StanceRequestHandler._docs_status.__get__(handler)

        result = handler._docs_status({})

        assert result["module"] == "docs"
        assert "components" in result
        assert "data_classes" in result
        assert "capabilities" in result

    def test_status_components_available(self):
        """Test all components are available."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_status = StanceRequestHandler._docs_status.__get__(handler)

        result = handler._docs_status({})

        for name, available in result["components"].items():
            assert available is True, f"{name} should be available"

        for name, available in result["data_classes"].items():
            assert available is True, f"{name} should be available"


class TestDocsSummaryEndpoint:
    """Tests for /api/docs/summary endpoint."""

    def test_get_summary(self):
        """Test getting docs module summary."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_summary = StanceRequestHandler._docs_summary.__get__(handler)

        result = handler._docs_summary({})

        assert "overview" in result
        assert "features" in result
        assert "architecture" in result

    def test_summary_architecture(self):
        """Test summary includes architecture details."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_summary = StanceRequestHandler._docs_summary.__get__(handler)

        result = handler._docs_summary({})

        arch = result["architecture"]
        assert arch["main_class"] == "DocumentationGenerator"
        assert "generators" in arch
        assert "analyzers" in arch
        assert "writers" in arch


class TestDocsListEndpoint:
    """Tests for /api/docs/list endpoint."""

    def test_list_empty_dir(self):
        """Test listing docs from empty directory."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_list = StanceRequestHandler._docs_list.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._docs_list({"output_dir": [tmpdir]})

            assert result["total"] == 0
            assert result["files"]["api"] == []
            assert result["files"]["cli"] == []
            assert result["files"]["policies"] == []

    def test_list_with_files(self):
        """Test listing docs with existing files."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_list = StanceRequestHandler._docs_list.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create docs structure
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "module.md").write_text("# Module")
            (api_dir / "other.md").write_text("# Other")

            result = handler._docs_list({"output_dir": [tmpdir]})

            assert result["total"] == 2
            assert len(result["files"]["api"]) == 2

    def test_list_filtered_by_type(self):
        """Test listing filtered by doc type."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_list = StanceRequestHandler._docs_list.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple types
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "api.md").write_text("# API")

            cli_dir = Path(tmpdir) / "cli"
            cli_dir.mkdir()
            (cli_dir / "cli.md").write_text("# CLI")

            result = handler._docs_list({"output_dir": [tmpdir], "type": ["api"]})

            assert len(result["files"]["api"]) == 1
            assert len(result["files"]["cli"]) == 0


class TestDocsModuleEndpoint:
    """Tests for /api/docs/module endpoint."""

    def test_module_missing_param(self):
        """Test module endpoint with missing parameter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_module = StanceRequestHandler._docs_module.__get__(handler)

        result = handler._docs_module({})

        assert "error" in result
        assert "Missing required parameter" in result["error"]

    def test_module_not_found(self):
        """Test module endpoint when module doesn't exist."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_module = StanceRequestHandler._docs_module.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._docs_module({
                "module": ["nonexistent.module"],
                "source_dir": [tmpdir],
            })

            assert "error" in result
            assert "Module not found" in result["error"]

    def test_module_found(self):
        """Test module endpoint when module exists."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_module = StanceRequestHandler._docs_module.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create module
            mod_dir = Path(tmpdir) / "testmod"
            mod_dir.mkdir()
            (mod_dir / "__init__.py").write_text('"""Test module."""\n\nclass MyClass:\n    pass\n')

            result = handler._docs_module({
                "module": ["testmod"],
                "source_dir": [tmpdir],
            })

            assert "error" not in result
            assert result["name"] == "testmod"
            assert "docstring" in result
            assert "classes" in result


class TestDocsClassEndpoint:
    """Tests for /api/docs/class endpoint."""

    def test_class_missing_param(self):
        """Test class endpoint with missing parameter."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_class = StanceRequestHandler._docs_class.__get__(handler)

        result = handler._docs_class({})

        assert "error" in result
        assert "Missing required parameter" in result["error"]

    def test_class_invalid_name(self):
        """Test class endpoint with invalid name format."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_class = StanceRequestHandler._docs_class.__get__(handler)

        result = handler._docs_class({"class": ["InvalidName"]})

        assert "error" in result
        assert "fully qualified" in result["error"]

    def test_class_module_not_found(self):
        """Test class endpoint when module doesn't exist."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_class = StanceRequestHandler._docs_class.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = handler._docs_class({
                "class": ["nonexistent.MyClass"],
                "source_dir": [tmpdir],
            })

            assert "error" in result
            assert "Module not found" in result["error"]

    def test_class_not_found_in_module(self):
        """Test class endpoint when class doesn't exist in module."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_class = StanceRequestHandler._docs_class.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create module without the class
            mod_dir = Path(tmpdir) / "mymod"
            mod_dir.mkdir()
            (mod_dir / "__init__.py").write_text('"""Module."""\n')

            result = handler._docs_class({
                "class": ["mymod.NonExistent"],
                "source_dir": [tmpdir],
            })

            assert "error" in result
            assert "Class not found" in result["error"]

    def test_class_found(self):
        """Test class endpoint when class exists."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_class = StanceRequestHandler._docs_class.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create module with class
            mod_dir = Path(tmpdir) / "classpkg"
            mod_dir.mkdir()
            (mod_dir / "__init__.py").write_text('''"""Module."""

class TestClass:
    """A test class."""

    def method(self):
        """A method."""
        pass
''')

            result = handler._docs_class({
                "class": ["classpkg.TestClass"],
                "source_dir": [tmpdir],
            })

            assert "error" not in result
            assert result["name"] == "TestClass"
            assert result["module"] == "classpkg"
            assert "docstring" in result
            assert "methods" in result


class TestDocsGenerateEndpoint:
    """Tests for /api/docs/generate endpoint (POST)."""

    def test_generate_invalid_json(self):
        """Test generate with invalid JSON body."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_generate = StanceRequestHandler._docs_generate.__get__(handler)

        result = handler._docs_generate(b"not valid json")

        assert "error" in result
        assert "Invalid JSON" in result["error"]

    def test_generate_with_empty_body(self):
        """Test generate with empty body."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_generate = StanceRequestHandler._docs_generate.__get__(handler)

        # May fail due to missing directories but tests parsing
        result = handler._docs_generate(b"")

        # Should either succeed or fail with specific error
        assert "success" in result or "error" in result

    def test_generate_creates_output(self):
        """Test generate creates output."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_generate = StanceRequestHandler._docs_generate.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            source_dir = Path(tmpdir) / "src"
            source_dir.mkdir()
            (source_dir / "test.py").write_text('"""Test."""\n')

            output_dir = Path(tmpdir) / "docs"

            body = json.dumps({
                "source_dir": str(source_dir),
                "output_dir": str(output_dir),
                "type": "api",
            }).encode()

            result = handler._docs_generate(body)

            # Should return with success or error status
            assert "success" in result


class TestDocsValidateEndpoint:
    """Tests for /api/docs/validate endpoint (POST)."""

    def test_validate_invalid_json(self):
        """Test validate with invalid JSON body."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_validate = StanceRequestHandler._docs_validate.__get__(handler)

        result = handler._docs_validate(b"not valid json")

        assert "error" in result
        assert "Invalid JSON" in result["error"]

    def test_validate_missing_dir(self):
        """Test validate with missing directory."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_validate = StanceRequestHandler._docs_validate.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            body = json.dumps({
                "output_dir": os.path.join(tmpdir, "nonexistent"),
            }).encode()

            result = handler._docs_validate(body)

            assert result["valid"] is False
            assert "error" in result

    def test_validate_valid_docs(self):
        """Test validate with valid documentation."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_validate = StanceRequestHandler._docs_validate.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create valid docs
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "module.md").write_text("# Module\n\nContent here.")

            body = json.dumps({"output_dir": tmpdir}).encode()

            result = handler._docs_validate(body)

            assert result["valid"] is True
            assert result["files_checked"] >= 1
            assert "errors" in result
            assert len(result["errors"]) == 0

    def test_validate_empty_file(self):
        """Test validate with empty file."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_validate = StanceRequestHandler._docs_validate.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "empty.md").write_text("")

            body = json.dumps({"output_dir": tmpdir}).encode()

            result = handler._docs_validate(body)

            assert result["valid"] is False
            assert len(result["errors"]) > 0


class TestDocsCleanEndpoint:
    """Tests for /api/docs/clean endpoint (POST)."""

    def test_clean_invalid_json(self):
        """Test clean with invalid JSON body."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_clean = StanceRequestHandler._docs_clean.__get__(handler)

        result = handler._docs_clean(b"not valid json")

        assert "error" in result
        assert "Invalid JSON" in result["error"]

    def test_clean_missing_dir(self):
        """Test clean with missing directory."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_clean = StanceRequestHandler._docs_clean.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            body = json.dumps({
                "output_dir": os.path.join(tmpdir, "nonexistent"),
            }).encode()

            result = handler._docs_clean(body)

            assert result["success"] is True
            assert result["files_removed"] == 0

    def test_clean_existing_docs(self):
        """Test clean removes documentation files."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_clean = StanceRequestHandler._docs_clean.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create docs to clean
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "module.md").write_text("# Module")
            (api_dir / "other.md").write_text("# Other")

            body = json.dumps({"output_dir": tmpdir, "type": "all"}).encode()

            result = handler._docs_clean(body)

            assert result["success"] is True
            assert result["files_removed"] == 2

            # Verify files removed
            assert not (api_dir / "module.md").exists()
            assert not (api_dir / "other.md").exists()

    def test_clean_by_type(self):
        """Test clean specific documentation type."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler._docs_clean = StanceRequestHandler._docs_clean.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create multiple types
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "api.md").write_text("# API")

            cli_dir = Path(tmpdir) / "cli"
            cli_dir.mkdir()
            (cli_dir / "cli.md").write_text("# CLI")

            body = json.dumps({"output_dir": tmpdir, "type": "api"}).encode()

            result = handler._docs_clean(body)

            assert result["success"] is True
            assert result["files_removed"] == 1

            # Only API should be cleaned
            assert not (api_dir / "api.md").exists()
            assert (cli_dir / "cli.md").exists()


class TestDocsApiIntegration:
    """Integration tests for docs API endpoints."""

    def test_all_get_endpoints_callable(self):
        """Test all GET endpoints are callable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._docs_info = StanceRequestHandler._docs_info.__get__(handler)
        handler._docs_generators = StanceRequestHandler._docs_generators.__get__(handler)
        handler._docs_dataclasses = StanceRequestHandler._docs_dataclasses.__get__(handler)
        handler._docs_parsers = StanceRequestHandler._docs_parsers.__get__(handler)
        handler._docs_status = StanceRequestHandler._docs_status.__get__(handler)
        handler._docs_summary = StanceRequestHandler._docs_summary.__get__(handler)
        handler._docs_list = StanceRequestHandler._docs_list.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            endpoints = [
                ("_docs_info", {}),
                ("_docs_generators", {}),
                ("_docs_dataclasses", {}),
                ("_docs_parsers", {}),
                ("_docs_status", {}),
                ("_docs_summary", {}),
                ("_docs_list", {"output_dir": [tmpdir]}),
            ]

            for method_name, params in endpoints:
                method = getattr(handler, method_name)
                result = method(params)
                assert isinstance(result, dict), f"{method_name} should return dict"

    def test_all_post_endpoints_callable(self):
        """Test all POST endpoints are callable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._docs_generate = StanceRequestHandler._docs_generate.__get__(handler)
        handler._docs_validate = StanceRequestHandler._docs_validate.__get__(handler)
        handler._docs_clean = StanceRequestHandler._docs_clean.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            endpoints = [
                ("_docs_generate", {"source_dir": tmpdir, "output_dir": tmpdir}),
                ("_docs_validate", {"output_dir": tmpdir}),
                ("_docs_clean", {"output_dir": tmpdir}),
            ]

            for method_name, data in endpoints:
                method = getattr(handler, method_name)
                body = json.dumps(data).encode()
                result = method(body)
                assert isinstance(result, dict), f"{method_name} should return dict"

    def test_json_serializable(self):
        """Test all endpoint responses are JSON serializable."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Bind all methods
        handler._docs_info = StanceRequestHandler._docs_info.__get__(handler)
        handler._docs_generators = StanceRequestHandler._docs_generators.__get__(handler)
        handler._docs_dataclasses = StanceRequestHandler._docs_dataclasses.__get__(handler)
        handler._docs_parsers = StanceRequestHandler._docs_parsers.__get__(handler)
        handler._docs_status = StanceRequestHandler._docs_status.__get__(handler)
        handler._docs_summary = StanceRequestHandler._docs_summary.__get__(handler)
        handler._docs_list = StanceRequestHandler._docs_list.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            endpoints = [
                ("_docs_info", {}),
                ("_docs_generators", {}),
                ("_docs_dataclasses", {}),
                ("_docs_parsers", {}),
                ("_docs_status", {}),
                ("_docs_summary", {}),
                ("_docs_list", {"output_dir": [tmpdir]}),
            ]

            for method_name, params in endpoints:
                method = getattr(handler, method_name)
                result = method(params)
                try:
                    json.dumps(result, default=str)
                except (TypeError, ValueError) as e:
                    pytest.fail(f"{method_name} response not JSON serializable: {e}")

    def test_workflow_list_validate_clean(self):
        """Test workflow: list, validate, clean."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        handler._docs_list = StanceRequestHandler._docs_list.__get__(handler)
        handler._docs_validate = StanceRequestHandler._docs_validate.__get__(handler)
        handler._docs_clean = StanceRequestHandler._docs_clean.__get__(handler)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test docs
            api_dir = Path(tmpdir) / "api"
            api_dir.mkdir()
            (api_dir / "test.md").write_text("# Test\n\nContent.")

            # List
            result = handler._docs_list({"output_dir": [tmpdir]})
            assert result["total"] == 1

            # Validate
            body = json.dumps({"output_dir": tmpdir}).encode()
            result = handler._docs_validate(body)
            assert result["valid"] is True

            # Clean
            body = json.dumps({"output_dir": tmpdir, "type": "all"}).encode()
            result = handler._docs_clean(body)
            assert result["success"] is True
            assert result["files_removed"] == 1

            # Verify cleaned
            result = handler._docs_list({"output_dir": [tmpdir]})
            assert result["total"] == 0
