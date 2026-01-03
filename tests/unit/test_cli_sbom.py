"""
Unit tests for SBOM CLI commands.

Tests cover:
- CLI argument parsing
- Command handlers
- Output formatting
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_sbom import (
    add_sbom_parser,
    cmd_sbom,
)


# =============================================================================
# Parser Tests
# =============================================================================


class TestAddSBOMParser:
    """Tests for add_sbom_parser function."""

    def test_adds_sbom_parser(self):
        """Test that sbom parser is added."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_sbom_parser(subparsers)

        # Parse sbom command
        args = parser.parse_args(["sbom"])
        assert args is not None

    def test_generate_subcommand(self):
        """Test generate subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "generate", "."])
        assert args.sbom_command == "generate"

    def test_parse_subcommand(self):
        """Test parse subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "parse", "package.json"])
        assert args.sbom_command == "parse"
        assert args.path == "package.json"

    def test_license_subcommand(self):
        """Test license subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "license", "."])
        assert args.sbom_command == "license"

    def test_risk_subcommand(self):
        """Test risk subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "risk", "."])
        assert args.sbom_command == "risk"

    def test_validate_subcommand(self):
        """Test validate subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "validate", "sbom.json"])
        assert args.sbom_command == "validate"

    def test_formats_subcommand(self):
        """Test formats subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "formats"])
        assert args.sbom_command == "formats"

    def test_ecosystems_subcommand(self):
        """Test ecosystems subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "ecosystems"])
        assert args.sbom_command == "ecosystems"

    def test_licenses_subcommand(self):
        """Test licenses subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "licenses"])
        assert args.sbom_command == "licenses"

    def test_info_subcommand(self):
        """Test info subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "info"])
        assert args.sbom_command == "info"

    def test_status_subcommand(self):
        """Test status subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "status"])
        assert args.sbom_command == "status"

    def test_diff_subcommand(self):
        """Test diff subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "diff", "sbom1.json", "sbom2.json"])
        assert args.sbom_command == "diff"
        assert args.sbom1 == "sbom1.json"
        assert args.sbom2 == "sbom2.json"

    def test_convert_subcommand(self):
        """Test convert subcommand."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args([
            "sbom", "convert", "input.json", "output.json",
            "--to-format", "spdx-json"
        ])
        assert args.sbom_command == "convert"
        assert args.to_format == "spdx-json"


# =============================================================================
# Format Options Tests
# =============================================================================


class TestFormatOptions:
    """Tests for format option parsing."""

    def test_generate_format_options(self):
        """Test generate format options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        for fmt in ["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag", "stance"]:
            args = parser.parse_args(["sbom", "generate", ".", "--format", fmt])
            assert args.format == fmt

    def test_license_policy_options(self):
        """Test license policy options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        for policy in ["permissive", "copyleft-allowed", "strict"]:
            args = parser.parse_args(["sbom", "license", ".", "--policy", policy])
            assert args.policy == policy

    def test_risk_severity_options(self):
        """Test risk severity options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        for sev in ["critical", "high", "medium", "low", "info"]:
            args = parser.parse_args(["sbom", "risk", ".", "--min-severity", sev])
            assert args.min_severity == sev


# =============================================================================
# Command Handler Tests
# =============================================================================


class TestCmdSbom:
    """Tests for cmd_sbom function."""

    def test_no_command_shows_help(self, capsys):
        """Test that no command shows help."""
        args = argparse.Namespace()
        # Don't set sbom_command

        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage:" in captured.out

    def test_unknown_command(self, capsys):
        """Test unknown command handling."""
        args = argparse.Namespace(sbom_command="unknown")

        result = cmd_sbom(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown" in captured.out


class TestFormatsCommand:
    """Tests for formats command."""

    def test_formats_text_output(self, capsys):
        """Test formats command text output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "formats"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CycloneDX" in captured.out
        assert "SPDX" in captured.out

    def test_formats_json_output(self, capsys):
        """Test formats command JSON output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "formats", "--json"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "formats" in data
        assert len(data["formats"]) > 0


class TestEcosystemsCommand:
    """Tests for ecosystems command."""

    def test_ecosystems_text_output(self, capsys):
        """Test ecosystems command text output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "ecosystems"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "NPM" in captured.out
        assert "PyPI" in captured.out

    def test_ecosystems_json_output(self, capsys):
        """Test ecosystems command JSON output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "ecosystems", "--json"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "ecosystems" in data


class TestInfoCommand:
    """Tests for info command."""

    def test_info_text_output(self, capsys):
        """Test info command text output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "info"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "SBOM" in captured.out
        assert "stance.sbom" in captured.out

    def test_info_json_output(self, capsys):
        """Test info command JSON output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "info", "--json"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "stance.sbom"


class TestStatusCommand:
    """Tests for status command."""

    def test_status_text_output(self, capsys):
        """Test status command text output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "status"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Status" in captured.out or "status" in captured.out.lower()

    def test_status_json_output(self, capsys):
        """Test status command JSON output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "status", "--json"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "status" in data


class TestLicensesCommand:
    """Tests for licenses command."""

    def test_licenses_text_output(self, capsys):
        """Test licenses command text output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "licenses"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "License" in captured.out

    def test_licenses_json_output(self, capsys):
        """Test licenses command JSON output."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "licenses", "--json"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "licenses" in data

    def test_licenses_category_filter(self, capsys):
        """Test licenses command with category filter."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "licenses", "--category", "permissive", "--json"])
        result = cmd_sbom(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        for lic in data.get("licenses", []):
            assert lic.get("category") == "permissive"


# =============================================================================
# Parse Command Tests
# =============================================================================


class TestParseCommand:
    """Tests for parse command."""

    def test_parse_package_json(self, capsys):
        """Test parsing package.json."""
        content = json.dumps({
            "name": "test",
            "dependencies": {"express": "^4.18.0"},
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_sbom_parser(subparsers)

            args = parser.parse_args(["sbom", "parse", f.name])
            result = cmd_sbom(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "express" in captured.out

    def test_parse_json_output(self, capsys):
        """Test parse command JSON output."""
        content = json.dumps({
            "dependencies": {"lodash": "4.17.21"},
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_sbom_parser(subparsers)

            args = parser.parse_args(["sbom", "parse", f.name, "--json"])
            result = cmd_sbom(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "files" in data


# =============================================================================
# Generate Command Tests
# =============================================================================


class TestGenerateCommand:
    """Tests for generate command."""

    def test_generate_sbom(self, capsys):
        """Test SBOM generation."""
        content = json.dumps({
            "dependencies": {"express": "^4.18.0"},
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_sbom_parser(subparsers)

            args = parser.parse_args(["sbom", "generate", f.name])
            result = cmd_sbom(args)

            # Should succeed
            captured = capsys.readouterr()
            # Output contains SBOM JSON


# =============================================================================
# Validate Command Tests
# =============================================================================


class TestValidateCommand:
    """Tests for validate command."""

    def test_validate_cyclonedx(self, capsys):
        """Test validating CycloneDX SBOM."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(json.dumps(sbom))
            f.flush()

            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_sbom_parser(subparsers)

            args = parser.parse_args(["sbom", "validate", f.name])
            result = cmd_sbom(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "VALID" in captured.out

    def test_validate_invalid_json(self, capsys):
        """Test validating invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ invalid }")
            f.flush()

            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_sbom_parser(subparsers)

            args = parser.parse_args(["sbom", "validate", f.name])
            result = cmd_sbom(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "INVALID" in captured.out or "Error" in captured.out


# =============================================================================
# Diff Command Tests
# =============================================================================


class TestDiffCommand:
    """Tests for diff command."""

    def test_diff_sboms(self, capsys):
        """Test diffing two SBOMs."""
        sbom1 = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "pkg1", "version": "1.0.0"},
                {"name": "pkg2", "version": "2.0.0"},
            ],
        }

        sbom2 = {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "pkg1", "version": "1.1.0"},  # Changed
                {"name": "pkg3", "version": "3.0.0"},  # Added
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f1:
            f1.write(json.dumps(sbom1))
            f1.flush()

            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f2:
                f2.write(json.dumps(sbom2))
                f2.flush()

                parser = argparse.ArgumentParser()
                subparsers = parser.add_subparsers()
                add_sbom_parser(subparsers)

                args = parser.parse_args(["sbom", "diff", f1.name, f2.name])
                result = cmd_sbom(args)

                assert result == 0
                captured = capsys.readouterr()
                # Should show changes
                assert "Added" in captured.out or "Removed" in captured.out or "Changed" in captured.out


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Edge case tests for SBOM CLI."""

    def test_nonexistent_file(self, capsys):
        """Test with nonexistent file."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_sbom_parser(subparsers)

        args = parser.parse_args(["sbom", "parse", "/nonexistent/file.json"])
        result = cmd_sbom(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out or "error" in captured.out.lower()

    def test_empty_directory(self, capsys):
        """Test with empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers()
            add_sbom_parser(subparsers)

            args = parser.parse_args(["sbom", "parse", tmpdir])
            result = cmd_sbom(args)

            captured = capsys.readouterr()
            # Should handle gracefully
