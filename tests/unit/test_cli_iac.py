"""
Unit tests for CLI IaC commands.

Tests the CLI commands for Infrastructure as Code scanning.
"""

import argparse
import pytest
from unittest.mock import patch
from io import StringIO

from stance.cli_iac import (
    add_iac_parser,
    cmd_iac,
    _handle_scan,
    _handle_policies,
    _handle_policy,
    _handle_formats,
    _handle_validate,
    _handle_resources,
    _handle_stats,
    _handle_compliance,
    _handle_providers,
    _handle_resource_types,
    _handle_severity_levels,
    _handle_summary,
    _generate_sample_findings,
    _get_sample_policies,
    _get_sample_policy,
    _get_sample_formats,
    _validate_file,
    _get_sample_resources,
    _get_sample_stats,
    _get_sample_compliance,
    _get_sample_providers,
    _get_sample_resource_types,
)


class TestAddIacParser:
    """Tests for add_iac_parser function."""

    def test_parser_added(self):
        """Test that IaC parser is added to subparsers."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_iac_parser(subparsers)

        # Parse a simple command
        args = parser.parse_args(["iac", "formats"])
        assert args.iac_action == "formats"

    def test_scan_parser(self):
        """Test scan subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_iac_parser(subparsers)

        args = parser.parse_args(["iac", "scan", "/path/to/scan"])
        assert args.iac_action == "scan"
        assert args.path == "/path/to/scan"

    def test_scan_parser_with_options(self):
        """Test scan with options."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_iac_parser(subparsers)

        args = parser.parse_args(["iac", "scan", ".", "--severity", "high", "--iac-format", "terraform"])
        assert args.severity == "high"
        assert args.iac_format == "terraform"

    def test_policies_parser(self):
        """Test policies subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_iac_parser(subparsers)

        args = parser.parse_args(["iac", "policies", "--provider", "aws"])
        assert args.iac_action == "policies"
        assert args.provider == "aws"

    def test_policy_parser(self):
        """Test policy subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_iac_parser(subparsers)

        args = parser.parse_args(["iac", "policy", "iac-aws-s3-encryption"])
        assert args.iac_action == "policy"
        assert args.policy_id == "iac-aws-s3-encryption"

    def test_validate_parser(self):
        """Test validate subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_iac_parser(subparsers)

        args = parser.parse_args(["iac", "validate", "main.tf"])
        assert args.iac_action == "validate"
        assert args.path == "main.tf"

    def test_resources_parser(self):
        """Test resources subcommand parser."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_iac_parser(subparsers)

        args = parser.parse_args(["iac", "resources", "--type", "aws_s3_bucket"])
        assert args.iac_action == "resources"
        assert args.resource_type == "aws_s3_bucket"


class TestCmdIac:
    """Tests for cmd_iac function."""

    def test_no_action(self):
        """Test handling of no action specified."""
        args = argparse.Namespace(iac_action=None)
        result = cmd_iac(args)
        assert result == 1

    def test_scan_action(self):
        """Test scan action routing."""
        args = argparse.Namespace(iac_action="scan", path=".", format="text", severity=None, iac_format="all")
        result = cmd_iac(args)
        assert result == 0

    def test_policies_action(self):
        """Test policies action routing."""
        args = argparse.Namespace(iac_action="policies", format="text", provider=None, severity=None, enabled_only=False)
        result = cmd_iac(args)
        assert result == 0

    def test_unknown_action(self):
        """Test handling of unknown action."""
        args = argparse.Namespace(iac_action="unknown")
        result = cmd_iac(args)
        assert result == 1


class TestHandleScan:
    """Tests for _handle_scan function."""

    def test_scan_text_output(self):
        """Test scan with text output."""
        args = argparse.Namespace(path=".", format="text", severity=None, iac_format="all")
        result = _handle_scan(args)
        assert result == 0

    def test_scan_json_output(self, capsys):
        """Test scan with JSON output."""
        args = argparse.Namespace(path=".", format="json", severity=None, iac_format="all")
        result = _handle_scan(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "findings" in captured.out

    def test_scan_with_severity_filter(self, capsys):
        """Test scan with severity filter."""
        args = argparse.Namespace(path=".", format="json", severity="critical", iac_format="all")
        result = _handle_scan(args)
        assert result == 0


class TestHandlePolicies:
    """Tests for _handle_policies function."""

    def test_policies_text_output(self):
        """Test policies with text output."""
        args = argparse.Namespace(format="text", provider=None, severity=None, enabled_only=False)
        result = _handle_policies(args)
        assert result == 0

    def test_policies_json_output(self, capsys):
        """Test policies with JSON output."""
        args = argparse.Namespace(format="json", provider=None, severity=None, enabled_only=False)
        result = _handle_policies(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "policies" in captured.out

    def test_policies_filter_by_provider(self, capsys):
        """Test filtering policies by provider."""
        args = argparse.Namespace(format="json", provider="aws", severity=None, enabled_only=False)
        result = _handle_policies(args)
        assert result == 0


class TestHandlePolicy:
    """Tests for _handle_policy function."""

    def test_policy_found(self):
        """Test policy found."""
        args = argparse.Namespace(policy_id="iac-aws-s3-encryption", format="text")
        result = _handle_policy(args)
        assert result == 0

    def test_policy_not_found(self):
        """Test policy not found."""
        args = argparse.Namespace(policy_id="nonexistent", format="text")
        result = _handle_policy(args)
        assert result == 1


class TestHandleFormats:
    """Tests for _handle_formats function."""

    def test_formats_text_output(self):
        """Test formats with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_formats(args)
        assert result == 0

    def test_formats_json_output(self, capsys):
        """Test formats with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_formats(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "formats" in captured.out


class TestHandleValidate:
    """Tests for _handle_validate function."""

    def test_validate_terraform(self):
        """Test validating terraform file."""
        args = argparse.Namespace(path="main.tf", format="text")
        result = _handle_validate(args)
        assert result == 0

    def test_validate_yaml(self):
        """Test validating YAML file."""
        args = argparse.Namespace(path="template.yaml", format="text")
        result = _handle_validate(args)
        assert result == 0

    def test_validate_unknown(self):
        """Test validating unknown file type."""
        args = argparse.Namespace(path="unknown.xyz", format="text")
        result = _handle_validate(args)
        assert result == 0  # Still returns 0, just shows invalid


class TestHandleResources:
    """Tests for _handle_resources function."""

    def test_resources_text_output(self):
        """Test resources with text output."""
        args = argparse.Namespace(path=".", format="text", resource_type=None, provider=None)
        result = _handle_resources(args)
        assert result == 0

    def test_resources_filter_by_type(self, capsys):
        """Test filtering resources by type."""
        args = argparse.Namespace(path=".", format="json", resource_type="aws_s3_bucket", provider=None)
        result = _handle_resources(args)
        assert result == 0


class TestHandleStats:
    """Tests for _handle_stats function."""

    def test_stats_text_output(self):
        """Test stats with text output."""
        args = argparse.Namespace(path=".", format="text")
        result = _handle_stats(args)
        assert result == 0

    def test_stats_json_output(self, capsys):
        """Test stats with JSON output."""
        args = argparse.Namespace(path=".", format="json")
        result = _handle_stats(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "total_files" in captured.out


class TestHandleCompliance:
    """Tests for _handle_compliance function."""

    def test_compliance_text_output(self):
        """Test compliance with text output."""
        args = argparse.Namespace(format="text", framework=None)
        result = _handle_compliance(args)
        assert result == 0

    def test_compliance_filter_by_framework(self, capsys):
        """Test filtering compliance by framework."""
        args = argparse.Namespace(format="json", framework="CIS AWS")
        result = _handle_compliance(args)
        assert result == 0


class TestHandleProviders:
    """Tests for _handle_providers function."""

    def test_providers_text_output(self):
        """Test providers with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_providers(args)
        assert result == 0

    def test_providers_json_output(self, capsys):
        """Test providers with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_providers(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "providers" in captured.out


class TestHandleResourceTypes:
    """Tests for _handle_resource_types function."""

    def test_resource_types_text_output(self):
        """Test resource types with text output."""
        args = argparse.Namespace(format="text", provider=None)
        result = _handle_resource_types(args)
        assert result == 0

    def test_resource_types_filter_by_provider(self, capsys):
        """Test filtering resource types by provider."""
        args = argparse.Namespace(format="json", provider="aws")
        result = _handle_resource_types(args)
        assert result == 0


class TestHandleSeverityLevels:
    """Tests for _handle_severity_levels function."""

    def test_severity_levels_text_output(self):
        """Test severity levels with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_severity_levels(args)
        assert result == 0

    def test_severity_levels_json_output(self, capsys):
        """Test severity levels with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_severity_levels(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "severity_levels" in captured.out


class TestHandleSummary:
    """Tests for _handle_summary function."""

    def test_summary_text_output(self):
        """Test summary with text output."""
        args = argparse.Namespace(format="text")
        result = _handle_summary(args)
        assert result == 0

    def test_summary_json_output(self, capsys):
        """Test summary with JSON output."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0
        captured = capsys.readouterr()
        assert "module" in captured.out


class TestSampleDataGenerators:
    """Tests for sample data generator functions."""

    def test_generate_sample_findings(self):
        """Test generating sample findings."""
        findings = _generate_sample_findings(".", None, "all")
        assert "findings" in findings
        assert "summary" in findings
        assert len(findings["findings"]) > 0

    def test_generate_sample_findings_with_severity_filter(self):
        """Test generating findings with severity filter."""
        findings = _generate_sample_findings(".", "critical", "all")
        for f in findings["findings"]:
            assert f["severity"] == "critical"

    def test_get_sample_policies(self):
        """Test getting sample policies."""
        policies = _get_sample_policies(None, None, False)
        assert "policies" in policies
        assert "total" in policies
        assert len(policies["policies"]) > 0

    def test_get_sample_policies_filtered(self):
        """Test getting filtered policies."""
        policies = _get_sample_policies("aws", None, False)
        for p in policies["policies"]:
            assert "aws" in p["providers"] or not p["providers"]

    def test_get_sample_policy_found(self):
        """Test getting existing policy."""
        policy = _get_sample_policy("iac-aws-s3-encryption")
        assert "policy" in policy
        assert policy["policy"]["id"] == "iac-aws-s3-encryption"

    def test_get_sample_policy_not_found(self):
        """Test getting non-existent policy."""
        policy = _get_sample_policy("nonexistent")
        assert "error" in policy

    def test_get_sample_formats(self):
        """Test getting sample formats."""
        formats = _get_sample_formats()
        assert "formats" in formats
        assert "total" in formats
        assert formats["total"] == 6

    def test_validate_file_terraform(self):
        """Test validating terraform file."""
        result = _validate_file("main.tf")
        assert result["valid"] is True
        assert result["format"] == "terraform"

    def test_validate_file_yaml(self):
        """Test validating YAML file."""
        result = _validate_file("template.yaml")
        assert result["valid"] is True

    def test_validate_file_unknown(self):
        """Test validating unknown file."""
        result = _validate_file("unknown.xyz")
        assert result["valid"] is False

    def test_get_sample_resources(self):
        """Test getting sample resources."""
        resources = _get_sample_resources(".", None, None)
        assert "resources" in resources
        assert len(resources["resources"]) > 0

    def test_get_sample_resources_filtered(self):
        """Test getting filtered resources."""
        resources = _get_sample_resources(".", "aws_s3_bucket", None)
        for r in resources["resources"]:
            assert r["type"] == "aws_s3_bucket"

    def test_get_sample_stats(self):
        """Test getting sample stats."""
        stats = _get_sample_stats(".")
        assert "total_files" in stats
        assert "total_resources" in stats
        assert "by_format" in stats

    def test_get_sample_compliance(self):
        """Test getting sample compliance."""
        compliance = _get_sample_compliance(None)
        assert "frameworks" in compliance
        assert "total_frameworks" in compliance

    def test_get_sample_compliance_filtered(self):
        """Test getting filtered compliance."""
        compliance = _get_sample_compliance("CIS AWS")
        assert len(compliance["frameworks"]) == 1

    def test_get_sample_providers(self):
        """Test getting sample providers."""
        providers = _get_sample_providers()
        assert "providers" in providers
        assert providers["total"] == 4

    def test_get_sample_resource_types(self):
        """Test getting sample resource types."""
        types = _get_sample_resource_types(None)
        assert "resource_types" in types
        assert len(types["resource_types"]) > 0

    def test_get_sample_resource_types_filtered(self):
        """Test getting filtered resource types."""
        types = _get_sample_resource_types("aws")
        for t in types["resource_types"]:
            assert t["provider"] == "aws"
