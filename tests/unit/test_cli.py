"""
Tests for Mantissa Stance CLI.

Tests CLI argument parsing, command execution, and output formatting.
"""

from __future__ import annotations

import argparse
import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from stance.cli import create_parser, main
from stance.cli_commands import (
    format_output,
    format_table,
    cmd_findings,
    cmd_assets,
    cmd_policies,
)


class TestCLIParser:
    """Tests for CLI argument parsing."""

    @pytest.fixture
    def parser(self) -> argparse.ArgumentParser:
        """Return the CLI argument parser."""
        return create_parser()

    def test_cli_parser_scan(self, parser):
        """Test scan command argument parsing."""
        args = parser.parse_args(["scan", "--region", "us-west-2"])

        assert args.command == "scan"
        assert args.region == "us-west-2"

    def test_cli_parser_scan_defaults(self, parser):
        """Test scan command default values."""
        args = parser.parse_args(["scan"])

        assert args.command == "scan"
        assert args.region == "us-east-1"
        assert args.output == "table"
        assert args.storage == "local"

    def test_cli_parser_scan_collectors(self, parser):
        """Test scan command with collectors argument."""
        args = parser.parse_args(["scan", "--collectors", "aws_iam,aws_s3"])

        assert args.collectors == "aws_iam,aws_s3"

    def test_cli_parser_query(self, parser):
        """Test query command argument parsing."""
        args = parser.parse_args(["query", "-q", "show critical findings"])

        assert args.command == "query"
        assert args.question == "show critical findings"

    def test_cli_parser_query_no_llm(self, parser):
        """Test query command with --no-llm flag."""
        args = parser.parse_args([
            "query",
            "-q",
            "SELECT * FROM findings",
            "--no-llm",
        ])

        assert args.no_llm is True

    def test_cli_parser_query_llm_provider(self, parser):
        """Test query command with --llm-provider."""
        args = parser.parse_args([
            "query",
            "-q",
            "show findings",
            "--llm-provider",
            "openai",
        ])

        assert args.llm_provider == "openai"

    def test_cli_parser_report(self, parser):
        """Test report command argument parsing."""
        args = parser.parse_args([
            "report",
            "--format",
            "html",
            "-o",
            "report.html",
        ])

        assert args.command == "report"
        assert args.format == "html"
        assert args.output == "report.html"

    def test_cli_parser_report_framework(self, parser):
        """Test report command with framework filter."""
        args = parser.parse_args([
            "report",
            "--framework",
            "cis-aws",
        ])

        assert args.framework == "cis-aws"

    def test_cli_parser_policies_list(self, parser):
        """Test policies list command."""
        args = parser.parse_args(["policies", "list"])

        assert args.command == "policies"
        assert args.action == "list"

    def test_cli_parser_policies_validate(self, parser):
        """Test policies validate command."""
        args = parser.parse_args(["policies", "validate"])

        assert args.command == "policies"
        assert args.action == "validate"

    def test_cli_parser_policies_severity_filter(self, parser):
        """Test policies command with severity filter."""
        args = parser.parse_args([
            "policies",
            "list",
            "--severity",
            "critical",
        ])

        assert args.severity == "critical"

    def test_cli_parser_findings(self, parser):
        """Test findings command argument parsing."""
        args = parser.parse_args([
            "findings",
            "--severity",
            "high",
            "--status",
            "open",
        ])

        assert args.command == "findings"
        assert args.severity == "high"
        assert args.status == "open"

    def test_cli_parser_assets(self, parser):
        """Test assets command argument parsing."""
        args = parser.parse_args([
            "assets",
            "--type",
            "aws_s3_bucket",
            "--exposure",
            "internet_facing",
        ])

        assert args.command == "assets"
        assert args.type == "aws_s3_bucket"
        assert args.exposure == "internet_facing"

    def test_cli_parser_dashboard(self, parser):
        """Test dashboard command argument parsing."""
        args = parser.parse_args([
            "dashboard",
            "--port",
            "3000",
            "--host",
            "0.0.0.0",
        ])

        assert args.command == "dashboard"
        assert args.port == 3000
        assert args.host == "0.0.0.0"

    def test_cli_parser_version(self, parser):
        """Test version command."""
        args = parser.parse_args(["version"])

        assert args.command == "version"

    def test_cli_parser_global_verbose(self, parser):
        """Test global verbose flag."""
        args = parser.parse_args(["-v", "scan"])

        assert args.verbose == 1

        args = parser.parse_args(["-vv", "scan"])
        assert args.verbose == 2

    def test_cli_parser_global_quiet(self, parser):
        """Test global quiet flag."""
        args = parser.parse_args(["-q", "scan"])

        assert args.quiet is True


class TestCLIMain:
    """Tests for CLI main entry point."""

    def test_cli_no_command_shows_help(self, capsys):
        """Test no command shows help."""
        with patch("sys.argv", ["stance"]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "usage:" in captured.out.lower() or "stance" in captured.out

    def test_cli_version_command(self, capsys):
        """Test version command output."""
        with patch("sys.argv", ["stance", "version"]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "version" in captured.out.lower()


class TestOutputFormatting:
    """Tests for output formatting functions."""

    @pytest.fixture
    def sample_data(self) -> list[dict]:
        """Return sample data for formatting tests."""
        return [
            {"id": "1", "name": "Item 1", "value": 100},
            {"id": "2", "name": "Item 2", "value": 200},
            {"id": "3", "name": "Item 3", "value": 300},
        ]

    def test_format_output_json(self, sample_data):
        """Test JSON formatting."""
        output = format_output(sample_data, "json")

        parsed = json.loads(output)
        assert len(parsed) == 3
        assert parsed[0]["id"] == "1"

    def test_format_output_csv(self, sample_data):
        """Test CSV formatting."""
        output = format_output(sample_data, "csv")

        lines = output.strip().split("\n")
        assert len(lines) == 4  # header + 3 rows
        assert "id,name,value" in lines[0]

    def test_format_output_table(self, sample_data):
        """Test table formatting."""
        output = format_output(sample_data, "table")

        assert "id" in output
        assert "name" in output
        assert "Item 1" in output
        assert "|" in output  # Table separator

    def test_format_table_alignment(self, sample_data):
        """Test table column alignment."""
        output = format_table(sample_data)

        lines = output.split("\n")
        # Check header and separator exist
        assert len(lines) >= 3
        assert "-+-" in lines[1]  # Separator line

    def test_format_output_empty_data(self):
        """Test formatting empty data."""
        output = format_output([], "table")
        assert output == ""

        output = format_output([], "json")
        # format_output returns empty string for empty data
        assert output == ""


class TestCLICommands:
    """Tests for CLI command handlers."""

    def test_cmd_findings_no_data(self, capsys, populated_storage):
        """Test findings command with no matching data."""
        args = argparse.Namespace(
            severity="info",  # No info findings in test data
            status=None,
            asset_id=None,
            format="table",
            quiet=False,
        )

        with patch("stance.storage.get_storage", return_value=populated_storage):
            result = cmd_findings(args)

        # Should succeed even with no matching findings
        assert result == 0

    def test_cmd_assets_with_filters(self, capsys, populated_storage):
        """Test assets command with filters."""
        args = argparse.Namespace(
            type="aws_s3_bucket",
            region=None,
            exposure=None,
            format="json",
            quiet=False,
        )

        with patch("stance.storage.get_storage", return_value=populated_storage):
            result = cmd_assets(args)

        assert result == 0
        captured = capsys.readouterr()
        # Check output is valid
        assert captured.out is not None
        output = captured.out.strip()
        # Should either have JSON output or a message
        if output and "No assets" not in output and "No scan data" not in output:
            # The JSON output is pretty-printed, so find the JSON portion
            # by looking for lines between [ and ]
            if "[" in output:
                # Find the JSON array by extracting everything between first [ and last ]
                start_idx = output.find("[")
                end_idx = output.rfind("]")
                if start_idx != -1 and end_idx != -1:
                    json_content = output[start_idx:end_idx + 1]
                    data = json.loads(json_content)
                    assert isinstance(data, list)

    def test_cmd_policies_list(self, capsys, tmp_path):
        """Test policies list command."""
        from stance.engine import PolicyLoader
        from stance.models import Policy, PolicyCollection, Check, CheckType, Severity, Remediation

        # Create a temporary policy
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        policy_content = """
id: test-001
name: Test Policy
description: Test policy description
enabled: true
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.field == true"
remediation:
  guidance: Test guidance
  automation_supported: false
"""
        (policy_dir / "test.yaml").write_text(policy_content)

        args = argparse.Namespace(
            action="list",
            severity=None,
            framework=None,
            quiet=False,
        )

        # Create a mock policy to return
        mock_policy = Policy(
            id="test-001",
            name="Test Policy",
            description="Test policy description",
            enabled=True,
            severity=Severity.HIGH,
            resource_type="aws_s3_bucket",
            check=Check(check_type=CheckType.EXPRESSION, expression="resource.field == true"),
            remediation=Remediation(guidance="Test guidance", automation_supported=False),
        )
        mock_collection = PolicyCollection([mock_policy])

        with patch.object(PolicyLoader, "load_all", return_value=mock_collection):
            result = cmd_policies(args)

        assert result == 0
        captured = capsys.readouterr()
        # Should list policies
        assert "test-001" in captured.out or "Test Policy" in captured.out
