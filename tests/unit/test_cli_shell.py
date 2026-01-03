"""
Unit tests for the interactive shell module.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_shell import StanceShell, cmd_shell


class TestStanceShell:
    """Tests for StanceShell class."""

    def test_shell_initialization(self):
        """Test shell initializes with correct defaults."""
        shell = StanceShell()

        assert shell._storage_type == "local"
        assert shell._verbose is False
        assert shell._llm_provider is None
        assert shell._last_results == []
        assert shell._history == []

    def test_shell_with_custom_options(self):
        """Test shell with custom initialization options."""
        shell = StanceShell(
            storage_type="s3",
            verbose=True,
            llm_provider="openai",
        )

        assert shell._storage_type == "s3"
        assert shell._verbose is True
        assert shell._llm_provider == "openai"

    def test_shell_prompt(self):
        """Test shell has correct prompt."""
        shell = StanceShell()
        assert shell.prompt == "stance> "

    def test_shell_intro(self):
        """Test shell has intro banner."""
        shell = StanceShell()
        assert "Mantissa Stance Interactive Shell" in shell.intro
        assert "help" in shell.intro.lower()

    def test_do_quit(self):
        """Test quit command returns True to exit."""
        shell = StanceShell()
        result = shell.do_quit("")
        assert result is True

    def test_do_exit(self):
        """Test exit command returns True to exit."""
        shell = StanceShell()
        result = shell.do_exit("")
        assert result is True

    def test_do_EOF(self):
        """Test EOF (Ctrl+D) returns True to exit."""
        shell = StanceShell()
        result = shell.do_EOF("")
        assert result is True

    def test_do_version(self, capsys):
        """Test version command shows version."""
        shell = StanceShell()
        shell.do_version("")

        captured = capsys.readouterr()
        assert "Mantissa Stance" in captured.out

    def test_do_clear(self, capsys):
        """Test clear command outputs ANSI escape codes."""
        shell = StanceShell()
        shell.do_clear("")

        captured = capsys.readouterr()
        assert "\033[2J" in captured.out

    def test_emptyline(self):
        """Test empty line does not repeat last command."""
        shell = StanceShell()
        result = shell.emptyline()
        assert result is False

    def test_precmd_records_history(self):
        """Test commands are recorded in history."""
        shell = StanceShell()
        shell.precmd("findings")
        shell.precmd("assets")

        assert "findings" in shell._history
        assert "assets" in shell._history

    def test_precmd_ignores_empty(self):
        """Test empty commands are not recorded."""
        shell = StanceShell()
        shell.precmd("")
        shell.precmd("   ")

        assert len(shell._history) == 0


class TestShellFindingsCommands:
    """Tests for findings-related shell commands."""

    @pytest.fixture
    def shell_with_storage(self):
        """Create shell with mocked storage."""
        shell = StanceShell()
        shell._storage = MagicMock()
        return shell

    def test_do_findings_no_results(self, shell_with_storage, capsys):
        """Test findings command with no results."""
        shell_with_storage._storage.query_findings.return_value = []

        shell_with_storage.do_findings("")

        captured = capsys.readouterr()
        assert "No findings found" in captured.out

    def test_do_findings_with_results(self, shell_with_storage, capsys):
        """Test findings command with results."""
        shell_with_storage._storage.query_findings.return_value = [
            {
                "id": "finding-1",
                "severity": "critical",
                "rule_id": "aws-s3-001",
                "asset_id": "bucket-123",
            },
            {
                "id": "finding-2",
                "severity": "high",
                "rule_id": "aws-iam-001",
                "asset_id": "role-456",
            },
        ]

        shell_with_storage.do_findings("")

        captured = capsys.readouterr()
        assert "finding-1" in captured.out
        assert "critical" in captured.out
        assert "Total: 2 findings" in captured.out

    def test_do_findings_with_severity_filter(self, shell_with_storage):
        """Test findings command with severity filter."""
        shell_with_storage._storage.query_findings.return_value = []

        shell_with_storage.do_findings("--severity critical")

        call_args = shell_with_storage._storage.query_findings.call_args[0][0]
        assert "severity = 'critical'" in call_args

    def test_do_findings_with_limit(self, shell_with_storage):
        """Test findings command with limit option."""
        shell_with_storage._storage.query_findings.return_value = []

        shell_with_storage.do_findings("--limit 5")

        call_args = shell_with_storage._storage.query_findings.call_args[0][0]
        assert "LIMIT 5" in call_args

    def test_do_findings_json_output(self, shell_with_storage, capsys):
        """Test findings command with JSON output."""
        shell_with_storage._storage.query_findings.return_value = [
            {"id": "finding-1", "severity": "critical"},
        ]

        shell_with_storage.do_findings("--json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result[0]["id"] == "finding-1"

    def test_do_finding_detail(self, shell_with_storage, capsys):
        """Test finding detail command."""
        shell_with_storage._storage.query_findings.return_value = [
            {
                "id": "finding-123",
                "severity": "critical",
                "rule_id": "aws-s3-001",
                "asset_id": "bucket-test",
                "asset_type": "aws_s3_bucket",
                "status": "open",
                "description": "Public access enabled",
            },
        ]

        shell_with_storage.do_finding("finding-123")

        captured = capsys.readouterr()
        assert "finding-123" in captured.out
        assert "critical" in captured.out
        assert "Public access enabled" in captured.out

    def test_do_finding_not_found(self, shell_with_storage, capsys):
        """Test finding command when not found."""
        shell_with_storage._storage.query_findings.return_value = []

        shell_with_storage.do_finding("nonexistent")

        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_do_finding_no_id(self, shell_with_storage, capsys):
        """Test finding command with no ID."""
        shell_with_storage.do_finding("")

        captured = capsys.readouterr()
        assert "Usage:" in captured.out


class TestShellAssetsCommands:
    """Tests for assets-related shell commands."""

    @pytest.fixture
    def shell_with_storage(self):
        """Create shell with mocked storage."""
        shell = StanceShell()
        shell._storage = MagicMock()
        return shell

    def test_do_assets_no_results(self, shell_with_storage, capsys):
        """Test assets command with no results."""
        shell_with_storage._storage.query_assets.return_value = []

        shell_with_storage.do_assets("")

        captured = capsys.readouterr()
        assert "No assets found" in captured.out

    def test_do_assets_with_results(self, shell_with_storage, capsys):
        """Test assets command with results."""
        shell_with_storage._storage.query_assets.return_value = [
            {
                "id": "bucket-123",
                "asset_type": "aws_s3_bucket",
                "region": "us-east-1",
            },
            {
                "id": "instance-456",
                "asset_type": "aws_ec2_instance",
                "region": "us-west-2",
            },
        ]

        shell_with_storage.do_assets("")

        captured = capsys.readouterr()
        assert "bucket-123" in captured.out
        assert "aws_s3_bucket" in captured.out
        assert "Total: 2 assets" in captured.out

    def test_do_assets_with_type_filter(self, shell_with_storage):
        """Test assets command with type filter."""
        shell_with_storage._storage.query_assets.return_value = []

        shell_with_storage.do_assets("--type s3")

        call_args = shell_with_storage._storage.query_assets.call_args[0][0]
        assert "asset_type LIKE '%s3%'" in call_args

    def test_do_asset_detail(self, shell_with_storage, capsys):
        """Test asset detail command."""
        shell_with_storage._storage.query_assets.return_value = [
            {
                "id": "bucket-test",
                "asset_type": "aws_s3_bucket",
                "region": "us-east-1",
                "account_id": "123456789012",
                "tags": {"Name": "test-bucket"},
            },
        ]

        shell_with_storage.do_asset("bucket-test")

        captured = capsys.readouterr()
        assert "bucket-test" in captured.out
        assert "aws_s3_bucket" in captured.out
        assert "us-east-1" in captured.out


class TestShellQueryCommands:
    """Tests for query-related shell commands."""

    @pytest.fixture
    def shell_with_storage(self):
        """Create shell with mocked storage."""
        shell = StanceShell()
        shell._storage = MagicMock()
        return shell

    def test_do_sql_findings_query(self, shell_with_storage, capsys):
        """Test SQL query against findings table."""
        shell_with_storage._storage.query_findings.return_value = [
            {"id": "f1", "severity": "critical"},
        ]

        shell_with_storage.do_sql("SELECT * FROM findings WHERE severity = 'critical'")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result[0]["id"] == "f1"

    def test_do_sql_assets_query(self, shell_with_storage, capsys):
        """Test SQL query against assets table."""
        shell_with_storage._storage.query_assets.return_value = [
            {"id": "a1", "asset_type": "s3"},
        ]

        shell_with_storage.do_sql("SELECT * FROM assets WHERE asset_type = 's3'")

        shell_with_storage._storage.query_assets.assert_called_once()

    def test_do_sql_non_select_rejected(self, shell_with_storage, capsys):
        """Test non-SELECT queries are rejected."""
        shell_with_storage.do_sql("DELETE FROM findings")

        captured = capsys.readouterr()
        assert "Only SELECT queries are allowed" in captured.out

    def test_do_sql_no_query(self, shell_with_storage, capsys):
        """Test SQL command with no query."""
        shell_with_storage.do_sql("")

        captured = capsys.readouterr()
        assert "Usage:" in captured.out

    def test_do_query_no_llm(self, capsys):
        """Test natural language query without LLM."""
        shell = StanceShell()
        shell.do_query("Show me all critical findings")

        captured = capsys.readouterr()
        assert "LLM provider not configured" in captured.out

    def test_default_handles_sql(self, shell_with_storage, capsys):
        """Test default handler recognizes SQL."""
        shell_with_storage._storage.query_findings.return_value = []

        shell_with_storage.default("SELECT * FROM findings")

        captured = capsys.readouterr()
        assert "No results found" in captured.out

    def test_default_unknown_command(self, capsys):
        """Test default handler for unknown commands."""
        shell = StanceShell()
        shell.default("foobar")

        captured = capsys.readouterr()
        assert "Unknown command" in captured.out


class TestShellPolicyCommands:
    """Tests for policy-related shell commands."""

    def test_do_policies(self, capsys):
        """Test policies command lists policies."""
        with patch("stance.engine.PolicyLoader") as mock_loader:
            mock_policy = MagicMock()
            mock_policy.id = "aws-s3-001"
            mock_policy.name = "S3 bucket public access"
            mock_policy.severity.value = "critical"
            mock_loader.return_value.load_all.return_value = [mock_policy]

            shell = StanceShell()
            shell.do_policies("")

            captured = capsys.readouterr()
            assert "aws-s3-001" in captured.out
            assert "critical" in captured.out

    def test_do_policies_with_severity_filter(self, capsys):
        """Test policies command with severity filter."""
        with patch("stance.engine.PolicyLoader") as mock_loader:
            critical_policy = MagicMock()
            critical_policy.id = "aws-s3-001"
            critical_policy.name = "S3 public access"
            critical_policy.severity.value = "critical"

            high_policy = MagicMock()
            high_policy.id = "aws-iam-001"
            high_policy.name = "IAM policy"
            high_policy.severity.value = "high"

            mock_loader.return_value.load_all.return_value = [critical_policy, high_policy]

            shell = StanceShell()
            shell.do_policies("--severity critical")

            captured = capsys.readouterr()
            assert "aws-s3-001" in captured.out
            assert "aws-iam-001" not in captured.out

    def test_do_policy_detail(self, capsys):
        """Test policy detail command."""
        with patch("stance.engine.PolicyLoader") as mock_loader:
            mock_policy = MagicMock()
            mock_policy.id = "aws-s3-001"
            mock_policy.name = "S3 bucket public access"
            mock_policy.severity.value = "critical"
            mock_policy.resource_type = "aws_s3_bucket"
            mock_policy.enabled = True
            mock_policy.description = "Ensure S3 buckets are not public"
            mock_policy.remediation.guidance = "Disable public access"
            mock_policy.tags = ["s3", "security"]
            mock_loader.return_value.load_all.return_value = [mock_policy]

            shell = StanceShell()
            shell.do_policy("aws-s3-001")

            captured = capsys.readouterr()
            assert "aws-s3-001" in captured.out
            assert "S3 bucket public access" in captured.out
            assert "Ensure S3 buckets are not public" in captured.out


class TestShellSummaryCommand:
    """Tests for summary command."""

    def test_do_summary(self, capsys):
        """Test summary command."""
        shell = StanceShell()
        shell._storage = MagicMock()
        shell._storage.query_findings.return_value = [
            {"severity": "critical", "count": 5},
            {"severity": "high", "count": 10},
        ]
        shell._storage.query_assets.return_value = [{"count": 100}]

        shell.do_summary("")

        captured = capsys.readouterr()
        assert "POSTURE SUMMARY" in captured.out
        assert "Total Assets: 100" in captured.out
        assert "CRITICAL" in captured.out

    def test_do_summary_json(self, capsys):
        """Test summary command with JSON output."""
        shell = StanceShell()
        shell._storage = MagicMock()
        shell._storage.query_findings.return_value = [
            {"severity": "critical", "count": 5},
        ]
        shell._storage.query_assets.return_value = [{"count": 50}]

        shell.do_summary("--json")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "total_assets" in result
        assert result["total_assets"] == 50


class TestShellUtilityCommands:
    """Tests for utility commands."""

    def test_do_last_no_results(self, capsys):
        """Test last command with no previous results."""
        shell = StanceShell()
        shell.do_last("")

        captured = capsys.readouterr()
        assert "No previous results" in captured.out

    def test_do_last_with_results(self, capsys):
        """Test last command with previous results."""
        shell = StanceShell()
        shell._last_results = [{"id": "test-1"}, {"id": "test-2"}]

        shell.do_last("")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert len(result) == 2

    def test_do_last_with_limit(self, capsys):
        """Test last command with limit."""
        shell = StanceShell()
        shell._last_results = [{"id": f"test-{i}"} for i in range(10)]

        shell.do_last("3")

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert len(result) == 3

    def test_do_count(self, capsys):
        """Test count command."""
        shell = StanceShell()
        shell._last_results = [{"id": i} for i in range(5)]

        shell.do_count("")

        captured = capsys.readouterr()
        assert "5" in captured.out

    def test_do_history(self, capsys):
        """Test history command."""
        shell = StanceShell()
        shell._history = ["findings", "assets", "summary"]

        shell.do_history("")

        captured = capsys.readouterr()
        assert "findings" in captured.out
        assert "assets" in captured.out
        assert "summary" in captured.out

    def test_do_set_verbose(self, capsys):
        """Test set verbose command."""
        shell = StanceShell()
        assert shell._verbose is False

        shell.do_set("verbose on")
        assert shell._verbose is True

        shell.do_set("verbose off")
        assert shell._verbose is False

    def test_do_set_llm(self, capsys):
        """Test set llm command."""
        shell = StanceShell()
        shell.do_set("llm openai")

        assert shell._llm_provider == "openai"

    def test_do_set_show_current(self, capsys):
        """Test set command shows current settings."""
        shell = StanceShell()
        shell.do_set("")

        captured = capsys.readouterr()
        assert "verbose" in captured.out
        assert "storage" in captured.out

    def test_help_commands(self, capsys):
        """Test help commands output."""
        shell = StanceShell()
        shell.help_commands()

        captured = capsys.readouterr()
        assert "Available Commands" in captured.out
        assert "findings" in captured.out
        assert "assets" in captured.out
        assert "sql" in captured.out


class TestCmdShell:
    """Tests for cmd_shell function."""

    def test_cmd_shell_basic(self):
        """Test cmd_shell function with mock shell."""
        with patch("stance.cli_shell.StanceShell") as mock_shell_class:
            mock_shell = MagicMock()
            mock_shell.cmdloop.return_value = None
            mock_shell_class.return_value = mock_shell

            args = argparse.Namespace(
                storage="local",
                verbose=0,
                llm_provider=None,
            )
            result = cmd_shell(args)

            assert result == 0
            mock_shell.cmdloop.assert_called_once()

    def test_cmd_shell_keyboard_interrupt(self):
        """Test cmd_shell handles keyboard interrupt."""
        with patch("stance.cli_shell.StanceShell") as mock_shell_class:
            mock_shell = MagicMock()
            mock_shell.cmdloop.side_effect = KeyboardInterrupt()
            mock_shell_class.return_value = mock_shell

            args = argparse.Namespace(
                storage="local",
                verbose=0,
                llm_provider=None,
            )
            result = cmd_shell(args)

            assert result == 0

    def test_cmd_shell_with_options(self):
        """Test cmd_shell passes options to shell."""
        with patch("stance.cli_shell.StanceShell") as mock_shell_class:
            mock_shell = MagicMock()
            mock_shell_class.return_value = mock_shell

            args = argparse.Namespace(
                storage="s3",
                verbose=1,
                llm_provider="openai",
            )
            cmd_shell(args)

            mock_shell_class.assert_called_with(
                storage_type="s3",
                verbose=True,
                llm_provider="openai",
            )


class TestShellStorageLazyLoading:
    """Tests for storage lazy loading."""

    def test_storage_lazy_loaded(self):
        """Test storage is lazily loaded on first access."""
        with patch("stance.storage.get_storage") as mock_get_storage:
            mock_storage = MagicMock()
            mock_get_storage.return_value = mock_storage

            shell = StanceShell()

            # Storage not loaded yet
            mock_get_storage.assert_not_called()

            # Access storage
            _ = shell.storage

            # Now loaded
            mock_get_storage.assert_called_once_with("local")

    def test_storage_cached(self):
        """Test storage is cached after first load."""
        with patch("stance.storage.get_storage") as mock_get_storage:
            mock_storage = MagicMock()
            mock_get_storage.return_value = mock_storage

            shell = StanceShell()

            # Access twice
            _ = shell.storage
            _ = shell.storage

            # Only loaded once
            mock_get_storage.assert_called_once()
