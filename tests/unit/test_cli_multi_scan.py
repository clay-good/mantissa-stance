"""
Unit tests for Multi-Account Scanning CLI module.

Tests the command-line interface for multi-account scanning orchestration.
"""

import pytest
import argparse
import json
from unittest.mock import MagicMock, patch

from stance.cli_scanning import (
    add_scanning_parser,
    cmd_scanning,
    _handle_scan,
    _handle_progress,
    _handle_results,
    _handle_accounts,
    _handle_report,
    _handle_account_statuses,
    _handle_options,
    _handle_providers,
    _handle_stats,
    _handle_status,
    _handle_summary,
)


class TestAddScanningParser:
    """Tests for add_scanning_parser function."""

    def test_parser_creation(self):
        """Test that parser is created correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanning_parser(subparsers)

        # Should not raise
        args = parser.parse_args(["scanning", "status"])
        assert args.scanning_action == "status"

    def test_all_subcommands_available(self):
        """Test that all subcommands are available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanning_parser(subparsers)

        commands = [
            ("scan", []),
            ("progress", []),
            ("results", []),
            ("accounts", []),
            ("report", []),
            ("account-statuses", []),
            ("options", []),
            ("providers", []),
            ("stats", []),
            ("status", []),
            ("summary", []),
        ]

        for cmd, extra_args in commands:
            args = parser.parse_args(["scanning", cmd] + extra_args)
            assert args.scanning_action == cmd


class TestCmdScanning:
    """Tests for cmd_scanning handler."""

    def test_no_action_shows_error(self, capsys):
        """Test that no action shows error."""
        args = argparse.Namespace(scanning_action=None)
        result = cmd_scanning(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "No scanning action specified" in captured.out

    def test_unknown_action_shows_error(self, capsys):
        """Test that unknown action shows error."""
        args = argparse.Namespace(scanning_action="unknown")
        result = cmd_scanning(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown action" in captured.out

    def test_valid_action_routes_correctly(self):
        """Test that valid actions route to correct handlers."""
        args = argparse.Namespace(
            scanning_action="status",
            format="json",
        )
        result = cmd_scanning(args)
        assert result == 0


class TestHandleScan:
    """Tests for scan command handler."""

    def test_scan_table(self, capsys):
        """Test scan command in table format."""
        args = argparse.Namespace(
            config="default",
            parallel=3,
            timeout=300,
            continue_on_error=True,
            severity=None,
            collectors=None,
            regions=None,
            skip_accounts=None,
            include_disabled=False,
            format="table",
        )
        result = _handle_scan(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Multi-Account Scan Configuration" in captured.out
        assert "Configuration: default" in captured.out

    def test_scan_json(self, capsys):
        """Test scan command in JSON format."""
        args = argparse.Namespace(
            config="production",
            parallel=5,
            timeout=600,
            continue_on_error=True,
            severity="high",
            collectors="iam,s3",
            regions="us-east-1,us-west-2",
            skip_accounts="123456789012",
            include_disabled=False,
            format="json",
        )
        result = _handle_scan(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["config"] == "production"
        assert "options" in data


class TestHandleProgress:
    """Tests for progress command handler."""

    def test_progress_table(self, capsys):
        """Test progress in table format."""
        args = argparse.Namespace(scan_id=None, format="table")
        result = _handle_progress(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scan Progress" in captured.out
        assert "Progress:" in captured.out

    def test_progress_json(self, capsys):
        """Test progress in JSON format."""
        args = argparse.Namespace(scan_id="test-scan-123", format="json")
        result = _handle_progress(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "scan_id" in data
        assert "total_accounts" in data
        assert "progress_percent" in data


class TestHandleResults:
    """Tests for results command handler."""

    def test_results_table(self, capsys):
        """Test results in table format."""
        args = argparse.Namespace(scan_id=None, account=None, format="table")
        result = _handle_results(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scan Results" in captured.out
        assert "Summary:" in captured.out

    def test_results_json(self, capsys):
        """Test results in JSON format."""
        args = argparse.Namespace(scan_id="test-scan", account=None, format="json")
        result = _handle_results(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "scan_id" in data
        assert "summary" in data
        assert "findings_by_severity" in data


class TestHandleAccounts:
    """Tests for accounts command handler."""

    def test_accounts_table(self, capsys):
        """Test accounts in table format."""
        args = argparse.Namespace(config="default", include_disabled=False, format="table")
        result = _handle_accounts(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Configured Accounts" in captured.out
        assert "Account ID" in captured.out

    def test_accounts_json(self, capsys):
        """Test accounts in JSON format."""
        args = argparse.Namespace(config="default", include_disabled=False, format="json")
        result = _handle_accounts(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data
        assert "accounts" in data
        # Should exclude disabled accounts
        assert all(a["enabled"] for a in data["accounts"])

    def test_accounts_include_disabled(self, capsys):
        """Test accounts with disabled included."""
        args = argparse.Namespace(config="default", include_disabled=True, format="json")
        result = _handle_accounts(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        # Should include disabled accounts
        assert any(not a["enabled"] for a in data["accounts"])


class TestHandleReport:
    """Tests for report command handler."""

    def test_report_table(self, capsys):
        """Test report in table format."""
        args = argparse.Namespace(scan_id=None, format="table")
        result = _handle_report(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Organization Scan Report" in captured.out
        assert "Accounts:" in captured.out
        assert "Findings:" in captured.out

    def test_report_json(self, capsys):
        """Test report in JSON format."""
        args = argparse.Namespace(scan_id="scan-123", format="json")
        result = _handle_report(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "scan_id" in data
        assert "summary" in data
        assert "findings_by_severity" in data
        assert "top_accounts_by_findings" in data


class TestHandleAccountStatuses:
    """Tests for account-statuses command handler."""

    def test_account_statuses_table(self, capsys):
        """Test account statuses in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_account_statuses(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Account Statuses" in captured.out
        assert "PENDING" in captured.out
        assert "RUNNING" in captured.out
        assert "COMPLETED" in captured.out

    def test_account_statuses_json(self, capsys):
        """Test account statuses in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_account_statuses(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 5
        assert len(data["statuses"]) == 5


class TestHandleOptions:
    """Tests for options command handler."""

    def test_options_table(self, capsys):
        """Test options in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_options(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scan Options" in captured.out
        assert "parallel_accounts" in captured.out
        assert "timeout_per_account" in captured.out

    def test_options_json(self, capsys):
        """Test options in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_options(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 8
        assert len(data["options"]) == 8


class TestHandleProviders:
    """Tests for providers command handler."""

    def test_providers_table(self, capsys):
        """Test providers in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_providers(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Supported Cloud Providers" in captured.out
        assert "Amazon Web Services" in captured.out
        assert "Google Cloud Platform" in captured.out
        assert "Microsoft Azure" in captured.out

    def test_providers_json(self, capsys):
        """Test providers in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_providers(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 3
        assert len(data["providers"]) == 3


class TestHandleStats:
    """Tests for stats command handler."""

    def test_stats_table(self, capsys):
        """Test stats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scanning Module Statistics" in captured.out
        assert "Account Statuses" in captured.out
        assert "Features:" in captured.out

    def test_stats_json(self, capsys):
        """Test stats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["account_statuses"] == 5
        assert data["scan_options"] == 8
        assert data["cloud_providers"] == 3


class TestHandleStatus:
    """Tests for status command handler."""

    def test_status_table(self, capsys):
        """Test status in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scanning Module Status" in captured.out
        assert "Components:" in captured.out
        assert "Capabilities" in captured.out

    def test_status_json(self, capsys):
        """Test status in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "scanning"
        assert data["status"] == "operational"
        assert "components" in data
        assert "capabilities" in data


class TestHandleSummary:
    """Tests for summary command handler."""

    def test_summary_table(self, capsys):
        """Test summary in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Scanning Module Summary" in captured.out
        assert "Features:" in captured.out
        assert "Scan Workflow:" in captured.out

    def test_summary_json(self, capsys):
        """Test summary in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "scanning"
        assert "features" in data
        assert "scan_workflow" in data
        assert "data_classes" in data


class TestCLIRouting:
    """Tests for CLI command routing."""

    def test_all_handlers_exist(self):
        """Test that all handlers exist."""
        handlers = [
            _handle_scan,
            _handle_progress,
            _handle_results,
            _handle_accounts,
            _handle_report,
            _handle_account_statuses,
            _handle_options,
            _handle_providers,
            _handle_stats,
            _handle_status,
            _handle_summary,
        ]

        for handler in handlers:
            assert callable(handler)

    def test_cmd_scanning_routes_to_all_handlers(self, capsys):
        """Test that cmd_scanning routes to all handlers."""
        actions = [
            ("status", {}),
            ("summary", {}),
            ("stats", {}),
            ("account-statuses", {}),
            ("options", {}),
            ("providers", {}),
        ]

        for action, extra_args in actions:
            args = argparse.Namespace(
                scanning_action=action,
                format="json",
                **extra_args,
            )
            result = cmd_scanning(args)
            assert result == 0, f"Handler for {action} failed"


class TestScanningModuleIntegration:
    """Integration tests with scanning module structures."""

    def test_account_statuses_structure(self, capsys):
        """Test account statuses have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_account_statuses(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for status in data["statuses"]:
            assert "status" in status
            assert "description" in status
            assert "indicator" in status

    def test_options_structure(self, capsys):
        """Test options have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_options(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for opt in data["options"]:
            assert "option" in opt
            assert "type" in opt
            assert "default" in opt
            assert "description" in opt

    def test_providers_structure(self, capsys):
        """Test providers have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_providers(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for provider in data["providers"]:
            assert "provider" in provider
            assert "name" in provider
            assert "account_format" in provider
            assert "collectors" in provider

    def test_accounts_structure(self, capsys):
        """Test accounts have correct structure."""
        args = argparse.Namespace(config="default", include_disabled=True, format="json")
        _handle_accounts(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for account in data["accounts"]:
            assert "account_id" in account
            assert "name" in account
            assert "provider" in account
            assert "enabled" in account
            assert "regions" in account

    def test_status_components(self, capsys):
        """Test status includes all components."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "MultiAccountScanner" in data["components"]
        assert "ScanOptions" in data["components"]
        assert "ScanProgress" in data["components"]
        assert "AccountScanResult" in data["components"]
        assert "OrganizationScan" in data["components"]

    def test_status_capabilities(self, capsys):
        """Test status includes capabilities."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        expected_caps = [
            "parallel_account_scanning",
            "progress_tracking",
            "cross_account_aggregation",
            "findings_deduplication",
        ]
        for cap in expected_caps:
            assert cap in data["capabilities"]


class TestSummaryContent:
    """Tests for summary content."""

    def test_summary_has_features(self, capsys):
        """Test summary includes features."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert len(data["features"]) >= 5

    def test_summary_has_workflow(self, capsys):
        """Test summary includes workflow."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert len(data["scan_workflow"]) >= 5

    def test_summary_has_data_classes(self, capsys):
        """Test summary includes data classes."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "ScanOptions" in data["data_classes"]
        assert "AccountScanResult" in data["data_classes"]
        assert "ScanProgress" in data["data_classes"]
        assert "OrganizationScan" in data["data_classes"]

    def test_summary_has_cloud_support(self, capsys):
        """Test summary includes cloud support."""
        args = argparse.Namespace(format="json")
        _handle_summary(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "aws" in data["cloud_support"]
        assert "gcp" in data["cloud_support"]
        assert "azure" in data["cloud_support"]


class TestParserArguments:
    """Tests for parser argument handling."""

    def test_scan_default_arguments(self):
        """Test scan command with default arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanning_parser(subparsers)

        args = parser.parse_args(["scanning", "scan"])
        assert args.config == "default"
        assert args.parallel == 3
        assert args.timeout == 300
        assert args.format == "table"

    def test_scan_custom_arguments(self):
        """Test scan command with custom arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanning_parser(subparsers)

        args = parser.parse_args([
            "scanning", "scan",
            "--config", "production",
            "--parallel", "5",
            "--timeout", "600",
            "--severity", "high",
            "--collectors", "iam,s3",
            "--format", "json",
        ])
        assert args.config == "production"
        assert args.parallel == 5
        assert args.timeout == 600
        assert args.severity == "high"
        assert args.collectors == "iam,s3"
        assert args.format == "json"

    def test_progress_arguments(self):
        """Test progress command arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanning_parser(subparsers)

        args = parser.parse_args([
            "scanning", "progress",
            "--scan-id", "scan-123",
            "--format", "json",
        ])
        assert args.scan_id == "scan-123"
        assert args.format == "json"

    def test_results_arguments(self):
        """Test results command arguments."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_scanning_parser(subparsers)

        args = parser.parse_args([
            "scanning", "results",
            "--scan-id", "scan-456",
            "--account", "123456789012",
            "--format", "json",
        ])
        assert args.scan_id == "scan-456"
        assert args.account == "123456789012"
        assert args.format == "json"


class TestReportContent:
    """Tests for report content."""

    def test_report_has_summary(self, capsys):
        """Test report includes summary."""
        args = argparse.Namespace(scan_id=None, format="json")
        _handle_report(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "accounts_scanned" in data["summary"]
        assert "total_findings" in data["summary"]
        assert "unique_findings" in data["summary"]

    def test_report_has_findings_breakdown(self, capsys):
        """Test report includes findings breakdown."""
        args = argparse.Namespace(scan_id=None, format="json")
        _handle_report(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "findings_by_severity" in data
        assert "findings_by_provider" in data

    def test_report_has_top_accounts(self, capsys):
        """Test report includes top accounts."""
        args = argparse.Namespace(scan_id=None, format="json")
        _handle_report(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "top_accounts_by_findings" in data
        assert len(data["top_accounts_by_findings"]) > 0

    def test_report_has_critical_accounts(self, capsys):
        """Test report includes accounts with critical findings."""
        args = argparse.Namespace(scan_id=None, format="json")
        _handle_report(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "accounts_with_critical_findings" in data


class TestProgressContent:
    """Tests for progress content."""

    def test_progress_has_counts(self, capsys):
        """Test progress includes account counts."""
        args = argparse.Namespace(scan_id=None, format="json")
        _handle_progress(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "total_accounts" in data
        assert "completed_accounts" in data
        assert "failed_accounts" in data
        assert "pending_accounts" in data

    def test_progress_has_metrics(self, capsys):
        """Test progress includes metrics."""
        args = argparse.Namespace(scan_id=None, format="json")
        _handle_progress(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "progress_percent" in data
        assert "findings_so_far" in data
        assert "is_complete" in data

    def test_progress_has_timestamps(self, capsys):
        """Test progress includes timestamps."""
        args = argparse.Namespace(scan_id=None, format="json")
        _handle_progress(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "started_at" in data
        assert "estimated_completion" in data
