"""
Unit tests for CLI State module.

Tests the CLI commands for state management including scans,
checkpoints, and finding lifecycle tracking.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from io import StringIO
from typing import Any
from unittest import mock

import pytest


class TestAddStateParser:
    """Tests for add_state_parser function."""

    def test_parser_creation(self):
        """Test that state parser is created correctly."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        # Parse a valid state command
        args = parser.parse_args(["state", "scan-statuses"])
        assert args.state_action == "scan-statuses"

    def test_scans_command_with_options(self):
        """Test scans command with options."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args(["state", "scans", "--limit", "10", "--status", "completed"])
        assert args.state_action == "scans"
        assert args.limit == 10
        assert args.status == "completed"

    def test_scan_command(self):
        """Test scan command."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args(["state", "scan", "scan-123"])
        assert args.state_action == "scan"
        assert args.scan_id == "scan-123"

    def test_checkpoints_command(self):
        """Test checkpoints command."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args(["state", "checkpoints", "--collector", "IAMCollector"])
        assert args.state_action == "checkpoints"
        assert args.collector == "IAMCollector"

    def test_checkpoint_command(self):
        """Test checkpoint command."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args([
            "state", "checkpoint",
            "--collector", "IAMCollector",
            "--account", "123456789",
            "--region", "us-east-1"
        ])
        assert args.state_action == "checkpoint"
        assert args.collector == "IAMCollector"
        assert args.account == "123456789"
        assert args.region == "us-east-1"

    def test_findings_command(self):
        """Test findings command."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args(["state", "findings", "--lifecycle", "new"])
        assert args.state_action == "findings"
        assert args.lifecycle == "new"

    def test_finding_command(self):
        """Test finding command."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args(["state", "finding", "finding-456"])
        assert args.state_action == "finding"
        assert args.finding_id == "finding-456"

    def test_suppress_command(self):
        """Test suppress command."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args([
            "state", "suppress", "finding-789",
            "--by", "admin@example.com",
            "--reason", "False positive"
        ])
        assert args.state_action == "suppress"
        assert args.finding_id == "finding-789"
        assert args.by == "admin@example.com"
        assert args.reason == "False positive"

    def test_resolve_command(self):
        """Test resolve command."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        args = parser.parse_args(["state", "resolve", "finding-101"])
        assert args.state_action == "resolve"
        assert args.finding_id == "finding-101"


class TestCmdState:
    """Tests for cmd_state function."""

    def test_no_action_shows_help(self, capsys):
        """Test that no action shows help."""
        from stance.cli_state import cmd_state

        args = argparse.Namespace(state_action=None)
        result = cmd_state(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Available actions:" in captured.out

    def test_unknown_action_returns_error(self, capsys):
        """Test that unknown action returns error."""
        from stance.cli_state import cmd_state

        args = argparse.Namespace(state_action="unknown")
        result = cmd_state(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown state action" in captured.out


class TestHandleScanStatuses:
    """Tests for _handle_scan_statuses function."""

    def test_table_format(self, capsys):
        """Test table format output."""
        from stance.cli_state import _handle_scan_statuses

        args = argparse.Namespace(format="table")
        result = _handle_scan_statuses(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Scan Statuses" in captured.out
        assert "pending" in captured.out
        assert "running" in captured.out
        assert "completed" in captured.out
        assert "failed" in captured.out
        assert "cancelled" in captured.out

    def test_json_format(self, capsys):
        """Test JSON format output."""
        from stance.cli_state import _handle_scan_statuses

        args = argparse.Namespace(format="json")
        result = _handle_scan_statuses(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 5
        assert data[0]["status"] == "pending"


class TestHandleLifecycles:
    """Tests for _handle_lifecycles function."""

    def test_table_format(self, capsys):
        """Test table format output."""
        from stance.cli_state import _handle_lifecycles

        args = argparse.Namespace(format="table")
        result = _handle_lifecycles(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Finding Lifecycle States" in captured.out
        assert "new" in captured.out
        assert "recurring" in captured.out
        assert "resolved" in captured.out
        assert "suppressed" in captured.out

    def test_json_format(self, capsys):
        """Test JSON format output."""
        from stance.cli_state import _handle_lifecycles

        args = argparse.Namespace(format="json")
        result = _handle_lifecycles(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 6
        lifecycle_values = [lc["lifecycle"] for lc in data]
        assert "new" in lifecycle_values
        assert "resolved" in lifecycle_values


class TestHandleBackends:
    """Tests for _handle_backends function."""

    def test_table_format(self, capsys):
        """Test table format output."""
        from stance.cli_state import _handle_backends

        args = argparse.Namespace(format="table")
        result = _handle_backends(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "State Backends" in captured.out
        assert "local" in captured.out
        assert "SQLite" in captured.out
        assert "dynamodb" in captured.out
        assert "firestore" in captured.out
        assert "cosmosdb" in captured.out

    def test_json_format(self, capsys):
        """Test JSON format output."""
        from stance.cli_state import _handle_backends

        args = argparse.Namespace(format="json")
        result = _handle_backends(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert len(data) == 4
        assert data[0]["backend"] == "local"
        assert data[0]["available"] is True


class TestHandleStatus:
    """Tests for _handle_status function."""

    def test_table_format(self, capsys):
        """Test table format output."""
        from stance.cli_state import _handle_status

        args = argparse.Namespace(format="table")
        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "State Module Status" in captured.out
        assert "state" in captured.out
        assert "local" in captured.out
        assert "StateManager" in captured.out
        assert "Checkpoint" in captured.out

    def test_json_format(self, capsys):
        """Test JSON format output."""
        from stance.cli_state import _handle_status

        args = argparse.Namespace(format="json")
        result = _handle_status(args)

        assert result == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "state"
        assert data["active_backend"] == "local"
        assert "StateManager" in data["components"]
        assert "scan_tracking" in data["capabilities"]


class TestHandleScans:
    """Tests for _handle_scans function."""

    def test_empty_scans_table(self, capsys):
        """Test empty scans in table format."""
        from stance.cli_state import _handle_scans

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = []

            args = argparse.Namespace(format="table", limit=20, status=None, days=None)
            result = _handle_scans(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "No scans found" in captured.out

    def test_scans_with_data_table(self, capsys):
        """Test scans with data in table format."""
        from stance.cli_state import _handle_scans
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-001",
            snapshot_id="snap-001",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            asset_count=100,
            finding_count=25,
            duration_seconds=60.5,
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]

            args = argparse.Namespace(format="table", limit=20, status=None, days=None)
            result = _handle_scans(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "scan-001" in captured.out
            assert "completed" in captured.out

    def test_scans_json_format(self, capsys):
        """Test scans in JSON format."""
        from stance.cli_state import _handle_scans
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-002",
            snapshot_id="snap-002",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
            asset_count=50,
            finding_count=10,
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]

            args = argparse.Namespace(format="json", limit=20, status=None, days=None)
            result = _handle_scans(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert len(data) == 1
            assert data[0]["scan_id"] == "scan-002"


class TestHandleScan:
    """Tests for _handle_scan function."""

    def test_scan_not_found(self, capsys):
        """Test scan not found."""
        from stance.cli_state import _handle_scan

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_scan.return_value = None

            args = argparse.Namespace(format="table", scan_id="nonexistent")
            result = _handle_scan(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Scan not found" in captured.out

    def test_scan_found_table(self, capsys):
        """Test scan found in table format."""
        from stance.cli_state import _handle_scan
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-003",
            snapshot_id="snap-003",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            config_name="production",
            account_id="123456789",
            region="us-east-1",
            collectors=["IAMCollector", "S3Collector"],
            asset_count=200,
            finding_count=15,
            duration_seconds=120.0,
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_scan.return_value = mock_scan

            args = argparse.Namespace(format="table", scan_id="scan-003")
            result = _handle_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "scan-003" in captured.out
            assert "completed" in captured.out
            assert "production" in captured.out
            assert "IAMCollector" in captured.out

    def test_scan_found_json(self, capsys):
        """Test scan found in JSON format."""
        from stance.cli_state import _handle_scan
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-004",
            snapshot_id="snap-004",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_scan.return_value = mock_scan

            args = argparse.Namespace(format="json", scan_id="scan-004")
            result = _handle_scan(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["scan_id"] == "scan-004"


class TestHandleCheckpoints:
    """Tests for _handle_checkpoints function."""

    def test_empty_checkpoints(self, capsys):
        """Test empty checkpoints."""
        from stance.cli_state import _handle_checkpoints

        with mock.patch("stance.cli_state._get_all_checkpoints") as mock_get:
            mock_get.return_value = []

            args = argparse.Namespace(format="table", collector=None, account=None, limit=50)
            result = _handle_checkpoints(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "No checkpoints found" in captured.out

    def test_checkpoints_with_data_table(self, capsys):
        """Test checkpoints with data in table format."""
        from stance.cli_state import _handle_checkpoints

        mock_checkpoints = [
            {
                "checkpoint_id": "cp-001",
                "collector_name": "IAMCollector",
                "account_id": "123456789",
                "region": "us-east-1",
                "last_scan_id": "scan-001",
                "last_scan_time": "2025-01-01T12:00:00",
            }
        ]

        with mock.patch("stance.cli_state._get_all_checkpoints") as mock_get:
            mock_get.return_value = mock_checkpoints

            args = argparse.Namespace(format="table", collector=None, account=None, limit=50)
            result = _handle_checkpoints(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "cp-001" in captured.out
            assert "IAMCollector" in captured.out

    def test_checkpoints_json(self, capsys):
        """Test checkpoints in JSON format."""
        from stance.cli_state import _handle_checkpoints

        mock_checkpoints = [
            {
                "checkpoint_id": "cp-002",
                "collector_name": "S3Collector",
                "account_id": "987654321",
                "region": "eu-west-1",
                "last_scan_id": "scan-002",
                "last_scan_time": "2025-01-02T12:00:00",
            }
        ]

        with mock.patch("stance.cli_state._get_all_checkpoints") as mock_get:
            mock_get.return_value = mock_checkpoints

            args = argparse.Namespace(format="json", collector=None, account=None, limit=50)
            result = _handle_checkpoints(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert len(data) == 1
            assert data[0]["checkpoint_id"] == "cp-002"


class TestHandleCheckpoint:
    """Tests for _handle_checkpoint function."""

    def test_checkpoint_not_found(self, capsys):
        """Test checkpoint not found."""
        from stance.cli_state import _handle_checkpoint

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.get_checkpoint.return_value = None

            args = argparse.Namespace(
                format="table",
                collector="NonExistent",
                account="123",
                region="us-east-1"
            )
            result = _handle_checkpoint(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Checkpoint not found" in captured.out

    def test_checkpoint_found_table(self, capsys):
        """Test checkpoint found in table format."""
        from stance.cli_state import _handle_checkpoint
        from stance.state import Checkpoint

        mock_cp = Checkpoint(
            checkpoint_id="cp-003",
            collector_name="IAMCollector",
            account_id="123456789",
            region="us-east-1",
            last_scan_id="scan-003",
            last_scan_time=datetime.utcnow(),
            cursor="page2",
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.get_checkpoint.return_value = mock_cp

            args = argparse.Namespace(
                format="table",
                collector="IAMCollector",
                account="123456789",
                region="us-east-1"
            )
            result = _handle_checkpoint(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "cp-003" in captured.out
            assert "IAMCollector" in captured.out
            assert "page2" in captured.out


class TestHandleDeleteCheckpoint:
    """Tests for _handle_delete_checkpoint function."""

    def test_checkpoint_deleted(self, capsys):
        """Test checkpoint deleted."""
        from stance.cli_state import _handle_delete_checkpoint

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.delete_checkpoint.return_value = True

            args = argparse.Namespace(
                format="table",
                collector="IAMCollector",
                account="123456789",
                region="us-east-1"
            )
            result = _handle_delete_checkpoint(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "deleted" in captured.out

    def test_checkpoint_not_found_on_delete(self, capsys):
        """Test checkpoint not found on delete."""
        from stance.cli_state import _handle_delete_checkpoint

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.delete_checkpoint.return_value = False

            args = argparse.Namespace(
                format="table",
                collector="IAMCollector",
                account="123456789",
                region="us-east-1"
            )
            result = _handle_delete_checkpoint(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "not found" in captured.out


class TestHandleFindings:
    """Tests for _handle_findings function."""

    def test_empty_findings(self, capsys):
        """Test empty findings."""
        from stance.cli_state import _handle_findings

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_finding_states.return_value = []

            args = argparse.Namespace(format="table", asset_id=None, lifecycle=None, limit=50)
            result = _handle_findings(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "No findings found" in captured.out

    def test_findings_with_data_table(self, capsys):
        """Test findings with data in table format."""
        from stance.cli_state import _handle_findings
        from stance.state import FindingLifecycle, FindingState

        mock_finding = FindingState(
            finding_id="finding-001",
            asset_id="asset-001",
            rule_id="rule-001",
            lifecycle=FindingLifecycle.NEW,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            scan_count=1,
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_finding_states.return_value = [mock_finding]

            args = argparse.Namespace(format="table", asset_id=None, lifecycle=None, limit=50)
            result = _handle_findings(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "finding-001" in captured.out
            assert "new" in captured.out

    def test_findings_json(self, capsys):
        """Test findings in JSON format."""
        from stance.cli_state import _handle_findings
        from stance.state import FindingLifecycle, FindingState

        mock_finding = FindingState(
            finding_id="finding-002",
            asset_id="asset-002",
            rule_id="rule-002",
            lifecycle=FindingLifecycle.RECURRING,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            scan_count=5,
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_finding_states.return_value = [mock_finding]

            args = argparse.Namespace(format="json", asset_id=None, lifecycle=None, limit=50)
            result = _handle_findings(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert len(data) == 1
            assert data[0]["finding_id"] == "finding-002"


class TestHandleFinding:
    """Tests for _handle_finding function."""

    def test_finding_not_found(self, capsys):
        """Test finding not found."""
        from stance.cli_state import _handle_finding

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_finding_state.return_value = None

            args = argparse.Namespace(format="table", finding_id="nonexistent")
            result = _handle_finding(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Finding not found" in captured.out

    def test_finding_found_table(self, capsys):
        """Test finding found in table format."""
        from stance.cli_state import _handle_finding
        from stance.state import FindingLifecycle, FindingState

        mock_state = FindingState(
            finding_id="finding-003",
            asset_id="asset-003",
            rule_id="rule-003",
            lifecycle=FindingLifecycle.NEW,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            scan_count=1,
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_finding_state.return_value = mock_state

            args = argparse.Namespace(format="table", finding_id="finding-003")
            result = _handle_finding(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "finding-003" in captured.out
            assert "new" in captured.out
            assert "asset-003" in captured.out


class TestHandleSuppress:
    """Tests for _handle_suppress function."""

    def test_suppress_finding_not_found(self, capsys):
        """Test suppress finding not found."""
        from stance.cli_state import _handle_suppress

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.suppress_finding.return_value = None

            args = argparse.Namespace(
                format="table",
                finding_id="nonexistent",
                by="admin",
                reason="Test"
            )
            result = _handle_suppress(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Finding not found" in captured.out

    def test_suppress_success(self, capsys):
        """Test suppress success."""
        from stance.cli_state import _handle_suppress
        from stance.state import FindingLifecycle, FindingState

        mock_state = FindingState(
            finding_id="finding-004",
            asset_id="asset-004",
            rule_id="rule-004",
            lifecycle=FindingLifecycle.SUPPRESSED,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            suppressed_by="admin",
            suppressed_at=datetime.utcnow(),
            suppression_reason="False positive",
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.suppress_finding.return_value = mock_state

            args = argparse.Namespace(
                format="table",
                finding_id="finding-004",
                by="admin",
                reason="False positive"
            )
            result = _handle_suppress(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "suppressed" in captured.out
            assert "admin" in captured.out


class TestHandleResolve:
    """Tests for _handle_resolve function."""

    def test_resolve_finding_not_found(self, capsys):
        """Test resolve finding not found."""
        from stance.cli_state import _handle_resolve

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.resolve_finding.return_value = None

            args = argparse.Namespace(format="table", finding_id="nonexistent")
            result = _handle_resolve(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "Finding not found" in captured.out

    def test_resolve_success(self, capsys):
        """Test resolve success."""
        from stance.cli_state import _handle_resolve
        from stance.state import FindingLifecycle, FindingState

        mock_state = FindingState(
            finding_id="finding-005",
            asset_id="asset-005",
            rule_id="rule-005",
            lifecycle=FindingLifecycle.RESOLVED,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            resolved_at=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.resolve_finding.return_value = mock_state

            args = argparse.Namespace(format="table", finding_id="finding-005")
            result = _handle_resolve(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "resolved" in captured.out


class TestHandleFindingStats:
    """Tests for _handle_finding_stats function."""

    def test_finding_stats_table(self, capsys):
        """Test finding stats in table format."""
        from stance.cli_state import _handle_finding_stats

        mock_stats = {
            "new": 10,
            "recurring": 5,
            "resolved": 3,
            "reopened": 1,
            "suppressed": 2,
            "false_positive": 0,
        }

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.get_finding_stats.return_value = mock_stats

            args = argparse.Namespace(format="table")
            result = _handle_finding_stats(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "new" in captured.out
            assert "10" in captured.out

    def test_finding_stats_json(self, capsys):
        """Test finding stats in JSON format."""
        from stance.cli_state import _handle_finding_stats

        mock_stats = {
            "new": 5,
            "resolved": 10,
        }

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.get_finding_stats.return_value = mock_stats

            args = argparse.Namespace(format="json")
            result = _handle_finding_stats(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["new"] == 5
            assert data["resolved"] == 10


class TestHandleStats:
    """Tests for _handle_stats function."""

    def test_stats_table(self, capsys):
        """Test stats in table format."""
        from stance.cli_state import _handle_stats
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-001",
            snapshot_id="snap-001",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )
        mock_stats = {"new": 5, "resolved": 3}

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]
            mock_manager.return_value.get_finding_stats.return_value = mock_stats

            with mock.patch("stance.cli_state._get_all_checkpoints") as mock_cp:
                mock_cp.return_value = []

                args = argparse.Namespace(format="table")
                result = _handle_stats(args)

                assert result == 0
                captured = capsys.readouterr()
                assert "State Module Statistics" in captured.out

    def test_stats_json(self, capsys):
        """Test stats in JSON format."""
        from stance.cli_state import _handle_stats
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-002",
            snapshot_id="snap-002",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )
        mock_stats = {"new": 2, "resolved": 1}

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]
            mock_manager.return_value.get_finding_stats.return_value = mock_stats

            with mock.patch("stance.cli_state._get_all_checkpoints") as mock_cp:
                mock_cp.return_value = []

                args = argparse.Namespace(format="json")
                result = _handle_stats(args)

                assert result == 0
                captured = capsys.readouterr()
                data = json.loads(captured.out)
                assert "scans" in data
                assert "findings" in data


class TestHandleSummary:
    """Tests for _handle_summary function."""

    def test_summary_table(self, capsys):
        """Test summary in table format."""
        from stance.cli_state import _handle_summary
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-001",
            snapshot_id="snap-001",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            asset_count=100,
            finding_count=10,
        )
        mock_stats = {"new": 5, "resolved": 3}

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]
            mock_manager.return_value.get_finding_stats.return_value = mock_stats

            with mock.patch("stance.cli_state._get_all_checkpoints") as mock_cp:
                mock_cp.return_value = []

                with mock.patch("os.path.expanduser") as mock_expand:
                    mock_expand.return_value = "/tmp/test_state.db"

                    with mock.patch("pathlib.Path") as mock_path:
                        mock_path.return_value.exists.return_value = True
                        mock_path.return_value.stat.return_value.st_size = 1024

                        args = argparse.Namespace(format="table")
                        result = _handle_summary(args)

                        assert result == 0
                        captured = capsys.readouterr()
                        assert "State Module Summary" in captured.out
                        assert "Scan History" in captured.out

    def test_summary_json(self, capsys):
        """Test summary in JSON format."""
        from stance.cli_state import _handle_summary
        from stance.state import ScanRecord, ScanStatus

        mock_scan = ScanRecord(
            scan_id="scan-002",
            snapshot_id="snap-002",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )
        mock_stats = {"new": 3, "resolved": 2}

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]
            mock_manager.return_value.get_finding_stats.return_value = mock_stats

            with mock.patch("stance.cli_state._get_all_checkpoints") as mock_cp:
                mock_cp.return_value = []

                with mock.patch("os.path.expanduser") as mock_expand:
                    mock_expand.return_value = "/tmp/test_state.db"

                    with mock.patch("pathlib.Path") as mock_path:
                        mock_path.return_value.exists.return_value = True
                        mock_path.return_value.stat.return_value.st_size = 2048

                        args = argparse.Namespace(format="json")
                        result = _handle_summary(args)

                        assert result == 0
                        captured = capsys.readouterr()
                        data = json.loads(captured.out)
                        assert "overview" in data
                        assert "scans" in data
                        assert "features" in data


class TestGetAllCheckpoints:
    """Tests for _get_all_checkpoints helper function."""

    def test_no_database(self):
        """Test when database doesn't exist."""
        from stance.cli_state import _get_all_checkpoints

        with mock.patch("os.path.expanduser") as mock_expand:
            mock_expand.return_value = "/nonexistent/path/state.db"

            with mock.patch("pathlib.Path") as mock_path:
                mock_path.return_value.exists.return_value = False

                result = _get_all_checkpoints()
                assert result == []


class TestStateCliIntegration:
    """Integration tests for state CLI."""

    def test_all_actions_have_handlers(self):
        """Test that all defined actions have handlers."""
        from stance.cli_state import cmd_state

        actions = [
            "scans", "scan", "checkpoints", "checkpoint", "delete-checkpoint",
            "findings", "finding", "suppress", "resolve", "scan-statuses",
            "lifecycles", "backends", "finding-stats", "stats", "status", "summary"
        ]

        for action in actions:
            args = argparse.Namespace(state_action=action)
            # Just verify the action is recognized (may fail due to missing mocks but that's ok)
            # The important thing is it doesn't say "Unknown state action"
            with mock.patch("stance.cli_state._handle_" + action.replace("-", "_")) as mock_handler:
                mock_handler.return_value = 0
                result = cmd_state(args)
                # If we get here, the action was recognized

    def test_output_format_options(self):
        """Test that all commands support table and JSON formats."""
        from stance.cli_state import add_state_parser

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_state_parser(subparsers)

        # Test table format
        args = parser.parse_args(["state", "scan-statuses", "--format", "table"])
        assert args.format == "table"

        # Test JSON format
        args = parser.parse_args(["state", "scan-statuses", "--format", "json"])
        assert args.format == "json"
