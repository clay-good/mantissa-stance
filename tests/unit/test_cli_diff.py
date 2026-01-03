"""
Unit tests for the findings diff module.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_diff import (
    DiffChangeType,
    FindingChange,
    DiffSummary,
    DiffResult,
    FindingsDiffer,
    format_diff_table,
    cmd_diff,
)


class TestDiffChangeType:
    """Tests for DiffChangeType enum."""

    def test_change_types(self):
        """Test all change types exist."""
        assert DiffChangeType.NEW.value == "new"
        assert DiffChangeType.RESOLVED.value == "resolved"
        assert DiffChangeType.SEVERITY_CHANGED.value == "severity_changed"
        assert DiffChangeType.UNCHANGED.value == "unchanged"


class TestFindingChange:
    """Tests for FindingChange dataclass."""

    def test_create_new_finding(self):
        """Test creating a new finding change."""
        change = FindingChange(
            finding_id="f-123",
            change_type=DiffChangeType.NEW,
            severity="critical",
            rule_id="aws-s3-001",
            asset_id="bucket-test",
            description="Public bucket found",
        )

        assert change.finding_id == "f-123"
        assert change.change_type == DiffChangeType.NEW
        assert change.severity == "critical"
        assert change.previous_severity is None

    def test_create_severity_change(self):
        """Test creating a severity change."""
        change = FindingChange(
            finding_id="f-456",
            change_type=DiffChangeType.SEVERITY_CHANGED,
            severity="critical",
            previous_severity="high",
            rule_id="aws-iam-001",
        )

        assert change.change_type == DiffChangeType.SEVERITY_CHANGED
        assert change.severity == "critical"
        assert change.previous_severity == "high"

    def test_finding_change_to_dict(self):
        """Test serialization."""
        change = FindingChange(
            finding_id="f-789",
            change_type=DiffChangeType.RESOLVED,
            severity="medium",
            rule_id="aws-ec2-001",
        )

        result = change.to_dict()

        assert result["finding_id"] == "f-789"
        assert result["change_type"] == "resolved"
        assert result["severity"] == "medium"


class TestDiffSummary:
    """Tests for DiffSummary dataclass."""

    def test_create_summary(self):
        """Test creating a diff summary."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
            new_findings=5,
            resolved_findings=3,
            severity_changes=2,
            unchanged_findings=10,
            new_by_severity={"critical": 2, "high": 3},
            resolved_by_severity={"medium": 3},
            net_change=2,
            is_improved=False,
        )

        assert summary.baseline_snapshot == "snap-1"
        assert summary.new_findings == 5
        assert summary.resolved_findings == 3
        assert summary.net_change == 2
        assert summary.is_improved is False

    def test_summary_to_dict(self):
        """Test summary serialization."""
        summary = DiffSummary(
            baseline_snapshot="snap-a",
            current_snapshot="snap-b",
            new_findings=1,
            resolved_findings=5,
            net_change=-4,
            is_improved=True,
        )

        result = summary.to_dict()

        assert result["baseline_snapshot"] == "snap-a"
        assert result["net_change"] == -4
        assert result["is_improved"] is True


class TestDiffResult:
    """Tests for DiffResult dataclass."""

    def test_create_result(self):
        """Test creating a diff result."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
        )
        changes = [
            FindingChange(
                finding_id="f1",
                change_type=DiffChangeType.NEW,
                severity="high",
            ),
            FindingChange(
                finding_id="f2",
                change_type=DiffChangeType.RESOLVED,
                severity="low",
            ),
        ]

        result = DiffResult(summary=summary, changes=changes)

        assert result.summary == summary
        assert len(result.changes) == 2

    def test_get_new_findings(self):
        """Test filtering new findings."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
        )
        changes = [
            FindingChange("f1", DiffChangeType.NEW, "high"),
            FindingChange("f2", DiffChangeType.RESOLVED, "low"),
            FindingChange("f3", DiffChangeType.NEW, "critical"),
        ]

        result = DiffResult(summary=summary, changes=changes)
        new_findings = result.get_new_findings()

        assert len(new_findings) == 2
        assert all(c.change_type == DiffChangeType.NEW for c in new_findings)

    def test_get_resolved_findings(self):
        """Test filtering resolved findings."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
        )
        changes = [
            FindingChange("f1", DiffChangeType.RESOLVED, "high"),
            FindingChange("f2", DiffChangeType.NEW, "low"),
            FindingChange("f3", DiffChangeType.RESOLVED, "medium"),
        ]

        result = DiffResult(summary=summary, changes=changes)
        resolved = result.get_resolved_findings()

        assert len(resolved) == 2

    def test_get_severity_changes(self):
        """Test filtering severity changes."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
        )
        changes = [
            FindingChange(
                "f1",
                DiffChangeType.SEVERITY_CHANGED,
                "critical",
                previous_severity="high",
            ),
            FindingChange("f2", DiffChangeType.NEW, "low"),
        ]

        result = DiffResult(summary=summary, changes=changes)
        sev_changes = result.get_severity_changes()

        assert len(sev_changes) == 1
        assert sev_changes[0].previous_severity == "high"

    def test_result_to_dict(self):
        """Test result serialization."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
            new_findings=1,
        )
        changes = [
            FindingChange("f1", DiffChangeType.NEW, "high"),
        ]

        result = DiffResult(summary=summary, changes=changes)
        data = result.to_dict()

        assert "summary" in data
        assert "changes" in data
        assert len(data["changes"]) == 1


class TestFindingsDiffer:
    """Tests for FindingsDiffer class."""

    def test_initialization(self):
        """Test differ initialization."""
        differ = FindingsDiffer()
        assert differ._storage_type == "local"

    def test_initialization_with_storage_type(self):
        """Test differ with custom storage type."""
        differ = FindingsDiffer(storage_type="s3")
        assert differ._storage_type == "s3"

    def test_diff_from_data_new_findings(self):
        """Test diff with new findings."""
        differ = FindingsDiffer()

        baseline = [
            {"id": "f1", "severity": "high", "rule_id": "r1"},
            {"id": "f2", "severity": "medium", "rule_id": "r2"},
        ]
        current = [
            {"id": "f1", "severity": "high", "rule_id": "r1"},
            {"id": "f2", "severity": "medium", "rule_id": "r2"},
            {"id": "f3", "severity": "critical", "rule_id": "r3"},
        ]

        result = differ.diff_from_data(baseline, current)

        assert result.summary.new_findings == 1
        assert result.summary.resolved_findings == 0
        assert result.summary.new_by_severity["critical"] == 1

    def test_diff_from_data_resolved_findings(self):
        """Test diff with resolved findings."""
        differ = FindingsDiffer()

        baseline = [
            {"id": "f1", "severity": "critical", "rule_id": "r1"},
            {"id": "f2", "severity": "high", "rule_id": "r2"},
            {"id": "f3", "severity": "medium", "rule_id": "r3"},
        ]
        current = [
            {"id": "f1", "severity": "critical", "rule_id": "r1"},
        ]

        result = differ.diff_from_data(baseline, current)

        assert result.summary.new_findings == 0
        assert result.summary.resolved_findings == 2
        assert result.summary.is_improved is True

    def test_diff_from_data_severity_changes(self):
        """Test diff with severity changes."""
        differ = FindingsDiffer()

        baseline = [
            {"id": "f1", "severity": "high", "rule_id": "r1"},
            {"id": "f2", "severity": "medium", "rule_id": "r2"},
        ]
        current = [
            {"id": "f1", "severity": "critical", "rule_id": "r1"},
            {"id": "f2", "severity": "medium", "rule_id": "r2"},
        ]

        result = differ.diff_from_data(baseline, current)

        assert result.summary.severity_changes == 1
        assert result.summary.unchanged_findings == 1

        sev_changes = result.get_severity_changes()
        assert len(sev_changes) == 1
        assert sev_changes[0].previous_severity == "high"
        assert sev_changes[0].severity == "critical"

    def test_diff_from_data_no_changes(self):
        """Test diff with no changes."""
        differ = FindingsDiffer()

        findings = [
            {"id": "f1", "severity": "high"},
            {"id": "f2", "severity": "low"},
        ]

        result = differ.diff_from_data(findings, findings)

        assert result.summary.new_findings == 0
        assert result.summary.resolved_findings == 0
        assert result.summary.severity_changes == 0
        assert result.summary.unchanged_findings == 2

    def test_diff_from_data_empty_baseline(self):
        """Test diff with empty baseline."""
        differ = FindingsDiffer()

        baseline: list = []
        current = [
            {"id": "f1", "severity": "critical"},
            {"id": "f2", "severity": "high"},
        ]

        result = differ.diff_from_data(baseline, current)

        assert result.summary.new_findings == 2
        assert result.summary.resolved_findings == 0

    def test_diff_from_data_empty_current(self):
        """Test diff with empty current."""
        differ = FindingsDiffer()

        baseline = [
            {"id": "f1", "severity": "critical"},
            {"id": "f2", "severity": "high"},
        ]
        current: list = []

        result = differ.diff_from_data(baseline, current)

        assert result.summary.new_findings == 0
        assert result.summary.resolved_findings == 2
        assert result.summary.is_improved is True


class TestFormatDiffTable:
    """Tests for format_diff_table function."""

    def test_format_basic_diff(self):
        """Test basic diff formatting."""
        summary = DiffSummary(
            baseline_snapshot="snap-baseline",
            current_snapshot="snap-current",
            new_findings=3,
            resolved_findings=1,
            net_change=2,
        )
        result = DiffResult(summary=summary)

        output = format_diff_table(result)

        assert "FINDINGS DIFF" in output
        assert "snap-baseline" in output
        assert "snap-current" in output
        assert "+3" in output
        assert "-1" in output

    def test_format_with_new_findings(self):
        """Test formatting with new findings list."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
            new_findings=2,
        )
        changes = [
            FindingChange(
                "f1",
                DiffChangeType.NEW,
                "critical",
                rule_id="aws-s3-001",
                asset_id="bucket-test",
            ),
            FindingChange(
                "f2",
                DiffChangeType.NEW,
                "high",
                rule_id="aws-iam-001",
                asset_id="role-test",
            ),
        ]
        result = DiffResult(summary=summary, changes=changes)

        output = format_diff_table(result)

        assert "NEW FINDINGS (2)" in output
        assert "critical" in output
        assert "aws-s3-001" in output

    def test_format_with_resolved_findings(self):
        """Test formatting with resolved findings."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
            resolved_findings=1,
        )
        changes = [
            FindingChange(
                "f1",
                DiffChangeType.RESOLVED,
                "medium",
                rule_id="aws-ec2-001",
            ),
        ]
        result = DiffResult(summary=summary, changes=changes)

        output = format_diff_table(result)

        assert "RESOLVED FINDINGS (1)" in output

    def test_format_improved_status(self):
        """Test formatting shows IMPROVED status."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
            resolved_findings=5,
            net_change=-5,
            is_improved=True,
        )
        result = DiffResult(summary=summary)

        output = format_diff_table(result)

        assert "IMPROVED" in output

    def test_format_degraded_status(self):
        """Test formatting shows DEGRADED status."""
        summary = DiffSummary(
            baseline_snapshot="snap-1",
            current_snapshot="snap-2",
            new_findings=5,
            net_change=5,
            is_improved=False,
        )
        result = DiffResult(summary=summary)

        output = format_diff_table(result)

        assert "DEGRADED" in output


class TestCmdDiff:
    """Tests for cmd_diff function."""

    def test_cmd_diff_missing_baseline(self, capsys):
        """Test cmd_diff requires baseline."""
        args = argparse.Namespace(
            baseline=None,
            current=None,
            format="table",
            show_unchanged=False,
            fail_on_new=False,
        )

        result = cmd_diff(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "baseline" in captured.out.lower()

    def test_cmd_diff_json_output(self, capsys):
        """Test cmd_diff JSON output."""
        with patch("stance.cli_diff.FindingsDiffer") as mock_differ_class:
            mock_differ = MagicMock()
            mock_differ.diff.return_value = DiffResult(
                summary=DiffSummary(
                    baseline_snapshot="snap-1",
                    current_snapshot="snap-2",
                    new_findings=1,
                ),
                changes=[
                    FindingChange("f1", DiffChangeType.NEW, "high"),
                ],
            )
            mock_differ_class.return_value = mock_differ

            args = argparse.Namespace(
                baseline="snap-1",
                current="snap-2",
                format="json",
                show_unchanged=False,
                fail_on_new=False,
            )

            result = cmd_diff(args)

            assert result == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "summary" in data
            assert "changes" in data

    def test_cmd_diff_table_output(self, capsys):
        """Test cmd_diff table output."""
        with patch("stance.cli_diff.FindingsDiffer") as mock_differ_class:
            mock_differ = MagicMock()
            mock_differ.diff.return_value = DiffResult(
                summary=DiffSummary(
                    baseline_snapshot="snap-1",
                    current_snapshot="snap-2",
                    new_findings=0,
                    resolved_findings=2,
                    is_improved=True,
                ),
            )
            mock_differ_class.return_value = mock_differ

            args = argparse.Namespace(
                baseline="snap-1",
                current=None,
                format="table",
                show_unchanged=False,
                fail_on_new=False,
            )

            result = cmd_diff(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "FINDINGS DIFF" in captured.out

    def test_cmd_diff_fail_on_new(self):
        """Test cmd_diff fails when new findings and fail_on_new is set."""
        with patch("stance.cli_diff.FindingsDiffer") as mock_differ_class:
            mock_differ = MagicMock()
            mock_differ.diff.return_value = DiffResult(
                summary=DiffSummary(
                    baseline_snapshot="snap-1",
                    current_snapshot="snap-2",
                    new_findings=5,
                ),
            )
            mock_differ_class.return_value = mock_differ

            args = argparse.Namespace(
                baseline="snap-1",
                current="snap-2",
                format="table",
                show_unchanged=False,
                fail_on_new=True,
            )

            result = cmd_diff(args)

            assert result == 1

    def test_cmd_diff_no_fail_without_flag(self):
        """Test cmd_diff succeeds with new findings when flag not set."""
        with patch("stance.cli_diff.FindingsDiffer") as mock_differ_class:
            mock_differ = MagicMock()
            mock_differ.diff.return_value = DiffResult(
                summary=DiffSummary(
                    baseline_snapshot="snap-1",
                    current_snapshot="snap-2",
                    new_findings=5,
                ),
            )
            mock_differ_class.return_value = mock_differ

            args = argparse.Namespace(
                baseline="snap-1",
                current="snap-2",
                format="table",
                show_unchanged=False,
                fail_on_new=False,
            )

            result = cmd_diff(args)

            assert result == 0


class TestFindingsDifferIntegration:
    """Integration tests for FindingsDiffer."""

    def test_complex_diff_scenario(self):
        """Test complex diff with multiple change types."""
        differ = FindingsDiffer()

        baseline = [
            {"id": "f1", "severity": "critical", "rule_id": "r1", "asset_id": "a1"},
            {"id": "f2", "severity": "high", "rule_id": "r2", "asset_id": "a2"},
            {"id": "f3", "severity": "medium", "rule_id": "r3", "asset_id": "a3"},
            {"id": "f4", "severity": "low", "rule_id": "r4", "asset_id": "a4"},
        ]
        current = [
            {"id": "f1", "severity": "high", "rule_id": "r1", "asset_id": "a1"},  # Downgraded
            {"id": "f3", "severity": "medium", "rule_id": "r3", "asset_id": "a3"},  # Unchanged
            {"id": "f5", "severity": "critical", "rule_id": "r5", "asset_id": "a5"},  # New
            {"id": "f6", "severity": "high", "rule_id": "r6", "asset_id": "a6"},  # New
        ]

        result = differ.diff_from_data(baseline, current)

        # Check counts
        assert result.summary.new_findings == 2  # f5, f6
        assert result.summary.resolved_findings == 2  # f2, f4
        assert result.summary.severity_changes == 1  # f1
        assert result.summary.unchanged_findings == 1  # f3

        # Check new findings breakdown
        assert result.summary.new_by_severity["critical"] == 1
        assert result.summary.new_by_severity["high"] == 1

        # Check resolved breakdown
        assert result.summary.resolved_by_severity["high"] == 1
        assert result.summary.resolved_by_severity["low"] == 1

        # Net change: +2 new, -2 resolved = 0
        assert result.summary.net_change == 0

    def test_diff_preserves_finding_details(self):
        """Test that finding details are preserved in changes."""
        differ = FindingsDiffer()

        baseline = [
            {
                "id": "f1",
                "severity": "critical",
                "rule_id": "aws-s3-001",
                "asset_id": "bucket-prod",
                "description": "Public S3 bucket",
            },
        ]
        current: list = []

        result = differ.diff_from_data(baseline, current)

        resolved = result.get_resolved_findings()
        assert len(resolved) == 1
        assert resolved[0].rule_id == "aws-s3-001"
        assert resolved[0].asset_id == "bucket-prod"
        assert resolved[0].description == "Public S3 bucket"
