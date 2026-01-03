"""
Unit tests for the watch mode module.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.cli_watch import (
    WatchConfig,
    ScanSnapshot,
    ScanDelta,
    WatchMode,
    cmd_watch,
)


class TestWatchConfig:
    """Tests for WatchConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = WatchConfig()

        assert config.interval_seconds == 300
        assert config.collectors is None
        assert config.policies is None
        assert config.notify_on_change is False
        assert config.show_summary is True
        assert config.show_diff is True
        assert config.max_iterations == 0
        assert config.quiet is False
        assert config.output_format == "table"

    def test_custom_config(self):
        """Test custom configuration values."""
        config = WatchConfig(
            interval_seconds=60,
            collectors=["s3", "iam"],
            policies=["aws-s3-001"],
            notify_on_change=True,
            show_summary=False,
            show_diff=False,
            max_iterations=5,
            quiet=True,
            output_format="json",
        )

        assert config.interval_seconds == 60
        assert config.collectors == ["s3", "iam"]
        assert config.policies == ["aws-s3-001"]
        assert config.notify_on_change is True
        assert config.show_summary is False
        assert config.show_diff is False
        assert config.max_iterations == 5
        assert config.quiet is True
        assert config.output_format == "json"


class TestScanSnapshot:
    """Tests for ScanSnapshot dataclass."""

    def test_create_snapshot(self):
        """Test creating a snapshot."""
        now = datetime.utcnow()
        snapshot = ScanSnapshot(
            timestamp=now,
            snapshot_id="snap-123",
            total_findings=10,
            findings_by_severity={"critical": 2, "high": 5, "medium": 3},
            critical_findings=["f1", "f2"],
            finding_ids={"f1", "f2", "f3"},
        )

        assert snapshot.timestamp == now
        assert snapshot.snapshot_id == "snap-123"
        assert snapshot.total_findings == 10
        assert snapshot.findings_by_severity["critical"] == 2
        assert len(snapshot.critical_findings) == 2
        assert len(snapshot.finding_ids) == 3

    def test_snapshot_to_dict(self):
        """Test snapshot serialization."""
        now = datetime.utcnow()
        snapshot = ScanSnapshot(
            timestamp=now,
            snapshot_id="snap-456",
            total_findings=5,
            findings_by_severity={"high": 3, "low": 2},
            critical_findings=[],
            finding_ids={"f1", "f2", "f3", "f4", "f5"},
        )

        result = snapshot.to_dict()

        assert result["snapshot_id"] == "snap-456"
        assert result["total_findings"] == 5
        assert result["findings_by_severity"]["high"] == 3
        assert result["finding_count"] == 5


class TestScanDelta:
    """Tests for ScanDelta dataclass."""

    def test_create_delta(self):
        """Test creating a delta."""
        prev = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-1",
            total_findings=10,
            finding_ids={"f1", "f2", "f3"},
        )
        curr = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-2",
            total_findings=8,
            finding_ids={"f1", "f3", "f4"},
        )

        delta = ScanDelta(
            previous=prev,
            current=curr,
            new_findings=1,
            resolved_findings=2,
            new_critical=0,
            severity_changes={"high": -2},
            is_improved=True,
            is_degraded=False,
        )

        assert delta.new_findings == 1
        assert delta.resolved_findings == 2
        assert delta.is_improved is True
        assert delta.is_degraded is False

    def test_delta_to_dict(self):
        """Test delta serialization."""
        prev = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-1",
        )
        curr = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-2",
        )

        delta = ScanDelta(
            previous=prev,
            current=curr,
            new_findings=3,
            resolved_findings=1,
        )

        result = delta.to_dict()

        assert result["previous_snapshot"] == "snap-1"
        assert result["current_snapshot"] == "snap-2"
        assert result["new_findings"] == 3
        assert result["resolved_findings"] == 1
        assert result["net_change"] == 2


class TestWatchMode:
    """Tests for WatchMode class."""

    def test_initialization(self):
        """Test watch mode initialization."""
        watch = WatchMode()

        assert watch.is_running is False
        assert watch.iteration_count == 0
        assert watch.snapshots == []
        assert watch.last_snapshot is None

    def test_initialization_with_config(self):
        """Test watch mode with custom config."""
        config = WatchConfig(interval_seconds=60, max_iterations=5)
        watch = WatchMode(config)

        assert watch.config.interval_seconds == 60
        assert watch.config.max_iterations == 5

    def test_add_callback(self):
        """Test adding a callback."""
        watch = WatchMode()
        callback = MagicMock()

        watch.add_callback(callback)

        assert len(watch._callbacks) == 1

    def test_stop(self):
        """Test stopping watch mode."""
        watch = WatchMode()
        watch._running = True

        watch.stop()

        assert watch.is_running is False

    def test_calculate_delta(self):
        """Test delta calculation."""
        watch = WatchMode()

        prev = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-1",
            total_findings=10,
            findings_by_severity={"critical": 2, "high": 5},
            critical_findings=["c1", "c2"],
            finding_ids={"f1", "f2", "f3", "f4", "f5"},
        )
        curr = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-2",
            total_findings=8,
            findings_by_severity={"critical": 1, "high": 4},
            critical_findings=["c1"],
            finding_ids={"f1", "f2", "f3", "f6"},
        )

        delta = watch._calculate_delta(prev, curr)

        assert delta.new_findings == 1  # f6 is new
        assert delta.resolved_findings == 2  # f4, f5 resolved
        assert delta.is_improved is True
        assert delta.is_degraded is False

    def test_calculate_delta_degradation(self):
        """Test delta calculation for degradation."""
        watch = WatchMode()

        prev = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-1",
            total_findings=5,
            findings_by_severity={"critical": 0},
            critical_findings=[],
            finding_ids={"f1", "f2"},
        )
        curr = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-2",
            total_findings=10,
            findings_by_severity={"critical": 3},
            critical_findings=["c1", "c2", "c3"],
            finding_ids={"f1", "f2", "f3", "f4", "f5"},
        )

        delta = watch._calculate_delta(prev, curr)

        assert delta.new_findings == 3
        assert delta.new_critical == 3
        assert delta.is_degraded is True

    def test_snapshots_stored(self):
        """Test that snapshots are stored after scans."""
        config = WatchConfig(max_iterations=1, quiet=True)
        watch = WatchMode(config)

        # Mock the perform_scan method
        mock_snapshot = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-test",
            total_findings=5,
        )
        watch._perform_scan = MagicMock(return_value=mock_snapshot)

        watch.start()

        assert len(watch.snapshots) == 1
        assert watch.last_snapshot == mock_snapshot

    def test_callbacks_invoked(self):
        """Test that callbacks are invoked after scans."""
        config = WatchConfig(max_iterations=1, quiet=True)
        watch = WatchMode(config)

        callback = MagicMock()
        watch.add_callback(callback)

        mock_snapshot = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-test",
        )
        watch._perform_scan = MagicMock(return_value=mock_snapshot)

        watch.start()

        callback.assert_called_once()
        call_args = callback.call_args[0]
        assert call_args[0] == mock_snapshot

    def test_max_iterations_respected(self):
        """Test that max iterations limit is respected."""
        config = WatchConfig(max_iterations=3, quiet=True, interval_seconds=0)
        watch = WatchMode(config)

        mock_snapshot = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-test",
        )
        watch._perform_scan = MagicMock(return_value=mock_snapshot)

        watch.start()

        assert watch.iteration_count == 3
        assert len(watch.snapshots) == 3


class TestWatchModeDisplay:
    """Tests for watch mode display functionality."""

    def test_display_results_json(self, capsys):
        """Test JSON output format."""
        config = WatchConfig(output_format="json", quiet=False)
        watch = WatchMode(config)

        snapshot = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-json",
            total_findings=5,
            findings_by_severity={"high": 3, "low": 2},
        )

        watch._display_results(snapshot, None)

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["snapshot"]["snapshot_id"] == "snap-json"

    def test_display_results_table(self, capsys):
        """Test table output format."""
        config = WatchConfig(output_format="table", quiet=False)
        watch = WatchMode(config)

        snapshot = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-table",
            total_findings=10,
            findings_by_severity={"critical": 2, "high": 5},
        )

        watch._display_results(snapshot, None)

        captured = capsys.readouterr()
        assert "snap-table" in captured.out
        assert "Total findings: 10" in captured.out

    def test_display_results_quiet(self, capsys):
        """Test quiet mode suppresses output."""
        config = WatchConfig(quiet=True)
        watch = WatchMode(config)

        snapshot = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-quiet",
        )

        watch._display_results(snapshot, None)

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_display_with_delta(self, capsys):
        """Test display with delta information."""
        config = WatchConfig(output_format="table", quiet=False)
        watch = WatchMode(config)

        prev = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-1",
        )
        curr = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-2",
            total_findings=5,
            findings_by_severity={},
        )
        delta = ScanDelta(
            previous=prev,
            current=curr,
            new_findings=2,
            resolved_findings=1,
            is_improved=False,
            is_degraded=True,
        )

        watch._display_results(curr, delta)

        captured = capsys.readouterr()
        assert "DEGRADED" in captured.out
        assert "+2" in captured.out


class TestWatchModeHeader:
    """Tests for watch mode header and footer."""

    def test_print_header(self, capsys):
        """Test header output."""
        config = WatchConfig(interval_seconds=60, collectors=["s3", "iam"])
        watch = WatchMode(config)

        watch._print_header()

        captured = capsys.readouterr()
        assert "STANCE WATCH MODE" in captured.out
        assert "60s" in captured.out
        assert "s3" in captured.out

    def test_print_header_quiet(self, capsys):
        """Test header suppressed in quiet mode."""
        config = WatchConfig(quiet=True)
        watch = WatchMode(config)

        watch._print_header()

        captured = capsys.readouterr()
        assert captured.out == ""

    def test_print_footer(self, capsys):
        """Test footer output."""
        config = WatchConfig()
        watch = WatchMode(config)
        watch._iteration = 5
        watch._snapshots = [
            ScanSnapshot(
                timestamp=datetime.utcnow(),
                snapshot_id="snap-1",
                total_findings=10,
            ),
            ScanSnapshot(
                timestamp=datetime.utcnow(),
                snapshot_id="snap-5",
                total_findings=8,
            ),
        ]

        watch._print_footer()

        captured = capsys.readouterr()
        assert "5 iteration(s)" in captured.out
        assert "10 -> 8" in captured.out


class TestCmdWatch:
    """Tests for cmd_watch function."""

    def test_cmd_watch_basic(self):
        """Test basic cmd_watch execution."""
        with patch("stance.cli_watch.WatchMode") as mock_watch_class:
            mock_watch = MagicMock()
            mock_watch_class.return_value = mock_watch

            args = argparse.Namespace(
                interval=60,
                collectors=None,
                count=1,
                notify=False,
                no_summary=False,
                no_diff=False,
                quiet=False,
                format="table",
            )

            result = cmd_watch(args)

            assert result == 0
            mock_watch.start.assert_called_once()

    def test_cmd_watch_with_collectors(self):
        """Test cmd_watch with collectors."""
        with patch("stance.cli_watch.WatchMode") as mock_watch_class:
            mock_watch = MagicMock()
            mock_watch_class.return_value = mock_watch

            args = argparse.Namespace(
                interval=300,
                collectors="s3,iam,ec2",
                count=0,
                notify=True,
                no_summary=True,
                no_diff=False,
                quiet=False,
                format="json",
            )

            cmd_watch(args)

            # Verify config was created with correct values
            call_args = mock_watch_class.call_args[0][0]
            assert call_args.collectors == ["s3", "iam", "ec2"]
            assert call_args.notify_on_change is True
            assert call_args.show_summary is False

    def test_cmd_watch_keyboard_interrupt(self):
        """Test cmd_watch handles keyboard interrupt."""
        with patch("stance.cli_watch.WatchMode") as mock_watch_class:
            mock_watch = MagicMock()
            mock_watch.start.side_effect = KeyboardInterrupt()
            mock_watch_class.return_value = mock_watch

            args = argparse.Namespace(
                interval=60,
                collectors=None,
                count=0,
                notify=False,
                no_summary=False,
                no_diff=False,
                quiet=False,
                format="table",
            )

            result = cmd_watch(args)

            assert result == 0


class TestWatchModeIntegration:
    """Integration tests for watch mode."""

    def test_multiple_iterations_track_changes(self):
        """Test that multiple iterations track changes correctly."""
        config = WatchConfig(max_iterations=3, quiet=True, interval_seconds=0)
        watch = WatchMode(config)

        # Create sequence of snapshots with changes
        snapshots = [
            ScanSnapshot(
                timestamp=datetime.utcnow(),
                snapshot_id="snap-1",
                total_findings=10,
                findings_by_severity={"critical": 2},
                critical_findings=["c1", "c2"],
                finding_ids={"f1", "f2", "f3"},
            ),
            ScanSnapshot(
                timestamp=datetime.utcnow(),
                snapshot_id="snap-2",
                total_findings=12,
                findings_by_severity={"critical": 3},
                critical_findings=["c1", "c2", "c3"],
                finding_ids={"f1", "f2", "f3", "f4", "f5"},
            ),
            ScanSnapshot(
                timestamp=datetime.utcnow(),
                snapshot_id="snap-3",
                total_findings=8,
                findings_by_severity={"critical": 1},
                critical_findings=["c1"],
                finding_ids={"f1", "f2"},
            ),
        ]

        scan_index = [0]

        def mock_scan():
            idx = scan_index[0]
            scan_index[0] += 1
            return snapshots[idx]

        watch._perform_scan = mock_scan

        # Track deltas
        deltas = []

        def track_delta(snapshot, delta):
            if delta:
                deltas.append(delta)

        watch.add_callback(track_delta)
        watch.start()

        assert len(watch.snapshots) == 3
        assert len(deltas) == 2

        # First delta: degradation (10 -> 12 findings)
        assert deltas[0].is_degraded is True
        assert deltas[0].new_critical == 1

        # Second delta: improvement (12 -> 8 findings)
        assert deltas[1].is_improved is True
        assert deltas[1].resolved_findings == 3


class TestWatchModeSeverityChanges:
    """Tests for severity change tracking."""

    def test_severity_changes_tracked(self):
        """Test that severity changes are tracked correctly."""
        watch = WatchMode()

        prev = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-1",
            findings_by_severity={
                "critical": 5,
                "high": 10,
                "medium": 15,
            },
            finding_ids=set(),
        )
        curr = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-2",
            findings_by_severity={
                "critical": 3,
                "high": 12,
                "medium": 10,
            },
            finding_ids=set(),
        )

        delta = watch._calculate_delta(prev, curr)

        assert delta.severity_changes["critical"] == -2
        assert delta.severity_changes["high"] == 2
        assert delta.severity_changes["medium"] == -5

    def test_no_severity_change_not_tracked(self):
        """Test that unchanged severities are not in changes."""
        watch = WatchMode()

        prev = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-1",
            findings_by_severity={"high": 5},
            finding_ids=set(),
        )
        curr = ScanSnapshot(
            timestamp=datetime.utcnow(),
            snapshot_id="snap-2",
            findings_by_severity={"high": 5},
            finding_ids=set(),
        )

        delta = watch._calculate_delta(prev, curr)

        assert "high" not in delta.severity_changes
