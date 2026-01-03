"""
Unit tests for CLI Drift Detection commands.

Tests the drift detection CLI including:
- Drift detection
- Baseline management (create, list, show, update, archive, delete)
- Change history and tracking
- Summary reporting
"""

from __future__ import annotations

import argparse
import json
import pytest
from datetime import datetime, timedelta
from io import StringIO
from unittest.mock import MagicMock, patch, PropertyMock

from stance.cli_drift import (
    cmd_drift,
    _cmd_drift_detect,
    _cmd_drift_baseline,
    _cmd_drift_history,
    _cmd_drift_changes,
    _cmd_drift_summary,
    _cmd_baseline_create,
    _cmd_baseline_list,
    _cmd_baseline_show,
    _cmd_baseline_update,
    _cmd_baseline_archive,
    _cmd_baseline_delete,
)
from stance.drift.baseline import (
    Baseline,
    BaselineStatus,
    BaselineManager,
    AssetBaseline,
    BaselineConfig,
)
from stance.drift.drift_detector import (
    DriftDetector,
    DriftDetectionResult,
    DriftEvent,
    DriftType,
    DriftSeverity,
    ConfigDifference,
)
from stance.drift.change_tracker import (
    ChangeTracker,
    ChangeEvent,
    ChangeType,
    AssetHistory,
    ConfigSnapshot,
)
from stance.models.asset import Asset, AssetCollection


class TestCmdDrift:
    """Tests for the main drift command router."""

    def test_drift_no_action_shows_help(self, capsys):
        """Test drift with no action shows usage."""
        args = argparse.Namespace(drift_action=None)
        result = cmd_drift(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage: stance drift <command>" in captured.out
        assert "detect" in captured.out
        assert "baseline" in captured.out
        assert "history" in captured.out
        assert "changes" in captured.out
        assert "summary" in captured.out

    def test_drift_unknown_action(self, capsys):
        """Test drift with unknown action returns error."""
        args = argparse.Namespace(drift_action="unknown")
        result = cmd_drift(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown drift command: unknown" in captured.out


class TestDriftDetect:
    """Tests for drift detection command."""

    @pytest.fixture
    def mock_assets(self):
        """Create mock assets collection."""
        asset = Asset(
            id="asset-001",
            name="test-bucket",
            resource_type="aws_s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
            raw_config={"Versioning": True, "Encryption": True},
        )
        collection = MagicMock(spec=AssetCollection)
        collection.assets = [asset]
        return collection

    @pytest.fixture
    def mock_baseline(self):
        """Create mock baseline."""
        baseline = Baseline(
            id="baseline-123",
            name="test-baseline",
            description="Test baseline",
            status=BaselineStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        return baseline

    @pytest.fixture
    def mock_drift_result(self):
        """Create mock drift detection result."""
        drift_event = DriftEvent(
            asset_id="asset-001",
            asset_type="aws_s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
            drift_type=DriftType.CONFIG_CHANGED,
            severity=DriftSeverity.MEDIUM,
            differences=[
                ConfigDifference(
                    path="Encryption",
                    change_type="changed",
                    baseline_value=True,
                    current_value=False,
                    is_security_relevant=True,
                    severity=DriftSeverity.MEDIUM,
                )
            ],
            detected_at=datetime.utcnow(),
            baseline_id="baseline-123",
            description="Configuration drift detected",
        )

        return DriftDetectionResult(
            baseline_id="baseline-123",
            detected_at=datetime.utcnow(),
            drift_events=[drift_event],
            assets_checked=10,
            assets_with_drift=1,
            summary={
                "has_drift": True,
                "drift_by_severity": {"medium": 1},
                "security_drift_count": 1,
            },
        )

    def test_detect_no_assets(self, capsys):
        """Test detect with no assets available."""
        args = argparse.Namespace(
            format="table",
            baseline=None,
            severity=None,
            type=None,
            cloud=None,
            region=None,
            limit=50,
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = None
            result = _cmd_drift_detect(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No assets found" in captured.out

    def test_detect_no_baseline(self, capsys, mock_assets):
        """Test detect with no baseline available."""
        args = argparse.Namespace(
            format="table",
            baseline=None,
            severity=None,
            type=None,
            cloud=None,
            region=None,
            limit=50,
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager") as mock_manager:
                with patch("stance.cli_drift.DriftDetector") as mock_detector:
                    # Simulate no baseline found
                    mock_detector_instance = MagicMock()
                    mock_detector_instance.detect_drift.return_value = DriftDetectionResult(
                        baseline_id="none",
                        detected_at=datetime.utcnow(),
                        drift_events=[],
                        assets_checked=0,
                        assets_with_drift=0,
                        summary={"error": "No baseline found"},
                    )
                    mock_detector.return_value = mock_detector_instance

                    result = _cmd_drift_detect(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No baseline found" in captured.out

    def test_detect_success_table_format(self, capsys, mock_assets, mock_drift_result):
        """Test successful drift detection with table output."""
        args = argparse.Namespace(
            format="table",
            baseline=None,
            severity=None,
            type=None,
            cloud=None,
            region=None,
            limit=50,
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager"):
                with patch("stance.cli_drift.DriftDetector") as mock_detector:
                    mock_detector_instance = MagicMock()
                    mock_detector_instance.detect_drift.return_value = mock_drift_result
                    mock_detector.return_value = mock_detector_instance

                    result = _cmd_drift_detect(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Drift Detection Results" in captured.out
        assert "baseline-123" in captured.out
        assert "Assets checked: 10" in captured.out
        assert "Assets with drift: 1" in captured.out

    def test_detect_success_json_format(self, capsys, mock_assets, mock_drift_result):
        """Test successful drift detection with JSON output."""
        args = argparse.Namespace(
            format="json",
            baseline=None,
            severity=None,
            type=None,
            cloud=None,
            region=None,
            limit=50,
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager"):
                with patch("stance.cli_drift.DriftDetector") as mock_detector:
                    mock_detector_instance = MagicMock()
                    mock_detector_instance.detect_drift.return_value = mock_drift_result
                    mock_detector.return_value = mock_detector_instance

                    result = _cmd_drift_detect(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["baseline_id"] == "baseline-123"
        assert output["assets_checked"] == 10
        assert output["has_drift"] is True

    def test_detect_filter_by_severity(self, capsys, mock_assets, mock_drift_result):
        """Test drift detection filtering by severity."""
        args = argparse.Namespace(
            format="table",
            baseline=None,
            severity="high",
            type=None,
            cloud=None,
            region=None,
            limit=50,
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager"):
                with patch("stance.cli_drift.DriftDetector") as mock_detector:
                    mock_detector_instance = MagicMock()
                    mock_detector_instance.detect_drift.return_value = mock_drift_result
                    mock_detector.return_value = mock_detector_instance

                    result = _cmd_drift_detect(args)

        assert result == 0
        # Medium severity drift should be filtered out with high filter

    def test_detect_filter_by_cloud(self, capsys, mock_assets, mock_drift_result):
        """Test drift detection filtering by cloud provider."""
        args = argparse.Namespace(
            format="table",
            baseline=None,
            severity=None,
            type=None,
            cloud="aws",
            region=None,
            limit=50,
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager"):
                with patch("stance.cli_drift.DriftDetector") as mock_detector:
                    mock_detector_instance = MagicMock()
                    mock_detector_instance.detect_drift.return_value = mock_drift_result
                    mock_detector.return_value = mock_detector_instance

                    result = _cmd_drift_detect(args)

        assert result == 0


class TestBaselineCommands:
    """Tests for baseline management commands."""

    @pytest.fixture
    def mock_assets(self):
        """Create mock assets collection."""
        asset = Asset(
            id="asset-001",
            name="test-bucket",
            resource_type="aws_s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
        )
        collection = MagicMock(spec=AssetCollection)
        collection.assets = [asset]
        return collection

    @pytest.fixture
    def mock_baseline(self):
        """Create mock baseline."""
        baseline = Baseline(
            id="baseline-20231201-abc123",
            name="production-baseline",
            description="Production environment baseline",
            status=BaselineStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            created_by="cli",
        )
        # Add mock asset count
        type(baseline).asset_count = PropertyMock(return_value=5)
        return baseline

    def test_baseline_create_no_name(self, capsys):
        """Test baseline create without name returns error."""
        args = argparse.Namespace(
            baseline_action="create",
            name=None,
            description="",
            format="table",
        )

        result = _cmd_baseline_create(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Baseline name is required" in captured.out

    def test_baseline_create_no_assets(self, capsys):
        """Test baseline create with no assets available."""
        args = argparse.Namespace(
            baseline_action="create",
            name="test-baseline",
            description="Test",
            format="table",
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = None
            result = _cmd_baseline_create(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No assets found" in captured.out

    def test_baseline_create_success(self, capsys, mock_assets, mock_baseline):
        """Test successful baseline creation."""
        args = argparse.Namespace(
            baseline_action="create",
            name="test-baseline",
            description="Test description",
            format="table",
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager") as mock_manager:
                mock_manager_instance = MagicMock()
                mock_manager_instance.create_baseline.return_value = mock_baseline
                mock_manager.return_value = mock_manager_instance

                result = _cmd_baseline_create(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Baseline created successfully!" in captured.out
        assert "production-baseline" in captured.out

    def test_baseline_create_json_format(self, capsys, mock_assets, mock_baseline):
        """Test baseline creation with JSON output."""
        args = argparse.Namespace(
            baseline_action="create",
            name="test-baseline",
            description="Test",
            format="json",
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager") as mock_manager:
                mock_manager_instance = MagicMock()
                mock_manager_instance.create_baseline.return_value = mock_baseline
                mock_manager.return_value = mock_manager_instance

                result = _cmd_baseline_create(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["success"] is True
        assert "baseline" in output

    def test_baseline_list_empty(self, capsys):
        """Test baseline list with no baselines."""
        args = argparse.Namespace(
            baseline_action="list",
            status=None,
            format="table",
        )

        with patch("stance.cli_drift.BaselineManager") as mock_manager:
            mock_manager_instance = MagicMock()
            mock_manager_instance.list_baselines.return_value = []
            mock_manager.return_value = mock_manager_instance

            result = _cmd_baseline_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No baselines found" in captured.out

    def test_baseline_list_success(self, capsys, mock_baseline):
        """Test successful baseline listing."""
        args = argparse.Namespace(
            baseline_action="list",
            status=None,
            format="table",
        )

        with patch("stance.cli_drift.BaselineManager") as mock_manager:
            mock_manager_instance = MagicMock()
            mock_manager_instance.list_baselines.return_value = [mock_baseline]
            mock_manager.return_value = mock_manager_instance

            result = _cmd_baseline_list(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Baselines" in captured.out
        assert "production-baseline" in captured.out

    def test_baseline_list_filter_by_status(self, capsys, mock_baseline):
        """Test baseline listing filtered by status."""
        args = argparse.Namespace(
            baseline_action="list",
            status="active",
            format="table",
        )

        with patch("stance.cli_drift.BaselineManager") as mock_manager:
            mock_manager_instance = MagicMock()
            mock_manager_instance.list_baselines.return_value = [mock_baseline]
            mock_manager.return_value = mock_manager_instance

            result = _cmd_baseline_list(args)

        assert result == 0

    def test_baseline_show_not_found(self, capsys):
        """Test baseline show for non-existent baseline."""
        args = argparse.Namespace(
            baseline_action="show",
            id="nonexistent",
            format="table",
        )

        with patch("stance.cli_drift.BaselineManager") as mock_manager:
            mock_manager_instance = MagicMock()
            mock_manager_instance.get_baseline.return_value = None
            mock_manager.return_value = mock_manager_instance

            result = _cmd_baseline_show(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Baseline not found" in captured.out

    def test_baseline_show_success(self, capsys, mock_baseline):
        """Test successful baseline show."""
        args = argparse.Namespace(
            baseline_action="show",
            id="baseline-123",
            format="table",
        )

        with patch("stance.cli_drift.BaselineManager") as mock_manager:
            mock_manager_instance = MagicMock()
            mock_manager_instance.get_baseline.return_value = mock_baseline
            mock_manager.return_value = mock_manager_instance

            result = _cmd_baseline_show(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "production-baseline" in captured.out

    def test_baseline_update_no_id(self, capsys):
        """Test baseline update without ID."""
        args = argparse.Namespace(
            baseline_action="update",
            id=None,
            assets=None,
            format="table",
        )

        result = _cmd_baseline_update(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Baseline ID is required" in captured.out

    def test_baseline_update_success(self, capsys, mock_assets, mock_baseline):
        """Test successful baseline update."""
        args = argparse.Namespace(
            baseline_action="update",
            id="baseline-123",
            assets=None,
            format="table",
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager") as mock_manager:
                mock_manager_instance = MagicMock()
                mock_manager_instance.update_baseline.return_value = mock_baseline
                mock_manager.return_value = mock_manager_instance

                result = _cmd_baseline_update(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Baseline updated successfully!" in captured.out

    def test_baseline_archive_success(self, capsys):
        """Test successful baseline archive."""
        args = argparse.Namespace(
            baseline_action="archive",
            id="baseline-123",
            format="table",
        )

        with patch("stance.cli_drift.BaselineManager") as mock_manager:
            mock_manager_instance = MagicMock()
            mock_manager_instance.archive_baseline.return_value = True
            mock_manager.return_value = mock_manager_instance

            result = _cmd_baseline_archive(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Baseline archived" in captured.out

    def test_baseline_delete_no_force(self, capsys):
        """Test baseline delete without force flag."""
        args = argparse.Namespace(
            baseline_action="delete",
            id="baseline-123",
            force=False,
            format="table",
        )

        result = _cmd_baseline_delete(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Use --force to confirm" in captured.out

    def test_baseline_delete_success(self, capsys):
        """Test successful baseline deletion."""
        args = argparse.Namespace(
            baseline_action="delete",
            id="baseline-123",
            force=True,
            format="table",
        )

        with patch("stance.cli_drift.BaselineManager") as mock_manager:
            mock_manager_instance = MagicMock()
            mock_manager_instance.delete_baseline.return_value = True
            mock_manager.return_value = mock_manager_instance

            result = _cmd_baseline_delete(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Baseline deleted" in captured.out


class TestHistoryCommand:
    """Tests for drift history command."""

    @pytest.fixture
    def mock_history(self):
        """Create mock asset history."""
        history = AssetHistory(
            asset_id="asset-001",
            asset_type="aws_s3_bucket",
            cloud_provider="aws",
            first_seen=datetime.utcnow() - timedelta(days=30),
            last_seen=datetime.utcnow(),
        )
        return history

    def test_history_no_asset_id(self, capsys):
        """Test history without asset ID."""
        args = argparse.Namespace(
            drift_action="history",
            asset_id=None,
            days=30,
            format="table",
        )

        result = _cmd_drift_history(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Asset ID is required" in captured.out

    def test_history_not_found(self, capsys):
        """Test history for asset with no history."""
        args = argparse.Namespace(
            drift_action="history",
            asset_id="nonexistent",
            days=30,
            format="table",
        )

        with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
            mock_tracker_instance = MagicMock()
            mock_tracker_instance.get_asset_history.return_value = None
            mock_tracker.return_value = mock_tracker_instance

            result = _cmd_drift_history(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No history found" in captured.out

    def test_history_success(self, capsys, mock_history):
        """Test successful history retrieval."""
        args = argparse.Namespace(
            drift_action="history",
            asset_id="asset-001",
            days=30,
            format="table",
        )

        timeline = [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "change_type": "updated",
                "changed_paths": ["Encryption (changed)"],
                "attributed_to": "admin",
                "source": "console",
            }
        ]

        with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
            mock_tracker_instance = MagicMock()
            mock_tracker_instance.get_asset_history.return_value = mock_history
            mock_tracker_instance.get_change_timeline.return_value = timeline
            mock_tracker.return_value = mock_tracker_instance

            result = _cmd_drift_history(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Change History" in captured.out
        assert "asset-001" in captured.out

    def test_history_json_format(self, capsys, mock_history):
        """Test history with JSON output."""
        args = argparse.Namespace(
            drift_action="history",
            asset_id="asset-001",
            days=30,
            format="json",
        )

        timeline = []

        with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
            mock_tracker_instance = MagicMock()
            mock_tracker_instance.get_asset_history.return_value = mock_history
            mock_tracker_instance.get_change_timeline.return_value = timeline
            mock_tracker.return_value = mock_tracker_instance

            result = _cmd_drift_history(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["asset_id"] == "asset-001"


class TestChangesCommand:
    """Tests for drift changes command."""

    def test_changes_empty(self, capsys):
        """Test changes with no recent changes."""
        args = argparse.Namespace(
            drift_action="changes",
            hours=24,
            type=None,
            limit=50,
            format="table",
        )

        summary = {
            "period_hours": 24,
            "total_changes": 0,
            "unique_assets_changed": 0,
            "created": 0,
            "updated": 0,
            "deleted": 0,
            "most_active_assets": [],
        }

        with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
            mock_tracker_instance = MagicMock()
            mock_tracker_instance.get_change_summary.return_value = summary
            mock_tracker_instance.get_recent_changes.return_value = []
            mock_tracker.return_value = mock_tracker_instance

            result = _cmd_drift_changes(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No changes found" in captured.out

    def test_changes_success(self, capsys):
        """Test successful changes retrieval."""
        args = argparse.Namespace(
            drift_action="changes",
            hours=24,
            type=None,
            limit=50,
            format="table",
        )

        summary = {
            "period_hours": 24,
            "total_changes": 5,
            "unique_assets_changed": 3,
            "created": 1,
            "updated": 3,
            "deleted": 1,
            "most_active_assets": [
                {"asset_id": "asset-001", "change_count": 3},
            ],
        }

        mock_change = MagicMock()
        mock_change.detected_at = datetime.utcnow()
        mock_change.asset_id = "asset-001"
        mock_change.change_type = ChangeType.UPDATED
        mock_change.source = "console"

        with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
            mock_tracker_instance = MagicMock()
            mock_tracker_instance.get_change_summary.return_value = summary
            mock_tracker_instance.get_recent_changes.return_value = [mock_change]
            mock_tracker.return_value = mock_tracker_instance

            result = _cmd_drift_changes(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Recent Changes" in captured.out
        assert "Total changes: 5" in captured.out

    def test_changes_json_format(self, capsys):
        """Test changes with JSON output."""
        args = argparse.Namespace(
            drift_action="changes",
            hours=24,
            type=None,
            limit=50,
            format="json",
        )

        summary = {
            "period_hours": 24,
            "total_changes": 0,
            "unique_assets_changed": 0,
            "created": 0,
            "updated": 0,
            "deleted": 0,
        }

        with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
            mock_tracker_instance = MagicMock()
            mock_tracker_instance.get_change_summary.return_value = summary
            mock_tracker_instance.get_recent_changes.return_value = []
            mock_tracker.return_value = mock_tracker_instance

            result = _cmd_drift_changes(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["period_hours"] == 24


class TestSummaryCommand:
    """Tests for drift summary command."""

    @pytest.fixture
    def mock_assets(self):
        """Create mock assets collection."""
        asset = Asset(
            id="asset-001",
            name="test-bucket",
            resource_type="aws_s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
        )
        collection = MagicMock(spec=AssetCollection)
        collection.assets = [asset]
        return collection

    def test_summary_no_assets(self, capsys):
        """Test summary with no assets."""
        args = argparse.Namespace(
            drift_action="summary",
            hours=24,
            format="table",
        )

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = None
            result = _cmd_drift_summary(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No assets found" in captured.out

    def test_summary_no_baseline(self, capsys, mock_assets):
        """Test summary with no active baseline."""
        args = argparse.Namespace(
            drift_action="summary",
            hours=24,
            format="table",
        )

        change_summary = {
            "total_changes": 0,
            "unique_assets_changed": 0,
            "created": 0,
            "updated": 0,
            "deleted": 0,
        }

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager") as mock_manager:
                mock_manager_instance = MagicMock()
                mock_manager_instance.list_baselines.return_value = []
                mock_manager_instance.get_active_baseline.return_value = None
                mock_manager.return_value = mock_manager_instance

                with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
                    mock_tracker_instance = MagicMock()
                    mock_tracker_instance.get_change_summary.return_value = change_summary
                    mock_tracker.return_value = mock_tracker_instance

                    result = _cmd_drift_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Drift Detection Summary" in captured.out
        assert "Active baseline: None" in captured.out

    def test_summary_with_drift(self, capsys, mock_assets):
        """Test summary with drift detected."""
        args = argparse.Namespace(
            drift_action="summary",
            hours=24,
            format="table",
        )

        mock_baseline = Baseline(
            id="baseline-123",
            name="prod-baseline",
            description="",
            status=BaselineStatus.ACTIVE,
        )
        type(mock_baseline).asset_count = PropertyMock(return_value=10)

        mock_drift_result = DriftDetectionResult(
            baseline_id="baseline-123",
            detected_at=datetime.utcnow(),
            drift_events=[],
            assets_checked=10,
            assets_with_drift=2,
            summary={
                "has_drift": True,
                "drift_by_severity": {"medium": 2},
                "security_drift_count": 1,
            },
        )

        change_summary = {
            "total_changes": 5,
            "unique_assets_changed": 3,
            "created": 1,
            "updated": 3,
            "deleted": 1,
        }

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager") as mock_manager:
                mock_manager_instance = MagicMock()
                mock_manager_instance.list_baselines.return_value = [mock_baseline]
                mock_manager_instance.get_active_baseline.return_value = mock_baseline
                mock_manager.return_value = mock_manager_instance

                with patch("stance.cli_drift.DriftDetector") as mock_detector:
                    mock_detector_instance = MagicMock()
                    mock_detector_instance.detect_drift.return_value = mock_drift_result
                    mock_detector.return_value = mock_detector_instance

                    with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
                        mock_tracker_instance = MagicMock()
                        mock_tracker_instance.get_change_summary.return_value = change_summary
                        mock_tracker.return_value = mock_tracker_instance

                        result = _cmd_drift_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Drift Detection Summary" in captured.out
        assert "Has drift: Yes" in captured.out

    def test_summary_json_format(self, capsys, mock_assets):
        """Test summary with JSON output."""
        args = argparse.Namespace(
            drift_action="summary",
            hours=24,
            format="json",
        )

        change_summary = {
            "total_changes": 0,
            "unique_assets_changed": 0,
            "created": 0,
            "updated": 0,
            "deleted": 0,
        }

        with patch("stance.cli_drift.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets

            with patch("stance.cli_drift.BaselineManager") as mock_manager:
                mock_manager_instance = MagicMock()
                mock_manager_instance.list_baselines.return_value = []
                mock_manager_instance.get_active_baseline.return_value = None
                mock_manager.return_value = mock_manager_instance

                with patch("stance.cli_drift.ChangeTracker") as mock_tracker:
                    mock_tracker_instance = MagicMock()
                    mock_tracker_instance.get_change_summary.return_value = change_summary
                    mock_tracker.return_value = mock_tracker_instance

                    result = _cmd_drift_summary(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "assets" in output
        assert "baselines" in output
        assert "changes" in output


class TestCLIIntegration:
    """Integration tests for CLI argument parsing."""

    def test_parser_drift_detect(self):
        """Test drift detect parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "drift", "detect",
            "--severity", "high",
            "--cloud", "aws",
            "--format", "json",
        ])

        assert args.command == "drift"
        assert args.drift_action == "detect"
        assert args.severity == "high"
        assert args.cloud == "aws"
        assert args.format == "json"

    def test_parser_drift_baseline_create(self):
        """Test drift baseline create parser."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "drift", "baseline", "create",
            "--name", "prod-baseline",
            "--description", "Production baseline",
        ])

        assert args.command == "drift"
        assert args.drift_action == "baseline"
        assert args.baseline_action == "create"
        assert args.name == "prod-baseline"
        assert args.description == "Production baseline"

    def test_parser_drift_baseline_list(self):
        """Test drift baseline list parser."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "drift", "baseline", "list",
            "--status", "active",
        ])

        assert args.command == "drift"
        assert args.drift_action == "baseline"
        assert args.baseline_action == "list"
        assert args.status == "active"

    def test_parser_drift_history(self):
        """Test drift history parser."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "drift", "history",
            "--asset-id", "asset-123",
            "--days", "7",
        ])

        assert args.command == "drift"
        assert args.drift_action == "history"
        assert args.asset_id == "asset-123"
        assert args.days == 7

    def test_parser_drift_changes(self):
        """Test drift changes parser."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "drift", "changes",
            "--hours", "48",
            "--type", "updated",
        ])

        assert args.command == "drift"
        assert args.drift_action == "changes"
        assert args.hours == 48
        assert args.type == "updated"

    def test_parser_drift_summary(self):
        """Test drift summary parser."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "drift", "summary",
            "--format", "json",
        ])

        assert args.command == "drift"
        assert args.drift_action == "summary"
        assert args.format == "json"
