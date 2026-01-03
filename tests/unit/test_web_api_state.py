"""
Unit tests for Web API State endpoints.

Tests the REST API endpoints for state management including scans,
checkpoints, and finding lifecycle tracking.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from unittest import mock

import pytest


class TestStateScansEndpoint:
    """Tests for /api/state/scans endpoint."""

    def test_scans_empty(self):
        """Test scans endpoint with no data."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler.storage = None

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = []

            result = StanceRequestHandler._state_scans(handler, {})

            assert "scans" in result
            assert result["scans"] == []
            assert result["total"] == 0

    def test_scans_with_data(self):
        """Test scans endpoint with data."""
        from stance.state import ScanRecord, ScanStatus
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)
        handler.storage = None

        mock_scan = ScanRecord(
            scan_id="scan-001",
            snapshot_id="snap-001",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
            asset_count=100,
            finding_count=10,
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]

            result = StanceRequestHandler._state_scans(handler, {"limit": ["10"]})

            assert len(result["scans"]) == 1
            assert result["scans"][0]["scan_id"] == "scan-001"
            assert result["total"] == 1

    def test_scans_with_status_filter(self):
        """Test scans endpoint with status filter."""
        from stance.state import ScanStatus
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = []

            result = StanceRequestHandler._state_scans(handler, {"status": ["completed"]})

            # Verify status filter was applied
            call_args = mock_manager.return_value.backend.list_scans.call_args
            assert call_args[1]["status"] == ScanStatus.COMPLETED


class TestStateScanEndpoint:
    """Tests for /api/state/scan endpoint."""

    def test_scan_missing_id(self):
        """Test scan endpoint without scan_id."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_scan(handler, {})

        assert "error" in result
        assert "scan_id" in result["error"]

    def test_scan_not_found(self):
        """Test scan endpoint with nonexistent scan."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_scan.return_value = None

            result = StanceRequestHandler._state_scan(handler, {"scan_id": ["nonexistent"]})

            assert "error" in result
            assert "not found" in result["error"].lower()

    def test_scan_found(self):
        """Test scan endpoint with valid scan."""
        from stance.state import ScanRecord, ScanStatus
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_scan = ScanRecord(
            scan_id="scan-002",
            snapshot_id="snap-002",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_scan.return_value = mock_scan

            result = StanceRequestHandler._state_scan(handler, {"scan_id": ["scan-002"]})

            assert result["scan_id"] == "scan-002"
            assert result["status"] == "completed"


class TestStateCheckpointsEndpoint:
    """Tests for /api/state/checkpoints endpoint."""

    def test_checkpoints_no_database(self):
        """Test checkpoints endpoint when database doesn't exist."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("os.path.expanduser") as mock_expand:
            mock_expand.return_value = "/nonexistent/path/state.db"

            with mock.patch("pathlib.Path") as mock_path:
                mock_path.return_value.exists.return_value = False

                result = StanceRequestHandler._state_checkpoints(handler, {})

                assert result["checkpoints"] == []
                assert result["total"] == 0

    def test_checkpoints_with_filters(self):
        """Test checkpoints endpoint with filters."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("os.path.expanduser") as mock_expand:
            mock_expand.return_value = "/tmp/state.db"

            with mock.patch("pathlib.Path") as mock_path:
                mock_path.return_value.exists.return_value = True

                with mock.patch("sqlite3.connect") as mock_conn:
                    mock_row = mock.MagicMock()
                    mock_row.__getitem__ = lambda self, key: {
                        "checkpoint_id": "cp-001",
                        "collector_name": "IAMCollector",
                        "account_id": "123456789",
                        "region": "us-east-1",
                        "last_scan_id": "scan-001",
                        "last_scan_time": "2025-01-01T12:00:00",
                        "cursor": "",
                    }[key]

                    mock_cursor = mock.MagicMock()
                    mock_cursor.fetchall.return_value = [mock_row]
                    mock_conn.return_value.__enter__.return_value.execute.return_value = mock_cursor
                    mock_conn.return_value.__enter__.return_value.row_factory = None

                    result = StanceRequestHandler._state_checkpoints(
                        handler,
                        {"collector": ["IAMCollector"]}
                    )

                    assert "checkpoints" in result


class TestStateCheckpointEndpoint:
    """Tests for /api/state/checkpoint endpoint."""

    def test_checkpoint_missing_params(self):
        """Test checkpoint endpoint without required params."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_checkpoint(handler, {})

        assert "error" in result

    def test_checkpoint_not_found(self):
        """Test checkpoint endpoint with nonexistent checkpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.get_checkpoint.return_value = None

            result = StanceRequestHandler._state_checkpoint(
                handler,
                {"collector": ["IAM"], "account": ["123"], "region": ["us-east-1"]}
            )

            assert "error" in result
            assert "not found" in result["error"].lower()

    def test_checkpoint_found(self):
        """Test checkpoint endpoint with valid checkpoint."""
        from stance.state import Checkpoint
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_cp = Checkpoint(
            checkpoint_id="cp-001",
            collector_name="IAMCollector",
            account_id="123456789",
            region="us-east-1",
            last_scan_id="scan-001",
            last_scan_time=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.get_checkpoint.return_value = mock_cp

            result = StanceRequestHandler._state_checkpoint(
                handler,
                {"collector": ["IAMCollector"], "account": ["123456789"], "region": ["us-east-1"]}
            )

            assert result["checkpoint_id"] == "cp-001"


class TestStateFindingsEndpoint:
    """Tests for /api/state/findings endpoint."""

    def test_findings_empty(self):
        """Test findings endpoint with no data."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_finding_states.return_value = []

            result = StanceRequestHandler._state_findings(handler, {})

            assert result["findings"] == []
            assert result["total"] == 0

    def test_findings_with_data(self):
        """Test findings endpoint with data."""
        from stance.state import FindingLifecycle, FindingState
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_finding = FindingState(
            finding_id="finding-001",
            asset_id="asset-001",
            rule_id="rule-001",
            lifecycle=FindingLifecycle.NEW,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_finding_states.return_value = [mock_finding]

            result = StanceRequestHandler._state_findings(handler, {})

            assert len(result["findings"]) == 1
            assert result["findings"][0]["finding_id"] == "finding-001"


class TestStateFindingEndpoint:
    """Tests for /api/state/finding endpoint."""

    def test_finding_missing_id(self):
        """Test finding endpoint without finding_id."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_finding(handler, {})

        assert "error" in result
        assert "finding_id" in result["error"]

    def test_finding_not_found(self):
        """Test finding endpoint with nonexistent finding."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_finding_state.return_value = None

            result = StanceRequestHandler._state_finding(handler, {"finding_id": ["nonexistent"]})

            assert "error" in result

    def test_finding_found(self):
        """Test finding endpoint with valid finding."""
        from stance.state import FindingLifecycle, FindingState
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_state = FindingState(
            finding_id="finding-002",
            asset_id="asset-002",
            rule_id="rule-002",
            lifecycle=FindingLifecycle.RECURRING,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.get_finding_state.return_value = mock_state

            result = StanceRequestHandler._state_finding(handler, {"finding_id": ["finding-002"]})

            assert result["finding_id"] == "finding-002"
            assert result["lifecycle"] == "recurring"


class TestStateScanStatusesEndpoint:
    """Tests for /api/state/scan-statuses endpoint."""

    def test_scan_statuses(self):
        """Test scan statuses endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_scan_statuses(handler, {})

        assert "statuses" in result
        assert result["total"] == 5
        statuses = [s["status"] for s in result["statuses"]]
        assert "pending" in statuses
        assert "running" in statuses
        assert "completed" in statuses
        assert "failed" in statuses
        assert "cancelled" in statuses


class TestStateLifecyclesEndpoint:
    """Tests for /api/state/lifecycles endpoint."""

    def test_lifecycles(self):
        """Test lifecycles endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_lifecycles(handler, {})

        assert "lifecycles" in result
        assert result["total"] == 6
        lifecycles = [lc["lifecycle"] for lc in result["lifecycles"]]
        assert "new" in lifecycles
        assert "recurring" in lifecycles
        assert "resolved" in lifecycles
        assert "suppressed" in lifecycles


class TestStateBackendsEndpoint:
    """Tests for /api/state/backends endpoint."""

    def test_backends(self):
        """Test backends endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_backends(handler, {})

        assert "backends" in result
        assert result["total"] == 4
        backends = [b["backend"] for b in result["backends"]]
        assert "local" in backends
        assert "dynamodb" in backends
        assert "firestore" in backends
        assert "cosmosdb" in backends

        # Verify local is available and default
        local = next(b for b in result["backends"] if b["backend"] == "local")
        assert local["available"] is True
        assert local["default"] is True


class TestStateFindingStatsEndpoint:
    """Tests for /api/state/finding-stats endpoint."""

    def test_finding_stats(self):
        """Test finding stats endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_stats = {
            "new": 10,
            "recurring": 5,
            "resolved": 3,
        }

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.get_finding_stats.return_value = mock_stats

            result = StanceRequestHandler._state_finding_stats(handler, {})

            assert "stats" in result
            assert result["stats"]["new"] == 10
            assert result["total"] == 18
            assert "breakdown" in result


class TestStateStatsEndpoint:
    """Tests for /api/state/stats endpoint."""

    def test_stats(self):
        """Test stats endpoint."""
        from stance.state import ScanRecord, ScanStatus
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_scan = ScanRecord(
            scan_id="scan-001",
            snapshot_id="snap-001",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]
            mock_manager.return_value.get_finding_stats.return_value = {"new": 5}

            with mock.patch("os.path.expanduser") as mock_expand:
                mock_expand.return_value = "/tmp/state.db"

                with mock.patch("pathlib.Path") as mock_path:
                    mock_path.return_value.exists.return_value = True

                    with mock.patch("sqlite3.connect") as mock_conn:
                        mock_cursor = mock.MagicMock()
                        mock_cursor.fetchone.return_value = (5,)
                        mock_conn.return_value.__enter__.return_value.execute.return_value = mock_cursor

                        result = StanceRequestHandler._state_stats(handler, {})

                        assert "scans" in result
                        assert "checkpoints" in result
                        assert "findings" in result


class TestStateStatusEndpoint:
    """Tests for /api/state/status endpoint."""

    def test_status(self):
        """Test status endpoint."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("os.path.expanduser") as mock_expand:
            mock_expand.return_value = "/tmp/state.db"

            with mock.patch("pathlib.Path") as mock_path:
                mock_path.return_value.exists.return_value = True

                result = StanceRequestHandler._state_status(handler, {})

                assert result["module"] == "state"
                assert result["active_backend"] == "local"
                assert "StateManager" in result["components"]
                assert "scan_tracking" in result["capabilities"]


class TestStateSummaryEndpoint:
    """Tests for /api/state/summary endpoint."""

    def test_summary(self):
        """Test summary endpoint."""
        from stance.state import ScanRecord, ScanStatus
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_scan = ScanRecord(
            scan_id="scan-001",
            snapshot_id="snap-001",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.list_scans.return_value = [mock_scan]
            mock_manager.return_value.get_finding_stats.return_value = {"new": 5, "resolved": 3}

            # Mock _get_checkpoint_count
            with mock.patch.object(StanceRequestHandler, "_get_checkpoint_count", return_value=2):
                with mock.patch("os.path.expanduser") as mock_expand:
                    mock_expand.return_value = "/tmp/state.db"

                    with mock.patch("pathlib.Path") as mock_path:
                        mock_path.return_value.exists.return_value = True
                        mock_path.return_value.stat.return_value.st_size = 1024

                        result = StanceRequestHandler._state_summary(handler, {})

                        assert "overview" in result
                        assert "scans" in result
                        assert "features" in result
                        assert result["scans"]["total"] == 1


class TestStateSuppressEndpoint:
    """Tests for /api/state/suppress POST endpoint."""

    def test_suppress_missing_finding_id(self):
        """Test suppress with missing finding_id."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_suppress(handler, b'{}')

        assert "error" in result
        assert "finding_id" in result["error"]

    def test_suppress_finding_not_found(self):
        """Test suppress with nonexistent finding."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.suppress_finding.return_value = None

            body = json.dumps({"finding_id": "nonexistent"}).encode()
            result = StanceRequestHandler._state_suppress(handler, body)

            assert "error" in result

    def test_suppress_success(self):
        """Test successful suppression."""
        from stance.state import FindingLifecycle, FindingState
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_state = FindingState(
            finding_id="finding-001",
            asset_id="asset-001",
            rule_id="rule-001",
            lifecycle=FindingLifecycle.SUPPRESSED,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.suppress_finding.return_value = mock_state

            body = json.dumps({
                "finding_id": "finding-001",
                "by": "admin",
                "reason": "False positive"
            }).encode()
            result = StanceRequestHandler._state_suppress(handler, body)

            assert result["suppressed"] is True
            assert result["lifecycle"] == "suppressed"

    def test_suppress_invalid_json(self):
        """Test suppress with invalid JSON."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_suppress(handler, b'invalid json')

        assert "error" in result


class TestStateResolveEndpoint:
    """Tests for /api/state/resolve POST endpoint."""

    def test_resolve_missing_finding_id(self):
        """Test resolve with missing finding_id."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_resolve(handler, b'{}')

        assert "error" in result
        assert "finding_id" in result["error"]

    def test_resolve_finding_not_found(self):
        """Test resolve with nonexistent finding."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.resolve_finding.return_value = None

            body = json.dumps({"finding_id": "nonexistent"}).encode()
            result = StanceRequestHandler._state_resolve(handler, body)

            assert "error" in result

    def test_resolve_success(self):
        """Test successful resolution."""
        from stance.state import FindingLifecycle, FindingState
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        mock_state = FindingState(
            finding_id="finding-002",
            asset_id="asset-002",
            rule_id="rule-002",
            lifecycle=FindingLifecycle.RESOLVED,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            resolved_at=datetime.utcnow(),
        )

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.resolve_finding.return_value = mock_state

            body = json.dumps({"finding_id": "finding-002"}).encode()
            result = StanceRequestHandler._state_resolve(handler, body)

            assert result["resolved"] is True
            assert result["lifecycle"] == "resolved"


class TestStateDeleteCheckpointEndpoint:
    """Tests for /api/state/delete-checkpoint POST endpoint."""

    def test_delete_checkpoint_missing_params(self):
        """Test delete checkpoint with missing params."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._state_delete_checkpoint(handler, b'{}')

        assert "error" in result

    def test_delete_checkpoint_success(self):
        """Test successful checkpoint deletion."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.delete_checkpoint.return_value = True

            body = json.dumps({
                "collector": "IAMCollector",
                "account": "123456789",
                "region": "us-east-1"
            }).encode()
            result = StanceRequestHandler._state_delete_checkpoint(handler, body)

            assert result["deleted"] is True

    def test_delete_checkpoint_not_found(self):
        """Test delete checkpoint when not found."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("stance.state.get_state_manager") as mock_manager:
            mock_manager.return_value.backend.delete_checkpoint.return_value = False

            body = json.dumps({
                "collector": "IAMCollector",
                "account": "123456789",
                "region": "us-east-1"
            }).encode()
            result = StanceRequestHandler._state_delete_checkpoint(handler, body)

            assert result["deleted"] is False


class TestGetCheckpointCount:
    """Tests for _get_checkpoint_count helper."""

    def test_no_database(self):
        """Test when database doesn't exist."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("os.path.expanduser") as mock_expand:
            mock_expand.return_value = "/nonexistent/path/state.db"

            with mock.patch("pathlib.Path") as mock_path:
                mock_path.return_value.exists.return_value = False

                result = StanceRequestHandler._get_checkpoint_count(handler)

                assert result == 0

    def test_with_checkpoints(self):
        """Test with checkpoints in database."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        with mock.patch("os.path.expanduser") as mock_expand:
            mock_expand.return_value = "/tmp/state.db"

            with mock.patch("pathlib.Path") as mock_path:
                mock_path.return_value.exists.return_value = True

                with mock.patch("sqlite3.connect") as mock_conn:
                    mock_cursor = mock.MagicMock()
                    mock_cursor.fetchone.return_value = (5,)
                    mock_conn.return_value.__enter__.return_value.execute.return_value = mock_cursor

                    result = StanceRequestHandler._get_checkpoint_count(handler)

                    assert result == 5


class TestStateEndpointIntegration:
    """Integration tests for state API endpoints."""

    def test_all_get_endpoints_exist(self):
        """Test that all GET endpoints are defined."""
        from stance.web.server import StanceRequestHandler

        endpoints = [
            "_state_scans",
            "_state_scan",
            "_state_checkpoints",
            "_state_checkpoint",
            "_state_findings",
            "_state_finding",
            "_state_scan_statuses",
            "_state_lifecycles",
            "_state_backends",
            "_state_finding_stats",
            "_state_stats",
            "_state_status",
            "_state_summary",
        ]

        for endpoint in endpoints:
            assert hasattr(StanceRequestHandler, endpoint), f"Missing endpoint: {endpoint}"

    def test_all_post_endpoints_exist(self):
        """Test that all POST endpoints are defined."""
        from stance.web.server import StanceRequestHandler

        endpoints = [
            "_state_suppress",
            "_state_resolve",
            "_state_delete_checkpoint",
        ]

        for endpoint in endpoints:
            assert hasattr(StanceRequestHandler, endpoint), f"Missing endpoint: {endpoint}"

    def test_endpoints_return_dict(self):
        """Test that endpoints return dictionaries."""
        from stance.web.server import StanceRequestHandler

        handler = mock.MagicMock(spec=StanceRequestHandler)

        # Test a few static endpoints
        result = StanceRequestHandler._state_scan_statuses(handler, {})
        assert isinstance(result, dict)

        result = StanceRequestHandler._state_lifecycles(handler, {})
        assert isinstance(result, dict)

        result = StanceRequestHandler._state_backends(handler, {})
        assert isinstance(result, dict)
