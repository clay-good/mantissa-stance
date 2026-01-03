"""
Unit tests for state management module.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta

import pytest

from stance.state import (
    Checkpoint,
    FindingLifecycle,
    FindingState,
    LocalStateBackend,
    ScanRecord,
    ScanStatus,
    StateBackend,
    StateManager,
    get_state_manager,
)


class TestScanStatus:
    """Tests for ScanStatus enum."""

    def test_scan_status_values(self):
        """Test ScanStatus enum has expected values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"

    def test_scan_status_from_value(self):
        """Test creating ScanStatus from value."""
        assert ScanStatus("running") == ScanStatus.RUNNING
        assert ScanStatus("completed") == ScanStatus.COMPLETED


class TestFindingLifecycle:
    """Tests for FindingLifecycle enum."""

    def test_finding_lifecycle_values(self):
        """Test FindingLifecycle enum has expected values."""
        assert FindingLifecycle.NEW.value == "new"
        assert FindingLifecycle.RECURRING.value == "recurring"
        assert FindingLifecycle.RESOLVED.value == "resolved"
        assert FindingLifecycle.REOPENED.value == "reopened"
        assert FindingLifecycle.SUPPRESSED.value == "suppressed"
        assert FindingLifecycle.FALSE_POSITIVE.value == "false_positive"

    def test_finding_lifecycle_from_value(self):
        """Test creating FindingLifecycle from value."""
        assert FindingLifecycle("new") == FindingLifecycle.NEW
        assert FindingLifecycle("resolved") == FindingLifecycle.RESOLVED


class TestScanRecord:
    """Tests for ScanRecord dataclass."""

    def test_scan_record_creation(self):
        """Test creating a ScanRecord."""
        now = datetime.utcnow()
        record = ScanRecord(
            scan_id="scan-001",
            snapshot_id="20240115-120000",
            status=ScanStatus.RUNNING,
            started_at=now,
        )

        assert record.scan_id == "scan-001"
        assert record.snapshot_id == "20240115-120000"
        assert record.status == ScanStatus.RUNNING
        assert record.started_at == now
        assert record.completed_at is None
        assert record.config_name == "default"
        assert record.asset_count == 0
        assert record.finding_count == 0

    def test_scan_record_with_all_fields(self):
        """Test ScanRecord with all optional fields."""
        now = datetime.utcnow()
        completed = now + timedelta(minutes=5)

        record = ScanRecord(
            scan_id="scan-002",
            snapshot_id="20240115-120500",
            status=ScanStatus.COMPLETED,
            started_at=now,
            completed_at=completed,
            config_name="production",
            account_id="123456789012",
            region="us-west-2",
            collectors=["iam", "s3", "ec2"],
            asset_count=150,
            finding_count=25,
            duration_seconds=300.0,
            metadata={"source": "scheduled"},
        )

        assert record.account_id == "123456789012"
        assert record.collectors == ["iam", "s3", "ec2"]
        assert record.asset_count == 150
        assert record.finding_count == 25
        assert record.duration_seconds == 300.0
        assert record.metadata == {"source": "scheduled"}

    def test_scan_record_to_dict(self):
        """Test ScanRecord serialization to dict."""
        now = datetime.utcnow()
        record = ScanRecord(
            scan_id="scan-001",
            snapshot_id="20240115-120000",
            status=ScanStatus.COMPLETED,
            started_at=now,
            completed_at=now + timedelta(minutes=5),
            collectors=["iam", "s3"],
            asset_count=100,
        )

        data = record.to_dict()

        assert data["scan_id"] == "scan-001"
        assert data["status"] == "completed"
        assert data["collectors"] == ["iam", "s3"]
        assert data["asset_count"] == 100
        assert "started_at" in data
        assert "completed_at" in data

    def test_scan_record_from_dict(self):
        """Test ScanRecord deserialization from dict."""
        now = datetime.utcnow()
        data = {
            "scan_id": "scan-001",
            "snapshot_id": "20240115-120000",
            "status": "running",
            "started_at": now.isoformat(),
            "collectors": ["iam"],
            "asset_count": 50,
        }

        record = ScanRecord.from_dict(data)

        assert record.scan_id == "scan-001"
        assert record.status == ScanStatus.RUNNING
        assert record.collectors == ["iam"]
        assert record.asset_count == 50

    def test_scan_record_roundtrip(self):
        """Test ScanRecord serialization roundtrip."""
        now = datetime.utcnow()
        original = ScanRecord(
            scan_id="scan-001",
            snapshot_id="20240115-120000",
            status=ScanStatus.COMPLETED,
            started_at=now,
            completed_at=now + timedelta(minutes=5),
            collectors=["iam", "s3"],
            metadata={"key": "value"},
        )

        data = original.to_dict()
        restored = ScanRecord.from_dict(data)

        assert restored.scan_id == original.scan_id
        assert restored.status == original.status
        assert restored.collectors == original.collectors
        assert restored.metadata == original.metadata


class TestCheckpoint:
    """Tests for Checkpoint dataclass."""

    def test_checkpoint_creation(self):
        """Test creating a Checkpoint."""
        now = datetime.utcnow()
        checkpoint = Checkpoint(
            checkpoint_id="chk-001",
            collector_name="iam",
            account_id="123456789012",
            region="us-east-1",
            last_scan_id="scan-001",
            last_scan_time=now,
        )

        assert checkpoint.checkpoint_id == "chk-001"
        assert checkpoint.collector_name == "iam"
        assert checkpoint.cursor == ""
        assert checkpoint.metadata == {}

    def test_checkpoint_with_cursor(self):
        """Test Checkpoint with pagination cursor."""
        now = datetime.utcnow()
        checkpoint = Checkpoint(
            checkpoint_id="chk-002",
            collector_name="s3",
            account_id="123456789012",
            region="us-west-2",
            last_scan_id="scan-002",
            last_scan_time=now,
            cursor="next-page-token",
            metadata={"page": 5},
        )

        assert checkpoint.cursor == "next-page-token"
        assert checkpoint.metadata == {"page": 5}

    def test_checkpoint_to_dict(self):
        """Test Checkpoint serialization."""
        now = datetime.utcnow()
        checkpoint = Checkpoint(
            checkpoint_id="chk-001",
            collector_name="iam",
            account_id="123456789012",
            region="us-east-1",
            last_scan_id="scan-001",
            last_scan_time=now,
        )

        data = checkpoint.to_dict()

        assert data["checkpoint_id"] == "chk-001"
        assert data["collector_name"] == "iam"
        assert "last_scan_time" in data

    def test_checkpoint_from_dict(self):
        """Test Checkpoint deserialization."""
        now = datetime.utcnow()
        data = {
            "checkpoint_id": "chk-001",
            "collector_name": "iam",
            "account_id": "123456789012",
            "region": "us-east-1",
            "last_scan_id": "scan-001",
            "last_scan_time": now.isoformat(),
            "cursor": "token",
        }

        checkpoint = Checkpoint.from_dict(data)

        assert checkpoint.checkpoint_id == "chk-001"
        assert checkpoint.cursor == "token"


class TestFindingState:
    """Tests for FindingState dataclass."""

    def test_finding_state_creation(self):
        """Test creating a FindingState."""
        now = datetime.utcnow()
        state = FindingState(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
            lifecycle=FindingLifecycle.NEW,
            first_seen=now,
            last_seen=now,
        )

        assert state.finding_id == "finding-001"
        assert state.lifecycle == FindingLifecycle.NEW
        assert state.scan_count == 1
        assert state.resolved_at is None
        assert state.suppressed_by == ""
        assert state.notes == []

    def test_finding_state_with_suppression(self):
        """Test FindingState with suppression info."""
        now = datetime.utcnow()
        state = FindingState(
            finding_id="finding-002",
            asset_id="arn:aws:s3:::bucket-2",
            rule_id="aws-s3-002",
            lifecycle=FindingLifecycle.SUPPRESSED,
            first_seen=now - timedelta(days=7),
            last_seen=now,
            suppressed_by="admin@example.com",
            suppressed_at=now,
            suppression_reason="Known exception",
            notes=["Approved by security team"],
        )

        assert state.lifecycle == FindingLifecycle.SUPPRESSED
        assert state.suppressed_by == "admin@example.com"
        assert state.suppression_reason == "Known exception"
        assert "Approved by security team" in state.notes

    def test_finding_state_to_dict(self):
        """Test FindingState serialization."""
        now = datetime.utcnow()
        state = FindingState(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
            lifecycle=FindingLifecycle.NEW,
            first_seen=now,
            last_seen=now,
        )

        data = state.to_dict()

        assert data["finding_id"] == "finding-001"
        assert data["lifecycle"] == "new"
        assert data["scan_count"] == 1

    def test_finding_state_from_dict(self):
        """Test FindingState deserialization."""
        now = datetime.utcnow()
        data = {
            "finding_id": "finding-001",
            "asset_id": "arn:aws:s3:::bucket-1",
            "rule_id": "aws-s3-001",
            "lifecycle": "recurring",
            "first_seen": now.isoformat(),
            "last_seen": now.isoformat(),
            "scan_count": 3,
        }

        state = FindingState.from_dict(data)

        assert state.finding_id == "finding-001"
        assert state.lifecycle == FindingLifecycle.RECURRING
        assert state.scan_count == 3


class TestLocalStateBackend:
    """Tests for LocalStateBackend."""

    @pytest.fixture
    def backend(self, tmp_path):
        """Create a temporary LocalStateBackend."""
        db_path = str(tmp_path / "test_state.db")
        return LocalStateBackend(db_path=db_path)

    def test_backend_initialization(self, backend):
        """Test backend initializes correctly."""
        assert os.path.exists(backend.db_path)

    def test_save_and_get_scan(self, backend):
        """Test saving and retrieving a scan record."""
        now = datetime.utcnow()
        record = ScanRecord(
            scan_id="scan-001",
            snapshot_id="20240115-120000",
            status=ScanStatus.RUNNING,
            started_at=now,
            collectors=["iam", "s3"],
        )

        backend.save_scan(record)
        retrieved = backend.get_scan("scan-001")

        assert retrieved is not None
        assert retrieved.scan_id == "scan-001"
        assert retrieved.status == ScanStatus.RUNNING
        assert retrieved.collectors == ["iam", "s3"]

    def test_get_nonexistent_scan(self, backend):
        """Test getting a non-existent scan returns None."""
        result = backend.get_scan("nonexistent")
        assert result is None

    def test_list_scans(self, backend):
        """Test listing scans."""
        now = datetime.utcnow()
        for i in range(5):
            record = ScanRecord(
                scan_id=f"scan-{i:03d}",
                snapshot_id=f"snap-{i:03d}",
                status=ScanStatus.COMPLETED if i % 2 == 0 else ScanStatus.FAILED,
                started_at=now - timedelta(hours=i),
            )
            backend.save_scan(record)

        # List all
        all_scans = backend.list_scans(limit=10)
        assert len(all_scans) == 5

        # List with filter
        completed = backend.list_scans(status=ScanStatus.COMPLETED)
        assert len(completed) == 3

    def test_list_scans_since(self, backend):
        """Test listing scans since a date."""
        now = datetime.utcnow()
        for i in range(5):
            record = ScanRecord(
                scan_id=f"scan-{i:03d}",
                snapshot_id=f"snap-{i:03d}",
                status=ScanStatus.COMPLETED,
                started_at=now - timedelta(days=i),
            )
            backend.save_scan(record)

        # Only get scans from last 2 days
        since = now - timedelta(days=2)
        recent = backend.list_scans(since=since)
        assert len(recent) == 3

    def test_save_and_get_checkpoint(self, backend):
        """Test saving and retrieving a checkpoint."""
        now = datetime.utcnow()
        checkpoint = Checkpoint(
            checkpoint_id="chk-001",
            collector_name="iam",
            account_id="123456789012",
            region="us-east-1",
            last_scan_id="scan-001",
            last_scan_time=now,
            cursor="page-token",
        )

        backend.save_checkpoint(checkpoint)
        retrieved = backend.get_checkpoint("iam", "123456789012", "us-east-1")

        assert retrieved is not None
        assert retrieved.checkpoint_id == "chk-001"
        assert retrieved.cursor == "page-token"

    def test_get_nonexistent_checkpoint(self, backend):
        """Test getting a non-existent checkpoint returns None."""
        result = backend.get_checkpoint("iam", "000000000000", "us-west-1")
        assert result is None

    def test_delete_checkpoint(self, backend):
        """Test deleting a checkpoint."""
        now = datetime.utcnow()
        checkpoint = Checkpoint(
            checkpoint_id="chk-001",
            collector_name="iam",
            account_id="123456789012",
            region="us-east-1",
            last_scan_id="scan-001",
            last_scan_time=now,
        )

        backend.save_checkpoint(checkpoint)

        # Delete should succeed
        result = backend.delete_checkpoint("iam", "123456789012", "us-east-1")
        assert result is True

        # Should no longer exist
        retrieved = backend.get_checkpoint("iam", "123456789012", "us-east-1")
        assert retrieved is None

        # Delete again should return False
        result = backend.delete_checkpoint("iam", "123456789012", "us-east-1")
        assert result is False

    def test_save_and_get_finding_state(self, backend):
        """Test saving and retrieving finding state."""
        now = datetime.utcnow()
        state = FindingState(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
            lifecycle=FindingLifecycle.NEW,
            first_seen=now,
            last_seen=now,
        )

        backend.save_finding_state(state)
        retrieved = backend.get_finding_state("finding-001")

        assert retrieved is not None
        assert retrieved.finding_id == "finding-001"
        assert retrieved.lifecycle == FindingLifecycle.NEW

    def test_list_finding_states_by_asset(self, backend):
        """Test listing finding states by asset."""
        now = datetime.utcnow()
        asset_id = "arn:aws:s3:::bucket-1"

        for i in range(3):
            state = FindingState(
                finding_id=f"finding-{i:03d}",
                asset_id=asset_id,
                rule_id=f"aws-s3-{i:03d}",
                lifecycle=FindingLifecycle.NEW,
                first_seen=now,
                last_seen=now,
            )
            backend.save_finding_state(state)

        # Add finding for different asset
        other_state = FindingState(
            finding_id="finding-other",
            asset_id="arn:aws:s3:::bucket-2",
            rule_id="aws-s3-999",
            lifecycle=FindingLifecycle.NEW,
            first_seen=now,
            last_seen=now,
        )
        backend.save_finding_state(other_state)

        # Query by asset
        states = backend.list_finding_states(asset_id=asset_id)
        assert len(states) == 3

    def test_list_finding_states_by_lifecycle(self, backend):
        """Test listing finding states by lifecycle."""
        now = datetime.utcnow()

        lifecycles = [
            FindingLifecycle.NEW,
            FindingLifecycle.NEW,
            FindingLifecycle.RESOLVED,
            FindingLifecycle.SUPPRESSED,
        ]

        for i, lifecycle in enumerate(lifecycles):
            state = FindingState(
                finding_id=f"finding-{i:03d}",
                asset_id=f"asset-{i}",
                rule_id=f"rule-{i}",
                lifecycle=lifecycle,
                first_seen=now,
                last_seen=now,
            )
            backend.save_finding_state(state)

        new_states = backend.list_finding_states(lifecycle=FindingLifecycle.NEW)
        assert len(new_states) == 2

        resolved_states = backend.list_finding_states(lifecycle=FindingLifecycle.RESOLVED)
        assert len(resolved_states) == 1


class TestStateManager:
    """Tests for StateManager."""

    @pytest.fixture
    def manager(self, tmp_path):
        """Create a StateManager with temporary backend."""
        db_path = str(tmp_path / "test_state.db")
        backend = LocalStateBackend(db_path=db_path)
        return StateManager(backend=backend)

    def test_start_scan(self, manager):
        """Test starting a scan."""
        record = manager.start_scan(
            scan_id="scan-001",
            snapshot_id="20240115-120000",
            config_name="default",
            account_id="123456789012",
            region="us-east-1",
            collectors=["iam", "s3"],
        )

        assert record.scan_id == "scan-001"
        assert record.status == ScanStatus.RUNNING
        assert record.collectors == ["iam", "s3"]

        # Verify persisted
        retrieved = manager.backend.get_scan("scan-001")
        assert retrieved is not None
        assert retrieved.status == ScanStatus.RUNNING

    def test_complete_scan_success(self, manager):
        """Test completing a scan successfully."""
        # Start scan
        manager.start_scan(
            scan_id="scan-001",
            snapshot_id="20240115-120000",
        )

        # Complete scan
        record = manager.complete_scan(
            scan_id="scan-001",
            asset_count=100,
            finding_count=25,
        )

        assert record is not None
        assert record.status == ScanStatus.COMPLETED
        assert record.asset_count == 100
        assert record.finding_count == 25
        assert record.completed_at is not None
        assert record.duration_seconds > 0

    def test_complete_scan_failure(self, manager):
        """Test completing a scan with failure."""
        manager.start_scan(
            scan_id="scan-002",
            snapshot_id="20240115-120000",
        )

        record = manager.complete_scan(
            scan_id="scan-002",
            asset_count=50,
            finding_count=0,
            error_message="Connection timeout",
        )

        assert record is not None
        assert record.status == ScanStatus.FAILED
        assert record.error_message == "Connection timeout"

    def test_complete_nonexistent_scan(self, manager):
        """Test completing a non-existent scan."""
        result = manager.complete_scan(
            scan_id="nonexistent",
            asset_count=0,
            finding_count=0,
        )
        assert result is None

    def test_get_last_scan(self, manager):
        """Test getting the last completed scan."""
        # Create multiple scans
        for i in range(3):
            record = manager.start_scan(
                scan_id=f"scan-{i:03d}",
                snapshot_id=f"snap-{i:03d}",
            )
            manager.complete_scan(
                scan_id=f"scan-{i:03d}",
                asset_count=100 + i,
                finding_count=10 + i,
            )

        last = manager.get_last_scan()
        assert last is not None
        assert last.status == ScanStatus.COMPLETED

    def test_update_and_get_checkpoint(self, manager):
        """Test updating and getting checkpoints."""
        checkpoint = manager.update_checkpoint(
            collector_name="iam",
            account_id="123456789012",
            region="us-east-1",
            scan_id="scan-001",
            cursor="page-token",
        )

        assert checkpoint.collector_name == "iam"
        assert checkpoint.cursor == "page-token"

        # Retrieve
        retrieved = manager.get_checkpoint("iam", "123456789012", "us-east-1")
        assert retrieved is not None
        assert retrieved.cursor == "page-token"

    def test_track_new_finding(self, manager):
        """Test tracking a new finding."""
        state = manager.track_finding(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
        )

        assert state.lifecycle == FindingLifecycle.NEW
        assert state.scan_count == 1

    def test_track_recurring_finding(self, manager):
        """Test tracking a recurring finding."""
        # First time - NEW
        manager.track_finding(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
        )

        # Second time - RECURRING
        state = manager.track_finding(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
        )

        assert state.lifecycle == FindingLifecycle.RECURRING
        assert state.scan_count == 2

    def test_track_reopened_finding(self, manager):
        """Test tracking a reopened finding."""
        # First time
        manager.track_finding(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
        )

        # Resolve it
        manager.resolve_finding("finding-001")

        # Reopen by tracking again
        state = manager.track_finding(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
        )

        assert state.lifecycle == FindingLifecycle.REOPENED
        assert state.resolved_at is None

    def test_resolve_finding(self, manager):
        """Test resolving a finding."""
        manager.track_finding(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
        )

        state = manager.resolve_finding("finding-001")

        assert state is not None
        assert state.lifecycle == FindingLifecycle.RESOLVED
        assert state.resolved_at is not None

    def test_resolve_nonexistent_finding(self, manager):
        """Test resolving a non-existent finding."""
        result = manager.resolve_finding("nonexistent")
        assert result is None

    def test_suppress_finding(self, manager):
        """Test suppressing a finding."""
        manager.track_finding(
            finding_id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            rule_id="aws-s3-001",
        )

        state = manager.suppress_finding(
            finding_id="finding-001",
            suppressed_by="admin@example.com",
            reason="Known exception",
        )

        assert state is not None
        assert state.lifecycle == FindingLifecycle.SUPPRESSED
        assert state.suppressed_by == "admin@example.com"
        assert state.suppression_reason == "Known exception"
        assert state.suppressed_at is not None

    def test_suppress_nonexistent_finding(self, manager):
        """Test suppressing a non-existent finding."""
        result = manager.suppress_finding(
            finding_id="nonexistent",
            suppressed_by="admin",
        )
        assert result is None

    def test_get_finding_stats(self, manager):
        """Test getting finding statistics."""
        # Create some findings with different lifecycles
        lifecycles = [
            ("finding-001", FindingLifecycle.NEW),
            ("finding-002", FindingLifecycle.NEW),
            ("finding-003", FindingLifecycle.RECURRING),
        ]

        for finding_id, lifecycle in lifecycles:
            state = FindingState(
                finding_id=finding_id,
                asset_id="asset-1",
                rule_id="rule-1",
                lifecycle=lifecycle,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
            manager.backend.save_finding_state(state)

        stats = manager.get_finding_stats()

        assert stats["new"] == 2
        assert stats["recurring"] == 1
        assert stats["resolved"] == 0

    def test_cleanup_old_scans(self, manager):
        """Test cleanup returns 0 (not implemented for local)."""
        result = manager.cleanup_old_scans(days=30)
        assert result == 0


class TestGetStateManager:
    """Tests for get_state_manager factory function."""

    def test_get_local_state_manager(self, tmp_path):
        """Test creating a local state manager."""
        db_path = str(tmp_path / "test.db")
        manager = get_state_manager(backend_type="local", db_path=db_path)

        assert isinstance(manager, StateManager)
        assert isinstance(manager.backend, LocalStateBackend)

    def test_get_state_manager_default(self):
        """Test default state manager creation."""
        # Uses default path
        manager = get_state_manager()
        assert isinstance(manager, StateManager)

    def test_get_unknown_backend_raises(self):
        """Test unknown backend type raises ValueError."""
        with pytest.raises(ValueError, match="Unknown backend type"):
            get_state_manager(backend_type="unknown")


class TestStateBackendInterface:
    """Tests for StateBackend abstract interface."""

    def test_local_backend_is_state_backend(self, tmp_path):
        """Test LocalStateBackend is a StateBackend."""
        db_path = str(tmp_path / "test.db")
        backend = LocalStateBackend(db_path=db_path)
        assert isinstance(backend, StateBackend)

    def test_state_backend_has_required_methods(self):
        """Test StateBackend has all required abstract methods."""
        required_methods = [
            "save_scan",
            "get_scan",
            "list_scans",
            "save_checkpoint",
            "get_checkpoint",
            "delete_checkpoint",
            "save_finding_state",
            "get_finding_state",
            "list_finding_states",
        ]

        for method in required_methods:
            assert hasattr(StateBackend, method)
