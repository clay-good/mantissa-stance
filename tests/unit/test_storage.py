"""
Tests for Mantissa Stance storage backends.

Tests cover:
- LocalStorage (SQLite) operations
- S3Storage (mocked) operations
- Storage factory function
- Snapshot management
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    Severity,
    FindingStatus,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_INTERNET,
)
from stance.storage import (
    StorageBackend,
    LocalStorage,
    S3Storage,
    generate_snapshot_id,
    get_storage,
    list_available_backends,
)


class TestGenerateSnapshotId:
    """Tests for snapshot ID generation."""

    def test_snapshot_id_format(self):
        """Test snapshot ID format is YYYYMMDD-HHMMSS."""
        snapshot_id = generate_snapshot_id()

        # Should match pattern
        assert re.match(r"^\d{8}-\d{6}$", snapshot_id)

        # Should be parseable
        dt = datetime.strptime(snapshot_id, "%Y%m%d-%H%M%S")
        assert dt is not None

    def test_snapshot_id_unique(self):
        """Test that consecutive snapshot IDs are different (or same second)."""
        import time

        id1 = generate_snapshot_id()
        time.sleep(0.01)  # Small delay
        id2 = generate_snapshot_id()

        # IDs should be the same or id2 >= id1 (within same second or later)
        assert id2 >= id1


class TestGetStorage:
    """Tests for storage factory function."""

    def test_get_local_storage(self, tmp_path):
        """Test getting local storage."""
        db_path = str(tmp_path / "test.db")
        storage = get_storage("local", db_path=db_path)

        assert isinstance(storage, LocalStorage)
        assert isinstance(storage, StorageBackend)

    def test_get_local_storage_default(self):
        """Test getting local storage with defaults."""
        storage = get_storage("local")

        assert isinstance(storage, LocalStorage)

    def test_get_s3_storage(self):
        """Test getting S3 storage (without actual AWS)."""
        with patch("boto3.client"):
            storage = get_storage("s3", bucket="test-bucket")

            assert isinstance(storage, S3Storage)

    def test_unknown_backend_raises(self):
        """Test that unknown backend raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            get_storage("unknown")

        assert "Unknown storage backend" in str(exc_info.value)

    def test_case_insensitive_backend(self, tmp_path):
        """Test backend name is case insensitive."""
        db_path = str(tmp_path / "test.db")

        storage1 = get_storage("LOCAL", db_path=db_path)
        storage2 = get_storage("Local", db_path=db_path)

        assert isinstance(storage1, LocalStorage)
        assert isinstance(storage2, LocalStorage)


class TestListAvailableBackends:
    """Tests for listing available backends."""

    def test_local_always_available(self):
        """Test local backend is always available."""
        backends = list_available_backends()

        assert "local" in backends

    def test_returns_list(self):
        """Test returns a list."""
        backends = list_available_backends()

        assert isinstance(backends, list)
        assert all(isinstance(b, str) for b in backends)


class TestLocalStorage:
    """Tests for LocalStorage backend."""

    @pytest.fixture
    def storage(self, tmp_path) -> LocalStorage:
        """Create a temporary LocalStorage instance."""
        db_path = str(tmp_path / "test_stance.db")
        return LocalStorage(db_path=db_path)

    @pytest.fixture
    def sample_assets(self) -> AssetCollection:
        """Create sample assets for testing."""
        asset1 = Asset(
            id="arn:aws:s3:::bucket-1",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="bucket-1",
            tags={"Environment": "prod"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={"encryption": {"enabled": True}},
        )
        asset2 = Asset(
            id="arn:aws:s3:::bucket-2",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-west-2",
            resource_type="aws_s3_bucket",
            name="bucket-2",
            tags={"Environment": "dev"},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            created_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={"encryption": {"enabled": False}},
        )
        return AssetCollection([asset1, asset2])

    @pytest.fixture
    def sample_findings(self) -> FindingCollection:
        """Create sample findings for testing."""
        finding1 = Finding(
            id="finding-001",
            asset_id="arn:aws:s3:::bucket-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Encryption not enabled",
            description="S3 bucket does not have encryption enabled.",
            rule_id="aws-s3-001",
        )
        finding2 = Finding(
            id="finding-002",
            asset_id="arn:aws:s3:::bucket-2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="Public access enabled",
            description="S3 bucket allows public access.",
            rule_id="aws-s3-002",
        )
        finding3 = Finding(
            id="finding-003",
            asset_id="arn:aws:s3:::bucket-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            status=FindingStatus.RESOLVED,
            title="Versioning not enabled",
            description="S3 bucket does not have versioning enabled.",
            rule_id="aws-s3-003",
        )
        return FindingCollection([finding1, finding2, finding3])

    def test_store_and_retrieve_assets(self, storage, sample_assets):
        """Test storing and retrieving assets."""
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)
        retrieved = storage.get_assets(snapshot_id)

        assert len(retrieved) == 2
        assert any(a.name == "bucket-1" for a in retrieved)
        assert any(a.name == "bucket-2" for a in retrieved)

    def test_store_and_retrieve_findings(self, storage, sample_findings):
        """Test storing and retrieving findings."""
        snapshot_id = "20240115-120000"

        storage.store_findings(sample_findings, snapshot_id)
        retrieved = storage.get_findings(snapshot_id)

        assert len(retrieved) == 3
        assert any(f.id == "finding-001" for f in retrieved)

    def test_get_findings_filter_by_severity(self, storage, sample_findings):
        """Test filtering findings by severity."""
        snapshot_id = "20240115-120000"
        storage.store_findings(sample_findings, snapshot_id)

        critical = storage.get_findings(snapshot_id, severity=Severity.CRITICAL)
        high = storage.get_findings(snapshot_id, severity=Severity.HIGH)

        assert len(critical) == 1
        assert critical.findings[0].severity == Severity.CRITICAL

        assert len(high) == 1
        assert high.findings[0].severity == Severity.HIGH

    def test_get_findings_filter_by_status(self, storage, sample_findings):
        """Test filtering findings by status."""
        snapshot_id = "20240115-120000"
        storage.store_findings(sample_findings, snapshot_id)

        open_findings = storage.get_findings(snapshot_id, status=FindingStatus.OPEN)
        resolved = storage.get_findings(snapshot_id, status=FindingStatus.RESOLVED)

        assert len(open_findings) == 2
        assert len(resolved) == 1

    def test_get_latest_snapshot_id(self, storage, sample_assets, sample_findings):
        """Test getting the latest snapshot ID."""
        # Initially no snapshots
        assert storage.get_latest_snapshot_id() is None

        # Add first snapshot
        storage.store_assets(sample_assets, "20240115-100000")
        assert storage.get_latest_snapshot_id() == "20240115-100000"

        # Add later snapshot
        storage.store_assets(sample_assets, "20240115-120000")
        assert storage.get_latest_snapshot_id() == "20240115-120000"

    def test_list_snapshots(self, storage, sample_assets):
        """Test listing snapshots."""
        # Add multiple snapshots
        storage.store_assets(sample_assets, "20240115-100000")
        storage.store_assets(sample_assets, "20240115-110000")
        storage.store_assets(sample_assets, "20240115-120000")

        snapshots = storage.list_snapshots()

        assert len(snapshots) == 3
        # Should be ordered most recent first
        assert snapshots[0] == "20240115-120000"
        assert snapshots[1] == "20240115-110000"
        assert snapshots[2] == "20240115-100000"

    def test_list_snapshots_with_limit(self, storage, sample_assets):
        """Test listing snapshots with limit."""
        for i in range(5):
            storage.store_assets(sample_assets, f"20240115-{i:02d}0000")

        snapshots = storage.list_snapshots(limit=2)

        assert len(snapshots) == 2

    def test_get_assets_latest(self, storage, sample_assets):
        """Test getting assets from latest snapshot when no ID specified."""
        storage.store_assets(sample_assets, "20240115-100000")

        # Modify and store as new snapshot
        new_asset = Asset(
            id="arn:aws:s3:::bucket-3",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="bucket-3",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, 3, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={},
        )
        storage.store_assets(AssetCollection([new_asset]), "20240115-120000")

        # Get latest should return only bucket-3
        latest = storage.get_assets()
        assert len(latest) == 1
        assert latest.assets[0].name == "bucket-3"

    def test_create_snapshot(self, storage, sample_assets, sample_findings):
        """Test create_snapshot convenience method."""
        snapshot_id = storage.create_snapshot(sample_assets, sample_findings)

        assert snapshot_id is not None
        assert storage.get_latest_snapshot_id() == snapshot_id

        assets = storage.get_assets(snapshot_id)
        findings = storage.get_findings(snapshot_id)

        assert len(assets) == 2
        assert len(findings) == 3

    def test_create_snapshot_with_custom_id(self, storage, sample_assets, sample_findings):
        """Test create_snapshot with custom snapshot ID."""
        custom_id = "custom-snapshot-001"

        result = storage.create_snapshot(
            sample_assets, sample_findings, snapshot_id=custom_id
        )

        assert result == custom_id
        assert storage.get_latest_snapshot_id() == custom_id

    def test_empty_collections(self, storage):
        """Test storing and retrieving empty collections."""
        snapshot_id = "20240115-120000"

        storage.store_assets(AssetCollection([]), snapshot_id)
        storage.store_findings(FindingCollection([]), snapshot_id)

        assets = storage.get_assets(snapshot_id)
        findings = storage.get_findings(snapshot_id)

        assert len(assets) == 0
        assert len(findings) == 0

    def test_asset_tags_preserved(self, storage, sample_assets):
        """Test that asset tags are preserved through storage."""
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)
        retrieved = storage.get_assets(snapshot_id)

        # Find the prod bucket
        prod_bucket = next(a for a in retrieved if a.name == "bucket-1")
        assert prod_bucket.tags["Environment"] == "prod"

    def test_asset_raw_config_preserved(self, storage, sample_assets):
        """Test that raw_config is preserved through storage."""
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)
        retrieved = storage.get_assets(snapshot_id)

        bucket1 = next(a for a in retrieved if a.name == "bucket-1")
        assert bucket1.raw_config["encryption"]["enabled"] is True

    def test_finding_optional_fields(self, storage):
        """Test findings with optional fields."""
        finding_with_cve = Finding(
            id="vuln-001",
            asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-123",
            finding_type=FindingType.VULNERABILITY,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="Critical CVE",
            description="Critical vulnerability found.",
            cve_id="CVE-2024-0001",
            cvss_score=9.8,
            package_name="test-package",
            installed_version="1.0.0",
            fixed_version="1.0.1",
        )

        snapshot_id = "20240115-120000"
        storage.store_findings(FindingCollection([finding_with_cve]), snapshot_id)

        retrieved = storage.get_findings(snapshot_id)
        assert len(retrieved) == 1

        finding = retrieved.findings[0]
        assert finding.cve_id == "CVE-2024-0001"
        assert finding.cvss_score == 9.8
        assert finding.package_name == "test-package"


class TestS3Storage:
    """Tests for S3Storage backend (mocked)."""

    def test_s3_storage_init(self):
        """Test S3Storage initialization."""
        with patch("boto3.client"):
            storage = S3Storage(bucket="test-bucket", prefix="stance", region="us-east-1")

            assert storage.bucket == "test-bucket"
            assert storage.prefix == "stance"
            assert storage.region == "us-east-1"

    def test_s3_storage_init_default_prefix(self):
        """Test S3Storage initialization with default prefix."""
        with patch("boto3.client"):
            storage = S3Storage(bucket="test-bucket")

            assert storage.prefix == "stance"

    def test_s3_storage_init_default_region(self):
        """Test S3Storage initialization with default region."""
        with patch("boto3.client"):
            storage = S3Storage(bucket="test-bucket")

            assert storage.region == "us-east-1"

    def test_s3_storage_prefix_strips_trailing_slash(self):
        """Test that prefix trailing slash is stripped."""
        with patch("boto3.client"):
            storage = S3Storage(bucket="test-bucket", prefix="stance/")

            assert storage.prefix == "stance"

    def test_s3_storage_is_storage_backend(self):
        """Test S3Storage is a StorageBackend."""
        with patch("boto3.client"):
            storage = S3Storage(bucket="test")
            assert isinstance(storage, StorageBackend)

    def test_s3_storage_has_required_methods(self):
        """Test S3Storage has all required StorageBackend methods."""
        with patch("boto3.client"):
            storage = S3Storage(bucket="test")

            # Verify all abstract methods are implemented
            assert hasattr(storage, "store_assets")
            assert hasattr(storage, "store_findings")
            assert hasattr(storage, "get_assets")
            assert hasattr(storage, "get_findings")
            assert hasattr(storage, "get_latest_snapshot_id")
            assert hasattr(storage, "list_snapshots")

            # All should be callable
            assert callable(storage.store_assets)
            assert callable(storage.store_findings)
            assert callable(storage.get_assets)
            assert callable(storage.get_findings)
            assert callable(storage.get_latest_snapshot_id)
            assert callable(storage.list_snapshots)


class TestStorageInterface:
    """Tests to verify StorageBackend interface compliance."""

    def test_local_storage_is_storage_backend(self, tmp_path):
        """Test LocalStorage is a StorageBackend."""
        storage = LocalStorage(db_path=str(tmp_path / "test.db"))
        assert isinstance(storage, StorageBackend)

    def test_s3_storage_is_storage_backend(self):
        """Test S3Storage is a StorageBackend."""
        with patch("boto3.client"):
            storage = S3Storage(bucket="test")
            assert isinstance(storage, StorageBackend)

    def test_storage_backend_abstract_methods(self):
        """Test that StorageBackend cannot be instantiated directly."""
        with pytest.raises(TypeError):
            StorageBackend()
