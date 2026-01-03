"""
Tests for Mantissa Stance drift detection module.

Tests the drift detection functionality including:
- Baseline management
- Drift detection
- Change tracking
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from stance.drift import (
    Baseline,
    BaselineConfig,
    BaselineManager,
    AssetBaseline,
    ChangeEvent,
    ChangeTracker,
    ChangeType,
    ConfigDifference,
    DriftDetector,
    DriftEvent,
    DriftSeverity,
    DriftType,
    BaselineStatus,
)
from stance.models import Asset, AssetCollection


class TestBaselineConfig:
    """Tests for the BaselineConfig class."""

    def test_from_asset(self, sample_asset: Asset):
        """Test creating baseline config from asset."""
        config = BaselineConfig.from_asset(sample_asset)

        assert config.normalized_data is not None
        assert config.config_hash != ""
        assert config.config_data is not None

    def test_hash_consistency(self, sample_asset: Asset):
        """Test that same asset produces same hash."""
        config1 = BaselineConfig.from_asset(sample_asset)
        config2 = BaselineConfig.from_asset(sample_asset)

        assert config1.config_hash == config2.config_hash

    def test_hash_changes_with_config(self, sample_asset: Asset):
        """Test that different config produces different hash."""
        config1 = BaselineConfig.from_asset(sample_asset)

        # Create a modified asset
        modified_asset = Asset(
            id=sample_asset.id,
            cloud_provider=sample_asset.cloud_provider,
            account_id=sample_asset.account_id,
            region=sample_asset.region,
            resource_type=sample_asset.resource_type,
            name=sample_asset.name,
            tags=sample_asset.tags,
            network_exposure=sample_asset.network_exposure,
            created_at=sample_asset.created_at,
            last_seen=sample_asset.last_seen,
            raw_config={"encryption": {"enabled": False}},  # Changed
        )
        config2 = BaselineConfig.from_asset(modified_asset)

        assert config1.config_hash != config2.config_hash


class TestBaselineManager:
    """Tests for the BaselineManager class."""

    def test_create_baseline(self, asset_collection: AssetCollection):
        """Test creating a baseline."""
        manager = BaselineManager()
        baseline = manager.create_baseline(
            name="Test Baseline",
            assets=asset_collection,
        )

        assert baseline.id is not None
        assert len(baseline.asset_baselines) == 3
        assert baseline.status == BaselineStatus.ACTIVE

    def test_get_active_baseline(self, asset_collection: AssetCollection):
        """Test getting active baseline."""
        manager = BaselineManager()
        created = manager.create_baseline(
            name="Test Baseline",
            assets=asset_collection,
        )

        active = manager.get_active_baseline()

        assert active is not None
        assert active.id == created.id

    def test_multiple_baselines(self, asset_collection: AssetCollection):
        """Test managing multiple baselines."""
        manager = BaselineManager()

        baseline1 = manager.create_baseline(
            name="Baseline 1",
            assets=asset_collection,
        )
        baseline2 = manager.create_baseline(
            name="Baseline 2",
            assets=asset_collection,
        )

        # Active baseline should be one of the created baselines
        active = manager.get_active_baseline()
        assert active is not None
        assert active.id in (baseline1.id, baseline2.id)

        # Both baselines should exist
        assert manager.get_baseline(baseline1.id) is not None
        assert manager.get_baseline(baseline2.id) is not None


class TestDriftDetector:
    """Tests for the DriftDetector class."""

    def test_no_drift_when_unchanged(self, asset_collection: AssetCollection):
        """Test no drift detected when assets unchanged."""
        manager = BaselineManager()
        manager.create_baseline(name="Test", assets=asset_collection)

        detector = DriftDetector(baseline_manager=manager)
        result = detector.detect_drift(asset_collection)

        assert result.assets_checked == 3
        assert result.assets_with_drift == 0
        assert len(result.drift_events) == 0

    def test_detect_new_asset(self, asset_collection: AssetCollection):
        """Test detecting new assets."""
        manager = BaselineManager()
        manager.create_baseline(name="Test", assets=asset_collection)

        # Add a new asset
        new_asset = Asset(
            id="arn:aws:s3:::new-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="new-bucket",
            tags={},
            network_exposure="internal",
            raw_config={},
        )
        new_collection = AssetCollection(
            list(asset_collection.assets) + [new_asset]
        )

        detector = DriftDetector(baseline_manager=manager)
        result = detector.detect_drift(new_collection)

        assert result.assets_with_drift >= 1
        new_asset_events = [
            e for e in result.drift_events
            if e.drift_type == DriftType.NEW_ASSET
        ]
        assert len(new_asset_events) == 1
        assert new_asset_events[0].asset_id == "arn:aws:s3:::new-bucket"

    def test_detect_removed_asset(self, asset_collection: AssetCollection):
        """Test detecting removed assets."""
        manager = BaselineManager()
        manager.create_baseline(name="Test", assets=asset_collection)

        # Remove an asset
        reduced_assets = list(asset_collection.assets)[:-1]
        reduced_collection = AssetCollection(reduced_assets)

        detector = DriftDetector(baseline_manager=manager)
        result = detector.detect_drift(reduced_collection)

        removed_events = [
            e for e in result.drift_events
            if e.drift_type == DriftType.REMOVED_ASSET
        ]
        assert len(removed_events) == 1

    def test_detect_config_change(self, sample_asset: Asset):
        """Test detecting configuration changes."""
        original = AssetCollection([sample_asset])

        manager = BaselineManager()
        manager.create_baseline(name="Test", assets=original)

        # Modify the asset
        modified_asset = Asset(
            id=sample_asset.id,
            cloud_provider=sample_asset.cloud_provider,
            account_id=sample_asset.account_id,
            region=sample_asset.region,
            resource_type=sample_asset.resource_type,
            name=sample_asset.name,
            tags=sample_asset.tags,
            network_exposure=sample_asset.network_exposure,
            created_at=sample_asset.created_at,
            last_seen=sample_asset.last_seen,
            raw_config={
                "encryption": {"enabled": False},  # Changed from True
                "versioning": {"status": "Enabled"},
                "public_access_block": {
                    "block_public_acls": True,
                    "block_public_policy": True,
                },
            },
        )
        modified_collection = AssetCollection([modified_asset])

        detector = DriftDetector(baseline_manager=manager)
        result = detector.detect_drift(modified_collection)

        assert result.assets_with_drift == 1
        config_events = [
            e for e in result.drift_events
            if e.drift_type in (DriftType.CONFIG_CHANGED, DriftType.SECURITY_DEGRADED)
        ]
        assert len(config_events) == 1

    def test_security_sensitive_path_detection(self):
        """Test that security-sensitive paths are flagged."""
        detector = DriftDetector()

        # Security path should be flagged
        diff = ConfigDifference(
            path="encryption.enabled",
            change_type="changed",
            baseline_value=True,
            current_value=False,
        )
        scored = detector._score_difference(diff)
        assert scored.is_security_relevant

    def test_drift_to_finding(self, sample_asset: Asset):
        """Test converting drift event to finding."""
        event = DriftEvent(
            asset_id=sample_asset.id,
            asset_type=sample_asset.resource_type,
            cloud_provider=sample_asset.cloud_provider,
            region=sample_asset.region,
            drift_type=DriftType.SECURITY_DEGRADED,
            severity=DriftSeverity.HIGH,
            differences=[
                ConfigDifference(
                    path="encryption.enabled",
                    change_type="changed",
                    baseline_value=True,
                    current_value=False,
                    is_security_relevant=True,
                    severity=DriftSeverity.HIGH,
                )
            ],
            description="Security configuration changed",
        )

        finding = event.to_finding()

        assert finding is not None
        assert finding.asset_id == sample_asset.id
        assert finding.severity.value == "high"
        assert "drift" in finding.id


class TestChangeTracker:
    """Tests for the ChangeTracker class."""

    def test_track_changes_initial(self, sample_asset: Asset):
        """Test tracking initial asset state."""
        tracker = ChangeTracker()
        assets = AssetCollection([sample_asset])

        # First call creates initial snapshots
        events = tracker.track_changes(assets)

        # First track should create CREATED events
        assert len(events) == 1
        assert events[0].change_type == ChangeType.CREATED

    def test_track_changes_no_change(self, sample_asset: Asset):
        """Test no events when no changes."""
        tracker = ChangeTracker()
        assets = AssetCollection([sample_asset])

        # Initial tracking
        tracker.track_changes(assets)

        # Second tracking with same assets
        events = tracker.track_changes(assets)

        # No changes should be detected
        assert len(events) == 0

    def test_track_changes_modified(self, sample_asset: Asset):
        """Test detecting modified assets."""
        tracker = ChangeTracker()

        # Initial state
        initial = AssetCollection([sample_asset])
        tracker.track_changes(initial)

        # Modified state
        modified = Asset(
            id=sample_asset.id,
            cloud_provider=sample_asset.cloud_provider,
            account_id=sample_asset.account_id,
            region=sample_asset.region,
            resource_type=sample_asset.resource_type,
            name=sample_asset.name,
            tags=sample_asset.tags,
            network_exposure=sample_asset.network_exposure,
            created_at=sample_asset.created_at,
            last_seen=sample_asset.last_seen,
            raw_config={"encryption": {"enabled": False}},  # Changed
        )
        modified_collection = AssetCollection([modified])
        events = tracker.track_changes(modified_collection)

        # Should detect modification
        assert len(events) == 1
        assert events[0].change_type == ChangeType.UPDATED

    def test_change_type_values(self):
        """Test change type enumeration values."""
        assert ChangeType.CREATED.value == "created"
        assert ChangeType.UPDATED.value == "updated"
        assert ChangeType.DELETED.value == "deleted"


class TestConfigDifference:
    """Tests for the ConfigDifference class."""

    def test_to_dict(self):
        """Test ConfigDifference serialization."""
        diff = ConfigDifference(
            path="encryption.enabled",
            change_type="changed",
            baseline_value=True,
            current_value=False,
            is_security_relevant=True,
            severity=DriftSeverity.HIGH,
        )

        data = diff.to_dict()

        assert data["path"] == "encryption.enabled"
        assert data["change_type"] == "changed"
        assert data["baseline_value"] is True
        assert data["current_value"] is False
        assert data["is_security_relevant"] is True
        assert data["severity"] == "high"


class TestDriftEvent:
    """Tests for the DriftEvent class."""

    def test_to_dict(self, sample_asset: Asset):
        """Test DriftEvent serialization."""
        event = DriftEvent(
            asset_id=sample_asset.id,
            asset_type=sample_asset.resource_type,
            cloud_provider=sample_asset.cloud_provider,
            region=sample_asset.region,
            drift_type=DriftType.CONFIG_CHANGED,
            severity=DriftSeverity.MEDIUM,
            differences=[],
            description="Test drift event",
        )

        data = event.to_dict()

        assert data["asset_id"] == sample_asset.id
        assert data["drift_type"] == "config_changed"
        assert data["severity"] == "medium"
