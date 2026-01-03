"""
Baseline management for Mantissa Stance.

Provides baseline configuration storage, comparison,
and tracking for drift detection.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol

from stance.models.asset import Asset, AssetCollection


class BaselineStatus(Enum):
    """Status of a baseline."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    DRAFT = "draft"


@dataclass
class BaselineConfig:
    """
    Configuration snapshot for baselining.

    Attributes:
        config_hash: Hash of the configuration
        config_data: Full configuration data
        normalized_data: Normalized configuration for comparison
    """

    config_hash: str
    config_data: dict[str, Any]
    normalized_data: dict[str, Any]

    @classmethod
    def from_asset(cls, asset: Asset) -> BaselineConfig:
        """Create baseline config from an asset."""
        config_data = asset.raw_config or {}

        # Normalize configuration for comparison
        normalized = cls._normalize_config(config_data)

        # Calculate hash
        config_str = json.dumps(normalized, sort_keys=True)
        config_hash = hashlib.sha256(config_str.encode()).hexdigest()[:16]

        return cls(
            config_hash=config_hash,
            config_data=config_data,
            normalized_data=normalized,
        )

    @staticmethod
    def _normalize_config(config: dict) -> dict:
        """
        Normalize configuration for consistent comparison.

        Removes volatile fields that change between scans but
        don't represent actual configuration changes.
        """
        # Fields to exclude from comparison
        volatile_fields = {
            "LastModified",
            "LastUpdated",
            "lastModified",
            "lastUpdated",
            "Arn",
            "arn",
            "CreateDate",
            "createDate",
            "CreationDate",
            "creationDate",
            "ResponseMetadata",
            "requestId",
            "RequestId",
            "ETag",
            "etag",
        }

        def normalize_value(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    k: normalize_value(v)
                    for k, v in sorted(value.items())
                    if k not in volatile_fields
                }
            elif isinstance(value, list):
                return sorted(
                    [normalize_value(v) for v in value],
                    key=lambda x: json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else str(x)
                )
            else:
                return value

        return normalize_value(config)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "config_hash": self.config_hash,
            "config_data": self.config_data,
            "normalized_data": self.normalized_data,
        }


@dataclass
class AssetBaseline:
    """
    Baseline for a single asset.

    Attributes:
        asset_id: Asset identifier
        asset_type: Resource type
        cloud_provider: Cloud provider
        region: Asset region
        baseline_config: Configuration baseline
        created_at: When baseline was created
        created_by: Who created the baseline
        tags: Baseline tags
    """

    asset_id: str
    asset_type: str
    cloud_provider: str
    region: str
    baseline_config: BaselineConfig
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "system"
    tags: dict[str, str] = field(default_factory=dict)

    def matches(self, asset: Asset) -> bool:
        """Check if asset configuration matches baseline."""
        current_config = BaselineConfig.from_asset(asset)
        return current_config.config_hash == self.baseline_config.config_hash

    def compare(self, asset: Asset) -> dict[str, Any]:
        """Compare asset configuration to baseline."""
        current_config = BaselineConfig.from_asset(asset)
        return {
            "matches": current_config.config_hash == self.baseline_config.config_hash,
            "baseline_hash": self.baseline_config.config_hash,
            "current_hash": current_config.config_hash,
            "differences": self._find_differences(
                self.baseline_config.normalized_data,
                current_config.normalized_data,
            ),
        }

    def _find_differences(
        self,
        baseline: dict,
        current: dict,
        path: str = "",
    ) -> list[dict[str, Any]]:
        """Find differences between baseline and current config."""
        differences = []

        all_keys = set(baseline.keys()) | set(current.keys())

        for key in all_keys:
            current_path = f"{path}.{key}" if path else key

            if key not in baseline:
                differences.append({
                    "path": current_path,
                    "type": "added",
                    "baseline_value": None,
                    "current_value": current.get(key),
                })
            elif key not in current:
                differences.append({
                    "path": current_path,
                    "type": "removed",
                    "baseline_value": baseline.get(key),
                    "current_value": None,
                })
            elif baseline[key] != current[key]:
                if isinstance(baseline[key], dict) and isinstance(current[key], dict):
                    differences.extend(
                        self._find_differences(baseline[key], current[key], current_path)
                    )
                else:
                    differences.append({
                        "path": current_path,
                        "type": "changed",
                        "baseline_value": baseline.get(key),
                        "current_value": current.get(key),
                    })

        return differences

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "cloud_provider": self.cloud_provider,
            "region": self.region,
            "baseline_config": self.baseline_config.to_dict(),
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> AssetBaseline:
        """Create from dictionary."""
        config_data = data["baseline_config"]
        baseline_config = BaselineConfig(
            config_hash=config_data["config_hash"],
            config_data=config_data["config_data"],
            normalized_data=config_data["normalized_data"],
        )

        return cls(
            asset_id=data["asset_id"],
            asset_type=data["asset_type"],
            cloud_provider=data["cloud_provider"],
            region=data["region"],
            baseline_config=baseline_config,
            created_at=datetime.fromisoformat(data["created_at"]),
            created_by=data.get("created_by", "system"),
            tags=data.get("tags", {}),
        )


@dataclass
class Baseline:
    """
    Collection of asset baselines.

    Attributes:
        id: Baseline identifier
        name: Human-readable name
        description: Baseline description
        status: Baseline status
        asset_baselines: Individual asset baselines
        created_at: When baseline was created
        updated_at: When baseline was last updated
        created_by: Who created the baseline
        metadata: Additional metadata
    """

    id: str
    name: str
    description: str
    status: BaselineStatus
    asset_baselines: dict[str, AssetBaseline] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "system"
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_asset_baseline(self, baseline: AssetBaseline) -> None:
        """Add an asset baseline."""
        self.asset_baselines[baseline.asset_id] = baseline
        self.updated_at = datetime.utcnow()

    def remove_asset_baseline(self, asset_id: str) -> None:
        """Remove an asset baseline."""
        if asset_id in self.asset_baselines:
            del self.asset_baselines[asset_id]
            self.updated_at = datetime.utcnow()

    def get_asset_baseline(self, asset_id: str) -> AssetBaseline | None:
        """Get baseline for a specific asset."""
        return self.asset_baselines.get(asset_id)

    @property
    def asset_count(self) -> int:
        """Return number of assets in baseline."""
        return len(self.asset_baselines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "asset_baselines": {
                k: v.to_dict() for k, v in self.asset_baselines.items()
            },
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Baseline:
        """Create from dictionary."""
        asset_baselines = {
            k: AssetBaseline.from_dict(v)
            for k, v in data.get("asset_baselines", {}).items()
        }

        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            status=BaselineStatus(data.get("status", "active")),
            asset_baselines=asset_baselines,
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data.get("updated_at", data["created_at"])),
            created_by=data.get("created_by", "system"),
            metadata=data.get("metadata", {}),
        )


class BaselineStorage(Protocol):
    """Protocol for baseline storage backends."""

    def save_baseline(self, baseline: Baseline) -> None:
        """Save a baseline."""
        ...

    def get_baseline(self, baseline_id: str) -> Baseline | None:
        """Get a baseline by ID."""
        ...

    def list_baselines(self) -> list[Baseline]:
        """List all baselines."""
        ...

    def delete_baseline(self, baseline_id: str) -> None:
        """Delete a baseline."""
        ...


class InMemoryBaselineStorage:
    """In-memory baseline storage for testing."""

    def __init__(self):
        self._baselines: dict[str, Baseline] = {}

    def save_baseline(self, baseline: Baseline) -> None:
        """Save a baseline."""
        self._baselines[baseline.id] = baseline

    def get_baseline(self, baseline_id: str) -> Baseline | None:
        """Get a baseline by ID."""
        return self._baselines.get(baseline_id)

    def list_baselines(self) -> list[Baseline]:
        """List all baselines."""
        return list(self._baselines.values())

    def delete_baseline(self, baseline_id: str) -> None:
        """Delete a baseline."""
        if baseline_id in self._baselines:
            del self._baselines[baseline_id]


class BaselineManager:
    """
    Manages configuration baselines.

    Provides functionality to create, store, and compare
    configuration baselines.
    """

    def __init__(
        self,
        storage: BaselineStorage | None = None,
    ):
        """
        Initialize baseline manager.

        Args:
            storage: Baseline storage backend
        """
        self.storage = storage or InMemoryBaselineStorage()

    def create_baseline(
        self,
        name: str,
        assets: AssetCollection | list[Asset],
        description: str = "",
        created_by: str = "system",
        metadata: dict[str, Any] | None = None,
    ) -> Baseline:
        """
        Create a new baseline from assets.

        Args:
            name: Baseline name
            assets: Assets to baseline
            description: Baseline description
            created_by: Creator identifier
            metadata: Additional metadata

        Returns:
            Created baseline
        """
        if isinstance(assets, AssetCollection):
            assets_list = list(assets.assets)
        else:
            assets_list = assets

        # Generate baseline ID
        baseline_id = self._generate_baseline_id(name)

        # Create baseline
        baseline = Baseline(
            id=baseline_id,
            name=name,
            description=description,
            status=BaselineStatus.ACTIVE,
            created_by=created_by,
            metadata=metadata or {},
        )

        # Add asset baselines
        for asset in assets_list:
            asset_baseline = AssetBaseline(
                asset_id=asset.id,
                asset_type=asset.resource_type,
                cloud_provider=asset.cloud_provider,
                region=asset.region,
                baseline_config=BaselineConfig.from_asset(asset),
                created_by=created_by,
                tags=asset.tags or {},
            )
            baseline.add_asset_baseline(asset_baseline)

        # Save baseline
        self.storage.save_baseline(baseline)

        return baseline

    def get_baseline(self, baseline_id: str) -> Baseline | None:
        """Get a baseline by ID."""
        return self.storage.get_baseline(baseline_id)

    def get_active_baseline(self) -> Baseline | None:
        """Get the active baseline."""
        baselines = self.storage.list_baselines()
        for baseline in baselines:
            if baseline.status == BaselineStatus.ACTIVE:
                return baseline
        return None

    def list_baselines(self) -> list[Baseline]:
        """List all baselines."""
        return self.storage.list_baselines()

    def compare_to_baseline(
        self,
        baseline_id: str,
        assets: AssetCollection | list[Asset],
    ) -> dict[str, Any]:
        """
        Compare assets to a baseline.

        Args:
            baseline_id: Baseline to compare against
            assets: Current assets

        Returns:
            Comparison result with drift information
        """
        baseline = self.storage.get_baseline(baseline_id)
        if not baseline:
            return {"error": f"Baseline {baseline_id} not found"}

        if isinstance(assets, AssetCollection):
            assets_list = list(assets.assets)
        else:
            assets_list = assets

        # Build asset lookup
        current_assets = {a.id: a for a in assets_list}
        baseline_asset_ids = set(baseline.asset_baselines.keys())
        current_asset_ids = set(current_assets.keys())

        # Find drift
        results = {
            "baseline_id": baseline_id,
            "baseline_name": baseline.name,
            "compared_at": datetime.utcnow().isoformat(),
            "total_baseline_assets": len(baseline_asset_ids),
            "total_current_assets": len(current_asset_ids),
            "new_assets": [],
            "removed_assets": [],
            "changed_assets": [],
            "unchanged_assets": [],
        }

        # New assets (in current but not in baseline)
        new_asset_ids = current_asset_ids - baseline_asset_ids
        results["new_assets"] = [
            {
                "asset_id": aid,
                "asset_type": current_assets[aid].resource_type,
                "region": current_assets[aid].region,
            }
            for aid in new_asset_ids
        ]

        # Removed assets (in baseline but not in current)
        removed_asset_ids = baseline_asset_ids - current_asset_ids
        results["removed_assets"] = [
            {
                "asset_id": aid,
                "asset_type": baseline.asset_baselines[aid].asset_type,
                "region": baseline.asset_baselines[aid].region,
            }
            for aid in removed_asset_ids
        ]

        # Check existing assets for changes
        common_asset_ids = baseline_asset_ids & current_asset_ids
        for asset_id in common_asset_ids:
            asset_baseline = baseline.asset_baselines[asset_id]
            current_asset = current_assets[asset_id]

            comparison = asset_baseline.compare(current_asset)

            if comparison["matches"]:
                results["unchanged_assets"].append(asset_id)
            else:
                results["changed_assets"].append({
                    "asset_id": asset_id,
                    "asset_type": current_asset.resource_type,
                    "region": current_asset.region,
                    "baseline_hash": comparison["baseline_hash"],
                    "current_hash": comparison["current_hash"],
                    "differences": comparison["differences"],
                })

        # Summary statistics
        results["summary"] = {
            "has_drift": bool(
                results["new_assets"]
                or results["removed_assets"]
                or results["changed_assets"]
            ),
            "new_count": len(results["new_assets"]),
            "removed_count": len(results["removed_assets"]),
            "changed_count": len(results["changed_assets"]),
            "unchanged_count": len(results["unchanged_assets"]),
        }

        return results

    def update_baseline(
        self,
        baseline_id: str,
        assets: AssetCollection | list[Asset],
        asset_ids: list[str] | None = None,
    ) -> Baseline | None:
        """
        Update a baseline with new asset configurations.

        Args:
            baseline_id: Baseline to update
            assets: New asset configurations
            asset_ids: Specific asset IDs to update (None = all)

        Returns:
            Updated baseline or None if not found
        """
        baseline = self.storage.get_baseline(baseline_id)
        if not baseline:
            return None

        if isinstance(assets, AssetCollection):
            assets_list = list(assets.assets)
        else:
            assets_list = assets

        for asset in assets_list:
            if asset_ids and asset.id not in asset_ids:
                continue

            asset_baseline = AssetBaseline(
                asset_id=asset.id,
                asset_type=asset.resource_type,
                cloud_provider=asset.cloud_provider,
                region=asset.region,
                baseline_config=BaselineConfig.from_asset(asset),
                tags=asset.tags or {},
            )
            baseline.add_asset_baseline(asset_baseline)

        self.storage.save_baseline(baseline)
        return baseline

    def archive_baseline(self, baseline_id: str) -> bool:
        """Archive a baseline."""
        baseline = self.storage.get_baseline(baseline_id)
        if not baseline:
            return False

        baseline.status = BaselineStatus.ARCHIVED
        baseline.updated_at = datetime.utcnow()
        self.storage.save_baseline(baseline)
        return True

    def delete_baseline(self, baseline_id: str) -> bool:
        """Delete a baseline."""
        baseline = self.storage.get_baseline(baseline_id)
        if not baseline:
            return False

        self.storage.delete_baseline(baseline_id)
        return True

    def _generate_baseline_id(self, name: str) -> str:
        """Generate a unique baseline ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        name_hash = hashlib.sha256(name.encode()).hexdigest()[:8]
        return f"baseline-{timestamp}-{name_hash}"
