"""
Asset data model for Mantissa Stance.

This module defines the Asset class representing cloud resources
and AssetCollection for managing groups of assets.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator

# Network exposure constants
NETWORK_EXPOSURE_INTERNET = "internet_facing"
NETWORK_EXPOSURE_INTERNAL = "internal"
NETWORK_EXPOSURE_ISOLATED = "isolated"


@dataclass(frozen=True)
class Asset:
    """
    Represents a cloud resource.

    Assets are immutable snapshots of cloud resource configurations
    collected during a scan. Each asset has a unique identifier (ARN for AWS),
    metadata about its location and type, and a raw configuration snapshot.

    Attributes:
        id: Unique identifier (ARN for AWS resources)
        cloud_provider: Cloud provider name (e.g., "aws")
        account_id: Cloud account identifier
        region: Geographic region where resource is located
        resource_type: Type of resource (e.g., "aws_s3_bucket")
        name: Human-readable name of the resource
        tags: Resource tags as key-value pairs
        network_exposure: Network exposure level (internet_facing, internal, isolated)
        created_at: When the resource was created
        last_seen: When we last observed this resource
        raw_config: Full configuration snapshot as collected
    """

    id: str
    cloud_provider: str
    account_id: str
    region: str
    resource_type: str
    name: str
    tags: dict[str, str] = field(default_factory=dict)
    network_exposure: str = NETWORK_EXPOSURE_INTERNAL
    created_at: datetime | None = None
    last_seen: datetime | None = None
    raw_config: dict[str, Any] = field(default_factory=dict)

    def is_internet_facing(self) -> bool:
        """
        Check if this asset is exposed to the internet.

        Returns:
            True if network_exposure is "internet_facing"
        """
        return self.network_exposure == NETWORK_EXPOSURE_INTERNET

    def get_tag(self, key: str, default: str = "") -> str:
        """
        Get a tag value by key.

        Args:
            key: Tag key to look up
            default: Default value if tag not found

        Returns:
            Tag value or default
        """
        return self.tags.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert asset to dictionary representation.

        Returns:
            Dictionary with all asset fields, suitable for JSON serialization
        """
        return {
            "id": self.id,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "region": self.region,
            "resource_type": self.resource_type,
            "name": self.name,
            "tags": self.tags,
            "network_exposure": self.network_exposure,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "raw_config": self.raw_config,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Asset:
        """
        Create an Asset from a dictionary.

        Args:
            data: Dictionary with asset fields

        Returns:
            New Asset instance
        """
        created_at = None
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"])

        last_seen = None
        if data.get("last_seen"):
            last_seen = datetime.fromisoformat(data["last_seen"])

        return cls(
            id=data["id"],
            cloud_provider=data.get("cloud_provider", "aws"),
            account_id=data.get("account_id", ""),
            region=data.get("region", ""),
            resource_type=data.get("resource_type", ""),
            name=data.get("name", ""),
            tags=data.get("tags", {}),
            network_exposure=data.get("network_exposure", NETWORK_EXPOSURE_INTERNAL),
            created_at=created_at,
            last_seen=last_seen,
            raw_config=data.get("raw_config", {}),
        )


class AssetCollection:
    """
    A collection of Asset objects with filtering capabilities.

    Provides methods to filter assets by various criteria and
    convert the collection to different formats.

    Attributes:
        assets: List of Asset objects in this collection
    """

    def __init__(self, assets: list[Asset] | None = None) -> None:
        """
        Initialize collection with optional list of assets.

        Args:
            assets: Initial list of assets (defaults to empty list)
        """
        self._assets: list[Asset] = assets if assets is not None else []

    @property
    def assets(self) -> list[Asset]:
        """Get the list of assets."""
        return self._assets

    def __len__(self) -> int:
        """Return number of assets in collection."""
        return len(self._assets)

    def __iter__(self) -> Iterator[Asset]:
        """Iterate over assets in collection."""
        return iter(self._assets)

    def __getitem__(self, index: int) -> Asset:
        """Get asset by index."""
        return self._assets[index]

    def add(self, asset: Asset) -> None:
        """
        Add an asset to the collection.

        Args:
            asset: Asset to add
        """
        self._assets.append(asset)

    def extend(self, assets: list[Asset]) -> None:
        """
        Add multiple assets to the collection.

        Args:
            assets: List of assets to add
        """
        self._assets.extend(assets)

    def filter_by_type(self, resource_type: str) -> AssetCollection:
        """
        Filter assets by resource type.

        Args:
            resource_type: Resource type to filter by (e.g., "aws_s3_bucket")

        Returns:
            New AssetCollection containing only matching assets
        """
        filtered = [a for a in self._assets if a.resource_type == resource_type]
        return AssetCollection(filtered)

    def filter_by_region(self, region: str) -> AssetCollection:
        """
        Filter assets by region.

        Args:
            region: Region to filter by (e.g., "us-east-1")

        Returns:
            New AssetCollection containing only matching assets
        """
        filtered = [a for a in self._assets if a.region == region]
        return AssetCollection(filtered)

    def filter_by_tag(self, key: str, value: str) -> AssetCollection:
        """
        Filter assets by tag key-value pair.

        Args:
            key: Tag key to match
            value: Tag value to match

        Returns:
            New AssetCollection containing only matching assets
        """
        filtered = [a for a in self._assets if a.tags.get(key) == value]
        return AssetCollection(filtered)

    def filter_by_account(self, account_id: str) -> AssetCollection:
        """
        Filter assets by account ID.

        Args:
            account_id: Account ID to filter by

        Returns:
            New AssetCollection containing only matching assets
        """
        filtered = [a for a in self._assets if a.account_id == account_id]
        return AssetCollection(filtered)

    def filter_internet_facing(self) -> AssetCollection:
        """
        Filter to only internet-facing assets.

        Returns:
            New AssetCollection containing only internet-facing assets
        """
        filtered = [a for a in self._assets if a.is_internet_facing()]
        return AssetCollection(filtered)

    def get_by_id(self, asset_id: str) -> Asset | None:
        """
        Get an asset by its ID.

        Args:
            asset_id: Asset ID to find

        Returns:
            Asset if found, None otherwise
        """
        for asset in self._assets:
            if asset.id == asset_id:
                return asset
        return None

    def to_list(self) -> list[dict[str, Any]]:
        """
        Convert collection to list of dictionaries.

        Returns:
            List of asset dictionaries
        """
        return [asset.to_dict() for asset in self._assets]

    def to_json(self) -> str:
        """
        Convert collection to JSON string.

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_list(), indent=2, default=str)

    @classmethod
    def from_list(cls, data: list[dict[str, Any]]) -> AssetCollection:
        """
        Create collection from list of dictionaries.

        Args:
            data: List of asset dictionaries

        Returns:
            New AssetCollection
        """
        assets = [Asset.from_dict(item) for item in data]
        return cls(assets)

    def count_by_type(self) -> dict[str, int]:
        """
        Count assets grouped by resource type.

        Returns:
            Dictionary mapping resource type to count
        """
        counts: dict[str, int] = {}
        for asset in self._assets:
            counts[asset.resource_type] = counts.get(asset.resource_type, 0) + 1
        return counts

    def count_by_region(self) -> dict[str, int]:
        """
        Count assets grouped by region.

        Returns:
            Dictionary mapping region to count
        """
        counts: dict[str, int] = {}
        for asset in self._assets:
            counts[asset.region] = counts.get(asset.region, 0) + 1
        return counts

    def merge(self, other: AssetCollection) -> AssetCollection:
        """
        Merge with another collection.

        Args:
            other: Another AssetCollection to merge

        Returns:
            New AssetCollection with assets from both collections
        """
        return AssetCollection(self._assets + other._assets)
