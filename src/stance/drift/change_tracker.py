"""
Change tracking for Mantissa Stance.

Provides asset change tracking over time, change timeline,
and change attribution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Protocol

from stance.models.asset import Asset, AssetCollection


class ChangeType(Enum):
    """Types of asset changes."""

    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    RESTORED = "restored"


@dataclass
class ConfigSnapshot:
    """
    Point-in-time configuration snapshot.

    Attributes:
        snapshot_id: Unique snapshot identifier
        config_hash: Hash of configuration
        config_data: Full configuration data
        captured_at: When snapshot was taken
    """

    snapshot_id: str
    config_hash: str
    config_data: dict[str, Any]
    captured_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "snapshot_id": self.snapshot_id,
            "config_hash": self.config_hash,
            "config_data": self.config_data,
            "captured_at": self.captured_at.isoformat(),
        }

    @classmethod
    def from_asset(cls, asset: Asset, snapshot_id: str) -> ConfigSnapshot:
        """Create snapshot from asset."""
        config_data = asset.raw_config or {}
        config_str = json.dumps(config_data, sort_keys=True)
        config_hash = hashlib.sha256(config_str.encode()).hexdigest()[:16]

        return cls(
            snapshot_id=snapshot_id,
            config_hash=config_hash,
            config_data=config_data,
            captured_at=datetime.utcnow(),
        )


@dataclass
class ChangeEvent:
    """
    Record of a single change event.

    Attributes:
        event_id: Unique event identifier
        asset_id: Asset that changed
        change_type: Type of change
        occurred_at: When change occurred
        detected_at: When change was detected
        previous_snapshot: Previous configuration (if applicable)
        current_snapshot: Current configuration (if applicable)
        changed_paths: List of changed configuration paths
        attributed_to: Who/what made the change
        source: Source of change (api, console, terraform, etc.)
        metadata: Additional metadata
    """

    event_id: str
    asset_id: str
    change_type: ChangeType
    occurred_at: datetime
    detected_at: datetime
    previous_snapshot: ConfigSnapshot | None
    current_snapshot: ConfigSnapshot | None
    changed_paths: list[str] = field(default_factory=list)
    attributed_to: str = "unknown"
    source: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "asset_id": self.asset_id,
            "change_type": self.change_type.value,
            "occurred_at": self.occurred_at.isoformat(),
            "detected_at": self.detected_at.isoformat(),
            "previous_snapshot": self.previous_snapshot.to_dict() if self.previous_snapshot else None,
            "current_snapshot": self.current_snapshot.to_dict() if self.current_snapshot else None,
            "changed_paths": self.changed_paths,
            "attributed_to": self.attributed_to,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class AssetHistory:
    """
    Change history for a single asset.

    Attributes:
        asset_id: Asset identifier
        asset_type: Resource type
        cloud_provider: Cloud provider
        events: List of change events
        first_seen: When asset was first observed
        last_seen: When asset was last observed
        current_config_hash: Current configuration hash
    """

    asset_id: str
    asset_type: str
    cloud_provider: str
    events: list[ChangeEvent] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    current_config_hash: str = ""

    def add_event(self, event: ChangeEvent) -> None:
        """Add a change event."""
        self.events.append(event)
        self.events.sort(key=lambda e: e.detected_at, reverse=True)

    def get_recent_events(self, limit: int = 10) -> list[ChangeEvent]:
        """Get most recent events."""
        return self.events[:limit]

    def get_events_in_range(
        self,
        start: datetime,
        end: datetime,
    ) -> list[ChangeEvent]:
        """Get events within time range."""
        return [
            e for e in self.events
            if start <= e.detected_at <= end
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "cloud_provider": self.cloud_provider,
            "events": [e.to_dict() for e in self.events],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "current_config_hash": self.current_config_hash,
            "total_changes": len(self.events),
        }


class ChangeStorage(Protocol):
    """Protocol for change storage backends."""

    def save_event(self, event: ChangeEvent) -> None:
        """Save a change event."""
        ...

    def get_asset_history(self, asset_id: str) -> AssetHistory | None:
        """Get history for an asset."""
        ...

    def get_recent_events(self, limit: int) -> list[ChangeEvent]:
        """Get recent events across all assets."""
        ...

    def save_snapshot(self, asset_id: str, snapshot: ConfigSnapshot) -> None:
        """Save a configuration snapshot."""
        ...

    def get_latest_snapshot(self, asset_id: str) -> ConfigSnapshot | None:
        """Get latest snapshot for an asset."""
        ...


class InMemoryChangeStorage:
    """In-memory change storage for testing."""

    def __init__(self):
        self._events: list[ChangeEvent] = []
        self._histories: dict[str, AssetHistory] = {}
        self._snapshots: dict[str, list[ConfigSnapshot]] = {}

    def save_event(self, event: ChangeEvent) -> None:
        """Save a change event."""
        self._events.append(event)

        if event.asset_id not in self._histories:
            self._histories[event.asset_id] = AssetHistory(
                asset_id=event.asset_id,
                asset_type="unknown",
                cloud_provider="unknown",
            )

        self._histories[event.asset_id].add_event(event)

    def get_asset_history(self, asset_id: str) -> AssetHistory | None:
        """Get history for an asset."""
        return self._histories.get(asset_id)

    def get_recent_events(self, limit: int = 100) -> list[ChangeEvent]:
        """Get recent events."""
        sorted_events = sorted(
            self._events,
            key=lambda e: e.detected_at,
            reverse=True,
        )
        return sorted_events[:limit]

    def save_snapshot(self, asset_id: str, snapshot: ConfigSnapshot) -> None:
        """Save a configuration snapshot."""
        if asset_id not in self._snapshots:
            self._snapshots[asset_id] = []
        self._snapshots[asset_id].append(snapshot)

    def get_latest_snapshot(self, asset_id: str) -> ConfigSnapshot | None:
        """Get latest snapshot for an asset."""
        snapshots = self._snapshots.get(asset_id, [])
        if not snapshots:
            return None
        return max(snapshots, key=lambda s: s.captured_at)


class ChangeTracker:
    """
    Tracks asset changes over time.

    Monitors configuration changes, maintains history,
    and provides change attribution when possible.
    """

    def __init__(
        self,
        storage: ChangeStorage | None = None,
    ):
        """
        Initialize change tracker.

        Args:
            storage: Change storage backend
        """
        self.storage = storage or InMemoryChangeStorage()
        self._snapshot_counter = 0

    def track_changes(
        self,
        assets: AssetCollection | list[Asset],
        snapshot_id: str | None = None,
    ) -> list[ChangeEvent]:
        """
        Track changes in assets compared to previous snapshots.

        Args:
            assets: Current assets
            snapshot_id: Optional snapshot identifier

        Returns:
            List of detected change events
        """
        if isinstance(assets, AssetCollection):
            assets_list = list(assets.assets)
        else:
            assets_list = assets

        if not snapshot_id:
            snapshot_id = self._generate_snapshot_id()

        events: list[ChangeEvent] = []
        current_time = datetime.utcnow()

        for asset in assets_list:
            event = self._track_asset_change(asset, snapshot_id, current_time)
            if event:
                events.append(event)

        return events

    def _track_asset_change(
        self,
        asset: Asset,
        snapshot_id: str,
        current_time: datetime,
    ) -> ChangeEvent | None:
        """Track change for a single asset."""
        # Create current snapshot
        current_snapshot = ConfigSnapshot.from_asset(asset, snapshot_id)

        # Get previous snapshot
        previous_snapshot = self.storage.get_latest_snapshot(asset.id)

        # Determine change type
        if previous_snapshot is None:
            # New asset
            change_type = ChangeType.CREATED
            changed_paths = list(current_snapshot.config_data.keys())
        elif previous_snapshot.config_hash == current_snapshot.config_hash:
            # No change
            self.storage.save_snapshot(asset.id, current_snapshot)
            return None
        else:
            # Updated
            change_type = ChangeType.UPDATED
            changed_paths = self._find_changed_paths(
                previous_snapshot.config_data,
                current_snapshot.config_data,
            )

        # Save current snapshot
        self.storage.save_snapshot(asset.id, current_snapshot)

        # Create change event
        event_id = f"change-{asset.id}-{current_time.strftime('%Y%m%d%H%M%S')}"

        event = ChangeEvent(
            event_id=event_id,
            asset_id=asset.id,
            change_type=change_type,
            occurred_at=current_time,
            detected_at=current_time,
            previous_snapshot=previous_snapshot,
            current_snapshot=current_snapshot,
            changed_paths=changed_paths,
            attributed_to=self._attribute_change(asset),
            source=self._detect_change_source(asset),
        )

        # Save event
        self.storage.save_event(event)

        # Update asset history
        history = self.storage.get_asset_history(asset.id)
        if history:
            history.asset_type = asset.resource_type
            history.cloud_provider = asset.cloud_provider
            history.last_seen = current_time
            history.current_config_hash = current_snapshot.config_hash
            if history.first_seen is None:
                history.first_seen = current_time

        return event

    def record_deletion(
        self,
        asset_id: str,
        asset_type: str = "unknown",
        cloud_provider: str = "unknown",
    ) -> ChangeEvent:
        """
        Record an asset deletion.

        Args:
            asset_id: Deleted asset ID
            asset_type: Resource type
            cloud_provider: Cloud provider

        Returns:
            Deletion event
        """
        current_time = datetime.utcnow()
        previous_snapshot = self.storage.get_latest_snapshot(asset_id)

        event = ChangeEvent(
            event_id=f"change-{asset_id}-{current_time.strftime('%Y%m%d%H%M%S')}",
            asset_id=asset_id,
            change_type=ChangeType.DELETED,
            occurred_at=current_time,
            detected_at=current_time,
            previous_snapshot=previous_snapshot,
            current_snapshot=None,
            changed_paths=[],
            attributed_to="unknown",
            source="unknown",
        )

        self.storage.save_event(event)
        return event

    def get_asset_history(self, asset_id: str) -> AssetHistory | None:
        """Get change history for an asset."""
        return self.storage.get_asset_history(asset_id)

    def get_recent_changes(
        self,
        limit: int = 100,
        asset_type: str | None = None,
        change_type: ChangeType | None = None,
    ) -> list[ChangeEvent]:
        """
        Get recent changes with optional filters.

        Args:
            limit: Maximum number of events
            asset_type: Filter by asset type
            change_type: Filter by change type

        Returns:
            List of change events
        """
        events = self.storage.get_recent_events(limit * 2)  # Get more for filtering

        # Apply filters
        if asset_type:
            events = [
                e for e in events
                if e.current_snapshot and asset_type in str(e.metadata.get("asset_type", ""))
            ]

        if change_type:
            events = [e for e in events if e.change_type == change_type]

        return events[:limit]

    def get_changes_in_range(
        self,
        start: datetime,
        end: datetime,
        asset_ids: list[str] | None = None,
    ) -> list[ChangeEvent]:
        """
        Get changes within a time range.

        Args:
            start: Start of range
            end: End of range
            asset_ids: Optional filter by asset IDs

        Returns:
            List of change events
        """
        events = self.storage.get_recent_events(1000)

        filtered = [
            e for e in events
            if start <= e.detected_at <= end
        ]

        if asset_ids:
            filtered = [e for e in filtered if e.asset_id in asset_ids]

        return filtered

    def get_change_timeline(
        self,
        asset_id: str,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """
        Get change timeline for an asset.

        Args:
            asset_id: Asset to get timeline for
            days: Number of days to include

        Returns:
            Timeline entries
        """
        history = self.storage.get_asset_history(asset_id)
        if not history:
            return []

        cutoff = datetime.utcnow() - timedelta(days=days)
        events = [e for e in history.events if e.detected_at >= cutoff]

        timeline = []
        for event in events:
            timeline.append({
                "timestamp": event.detected_at.isoformat(),
                "change_type": event.change_type.value,
                "changed_paths": event.changed_paths,
                "attributed_to": event.attributed_to,
                "source": event.source,
                "config_hash": event.current_snapshot.config_hash if event.current_snapshot else None,
            })

        return timeline

    def get_change_summary(
        self,
        hours: int = 24,
    ) -> dict[str, Any]:
        """
        Get summary of recent changes.

        Args:
            hours: Number of hours to summarize

        Returns:
            Summary dictionary
        """
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        events = self.storage.get_recent_events(1000)
        recent_events = [e for e in events if e.detected_at >= cutoff]

        # Count by type
        by_type: dict[str, int] = {}
        for event in recent_events:
            ct = event.change_type.value
            by_type[ct] = by_type.get(ct, 0) + 1

        # Count by asset
        by_asset: dict[str, int] = {}
        for event in recent_events:
            by_asset[event.asset_id] = by_asset.get(event.asset_id, 0) + 1

        # Most active assets
        most_active = sorted(
            by_asset.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        return {
            "period_hours": hours,
            "total_changes": len(recent_events),
            "by_change_type": by_type,
            "unique_assets_changed": len(by_asset),
            "most_active_assets": [
                {"asset_id": aid, "change_count": count}
                for aid, count in most_active
            ],
            "created": by_type.get("created", 0),
            "updated": by_type.get("updated", 0),
            "deleted": by_type.get("deleted", 0),
        }

    def _find_changed_paths(
        self,
        previous: dict,
        current: dict,
        path: str = "",
    ) -> list[str]:
        """Find changed configuration paths."""
        changed = []

        all_keys = set(previous.keys()) | set(current.keys())

        for key in all_keys:
            current_path = f"{path}.{key}" if path else key

            if key not in previous:
                changed.append(f"{current_path} (added)")
            elif key not in current:
                changed.append(f"{current_path} (removed)")
            elif previous[key] != current[key]:
                if isinstance(previous[key], dict) and isinstance(current[key], dict):
                    changed.extend(
                        self._find_changed_paths(previous[key], current[key], current_path)
                    )
                else:
                    changed.append(f"{current_path} (changed)")

        return changed

    def _attribute_change(self, asset: Asset) -> str:
        """Attempt to attribute a change to a user/system."""
        tags = asset.tags or {}

        # Check for attribution tags
        for tag in ["LastModifiedBy", "last_modified_by", "UpdatedBy", "modified_by"]:
            if tag in tags:
                return tags[tag]

        # Check raw config for attribution info
        config = asset.raw_config or {}

        if "LastModifiedBy" in config:
            return str(config["LastModifiedBy"])

        if "creator" in config:
            return str(config["creator"])

        return "unknown"

    def _detect_change_source(self, asset: Asset) -> str:
        """Detect the source of a change."""
        tags = asset.tags or {}

        # Check for IaC tags
        if tags.get("ManagedBy") == "terraform" or "terraform" in tags.get("aws:cloudformation:stack-name", "").lower():
            return "terraform"

        if "aws:cloudformation:stack-name" in tags:
            return "cloudformation"

        if tags.get("goog-dm-deployment"):
            return "deployment_manager"

        if tags.get("azure-resource-manager"):
            return "arm_template"

        # Check for console indicators
        config = asset.raw_config or {}
        if "ConsoleUI" in str(config.get("UserAgent", "")):
            return "console"

        return "api"

    def _generate_snapshot_id(self) -> str:
        """Generate a unique snapshot ID."""
        self._snapshot_counter += 1
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        return f"snapshot-{timestamp}-{self._snapshot_counter}"
