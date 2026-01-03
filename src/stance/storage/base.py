"""
Abstract base class for storage backends.

This module defines the StorageBackend interface that all storage
implementations must follow, along with utility functions for
snapshot ID generation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from stance.models import (
        AssetCollection,
        FindingCollection,
        Severity,
        FindingStatus,
    )


def generate_snapshot_id() -> str:
    """
    Generate a timestamp-based snapshot ID.

    Returns:
        Snapshot ID in format YYYYMMDD-HHMMSS
    """
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")


class StorageBackend(ABC):
    """
    Abstract base class for storage implementations.

    All storage backends must implement these methods to provide
    consistent storage and retrieval of assets and findings.
    """

    @abstractmethod
    def store_assets(self, assets: AssetCollection, snapshot_id: str) -> None:
        """
        Store an asset inventory snapshot.

        Args:
            assets: Collection of assets to store
            snapshot_id: Unique identifier for this snapshot
        """
        pass

    @abstractmethod
    def store_findings(self, findings: FindingCollection, snapshot_id: str) -> None:
        """
        Store findings from policy evaluation.

        Args:
            findings: Collection of findings to store
            snapshot_id: Unique identifier for this snapshot
        """
        pass

    @abstractmethod
    def get_assets(self, snapshot_id: str | None = None) -> AssetCollection:
        """
        Retrieve assets from storage.

        Args:
            snapshot_id: Snapshot to retrieve. If None, returns latest.

        Returns:
            Collection of assets from the specified snapshot
        """
        pass

    @abstractmethod
    def get_findings(
        self,
        snapshot_id: str | None = None,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
    ) -> FindingCollection:
        """
        Retrieve findings from storage with optional filters.

        Args:
            snapshot_id: Snapshot to retrieve. If None, returns latest.
            severity: Filter by severity level
            status: Filter by finding status

        Returns:
            Collection of findings matching the criteria
        """
        pass

    @abstractmethod
    def get_latest_snapshot_id(self) -> str | None:
        """
        Get the most recent snapshot ID.

        Returns:
            Latest snapshot ID, or None if no snapshots exist
        """
        pass

    @abstractmethod
    def list_snapshots(self, limit: int = 10) -> list[str]:
        """
        List recent snapshot IDs.

        Args:
            limit: Maximum number of snapshots to return

        Returns:
            List of snapshot IDs, most recent first
        """
        pass

    def create_snapshot(
        self,
        assets: AssetCollection,
        findings: FindingCollection,
        snapshot_id: str | None = None,
    ) -> str:
        """
        Create a new snapshot with assets and findings.

        This is a convenience method that stores both assets and findings
        with the same snapshot ID.

        Args:
            assets: Collection of assets to store
            findings: Collection of findings to store
            snapshot_id: Optional snapshot ID. If None, generates one.

        Returns:
            The snapshot ID used
        """
        if snapshot_id is None:
            snapshot_id = generate_snapshot_id()

        self.store_assets(assets, snapshot_id)
        self.store_findings(findings, snapshot_id)

        return snapshot_id
