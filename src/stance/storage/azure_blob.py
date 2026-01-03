"""
Azure Blob Storage based storage implementation.

This module provides AzureBlobStorage, a storage backend that stores assets
and findings in Azure Blob Storage with support for Azure Synapse querying.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

try:
    from azure.storage.blob import BlobServiceClient, ContainerClient
    from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingStatus,
    Severity,
)
from stance.storage.base import StorageBackend

logger = logging.getLogger(__name__)


class AzureBlobStorage(StorageBackend):
    """
    Azure Blob Storage based storage for production deployments.

    Stores assets and findings as JSON files in Azure Blob Storage,
    organized by snapshot ID. The format is compatible with Azure Synapse
    for SQL querying.

    Attributes:
        account_name: Azure Storage account name
        container: Container name for storage
        prefix: Blob prefix for all stored objects
    """

    def __init__(
        self,
        account_name: str,
        container: str,
        prefix: str = "stance",
        credential: Any = None,
        connection_string: str | None = None,
    ) -> None:
        """
        Initialize the Azure Blob storage backend.

        Args:
            account_name: Azure Storage account name
            container: Container name for storage
            prefix: Blob prefix for all objects (default: "stance")
            credential: Azure credential object (from azure.identity)
            connection_string: Optional connection string (alternative to credential)

        Raises:
            ImportError: If azure-storage-blob is not installed
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob is required for AzureBlobStorage. "
                "Install with: pip install azure-storage-blob"
            )

        self.account_name = account_name
        self.container_name = container
        self.prefix = prefix.rstrip("/")
        self._credential = credential
        self._connection_string = connection_string
        self._blob_service_client: Any = None
        self._container_client: Any = None

    def _get_blob_service_client(self) -> Any:
        """Get or create Blob Service client."""
        if self._blob_service_client is None:
            if self._connection_string:
                self._blob_service_client = BlobServiceClient.from_connection_string(
                    self._connection_string
                )
            else:
                account_url = f"https://{self.account_name}.blob.core.windows.net"
                self._blob_service_client = BlobServiceClient(
                    account_url=account_url,
                    credential=self._credential,
                )
        return self._blob_service_client

    def _get_container_client(self) -> Any:
        """Get the container client."""
        if self._container_client is None:
            service = self._get_blob_service_client()
            self._container_client = service.get_container_client(self.container_name)
        return self._container_client

    def _get_blob_name(self, *parts: str) -> str:
        """Build a blob name from parts."""
        return "/".join([self.prefix] + list(parts))

    def _write_json(self, blob_name: str, data: Any) -> None:
        """
        Write JSON data to Azure Blob.

        Args:
            blob_name: Blob name
            data: Data to serialize as JSON
        """
        container = self._get_container_client()
        blob = container.get_blob_client(blob_name)
        content = json.dumps(data, indent=2, default=str)

        try:
            blob.upload_blob(
                content,
                overwrite=True,
                content_settings={"content_type": "application/json"},
            )
        except HttpResponseError as e:
            if "AuthorizationFailure" in str(e) or "403" in str(e):
                raise PermissionError(
                    f"Access denied when writing to {self.account_name}/{self.container_name}/{blob_name}"
                ) from e
            raise

    def _write_jsonl(self, blob_name: str, items: list[dict[str, Any]]) -> None:
        """
        Write JSON Lines format to Azure Blob.

        Args:
            blob_name: Blob name
            items: List of dictionaries to write
        """
        container = self._get_container_client()
        blob = container.get_blob_client(blob_name)
        lines = [json.dumps(item, default=str) for item in items]
        content = "\n".join(lines)

        try:
            blob.upload_blob(
                content,
                overwrite=True,
                content_settings={"content_type": "application/json"},
            )
        except HttpResponseError as e:
            if "AuthorizationFailure" in str(e) or "403" in str(e):
                raise PermissionError(
                    f"Access denied when writing to {self.account_name}/{self.container_name}/{blob_name}"
                ) from e
            raise

    def _read_json(self, blob_name: str) -> Any | None:
        """
        Read JSON data from Azure Blob.

        Args:
            blob_name: Blob name

        Returns:
            Parsed JSON data, or None if blob doesn't exist
        """
        container = self._get_container_client()
        blob = container.get_blob_client(blob_name)

        try:
            download = blob.download_blob()
            content = download.readall().decode("utf-8")
            return json.loads(content)
        except ResourceNotFoundError:
            return None
        except HttpResponseError as e:
            if "AuthorizationFailure" in str(e) or "403" in str(e):
                raise PermissionError(
                    f"Access denied when reading {self.account_name}/{self.container_name}/{blob_name}"
                ) from e
            raise

    def _read_jsonl(self, blob_name: str) -> list[dict[str, Any]]:
        """
        Read JSON Lines format from Azure Blob.

        Args:
            blob_name: Blob name

        Returns:
            List of parsed dictionaries
        """
        container = self._get_container_client()
        blob = container.get_blob_client(blob_name)

        try:
            download = blob.download_blob()
            content = download.readall().decode("utf-8")
            items = []
            for line in content.strip().split("\n"):
                if line:
                    items.append(json.loads(line))
            return items
        except ResourceNotFoundError:
            return []
        except HttpResponseError as e:
            if "AuthorizationFailure" in str(e) or "403" in str(e):
                raise PermissionError(
                    f"Access denied when reading {self.account_name}/{self.container_name}/{blob_name}"
                ) from e
            raise

    def _get_manifest(self) -> dict[str, Any]:
        """Get the snapshots manifest."""
        blob_name = self._get_blob_name("snapshots", "manifest.json")
        manifest = self._read_json(blob_name)
        if manifest is None:
            manifest = {"snapshots": []}
        return manifest

    def _update_manifest(
        self,
        snapshot_id: str,
        account_id: str | None = None,
        asset_count: int = 0,
        finding_count: int = 0,
    ) -> None:
        """Update the snapshots manifest."""
        manifest = self._get_manifest()

        # Find or create snapshot entry
        snapshot_entry = None
        for entry in manifest["snapshots"]:
            if entry["id"] == snapshot_id:
                snapshot_entry = entry
                break

        if snapshot_entry is None:
            snapshot_entry = {
                "id": snapshot_id,
                "created_at": datetime.utcnow().isoformat(),
            }
            manifest["snapshots"].insert(0, snapshot_entry)

        if account_id:
            snapshot_entry["account_id"] = account_id
        if asset_count > 0:
            snapshot_entry["asset_count"] = asset_count
        if finding_count > 0:
            snapshot_entry["finding_count"] = finding_count

        # Sort by created_at descending
        manifest["snapshots"].sort(
            key=lambda x: x.get("created_at", ""),
            reverse=True,
        )

        blob_name = self._get_blob_name("snapshots", "manifest.json")
        self._write_json(blob_name, manifest)

    def store_assets(self, assets: AssetCollection, snapshot_id: str) -> None:
        """Store an asset inventory snapshot."""
        asset_dicts = assets.to_list()

        account_id = None
        if len(assets) > 0:
            account_id = assets[0].account_id

        blob_name = self._get_blob_name("assets", snapshot_id, "assets.jsonl")
        self._write_jsonl(blob_name, asset_dicts)

        self._update_manifest(
            snapshot_id,
            account_id=account_id,
            asset_count=len(assets),
        )

        logger.info(
            f"Stored {len(assets)} assets to {self.account_name}/{self.container_name}/{blob_name}"
        )

    def store_findings(self, findings: FindingCollection, snapshot_id: str) -> None:
        """Store findings from policy evaluation."""
        finding_dicts = findings.to_list()

        blob_name = self._get_blob_name("findings", snapshot_id, "findings.jsonl")
        self._write_jsonl(blob_name, finding_dicts)

        self._update_manifest(
            snapshot_id,
            finding_count=len(findings),
        )

        logger.info(
            f"Stored {len(findings)} findings to {self.account_name}/{self.container_name}/{blob_name}"
        )

    def get_assets(self, snapshot_id: str | None = None) -> AssetCollection:
        """Retrieve assets from storage."""
        if snapshot_id is None:
            snapshot_id = self.get_latest_snapshot_id()
            if snapshot_id is None:
                return AssetCollection()

        blob_name = self._get_blob_name("assets", snapshot_id, "assets.jsonl")
        asset_dicts = self._read_jsonl(blob_name)

        assets = [Asset.from_dict(d) for d in asset_dicts]
        return AssetCollection(assets)

    def get_findings(
        self,
        snapshot_id: str | None = None,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
    ) -> FindingCollection:
        """Retrieve findings from storage with optional filters."""
        if snapshot_id is None:
            snapshot_id = self.get_latest_snapshot_id()
            if snapshot_id is None:
                return FindingCollection()

        blob_name = self._get_blob_name("findings", snapshot_id, "findings.jsonl")
        finding_dicts = self._read_jsonl(blob_name)

        findings = [Finding.from_dict(d) for d in finding_dicts]

        if severity is not None:
            findings = [f for f in findings if f.severity == severity]
        if status is not None:
            findings = [f for f in findings if f.status == status]

        return FindingCollection(findings)

    def get_latest_snapshot_id(self) -> str | None:
        """Get the most recent snapshot ID."""
        manifest = self._get_manifest()
        if not manifest["snapshots"]:
            return None
        return manifest["snapshots"][0]["id"]

    def list_snapshots(self, limit: int = 10) -> list[str]:
        """List recent snapshot IDs."""
        manifest = self._get_manifest()
        return [s["id"] for s in manifest["snapshots"][:limit]]

    def get_snapshot_info(self, snapshot_id: str) -> dict[str, Any] | None:
        """Get information about a specific snapshot."""
        manifest = self._get_manifest()
        for snapshot in manifest["snapshots"]:
            if snapshot["id"] == snapshot_id:
                return snapshot
        return None

    def get_synapse_table_ddl(self, table_type: str = "assets") -> str:
        """
        Get Azure Synapse CREATE TABLE statement for querying data.

        Args:
            table_type: Either "assets" or "findings"

        Returns:
            CREATE EXTERNAL TABLE statement for Synapse
        """
        location = f"https://{self.account_name}.blob.core.windows.net/{self.container_name}/{self.prefix}"

        if table_type == "assets":
            return f"""
CREATE EXTERNAL TABLE stance_assets (
    id VARCHAR(500),
    cloud_provider VARCHAR(50),
    account_id VARCHAR(100),
    region VARCHAR(50),
    resource_type VARCHAR(100),
    name VARCHAR(500),
    tags VARCHAR(MAX),
    network_exposure VARCHAR(50),
    created_at VARCHAR(50),
    last_seen VARCHAR(50),
    raw_config VARCHAR(MAX)
)
WITH (
    LOCATION = '{location}/assets/',
    DATA_SOURCE = AzureBlob,
    FILE_FORMAT = JsonFormat
);
"""
        elif table_type == "findings":
            return f"""
CREATE EXTERNAL TABLE stance_findings (
    id VARCHAR(500),
    asset_id VARCHAR(500),
    finding_type VARCHAR(50),
    severity VARCHAR(20),
    status VARCHAR(20),
    title VARCHAR(500),
    description VARCHAR(MAX),
    rule_id VARCHAR(100),
    resource_path VARCHAR(500),
    expected_value VARCHAR(MAX),
    actual_value VARCHAR(MAX),
    cve_id VARCHAR(50),
    cvss_score FLOAT,
    package_name VARCHAR(200),
    installed_version VARCHAR(50),
    fixed_version VARCHAR(50),
    compliance_frameworks VARCHAR(MAX),
    remediation_guidance VARCHAR(MAX),
    first_seen VARCHAR(50),
    last_seen VARCHAR(50)
)
WITH (
    LOCATION = '{location}/findings/',
    DATA_SOURCE = AzureBlob,
    FILE_FORMAT = JsonFormat
);
"""
        else:
            raise ValueError(f"Unknown table type: {table_type}")

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """Delete a snapshot and all associated data."""
        manifest = self._get_manifest()
        found = False
        for i, snapshot in enumerate(manifest["snapshots"]):
            if snapshot["id"] == snapshot_id:
                manifest["snapshots"].pop(i)
                found = True
                break

        if not found:
            return False

        # Delete blobs
        container = self._get_container_client()
        prefixes = [
            self._get_blob_name("assets", snapshot_id),
            self._get_blob_name("findings", snapshot_id),
        ]

        for prefix in prefixes:
            try:
                blobs = container.list_blobs(name_starts_with=prefix)
                for blob in blobs:
                    container.delete_blob(blob.name)
            except Exception as e:
                logger.warning(f"Error deleting blobs with prefix {prefix}: {e}")

        # Update manifest
        blob_name = self._get_blob_name("snapshots", "manifest.json")
        self._write_json(blob_name, manifest)

        return True
