"""
Google Cloud Storage based storage implementation.

This module provides GCSStorage, a storage backend that stores assets
and findings in Google Cloud Storage with support for BigQuery querying.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

try:
    from google.cloud import storage as gcs
    from google.api_core.exceptions import NotFound, Forbidden

    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False

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


class GCSStorage(StorageBackend):
    """
    Google Cloud Storage based storage for production deployments.

    Stores assets and findings as JSON files in GCS, organized by snapshot ID.
    The format is compatible with BigQuery for SQL querying.

    Attributes:
        bucket: GCS bucket name
        prefix: Key prefix for all stored objects
        project_id: GCP project ID
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "stance",
        project_id: str | None = None,
        credentials: Any = None,
    ) -> None:
        """
        Initialize the GCS storage backend.

        Args:
            bucket: GCS bucket name for storage
            prefix: Key prefix for all objects (default: "stance")
            project_id: GCP project ID
            credentials: Optional google.auth credentials object

        Raises:
            ImportError: If google-cloud-storage is not installed
        """
        if not GCS_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCSStorage. "
                "Install with: pip install google-cloud-storage"
            )

        self.bucket_name = bucket
        self.prefix = prefix.rstrip("/")
        self.project_id = project_id
        self._credentials = credentials
        self._client: Any = None
        self._bucket: Any = None

    def _get_client(self) -> Any:
        """Get or create GCS client."""
        if self._client is None:
            self._client = gcs.Client(
                project=self.project_id,
                credentials=self._credentials,
            )
        return self._client

    def _get_bucket(self) -> Any:
        """Get the GCS bucket object."""
        if self._bucket is None:
            client = self._get_client()
            self._bucket = client.bucket(self.bucket_name)
        return self._bucket

    def _get_blob_name(self, *parts: str) -> str:
        """Build a blob name from parts."""
        return "/".join([self.prefix] + list(parts))

    def _write_json(self, blob_name: str, data: Any) -> None:
        """
        Write JSON data to GCS.

        Args:
            blob_name: GCS blob name
            data: Data to serialize as JSON
        """
        bucket = self._get_bucket()
        blob = bucket.blob(blob_name)
        content = json.dumps(data, indent=2, default=str)

        try:
            blob.upload_from_string(
                content,
                content_type="application/json",
            )
        except Forbidden as e:
            raise PermissionError(
                f"Access denied when writing to gs://{self.bucket_name}/{blob_name}"
            ) from e

    def _write_jsonl(self, blob_name: str, items: list[dict[str, Any]]) -> None:
        """
        Write JSON Lines format to GCS.

        Args:
            blob_name: GCS blob name
            items: List of dictionaries to write
        """
        bucket = self._get_bucket()
        blob = bucket.blob(blob_name)
        lines = [json.dumps(item, default=str) for item in items]
        content = "\n".join(lines)

        try:
            blob.upload_from_string(
                content,
                content_type="application/json",
            )
        except Forbidden as e:
            raise PermissionError(
                f"Access denied when writing to gs://{self.bucket_name}/{blob_name}"
            ) from e

    def _read_json(self, blob_name: str) -> Any | None:
        """
        Read JSON data from GCS.

        Args:
            blob_name: GCS blob name

        Returns:
            Parsed JSON data, or None if blob doesn't exist
        """
        bucket = self._get_bucket()
        blob = bucket.blob(blob_name)

        try:
            content = blob.download_as_string().decode("utf-8")
            return json.loads(content)
        except NotFound:
            return None
        except Forbidden as e:
            raise PermissionError(
                f"Access denied when reading gs://{self.bucket_name}/{blob_name}"
            ) from e

    def _read_jsonl(self, blob_name: str) -> list[dict[str, Any]]:
        """
        Read JSON Lines format from GCS.

        Args:
            blob_name: GCS blob name

        Returns:
            List of parsed dictionaries
        """
        bucket = self._get_bucket()
        blob = bucket.blob(blob_name)

        try:
            content = blob.download_as_string().decode("utf-8")
            items = []
            for line in content.strip().split("\n"):
                if line:
                    items.append(json.loads(line))
            return items
        except NotFound:
            return []
        except Forbidden as e:
            raise PermissionError(
                f"Access denied when reading gs://{self.bucket_name}/{blob_name}"
            ) from e

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
            f"Stored {len(assets)} assets to gs://{self.bucket_name}/{blob_name}"
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
            f"Stored {len(findings)} findings to gs://{self.bucket_name}/{blob_name}"
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

    def get_bigquery_table_ddl(self, table_type: str = "assets") -> str:
        """
        Get BigQuery CREATE TABLE statement for querying data.

        Args:
            table_type: Either "assets" or "findings"

        Returns:
            CREATE EXTERNAL TABLE statement for BigQuery
        """
        if table_type == "assets":
            return f"""
CREATE OR REPLACE EXTERNAL TABLE `{self.project_id}.stance.assets`
OPTIONS (
    format = 'JSON',
    uris = ['gs://{self.bucket_name}/{self.prefix}/assets/*/assets.jsonl']
);
"""
        elif table_type == "findings":
            return f"""
CREATE OR REPLACE EXTERNAL TABLE `{self.project_id}.stance.findings`
OPTIONS (
    format = 'JSON',
    uris = ['gs://{self.bucket_name}/{self.prefix}/findings/*/findings.jsonl']
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
        client = self._get_client()
        bucket = self._get_bucket()
        prefixes = [
            self._get_blob_name("assets", snapshot_id),
            self._get_blob_name("findings", snapshot_id),
        ]

        for prefix in prefixes:
            try:
                blobs = list(bucket.list_blobs(prefix=prefix))
                for blob in blobs:
                    blob.delete()
            except Exception as e:
                logger.warning(f"Error deleting blobs with prefix {prefix}: {e}")

        # Update manifest
        blob_name = self._get_blob_name("snapshots", "manifest.json")
        self._write_json(blob_name, manifest)

        return True
