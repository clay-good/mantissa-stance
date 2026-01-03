"""
Cross-cloud synchronization for Mantissa Stance.

Provides synchronization of findings to central storage with support
for hub-and-spoke deployment models.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Protocol

from stance.models.finding import Finding, FindingCollection, Severity
from stance.models.asset import Asset, AssetCollection

logger = logging.getLogger(__name__)


class SyncDirection(Enum):
    """Direction of synchronization."""

    PUSH = "push"  # Local to central
    PULL = "pull"  # Central to local
    BIDIRECTIONAL = "bidirectional"


class ConflictResolution(Enum):
    """Strategy for resolving sync conflicts."""

    LATEST_WINS = "latest_wins"  # Most recent last_seen wins
    CENTRAL_WINS = "central_wins"  # Central storage always wins
    LOCAL_WINS = "local_wins"  # Local storage always wins
    MERGE = "merge"  # Attempt to merge changes


@dataclass
class SyncConfig:
    """
    Configuration for cross-cloud synchronization.

    Attributes:
        central_bucket: S3/GCS/ADLS bucket for central storage
        central_prefix: Prefix path in central storage
        sync_direction: Direction of synchronization
        conflict_resolution: Strategy for conflicts
        include_assets: Whether to sync assets (not just findings)
        batch_size: Number of records to sync per batch
        checksum_verify: Verify data integrity with checksums
    """

    central_bucket: str
    central_prefix: str = "aggregated"
    sync_direction: SyncDirection = SyncDirection.PUSH
    conflict_resolution: ConflictResolution = ConflictResolution.LATEST_WINS
    include_assets: bool = True
    batch_size: int = 1000
    checksum_verify: bool = True


@dataclass
class SyncRecord:
    """
    Record of a synchronized item.

    Attributes:
        id: Unique identifier of the record
        record_type: Type of record (finding, asset)
        source_account: Source cloud account
        source_provider: Source cloud provider
        synced_at: When the record was synced
        checksum: SHA256 checksum of the data
        version: Version number for optimistic locking
    """

    id: str
    record_type: str
    source_account: str
    source_provider: str
    synced_at: datetime
    checksum: str
    version: int = 1


@dataclass
class SyncResult:
    """
    Result of a synchronization operation.

    Attributes:
        success: Whether sync completed successfully
        records_synced: Number of records synchronized
        records_skipped: Number of records skipped (already synced)
        conflicts_resolved: Number of conflicts resolved
        errors: List of error messages
        duration_seconds: Time taken for sync
        sync_direction: Direction of sync
    """

    success: bool = True
    records_synced: int = 0
    records_skipped: int = 0
    conflicts_resolved: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    sync_direction: SyncDirection = SyncDirection.PUSH

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "success": self.success,
            "records_synced": self.records_synced,
            "records_skipped": self.records_skipped,
            "conflicts_resolved": self.conflicts_resolved,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
            "sync_direction": self.sync_direction.value,
        }


class StorageAdapter(Protocol):
    """Protocol for storage backends used in sync."""

    def write_record(self, path: str, data: dict[str, Any]) -> None:
        """Write a record to storage."""
        ...

    def read_record(self, path: str) -> dict[str, Any] | None:
        """Read a record from storage."""
        ...

    def list_records(self, prefix: str) -> list[str]:
        """List record paths under a prefix."""
        ...

    def delete_record(self, path: str) -> None:
        """Delete a record from storage."""
        ...

    def get_metadata(self, path: str) -> dict[str, Any] | None:
        """Get metadata for a record."""
        ...


class CrossCloudSync:
    """
    Synchronizes findings across cloud environments.

    Supports hub-and-spoke model where multiple cloud accounts sync
    their findings to a central storage location. Handles conflict
    resolution and maintains data integrity.

    Example:
        >>> config = SyncConfig(
        ...     central_bucket="stance-central-findings",
        ...     sync_direction=SyncDirection.PUSH
        ... )
        >>> sync = CrossCloudSync(config, storage_adapter)
        >>> sync.add_local_findings(findings, "123456789012", "aws")
        >>> result = sync.sync()
        >>> print(f"Synced {result.records_synced} records")
    """

    def __init__(
        self,
        config: SyncConfig,
        storage: StorageAdapter,
    ) -> None:
        """
        Initialize the cross-cloud sync.

        Args:
            config: Sync configuration
            storage: Storage adapter for central storage
        """
        self._config = config
        self._storage = storage
        self._local_findings: list[tuple[Finding, str, str]] = []  # (finding, account, provider)
        self._local_assets: list[tuple[Asset, str, str]] = []
        self._sync_state: dict[str, SyncRecord] = {}

    def add_local_findings(
        self,
        findings: FindingCollection | list[Finding],
        account_id: str,
        provider: str,
    ) -> None:
        """
        Add local findings to be synced.

        Args:
            findings: Findings to sync
            account_id: Source account identifier
            provider: Cloud provider (aws, gcp, azure)
        """
        if isinstance(findings, FindingCollection):
            finding_list = list(findings)
        else:
            finding_list = findings

        for finding in finding_list:
            self._local_findings.append((finding, account_id, provider))

        logger.info(
            f"Added {len(finding_list)} findings for sync from {provider}/{account_id}"
        )

    def add_local_assets(
        self,
        assets: AssetCollection | list[Asset],
        account_id: str,
        provider: str,
    ) -> None:
        """
        Add local assets to be synced.

        Args:
            assets: Assets to sync
            account_id: Source account identifier
            provider: Cloud provider
        """
        if not self._config.include_assets:
            logger.debug("Asset sync disabled, skipping")
            return

        if isinstance(assets, AssetCollection):
            asset_list = list(assets)
        else:
            asset_list = assets

        for asset in asset_list:
            self._local_assets.append((asset, account_id, provider))

        logger.info(
            f"Added {len(asset_list)} assets for sync from {provider}/{account_id}"
        )

    def sync(self) -> SyncResult:
        """
        Perform synchronization based on configured direction.

        Returns:
            SyncResult with sync statistics
        """
        start_time = datetime.utcnow()

        if self._config.sync_direction == SyncDirection.PUSH:
            result = self._sync_push()
        elif self._config.sync_direction == SyncDirection.PULL:
            result = self._sync_pull()
        else:
            result = self._sync_bidirectional()

        result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        result.sync_direction = self._config.sync_direction

        logger.info(
            f"Sync complete: {result.records_synced} synced, "
            f"{result.records_skipped} skipped, "
            f"{result.conflicts_resolved} conflicts in {result.duration_seconds:.2f}s"
        )

        return result

    def _sync_push(self) -> SyncResult:
        """Push local findings to central storage."""
        result = SyncResult()
        batch: list[dict[str, Any]] = []

        # Process findings
        for finding, account_id, provider in self._local_findings:
            try:
                record_data = self._prepare_finding_record(finding, account_id, provider)
                path = self._get_finding_path(finding.id, account_id)

                # Check for existing record
                existing = self._storage.read_record(path)
                if existing:
                    conflict_result = self._resolve_conflict(existing, record_data)
                    if conflict_result == "skip":
                        result.records_skipped += 1
                        continue
                    elif conflict_result == "resolved":
                        result.conflicts_resolved += 1

                # Write record
                self._storage.write_record(path, record_data)
                result.records_synced += 1

                # Track sync state
                self._sync_state[finding.id] = SyncRecord(
                    id=finding.id,
                    record_type="finding",
                    source_account=account_id,
                    source_provider=provider,
                    synced_at=datetime.utcnow(),
                    checksum=self._compute_checksum(record_data),
                    version=1,
                )

            except Exception as e:
                result.errors.append(f"Error syncing finding {finding.id}: {e}")
                logger.error(f"Error syncing finding {finding.id}: {e}")

        # Process assets if enabled
        if self._config.include_assets:
            for asset, account_id, provider in self._local_assets:
                try:
                    record_data = self._prepare_asset_record(asset, account_id, provider)
                    path = self._get_asset_path(asset.id, account_id)

                    existing = self._storage.read_record(path)
                    if existing:
                        conflict_result = self._resolve_conflict(existing, record_data)
                        if conflict_result == "skip":
                            result.records_skipped += 1
                            continue
                        elif conflict_result == "resolved":
                            result.conflicts_resolved += 1

                    self._storage.write_record(path, record_data)
                    result.records_synced += 1

                except Exception as e:
                    result.errors.append(f"Error syncing asset {asset.id}: {e}")
                    logger.error(f"Error syncing asset {asset.id}: {e}")

        result.success = len(result.errors) == 0
        return result

    def _sync_pull(self) -> SyncResult:
        """Pull findings from central storage."""
        result = SyncResult()

        try:
            # List all findings in central storage
            findings_prefix = f"{self._config.central_prefix}/findings/"
            paths = self._storage.list_records(findings_prefix)

            for path in paths:
                try:
                    record = self._storage.read_record(path)
                    if record:
                        # Verify checksum if enabled
                        if self._config.checksum_verify:
                            stored_checksum = record.get("_checksum", "")
                            data_copy = {k: v for k, v in record.items() if not k.startswith("_")}
                            computed = self._compute_checksum(data_copy)
                            if stored_checksum and stored_checksum != computed:
                                result.errors.append(f"Checksum mismatch for {path}")
                                continue

                        result.records_synced += 1

                except Exception as e:
                    result.errors.append(f"Error reading {path}: {e}")

            # Pull assets if enabled
            if self._config.include_assets:
                assets_prefix = f"{self._config.central_prefix}/assets/"
                asset_paths = self._storage.list_records(assets_prefix)

                for path in asset_paths:
                    try:
                        record = self._storage.read_record(path)
                        if record:
                            result.records_synced += 1
                    except Exception as e:
                        result.errors.append(f"Error reading asset {path}: {e}")

        except Exception as e:
            result.errors.append(f"Error listing records: {e}")
            result.success = False

        result.success = len(result.errors) == 0
        return result

    def _sync_bidirectional(self) -> SyncResult:
        """Perform bidirectional sync (push then pull new records)."""
        # First push local changes
        push_result = self._sync_push()

        # Then pull remote changes we don't have locally
        pull_result = self._sync_pull()

        # Combine results
        return SyncResult(
            success=push_result.success and pull_result.success,
            records_synced=push_result.records_synced + pull_result.records_synced,
            records_skipped=push_result.records_skipped + pull_result.records_skipped,
            conflicts_resolved=push_result.conflicts_resolved + pull_result.conflicts_resolved,
            errors=push_result.errors + pull_result.errors,
        )

    def _prepare_finding_record(
        self,
        finding: Finding,
        account_id: str,
        provider: str,
    ) -> dict[str, Any]:
        """Prepare a finding record for storage."""
        record = finding.to_dict()
        record["_source_account"] = account_id
        record["_source_provider"] = provider
        record["_synced_at"] = datetime.utcnow().isoformat()

        if self._config.checksum_verify:
            # Compute checksum without metadata fields
            data_for_checksum = {k: v for k, v in record.items() if not k.startswith("_")}
            record["_checksum"] = self._compute_checksum(data_for_checksum)

        return record

    def _prepare_asset_record(
        self,
        asset: Asset,
        account_id: str,
        provider: str,
    ) -> dict[str, Any]:
        """Prepare an asset record for storage."""
        record = asset.to_dict()
        record["_source_account"] = account_id
        record["_source_provider"] = provider
        record["_synced_at"] = datetime.utcnow().isoformat()

        if self._config.checksum_verify:
            data_for_checksum = {k: v for k, v in record.items() if not k.startswith("_")}
            record["_checksum"] = self._compute_checksum(data_for_checksum)

        return record

    def _get_finding_path(self, finding_id: str, account_id: str) -> str:
        """Get storage path for a finding."""
        # Use hash prefix for distribution
        prefix_hash = hashlib.md5(finding_id.encode()).hexdigest()[:4]
        return (
            f"{self._config.central_prefix}/findings/"
            f"{prefix_hash}/{account_id}/{finding_id}.json"
        )

    def _get_asset_path(self, asset_id: str, account_id: str) -> str:
        """Get storage path for an asset."""
        # Sanitize asset_id for use in path
        safe_id = asset_id.replace("/", "_").replace(":", "_")
        prefix_hash = hashlib.md5(asset_id.encode()).hexdigest()[:4]
        return (
            f"{self._config.central_prefix}/assets/"
            f"{prefix_hash}/{account_id}/{safe_id}.json"
        )

    def _resolve_conflict(
        self,
        existing: dict[str, Any],
        new: dict[str, Any],
    ) -> str:
        """
        Resolve conflict between existing and new record.

        Returns:
            "skip" to keep existing, "resolved" to use new
        """
        if self._config.conflict_resolution == ConflictResolution.CENTRAL_WINS:
            return "skip"

        elif self._config.conflict_resolution == ConflictResolution.LOCAL_WINS:
            return "resolved"

        elif self._config.conflict_resolution == ConflictResolution.LATEST_WINS:
            existing_time = existing.get("last_seen") or existing.get("_synced_at")
            new_time = new.get("last_seen") or new.get("_synced_at")

            if existing_time and new_time:
                # Parse timestamps and compare
                try:
                    existing_dt = datetime.fromisoformat(existing_time.replace("Z", "+00:00"))
                    new_dt = datetime.fromisoformat(new_time.replace("Z", "+00:00"))
                    if new_dt > existing_dt:
                        return "resolved"
                    else:
                        return "skip"
                except (ValueError, AttributeError):
                    pass

            return "resolved"

        elif self._config.conflict_resolution == ConflictResolution.MERGE:
            # Merge logic: take non-null values from new, keep existing otherwise
            # This is a simple merge - could be extended for field-level merge
            return "resolved"

        return "skip"

    def _compute_checksum(self, data: dict[str, Any]) -> str:
        """Compute SHA256 checksum of data."""
        # Sort keys for deterministic serialization
        json_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()

    def get_sync_state(self) -> dict[str, SyncRecord]:
        """Get current sync state."""
        return self._sync_state.copy()

    def clear(self) -> None:
        """Clear local data and sync state."""
        self._local_findings.clear()
        self._local_assets.clear()
        self._sync_state.clear()
        logger.info("Sync state cleared")


class S3StorageAdapter:
    """S3 implementation of StorageAdapter protocol."""

    def __init__(
        self,
        bucket: str,
        session: Any | None = None,
        region: str = "us-east-1",
    ) -> None:
        """Initialize S3 adapter."""
        self._bucket = bucket
        self._region = region

        try:
            import boto3

            if session:
                self._client = session.client("s3", region_name=region)
            else:
                self._client = boto3.client("s3", region_name=region)
        except ImportError:
            raise ImportError("boto3 is required for S3StorageAdapter")

    def write_record(self, path: str, data: dict[str, Any]) -> None:
        """Write a record to S3."""
        self._client.put_object(
            Bucket=self._bucket,
            Key=path,
            Body=json.dumps(data, default=str),
            ContentType="application/json",
        )

    def read_record(self, path: str) -> dict[str, Any] | None:
        """Read a record from S3."""
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=path)
            content = response["Body"].read().decode("utf-8")
            return json.loads(content)
        except self._client.exceptions.NoSuchKey:
            return None
        except Exception:
            return None

    def list_records(self, prefix: str) -> list[str]:
        """List record paths under a prefix."""
        paths: list[str] = []
        paginator = self._client.get_paginator("list_objects_v2")

        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                paths.append(obj["Key"])

        return paths

    def delete_record(self, path: str) -> None:
        """Delete a record from S3."""
        self._client.delete_object(Bucket=self._bucket, Key=path)

    def get_metadata(self, path: str) -> dict[str, Any] | None:
        """Get metadata for a record."""
        try:
            response = self._client.head_object(Bucket=self._bucket, Key=path)
            return {
                "size": response["ContentLength"],
                "last_modified": response["LastModified"].isoformat(),
                "etag": response["ETag"],
            }
        except Exception:
            return None


class GCSStorageAdapter:
    """Google Cloud Storage implementation of StorageAdapter protocol."""

    def __init__(
        self,
        bucket: str,
        credentials: Any | None = None,
    ) -> None:
        """Initialize GCS adapter."""
        self._bucket_name = bucket

        try:
            from google.cloud import storage

            self._client = storage.Client(credentials=credentials)
            self._bucket = self._client.bucket(bucket)
        except ImportError:
            raise ImportError("google-cloud-storage is required for GCSStorageAdapter")

    def write_record(self, path: str, data: dict[str, Any]) -> None:
        """Write a record to GCS."""
        blob = self._bucket.blob(path)
        blob.upload_from_string(
            json.dumps(data, default=str),
            content_type="application/json",
        )

    def read_record(self, path: str) -> dict[str, Any] | None:
        """Read a record from GCS."""
        try:
            blob = self._bucket.blob(path)
            content = blob.download_as_text()
            return json.loads(content)
        except Exception:
            return None

    def list_records(self, prefix: str) -> list[str]:
        """List record paths under a prefix."""
        blobs = self._client.list_blobs(self._bucket_name, prefix=prefix)
        return [blob.name for blob in blobs]

    def delete_record(self, path: str) -> None:
        """Delete a record from GCS."""
        blob = self._bucket.blob(path)
        blob.delete()

    def get_metadata(self, path: str) -> dict[str, Any] | None:
        """Get metadata for a record."""
        try:
            blob = self._bucket.blob(path)
            blob.reload()
            return {
                "size": blob.size,
                "last_modified": blob.updated.isoformat() if blob.updated else None,
                "etag": blob.etag,
            }
        except Exception:
            return None


class AzureBlobStorageAdapter:
    """Azure Blob Storage implementation of StorageAdapter protocol."""

    def __init__(
        self,
        account_name: str,
        container: str,
        credential: Any | None = None,
    ) -> None:
        """Initialize Azure Blob adapter."""
        self._container_name = container

        try:
            from azure.storage.blob import BlobServiceClient

            account_url = f"https://{account_name}.blob.core.windows.net"
            self._client = BlobServiceClient(account_url, credential=credential)
            self._container = self._client.get_container_client(container)
        except ImportError:
            raise ImportError("azure-storage-blob is required for AzureBlobStorageAdapter")

    def write_record(self, path: str, data: dict[str, Any]) -> None:
        """Write a record to Azure Blob Storage."""
        blob_client = self._container.get_blob_client(path)
        blob_client.upload_blob(
            json.dumps(data, default=str),
            overwrite=True,
            content_type="application/json",
        )

    def read_record(self, path: str) -> dict[str, Any] | None:
        """Read a record from Azure Blob Storage."""
        try:
            blob_client = self._container.get_blob_client(path)
            content = blob_client.download_blob().readall().decode("utf-8")
            return json.loads(content)
        except Exception:
            return None

    def list_records(self, prefix: str) -> list[str]:
        """List record paths under a prefix."""
        blobs = self._container.list_blobs(name_starts_with=prefix)
        return [blob.name for blob in blobs]

    def delete_record(self, path: str) -> None:
        """Delete a record from Azure Blob Storage."""
        blob_client = self._container.get_blob_client(path)
        blob_client.delete_blob()

    def get_metadata(self, path: str) -> dict[str, Any] | None:
        """Get metadata for a record."""
        try:
            blob_client = self._container.get_blob_client(path)
            props = blob_client.get_blob_properties()
            return {
                "size": props.size,
                "last_modified": props.last_modified.isoformat() if props.last_modified else None,
                "etag": props.etag,
            }
        except Exception:
            return None
