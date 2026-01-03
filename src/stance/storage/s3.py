"""
S3-based storage implementation for production deployments.

This module provides S3Storage, a storage backend that stores assets
and findings in Amazon S3 with support for Athena querying.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
    Severity,
)
from stance.storage.base import StorageBackend

logger = logging.getLogger(__name__)


class S3Storage(StorageBackend):
    """
    S3-based storage for production deployments with Athena querying.

    Stores assets and findings as JSON files in S3, organized by snapshot ID.
    The format is compatible with Athena for SQL querying.

    Attributes:
        bucket: S3 bucket name
        prefix: Key prefix for all stored objects
        region: AWS region
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "stance",
        region: str = "us-east-1",
    ) -> None:
        """
        Initialize the S3 storage backend.

        Args:
            bucket: S3 bucket name for storage
            prefix: Key prefix for all objects (default: "stance")
            region: AWS region (default: "us-east-1")

        Raises:
            ImportError: If boto3 is not installed
        """
        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 is required for S3Storage. Install with: pip install boto3"
            )

        self.bucket = bucket
        self.prefix = prefix.rstrip("/")
        self.region = region
        self._client: Any = None

    def _get_s3_client(self) -> Any:
        """Get or create S3 client."""
        if self._client is None:
            self._client = boto3.client("s3", region_name=self.region)
        return self._client

    def _get_key(self, *parts: str) -> str:
        """Build an S3 key from parts."""
        return "/".join([self.prefix] + list(parts))

    def _write_json(self, key: str, data: Any) -> None:
        """
        Write JSON data to S3.

        Args:
            key: S3 object key
            data: Data to serialize as JSON
        """
        client = self._get_s3_client()
        body = json.dumps(data, indent=2, default=str)

        try:
            client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body.encode("utf-8"),
                ContentType="application/json",
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDenied":
                raise PermissionError(
                    f"Access denied when writing to s3://{self.bucket}/{key}"
                ) from e
            elif error_code == "NoSuchBucket":
                raise ValueError(f"Bucket does not exist: {self.bucket}") from e
            raise

    def _write_jsonl(self, key: str, items: list[dict[str, Any]]) -> None:
        """
        Write JSON Lines format to S3 (one JSON object per line).

        This format is compatible with Athena.

        Args:
            key: S3 object key
            items: List of dictionaries to write
        """
        client = self._get_s3_client()
        lines = [json.dumps(item, default=str) for item in items]
        body = "\n".join(lines)

        try:
            client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body.encode("utf-8"),
                ContentType="application/json",
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "AccessDenied":
                raise PermissionError(
                    f"Access denied when writing to s3://{self.bucket}/{key}"
                ) from e
            elif error_code == "NoSuchBucket":
                raise ValueError(f"Bucket does not exist: {self.bucket}") from e
            raise

    def _read_json(self, key: str) -> Any | None:
        """
        Read JSON data from S3.

        Args:
            key: S3 object key

        Returns:
            Parsed JSON data, or None if object doesn't exist
        """
        client = self._get_s3_client()

        try:
            response = client.get_object(Bucket=self.bucket, Key=key)
            body = response["Body"].read().decode("utf-8")
            return json.loads(body)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code in ("NoSuchKey", "404"):
                return None
            if error_code == "AccessDenied":
                raise PermissionError(
                    f"Access denied when reading s3://{self.bucket}/{key}"
                ) from e
            raise

    def _read_jsonl(self, key: str) -> list[dict[str, Any]]:
        """
        Read JSON Lines format from S3.

        Args:
            key: S3 object key

        Returns:
            List of parsed dictionaries
        """
        client = self._get_s3_client()

        try:
            response = client.get_object(Bucket=self.bucket, Key=key)
            body = response["Body"].read().decode("utf-8")
            items = []
            for line in body.strip().split("\n"):
                if line:
                    items.append(json.loads(line))
            return items
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code in ("NoSuchKey", "404"):
                return []
            if error_code == "AccessDenied":
                raise PermissionError(
                    f"Access denied when reading s3://{self.bucket}/{key}"
                ) from e
            raise

    def _get_manifest(self) -> dict[str, Any]:
        """Get the snapshots manifest."""
        key = self._get_key("snapshots", "manifest.json")
        manifest = self._read_json(key)
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
        """
        Update the snapshots manifest with a new or updated snapshot.

        Args:
            snapshot_id: Snapshot ID to add/update
            account_id: AWS account ID
            asset_count: Number of assets in snapshot
            finding_count: Number of findings in snapshot
        """
        manifest = self._get_manifest()

        # Find existing entry or create new one
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

        # Update entry
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

        # Write updated manifest
        key = self._get_key("snapshots", "manifest.json")
        self._write_json(key, manifest)

    def store_assets(self, assets: AssetCollection, snapshot_id: str) -> None:
        """Store an asset inventory snapshot."""
        # Convert assets to dictionaries
        asset_dicts = assets.to_list()

        # Get account_id from first asset
        account_id = None
        if len(assets) > 0:
            account_id = assets[0].account_id

        # Write assets as JSON Lines
        key = self._get_key("assets", snapshot_id, "assets.jsonl")
        self._write_jsonl(key, asset_dicts)

        # Update manifest
        self._update_manifest(
            snapshot_id,
            account_id=account_id,
            asset_count=len(assets),
        )

        logger.info(
            f"Stored {len(assets)} assets to s3://{self.bucket}/{key}"
        )

    def store_findings(self, findings: FindingCollection, snapshot_id: str) -> None:
        """Store findings from policy evaluation."""
        # Convert findings to dictionaries
        finding_dicts = findings.to_list()

        # Write findings as JSON Lines
        key = self._get_key("findings", snapshot_id, "findings.jsonl")
        self._write_jsonl(key, finding_dicts)

        # Update manifest
        self._update_manifest(
            snapshot_id,
            finding_count=len(findings),
        )

        logger.info(
            f"Stored {len(findings)} findings to s3://{self.bucket}/{key}"
        )

    def get_assets(self, snapshot_id: str | None = None) -> AssetCollection:
        """Retrieve assets from storage."""
        if snapshot_id is None:
            snapshot_id = self.get_latest_snapshot_id()
            if snapshot_id is None:
                return AssetCollection()

        key = self._get_key("assets", snapshot_id, "assets.jsonl")
        asset_dicts = self._read_jsonl(key)

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

        key = self._get_key("findings", snapshot_id, "findings.jsonl")
        finding_dicts = self._read_jsonl(key)

        findings = [Finding.from_dict(d) for d in finding_dicts]

        # Apply filters
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
        """
        Get information about a specific snapshot.

        Args:
            snapshot_id: The snapshot to get info for

        Returns:
            Dictionary with snapshot metadata, or None if not found
        """
        manifest = self._get_manifest()
        for snapshot in manifest["snapshots"]:
            if snapshot["id"] == snapshot_id:
                return snapshot
        return None

    def get_athena_table_ddl(self, table_type: str = "assets") -> str:
        """
        Get Athena CREATE TABLE statement for querying data.

        Args:
            table_type: Either "assets" or "findings"

        Returns:
            CREATE EXTERNAL TABLE statement for Athena
        """
        if table_type == "assets":
            return f"""
CREATE EXTERNAL TABLE IF NOT EXISTS stance_assets (
    id STRING,
    cloud_provider STRING,
    account_id STRING,
    region STRING,
    resource_type STRING,
    name STRING,
    tags MAP<STRING, STRING>,
    network_exposure STRING,
    created_at STRING,
    last_seen STRING,
    raw_config STRING
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://{self.bucket}/{self.prefix}/assets/'
"""
        elif table_type == "findings":
            return f"""
CREATE EXTERNAL TABLE IF NOT EXISTS stance_findings (
    id STRING,
    asset_id STRING,
    finding_type STRING,
    severity STRING,
    status STRING,
    title STRING,
    description STRING,
    rule_id STRING,
    resource_path STRING,
    expected_value STRING,
    actual_value STRING,
    cve_id STRING,
    cvss_score DOUBLE,
    package_name STRING,
    installed_version STRING,
    fixed_version STRING,
    compliance_frameworks ARRAY<STRING>,
    remediation_guidance STRING,
    first_seen STRING,
    last_seen STRING
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://{self.bucket}/{self.prefix}/findings/'
"""
        else:
            raise ValueError(f"Unknown table type: {table_type}")

    def delete_snapshot(self, snapshot_id: str) -> bool:
        """
        Delete a snapshot and all associated data.

        Args:
            snapshot_id: Snapshot to delete

        Returns:
            True if snapshot was deleted, False if not found
        """
        client = self._get_s3_client()

        # Check if snapshot exists in manifest
        manifest = self._get_manifest()
        found = False
        for i, snapshot in enumerate(manifest["snapshots"]):
            if snapshot["id"] == snapshot_id:
                manifest["snapshots"].pop(i)
                found = True
                break

        if not found:
            return False

        # Delete S3 objects
        prefixes = [
            self._get_key("assets", snapshot_id),
            self._get_key("findings", snapshot_id),
        ]

        for prefix in prefixes:
            try:
                # List and delete objects with this prefix
                paginator = client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                    if "Contents" in page:
                        objects = [{"Key": obj["Key"]} for obj in page["Contents"]]
                        if objects:
                            client.delete_objects(
                                Bucket=self.bucket,
                                Delete={"Objects": objects},
                            )
            except ClientError as e:
                logger.warning(f"Error deleting objects with prefix {prefix}: {e}")

        # Update manifest
        key = self._get_key("snapshots", "manifest.json")
        self._write_json(key, manifest)

        return True
