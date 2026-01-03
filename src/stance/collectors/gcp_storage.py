"""
GCP Cloud Storage collector for Mantissa Stance.

Collects Cloud Storage bucket configurations including ACLs, IAM policies,
encryption settings, and public access status for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)

# Optional GCP imports
try:
    from google.cloud import storage
    from google.auth.credentials import Credentials

    GCP_STORAGE_AVAILABLE = True
except ImportError:
    GCP_STORAGE_AVAILABLE = False
    Credentials = Any  # type: ignore


class GCPStorageCollector(BaseCollector):
    """
    Collects GCP Cloud Storage bucket resources and configuration.

    Gathers bucket configurations, ACLs, IAM policies, encryption settings,
    and public access status. All API calls are read-only.
    """

    collector_name = "gcp_storage"
    resource_types = [
        "gcp_storage_bucket",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Storage collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_STORAGE_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCP storage collector. "
                "Install with: pip install google-cloud-storage"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._client: storage.Client | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_storage_client(self) -> storage.Client:
        """Get or create Storage client."""
        if self._client is None:
            self._client = storage.Client(
                project=self._project_id,
                credentials=self._credentials,
            )
        return self._client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Cloud Storage buckets.

        Returns:
            Collection of storage bucket assets
        """
        assets: list[Asset] = []

        try:
            assets.extend(self._collect_buckets())
        except Exception as e:
            logger.warning(f"Failed to collect storage buckets: {e}")

        return AssetCollection(assets)

    def _collect_buckets(self) -> list[Asset]:
        """Collect Cloud Storage buckets with their configurations."""
        client = self._get_storage_client()
        assets: list[Asset] = []
        now = self._now()

        try:
            for bucket in client.list_buckets():
                bucket_name = bucket.name
                bucket_id = f"projects/{self._project_id}/buckets/{bucket_name}"

                raw_config: dict[str, Any] = {
                    "name": bucket_name,
                    "id": bucket.id,
                    "location": bucket.location,
                    "location_type": bucket.location_type,
                    "storage_class": bucket.storage_class,
                    "created": (
                        bucket.time_created.isoformat()
                        if bucket.time_created
                        else None
                    ),
                    "updated": (
                        bucket.updated.isoformat() if bucket.updated else None
                    ),
                    "versioning_enabled": bucket.versioning_enabled,
                    "requester_pays": bucket.requester_pays,
                }

                # Get labels (tags)
                labels = bucket.labels or {}
                raw_config["labels"] = labels

                # Check uniform bucket-level access
                iam_configuration = bucket.iam_configuration
                uniform_access = False
                if iam_configuration:
                    uniform_access = (
                        iam_configuration.get("uniformBucketLevelAccess", {})
                        .get("enabled", False)
                    )
                raw_config["uniform_bucket_level_access"] = uniform_access

                # Get public access prevention
                public_access_prevention = "inherited"
                if iam_configuration:
                    public_access_prevention = iam_configuration.get(
                        "publicAccessPrevention", "inherited"
                    )
                raw_config["public_access_prevention"] = public_access_prevention

                # Get encryption configuration
                default_kms_key = None
                if bucket.default_kms_key_name:
                    default_kms_key = bucket.default_kms_key_name
                raw_config["default_kms_key"] = default_kms_key
                raw_config["encryption_type"] = (
                    "customer_managed" if default_kms_key else "google_managed"
                )

                # Get lifecycle rules
                lifecycle_rules = []
                if bucket.lifecycle_rules:
                    for rule in bucket.lifecycle_rules:
                        lifecycle_rules.append({
                            "action": rule.get("action", {}),
                            "condition": rule.get("condition", {}),
                        })
                raw_config["lifecycle_rules"] = lifecycle_rules
                raw_config["has_lifecycle_rules"] = len(lifecycle_rules) > 0

                # Get logging configuration
                logging_config = None
                if bucket.logging:
                    logging_config = {
                        "log_bucket": bucket.logging.get("logBucket"),
                        "log_object_prefix": bucket.logging.get("logObjectPrefix"),
                    }
                raw_config["logging"] = logging_config
                raw_config["logging_enabled"] = logging_config is not None

                # Get CORS configuration
                cors_config = []
                if bucket.cors:
                    for cors in bucket.cors:
                        cors_config.append({
                            "origin": cors.get("origin", []),
                            "method": cors.get("method", []),
                            "response_header": cors.get("responseHeader", []),
                            "max_age_seconds": cors.get("maxAgeSeconds"),
                        })
                raw_config["cors"] = cors_config

                # Get retention policy
                retention_policy = None
                if bucket.retention_policy_effective_time:
                    retention_policy = {
                        "retention_period": bucket.retention_period,
                        "effective_time": (
                            bucket.retention_policy_effective_time.isoformat()
                        ),
                        "is_locked": bucket.retention_policy_locked,
                    }
                raw_config["retention_policy"] = retention_policy

                # Check IAM policy for public access
                is_public = False
                iam_bindings = []
                try:
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        members = list(binding.get("members", []))
                        role = binding.get("role", "")
                        iam_bindings.append({
                            "role": role,
                            "members": members,
                        })
                        # Check for public access
                        if "allUsers" in members or "allAuthenticatedUsers" in members:
                            is_public = True
                except Exception as e:
                    logger.debug(f"Could not get IAM policy for {bucket_name}: {e}")

                raw_config["iam_bindings"] = iam_bindings
                raw_config["is_public"] = is_public

                # Legacy ACL check (if uniform access not enabled)
                acl_public = False
                if not uniform_access:
                    try:
                        for entry in bucket.acl:
                            entity = entry.get("entity", "")
                            if entity in ("allUsers", "allAuthenticatedUsers"):
                                acl_public = True
                                break
                    except Exception as e:
                        logger.debug(f"Could not get ACL for {bucket_name}: {e}")

                raw_config["acl_is_public"] = acl_public

                # Determine network exposure
                network_exposure = NETWORK_EXPOSURE_INTERNAL
                if is_public or acl_public:
                    network_exposure = NETWORK_EXPOSURE_INTERNET

                # Also consider public access prevention setting
                if public_access_prevention == "enforced":
                    network_exposure = NETWORK_EXPOSURE_INTERNAL
                    is_public = False
                    raw_config["is_public"] = False

                # Summary flags
                raw_config["has_public_access"] = is_public or acl_public
                raw_config["public_access_blocked"] = (
                    public_access_prevention == "enforced"
                )

                created_at = None
                if bucket.time_created:
                    created_at = bucket.time_created.replace(tzinfo=timezone.utc)

                assets.append(
                    Asset(
                        id=bucket_id,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region=bucket.location.lower() if bucket.location else "global",
                        resource_type="gcp_storage_bucket",
                        name=bucket_name,
                        tags=labels,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        except Exception as e:
            logger.error(f"Error listing storage buckets: {e}")
            raise

        return assets
