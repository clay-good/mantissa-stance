"""
GCS Cost Analyzer for DSPM.

Analyzes Google Cloud Storage bucket costs and identifies cold data
that can be archived or deleted to save costs.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from typing import Any, Iterator

from stance.dspm.cost.base import (
    BaseCostAnalyzer,
    CostAnalysisConfig,
    StorageMetrics,
    ObjectAccessInfo,
    ColdDataFinding,
    CostAnalysisResult,
    StorageTier,
    STORAGE_COSTS_PER_GB_MONTH,
)

logger = logging.getLogger(__name__)

# Import GCP libraries optionally
try:
    from google.cloud import storage
    from google.api_core.exceptions import GoogleAPIError, NotFound, Forbidden

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    storage = None  # type: ignore
    GoogleAPIError = Exception  # type: ignore
    NotFound = Exception  # type: ignore
    Forbidden = Exception  # type: ignore


# GCS storage class to tier mapping
GCS_STORAGE_CLASS_MAP = {
    "STANDARD": StorageTier.GCS_STANDARD,
    "NEARLINE": StorageTier.GCS_NEARLINE,
    "COLDLINE": StorageTier.GCS_COLDLINE,
    "ARCHIVE": StorageTier.GCS_ARCHIVE,
    "MULTI_REGIONAL": StorageTier.GCS_STANDARD,
    "REGIONAL": StorageTier.GCS_STANDARD,
    "DURABLE_REDUCED_AVAILABILITY": StorageTier.GCS_STANDARD,
}


class GCSCostAnalyzer(BaseCostAnalyzer):
    """
    Google Cloud Storage cost analyzer.

    Analyzes GCS buckets to identify cold data and estimate storage costs.
    Uses GCS object metadata and optionally Cloud Monitoring for access patterns.

    All operations are read-only.
    """

    cloud_provider = "gcp"

    def __init__(
        self,
        config: CostAnalysisConfig | None = None,
        project: str | None = None,
        credentials: Any | None = None,
    ):
        """
        Initialize GCS cost analyzer.

        Args:
            config: Optional cost analysis configuration
            project: GCP project ID
            credentials: Optional credentials object
        """
        super().__init__(config)

        if not GCP_AVAILABLE:
            raise ImportError(
                "google-cloud-storage is required for GCS cost analysis. "
                "Install with: pip install google-cloud-storage"
            )

        self._project = project
        self._credentials = credentials
        self._storage_client = storage.Client(
            project=project, credentials=credentials
        )

    def analyze_bucket(self, bucket_name: str) -> CostAnalysisResult:
        """
        Analyze a GCS bucket for cost optimization opportunities.

        Args:
            bucket_name: Name of the GCS bucket (with or without gs:// prefix)

        Returns:
            Cost analysis result with findings and metrics
        """
        # Handle gs:// prefix
        if bucket_name.startswith("gs://"):
            bucket_name = bucket_name[5:].split("/")[0]

        analysis_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(f"Starting GCS cost analysis: bucket={bucket_name}, id={analysis_id}")

        result = CostAnalysisResult(
            analysis_id=analysis_id,
            bucket_name=bucket_name,
            config=self._config,
            started_at=started_at,
        )

        try:
            # Get storage metrics
            metrics = self.get_storage_metrics(bucket_name)
            result.metrics = metrics
            result.total_size_bytes = metrics.total_size_bytes
            result.total_monthly_cost = metrics.monthly_cost_estimate

            # Get objects with access info
            objects: list[ObjectAccessInfo] = []
            for obj_info in self.list_objects_with_access_info(bucket_name):
                objects.append(obj_info)
                result.objects_analyzed += 1

                if (
                    self._config.sample_size
                    and result.objects_analyzed >= self._config.sample_size
                ):
                    break

            # Calculate cold data size
            for obj in objects:
                days = obj.days_since_access or obj.days_since_modified or 0
                if days >= self._config.cold_data_days:
                    result.cold_data_size_bytes += obj.size_bytes

            # Generate findings
            current_tier = metrics.storage_tier
            result.findings = self._generate_findings(bucket_name, objects, current_tier)

            # Calculate potential savings
            for finding in result.findings:
                result.potential_monthly_savings += finding.potential_savings_monthly

        except GoogleAPIError as e:
            error_msg = f"GCS error: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"GCS cost analysis complete: {result.objects_analyzed} objects, "
            f"{len(result.findings)} findings, "
            f"${float(result.potential_monthly_savings):.2f}/month savings"
        )

        return result

    def get_storage_metrics(self, bucket_name: str) -> StorageMetrics:
        """
        Get storage metrics for a GCS bucket.

        Args:
            bucket_name: Name of the GCS bucket

        Returns:
            Storage metrics including size, object count, costs
        """
        metrics = StorageMetrics(bucket_name=bucket_name)

        try:
            bucket = self._storage_client.bucket(bucket_name)
            blobs = bucket.list_blobs()

            size_by_class: dict[str, int] = {}
            object_count = 0

            for blob in blobs:
                size = blob.size or 0
                storage_class = blob.storage_class or "STANDARD"

                metrics.total_size_bytes += size
                object_count += 1

                size_by_class[storage_class] = (
                    size_by_class.get(storage_class, 0) + size
                )

            metrics.total_objects = object_count
            metrics.size_by_tier = size_by_class

            # Determine predominant storage tier
            if size_by_class:
                predominant_class = max(size_by_class, key=size_by_class.get)
                metrics.storage_tier = GCS_STORAGE_CLASS_MAP.get(
                    predominant_class, StorageTier.GCS_STANDARD
                )
            else:
                # Get bucket default storage class
                bucket_obj = self._storage_client.get_bucket(bucket_name)
                default_class = bucket_obj.storage_class or "STANDARD"
                metrics.storage_tier = GCS_STORAGE_CLASS_MAP.get(
                    default_class, StorageTier.GCS_STANDARD
                )

            # Calculate cost estimate
            total_cost = Decimal("0")
            for storage_class, size in size_by_class.items():
                tier = GCS_STORAGE_CLASS_MAP.get(storage_class, StorageTier.GCS_STANDARD)
                total_cost += self._calculate_cost(size, tier)

            metrics.monthly_cost_estimate = total_cost

        except NotFound:
            logger.warning(f"Bucket not found: {bucket_name}")
        except Forbidden:
            logger.warning(f"Access denied to bucket: {bucket_name}")
        except GoogleAPIError as e:
            logger.warning(f"Error getting bucket metrics: {e}")

        return metrics

    def get_object_access_info(
        self,
        bucket_name: str,
        object_key: str,
    ) -> ObjectAccessInfo | None:
        """
        Get access information for a specific GCS object.

        Note: GCS doesn't provide last access time directly.
        We use time_created and updated timestamps as proxies.

        Args:
            bucket_name: Name of the GCS bucket
            object_key: Object key/blob name

        Returns:
            Object access information or None if not found
        """
        try:
            bucket = self._storage_client.bucket(bucket_name)
            blob = bucket.get_blob(object_key)

            if blob is None:
                return None

            now = datetime.now(timezone.utc)
            last_modified = blob.updated or blob.time_created

            days_since_modified = None
            if last_modified:
                # Ensure timezone-aware
                if last_modified.tzinfo is None:
                    last_modified = last_modified.replace(tzinfo=timezone.utc)
                delta = now - last_modified
                days_since_modified = delta.days

            return ObjectAccessInfo(
                object_key=object_key,
                size_bytes=blob.size or 0,
                storage_class=blob.storage_class or "STANDARD",
                last_modified=last_modified,
                last_accessed=None,  # GCS doesn't track this directly
                days_since_access=days_since_modified,
                days_since_modified=days_since_modified,
            )

        except NotFound:
            return None
        except GoogleAPIError as e:
            logger.warning(f"Error getting object info for {object_key}: {e}")
            return None

    def list_objects_with_access_info(
        self,
        bucket_name: str,
        prefix: str = "",
    ) -> Iterator[ObjectAccessInfo]:
        """
        List objects with access information.

        Args:
            bucket_name: Name of the GCS bucket
            prefix: Optional prefix filter

        Yields:
            Object access information for each object
        """
        now = datetime.now(timezone.utc)

        try:
            bucket = self._storage_client.bucket(bucket_name)
            blobs = bucket.list_blobs(prefix=prefix) if prefix else bucket.list_blobs()

            for blob in blobs:
                size_bytes = blob.size or 0
                storage_class = blob.storage_class or "STANDARD"
                last_modified = blob.updated or blob.time_created

                # Skip objects smaller than minimum size
                if size_bytes < self._config.min_object_size_bytes:
                    continue

                days_since_modified = None
                if last_modified:
                    # Ensure timezone-aware
                    if last_modified.tzinfo is None:
                        last_modified = last_modified.replace(tzinfo=timezone.utc)
                    delta = now - last_modified
                    days_since_modified = delta.days

                yield ObjectAccessInfo(
                    object_key=blob.name,
                    size_bytes=size_bytes,
                    storage_class=storage_class,
                    last_modified=last_modified,
                    last_accessed=None,
                    days_since_access=days_since_modified,
                    days_since_modified=days_since_modified,
                )

        except NotFound:
            logger.warning(f"Bucket not found: {bucket_name}")
        except Forbidden:
            logger.warning(f"Access denied to bucket: {bucket_name}")
        except GoogleAPIError as e:
            logger.warning(f"Error listing objects: {e}")

    def get_bucket_lifecycle_rules(
        self, bucket_name: str
    ) -> list[dict[str, Any]]:
        """
        Get lifecycle rules for a bucket.

        Args:
            bucket_name: Name of the GCS bucket

        Returns:
            List of lifecycle rules
        """
        try:
            bucket = self._storage_client.get_bucket(bucket_name)
            rules = bucket.lifecycle_rules or []
            return [dict(rule) for rule in rules]
        except NotFound:
            return []
        except GoogleAPIError as e:
            logger.warning(f"Error getting lifecycle rules: {e}")
            return []

    def get_bucket_location(self, bucket_name: str) -> str:
        """
        Get the location where a bucket is stored.

        Args:
            bucket_name: Name of the GCS bucket

        Returns:
            Location/region string
        """
        try:
            bucket = self._storage_client.get_bucket(bucket_name)
            return bucket.location or "US"
        except GoogleAPIError:
            return "UNKNOWN"

    def list_buckets(self) -> Iterator[str]:
        """
        List all GCS buckets in the project.

        Yields:
            Bucket names
        """
        try:
            for bucket in self._storage_client.list_buckets():
                yield bucket.name
        except GoogleAPIError as e:
            logger.warning(f"Error listing buckets: {e}")
