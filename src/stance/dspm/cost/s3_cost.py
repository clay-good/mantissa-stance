"""
AWS S3 Cost Analyzer for DSPM.

Analyzes S3 bucket storage costs and identifies cold data
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

# Import boto3 optionally
try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore


# S3 storage class to tier mapping
S3_STORAGE_CLASS_MAP = {
    "STANDARD": StorageTier.S3_STANDARD,
    "INTELLIGENT_TIERING": StorageTier.S3_INTELLIGENT_TIERING,
    "STANDARD_IA": StorageTier.S3_STANDARD_IA,
    "ONEZONE_IA": StorageTier.S3_ONE_ZONE_IA,
    "GLACIER": StorageTier.S3_GLACIER_FLEXIBLE,
    "GLACIER_IR": StorageTier.S3_GLACIER_INSTANT,
    "DEEP_ARCHIVE": StorageTier.S3_GLACIER_DEEP_ARCHIVE,
    "REDUCED_REDUNDANCY": StorageTier.S3_STANDARD,  # Deprecated but still exists
    "OUTPOSTS": StorageTier.S3_STANDARD,
    "EXPRESS_ONEZONE": StorageTier.S3_STANDARD,
}


class S3CostAnalyzer(BaseCostAnalyzer):
    """
    AWS S3 storage cost analyzer.

    Analyzes S3 buckets to identify cold data and estimate storage costs.
    Uses S3 object metadata and optionally S3 Storage Lens or CloudWatch
    for access patterns.

    All operations are read-only.
    """

    cloud_provider = "aws"

    def __init__(
        self,
        config: CostAnalysisConfig | None = None,
        session: Any | None = None,
        region: str = "us-east-1",
    ):
        """
        Initialize S3 cost analyzer.

        Args:
            config: Optional cost analysis configuration
            session: Optional boto3 Session
            region: AWS region
        """
        super().__init__(config)

        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 is required for S3 cost analysis. Install with: pip install boto3"
            )

        self._session = session or boto3.Session()
        self._region = region
        self._s3_client = self._session.client("s3", region_name=region)

        # CloudWatch client for access metrics (optional)
        try:
            self._cloudwatch_client = self._session.client(
                "cloudwatch", region_name=region
            )
        except Exception:
            self._cloudwatch_client = None

    def analyze_bucket(self, bucket_name: str) -> CostAnalysisResult:
        """
        Analyze an S3 bucket for cost optimization opportunities.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Cost analysis result with findings and metrics
        """
        # Handle s3:// prefix
        if bucket_name.startswith("s3://"):
            bucket_name = bucket_name[5:].split("/")[0]

        analysis_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(f"Starting S3 cost analysis: bucket={bucket_name}, id={analysis_id}")

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

        except ClientError as e:
            error_msg = f"S3 error: {e.response.get('Error', {}).get('Message', str(e))}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"S3 cost analysis complete: {result.objects_analyzed} objects, "
            f"{len(result.findings)} findings, "
            f"${float(result.potential_monthly_savings):.2f}/month savings"
        )

        return result

    def get_storage_metrics(self, bucket_name: str) -> StorageMetrics:
        """
        Get storage metrics for an S3 bucket.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Storage metrics including size, object count, costs
        """
        metrics = StorageMetrics(bucket_name=bucket_name)

        try:
            # Get total size and object count by iterating objects
            paginator = self._s3_client.get_paginator("list_objects_v2")
            size_by_class: dict[str, int] = {}
            object_count = 0

            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get("Contents", []):
                    size = obj.get("Size", 0)
                    storage_class = obj.get("StorageClass", "STANDARD")

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
                metrics.storage_tier = S3_STORAGE_CLASS_MAP.get(
                    predominant_class, StorageTier.S3_STANDARD
                )
            else:
                metrics.storage_tier = StorageTier.S3_STANDARD

            # Calculate cost estimate
            total_cost = Decimal("0")
            for storage_class, size in size_by_class.items():
                tier = S3_STORAGE_CLASS_MAP.get(storage_class, StorageTier.S3_STANDARD)
                total_cost += self._calculate_cost(size, tier)

            metrics.monthly_cost_estimate = total_cost

        except ClientError as e:
            logger.warning(f"Error getting bucket metrics: {e}")

        return metrics

    def get_object_access_info(
        self,
        bucket_name: str,
        object_key: str,
    ) -> ObjectAccessInfo | None:
        """
        Get access information for a specific S3 object.

        Note: S3 doesn't provide last access time directly.
        We use last modified time as a proxy and optionally
        query CloudWatch for request metrics.

        Args:
            bucket_name: Name of the S3 bucket
            object_key: Object key

        Returns:
            Object access information or None if not found
        """
        try:
            response = self._s3_client.head_object(Bucket=bucket_name, Key=object_key)

            last_modified = response.get("LastModified")
            now = datetime.now(timezone.utc)

            days_since_modified = None
            if last_modified:
                # Ensure last_modified is timezone-aware
                if last_modified.tzinfo is None:
                    last_modified = last_modified.replace(tzinfo=timezone.utc)
                delta = now - last_modified
                days_since_modified = delta.days

            return ObjectAccessInfo(
                object_key=object_key,
                size_bytes=response.get("ContentLength", 0),
                storage_class=response.get("StorageClass", "STANDARD"),
                last_modified=last_modified,
                last_accessed=None,  # S3 doesn't track this directly
                days_since_access=days_since_modified,  # Use last modified as proxy
                days_since_modified=days_since_modified,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404" or error_code == "NoSuchKey":
                return None
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
            bucket_name: Name of the S3 bucket
            prefix: Optional prefix filter

        Yields:
            Object access information for each object
        """
        now = datetime.now(timezone.utc)
        paginator = self._s3_client.get_paginator("list_objects_v2")
        page_config: dict[str, Any] = {"Bucket": bucket_name}

        if prefix:
            page_config["Prefix"] = prefix

        for page in paginator.paginate(**page_config):
            for obj in page.get("Contents", []):
                object_key = obj.get("Key", "")
                size_bytes = obj.get("Size", 0)
                storage_class = obj.get("StorageClass", "STANDARD")
                last_modified = obj.get("LastModified")

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
                    object_key=object_key,
                    size_bytes=size_bytes,
                    storage_class=storage_class,
                    last_modified=last_modified,
                    last_accessed=None,
                    days_since_access=days_since_modified,
                    days_since_modified=days_since_modified,
                )

    def get_bucket_lifecycle_rules(
        self, bucket_name: str
    ) -> list[dict[str, Any]]:
        """
        Get lifecycle rules for a bucket.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            List of lifecycle rules
        """
        try:
            response = self._s3_client.get_bucket_lifecycle_configuration(
                Bucket=bucket_name
            )
            return response.get("Rules", [])
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchLifecycleConfiguration":
                return []
            logger.warning(f"Error getting lifecycle rules: {e}")
            return []

    def get_intelligent_tiering_config(
        self, bucket_name: str
    ) -> dict[str, Any] | None:
        """
        Get Intelligent-Tiering configuration for a bucket.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Intelligent-Tiering configuration or None
        """
        try:
            response = self._s3_client.list_bucket_intelligent_tiering_configurations(
                Bucket=bucket_name
            )
            configs = response.get("IntelligentTieringConfigurationList", [])
            return configs[0] if configs else None
        except ClientError:
            return None

    def list_buckets(self) -> Iterator[str]:
        """
        List all S3 buckets in the account.

        Yields:
            Bucket names
        """
        try:
            response = self._s3_client.list_buckets()
            for bucket in response.get("Buckets", []):
                yield bucket.get("Name", "")
        except ClientError as e:
            logger.warning(f"Error listing buckets: {e}")
