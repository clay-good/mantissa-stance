"""
Azure Blob Storage Cost Analyzer for DSPM.

Analyzes Azure Blob Storage container costs and identifies cold data
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

# Import Azure libraries optionally
try:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient, ContainerClient
    from azure.core.exceptions import (
        AzureError,
        ResourceNotFoundError,
        ClientAuthenticationError,
    )

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    DefaultAzureCredential = None  # type: ignore
    BlobServiceClient = None  # type: ignore
    ContainerClient = None  # type: ignore
    AzureError = Exception  # type: ignore
    ResourceNotFoundError = Exception  # type: ignore
    ClientAuthenticationError = Exception  # type: ignore


# Azure access tier to storage tier mapping
AZURE_ACCESS_TIER_MAP = {
    "Hot": StorageTier.AZURE_HOT,
    "Cool": StorageTier.AZURE_COOL,
    "Cold": StorageTier.AZURE_COLD,
    "Archive": StorageTier.AZURE_ARCHIVE,
}


class AzureCostAnalyzer(BaseCostAnalyzer):
    """
    Azure Blob Storage cost analyzer.

    Analyzes Azure Blob containers to identify cold data and estimate storage costs.
    Uses blob metadata and last access time (if available) for analysis.

    All operations are read-only.
    """

    cloud_provider = "azure"

    def __init__(
        self,
        config: CostAnalysisConfig | None = None,
        connection_string: str | None = None,
        account_url: str | None = None,
        credential: Any | None = None,
    ):
        """
        Initialize Azure cost analyzer.

        Args:
            config: Optional cost analysis configuration
            connection_string: Azure Storage connection string
            account_url: Storage account URL (https://<account>.blob.core.windows.net)
            credential: Optional credential object
        """
        super().__init__(config)

        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob is required for Azure cost analysis. "
                "Install with: pip install azure-storage-blob azure-identity"
            )

        if connection_string:
            self._blob_service_client = BlobServiceClient.from_connection_string(
                connection_string
            )
        elif account_url:
            self._credential = credential or DefaultAzureCredential()
            self._blob_service_client = BlobServiceClient(
                account_url=account_url,
                credential=self._credential,
            )
        else:
            raise ValueError(
                "Either connection_string or account_url must be provided"
            )

    def analyze_bucket(self, bucket_name: str) -> CostAnalysisResult:
        """
        Analyze an Azure Blob container for cost optimization opportunities.

        Args:
            bucket_name: Name of the container (with or without azure:// prefix)

        Returns:
            Cost analysis result with findings and metrics
        """
        # Handle azure:// prefix
        container_name = bucket_name
        if container_name.startswith("azure://"):
            container_name = container_name[8:].split("/")[0]

        analysis_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting Azure Blob cost analysis: container={container_name}, id={analysis_id}"
        )

        result = CostAnalysisResult(
            analysis_id=analysis_id,
            bucket_name=container_name,
            config=self._config,
            started_at=started_at,
        )

        try:
            # Get storage metrics
            metrics = self.get_storage_metrics(container_name)
            result.metrics = metrics
            result.total_size_bytes = metrics.total_size_bytes
            result.total_monthly_cost = metrics.monthly_cost_estimate

            # Get objects with access info
            objects: list[ObjectAccessInfo] = []
            for obj_info in self.list_objects_with_access_info(container_name):
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
            result.findings = self._generate_findings(
                container_name, objects, current_tier
            )

            # Calculate potential savings
            for finding in result.findings:
                result.potential_monthly_savings += finding.potential_savings_monthly

        except AzureError as e:
            error_msg = f"Azure error: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"Azure Blob cost analysis complete: {result.objects_analyzed} objects, "
            f"{len(result.findings)} findings, "
            f"${float(result.potential_monthly_savings):.2f}/month savings"
        )

        return result

    def get_storage_metrics(self, bucket_name: str) -> StorageMetrics:
        """
        Get storage metrics for an Azure Blob container.

        Args:
            bucket_name: Name of the container

        Returns:
            Storage metrics including size, object count, costs
        """
        container_name = bucket_name
        if container_name.startswith("azure://"):
            container_name = container_name[8:].split("/")[0]

        metrics = StorageMetrics(bucket_name=container_name)

        try:
            container_client = self._blob_service_client.get_container_client(
                container_name
            )
            blobs = container_client.list_blobs()

            size_by_tier: dict[str, int] = {}
            object_count = 0

            for blob in blobs:
                size = blob.size or 0
                access_tier = blob.blob_tier or "Hot"

                metrics.total_size_bytes += size
                object_count += 1

                size_by_tier[access_tier] = size_by_tier.get(access_tier, 0) + size

            metrics.total_objects = object_count
            metrics.size_by_tier = size_by_tier

            # Determine predominant storage tier
            if size_by_tier:
                predominant_tier = max(size_by_tier, key=size_by_tier.get)
                metrics.storage_tier = AZURE_ACCESS_TIER_MAP.get(
                    predominant_tier, StorageTier.AZURE_HOT
                )
            else:
                metrics.storage_tier = StorageTier.AZURE_HOT

            # Calculate cost estimate
            total_cost = Decimal("0")
            for access_tier, size in size_by_tier.items():
                tier = AZURE_ACCESS_TIER_MAP.get(access_tier, StorageTier.AZURE_HOT)
                total_cost += self._calculate_cost(size, tier)

            metrics.monthly_cost_estimate = total_cost

        except ResourceNotFoundError:
            logger.warning(f"Container not found: {container_name}")
        except ClientAuthenticationError:
            logger.warning(f"Access denied to container: {container_name}")
        except AzureError as e:
            logger.warning(f"Error getting container metrics: {e}")

        return metrics

    def get_object_access_info(
        self,
        bucket_name: str,
        object_key: str,
    ) -> ObjectAccessInfo | None:
        """
        Get access information for a specific Azure blob.

        Azure Blob Storage can track last access time if enabled on the account.
        Otherwise, we use last modified time as a proxy.

        Args:
            bucket_name: Name of the container
            object_key: Blob name

        Returns:
            Object access information or None if not found
        """
        container_name = bucket_name
        if container_name.startswith("azure://"):
            container_name = container_name[8:].split("/")[0]

        try:
            container_client = self._blob_service_client.get_container_client(
                container_name
            )
            blob_client = container_client.get_blob_client(object_key)
            properties = blob_client.get_blob_properties()

            now = datetime.now(timezone.utc)
            last_modified = properties.last_modified
            last_accessed = properties.last_accessed_on  # May be None if not enabled

            days_since_modified = None
            days_since_access = None

            if last_modified:
                if last_modified.tzinfo is None:
                    last_modified = last_modified.replace(tzinfo=timezone.utc)
                delta = now - last_modified
                days_since_modified = delta.days

            if last_accessed:
                if last_accessed.tzinfo is None:
                    last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                delta = now - last_accessed
                days_since_access = delta.days
            else:
                # Fall back to last modified if access tracking not enabled
                days_since_access = days_since_modified

            return ObjectAccessInfo(
                object_key=object_key,
                size_bytes=properties.size or 0,
                storage_class=properties.blob_tier or "Hot",
                last_modified=last_modified,
                last_accessed=last_accessed,
                days_since_access=days_since_access,
                days_since_modified=days_since_modified,
            )

        except ResourceNotFoundError:
            return None
        except AzureError as e:
            logger.warning(f"Error getting blob info for {object_key}: {e}")
            return None

    def list_objects_with_access_info(
        self,
        bucket_name: str,
        prefix: str = "",
    ) -> Iterator[ObjectAccessInfo]:
        """
        List blobs with access information.

        Args:
            bucket_name: Name of the container
            prefix: Optional prefix filter

        Yields:
            Object access information for each blob
        """
        container_name = bucket_name
        if container_name.startswith("azure://"):
            container_name = container_name[8:].split("/")[0]

        now = datetime.now(timezone.utc)

        try:
            container_client = self._blob_service_client.get_container_client(
                container_name
            )

            if prefix:
                blobs = container_client.list_blobs(name_starts_with=prefix)
            else:
                blobs = container_client.list_blobs()

            for blob in blobs:
                size_bytes = blob.size or 0
                access_tier = blob.blob_tier or "Hot"
                last_modified = blob.last_modified
                last_accessed = getattr(blob, "last_accessed_on", None)

                # Skip objects smaller than minimum size
                if size_bytes < self._config.min_object_size_bytes:
                    continue

                days_since_modified = None
                days_since_access = None

                if last_modified:
                    if last_modified.tzinfo is None:
                        last_modified = last_modified.replace(tzinfo=timezone.utc)
                    delta = now - last_modified
                    days_since_modified = delta.days

                if last_accessed:
                    if last_accessed.tzinfo is None:
                        last_accessed = last_accessed.replace(tzinfo=timezone.utc)
                    delta = now - last_accessed
                    days_since_access = delta.days
                else:
                    days_since_access = days_since_modified

                yield ObjectAccessInfo(
                    object_key=blob.name,
                    size_bytes=size_bytes,
                    storage_class=access_tier,
                    last_modified=last_modified,
                    last_accessed=last_accessed,
                    days_since_access=days_since_access,
                    days_since_modified=days_since_modified,
                )

        except ResourceNotFoundError:
            logger.warning(f"Container not found: {container_name}")
        except ClientAuthenticationError:
            logger.warning(f"Access denied to container: {container_name}")
        except AzureError as e:
            logger.warning(f"Error listing blobs: {e}")

    def get_lifecycle_management_policy(
        self, container_name: str
    ) -> dict[str, Any] | None:
        """
        Get lifecycle management policy for the storage account.

        Note: Lifecycle policies are set at the storage account level in Azure,
        not per container.

        Args:
            container_name: Name of the container (unused, kept for API consistency)

        Returns:
            Lifecycle management policy or None
        """
        try:
            # Lifecycle management is at account level
            # Would need azure-mgmt-storage to get this
            logger.info(
                "Lifecycle management policy retrieval requires azure-mgmt-storage"
            )
            return None
        except Exception as e:
            logger.warning(f"Error getting lifecycle policy: {e}")
            return None

    def list_containers(self) -> Iterator[str]:
        """
        List all containers in the storage account.

        Yields:
            Container names
        """
        try:
            for container in self._blob_service_client.list_containers():
                yield container.name
        except AzureError as e:
            logger.warning(f"Error listing containers: {e}")

    def get_account_info(self) -> dict[str, Any]:
        """
        Get storage account information.

        Returns:
            Account information dictionary
        """
        try:
            account_info = self._blob_service_client.get_account_information()
            return {
                "sku_name": account_info.get("sku_name"),
                "account_kind": account_info.get("account_kind"),
            }
        except AzureError as e:
            logger.warning(f"Error getting account info: {e}")
            return {}
