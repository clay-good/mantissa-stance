"""
Base classes for DSPM cost analysis.

Provides abstract base class and common data models for analyzing
cloud storage costs and identifying cold/unused data.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class FindingType(Enum):
    """Types of cost analysis findings."""

    COLD_DATA = "cold_data"
    ARCHIVE_CANDIDATE = "archive_candidate"
    DELETE_CANDIDATE = "delete_candidate"
    INEFFICIENT_STORAGE_CLASS = "inefficient_storage_class"
    LARGE_OBJECT = "large_object"


class StorageTier(Enum):
    """Cloud storage tiers for cost estimation."""

    # AWS S3 tiers
    S3_STANDARD = "s3_standard"
    S3_INTELLIGENT_TIERING = "s3_intelligent_tiering"
    S3_STANDARD_IA = "s3_standard_ia"
    S3_ONE_ZONE_IA = "s3_one_zone_ia"
    S3_GLACIER_INSTANT = "s3_glacier_instant"
    S3_GLACIER_FLEXIBLE = "s3_glacier_flexible"
    S3_GLACIER_DEEP_ARCHIVE = "s3_glacier_deep_archive"

    # GCS tiers
    GCS_STANDARD = "gcs_standard"
    GCS_NEARLINE = "gcs_nearline"
    GCS_COLDLINE = "gcs_coldline"
    GCS_ARCHIVE = "gcs_archive"

    # Azure Blob tiers
    AZURE_HOT = "azure_hot"
    AZURE_COOL = "azure_cool"
    AZURE_COLD = "azure_cold"
    AZURE_ARCHIVE = "azure_archive"

    # Generic
    UNKNOWN = "unknown"


# Approximate storage costs per GB per month (USD)
# These are rough estimates and vary by region
STORAGE_COSTS_PER_GB_MONTH: dict[StorageTier, Decimal] = {
    # AWS S3 (us-east-1 approximation)
    StorageTier.S3_STANDARD: Decimal("0.023"),
    StorageTier.S3_INTELLIGENT_TIERING: Decimal("0.023"),
    StorageTier.S3_STANDARD_IA: Decimal("0.0125"),
    StorageTier.S3_ONE_ZONE_IA: Decimal("0.01"),
    StorageTier.S3_GLACIER_INSTANT: Decimal("0.004"),
    StorageTier.S3_GLACIER_FLEXIBLE: Decimal("0.0036"),
    StorageTier.S3_GLACIER_DEEP_ARCHIVE: Decimal("0.00099"),
    # GCS (us approximation)
    StorageTier.GCS_STANDARD: Decimal("0.020"),
    StorageTier.GCS_NEARLINE: Decimal("0.010"),
    StorageTier.GCS_COLDLINE: Decimal("0.004"),
    StorageTier.GCS_ARCHIVE: Decimal("0.0012"),
    # Azure Blob (East US approximation)
    StorageTier.AZURE_HOT: Decimal("0.0184"),
    StorageTier.AZURE_COOL: Decimal("0.01"),
    StorageTier.AZURE_COLD: Decimal("0.0036"),
    StorageTier.AZURE_ARCHIVE: Decimal("0.00099"),
    # Default
    StorageTier.UNKNOWN: Decimal("0.023"),
}


@dataclass
class CostAnalysisConfig:
    """
    Configuration for cost analysis.

    Attributes:
        cold_data_days: Days without access to consider cold (default: 90)
        archive_candidate_days: Days without access to suggest archiving (default: 180)
        delete_candidate_days: Days without access to suggest deletion (default: 365)
        min_object_size_bytes: Minimum object size to analyze (skip small files)
        include_storage_class_analysis: Whether to suggest storage class changes
        cost_currency: Currency for cost estimates (default: USD)
        sample_size: Max objects to analyze per bucket (None for all)
    """

    cold_data_days: int = 90
    archive_candidate_days: int = 180
    delete_candidate_days: int = 365
    min_object_size_bytes: int = 1024  # 1KB minimum
    include_storage_class_analysis: bool = True
    cost_currency: str = "USD"
    sample_size: int | None = None


@dataclass
class StorageMetrics:
    """
    Storage metrics for a bucket/container.

    Attributes:
        bucket_name: Name of the bucket/container
        total_size_bytes: Total size in bytes
        total_objects: Total number of objects
        storage_tier: Current storage tier
        monthly_cost_estimate: Estimated monthly cost
        size_by_tier: Size breakdown by storage tier
    """

    bucket_name: str
    total_size_bytes: int = 0
    total_objects: int = 0
    storage_tier: StorageTier = StorageTier.UNKNOWN
    monthly_cost_estimate: Decimal = Decimal("0")
    size_by_tier: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "bucket_name": self.bucket_name,
            "total_size_bytes": self.total_size_bytes,
            "total_size_gb": round(self.total_size_bytes / (1024**3), 3),
            "total_objects": self.total_objects,
            "storage_tier": self.storage_tier.value,
            "monthly_cost_estimate": float(self.monthly_cost_estimate),
            "size_by_tier": self.size_by_tier,
        }


@dataclass
class ObjectAccessInfo:
    """
    Access information for a storage object.

    Attributes:
        object_key: Object key/path
        size_bytes: Object size in bytes
        storage_class: Current storage class
        last_modified: Last modification time
        last_accessed: Last access time (if available)
        days_since_access: Days since last access
        days_since_modified: Days since last modification
    """

    object_key: str
    size_bytes: int
    storage_class: str = "STANDARD"
    last_modified: datetime | None = None
    last_accessed: datetime | None = None
    days_since_access: int | None = None
    days_since_modified: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "object_key": self.object_key,
            "size_bytes": self.size_bytes,
            "size_mb": round(self.size_bytes / (1024**2), 3),
            "storage_class": self.storage_class,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "last_accessed": self.last_accessed.isoformat() if self.last_accessed else None,
            "days_since_access": self.days_since_access,
            "days_since_modified": self.days_since_modified,
        }


@dataclass
class ColdDataFinding:
    """
    A finding from cost analysis.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level (critical, high, medium, low, info)
        title: Short title
        description: Detailed description
        bucket_name: Affected bucket/container
        object_key: Affected object (if applicable)
        size_bytes: Size of affected data
        current_cost_monthly: Current monthly cost
        potential_savings_monthly: Potential monthly savings
        recommended_tier: Recommended storage tier
        recommended_action: Suggested action
        days_since_access: Days since last access
        metadata: Additional context
        detected_at: When finding was generated
    """

    finding_id: str
    finding_type: FindingType
    severity: str
    title: str
    description: str
    bucket_name: str
    object_key: str | None = None
    size_bytes: int = 0
    current_cost_monthly: Decimal = Decimal("0")
    potential_savings_monthly: Decimal = Decimal("0")
    recommended_tier: StorageTier | None = None
    recommended_action: str = ""
    days_since_access: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "bucket_name": self.bucket_name,
            "object_key": self.object_key,
            "size_bytes": self.size_bytes,
            "size_gb": round(self.size_bytes / (1024**3), 3),
            "current_cost_monthly": float(self.current_cost_monthly),
            "potential_savings_monthly": float(self.potential_savings_monthly),
            "recommended_tier": self.recommended_tier.value if self.recommended_tier else None,
            "recommended_action": self.recommended_action,
            "days_since_access": self.days_since_access,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class CostAnalysisResult:
    """
    Result of cost analysis.

    Attributes:
        analysis_id: Unique identifier
        bucket_name: Bucket/container analyzed
        config: Configuration used
        started_at: Analysis start time
        completed_at: Analysis completion time
        metrics: Storage metrics
        findings: List of findings
        total_size_bytes: Total data size analyzed
        cold_data_size_bytes: Size of cold data found
        total_monthly_cost: Total estimated monthly cost
        potential_monthly_savings: Potential monthly savings
        objects_analyzed: Number of objects analyzed
        errors: Errors encountered
    """

    analysis_id: str
    bucket_name: str
    config: CostAnalysisConfig
    started_at: datetime
    completed_at: datetime | None = None
    metrics: StorageMetrics | None = None
    findings: list[ColdDataFinding] = field(default_factory=list)
    total_size_bytes: int = 0
    cold_data_size_bytes: int = 0
    total_monthly_cost: Decimal = Decimal("0")
    potential_monthly_savings: Decimal = Decimal("0")
    objects_analyzed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Check if analysis has any findings."""
        return len(self.findings) > 0

    @property
    def findings_by_type(self) -> dict[str, int]:
        """Get count of findings by type."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            type_val = finding.finding_type.value
            counts[type_val] = counts.get(type_val, 0) + 1
        return counts

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Get count of findings by severity."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def cold_data_percentage(self) -> float:
        """Get percentage of data that is cold."""
        if self.total_size_bytes == 0:
            return 0.0
        return (self.cold_data_size_bytes / self.total_size_bytes) * 100

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "analysis_id": self.analysis_id,
            "bucket_name": self.bucket_name,
            "config": {
                "cold_data_days": self.config.cold_data_days,
                "archive_candidate_days": self.config.archive_candidate_days,
                "delete_candidate_days": self.config.delete_candidate_days,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "metrics": self.metrics.to_dict() if self.metrics else None,
            "findings_count": len(self.findings),
            "findings_by_type": self.findings_by_type,
            "findings_by_severity": self.findings_by_severity,
            "total_size_bytes": self.total_size_bytes,
            "total_size_gb": round(self.total_size_bytes / (1024**3), 3),
            "cold_data_size_bytes": self.cold_data_size_bytes,
            "cold_data_size_gb": round(self.cold_data_size_bytes / (1024**3), 3),
            "cold_data_percentage": round(self.cold_data_percentage, 2),
            "total_monthly_cost": float(self.total_monthly_cost),
            "potential_monthly_savings": float(self.potential_monthly_savings),
            "objects_analyzed": self.objects_analyzed,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


class BaseCostAnalyzer(ABC):
    """
    Abstract base class for cloud storage cost analyzers.

    Subclasses implement cloud-specific logic for retrieving storage
    metrics and access patterns.

    All operations are read-only.
    """

    cloud_provider = "unknown"

    def __init__(self, config: CostAnalysisConfig | None = None):
        """
        Initialize the cost analyzer.

        Args:
            config: Optional configuration for cost analysis
        """
        self._config = config or CostAnalysisConfig()

    @property
    def config(self) -> CostAnalysisConfig:
        """Get the analysis configuration."""
        return self._config

    @abstractmethod
    def analyze_bucket(self, bucket_name: str) -> CostAnalysisResult:
        """
        Analyze a bucket/container for cost optimization opportunities.

        Args:
            bucket_name: Name of the bucket to analyze

        Returns:
            Cost analysis result with findings and metrics
        """
        pass

    @abstractmethod
    def get_storage_metrics(self, bucket_name: str) -> StorageMetrics:
        """
        Get storage metrics for a bucket.

        Args:
            bucket_name: Name of the bucket

        Returns:
            Storage metrics including size, object count, costs
        """
        pass

    @abstractmethod
    def get_object_access_info(
        self,
        bucket_name: str,
        object_key: str,
    ) -> ObjectAccessInfo | None:
        """
        Get access information for a specific object.

        Args:
            bucket_name: Name of the bucket
            object_key: Object key

        Returns:
            Object access information or None if not available
        """
        pass

    @abstractmethod
    def list_objects_with_access_info(
        self,
        bucket_name: str,
        prefix: str = "",
    ) -> Iterator[ObjectAccessInfo]:
        """
        List objects with access information.

        Args:
            bucket_name: Name of the bucket
            prefix: Optional prefix filter

        Yields:
            Object access information for each object
        """
        pass

    def _calculate_cost(
        self,
        size_bytes: int,
        tier: StorageTier,
    ) -> Decimal:
        """
        Calculate monthly storage cost.

        Args:
            size_bytes: Size in bytes
            tier: Storage tier

        Returns:
            Estimated monthly cost in USD
        """
        size_gb = Decimal(size_bytes) / Decimal(1024**3)
        cost_per_gb = STORAGE_COSTS_PER_GB_MONTH.get(tier, Decimal("0.023"))
        return size_gb * cost_per_gb

    def _get_recommended_tier(
        self,
        current_tier: StorageTier,
        days_since_access: int,
    ) -> StorageTier | None:
        """
        Get recommended storage tier based on access patterns.

        Args:
            current_tier: Current storage tier
            days_since_access: Days since last access

        Returns:
            Recommended tier or None if no change suggested
        """
        # Map cloud provider tiers to archive tiers
        tier_recommendations: dict[str, list[tuple[int, StorageTier]]] = {
            "s3": [
                (365, StorageTier.S3_GLACIER_DEEP_ARCHIVE),
                (180, StorageTier.S3_GLACIER_FLEXIBLE),
                (90, StorageTier.S3_STANDARD_IA),
            ],
            "gcs": [
                (365, StorageTier.GCS_ARCHIVE),
                (180, StorageTier.GCS_COLDLINE),
                (90, StorageTier.GCS_NEARLINE),
            ],
            "azure": [
                (365, StorageTier.AZURE_ARCHIVE),
                (180, StorageTier.AZURE_COLD),
                (90, StorageTier.AZURE_COOL),
            ],
        }

        # Determine cloud provider from current tier
        cloud = "s3"
        if current_tier.value.startswith("gcs"):
            cloud = "gcs"
        elif current_tier.value.startswith("azure"):
            cloud = "azure"

        recommendations = tier_recommendations.get(cloud, [])
        for threshold_days, recommended_tier in recommendations:
            if days_since_access >= threshold_days:
                # Only recommend if it's a "colder" tier than current
                if self._tier_rank(recommended_tier) > self._tier_rank(current_tier):
                    return recommended_tier
                break

        return None

    def _tier_rank(self, tier: StorageTier) -> int:
        """Get numeric rank for tier (higher = colder/cheaper)."""
        ranks = {
            # S3
            StorageTier.S3_STANDARD: 0,
            StorageTier.S3_INTELLIGENT_TIERING: 1,
            StorageTier.S3_STANDARD_IA: 2,
            StorageTier.S3_ONE_ZONE_IA: 2,
            StorageTier.S3_GLACIER_INSTANT: 3,
            StorageTier.S3_GLACIER_FLEXIBLE: 4,
            StorageTier.S3_GLACIER_DEEP_ARCHIVE: 5,
            # GCS
            StorageTier.GCS_STANDARD: 0,
            StorageTier.GCS_NEARLINE: 2,
            StorageTier.GCS_COLDLINE: 3,
            StorageTier.GCS_ARCHIVE: 5,
            # Azure
            StorageTier.AZURE_HOT: 0,
            StorageTier.AZURE_COOL: 2,
            StorageTier.AZURE_COLD: 3,
            StorageTier.AZURE_ARCHIVE: 5,
            # Unknown
            StorageTier.UNKNOWN: 0,
        }
        return ranks.get(tier, 0)

    def _get_severity_for_cold_data(
        self,
        days_since_access: int,
        size_bytes: int,
    ) -> str:
        """Determine severity based on age and size of cold data."""
        size_gb = size_bytes / (1024**3)

        # Large and very old data is critical
        if days_since_access >= 365 and size_gb >= 100:
            return "critical"
        if days_since_access >= 365 and size_gb >= 10:
            return "high"
        if days_since_access >= 180 and size_gb >= 10:
            return "high"
        if days_since_access >= 180:
            return "medium"
        if days_since_access >= 90:
            return "low"
        return "info"

    def _generate_findings(
        self,
        bucket_name: str,
        objects: list[ObjectAccessInfo],
        current_tier: StorageTier,
    ) -> list[ColdDataFinding]:
        """
        Generate findings from object access information.

        Args:
            bucket_name: Bucket name
            objects: List of objects with access info
            current_tier: Current storage tier

        Returns:
            List of findings
        """
        findings: list[ColdDataFinding] = []
        finding_counter = 0

        # Aggregate cold data by age brackets
        cold_90_size = 0
        cold_180_size = 0
        cold_365_size = 0
        cold_90_objects: list[ObjectAccessInfo] = []
        cold_180_objects: list[ObjectAccessInfo] = []
        cold_365_objects: list[ObjectAccessInfo] = []

        for obj in objects:
            days = obj.days_since_access or obj.days_since_modified or 0

            if days >= self._config.delete_candidate_days:
                cold_365_size += obj.size_bytes
                cold_365_objects.append(obj)
            elif days >= self._config.archive_candidate_days:
                cold_180_size += obj.size_bytes
                cold_180_objects.append(obj)
            elif days >= self._config.cold_data_days:
                cold_90_size += obj.size_bytes
                cold_90_objects.append(obj)

        # Generate aggregate findings for each bracket

        # Delete candidates (365+ days)
        if cold_365_objects:
            finding_counter += 1
            current_cost = self._calculate_cost(cold_365_size, current_tier)
            savings = current_cost  # Full savings if deleted

            findings.append(
                ColdDataFinding(
                    finding_id=f"{bucket_name}-cost-{finding_counter:04d}",
                    finding_type=FindingType.DELETE_CANDIDATE,
                    severity=self._get_severity_for_cold_data(365, cold_365_size),
                    title=f"Delete candidate: {len(cold_365_objects)} objects not accessed in {self._config.delete_candidate_days}+ days",
                    description=(
                        f"Found {len(cold_365_objects)} objects totaling "
                        f"{cold_365_size / (1024**3):.2f} GB that have not been accessed "
                        f"in {self._config.delete_candidate_days} or more days. "
                        f"Consider deleting if no longer needed."
                    ),
                    bucket_name=bucket_name,
                    size_bytes=cold_365_size,
                    current_cost_monthly=current_cost,
                    potential_savings_monthly=savings,
                    days_since_access=self._config.delete_candidate_days,
                    recommended_action=(
                        f"Review and delete {len(cold_365_objects)} unused objects "
                        f"to save ${float(savings):.2f}/month"
                    ),
                    metadata={
                        "object_count": len(cold_365_objects),
                        "sample_objects": [o.object_key for o in cold_365_objects[:5]],
                    },
                )
            )

        # Archive candidates (180+ days)
        if cold_180_objects:
            finding_counter += 1
            current_cost = self._calculate_cost(cold_180_size, current_tier)
            recommended = self._get_recommended_tier(current_tier, 180)
            archive_cost = (
                self._calculate_cost(cold_180_size, recommended)
                if recommended
                else current_cost
            )
            savings = current_cost - archive_cost

            findings.append(
                ColdDataFinding(
                    finding_id=f"{bucket_name}-cost-{finding_counter:04d}",
                    finding_type=FindingType.ARCHIVE_CANDIDATE,
                    severity=self._get_severity_for_cold_data(180, cold_180_size),
                    title=f"Archive candidate: {len(cold_180_objects)} objects not accessed in {self._config.archive_candidate_days}+ days",
                    description=(
                        f"Found {len(cold_180_objects)} objects totaling "
                        f"{cold_180_size / (1024**3):.2f} GB that have not been accessed "
                        f"in {self._config.archive_candidate_days} or more days. "
                        f"Consider moving to archive storage tier."
                    ),
                    bucket_name=bucket_name,
                    size_bytes=cold_180_size,
                    current_cost_monthly=current_cost,
                    potential_savings_monthly=savings if savings > 0 else Decimal("0"),
                    recommended_tier=recommended,
                    days_since_access=self._config.archive_candidate_days,
                    recommended_action=(
                        f"Move {len(cold_180_objects)} objects to {recommended.value if recommended else 'archive'} "
                        f"to save ${float(savings):.2f}/month"
                        if savings > 0
                        else f"Review {len(cold_180_objects)} objects for archival"
                    ),
                    metadata={
                        "object_count": len(cold_180_objects),
                        "sample_objects": [o.object_key for o in cold_180_objects[:5]],
                    },
                )
            )

        # Cold data (90+ days)
        if cold_90_objects:
            finding_counter += 1
            current_cost = self._calculate_cost(cold_90_size, current_tier)
            recommended = self._get_recommended_tier(current_tier, 90)
            infrequent_cost = (
                self._calculate_cost(cold_90_size, recommended)
                if recommended
                else current_cost
            )
            savings = current_cost - infrequent_cost

            findings.append(
                ColdDataFinding(
                    finding_id=f"{bucket_name}-cost-{finding_counter:04d}",
                    finding_type=FindingType.COLD_DATA,
                    severity=self._get_severity_for_cold_data(90, cold_90_size),
                    title=f"Cold data: {len(cold_90_objects)} objects not accessed in {self._config.cold_data_days}+ days",
                    description=(
                        f"Found {len(cold_90_objects)} objects totaling "
                        f"{cold_90_size / (1024**3):.2f} GB that have not been accessed "
                        f"in {self._config.cold_data_days} or more days. "
                        f"Consider moving to infrequent access storage tier."
                    ),
                    bucket_name=bucket_name,
                    size_bytes=cold_90_size,
                    current_cost_monthly=current_cost,
                    potential_savings_monthly=savings if savings > 0 else Decimal("0"),
                    recommended_tier=recommended,
                    days_since_access=self._config.cold_data_days,
                    recommended_action=(
                        f"Move {len(cold_90_objects)} objects to {recommended.value if recommended else 'infrequent access'} "
                        f"to save ${float(savings):.2f}/month"
                        if savings > 0
                        else f"Monitor access patterns for {len(cold_90_objects)} objects"
                    ),
                    metadata={
                        "object_count": len(cold_90_objects),
                        "sample_objects": [o.object_key for o in cold_90_objects[:5]],
                    },
                )
            )

        return findings

    def _storage_class_to_tier(self, storage_class: str) -> StorageTier:
        """Convert cloud storage class string to StorageTier enum."""
        mapping = {
            # S3 storage classes
            "STANDARD": StorageTier.S3_STANDARD,
            "INTELLIGENT_TIERING": StorageTier.S3_INTELLIGENT_TIERING,
            "STANDARD_IA": StorageTier.S3_STANDARD_IA,
            "ONEZONE_IA": StorageTier.S3_ONE_ZONE_IA,
            "GLACIER": StorageTier.S3_GLACIER_FLEXIBLE,
            "GLACIER_IR": StorageTier.S3_GLACIER_INSTANT,
            "DEEP_ARCHIVE": StorageTier.S3_GLACIER_DEEP_ARCHIVE,
            # GCS storage classes
            "STANDARD": StorageTier.GCS_STANDARD,
            "NEARLINE": StorageTier.GCS_NEARLINE,
            "COLDLINE": StorageTier.GCS_COLDLINE,
            "ARCHIVE": StorageTier.GCS_ARCHIVE,
            # Azure access tiers
            "Hot": StorageTier.AZURE_HOT,
            "Cool": StorageTier.AZURE_COOL,
            "Cold": StorageTier.AZURE_COLD,
            "Archive": StorageTier.AZURE_ARCHIVE,
        }
        return mapping.get(storage_class, StorageTier.UNKNOWN)
