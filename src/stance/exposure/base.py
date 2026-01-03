"""
Base classes for Exposure Management.

Provides data models and abstract base class for discovering and analyzing
publicly accessible cloud resources and correlating with data sensitivity.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class ExposureType(Enum):
    """Types of public exposure."""

    # Storage
    PUBLIC_BUCKET = "public_bucket"  # S3/GCS/Blob with public access
    PUBLIC_OBJECT = "public_object"  # Individual object with public access

    # Compute
    PUBLIC_INSTANCE = "public_instance"  # VM with public IP
    PUBLIC_FUNCTION = "public_function"  # Serverless function with public URL

    # Database
    PUBLIC_DATABASE = "public_database"  # Database with public endpoint

    # Network
    PUBLIC_LOAD_BALANCER = "public_load_balancer"  # Internet-facing LB
    PUBLIC_API_GATEWAY = "public_api_gateway"  # Public API endpoint
    PUBLIC_IP = "public_ip"  # Elastic/Static IP address

    # Kubernetes
    PUBLIC_INGRESS = "public_ingress"  # K8s ingress with public IP
    PUBLIC_SERVICE = "public_service"  # K8s LoadBalancer service

    # Other
    PUBLIC_CDN = "public_cdn"  # CDN distribution
    PUBLIC_DNS = "public_dns"  # DNS record pointing to public resource


class ExposureSeverity(Enum):
    """Severity levels for exposure findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison (higher = more severe)."""
        ranks = {
            ExposureSeverity.CRITICAL: 5,
            ExposureSeverity.HIGH: 4,
            ExposureSeverity.MEDIUM: 3,
            ExposureSeverity.LOW: 2,
            ExposureSeverity.INFO: 1,
        }
        return ranks.get(self, 0)

    def __gt__(self, other: "ExposureSeverity") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "ExposureSeverity") -> bool:
        return self.rank >= other.rank

    def __lt__(self, other: "ExposureSeverity") -> bool:
        return self.rank < other.rank

    def __le__(self, other: "ExposureSeverity") -> bool:
        return self.rank <= other.rank


class ExposureFindingType(Enum):
    """Types of exposure-related findings."""

    # Sensitive data exposure
    PUBLIC_PII_EXPOSURE = "public_pii_exposure"  # Public resource with PII
    PUBLIC_PCI_EXPOSURE = "public_pci_exposure"  # Public resource with payment data
    PUBLIC_PHI_EXPOSURE = "public_phi_exposure"  # Public resource with health data
    PUBLIC_CREDENTIALS = "public_credentials"  # Public resource with secrets/keys

    # Access configuration
    UNRESTRICTED_ACCESS = "unrestricted_access"  # No access controls
    WEAK_ACCESS_CONTROLS = "weak_access_controls"  # Insufficient controls
    OVERLY_PERMISSIVE = "overly_permissive"  # More access than needed

    # Network exposure
    DANGEROUS_PORTS_EXPOSED = "dangerous_ports_exposed"  # SSH/RDP/DB ports open
    UNENCRYPTED_ENDPOINT = "unencrypted_endpoint"  # HTTP instead of HTTPS
    NO_WAF_PROTECTION = "no_waf_protection"  # No WAF in front of public asset

    # Data exposure
    SENSITIVE_DATA_PUBLIC = "sensitive_data_public"  # Sensitive data publicly accessible
    UNCLASSIFIED_PUBLIC = "unclassified_public"  # Public data not classified


@dataclass
class ExposureConfig:
    """
    Configuration for exposure analysis.

    Attributes:
        include_storage: Whether to include storage resources
        include_compute: Whether to include compute resources
        include_database: Whether to include database resources
        include_network: Whether to include network resources
        include_kubernetes: Whether to include Kubernetes resources
        cloud_providers: List of cloud providers to analyze
        regions: List of regions to analyze (empty = all)
        min_sensitivity_for_critical: Minimum classification for critical severity
    """

    include_storage: bool = True
    include_compute: bool = True
    include_database: bool = True
    include_network: bool = True
    include_kubernetes: bool = True
    cloud_providers: list[str] = field(default_factory=lambda: ["aws", "gcp", "azure"])
    regions: list[str] = field(default_factory=list)
    min_sensitivity_for_critical: str = "confidential"


@dataclass
class PublicAsset:
    """
    A publicly accessible cloud resource.

    Attributes:
        asset_id: Unique identifier (ARN, resource ID, etc.)
        name: Human-readable name
        exposure_type: Type of exposure
        cloud_provider: Cloud provider (aws, gcp, azure)
        account_id: Account/project ID
        region: Region where resource is located
        resource_type: Type of resource (e.g., aws_s3_bucket)
        public_endpoint: Public URL or IP if applicable
        public_ips: List of public IP addresses
        access_method: How public access is granted (acl, policy, network, etc.)
        detected_at: When the public exposure was detected
        data_classification: Data sensitivity if known (from DSPM)
        data_categories: Data categories found (PII, PCI, etc.)
        has_sensitive_data: Whether sensitive data is present
        risk_score: Numeric risk score (0-100)
        metadata: Additional metadata
    """

    asset_id: str
    name: str
    exposure_type: ExposureType
    cloud_provider: str
    account_id: str
    region: str
    resource_type: str
    public_endpoint: str | None = None
    public_ips: list[str] = field(default_factory=list)
    access_method: str = "unknown"
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    data_classification: str | None = None
    data_categories: list[str] = field(default_factory=list)
    has_sensitive_data: bool = False
    risk_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "exposure_type": self.exposure_type.value,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "region": self.region,
            "resource_type": self.resource_type,
            "public_endpoint": self.public_endpoint,
            "public_ips": self.public_ips,
            "access_method": self.access_method,
            "detected_at": self.detected_at.isoformat(),
            "data_classification": self.data_classification,
            "data_categories": self.data_categories,
            "has_sensitive_data": self.has_sensitive_data,
            "risk_score": self.risk_score,
            "metadata": self.metadata,
        }


@dataclass
class ExposureFinding:
    """
    A finding about a publicly exposed resource.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level
        title: Short title
        description: Detailed description
        asset_id: Affected asset ID
        asset_name: Human-readable asset name
        exposure_type: Type of exposure
        cloud_provider: Cloud provider
        region: Region
        data_classification: Data sensitivity if known
        data_categories: Data categories affected
        recommended_action: Suggested remediation
        risk_score: Numeric risk score (0-100)
        metadata: Additional context
        detected_at: When finding was generated
    """

    finding_id: str
    finding_type: ExposureFindingType
    severity: ExposureSeverity
    title: str
    description: str
    asset_id: str
    asset_name: str
    exposure_type: ExposureType
    cloud_provider: str
    region: str
    data_classification: str | None = None
    data_categories: list[str] = field(default_factory=list)
    recommended_action: str = ""
    risk_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "exposure_type": self.exposure_type.value,
            "cloud_provider": self.cloud_provider,
            "region": self.region,
            "data_classification": self.data_classification,
            "data_categories": self.data_categories,
            "recommended_action": self.recommended_action,
            "risk_score": self.risk_score,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class ExposureInventorySummary:
    """
    Summary statistics for exposure inventory.

    Attributes:
        total_public_assets: Total number of public assets
        assets_by_type: Count by exposure type
        assets_by_cloud: Count by cloud provider
        assets_by_region: Count by region
        assets_with_sensitive_data: Count with sensitive data
        critical_exposures: Count of critical exposure findings
        high_exposures: Count of high exposure findings
        average_risk_score: Average risk score across assets
    """

    total_public_assets: int = 0
    assets_by_type: dict[str, int] = field(default_factory=dict)
    assets_by_cloud: dict[str, int] = field(default_factory=dict)
    assets_by_region: dict[str, int] = field(default_factory=dict)
    assets_with_sensitive_data: int = 0
    critical_exposures: int = 0
    high_exposures: int = 0
    average_risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_public_assets": self.total_public_assets,
            "assets_by_type": self.assets_by_type,
            "assets_by_cloud": self.assets_by_cloud,
            "assets_by_region": self.assets_by_region,
            "assets_with_sensitive_data": self.assets_with_sensitive_data,
            "critical_exposures": self.critical_exposures,
            "high_exposures": self.high_exposures,
            "average_risk_score": self.average_risk_score,
        }


@dataclass
class ExposureInventoryResult:
    """
    Result of exposure inventory analysis.

    Attributes:
        inventory_id: Unique identifier
        config: Configuration used
        started_at: Analysis start time
        completed_at: Analysis completion time
        public_assets: List of public assets found
        findings: List of exposure findings
        summary: Summary statistics
        errors: Errors encountered
    """

    inventory_id: str
    config: ExposureConfig
    started_at: datetime
    completed_at: datetime | None = None
    public_assets: list[PublicAsset] = field(default_factory=list)
    findings: list[ExposureFinding] = field(default_factory=list)
    summary: ExposureInventorySummary = field(default_factory=ExposureInventorySummary)
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Check if inventory has any findings."""
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
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @property
    def critical_findings(self) -> list[ExposureFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == ExposureSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[ExposureFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == ExposureSeverity.HIGH]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "inventory_id": self.inventory_id,
            "config": {
                "include_storage": self.config.include_storage,
                "include_compute": self.config.include_compute,
                "include_database": self.config.include_database,
                "cloud_providers": self.config.cloud_providers,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_public_assets": len(self.public_assets),
            "public_assets": [a.to_dict() for a in self.public_assets],
            "findings_count": len(self.findings),
            "findings_by_type": self.findings_by_type,
            "findings_by_severity": self.findings_by_severity,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
            "errors": self.errors,
        }


class BaseExposureAnalyzer(ABC):
    """
    Abstract base class for exposure analyzers.

    Subclasses implement cloud-specific or resource-specific logic
    for discovering publicly accessible resources.
    """

    analyzer_name = "base"

    def __init__(self, config: ExposureConfig | None = None):
        """
        Initialize the exposure analyzer.

        Args:
            config: Optional configuration for analysis
        """
        self._config = config or ExposureConfig()

    @property
    def config(self) -> ExposureConfig:
        """Get the analysis configuration."""
        return self._config

    @abstractmethod
    def discover_public_assets(self) -> Iterator[PublicAsset]:
        """
        Discover publicly accessible assets.

        Yields:
            Public assets found
        """
        pass

    @abstractmethod
    def analyze_asset(self, asset: PublicAsset) -> list[ExposureFinding]:
        """
        Analyze a public asset for exposure findings.

        Args:
            asset: Public asset to analyze

        Returns:
            List of findings for this asset
        """
        pass

    def calculate_risk_score(
        self,
        exposure_type: ExposureType,
        data_classification: str | None,
        data_categories: list[str],
        access_method: str,
    ) -> float:
        """
        Calculate risk score for a public asset.

        Args:
            exposure_type: Type of exposure
            data_classification: Data sensitivity level
            data_categories: Data categories present
            access_method: How access is granted

        Returns:
            Risk score (0-100)
        """
        score = 0.0

        # Base score by exposure type
        type_scores = {
            ExposureType.PUBLIC_BUCKET: 40.0,
            ExposureType.PUBLIC_DATABASE: 60.0,
            ExposureType.PUBLIC_INSTANCE: 35.0,
            ExposureType.PUBLIC_FUNCTION: 30.0,
            ExposureType.PUBLIC_API_GATEWAY: 25.0,
            ExposureType.PUBLIC_LOAD_BALANCER: 20.0,
            ExposureType.PUBLIC_IP: 15.0,
            ExposureType.PUBLIC_CDN: 10.0,
        }
        score += type_scores.get(exposure_type, 20.0)

        # Add for data classification
        classification_scores = {
            "top_secret": 40.0,
            "restricted": 35.0,
            "confidential": 25.0,
            "internal": 10.0,
            "public": 0.0,
        }
        if data_classification:
            score += classification_scores.get(data_classification.lower(), 10.0)

        # Add for sensitive data categories
        sensitive_categories = {"pii", "pci", "phi", "credentials", "financial"}
        for category in data_categories:
            if any(s in category.lower() for s in sensitive_categories):
                score += 15.0
                break  # Only count once

        # Add for access method (unrestricted is worse)
        if access_method in ("public_acl", "wildcard_policy", "anonymous"):
            score += 10.0

        return min(100.0, score)

    def calculate_severity(
        self,
        exposure_type: ExposureType,
        data_classification: str | None,
        has_sensitive_data: bool,
    ) -> ExposureSeverity:
        """
        Calculate severity for an exposure finding.

        Args:
            exposure_type: Type of exposure
            data_classification: Data sensitivity level
            has_sensitive_data: Whether sensitive data is present

        Returns:
            Severity level
        """
        # Critical: Sensitive data exposed publicly
        if has_sensitive_data:
            if data_classification in ("restricted", "top_secret"):
                return ExposureSeverity.CRITICAL
            if data_classification == "confidential":
                return ExposureSeverity.HIGH

        # High: Databases or storage with sensitive data
        if exposure_type in (ExposureType.PUBLIC_DATABASE,):
            return ExposureSeverity.HIGH

        if exposure_type == ExposureType.PUBLIC_BUCKET and has_sensitive_data:
            return ExposureSeverity.HIGH

        # Medium: Public instances or storage
        if exposure_type in (
            ExposureType.PUBLIC_BUCKET,
            ExposureType.PUBLIC_INSTANCE,
        ):
            if data_classification in ("confidential", "internal"):
                return ExposureSeverity.MEDIUM
            return ExposureSeverity.LOW

        # Low: Network infrastructure
        if exposure_type in (
            ExposureType.PUBLIC_LOAD_BALANCER,
            ExposureType.PUBLIC_API_GATEWAY,
            ExposureType.PUBLIC_CDN,
        ):
            return ExposureSeverity.LOW

        return ExposureSeverity.INFO

    def _build_summary(
        self,
        assets: list[PublicAsset],
        findings: list[ExposureFinding],
    ) -> ExposureInventorySummary:
        """Build summary statistics from assets and findings."""
        summary = ExposureInventorySummary(
            total_public_assets=len(assets),
        )

        # Count by type
        for asset in assets:
            type_val = asset.exposure_type.value
            summary.assets_by_type[type_val] = summary.assets_by_type.get(type_val, 0) + 1

            # Count by cloud
            summary.assets_by_cloud[asset.cloud_provider] = (
                summary.assets_by_cloud.get(asset.cloud_provider, 0) + 1
            )

            # Count by region
            summary.assets_by_region[asset.region] = (
                summary.assets_by_region.get(asset.region, 0) + 1
            )

            # Count with sensitive data
            if asset.has_sensitive_data:
                summary.assets_with_sensitive_data += 1

        # Count findings by severity
        for finding in findings:
            if finding.severity == ExposureSeverity.CRITICAL:
                summary.critical_exposures += 1
            elif finding.severity == ExposureSeverity.HIGH:
                summary.high_exposures += 1

        # Calculate average risk score
        if assets:
            summary.average_risk_score = sum(a.risk_score for a in assets) / len(assets)

        return summary
