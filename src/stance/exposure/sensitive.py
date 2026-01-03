"""
Sensitive Data Exposure Correlation for Exposure Management.

Cross-references publicly accessible resources with DSPM scan findings
to identify critical exposures where sensitive data is publicly accessible.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

from stance.dspm.classifier import ClassificationLevel, DataCategory
from stance.dspm.scanners.base import ScanResult, ScanFinding, FindingSeverity
from stance.exposure.base import (
    ExposureConfig,
    ExposureType,
    ExposureSeverity,
    ExposureFindingType,
    PublicAsset,
    ExposureFinding,
    ExposureInventoryResult,
)

logger = logging.getLogger(__name__)


class SensitiveExposureType(Enum):
    """Types of sensitive data exposure."""

    PII_EXPOSURE = "pii_exposure"  # Personally Identifiable Information
    PCI_EXPOSURE = "pci_exposure"  # Payment Card Industry data
    PHI_EXPOSURE = "phi_exposure"  # Protected Health Information
    CREDENTIAL_EXPOSURE = "credential_exposure"  # Secrets/keys/passwords
    FINANCIAL_EXPOSURE = "financial_exposure"  # Financial data
    CONFIDENTIAL_EXPOSURE = "confidential_exposure"  # General confidential data
    RESTRICTED_EXPOSURE = "restricted_exposure"  # Restricted/top-secret data


class ExposureRiskLevel(Enum):
    """Risk levels for sensitive data exposure."""

    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"  # High priority remediation
    MEDIUM = "medium"  # Should be addressed soon
    LOW = "low"  # Monitor and address when possible
    INFO = "info"  # Informational only

    @property
    def rank(self) -> int:
        """Numeric rank for comparison."""
        ranks = {
            ExposureRiskLevel.CRITICAL: 5,
            ExposureRiskLevel.HIGH: 4,
            ExposureRiskLevel.MEDIUM: 3,
            ExposureRiskLevel.LOW: 2,
            ExposureRiskLevel.INFO: 1,
        }
        return ranks.get(self, 0)

    def __gt__(self, other: "ExposureRiskLevel") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "ExposureRiskLevel") -> bool:
        return self.rank >= other.rank


@dataclass
class SensitiveExposureConfig:
    """
    Configuration for sensitive data exposure analysis.

    Attributes:
        min_classification_level: Minimum classification to consider sensitive
        include_pii: Include PII findings
        include_pci: Include PCI findings
        include_phi: Include PHI findings
        include_credentials: Include credential findings
        include_financial: Include financial data findings
        prioritize_internet_facing: Prioritize internet-facing exposures
        generate_remediation: Generate remediation recommendations
    """

    min_classification_level: ClassificationLevel = ClassificationLevel.INTERNAL
    include_pii: bool = True
    include_pci: bool = True
    include_phi: bool = True
    include_credentials: bool = True
    include_financial: bool = True
    prioritize_internet_facing: bool = True
    generate_remediation: bool = True


@dataclass
class SensitiveDataMatch:
    """
    A match between a public asset and sensitive data finding.

    Attributes:
        asset_id: Public asset identifier
        asset_name: Public asset name
        finding_id: DSPM finding identifier
        storage_location: Full path to the sensitive data
        classification_level: Data classification level
        data_categories: Categories of sensitive data found
        match_count: Number of sensitive patterns matched
        sample_data: Sample of matched patterns (redacted)
        detection_confidence: Confidence level of detection
    """

    asset_id: str
    asset_name: str
    finding_id: str
    storage_location: str
    classification_level: ClassificationLevel
    data_categories: list[DataCategory] = field(default_factory=list)
    match_count: int = 0
    sample_data: list[dict[str, Any]] = field(default_factory=list)
    detection_confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "finding_id": self.finding_id,
            "storage_location": self.storage_location,
            "classification_level": self.classification_level.value,
            "data_categories": [c.value for c in self.data_categories],
            "match_count": self.match_count,
            "sample_data": self.sample_data,
            "detection_confidence": self.detection_confidence,
        }


@dataclass
class SensitiveExposureFinding:
    """
    A finding of sensitive data being publicly exposed.

    Attributes:
        finding_id: Unique identifier
        exposure_type: Type of sensitive exposure
        risk_level: Risk level
        title: Short title
        description: Detailed description
        asset_id: Affected public asset ID
        asset_name: Public asset name
        exposure_type_asset: Type of public exposure (bucket, instance, etc.)
        cloud_provider: Cloud provider
        region: Region
        classification_level: Highest classification level exposed
        data_categories: Data categories exposed
        data_matches: Detailed match information
        total_findings_count: Total number of DSPM findings
        risk_score: Numeric risk score (0-100)
        recommended_action: Suggested remediation
        compliance_impact: Compliance frameworks affected
        metadata: Additional context
        detected_at: When finding was generated
    """

    finding_id: str
    exposure_type: SensitiveExposureType
    risk_level: ExposureRiskLevel
    title: str
    description: str
    asset_id: str
    asset_name: str
    exposure_type_asset: ExposureType
    cloud_provider: str
    region: str
    classification_level: ClassificationLevel
    data_categories: list[DataCategory] = field(default_factory=list)
    data_matches: list[SensitiveDataMatch] = field(default_factory=list)
    total_findings_count: int = 0
    risk_score: float = 0.0
    recommended_action: str = ""
    compliance_impact: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "exposure_type": self.exposure_type.value,
            "risk_level": self.risk_level.value,
            "title": self.title,
            "description": self.description,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "exposure_type_asset": self.exposure_type_asset.value,
            "cloud_provider": self.cloud_provider,
            "region": self.region,
            "classification_level": self.classification_level.value,
            "data_categories": [c.value for c in self.data_categories],
            "data_matches": [m.to_dict() for m in self.data_matches],
            "total_findings_count": self.total_findings_count,
            "risk_score": self.risk_score,
            "recommended_action": self.recommended_action,
            "compliance_impact": self.compliance_impact,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class SensitiveExposureSummary:
    """
    Summary statistics for sensitive data exposure analysis.

    Attributes:
        total_public_assets: Total public assets analyzed
        assets_with_sensitive_data: Assets with sensitive data exposed
        total_sensitive_findings: Total sensitive data findings
        critical_exposures: Count of critical risk exposures
        high_exposures: Count of high risk exposures
        exposures_by_type: Count by exposure type
        exposures_by_category: Count by data category
        exposures_by_cloud: Count by cloud provider
        highest_risk_assets: Top risk assets
        compliance_frameworks_impacted: Affected compliance frameworks
        average_risk_score: Average risk score
    """

    total_public_assets: int = 0
    assets_with_sensitive_data: int = 0
    total_sensitive_findings: int = 0
    critical_exposures: int = 0
    high_exposures: int = 0
    exposures_by_type: dict[str, int] = field(default_factory=dict)
    exposures_by_category: dict[str, int] = field(default_factory=dict)
    exposures_by_cloud: dict[str, int] = field(default_factory=dict)
    highest_risk_assets: list[str] = field(default_factory=list)
    compliance_frameworks_impacted: list[str] = field(default_factory=list)
    average_risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_public_assets": self.total_public_assets,
            "assets_with_sensitive_data": self.assets_with_sensitive_data,
            "total_sensitive_findings": self.total_sensitive_findings,
            "critical_exposures": self.critical_exposures,
            "high_exposures": self.high_exposures,
            "exposures_by_type": self.exposures_by_type,
            "exposures_by_category": self.exposures_by_category,
            "exposures_by_cloud": self.exposures_by_cloud,
            "highest_risk_assets": self.highest_risk_assets,
            "compliance_frameworks_impacted": self.compliance_frameworks_impacted,
            "average_risk_score": self.average_risk_score,
        }


@dataclass
class SensitiveExposureResult:
    """
    Result of sensitive data exposure analysis.

    Attributes:
        analysis_id: Unique identifier
        config: Configuration used
        started_at: Analysis start time
        completed_at: Analysis completion time
        public_assets_analyzed: Number of public assets analyzed
        dspm_findings_correlated: Number of DSPM findings correlated
        exposures: List of sensitive exposure findings
        summary: Summary statistics
        errors: Errors encountered
    """

    analysis_id: str
    config: SensitiveExposureConfig
    started_at: datetime
    completed_at: datetime | None = None
    public_assets_analyzed: int = 0
    dspm_findings_correlated: int = 0
    exposures: list[SensitiveExposureFinding] = field(default_factory=list)
    summary: SensitiveExposureSummary = field(default_factory=SensitiveExposureSummary)
    errors: list[str] = field(default_factory=list)

    @property
    def has_exposures(self) -> bool:
        """Check if any sensitive exposures were found."""
        return len(self.exposures) > 0

    @property
    def critical_exposures(self) -> list[SensitiveExposureFinding]:
        """Get critical risk exposures."""
        return [e for e in self.exposures if e.risk_level == ExposureRiskLevel.CRITICAL]

    @property
    def high_exposures(self) -> list[SensitiveExposureFinding]:
        """Get high risk exposures."""
        return [e for e in self.exposures if e.risk_level == ExposureRiskLevel.HIGH]

    @property
    def exposures_by_type(self) -> dict[str, int]:
        """Count exposures by type."""
        counts: dict[str, int] = {}
        for exposure in self.exposures:
            type_val = exposure.exposure_type.value
            counts[type_val] = counts.get(type_val, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "analysis_id": self.analysis_id,
            "config": {
                "min_classification_level": self.config.min_classification_level.value,
                "include_pii": self.config.include_pii,
                "include_pci": self.config.include_pci,
                "include_phi": self.config.include_phi,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "public_assets_analyzed": self.public_assets_analyzed,
            "dspm_findings_correlated": self.dspm_findings_correlated,
            "exposures_count": len(self.exposures),
            "exposures": [e.to_dict() for e in self.exposures],
            "summary": self.summary.to_dict(),
            "errors": self.errors,
        }


class SensitiveDataExposureAnalyzer:
    """
    Analyzer for correlating public assets with sensitive data findings.

    Cross-references publicly accessible resources with DSPM scan results
    to identify critical exposures where sensitive data is publicly accessible.
    """

    def __init__(self, config: SensitiveExposureConfig | None = None):
        """
        Initialize the sensitive data exposure analyzer.

        Args:
            config: Optional configuration
        """
        self._config = config or SensitiveExposureConfig()
        self._finding_counter = 0

        # Registered data for correlation
        self._public_assets: list[PublicAsset] = []
        self._dspm_results: dict[str, ScanResult] = {}  # Keyed by bucket/target
        self._dspm_findings: dict[str, list[ScanFinding]] = {}  # Keyed by asset_id

    @property
    def config(self) -> SensitiveExposureConfig:
        """Get the analysis configuration."""
        return self._config

    def register_public_assets(self, assets: list[PublicAsset]) -> None:
        """
        Register public assets for correlation.

        Args:
            assets: List of public assets
        """
        self._public_assets.extend(assets)

    def register_inventory_result(self, result: ExposureInventoryResult) -> None:
        """
        Register an exposure inventory result.

        Args:
            result: Exposure inventory result
        """
        self._public_assets.extend(result.public_assets)

    def register_dspm_scan_result(self, result: ScanResult) -> None:
        """
        Register a DSPM scan result for correlation.

        Args:
            result: DSPM scan result
        """
        self._dspm_results[result.target] = result

        # Index findings by storage location for efficient lookup
        for finding in result.findings:
            bucket_key = finding.bucket_name
            if bucket_key not in self._dspm_findings:
                self._dspm_findings[bucket_key] = []
            self._dspm_findings[bucket_key].append(finding)

    def register_dspm_findings(
        self,
        asset_id: str,
        findings: list[ScanFinding],
    ) -> None:
        """
        Register DSPM findings directly for an asset.

        Args:
            asset_id: Asset identifier
            findings: List of scan findings
        """
        if asset_id not in self._dspm_findings:
            self._dspm_findings[asset_id] = []
        self._dspm_findings[asset_id].extend(findings)

    def analyze(self) -> SensitiveExposureResult:
        """
        Analyze sensitive data exposure across all registered data.

        Returns:
            Complete analysis result
        """
        result = SensitiveExposureResult(
            analysis_id=f"sens-{uuid.uuid4().hex[:12]}",
            config=self._config,
            started_at=datetime.now(timezone.utc),
        )

        exposures: list[SensitiveExposureFinding] = []
        total_dspm_correlated = 0
        assets_with_sensitive = set()

        for asset in self._public_assets:
            # Find DSPM findings for this asset
            asset_findings = self._find_dspm_findings_for_asset(asset)

            if not asset_findings:
                continue

            # Filter findings based on configuration
            filtered_findings = self._filter_findings(asset_findings)

            if not filtered_findings:
                continue

            total_dspm_correlated += len(filtered_findings)
            assets_with_sensitive.add(asset.asset_id)

            # Generate exposure finding
            exposure = self._create_exposure_finding(asset, filtered_findings)
            exposures.append(exposure)

        result.exposures = exposures
        result.public_assets_analyzed = len(self._public_assets)
        result.dspm_findings_correlated = total_dspm_correlated
        result.summary = self._build_summary(exposures, len(assets_with_sensitive))
        result.completed_at = datetime.now(timezone.utc)

        return result

    def analyze_asset(
        self,
        asset: PublicAsset,
        dspm_findings: list[ScanFinding],
    ) -> SensitiveExposureFinding | None:
        """
        Analyze a single public asset with its DSPM findings.

        Args:
            asset: Public asset to analyze
            dspm_findings: DSPM findings for this asset

        Returns:
            Sensitive exposure finding or None if no exposure
        """
        filtered_findings = self._filter_findings(dspm_findings)
        if not filtered_findings:
            return None

        return self._create_exposure_finding(asset, filtered_findings)

    def get_critical_exposures(self) -> list[SensitiveExposureFinding]:
        """
        Get only critical risk exposures.

        Returns:
            List of critical exposures
        """
        result = self.analyze()
        return result.critical_exposures

    def get_exposures_by_category(
        self,
        category: DataCategory,
    ) -> list[SensitiveExposureFinding]:
        """
        Get exposures filtered by data category.

        Args:
            category: Data category to filter by

        Returns:
            List of exposures with the specified category
        """
        result = self.analyze()
        return [
            e for e in result.exposures
            if category in e.data_categories
        ]

    def get_exposures_by_classification(
        self,
        classification: ClassificationLevel,
    ) -> list[SensitiveExposureFinding]:
        """
        Get exposures filtered by classification level.

        Args:
            classification: Classification level to filter by

        Returns:
            List of exposures with the specified or higher classification
        """
        result = self.analyze()
        return [
            e for e in result.exposures
            if e.classification_level.severity_score >= classification.severity_score
        ]

    def _find_dspm_findings_for_asset(
        self,
        asset: PublicAsset,
    ) -> list[ScanFinding]:
        """Find DSPM findings that match a public asset."""
        findings: list[ScanFinding] = []

        # Check by asset ID
        if asset.asset_id in self._dspm_findings:
            findings.extend(self._dspm_findings[asset.asset_id])

        # Check by asset name (bucket name)
        if asset.name in self._dspm_findings:
            findings.extend(self._dspm_findings[asset.name])

        # Check in scan results by target
        for target, scan_result in self._dspm_results.items():
            if target == asset.name or target == asset.asset_id:
                findings.extend(scan_result.findings)
            elif asset.name in target or target in asset.name:
                findings.extend(scan_result.findings)

        # Deduplicate by finding_id
        seen_ids = set()
        unique_findings = []
        for finding in findings:
            if finding.finding_id not in seen_ids:
                seen_ids.add(finding.finding_id)
                unique_findings.append(finding)

        return unique_findings

    def _filter_findings(
        self,
        findings: list[ScanFinding],
    ) -> list[ScanFinding]:
        """Filter findings based on configuration."""
        filtered = []

        for finding in findings:
            # Check classification level
            if finding.classification_level.severity_score < self._config.min_classification_level.severity_score:
                continue

            # Check category filters
            categories = finding.categories
            include = False

            for cat in categories:
                cat_value = cat.value.lower()
                if self._config.include_pii and "pii" in cat_value:
                    include = True
                    break
                if self._config.include_pci and "pci" in cat_value:
                    include = True
                    break
                if self._config.include_phi and "phi" in cat_value:
                    include = True
                    break
                if self._config.include_credentials and (
                    "credential" in cat_value or "secret" in cat_value or "key" in cat_value
                ):
                    include = True
                    break
                if self._config.include_financial and "financial" in cat_value:
                    include = True
                    break

            # If no specific category matched, include based on classification
            if not include and finding.classification_level.severity_score >= ClassificationLevel.CONFIDENTIAL.severity_score:
                include = True

            if include:
                filtered.append(finding)

        return filtered

    def _create_exposure_finding(
        self,
        asset: PublicAsset,
        findings: list[ScanFinding],
    ) -> SensitiveExposureFinding:
        """Create a sensitive exposure finding."""
        self._finding_counter += 1

        # Determine highest classification level
        highest_classification = ClassificationLevel.PUBLIC
        for finding in findings:
            if finding.classification_level.severity_score > highest_classification.severity_score:
                highest_classification = finding.classification_level

        # Collect all unique categories
        all_categories: set[DataCategory] = set()
        for finding in findings:
            all_categories.update(finding.categories)

        # Determine exposure type based on categories
        exposure_type = self._determine_exposure_type(list(all_categories))

        # Calculate risk level
        risk_level = self._calculate_risk_level(
            asset.exposure_type,
            highest_classification,
            list(all_categories),
        )

        # Calculate risk score
        risk_score = self._calculate_risk_score(
            asset.exposure_type,
            highest_classification,
            list(all_categories),
            len(findings),
        )

        # Build data matches
        data_matches = [
            SensitiveDataMatch(
                asset_id=asset.asset_id,
                asset_name=asset.name,
                finding_id=f.finding_id,
                storage_location=f.storage_location,
                classification_level=f.classification_level,
                data_categories=f.categories,
                match_count=len(f.sample_matches),
                sample_data=f.sample_matches[:3],  # Limit samples
            )
            for f in findings[:10]  # Limit to first 10 matches
        ]

        # Determine compliance impact
        compliance_impact = self._determine_compliance_impact(list(all_categories))

        # Generate remediation
        remediation = self._generate_remediation(asset, highest_classification, list(all_categories))

        return SensitiveExposureFinding(
            finding_id=f"{asset.asset_id}-sens-{self._finding_counter:04d}",
            exposure_type=exposure_type,
            risk_level=risk_level,
            title=self._generate_title(asset, exposure_type, highest_classification),
            description=self._generate_description(
                asset, highest_classification, list(all_categories), len(findings)
            ),
            asset_id=asset.asset_id,
            asset_name=asset.name,
            exposure_type_asset=asset.exposure_type,
            cloud_provider=asset.cloud_provider,
            region=asset.region,
            classification_level=highest_classification,
            data_categories=list(all_categories),
            data_matches=data_matches,
            total_findings_count=len(findings),
            risk_score=risk_score,
            recommended_action=remediation,
            compliance_impact=compliance_impact,
        )

    def _determine_exposure_type(
        self,
        categories: list[DataCategory],
    ) -> SensitiveExposureType:
        """Determine the primary exposure type based on categories."""
        category_values = [c.value.lower() for c in categories]

        # Check in priority order
        if any("credential" in c or "secret" in c or "key" in c for c in category_values):
            return SensitiveExposureType.CREDENTIAL_EXPOSURE
        if any("pci" in c for c in category_values):
            return SensitiveExposureType.PCI_EXPOSURE
        if any("phi" in c for c in category_values):
            return SensitiveExposureType.PHI_EXPOSURE
        if any("pii" in c for c in category_values):
            return SensitiveExposureType.PII_EXPOSURE
        if any("financial" in c for c in category_values):
            return SensitiveExposureType.FINANCIAL_EXPOSURE

        return SensitiveExposureType.CONFIDENTIAL_EXPOSURE

    def _calculate_risk_level(
        self,
        exposure_type: ExposureType,
        classification: ClassificationLevel,
        categories: list[DataCategory],
    ) -> ExposureRiskLevel:
        """Calculate risk level for the exposure."""
        # Critical: Credentials or restricted data publicly exposed
        if classification == ClassificationLevel.TOP_SECRET:
            return ExposureRiskLevel.CRITICAL
        if classification == ClassificationLevel.RESTRICTED:
            return ExposureRiskLevel.CRITICAL

        category_values = [c.value.lower() for c in categories]

        # Critical: Credentials publicly exposed
        if any("credential" in c or "secret" in c or "key" in c for c in category_values):
            return ExposureRiskLevel.CRITICAL

        # Critical: PCI data on public storage
        if any("pci" in c for c in category_values):
            if exposure_type == ExposureType.PUBLIC_BUCKET:
                return ExposureRiskLevel.CRITICAL
            return ExposureRiskLevel.HIGH

        # High: PHI publicly exposed
        if any("phi" in c for c in category_values):
            return ExposureRiskLevel.HIGH

        # High: Confidential classification
        if classification == ClassificationLevel.CONFIDENTIAL:
            return ExposureRiskLevel.HIGH

        # Medium: PII publicly exposed
        if any("pii" in c for c in category_values):
            return ExposureRiskLevel.MEDIUM

        # Low: Internal data
        if classification == ClassificationLevel.INTERNAL:
            return ExposureRiskLevel.LOW

        return ExposureRiskLevel.INFO

    def _calculate_risk_score(
        self,
        exposure_type: ExposureType,
        classification: ClassificationLevel,
        categories: list[DataCategory],
        finding_count: int,
    ) -> float:
        """Calculate numeric risk score (0-100)."""
        score = 0.0

        # Base score from classification
        classification_scores = {
            ClassificationLevel.TOP_SECRET: 50.0,
            ClassificationLevel.RESTRICTED: 45.0,
            ClassificationLevel.CONFIDENTIAL: 35.0,
            ClassificationLevel.INTERNAL: 15.0,
            ClassificationLevel.PUBLIC: 0.0,
        }
        score += classification_scores.get(classification, 10.0)

        # Add for exposure type
        exposure_scores = {
            ExposureType.PUBLIC_BUCKET: 20.0,
            ExposureType.PUBLIC_DATABASE: 25.0,
            ExposureType.PUBLIC_INSTANCE: 15.0,
            ExposureType.PUBLIC_FUNCTION: 10.0,
        }
        score += exposure_scores.get(exposure_type, 10.0)

        # Add for sensitive categories
        category_values = [c.value.lower() for c in categories]
        if any("credential" in c or "secret" in c for c in category_values):
            score += 25.0
        elif any("pci" in c for c in category_values):
            score += 20.0
        elif any("phi" in c for c in category_values):
            score += 15.0
        elif any("pii" in c for c in category_values):
            score += 10.0
        elif any("financial" in c for c in category_values):
            score += 10.0

        # Add based on finding count (more findings = higher risk)
        if finding_count >= 100:
            score += 10.0
        elif finding_count >= 50:
            score += 7.0
        elif finding_count >= 10:
            score += 5.0
        elif finding_count >= 5:
            score += 2.0

        return min(100.0, score)

    def _determine_compliance_impact(
        self,
        categories: list[DataCategory],
    ) -> list[str]:
        """Determine affected compliance frameworks."""
        frameworks: set[str] = set()
        category_values = [c.value.lower() for c in categories]

        if any("pii" in c for c in category_values):
            frameworks.add("GDPR")
            frameworks.add("CCPA")
            frameworks.add("Privacy Shield")

        if any("pci" in c for c in category_values):
            frameworks.add("PCI-DSS")

        if any("phi" in c for c in category_values):
            frameworks.add("HIPAA")
            frameworks.add("HITECH")

        if any("financial" in c for c in category_values):
            frameworks.add("SOX")
            frameworks.add("GLBA")

        if any("credential" in c or "secret" in c for c in category_values):
            frameworks.add("SOC 2")
            frameworks.add("ISO 27001")

        return sorted(list(frameworks))

    def _generate_title(
        self,
        asset: PublicAsset,
        exposure_type: SensitiveExposureType,
        classification: ClassificationLevel,
    ) -> str:
        """Generate a descriptive title for the finding."""
        type_names = {
            SensitiveExposureType.PII_EXPOSURE: "PII",
            SensitiveExposureType.PCI_EXPOSURE: "Payment Card Data",
            SensitiveExposureType.PHI_EXPOSURE: "Health Information",
            SensitiveExposureType.CREDENTIAL_EXPOSURE: "Credentials",
            SensitiveExposureType.FINANCIAL_EXPOSURE: "Financial Data",
            SensitiveExposureType.CONFIDENTIAL_EXPOSURE: "Confidential Data",
            SensitiveExposureType.RESTRICTED_EXPOSURE: "Restricted Data",
        }
        type_name = type_names.get(exposure_type, "Sensitive Data")
        return f"{type_name} ({classification.value}) exposed on public {asset.exposure_type.value}: {asset.name}"

    def _generate_description(
        self,
        asset: PublicAsset,
        classification: ClassificationLevel,
        categories: list[DataCategory],
        finding_count: int,
    ) -> str:
        """Generate a detailed description."""
        category_names = [c.value for c in categories]
        return (
            f"Public resource '{asset.name}' contains {finding_count} instances of "
            f"sensitive data classified as '{classification.value}'. "
            f"Data categories detected: {', '.join(category_names)}. "
            f"This data is publicly accessible via {asset.access_method} access, "
            f"creating a significant security and compliance risk."
        )

    def _generate_remediation(
        self,
        asset: PublicAsset,
        classification: ClassificationLevel,
        categories: list[DataCategory],
    ) -> str:
        """Generate remediation recommendations."""
        if not self._config.generate_remediation:
            return ""

        steps = []

        # Primary action: Remove public access
        if asset.exposure_type == ExposureType.PUBLIC_BUCKET:
            steps.append(
                f"1. IMMEDIATE: Remove public access from '{asset.name}' by "
                f"updating bucket policy and ACLs to deny public access."
            )
        else:
            steps.append(
                f"1. IMMEDIATE: Restrict public access to '{asset.name}'."
            )

        # Secondary: Move or encrypt sensitive data
        if classification in (ClassificationLevel.RESTRICTED, ClassificationLevel.TOP_SECRET):
            steps.append(
                "2. Move sensitive data to a private, encrypted storage location "
                "with strict access controls."
            )
        else:
            steps.append(
                "2. Encrypt sensitive data at rest and enable server-side encryption."
            )

        # Tertiary: Review access
        steps.append(
            "3. Review and audit access permissions using least-privilege principles."
        )

        # Compliance check
        category_values = [c.value.lower() for c in categories]
        if any("pci" in c for c in category_values):
            steps.append(
                "4. Conduct PCI-DSS compliance review to assess breach notification requirements."
            )
        if any("phi" in c for c in category_values):
            steps.append(
                "4. Conduct HIPAA compliance review and assess breach notification requirements."
            )
        if any("pii" in c for c in category_values):
            steps.append(
                "4. Review GDPR/CCPA notification requirements for potential data exposure."
            )

        return "\n".join(steps)

    def _build_summary(
        self,
        exposures: list[SensitiveExposureFinding],
        assets_with_sensitive: int,
    ) -> SensitiveExposureSummary:
        """Build summary statistics."""
        summary = SensitiveExposureSummary(
            total_public_assets=len(self._public_assets),
            assets_with_sensitive_data=assets_with_sensitive,
            total_sensitive_findings=sum(e.total_findings_count for e in exposures),
        )

        for exposure in exposures:
            # Count by risk level
            if exposure.risk_level == ExposureRiskLevel.CRITICAL:
                summary.critical_exposures += 1
            elif exposure.risk_level == ExposureRiskLevel.HIGH:
                summary.high_exposures += 1

            # Count by type
            type_val = exposure.exposure_type.value
            summary.exposures_by_type[type_val] = summary.exposures_by_type.get(type_val, 0) + 1

            # Count by cloud
            summary.exposures_by_cloud[exposure.cloud_provider] = (
                summary.exposures_by_cloud.get(exposure.cloud_provider, 0) + 1
            )

            # Count by category
            for cat in exposure.data_categories:
                cat_val = cat.value
                summary.exposures_by_category[cat_val] = summary.exposures_by_category.get(cat_val, 0) + 1

            # Track compliance
            for framework in exposure.compliance_impact:
                if framework not in summary.compliance_frameworks_impacted:
                    summary.compliance_frameworks_impacted.append(framework)

        # Calculate average risk score
        if exposures:
            summary.average_risk_score = sum(e.risk_score for e in exposures) / len(exposures)

        # Get highest risk assets
        sorted_exposures = sorted(exposures, key=lambda e: e.risk_score, reverse=True)
        summary.highest_risk_assets = [e.asset_name for e in sorted_exposures[:5]]

        return summary


def correlate_exposure_with_dspm(
    inventory_result: ExposureInventoryResult,
    dspm_results: list[ScanResult],
    config: SensitiveExposureConfig | None = None,
) -> SensitiveExposureResult:
    """
    Convenience function to correlate exposure inventory with DSPM results.

    Args:
        inventory_result: Exposure inventory result
        dspm_results: List of DSPM scan results
        config: Optional configuration

    Returns:
        Sensitive exposure analysis result
    """
    analyzer = SensitiveDataExposureAnalyzer(config=config)
    analyzer.register_inventory_result(inventory_result)

    for result in dspm_results:
        analyzer.register_dspm_scan_result(result)

    return analyzer.analyze()
