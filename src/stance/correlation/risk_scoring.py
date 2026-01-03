"""
Risk scoring for Mantissa Stance.

Provides risk score calculation based on findings,
asset exposure, compliance status, and trends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from stance.models.asset import Asset, AssetCollection
from stance.models.finding import (
    Finding,
    FindingCollection,
    FindingStatus,
    FindingType,
    Severity,
)


class RiskLevel(Enum):
    """Risk level classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class RiskFactor:
    """
    Individual risk factor contributing to overall score.

    Attributes:
        name: Factor name
        category: Factor category (exposure, findings, compliance, etc.)
        weight: Weight multiplier for this factor
        score: Raw score before weighting (0-100)
        weighted_score: Score after applying weight
        details: Additional details about the factor
    """

    name: str
    category: str
    weight: float
    score: float
    weighted_score: float = field(init=False)
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.weighted_score = self.score * self.weight


@dataclass
class AssetRiskScore:
    """
    Risk score for a single asset.

    Attributes:
        asset_id: Asset identifier
        asset_name: Human-readable asset name
        asset_type: Resource type
        cloud_provider: Cloud provider
        overall_score: Combined risk score (0-100)
        risk_level: Classified risk level
        factors: Individual risk factors
        finding_count: Number of open findings
        critical_findings: Count of critical findings
        high_findings: Count of high findings
        exposure_level: Network exposure classification
        compliance_gaps: List of compliance framework gaps
        calculated_at: Timestamp of calculation
    """

    asset_id: str
    asset_name: str
    asset_type: str
    cloud_provider: str
    overall_score: float
    risk_level: RiskLevel
    factors: list[RiskFactor]
    finding_count: int
    critical_findings: int
    high_findings: int
    exposure_level: str
    compliance_gaps: list[str]
    calculated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "asset_type": self.asset_type,
            "cloud_provider": self.cloud_provider,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level.value,
            "factors": [
                {
                    "name": f.name,
                    "category": f.category,
                    "weight": f.weight,
                    "score": f.score,
                    "weighted_score": f.weighted_score,
                    "details": f.details,
                }
                for f in self.factors
            ],
            "finding_count": self.finding_count,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "exposure_level": self.exposure_level,
            "compliance_gaps": self.compliance_gaps,
            "calculated_at": self.calculated_at.isoformat(),
        }


@dataclass
class RiskTrend:
    """
    Risk trend over time.

    Attributes:
        period_start: Start of trend period
        period_end: End of trend period
        start_score: Score at period start
        end_score: Score at period end
        change: Absolute change in score
        change_percentage: Percentage change
        direction: Trend direction (improving, worsening, stable)
        data_points: Historical data points
    """

    period_start: datetime
    period_end: datetime
    start_score: float
    end_score: float
    change: float = field(init=False)
    change_percentage: float = field(init=False)
    direction: str = field(init=False)
    data_points: list[tuple[datetime, float]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.change = self.end_score - self.start_score
        if self.start_score > 0:
            self.change_percentage = (self.change / self.start_score) * 100
        else:
            self.change_percentage = 0.0

        if self.change > 5:
            self.direction = "worsening"
        elif self.change < -5:
            self.direction = "improving"
        else:
            self.direction = "stable"


@dataclass
class RiskScoringResult:
    """
    Complete risk scoring result.

    Attributes:
        asset_scores: Individual asset risk scores
        overall_score: Organization-wide risk score
        overall_risk_level: Organization risk level
        top_risks: Assets with highest risk
        risk_by_cloud: Risk breakdown by cloud provider
        risk_by_type: Risk breakdown by resource type
        trend: Risk trend if historical data available
        calculated_at: Timestamp of calculation
    """

    asset_scores: list[AssetRiskScore]
    overall_score: float
    overall_risk_level: RiskLevel
    top_risks: list[AssetRiskScore]
    risk_by_cloud: dict[str, float]
    risk_by_type: dict[str, float]
    trend: RiskTrend | None
    calculated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "asset_scores": [s.to_dict() for s in self.asset_scores],
            "overall_score": self.overall_score,
            "overall_risk_level": self.overall_risk_level.value,
            "top_risks": [s.to_dict() for s in self.top_risks],
            "risk_by_cloud": self.risk_by_cloud,
            "risk_by_type": self.risk_by_type,
            "trend": {
                "period_start": self.trend.period_start.isoformat(),
                "period_end": self.trend.period_end.isoformat(),
                "start_score": self.trend.start_score,
                "end_score": self.trend.end_score,
                "change": self.trend.change,
                "change_percentage": self.trend.change_percentage,
                "direction": self.trend.direction,
            } if self.trend else None,
            "calculated_at": self.calculated_at.isoformat(),
        }


class RiskScorer:
    """
    Calculates risk scores for assets and organization.

    Risk score components:
    - Finding severity (40% weight)
    - Network exposure (25% weight)
    - Compliance gaps (20% weight)
    - Asset criticality (15% weight)

    Scores range from 0 (minimal risk) to 100 (critical risk).
    """

    # Default weights for risk factors
    DEFAULT_WEIGHTS = {
        "findings": 0.40,
        "exposure": 0.25,
        "compliance": 0.20,
        "criticality": 0.15,
    }

    # Severity scores
    SEVERITY_SCORES = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 75,
        Severity.MEDIUM: 50,
        Severity.LOW: 25,
        Severity.INFO: 5,
    }

    # Exposure scores
    EXPOSURE_SCORES = {
        "internet_facing": 100,
        "internal": 40,
        "isolated": 10,
    }

    # Critical resource types (higher base criticality)
    CRITICAL_RESOURCE_TYPES = {
        "aws_iam_user",
        "aws_iam_role",
        "aws_s3_bucket",
        "aws_rds_instance",
        "aws_secretsmanager_secret",
        "gcp_iam_service_account",
        "gcp_storage_bucket",
        "gcp_sql_instance",
        "azure_ad_user",
        "azure_storage_account",
        "azure_sql_database",
        "azure_key_vault",
    }

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        critical_resource_types: set[str] | None = None,
        historical_scores: list[tuple[datetime, float]] | None = None,
    ):
        """
        Initialize risk scorer.

        Args:
            weights: Custom weights for risk factors
            critical_resource_types: Resource types considered critical
            historical_scores: Historical scores for trend analysis
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self.critical_resource_types = (
            critical_resource_types or self.CRITICAL_RESOURCE_TYPES.copy()
        )
        self.historical_scores = historical_scores or []

    def calculate_scores(
        self,
        findings: FindingCollection | list[Finding],
        assets: AssetCollection | list[Asset],
        compliance_results: dict[str, dict[str, Any]] | None = None,
    ) -> RiskScoringResult:
        """
        Calculate risk scores for all assets.

        Args:
            findings: Collection of findings
            assets: Collection of assets
            compliance_results: Optional compliance framework results

        Returns:
            Complete risk scoring result
        """
        if isinstance(findings, FindingCollection):
            findings_list = list(findings.findings)
        else:
            findings_list = findings

        if isinstance(assets, AssetCollection):
            assets_list = list(assets.assets)
        else:
            assets_list = assets

        # Filter to open findings only
        open_findings = [
            f for f in findings_list
            if f.status == FindingStatus.OPEN
        ]

        # Build asset -> findings mapping
        findings_by_asset: dict[str, list[Finding]] = {}
        for finding in open_findings:
            asset_id = finding.asset_id
            if asset_id not in findings_by_asset:
                findings_by_asset[asset_id] = []
            findings_by_asset[asset_id].append(finding)

        # Calculate score for each asset
        asset_scores: list[AssetRiskScore] = []
        for asset in assets_list:
            asset_findings = findings_by_asset.get(asset.id, [])
            score = self._calculate_asset_score(
                asset,
                asset_findings,
                compliance_results,
            )
            asset_scores.append(score)

        # Calculate overall organization score
        overall_score = self._calculate_overall_score(asset_scores)
        overall_risk_level = self._classify_risk_level(overall_score)

        # Get top risks
        top_risks = sorted(
            asset_scores,
            key=lambda s: s.overall_score,
            reverse=True,
        )[:10]

        # Calculate risk by cloud provider
        risk_by_cloud = self._calculate_risk_by_dimension(
            asset_scores,
            lambda s: s.cloud_provider,
        )

        # Calculate risk by resource type
        risk_by_type = self._calculate_risk_by_dimension(
            asset_scores,
            lambda s: s.asset_type,
        )

        # Calculate trend
        trend = self._calculate_trend(overall_score)

        # Store current score for future trend analysis
        self.historical_scores.append((datetime.utcnow(), overall_score))

        return RiskScoringResult(
            asset_scores=asset_scores,
            overall_score=overall_score,
            overall_risk_level=overall_risk_level,
            top_risks=top_risks,
            risk_by_cloud=risk_by_cloud,
            risk_by_type=risk_by_type,
            trend=trend,
        )

    def _calculate_asset_score(
        self,
        asset: Asset,
        findings: list[Finding],
        compliance_results: dict[str, dict[str, Any]] | None,
    ) -> AssetRiskScore:
        """Calculate risk score for a single asset."""
        factors: list[RiskFactor] = []

        # Factor 1: Findings severity
        findings_score, findings_details = self._calculate_findings_factor(findings)
        factors.append(RiskFactor(
            name="Finding Severity",
            category="findings",
            weight=self.weights["findings"],
            score=findings_score,
            details=findings_details,
        ))

        # Factor 2: Network exposure
        exposure_score, exposure_details = self._calculate_exposure_factor(asset)
        factors.append(RiskFactor(
            name="Network Exposure",
            category="exposure",
            weight=self.weights["exposure"],
            score=exposure_score,
            details=exposure_details,
        ))

        # Factor 3: Compliance gaps
        compliance_score, compliance_details = self._calculate_compliance_factor(
            asset,
            findings,
            compliance_results,
        )
        factors.append(RiskFactor(
            name="Compliance Gaps",
            category="compliance",
            weight=self.weights["compliance"],
            score=compliance_score,
            details=compliance_details,
        ))

        # Factor 4: Asset criticality
        criticality_score, criticality_details = self._calculate_criticality_factor(
            asset,
        )
        factors.append(RiskFactor(
            name="Asset Criticality",
            category="criticality",
            weight=self.weights["criticality"],
            score=criticality_score,
            details=criticality_details,
        ))

        # Calculate overall score (weighted sum)
        overall_score = sum(f.weighted_score for f in factors)

        # Ensure score is within bounds
        overall_score = max(0, min(100, overall_score))

        # Count findings by severity
        critical_count = sum(
            1 for f in findings if f.severity == Severity.CRITICAL
        )
        high_count = sum(
            1 for f in findings if f.severity == Severity.HIGH
        )

        # Get compliance gaps
        compliance_gaps = compliance_details.get("gaps", [])

        return AssetRiskScore(
            asset_id=asset.id,
            asset_name=asset.name,
            asset_type=asset.resource_type,
            cloud_provider=asset.cloud_provider,
            overall_score=overall_score,
            risk_level=self._classify_risk_level(overall_score),
            factors=factors,
            finding_count=len(findings),
            critical_findings=critical_count,
            high_findings=high_count,
            exposure_level=asset.network_exposure,
            compliance_gaps=compliance_gaps,
        )

    def _calculate_findings_factor(
        self,
        findings: list[Finding],
    ) -> tuple[float, dict[str, Any]]:
        """Calculate findings severity factor."""
        if not findings:
            return 0.0, {"count": 0, "breakdown": {}}

        # Calculate weighted severity score
        total_severity_score = 0
        severity_counts: dict[str, int] = {}

        for finding in findings:
            severity_score = self.SEVERITY_SCORES.get(finding.severity, 0)
            total_severity_score += severity_score

            severity_name = finding.severity.value
            severity_counts[severity_name] = severity_counts.get(severity_name, 0) + 1

        # Normalize: max score is if all findings were critical
        # Use diminishing returns for multiple findings
        base_score = total_severity_score / len(findings)

        # Apply multiplier for finding count (more findings = higher risk)
        count_multiplier = min(2.0, 1 + (len(findings) - 1) * 0.1)

        score = min(100, base_score * count_multiplier)

        return score, {
            "count": len(findings),
            "breakdown": severity_counts,
            "average_severity": base_score,
        }

    def _calculate_exposure_factor(
        self,
        asset: Asset,
    ) -> tuple[float, dict[str, Any]]:
        """Calculate network exposure factor."""
        exposure = asset.network_exposure
        score = self.EXPOSURE_SCORES.get(exposure, 50)

        return score, {
            "exposure_level": exposure,
            "is_internet_facing": exposure == "internet_facing",
        }

    def _calculate_compliance_factor(
        self,
        asset: Asset,
        findings: list[Finding],
        compliance_results: dict[str, dict[str, Any]] | None,
    ) -> tuple[float, dict[str, Any]]:
        """Calculate compliance gaps factor."""
        gaps: list[str] = []
        frameworks_affected: set[str] = set()

        # Extract compliance frameworks from findings
        for finding in findings:
            if finding.compliance_frameworks:
                for framework in finding.compliance_frameworks:
                    frameworks_affected.add(framework)
                    gaps.append(f"{framework}: {finding.title}")

        # Check compliance results if provided
        if compliance_results and asset.id in compliance_results:
            asset_compliance = compliance_results[asset.id]
            for framework, status in asset_compliance.items():
                if not status.get("compliant", True):
                    frameworks_affected.add(framework)
                    for control in status.get("failed_controls", []):
                        gaps.append(f"{framework}: {control}")

        # Score based on number of affected frameworks
        if not frameworks_affected:
            score = 0.0
        elif len(frameworks_affected) == 1:
            score = 40.0
        elif len(frameworks_affected) <= 3:
            score = 70.0
        else:
            score = 100.0

        return score, {
            "frameworks_affected": list(frameworks_affected),
            "gaps": gaps[:10],  # Limit to top 10 gaps
            "gap_count": len(gaps),
        }

    def _calculate_criticality_factor(
        self,
        asset: Asset,
    ) -> tuple[float, dict[str, Any]]:
        """Calculate asset criticality factor."""
        is_critical_type = asset.resource_type in self.critical_resource_types

        # Check tags for criticality indicators
        criticality_tag = asset.get_tag("criticality", "").lower()
        environment_tag = asset.get_tag("environment", "").lower()

        # Base score from resource type
        if is_critical_type:
            base_score = 70.0
        else:
            base_score = 30.0

        # Adjust based on tags
        if criticality_tag in ("critical", "high"):
            base_score = max(base_score, 80.0)
        elif criticality_tag == "medium":
            base_score = max(base_score, 50.0)
        elif criticality_tag == "low":
            base_score = min(base_score, 40.0)

        # Adjust based on environment
        if environment_tag == "production":
            base_score = min(100, base_score * 1.3)
        elif environment_tag == "staging":
            base_score = base_score * 0.8
        elif environment_tag in ("development", "dev"):
            base_score = base_score * 0.5

        return base_score, {
            "is_critical_type": is_critical_type,
            "criticality_tag": criticality_tag,
            "environment": environment_tag,
        }

    def _calculate_overall_score(
        self,
        asset_scores: list[AssetRiskScore],
    ) -> float:
        """Calculate organization-wide risk score."""
        if not asset_scores:
            return 0.0

        # Weight assets by their individual scores
        # Higher-risk assets contribute more to overall score
        total_weighted_score = 0.0
        total_weight = 0.0

        for score in asset_scores:
            # Assets with higher risk get more weight
            weight = 1 + (score.overall_score / 100)
            total_weighted_score += score.overall_score * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        weighted_average = total_weighted_score / total_weight

        # Apply penalty for number of high-risk assets
        high_risk_count = sum(
            1 for s in asset_scores
            if s.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)
        )

        if high_risk_count > 0:
            penalty = min(20, high_risk_count * 2)
            weighted_average = min(100, weighted_average + penalty)

        return round(weighted_average, 2)

    def _calculate_risk_by_dimension(
        self,
        asset_scores: list[AssetRiskScore],
        dimension_fn,
    ) -> dict[str, float]:
        """Calculate average risk by a dimension (cloud, type, etc.)."""
        scores_by_dimension: dict[str, list[float]] = {}

        for score in asset_scores:
            dimension = dimension_fn(score)
            if dimension not in scores_by_dimension:
                scores_by_dimension[dimension] = []
            scores_by_dimension[dimension].append(score.overall_score)

        return {
            dimension: round(sum(scores) / len(scores), 2)
            for dimension, scores in scores_by_dimension.items()
        }

    def _calculate_trend(
        self,
        current_score: float,
    ) -> RiskTrend | None:
        """Calculate risk trend from historical data."""
        if len(self.historical_scores) < 2:
            return None

        # Get scores from last 30 days
        cutoff = datetime.utcnow() - timedelta(days=30)
        recent_scores = [
            (ts, score) for ts, score in self.historical_scores
            if ts >= cutoff
        ]

        if len(recent_scores) < 2:
            return None

        # Sort by timestamp
        recent_scores.sort(key=lambda x: x[0])

        first_ts, first_score = recent_scores[0]

        return RiskTrend(
            period_start=first_ts,
            period_end=datetime.utcnow(),
            start_score=first_score,
            end_score=current_score,
            data_points=recent_scores,
        )

    def _classify_risk_level(self, score: float) -> RiskLevel:
        """Classify risk score into risk level."""
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def get_risk_summary(
        self,
        result: RiskScoringResult,
    ) -> dict[str, Any]:
        """
        Generate executive risk summary.

        Args:
            result: Risk scoring result

        Returns:
            Summary dictionary suitable for reporting
        """
        # Count assets by risk level
        risk_distribution = {
            RiskLevel.CRITICAL.value: 0,
            RiskLevel.HIGH.value: 0,
            RiskLevel.MEDIUM.value: 0,
            RiskLevel.LOW.value: 0,
            RiskLevel.MINIMAL.value: 0,
        }

        for score in result.asset_scores:
            risk_distribution[score.risk_level.value] += 1

        # Identify top risk categories
        risk_categories: dict[str, int] = {}
        for score in result.top_risks:
            for factor in score.factors:
                if factor.score >= 70:
                    category = factor.category
                    risk_categories[category] = risk_categories.get(category, 0) + 1

        return {
            "overall_score": result.overall_score,
            "overall_risk_level": result.overall_risk_level.value,
            "total_assets": len(result.asset_scores),
            "risk_distribution": risk_distribution,
            "critical_assets": risk_distribution[RiskLevel.CRITICAL.value],
            "high_risk_assets": risk_distribution[RiskLevel.HIGH.value],
            "top_risk_categories": risk_categories,
            "trend_direction": result.trend.direction if result.trend else "unknown",
            "trend_change": result.trend.change_percentage if result.trend else 0,
            "highest_risk_cloud": max(
                result.risk_by_cloud.items(),
                key=lambda x: x[1],
                default=("none", 0),
            )[0] if result.risk_by_cloud else "none",
            "calculated_at": result.calculated_at.isoformat(),
        }
