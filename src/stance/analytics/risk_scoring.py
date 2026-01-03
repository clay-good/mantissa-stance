"""
Risk Scoring for Mantissa Stance.

Calculates risk scores for assets based on exposure, findings, compliance
status, and relationships within the asset graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from stance.analytics.asset_graph import AssetGraph, AssetNode
from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingCollection, Severity


@dataclass
class RiskFactors:
    """
    Individual risk factors that contribute to an asset's risk score.

    Attributes:
        exposure_score: Risk from network exposure (0-100)
        finding_score: Risk from security findings (0-100)
        compliance_score: Risk from compliance violations (0-100)
        relationship_score: Risk from connected assets (0-100)
        age_score: Risk from resource age/staleness (0-100)
    """

    exposure_score: float = 0.0
    finding_score: float = 0.0
    compliance_score: float = 0.0
    relationship_score: float = 0.0
    age_score: float = 0.0

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return {
            "exposure_score": self.exposure_score,
            "finding_score": self.finding_score,
            "compliance_score": self.compliance_score,
            "relationship_score": self.relationship_score,
            "age_score": self.age_score,
        }


@dataclass
class RiskScore:
    """
    Complete risk assessment for an asset.

    Attributes:
        asset_id: ID of the assessed asset
        overall_score: Combined risk score (0-100)
        risk_level: Risk level category
        factors: Individual risk factors
        top_risks: List of top risk contributors
        recommendations: Suggested risk mitigation actions
        last_updated: When the score was calculated
    """

    asset_id: str
    overall_score: float
    risk_level: str
    factors: RiskFactors
    top_risks: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    last_updated: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "factors": self.factors.to_dict(),
            "top_risks": self.top_risks,
            "recommendations": self.recommendations,
            "last_updated": self.last_updated.isoformat(),
        }


@dataclass
class RiskTrend:
    """
    Risk score trend over time for an asset.

    Attributes:
        asset_id: ID of the asset
        scores: List of (timestamp, score) tuples
        trend_direction: 'improving', 'worsening', or 'stable'
        change_percentage: Percentage change from oldest to newest
    """

    asset_id: str
    scores: list[tuple[datetime, float]] = field(default_factory=list)
    trend_direction: str = "stable"
    change_percentage: float = 0.0

    def add_score(self, timestamp: datetime, score: float) -> None:
        """Add a new score to the trend."""
        self.scores.append((timestamp, score))
        self.scores.sort(key=lambda x: x[0])
        self._calculate_trend()

    def _calculate_trend(self) -> None:
        """Calculate trend direction and change percentage."""
        if len(self.scores) < 2:
            self.trend_direction = "stable"
            self.change_percentage = 0.0
            return

        oldest = self.scores[0][1]
        newest = self.scores[-1][1]

        if oldest == 0:
            self.change_percentage = 100.0 if newest > 0 else 0.0
        else:
            self.change_percentage = ((newest - oldest) / oldest) * 100

        if self.change_percentage > 5:
            self.trend_direction = "worsening"
        elif self.change_percentage < -5:
            self.trend_direction = "improving"
        else:
            self.trend_direction = "stable"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "scores": [
                {"timestamp": ts.isoformat(), "score": score}
                for ts, score in self.scores
            ],
            "trend_direction": self.trend_direction,
            "change_percentage": self.change_percentage,
        }


class RiskScorer:
    """
    Calculates risk scores for cloud assets.

    Considers multiple factors including network exposure, security findings,
    compliance status, and relationships with other assets.
    """

    # Weight factors for different risk components
    WEIGHTS = {
        "exposure": 0.25,
        "findings": 0.35,
        "compliance": 0.20,
        "relationships": 0.10,
        "age": 0.10,
    }

    # Severity to score multipliers
    SEVERITY_SCORES = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 75,
        Severity.MEDIUM: 50,
        Severity.LOW: 25,
        Severity.INFO: 10,
    }

    # Risk level thresholds
    RISK_LEVELS = [
        (90, "critical"),
        (70, "high"),
        (40, "medium"),
        (20, "low"),
        (0, "minimal"),
    ]

    def __init__(
        self,
        graph: AssetGraph | None = None,
        findings: FindingCollection | None = None,
    ) -> None:
        """
        Initialize the risk scorer.

        Args:
            graph: Optional asset graph for relationship analysis
            findings: Optional findings collection
        """
        self._graph = graph
        self._findings = findings
        self._findings_by_asset: dict[str, list[Finding]] = {}
        self._score_history: dict[str, RiskTrend] = {}

        if findings:
            for finding in findings.findings:
                if finding.asset_id not in self._findings_by_asset:
                    self._findings_by_asset[finding.asset_id] = []
                self._findings_by_asset[finding.asset_id].append(finding)

    def score_asset(self, asset: Asset) -> RiskScore:
        """
        Calculate the risk score for a single asset.

        Args:
            asset: Asset to score

        Returns:
            RiskScore with detailed breakdown
        """
        factors = RiskFactors(
            exposure_score=self._calculate_exposure_score(asset),
            finding_score=self._calculate_finding_score(asset),
            compliance_score=self._calculate_compliance_score(asset),
            relationship_score=self._calculate_relationship_score(asset),
            age_score=self._calculate_age_score(asset),
        )

        # Calculate weighted overall score
        overall = (
            factors.exposure_score * self.WEIGHTS["exposure"]
            + factors.finding_score * self.WEIGHTS["findings"]
            + factors.compliance_score * self.WEIGHTS["compliance"]
            + factors.relationship_score * self.WEIGHTS["relationships"]
            + factors.age_score * self.WEIGHTS["age"]
        )

        # Determine risk level
        risk_level = self._get_risk_level(overall)

        # Identify top risks
        top_risks = self._identify_top_risks(asset, factors)

        # Generate recommendations
        recommendations = self._generate_recommendations(asset, factors, top_risks)

        score = RiskScore(
            asset_id=asset.id,
            overall_score=round(overall, 2),
            risk_level=risk_level,
            factors=factors,
            top_risks=top_risks,
            recommendations=recommendations,
        )

        # Track trend
        self._update_trend(asset.id, overall)

        return score

    def score_collection(self, assets: AssetCollection) -> list[RiskScore]:
        """
        Calculate risk scores for all assets in a collection.

        Args:
            assets: Collection of assets to score

        Returns:
            List of RiskScores sorted by overall score (highest first)
        """
        scores = [self.score_asset(asset) for asset in assets.assets]
        scores.sort(key=lambda s: s.overall_score, reverse=True)
        return scores

    def get_trend(self, asset_id: str) -> RiskTrend | None:
        """Get the risk trend for an asset."""
        return self._score_history.get(asset_id)

    def get_high_risk_assets(
        self,
        assets: AssetCollection,
        threshold: float = 70.0,
    ) -> list[RiskScore]:
        """
        Get assets with risk scores above a threshold.

        Args:
            assets: Collection of assets to check
            threshold: Minimum risk score to include

        Returns:
            List of high-risk RiskScores
        """
        scores = self.score_collection(assets)
        return [s for s in scores if s.overall_score >= threshold]

    def aggregate_risk(self, assets: AssetCollection) -> dict[str, Any]:
        """
        Calculate aggregate risk metrics for an asset collection.

        Args:
            assets: Collection of assets

        Returns:
            Dictionary with aggregate risk metrics
        """
        scores = self.score_collection(assets)

        if not scores:
            return {
                "total_assets": 0,
                "average_score": 0,
                "median_score": 0,
                "max_score": 0,
                "min_score": 0,
                "by_level": {},
            }

        score_values = [s.overall_score for s in scores]
        score_values.sort()

        by_level: dict[str, int] = {}
        for score in scores:
            by_level[score.risk_level] = by_level.get(score.risk_level, 0) + 1

        median_idx = len(score_values) // 2
        median = (
            score_values[median_idx]
            if len(score_values) % 2 == 1
            else (score_values[median_idx - 1] + score_values[median_idx]) / 2
        )

        return {
            "total_assets": len(scores),
            "average_score": round(sum(score_values) / len(score_values), 2),
            "median_score": round(median, 2),
            "max_score": max(score_values),
            "min_score": min(score_values),
            "by_level": by_level,
        }

    def _calculate_exposure_score(self, asset: Asset) -> float:
        """Calculate exposure score based on network visibility."""
        if asset.is_internet_facing():
            return 100.0
        elif asset.network_exposure == "internal":
            return 40.0
        elif asset.network_exposure == "isolated":
            return 10.0
        else:
            return 50.0  # Unknown exposure

    def _calculate_finding_score(self, asset: Asset) -> float:
        """Calculate score based on security findings."""
        findings = self._findings_by_asset.get(asset.id, [])

        if not findings:
            return 0.0

        # Sum of severity scores, capped at 100
        total = 0.0
        for finding in findings:
            if finding.status.value == "open":
                total += self.SEVERITY_SCORES.get(finding.severity, 10)

        return min(100.0, total)

    def _calculate_compliance_score(self, asset: Asset) -> float:
        """Calculate score based on compliance violations."""
        findings = self._findings_by_asset.get(asset.id, [])

        # Count findings with compliance framework mappings
        compliance_violations = 0
        for finding in findings:
            if finding.status.value == "open" and finding.compliance_frameworks:
                compliance_violations += 1

        if compliance_violations == 0:
            return 0.0
        elif compliance_violations <= 2:
            return 30.0
        elif compliance_violations <= 5:
            return 60.0
        else:
            return 90.0

    def _calculate_relationship_score(self, asset: Asset) -> float:
        """Calculate score based on connected assets' risk."""
        if not self._graph:
            return 0.0

        node = self._graph.get_node(asset.id)
        if not node:
            return 0.0

        # Get connected assets
        connected_ids = node.get_neighbors()
        if not connected_ids:
            return 0.0

        # Calculate average finding score of connected assets
        connected_scores = []
        for neighbor_id in connected_ids:
            neighbor_findings = self._findings_by_asset.get(neighbor_id, [])
            if neighbor_findings:
                neighbor_score = sum(
                    self.SEVERITY_SCORES.get(f.severity, 10)
                    for f in neighbor_findings
                    if f.status.value == "open"
                )
                connected_scores.append(min(100.0, neighbor_score))

        if not connected_scores:
            return 0.0

        # Return weighted score (max of 50 to not dominate overall)
        avg_connected = sum(connected_scores) / len(connected_scores)
        return min(50.0, avg_connected * 0.5)

    def _calculate_age_score(self, asset: Asset) -> float:
        """Calculate score based on resource age and staleness."""
        now = datetime.utcnow()

        # Check last_seen - stale resources are risky
        if asset.last_seen:
            days_since_seen = (now - asset.last_seen).days
            if days_since_seen > 30:
                return 80.0
            elif days_since_seen > 7:
                return 40.0
            elif days_since_seen > 1:
                return 20.0

        # Check created_at - older resources may have legacy configs
        if asset.created_at:
            age_days = (now - asset.created_at).days
            if age_days > 365:
                return 30.0
            elif age_days > 180:
                return 20.0

        return 10.0

    def _get_risk_level(self, score: float) -> str:
        """Convert numeric score to risk level category."""
        for threshold, level in self.RISK_LEVELS:
            if score >= threshold:
                return level
        return "minimal"

    def _identify_top_risks(
        self, asset: Asset, factors: RiskFactors
    ) -> list[str]:
        """Identify the top risk contributors for an asset."""
        risks: list[tuple[float, str]] = []

        if factors.exposure_score >= 80:
            risks.append(
                (factors.exposure_score, "Internet-facing resource with high exposure")
            )

        if factors.finding_score >= 80:
            risks.append(
                (factors.finding_score, "Multiple critical or high severity findings")
            )
        elif factors.finding_score >= 50:
            risks.append((factors.finding_score, "Security findings present"))

        if factors.compliance_score >= 60:
            risks.append(
                (factors.compliance_score, "Multiple compliance framework violations")
            )

        if factors.relationship_score >= 40:
            risks.append(
                (factors.relationship_score, "Connected to high-risk assets")
            )

        if factors.age_score >= 60:
            risks.append((factors.age_score, "Stale resource (not recently scanned)"))

        # Sort by score and return top 3 descriptions
        risks.sort(reverse=True)
        return [r[1] for r in risks[:3]]

    def _generate_recommendations(
        self, asset: Asset, factors: RiskFactors, top_risks: list[str]
    ) -> list[str]:
        """Generate risk mitigation recommendations."""
        recommendations: list[str] = []

        if factors.exposure_score >= 80:
            recommendations.append(
                "Review and restrict network access to this resource"
            )

        if factors.finding_score >= 50:
            findings = self._findings_by_asset.get(asset.id, [])
            critical_count = sum(
                1 for f in findings if f.severity == Severity.CRITICAL
            )
            if critical_count > 0:
                recommendations.append(
                    f"Address {critical_count} critical finding(s) immediately"
                )
            else:
                recommendations.append("Review and remediate open security findings")

        if factors.compliance_score >= 60:
            recommendations.append(
                "Review compliance violations and implement required controls"
            )

        if factors.age_score >= 60:
            recommendations.append("Verify resource is still active and re-scan")

        if not recommendations:
            recommendations.append("Continue monitoring and maintain current posture")

        return recommendations

    def _update_trend(self, asset_id: str, score: float) -> None:
        """Update the risk trend for an asset."""
        if asset_id not in self._score_history:
            self._score_history[asset_id] = RiskTrend(asset_id=asset_id)

        self._score_history[asset_id].add_score(datetime.utcnow(), score)
