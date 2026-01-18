"""
ASM Risk Scoring for Mantissa Stance.

This module provides risk scoring for external assets based on multiple
weighted factors including service exposure, certificate issues, technology
vulnerabilities, and shadow IT status.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from stance.asm.config import ASMConfiguration
from stance.asm.models import ExternalAsset, ExternalAssetCollection
from stance.models.finding import Finding, Severity

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk level classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Critical service ports that represent high risk when exposed
CRITICAL_PORTS = {
    3389: "rdp",  # RDP - Remote Desktop
    22: "ssh",  # SSH
    23: "telnet",  # Telnet
    3306: "mysql",  # MySQL
    5432: "postgresql",  # PostgreSQL
    1433: "mssql",  # MS SQL Server
    1521: "oracle",  # Oracle DB
    27017: "mongodb",  # MongoDB
    6379: "redis",  # Redis
    9200: "elasticsearch",  # Elasticsearch
    5900: "vnc",  # VNC
    445: "smb",  # SMB/CIFS
    135: "rpc",  # RPC
    139: "netbios",  # NetBIOS
}

# Admin panel ports/services
ADMIN_PORTS = {
    8080: "admin_http",
    8443: "admin_https",
    9090: "prometheus",
    3000: "grafana",
    8081: "admin_alt",
    9000: "portainer",
    2375: "docker",  # Docker API
    2376: "docker_tls",
    10250: "kubelet",  # Kubernetes
}

# Standard web ports (lower risk)
WEB_PORTS = {80, 443, 8080, 8443}

# Known weak certificate algorithms
WEAK_ALGORITHMS = {"MD5", "SHA1", "SHA-1", "md5WithRSAEncryption", "sha1WithRSAEncryption"}

# Minimum key sizes considered secure
MIN_RSA_KEY_SIZE = 2048
MIN_EC_KEY_SIZE = 256


@dataclass
class RiskFactor:
    """
    A single risk factor contributing to overall risk score.

    Attributes:
        name: Factor name
        score: Factor score (0.0-1.0)
        weight: Weight applied to this factor
        description: Human-readable description
    """

    name: str
    score: float  # 0.0-1.0
    weight: float
    description: str

    @property
    def weighted_score(self) -> float:
        """Calculate weighted contribution to total risk."""
        return self.score * self.weight


@dataclass
class RiskAssessment:
    """
    Complete risk assessment for an external asset.

    Attributes:
        asset_id: ID of the assessed asset
        total_score: Final risk score (0.0-10.0)
        risk_level: Categorized risk level
        factors: Individual risk factors
        assessed_at: When assessment was performed
        asset_domain: Domain of the asset
    """

    asset_id: str
    total_score: float
    risk_level: RiskLevel
    factors: list[RiskFactor] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    asset_domain: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_domain": self.asset_domain,
            "total_score": round(self.total_score, 2),
            "risk_level": self.risk_level.value,
            "assessed_at": self.assessed_at.isoformat(),
            "factors": [
                {
                    "name": f.name,
                    "score": round(f.score, 2),
                    "weight": f.weight,
                    "weighted_score": round(f.weighted_score, 2),
                    "description": f.description,
                }
                for f in self.factors
            ],
        }


@dataclass
class RiskTrend:
    """
    Risk trend information for an asset over time.

    Attributes:
        asset_id: ID of the asset
        current_score: Current risk score
        previous_score: Previous risk score
        change: Score change (positive = increasing risk)
        velocity: Rate of change category
        history: Historical scores
    """

    asset_id: str
    current_score: float
    previous_score: float
    change: float
    velocity: str  # "rapid_increase", "increasing", "stable", "decreasing", "rapid_decrease"
    history: list[tuple[datetime, float]] = field(default_factory=list)

    @property
    def is_concerning(self) -> bool:
        """Check if risk trend is concerning (rapid increase)."""
        return self.velocity == "rapid_increase"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "current_score": round(self.current_score, 2),
            "previous_score": round(self.previous_score, 2),
            "change": round(self.change, 2),
            "velocity": self.velocity,
            "is_concerning": self.is_concerning,
            "history": [(ts.isoformat(), round(score, 2)) for ts, score in self.history],
        }


class ASMRiskScorer:
    """
    Risk scorer for external assets.

    Calculates risk scores based on multiple weighted factors:
    - Service exposure (weight: 3.0)
    - Certificate issues (weight: 2.0)
    - Technology vulnerabilities (weight: 2.0)
    - Shadow IT status (weight: 2.0)
    - Data exposure (weight: 1.0)

    Total possible score: 10.0
    """

    # Default weights for risk factors
    DEFAULT_WEIGHTS = {
        "service_exposure": 3.0,
        "certificate": 2.0,
        "technology": 2.0,
        "shadow_it": 2.0,
        "data_exposure": 1.0,
    }

    def __init__(
        self,
        config: ASMConfiguration | None = None,
        weights: dict[str, float] | None = None,
    ) -> None:
        """
        Initialize the risk scorer.

        Args:
            config: ASM configuration
            weights: Custom factor weights (optional)
        """
        self.config = config or ASMConfiguration()
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._risk_history: dict[str, list[tuple[datetime, float]]] = {}

    def calculate_risk(
        self,
        asset: ExternalAsset,
        findings: list[Finding] | None = None,
        is_shadow_it: bool = False,
        has_sensitive_data: bool = False,
    ) -> RiskAssessment:
        """
        Calculate risk score for an external asset.

        Args:
            asset: External asset to assess
            findings: Related findings (if any)
            is_shadow_it: Whether asset is shadow IT (not in CSPM)
            has_sensitive_data: Whether asset handles sensitive data (from DSPM)

        Returns:
            RiskAssessment with total score and factor breakdown
        """
        findings = findings or []
        factors: list[RiskFactor] = []

        # Factor 1: Service Exposure Risk
        service_factor = self._calculate_service_exposure_risk(asset)
        factors.append(service_factor)

        # Factor 2: Certificate Risk
        cert_factor = self._calculate_certificate_risk(asset)
        factors.append(cert_factor)

        # Factor 3: Technology Risk
        tech_factor = self._calculate_technology_risk(asset, findings)
        factors.append(tech_factor)

        # Factor 4: Shadow IT Risk
        shadow_factor = self._calculate_shadow_it_risk(asset, is_shadow_it)
        factors.append(shadow_factor)

        # Factor 5: Data Exposure Risk
        data_factor = self._calculate_data_exposure_risk(asset, has_sensitive_data)
        factors.append(data_factor)

        # Calculate total score (sum of weighted factors)
        total_score = sum(f.weighted_score for f in factors)

        # Normalize to 0-10 scale (should already be there with default weights)
        total_score = min(10.0, max(0.0, total_score))

        # Determine risk level
        risk_level = self._score_to_level(total_score)

        # Update history
        self._record_risk(asset.id, total_score)

        assessment = RiskAssessment(
            asset_id=asset.id,
            total_score=total_score,
            risk_level=risk_level,
            factors=factors,
            asset_domain=asset.domain,
        )

        logger.debug(f"Risk assessment for {asset.domain}: {total_score:.2f} ({risk_level.value})")

        return assessment

    def calculate_risk_batch(
        self,
        assets: ExternalAssetCollection,
        findings_map: dict[str, list[Finding]] | None = None,
        shadow_it_ids: set[str] | None = None,
        sensitive_data_ids: set[str] | None = None,
    ) -> list[RiskAssessment]:
        """
        Calculate risk scores for multiple assets.

        Args:
            assets: Collection of external assets
            findings_map: Map of asset ID to findings
            shadow_it_ids: Set of shadow IT asset IDs
            sensitive_data_ids: Set of asset IDs with sensitive data

        Returns:
            List of RiskAssessments
        """
        findings_map = findings_map or {}
        shadow_it_ids = shadow_it_ids or set()
        sensitive_data_ids = sensitive_data_ids or set()

        assessments = []
        for asset in assets:
            assessment = self.calculate_risk(
                asset=asset,
                findings=findings_map.get(asset.id, []),
                is_shadow_it=asset.id in shadow_it_ids,
                has_sensitive_data=asset.id in sensitive_data_ids,
            )
            assessments.append(assessment)

        return assessments

    def _calculate_service_exposure_risk(self, asset: ExternalAsset) -> RiskFactor:
        """
        Calculate service exposure risk based on port and service type.

        Risk scale:
        - Critical services (RDP, SSH, DB): 1.0
        - Admin panels: 0.8
        - Standard web: 0.2
        - No port/unknown: 0.1
        """
        weight = self.weights.get("service_exposure", 3.0)

        if not asset.port:
            return RiskFactor(
                name="service_exposure",
                score=0.1,
                weight=weight,
                description="No port information available",
            )

        port = asset.port
        service = (asset.service or "").lower()

        # Critical services - highest risk
        if port in CRITICAL_PORTS or any(
            s in service
            for s in ["rdp", "ssh", "mysql", "postgres", "mongodb", "redis", "vnc", "telnet"]
        ):
            return RiskFactor(
                name="service_exposure",
                score=1.0,
                weight=weight,
                description=f"Critical service exposed: {CRITICAL_PORTS.get(port, service)} on port {port}",
            )

        # Admin panels - high risk
        if port in ADMIN_PORTS or any(
            s in service
            for s in ["admin", "grafana", "prometheus", "kibana", "jenkins", "docker", "kubernetes"]
        ):
            return RiskFactor(
                name="service_exposure",
                score=0.8,
                weight=weight,
                description=f"Admin panel exposed: {ADMIN_PORTS.get(port, service)} on port {port}",
            )

        # Standard web ports - lower risk
        if port in WEB_PORTS:
            return RiskFactor(
                name="service_exposure",
                score=0.2,
                weight=weight,
                description=f"Standard web service on port {port}",
            )

        # Other ports - medium risk
        return RiskFactor(
            name="service_exposure",
            score=0.5,
            weight=weight,
            description=f"Non-standard service on port {port}",
        )

    def _calculate_certificate_risk(self, asset: ExternalAsset) -> RiskFactor:
        """
        Calculate certificate-related risk.

        Risk scale:
        - Expired: 1.0
        - Expiring < 7 days: 0.8
        - Expiring < 30 days: 0.5
        - Weak algorithm/key: 0.6
        - Self-signed: 0.4
        - No cert (on HTTPS port): 0.7
        - Valid cert: 0.0
        """
        weight = self.weights.get("certificate", 2.0)

        # No certificate info - check if it should have one
        if not asset.certificate_info:
            if asset.port in (443, 8443) or asset.protocol == "https":
                return RiskFactor(
                    name="certificate",
                    score=0.7,
                    weight=weight,
                    description="No certificate information for HTTPS service",
                )
            return RiskFactor(
                name="certificate",
                score=0.0,
                weight=weight,
                description="Certificate not applicable (non-HTTPS service)",
            )

        cert = asset.certificate_info
        issues: list[str] = []
        max_score = 0.0

        # Check expiration
        if cert.is_expired:
            issues.append("Certificate is expired")
            max_score = max(max_score, 1.0)
        elif cert.days_until_expiry <= 7:
            issues.append(f"Certificate expires in {cert.days_until_expiry} days")
            max_score = max(max_score, 0.8)
        elif cert.days_until_expiry <= 30:
            issues.append(f"Certificate expires in {cert.days_until_expiry} days")
            max_score = max(max_score, 0.5)

        # Check for weak key
        if cert.is_weak_key:
            issues.append(f"Weak key: {cert.key_algorithm} {cert.key_size}-bit")
            max_score = max(max_score, 0.6)

        # Check for self-signed
        if cert.is_self_signed:
            issues.append("Self-signed certificate")
            max_score = max(max_score, 0.4)

        if not issues:
            return RiskFactor(
                name="certificate",
                score=0.0,
                weight=weight,
                description="Valid certificate",
            )

        return RiskFactor(
            name="certificate",
            score=max_score,
            weight=weight,
            description="; ".join(issues),
        )

    def _calculate_technology_risk(
        self,
        asset: ExternalAsset,
        findings: list[Finding],
    ) -> RiskFactor:
        """
        Calculate technology-related risk based on stack and findings.

        Risk scale:
        - Known CVE with exploit: 1.0
        - Known CVE (no exploit): 0.6
        - Outdated version detected: 0.3
        - No issues: 0.0
        """
        weight = self.weights.get("technology", 2.0)
        max_score = 0.0
        issues: list[str] = []

        # Check findings for vulnerability information
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                if "exploit" in finding.description.lower():
                    issues.append(f"Critical vulnerability with exploit: {finding.title}")
                    max_score = max(max_score, 1.0)
                else:
                    issues.append(f"Critical vulnerability: {finding.title}")
                    max_score = max(max_score, 0.8)
            elif finding.severity == Severity.HIGH:
                issues.append(f"High severity vulnerability: {finding.title}")
                max_score = max(max_score, 0.6)
            elif finding.severity == Severity.MEDIUM:
                max_score = max(max_score, 0.3)

        # Check technology stack for known risky technologies
        risky_techs = {
            "php": 0.2,  # Common target
            "wordpress": 0.3,  # Plugin vulnerabilities
            "joomla": 0.3,
            "drupal": 0.3,
            "tomcat": 0.2,
            "apache": 0.1,
            "nginx": 0.1,
        }

        for tech in asset.technology_stack:
            tech_lower = tech.lower()
            for risky, score in risky_techs.items():
                if risky in tech_lower:
                    max_score = max(max_score, score)
                    # Check for outdated versions
                    if any(v in tech_lower for v in ["1.", "2.", "3.", "4.", "5."]):
                        if "outdated" not in " ".join(issues).lower():
                            issues.append(f"Potentially outdated: {tech}")
                            max_score = max(max_score, 0.3)

        if not issues:
            if asset.technology_stack:
                return RiskFactor(
                    name="technology",
                    score=0.1,
                    weight=weight,
                    description=f"Technology detected: {', '.join(asset.technology_stack[:3])}",
                )
            return RiskFactor(
                name="technology",
                score=0.0,
                weight=weight,
                description="No technology risk factors identified",
            )

        return RiskFactor(
            name="technology",
            score=max_score,
            weight=weight,
            description="; ".join(issues[:3]),
        )

    def _calculate_shadow_it_risk(
        self,
        asset: ExternalAsset,
        is_shadow_it: bool,
    ) -> RiskFactor:
        """
        Calculate shadow IT risk.

        Risk scale:
        - Confirmed shadow IT (not in any inventory): 1.0
        - Partially tracked (in ASM but not CSPM): 0.5
        - Fully tracked: 0.0
        """
        weight = self.weights.get("shadow_it", 2.0)

        if is_shadow_it:
            # Check if cloud provider is known (indicates partial tracking)
            if asset.cloud_provider:
                return RiskFactor(
                    name="shadow_it",
                    score=0.7,
                    weight=weight,
                    description=f"Shadow IT in {asset.cloud_provider} - not in CSPM inventory",
                )
            return RiskFactor(
                name="shadow_it",
                score=1.0,
                weight=weight,
                description="Shadow IT - external asset not in any internal inventory",
            )

        return RiskFactor(
            name="shadow_it",
            score=0.0,
            weight=weight,
            description="Asset tracked in internal inventory",
        )

    def _calculate_data_exposure_risk(
        self,
        asset: ExternalAsset,
        has_sensitive_data: bool,
    ) -> RiskFactor:
        """
        Calculate data exposure risk based on DSPM classification.

        Risk scale:
        - Handles sensitive data (from DSPM): 1.0
        - Unknown data handling: 0.3
        - No sensitive data: 0.0
        """
        weight = self.weights.get("data_exposure", 1.0)

        if has_sensitive_data:
            return RiskFactor(
                name="data_exposure",
                score=1.0,
                weight=weight,
                description="Asset handles sensitive data (DSPM classification)",
            )

        # Check if service type typically handles data
        data_services = {"api", "database", "storage", "backend", "data"}
        service_lower = (asset.service or "").lower()
        domain_lower = asset.domain.lower()

        if any(s in service_lower or s in domain_lower for s in data_services):
            return RiskFactor(
                name="data_exposure",
                score=0.3,
                weight=weight,
                description="Service type may handle data (unclassified)",
            )

        return RiskFactor(
            name="data_exposure",
            score=0.0,
            weight=weight,
            description="No data exposure indicators",
        )

    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level."""
        if score > 8.0:
            return RiskLevel.CRITICAL
        if score > 6.0:
            return RiskLevel.HIGH
        if score > 4.0:
            return RiskLevel.MEDIUM
        if score > 2.0:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _record_risk(self, asset_id: str, score: float) -> None:
        """Record risk score for trend tracking."""
        if asset_id not in self._risk_history:
            self._risk_history[asset_id] = []

        self._risk_history[asset_id].append((datetime.now(timezone.utc), score))

        # Keep only last 100 records per asset
        if len(self._risk_history[asset_id]) > 100:
            self._risk_history[asset_id] = self._risk_history[asset_id][-100:]

    def get_risk_trend(self, asset_id: str) -> RiskTrend | None:
        """
        Get risk trend for an asset.

        Args:
            asset_id: Asset ID to get trend for

        Returns:
            RiskTrend if history exists, None otherwise
        """
        history = self._risk_history.get(asset_id, [])
        if len(history) < 2:
            return None

        current = history[-1][1]
        previous = history[-2][1]
        change = current - previous

        # Calculate velocity
        if change > 2.0:
            velocity = "rapid_increase"
        elif change > 0.5:
            velocity = "increasing"
        elif change < -2.0:
            velocity = "rapid_decrease"
        elif change < -0.5:
            velocity = "decreasing"
        else:
            velocity = "stable"

        return RiskTrend(
            asset_id=asset_id,
            current_score=current,
            previous_score=previous,
            change=change,
            velocity=velocity,
            history=history[-10:],  # Last 10 data points
        )

    def get_high_risk_assets(
        self,
        assessments: list[RiskAssessment],
        min_score: float = 6.0,
    ) -> list[RiskAssessment]:
        """
        Filter assessments to high-risk assets.

        Args:
            assessments: List of risk assessments
            min_score: Minimum score to consider high-risk

        Returns:
            Filtered and sorted list (highest risk first)
        """
        high_risk = [a for a in assessments if a.total_score >= min_score]
        return sorted(high_risk, key=lambda a: a.total_score, reverse=True)

    def get_risk_distribution(
        self,
        assessments: list[RiskAssessment],
    ) -> dict[str, int]:
        """
        Get distribution of risk levels.

        Args:
            assessments: List of risk assessments

        Returns:
            Dictionary mapping risk level to count
        """
        distribution = {level.value: 0 for level in RiskLevel}
        for assessment in assessments:
            distribution[assessment.risk_level.value] += 1
        return distribution

    def get_top_risk_factors(
        self,
        assessments: list[RiskAssessment],
        top_n: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Get the most common risk factors across all assessments.

        Args:
            assessments: List of risk assessments
            top_n: Number of top factors to return

        Returns:
            List of factor summaries
        """
        factor_scores: dict[str, list[float]] = {}
        factor_counts: dict[str, int] = {}

        for assessment in assessments:
            for factor in assessment.factors:
                if factor.score > 0:
                    if factor.name not in factor_scores:
                        factor_scores[factor.name] = []
                        factor_counts[factor.name] = 0
                    factor_scores[factor.name].append(factor.score)
                    factor_counts[factor.name] += 1

        # Calculate averages and sort
        results = []
        for name, scores in factor_scores.items():
            avg_score = sum(scores) / len(scores) if scores else 0
            results.append({
                "name": name,
                "count": factor_counts[name],
                "average_score": round(avg_score, 2),
                "total_contribution": round(sum(scores), 2),
            })

        results.sort(key=lambda x: x["total_contribution"], reverse=True)
        return results[:top_n]


def calculate_attack_surface_risk(
    assets: ExternalAssetCollection,
    shadow_it_ids: set[str] | None = None,
) -> dict[str, Any]:
    """
    Calculate overall attack surface risk metrics.

    Args:
        assets: Collection of external assets
        shadow_it_ids: Set of shadow IT asset IDs

    Returns:
        Dictionary with attack surface risk metrics
    """
    scorer = ASMRiskScorer()
    shadow_it_ids = shadow_it_ids or set()

    assessments = scorer.calculate_risk_batch(
        assets=assets,
        shadow_it_ids=shadow_it_ids,
    )

    distribution = scorer.get_risk_distribution(assessments)
    top_factors = scorer.get_top_risk_factors(assessments)
    high_risk = scorer.get_high_risk_assets(assessments)

    total_score = sum(a.total_score for a in assessments)
    avg_score = total_score / len(assessments) if assessments else 0

    return {
        "total_assets": len(assets),
        "average_risk_score": round(avg_score, 2),
        "risk_distribution": distribution,
        "high_risk_count": len(high_risk),
        "critical_count": distribution.get("critical", 0),
        "top_risk_factors": top_factors,
        "highest_risk_assets": [
            {
                "domain": a.asset_domain,
                "score": round(a.total_score, 2),
                "level": a.risk_level.value,
            }
            for a in high_risk[:10]
        ],
    }
