"""
Unit tests for ASM risk scoring.

Tests cover:
- RiskLevel enum
- RiskFactor dataclass
- RiskAssessment dataclass
- RiskTrend dataclass
- ASMRiskScorer calculation logic
- Utility function calculate_attack_surface_risk
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from stance.asm.models import (
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.risk import (
    ADMIN_PORTS,
    ASMRiskScorer,
    CRITICAL_PORTS,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    RiskTrend,
    WEB_PORTS,
    calculate_attack_surface_risk,
)
from stance.models.finding import Finding, FindingStatus, FindingType, Severity


# ============================================================================
# Enum Tests
# ============================================================================


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_level_values(self) -> None:
        """Test RiskLevel enum values."""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"


# ============================================================================
# Port Constants Tests
# ============================================================================


class TestPortConstants:
    """Tests for port risk constants."""

    def test_critical_ports(self) -> None:
        """Test critical ports include expected services."""
        assert 3389 in CRITICAL_PORTS  # RDP
        assert 22 in CRITICAL_PORTS  # SSH
        assert 3306 in CRITICAL_PORTS  # MySQL
        assert 5432 in CRITICAL_PORTS  # PostgreSQL
        assert 27017 in CRITICAL_PORTS  # MongoDB
        assert 6379 in CRITICAL_PORTS  # Redis

    def test_admin_ports(self) -> None:
        """Test admin ports include expected services."""
        assert 8080 in ADMIN_PORTS
        assert 9090 in ADMIN_PORTS  # Prometheus
        assert 3000 in ADMIN_PORTS  # Grafana
        assert 2375 in ADMIN_PORTS  # Docker API

    def test_web_ports(self) -> None:
        """Test web ports include standard HTTP/HTTPS."""
        assert 80 in WEB_PORTS
        assert 443 in WEB_PORTS


# ============================================================================
# RiskFactor Tests
# ============================================================================


class TestRiskFactor:
    """Tests for RiskFactor dataclass."""

    def test_create_risk_factor(self) -> None:
        """Test creating a risk factor."""
        factor = RiskFactor(
            name="service_exposure",
            score=0.8,
            weight=3.0,
            description="Critical service exposed",
        )

        assert factor.name == "service_exposure"
        assert factor.score == 0.8
        assert factor.weight == 3.0

    def test_weighted_score(self) -> None:
        """Test weighted score calculation."""
        factor = RiskFactor(
            name="test",
            score=0.5,
            weight=2.0,
            description="Test factor",
        )

        assert factor.weighted_score == 1.0  # 0.5 * 2.0


# ============================================================================
# RiskAssessment Tests
# ============================================================================


class TestRiskAssessment:
    """Tests for RiskAssessment dataclass."""

    def test_create_assessment(self) -> None:
        """Test creating a risk assessment."""
        assessment = RiskAssessment(
            asset_id="asset-001",
            total_score=7.5,
            risk_level=RiskLevel.HIGH,
            asset_domain="example.com",
        )

        assert assessment.asset_id == "asset-001"
        assert assessment.total_score == 7.5
        assert assessment.risk_level == RiskLevel.HIGH

    def test_assessment_to_dict(self) -> None:
        """Test RiskAssessment serialization."""
        factor = RiskFactor(
            name="test",
            score=0.5,
            weight=2.0,
            description="Test",
        )

        assessment = RiskAssessment(
            asset_id="asset-001",
            total_score=5.0,
            risk_level=RiskLevel.MEDIUM,
            factors=[factor],
            asset_domain="example.com",
        )

        data = assessment.to_dict()
        assert data["asset_id"] == "asset-001"
        assert data["total_score"] == 5.0
        assert data["risk_level"] == "medium"
        assert len(data["factors"]) == 1


# ============================================================================
# RiskTrend Tests
# ============================================================================


class TestRiskTrend:
    """Tests for RiskTrend dataclass."""

    def test_create_trend(self) -> None:
        """Test creating a risk trend."""
        trend = RiskTrend(
            asset_id="asset-001",
            current_score=7.0,
            previous_score=5.0,
            change=2.0,
            velocity="increasing",
        )

        assert trend.current_score == 7.0
        assert trend.previous_score == 5.0
        assert trend.change == 2.0

    def test_is_concerning(self) -> None:
        """Test is_concerning property."""
        rapid = RiskTrend(
            asset_id="asset-001",
            current_score=8.0,
            previous_score=4.0,
            change=4.0,
            velocity="rapid_increase",
        )
        assert rapid.is_concerning is True

        stable = RiskTrend(
            asset_id="asset-001",
            current_score=5.0,
            previous_score=5.0,
            change=0.0,
            velocity="stable",
        )
        assert stable.is_concerning is False

    def test_trend_to_dict(self) -> None:
        """Test RiskTrend serialization."""
        trend = RiskTrend(
            asset_id="asset-001",
            current_score=6.0,
            previous_score=4.0,
            change=2.0,
            velocity="increasing",
        )

        data = trend.to_dict()
        assert data["current_score"] == 6.0
        assert data["change"] == 2.0
        assert data["velocity"] == "increasing"


# ============================================================================
# ASMRiskScorer Tests
# ============================================================================


class TestASMRiskScorer:
    """Tests for ASMRiskScorer."""

    def test_default_weights(self) -> None:
        """Test default weight configuration."""
        scorer = ASMRiskScorer()

        assert scorer.weights["service_exposure"] == 3.0
        assert scorer.weights["certificate"] == 2.0
        assert scorer.weights["technology"] == 2.0
        assert scorer.weights["shadow_it"] == 2.0
        assert scorer.weights["data_exposure"] == 1.0

    def test_custom_weights(self) -> None:
        """Test custom weight configuration."""
        custom = {"service_exposure": 5.0, "certificate": 1.0}
        scorer = ASMRiskScorer(weights=custom)

        assert scorer.weights["service_exposure"] == 5.0
        assert scorer.weights["certificate"] == 1.0


class TestServiceExposureRisk:
    """Tests for service exposure risk calculation."""

    def test_critical_port_rdp(self, rdp_asset: ExternalAsset) -> None:
        """Test RDP port (3389) is high risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(rdp_asset)

        service_factor = next(f for f in assessment.factors if f.name == "service_exposure")
        assert service_factor.score == 1.0

    def test_critical_port_database(self, database_asset: ExternalAsset) -> None:
        """Test database port (3306) is high risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(database_asset)

        service_factor = next(f for f in assessment.factors if f.name == "service_exposure")
        assert service_factor.score == 1.0

    def test_standard_web_port(self, web_asset: ExternalAsset) -> None:
        """Test standard HTTPS port (443) is lower risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(web_asset)

        service_factor = next(f for f in assessment.factors if f.name == "service_exposure")
        assert service_factor.score == 0.2  # Standard web port

    def test_admin_port(self) -> None:
        """Test admin panel port is high risk."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="admin-001",
            domain="admin.example.com",
            ip_address="10.0.0.1",
            port=9090,  # Prometheus
            protocol="http",
            service="prometheus",
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset)

        service_factor = next(f for f in assessment.factors if f.name == "service_exposure")
        assert service_factor.score == 0.8  # Admin panel

    def test_no_port(self) -> None:
        """Test asset with no port has low service risk."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="no-port-001",
            domain="example.com",
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset)

        service_factor = next(f for f in assessment.factors if f.name == "service_exposure")
        assert service_factor.score == 0.1


class TestCertificateRisk:
    """Tests for certificate risk calculation."""

    def test_expired_certificate(
        self,
        shadow_it_asset: ExternalAsset,
    ) -> None:
        """Test expired certificate is highest risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(shadow_it_asset)

        cert_factor = next(f for f in assessment.factors if f.name == "certificate")
        assert cert_factor.score == 1.0  # Expired

    def test_expiring_certificate(
        self,
        api_asset: ExternalAsset,
    ) -> None:
        """Test expiring certificate has elevated risk."""
        # api_asset has certificate expiring in 5 days
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(api_asset)

        cert_factor = next(f for f in assessment.factors if f.name == "certificate")
        assert cert_factor.score >= 0.5  # Expiring soon

    def test_valid_certificate(
        self,
        web_asset: ExternalAsset,
    ) -> None:
        """Test valid certificate has no risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(web_asset)

        cert_factor = next(f for f in assessment.factors if f.name == "certificate")
        assert cert_factor.score == 0.0  # Valid cert

    def test_weak_key_certificate(
        self,
        expired_certificate: CertificateInfo,
    ) -> None:
        """Test weak key certificate has elevated risk."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="weak-key-001",
            domain="weak.example.com",
            ip_address="10.0.0.1",
            port=443,
            protocol="https",
            certificate_info=expired_certificate,  # Has 1024-bit RSA
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset)

        cert_factor = next(f for f in assessment.factors if f.name == "certificate")
        # Expired + weak key
        assert cert_factor.score >= 0.6

    def test_no_certificate_on_https(self) -> None:
        """Test missing certificate on HTTPS port is risky."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="no-cert-001",
            domain="no-cert.example.com",
            ip_address="10.0.0.1",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset)

        cert_factor = next(f for f in assessment.factors if f.name == "certificate")
        assert cert_factor.score == 0.7


class TestShadowITRisk:
    """Tests for shadow IT risk calculation."""

    def test_shadow_it_unknown_provider(self) -> None:
        """Test shadow IT without cloud provider is highest risk."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="shadow-001",
            domain="unknown.example.com",
            ip_address="10.0.0.1",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset, is_shadow_it=True)

        shadow_factor = next(f for f in assessment.factors if f.name == "shadow_it")
        assert shadow_factor.score == 1.0

    def test_shadow_it_known_provider(
        self,
        shadow_it_asset: ExternalAsset,
    ) -> None:
        """Test shadow IT with known cloud provider has elevated risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(shadow_it_asset, is_shadow_it=True)

        shadow_factor = next(f for f in assessment.factors if f.name == "shadow_it")
        assert shadow_factor.score == 0.7  # Known provider (GCP)

    def test_tracked_asset(
        self,
        web_asset: ExternalAsset,
    ) -> None:
        """Test tracked asset has no shadow IT risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(web_asset, is_shadow_it=False)

        shadow_factor = next(f for f in assessment.factors if f.name == "shadow_it")
        assert shadow_factor.score == 0.0


class TestDataExposureRisk:
    """Tests for data exposure risk calculation."""

    def test_sensitive_data(
        self,
        api_asset: ExternalAsset,
    ) -> None:
        """Test asset with sensitive data has highest data risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(api_asset, has_sensitive_data=True)

        data_factor = next(f for f in assessment.factors if f.name == "data_exposure")
        assert data_factor.score == 1.0

    def test_api_service_without_classification(self) -> None:
        """Test API service without DSPM classification has medium risk."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="api-001",
            domain="api.example.com",
            ip_address="10.0.0.1",
            port=443,
            protocol="https",
            service="API Gateway",
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset)

        data_factor = next(f for f in assessment.factors if f.name == "data_exposure")
        assert data_factor.score == 0.3  # Unclassified data service

    def test_no_data_indicators(
        self,
        web_asset: ExternalAsset,
    ) -> None:
        """Test asset with no data indicators has no data risk."""
        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(web_asset, has_sensitive_data=False)

        data_factor = next(f for f in assessment.factors if f.name == "data_exposure")
        assert data_factor.score == 0.0


class TestTechnologyRisk:
    """Tests for technology risk calculation."""

    def test_technology_with_critical_finding(self) -> None:
        """Test asset with critical finding has high tech risk."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="vuln-001",
            domain="vuln.example.com",
            ip_address="10.0.0.1",
            port=443,
            protocol="https",
            technology_stack=("nginx", "PHP"),
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        finding = Finding(
            id="CVE-2023-1234",
            asset_id="vuln-001",
            finding_type=FindingType.VULNERABILITY,
            status=FindingStatus.OPEN,
            title="Critical RCE vulnerability",
            description="Remote code execution exploit available",
            severity=Severity.CRITICAL,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset, findings=[finding])

        tech_factor = next(f for f in assessment.factors if f.name == "technology")
        assert tech_factor.score >= 0.8

    def test_risky_technology_stack(self) -> None:
        """Test risky technology stack has elevated risk."""
        now = datetime.now(timezone.utc)
        asset = ExternalAsset(
            id="wp-001",
            domain="wp.example.com",
            ip_address="10.0.0.1",
            port=443,
            protocol="https",
            technology_stack=("WordPress 5.0", "PHP 7.4"),  # Include versions for detection
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        scorer = ASMRiskScorer()
        assessment = scorer.calculate_risk(asset)

        tech_factor = next(f for f in assessment.factors if f.name == "technology")
        # WordPress/PHP with versions trigger risk detection
        assert tech_factor.score >= 0.1  # At minimum detects technology


class TestRiskLevelClassification:
    """Tests for risk level classification."""

    def test_critical_threshold(self) -> None:
        """Test critical risk threshold (>8.0)."""
        scorer = ASMRiskScorer()
        assert scorer._score_to_level(9.0) == RiskLevel.CRITICAL
        assert scorer._score_to_level(8.1) == RiskLevel.CRITICAL

    def test_high_threshold(self) -> None:
        """Test high risk threshold (>6.0)."""
        scorer = ASMRiskScorer()
        assert scorer._score_to_level(7.0) == RiskLevel.HIGH
        assert scorer._score_to_level(6.1) == RiskLevel.HIGH

    def test_medium_threshold(self) -> None:
        """Test medium risk threshold (>4.0)."""
        scorer = ASMRiskScorer()
        assert scorer._score_to_level(5.0) == RiskLevel.MEDIUM
        assert scorer._score_to_level(4.1) == RiskLevel.MEDIUM

    def test_low_threshold(self) -> None:
        """Test low risk threshold (>2.0)."""
        scorer = ASMRiskScorer()
        assert scorer._score_to_level(3.0) == RiskLevel.LOW
        assert scorer._score_to_level(2.1) == RiskLevel.LOW

    def test_info_threshold(self) -> None:
        """Test info risk threshold (<=2.0)."""
        scorer = ASMRiskScorer()
        assert scorer._score_to_level(2.0) == RiskLevel.INFO
        assert scorer._score_to_level(1.0) == RiskLevel.INFO


class TestRiskTrending:
    """Tests for risk trending functionality."""

    def test_get_risk_trend(self, web_asset: ExternalAsset) -> None:
        """Test getting risk trend after multiple assessments."""
        scorer = ASMRiskScorer()

        # Calculate risk twice
        scorer.calculate_risk(web_asset)
        scorer.calculate_risk(web_asset)

        trend = scorer.get_risk_trend(web_asset.id)
        assert trend is not None
        assert len(trend.history) >= 2

    def test_get_risk_trend_insufficient_history(
        self,
        web_asset: ExternalAsset,
    ) -> None:
        """Test getting trend with insufficient history."""
        scorer = ASMRiskScorer()

        # Only one assessment
        scorer.calculate_risk(web_asset)

        trend = scorer.get_risk_trend(web_asset.id)
        assert trend is None

    def test_risk_velocity_calculation(self) -> None:
        """Test risk velocity is calculated correctly."""
        scorer = ASMRiskScorer()
        now = datetime.now(timezone.utc)

        # Simulate history
        scorer._risk_history["test-001"] = [
            (now - timedelta(hours=2), 4.0),
            (now, 8.0),  # Rapid increase
        ]

        trend = scorer.get_risk_trend("test-001")
        assert trend is not None
        assert trend.velocity == "rapid_increase"
        assert trend.is_concerning is True


class TestBatchRiskCalculation:
    """Tests for batch risk calculation."""

    def test_calculate_risk_batch(
        self,
        external_asset_collection: ExternalAssetCollection,
    ) -> None:
        """Test batch risk calculation."""
        scorer = ASMRiskScorer()
        assessments = scorer.calculate_risk_batch(external_asset_collection)

        assert len(assessments) == len(external_asset_collection)
        assert all(isinstance(a, RiskAssessment) for a in assessments)

    def test_calculate_risk_batch_with_shadow_it(
        self,
        external_asset_collection: ExternalAssetCollection,
        shadow_it_asset: ExternalAsset,
    ) -> None:
        """Test batch calculation with shadow IT markers."""
        scorer = ASMRiskScorer()

        shadow_ids = {shadow_it_asset.id}
        assessments = scorer.calculate_risk_batch(
            external_asset_collection,
            shadow_it_ids=shadow_ids,
        )

        # Find shadow IT asset assessment
        shadow_assessment = next(
            a for a in assessments if a.asset_id == shadow_it_asset.id
        )
        shadow_factor = next(
            f for f in shadow_assessment.factors if f.name == "shadow_it"
        )
        assert shadow_factor.score > 0


class TestRiskStatistics:
    """Tests for risk statistics functions."""

    def test_get_high_risk_assets(
        self,
        external_asset_collection: ExternalAssetCollection,
    ) -> None:
        """Test filtering high risk assets."""
        scorer = ASMRiskScorer()
        assessments = scorer.calculate_risk_batch(external_asset_collection)

        high_risk = scorer.get_high_risk_assets(assessments, min_score=6.0)

        # All should have score >= 6.0
        assert all(a.total_score >= 6.0 for a in high_risk)
        # Should be sorted descending
        scores = [a.total_score for a in high_risk]
        assert scores == sorted(scores, reverse=True)

    def test_get_risk_distribution(
        self,
        external_asset_collection: ExternalAssetCollection,
    ) -> None:
        """Test risk distribution calculation."""
        scorer = ASMRiskScorer()
        assessments = scorer.calculate_risk_batch(external_asset_collection)

        distribution = scorer.get_risk_distribution(assessments)

        assert "critical" in distribution
        assert "high" in distribution
        assert "medium" in distribution
        assert "low" in distribution
        assert "info" in distribution

        # Total should match number of assessments
        assert sum(distribution.values()) == len(assessments)

    def test_get_top_risk_factors(
        self,
        external_asset_collection: ExternalAssetCollection,
    ) -> None:
        """Test top risk factors calculation."""
        scorer = ASMRiskScorer()
        assessments = scorer.calculate_risk_batch(external_asset_collection)

        top_factors = scorer.get_top_risk_factors(assessments, top_n=3)

        assert len(top_factors) <= 3
        assert all("name" in f for f in top_factors)
        assert all("average_score" in f for f in top_factors)


class TestCalculateAttackSurfaceRisk:
    """Tests for calculate_attack_surface_risk function."""

    def test_basic_attack_surface_risk(
        self,
        external_asset_collection: ExternalAssetCollection,
    ) -> None:
        """Test basic attack surface risk calculation."""
        result = calculate_attack_surface_risk(external_asset_collection)

        assert "total_assets" in result
        assert result["total_assets"] == len(external_asset_collection)
        assert "average_risk_score" in result
        assert "risk_distribution" in result
        assert "top_risk_factors" in result
        assert "highest_risk_assets" in result

    def test_attack_surface_with_shadow_it(
        self,
        external_asset_collection: ExternalAssetCollection,
        shadow_it_asset: ExternalAsset,
    ) -> None:
        """Test attack surface risk with shadow IT."""
        result = calculate_attack_surface_risk(
            external_asset_collection,
            shadow_it_ids={shadow_it_asset.id},
        )

        # Should have elevated average risk due to shadow IT
        assert result["average_risk_score"] > 0

    def test_attack_surface_highest_risk_assets(
        self,
        external_asset_collection: ExternalAssetCollection,
    ) -> None:
        """Test highest risk assets in attack surface result."""
        result = calculate_attack_surface_risk(external_asset_collection)

        highest_risk = result["highest_risk_assets"]
        assert isinstance(highest_risk, list)

        # Should be limited to 10 and sorted by score
        assert len(highest_risk) <= 10
        if len(highest_risk) > 1:
            scores = [a["score"] for a in highest_risk]
            assert scores == sorted(scores, reverse=True)
