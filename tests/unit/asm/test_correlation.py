"""
Unit tests for CSPM-ASM correlation.

Tests cover:
- MatchMethod enum
- MatchedAsset dataclass
- CorrelationResult dataclass
- ASMCSPMCorrelator matching strategies
- Utility functions (create_unified_inventory, detect_shadow_it, get_attack_surface)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from stance.asm.correlation import (
    ASMCSPMCorrelator,
    CorrelationResult,
    MatchedAsset,
    MatchMethod,
    create_unified_inventory,
    detect_shadow_it,
    get_attack_surface,
)
from stance.asm.models import (
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.models.asset import Asset, AssetCollection


# ============================================================================
# Enum Tests
# ============================================================================


class TestMatchMethod:
    """Tests for MatchMethod enum."""

    def test_match_method_values(self) -> None:
        """Test MatchMethod enum values."""
        assert MatchMethod.IP_ADDRESS.value == "ip_address"
        assert MatchMethod.DOMAIN.value == "domain"
        assert MatchMethod.CERTIFICATE.value == "certificate"
        assert MatchMethod.TAG.value == "tag"
        assert MatchMethod.LOAD_BALANCER.value == "load_balancer"
        assert MatchMethod.DNS_RECORD.value == "dns_record"


# ============================================================================
# MatchedAsset Tests
# ============================================================================


class TestMatchedAsset:
    """Tests for MatchedAsset dataclass."""

    def test_create_matched_asset(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test creating a MatchedAsset."""
        match = MatchedAsset(
            external_asset=web_asset,
            internal_asset=cspm_ec2_asset,
            match_confidence=0.95,
            match_method=MatchMethod.IP_ADDRESS,
            match_details="IP: 203.0.113.10",
        )

        assert match.external_asset == web_asset
        assert match.internal_asset == cspm_ec2_asset
        assert match.match_confidence == 0.95
        assert match.match_method == MatchMethod.IP_ADDRESS

    def test_matched_asset_to_dict(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test MatchedAsset serialization."""
        match = MatchedAsset(
            external_asset=web_asset,
            internal_asset=cspm_ec2_asset,
            match_confidence=0.95,
            match_method=MatchMethod.DOMAIN,
            match_details="Domain match",
        )

        data = match.to_dict()
        assert "external_asset" in data
        assert "internal_asset" in data
        assert data["match_confidence"] == 0.95
        assert data["match_method"] == "domain"


# ============================================================================
# CorrelationResult Tests
# ============================================================================


class TestCorrelationResult:
    """Tests for CorrelationResult dataclass."""

    def test_default_correlation_result(self) -> None:
        """Test default CorrelationResult."""
        result = CorrelationResult()

        assert result.matched_assets == []
        assert result.shadow_it == []
        assert result.internal_only == []
        assert result.correlation_score == 0.0

    def test_matched_count(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test matched_count property."""
        match = MatchedAsset(
            external_asset=web_asset,
            internal_asset=cspm_ec2_asset,
            match_confidence=0.95,
            match_method=MatchMethod.IP_ADDRESS,
        )

        result = CorrelationResult(matched_assets=[match])
        assert result.matched_count == 1

    def test_shadow_it_count(self, shadow_it_asset: ExternalAsset) -> None:
        """Test shadow_it_count property."""
        result = CorrelationResult(shadow_it=[shadow_it_asset])
        assert result.shadow_it_count == 1

    def test_internal_only_count(self, cspm_rds_asset: Asset) -> None:
        """Test internal_only_count property."""
        result = CorrelationResult(internal_only=[cspm_rds_asset])
        assert result.internal_only_count == 1

    def test_high_risk_shadow_it(self, database_asset: ExternalAsset) -> None:
        """Test high_risk_shadow_it property."""
        # database_asset has risk_score 8.0
        result = CorrelationResult(shadow_it=[database_asset])
        assert len(result.high_risk_shadow_it) == 1

    def test_high_risk_shadow_it_filters(
        self,
        web_asset: ExternalAsset,
        database_asset: ExternalAsset,
    ) -> None:
        """Test high_risk_shadow_it filters low-risk assets."""
        # web_asset has risk_score 2.5
        result = CorrelationResult(shadow_it=[web_asset, database_asset])
        assert len(result.high_risk_shadow_it) == 1
        assert result.high_risk_shadow_it[0].risk_score >= 7.0

    def test_correlation_result_to_dict(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test CorrelationResult serialization."""
        match = MatchedAsset(
            external_asset=web_asset,
            internal_asset=cspm_ec2_asset,
            match_confidence=0.95,
            match_method=MatchMethod.IP_ADDRESS,
        )

        result = CorrelationResult(
            matched_assets=[match],
            total_external=1,
            total_internal=1,
        )

        data = result.to_dict()
        assert "matched_assets" in data
        assert "shadow_it" in data
        assert "summary" in data
        assert data["summary"]["matched_count"] == 1

    def test_get_summary(self, shadow_it_asset: ExternalAsset) -> None:
        """Test get_summary method."""
        result = CorrelationResult(
            shadow_it=[shadow_it_asset],
            total_external=5,
            total_internal=10,
            correlation_score=80.0,
        )

        summary = result.get_summary()
        assert summary["correlation_score"] == "80.0%"
        assert summary["shadow_it_detected"] == 1
        assert summary["total_external"] == 5
        assert summary["total_internal"] == 10


# ============================================================================
# ASMCSPMCorrelator Tests
# ============================================================================


class TestASMCSPMCorrelator:
    """Tests for ASMCSPMCorrelator."""

    def test_correlate_by_ip_address(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test correlation by IP address."""
        asm_assets = ExternalAssetCollection([web_asset])
        cspm_assets = AssetCollection([cspm_ec2_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
        result = correlator.correlate()

        assert result.matched_count == 1
        assert result.shadow_it_count == 0
        assert result.matched_assets[0].match_method == MatchMethod.IP_ADDRESS
        assert result.matched_assets[0].match_confidence == 1.0

    def test_correlate_by_domain(
        self,
        api_asset: ExternalAsset,
        cspm_alb_asset: Asset,
    ) -> None:
        """Test correlation by domain name."""
        asm_assets = ExternalAssetCollection([api_asset])
        cspm_assets = AssetCollection([cspm_alb_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
        result = correlator.correlate()

        assert result.matched_count == 1
        assert result.matched_assets[0].match_method == MatchMethod.DOMAIN

    def test_correlate_by_tag(self) -> None:
        """Test correlation by domain tag."""
        now = datetime.now(timezone.utc)

        # External asset
        external = ExternalAsset(
            id="ext-001",
            domain="tagged-app.example.com",
            ip_address="10.0.0.5",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        # Internal asset with matching domain tag
        internal = Asset(
            id="arn:aws:ec2:us-east-1:123:instance/i-tagged",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="tagged-server",
            tags={"Domain": "tagged-app.example.com"},
            network_exposure="internet_facing",
            raw_config={},
        )

        asm_assets = ExternalAssetCollection([external])
        cspm_assets = AssetCollection([internal])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
        result = correlator.correlate()

        assert result.matched_count == 1
        assert result.matched_assets[0].match_method == MatchMethod.TAG

    def test_detect_shadow_it(
        self,
        shadow_it_asset: ExternalAsset,
        cspm_asset_collection: AssetCollection,
    ) -> None:
        """Test shadow IT detection."""
        asm_assets = ExternalAssetCollection([shadow_it_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_asset_collection)
        result = correlator.correlate()

        assert result.shadow_it_count == 1
        assert result.shadow_it[0].domain == "unknown-app.example.com"

    def test_correlation_score(
        self,
        web_asset: ExternalAsset,
        shadow_it_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test correlation score calculation."""
        asm_assets = ExternalAssetCollection([web_asset, shadow_it_asset])
        cspm_assets = AssetCollection([cspm_ec2_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
        result = correlator.correlate()

        # 1 matched out of 2 external = 50%
        assert result.correlation_score == 50.0

    def test_internal_only_internet_facing(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
        cspm_rds_asset: Asset,
    ) -> None:
        """Test internal_only only includes internet-facing assets."""
        asm_assets = ExternalAssetCollection([web_asset])
        cspm_assets = AssetCollection([cspm_ec2_asset, cspm_rds_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
        result = correlator.correlate()

        # RDS is internal-only but not internet-facing, so excluded
        assert result.internal_only_count == 0

    def test_best_match_selection(self) -> None:
        """Test that highest confidence match is selected."""
        now = datetime.now(timezone.utc)

        # External asset
        external = ExternalAsset(
            id="ext-001",
            domain="multi-match.example.com",
            ip_address="10.0.0.100",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=7),
            last_seen=now,
        )

        # Internal assets - one matches by IP (higher confidence), one by tag (lower)
        internal_ip = Asset(
            id="arn:aws:ec2:us-east-1:123:instance/i-ip",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="ip-match-server",
            tags={},
            network_exposure="internet_facing",
            raw_config={"public_ip_address": "10.0.0.100"},
        )

        internal_tag = Asset(
            id="arn:aws:ec2:us-east-1:123:instance/i-tag",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="tag-match-server",
            tags={"Domain": "multi-match.example.com"},
            network_exposure="internet_facing",
            raw_config={},
        )

        asm_assets = ExternalAssetCollection([external])
        cspm_assets = AssetCollection([internal_ip, internal_tag])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
        result = correlator.correlate()

        # Should match by IP (confidence 1.0) over tag (confidence 0.7)
        assert result.matched_count == 1
        assert result.matched_assets[0].match_method == MatchMethod.IP_ADDRESS
        assert result.matched_assets[0].match_confidence == 1.0


# ============================================================================
# Utility Function Tests
# ============================================================================


class TestCreateUnifiedInventory:
    """Tests for create_unified_inventory function."""

    def test_create_unified_inventory_with_matches(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test creating unified inventory with matched assets."""
        asm_assets = ExternalAssetCollection([web_asset])
        cspm_assets = AssetCollection([cspm_ec2_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
        correlation = correlator.correlate()

        unified = create_unified_inventory(correlation)

        assert len(unified) == 1
        asset = unified[0]

        # Check enriched config
        assert "asm_correlation" in asset.raw_config
        asm_data = asset.raw_config["asm_correlation"]
        assert asm_data["external_domain"] == web_asset.domain
        assert asm_data["external_ip"] == web_asset.ip_address
        assert "certificate" in asm_data  # web_asset has certificate

    def test_create_unified_inventory_with_shadow_it(
        self,
        shadow_it_asset: ExternalAsset,
        cspm_asset_collection: AssetCollection,
    ) -> None:
        """Test creating unified inventory including shadow IT."""
        asm_assets = ExternalAssetCollection([shadow_it_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_asset_collection)
        correlation = correlator.correlate()

        unified = create_unified_inventory(correlation, include_shadow_it=True)

        # Should have shadow IT asset
        shadow_assets = [a for a in unified if a.resource_type == "shadow_it_asset"]
        assert len(shadow_assets) == 1
        assert shadow_assets[0].id.startswith("shadow-it:")
        assert shadow_assets[0].raw_config["is_shadow_it"] is True

    def test_create_unified_inventory_exclude_shadow_it(
        self,
        shadow_it_asset: ExternalAsset,
        cspm_asset_collection: AssetCollection,
    ) -> None:
        """Test creating unified inventory excluding shadow IT."""
        asm_assets = ExternalAssetCollection([shadow_it_asset])

        correlator = ASMCSPMCorrelator(asm_assets, cspm_asset_collection)
        correlation = correlator.correlate()

        unified = create_unified_inventory(correlation, include_shadow_it=False)

        # Should not have shadow IT assets
        shadow_assets = [a for a in unified if a.resource_type == "shadow_it_asset"]
        assert len(shadow_assets) == 0


class TestDetectShadowIT:
    """Tests for detect_shadow_it function."""

    def test_detect_shadow_it_basic(
        self,
        shadow_it_asset: ExternalAsset,
        cspm_asset_collection: AssetCollection,
    ) -> None:
        """Test basic shadow IT detection."""
        asm_assets = ExternalAssetCollection([shadow_it_asset])

        shadow_it = detect_shadow_it(asm_assets, cspm_asset_collection)

        assert len(shadow_it) == 1
        assert shadow_it[0].domain == "unknown-app.example.com"

    def test_detect_shadow_it_with_filter(
        self,
        external_asset_collection: ExternalAssetCollection,
        cspm_asset_collection: AssetCollection,
    ) -> None:
        """Test shadow IT detection with cloud provider filter."""
        # shadow_it_asset is on GCP
        shadow_it = detect_shadow_it(
            external_asset_collection,
            cspm_asset_collection,
            cloud_provider_filter="gcp",
        )

        # Only GCP shadow IT should be returned
        assert all(a.cloud_provider == "gcp" for a in shadow_it if a.cloud_provider)

    def test_detect_shadow_it_sorted_by_risk(
        self,
        shadow_it_asset: ExternalAsset,
        database_asset: ExternalAsset,
        cspm_asset_collection: AssetCollection,
    ) -> None:
        """Test shadow IT is sorted by risk score."""
        # database_asset has risk 8.0, shadow_it has 7.5
        asm_assets = ExternalAssetCollection([shadow_it_asset, database_asset])

        shadow_it = detect_shadow_it(asm_assets, cspm_asset_collection)

        # Should be sorted highest risk first
        if len(shadow_it) > 1:
            assert shadow_it[0].risk_score >= shadow_it[1].risk_score


class TestGetAttackSurface:
    """Tests for get_attack_surface function."""

    def test_get_attack_surface_basic(
        self,
        web_asset: ExternalAsset,
        shadow_it_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test basic attack surface generation."""
        asm_assets = ExternalAssetCollection([web_asset, shadow_it_asset])
        cspm_assets = AssetCollection([cspm_ec2_asset])

        attack_surface = get_attack_surface(asm_assets, cspm_assets)

        assert len(attack_surface) == 2

        # Check matched entry
        matched = [e for e in attack_surface if e["is_matched"]]
        assert len(matched) == 1
        assert matched[0]["is_shadow_it"] is False
        assert matched[0]["internal_asset_id"] is not None

        # Check shadow IT entry
        shadow = [e for e in attack_surface if e["is_shadow_it"]]
        assert len(shadow) == 1
        assert shadow[0]["is_matched"] is False
        assert shadow[0]["internal_asset_id"] is None

    def test_get_attack_surface_sorted_by_risk(
        self,
        web_asset: ExternalAsset,
        database_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test attack surface is sorted by risk score."""
        asm_assets = ExternalAssetCollection([web_asset, database_asset])
        cspm_assets = AssetCollection([cspm_ec2_asset])

        attack_surface = get_attack_surface(asm_assets, cspm_assets)

        # Should be sorted by risk score descending
        risks = [e["risk_score"] for e in attack_surface]
        assert risks == sorted(risks, reverse=True)

    def test_get_attack_surface_includes_certificate_info(
        self,
        web_asset: ExternalAsset,
        cspm_ec2_asset: Asset,
    ) -> None:
        """Test attack surface includes certificate information."""
        asm_assets = ExternalAssetCollection([web_asset])
        cspm_assets = AssetCollection([cspm_ec2_asset])

        attack_surface = get_attack_surface(asm_assets, cspm_assets)

        assert len(attack_surface) == 1
        assert "certificate_expiry" in attack_surface[0]
        assert "certificate_expired" in attack_surface[0]


# ============================================================================
# Index Building Tests
# ============================================================================


class TestCorrelatorIndexes:
    """Tests for correlator index building."""

    def test_ip_index(self) -> None:
        """Test IP address index is built correctly."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123:instance/i-test",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="test",
            raw_config={"public_ip_address": "1.2.3.4"},
        )

        correlator = ASMCSPMCorrelator(
            ExternalAssetCollection(),
            AssetCollection([asset]),
        )

        assert "1.2.3.4" in correlator._ip_index
        assert asset in correlator._ip_index["1.2.3.4"]

    def test_domain_index(self) -> None:
        """Test domain index is built correctly."""
        asset = Asset(
            id="arn:aws:alb:us-east-1:123:lb/test",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_alb",
            name="test-alb",
            raw_config={"dns_name": "Test.Example.Com"},
        )

        correlator = ASMCSPMCorrelator(
            ExternalAssetCollection(),
            AssetCollection([asset]),
        )

        assert "test.example.com" in correlator._domain_index

    def test_tag_domain_index(self) -> None:
        """Test tag-based domain index is built correctly."""
        asset = Asset(
            id="arn:aws:ec2:us-east-1:123:instance/i-test",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="test",
            tags={"Domain": "app.example.com", "hostname": "server.example.com"},
            raw_config={},
        )

        correlator = ASMCSPMCorrelator(
            ExternalAssetCollection(),
            AssetCollection([asset]),
        )

        assert "app.example.com" in correlator._tag_domain_index
        assert "server.example.com" in correlator._tag_domain_index

    def test_extract_hostname_from_url(self) -> None:
        """Test hostname extraction from URLs."""
        assert ASMCSPMCorrelator._extract_hostname("https://api.example.com/path") == "api.example.com"
        assert ASMCSPMCorrelator._extract_hostname("http://web.example.com:8080/") == "web.example.com"
        assert ASMCSPMCorrelator._extract_hostname("test.example.com") == "test.example.com"
        assert ASMCSPMCorrelator._extract_hostname("") is None

    def test_is_ip_address(self) -> None:
        """Test IP address detection."""
        assert ASMCSPMCorrelator._is_ip_address("192.168.1.1") is True
        assert ASMCSPMCorrelator._is_ip_address("10.0.0.255") is True
        assert ASMCSPMCorrelator._is_ip_address("example.com") is False
        assert ASMCSPMCorrelator._is_ip_address("192.168.1.256") is False
        assert ASMCSPMCorrelator._is_ip_address("192.168.1") is False
