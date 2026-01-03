"""
Tests for Mantissa Stance enrichment module.

Tests the enrichment functionality including:
- Base enricher interface
- IP enrichment
- Asset enrichment
- Threat intelligence enrichment
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from stance.enrichment import (
    AssetContextEnricher,
    CloudProviderRangeEnricher,
    CVEEnricher,
    EnrichedAsset,
    EnrichedFinding,
    EnrichmentData,
    EnrichmentPipeline,
    EnrichmentType,
    IPEnricher,
    TagEnricher,
    create_default_pipeline,
    enrich_findings,
    enrich_assets,
)
from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
    Severity,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)


class TestEnrichmentData:
    """Tests for the EnrichmentData class."""

    def test_creation(self):
        """Test EnrichmentData can be created."""
        data = EnrichmentData(
            enrichment_type=EnrichmentType.IP_GEOLOCATION,
            source="test",
            data={"country": "US"},
        )

        assert data.source == "test"
        assert data.enrichment_type == EnrichmentType.IP_GEOLOCATION
        assert data.data["country"] == "US"

    def test_default_confidence(self):
        """Test default confidence score."""
        data = EnrichmentData(
            enrichment_type=EnrichmentType.ASSET_CONTEXT,
            source="test",
            data={},
        )

        assert data.confidence == 1.0

    def test_custom_confidence(self):
        """Test custom confidence score."""
        data = EnrichmentData(
            enrichment_type=EnrichmentType.THREAT_INTEL,
            source="test",
            data={},
            confidence=0.8,
        )

        assert data.confidence == 0.8

    def test_is_expired(self):
        """Test expiration check."""
        # Not expired
        data = EnrichmentData(
            enrichment_type=EnrichmentType.IP_GEOLOCATION,
            source="test",
            data={},
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        assert not data.is_expired()

        # Expired
        expired_data = EnrichmentData(
            enrichment_type=EnrichmentType.IP_GEOLOCATION,
            source="test",
            data={},
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        assert expired_data.is_expired()

    def test_to_dict(self):
        """Test serialization to dictionary."""
        data = EnrichmentData(
            enrichment_type=EnrichmentType.CVE_DETAILS,
            source="nvd",
            data={"cve_id": "CVE-2024-0001"},
            confidence=0.9,
        )

        result = data.to_dict()

        assert result["enrichment_type"] == "cve_details"
        assert result["source"] == "nvd"
        assert result["data"]["cve_id"] == "CVE-2024-0001"
        assert result["confidence"] == 0.9


class TestEnrichedFinding:
    """Tests for the EnrichedFinding class."""

    def test_creation(self, sample_finding: Finding):
        """Test EnrichedFinding wraps finding correctly."""
        enriched = EnrichedFinding(finding=sample_finding)

        assert enriched.finding == sample_finding
        assert len(enriched.enrichments) == 0

    def test_add_enrichment(self, sample_finding: Finding):
        """Test adding enrichment data."""
        enriched = EnrichedFinding(finding=sample_finding)
        data = EnrichmentData(
            enrichment_type=EnrichmentType.THREAT_INTEL,
            source="test",
            data={"key": "value"},
        )

        enriched.add_enrichment(data)

        assert len(enriched.enrichments) == 1
        assert enriched.enrichments[0].source == "test"

    def test_get_enrichment(self, sample_finding: Finding):
        """Test getting specific enrichment by type."""
        enriched = EnrichedFinding(finding=sample_finding)
        cve_data = EnrichmentData(
            enrichment_type=EnrichmentType.CVE_DETAILS,
            source="nvd",
            data={"cve_id": "CVE-2024-0001"},
        )
        threat_data = EnrichmentData(
            enrichment_type=EnrichmentType.THREAT_INTEL,
            source="threat_intel",
            data={"score": 75},
        )
        enriched.add_enrichment(cve_data)
        enriched.add_enrichment(threat_data)

        cve = enriched.get_enrichment(EnrichmentType.CVE_DETAILS)
        threat = enriched.get_enrichment(EnrichmentType.THREAT_INTEL)

        assert cve is not None
        assert cve.data["cve_id"] == "CVE-2024-0001"
        assert threat is not None
        assert threat.data["score"] == 75

    def test_has_enrichment(self, sample_finding: Finding):
        """Test checking for enrichment type."""
        enriched = EnrichedFinding(finding=sample_finding)
        data = EnrichmentData(
            enrichment_type=EnrichmentType.CVE_DETAILS,
            source="test",
            data={},
        )
        enriched.add_enrichment(data)

        assert enriched.has_enrichment(EnrichmentType.CVE_DETAILS)
        assert not enriched.has_enrichment(EnrichmentType.THREAT_INTEL)

    def test_to_dict(self, sample_finding: Finding):
        """Test serialization to dictionary."""
        enriched = EnrichedFinding(finding=sample_finding)
        data = EnrichmentData(
            enrichment_type=EnrichmentType.CVE_DETAILS,
            source="nvd",
            data={"cve_id": "CVE-2024-0001"},
        )
        enriched.add_enrichment(data)

        result = enriched.to_dict()

        assert "finding" in result
        assert "enrichments" in result
        assert len(result["enrichments"]) == 1


class TestEnrichedAsset:
    """Tests for the EnrichedAsset class."""

    def test_creation(self, sample_asset: Asset):
        """Test EnrichedAsset wraps asset correctly."""
        enriched = EnrichedAsset(asset=sample_asset)

        assert enriched.asset == sample_asset
        assert len(enriched.enrichments) == 0

    def test_add_enrichment(self, sample_asset: Asset):
        """Test adding enrichment data."""
        enriched = EnrichedAsset(asset=sample_asset)
        data = EnrichmentData(
            enrichment_type=EnrichmentType.BUSINESS_UNIT,
            source="context",
            data={"unit": "engineering"},
        )

        enriched.add_enrichment(data)

        assert len(enriched.enrichments) == 1

    def test_get_enrichment(self, sample_asset: Asset):
        """Test getting enrichment by type."""
        enriched = EnrichedAsset(asset=sample_asset)
        data = EnrichmentData(
            enrichment_type=EnrichmentType.ASSET_CONTEXT,
            source="test",
            data={"environment": "production"},
        )
        enriched.add_enrichment(data)

        result = enriched.get_enrichment(EnrichmentType.ASSET_CONTEXT)

        assert result is not None
        assert result.data["environment"] == "production"

    def test_to_dict(self, sample_asset: Asset):
        """Test serialization to dictionary."""
        enriched = EnrichedAsset(asset=sample_asset)
        data = EnrichmentData(
            enrichment_type=EnrichmentType.CRITICALITY,
            source="rules",
            data={"level": "high"},
        )
        enriched.add_enrichment(data)

        result = enriched.to_dict()

        assert "asset" in result
        assert "enrichments" in result


class TestIPEnricher:
    """Tests for the IPEnricher class."""

    def test_enricher_name(self):
        """Test enricher has correct name."""
        enricher = IPEnricher()
        assert enricher.enricher_name == "ip_enricher"

    def test_enrichment_types(self):
        """Test enricher provides correct enrichment types."""
        enricher = IPEnricher()
        types = enricher.enrichment_types

        assert EnrichmentType.IP_GEOLOCATION in types
        assert EnrichmentType.IP_ASN in types
        assert EnrichmentType.IP_CLOUD_PROVIDER in types

    def test_is_available(self):
        """Test enricher is available."""
        enricher = IPEnricher()
        assert enricher.is_available()

    def test_extract_ips_from_ec2_config(self):
        """Test IP extraction from EC2-like config."""
        enricher = IPEnricher()

        asset = Asset(
            id="test",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="test-instance",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            raw_config={
                "PublicIpAddress": "54.123.45.67",
                "PrivateIpAddress": "10.0.1.5",
            },
        )

        ips = enricher._extract_ips(asset)

        assert "54.123.45.67" in ips
        assert "10.0.1.5" in ips

    def test_lookup_ip(self):
        """Test public IP lookup method."""
        enricher = IPEnricher(enable_geoip=False)

        result = enricher.lookup_ip("54.123.45.67")

        assert result["ip"] == "54.123.45.67"
        assert result["is_public"] is True
        assert result["is_private"] is False

    def test_lookup_private_ip(self):
        """Test private IP lookup method."""
        enricher = IPEnricher(enable_geoip=False)

        result = enricher.lookup_ip("10.0.1.5")

        assert result["ip"] == "10.0.1.5"
        assert result["is_public"] is False
        assert result["is_private"] is True


class TestCloudProviderRangeEnricher:
    """Tests for the CloudProviderRangeEnricher class."""

    def test_enricher_name(self):
        """Test enricher has correct name."""
        enricher = CloudProviderRangeEnricher()
        assert enricher.enricher_name == "cloud_provider_range_enricher"

    def test_enrichment_types(self):
        """Test enricher provides correct types."""
        enricher = CloudProviderRangeEnricher()
        types = enricher.enrichment_types

        assert EnrichmentType.IP_CLOUD_PROVIDER in types

    def test_identify_provider_aws(self):
        """Test AWS IP range detection."""
        enricher = CloudProviderRangeEnricher()

        # Test known AWS IP range
        result = enricher.identify_provider("3.5.140.1")
        assert result == "aws"

    def test_identify_provider_unknown(self):
        """Test unknown IP returns None."""
        enricher = CloudProviderRangeEnricher()

        result = enricher.identify_provider("8.8.8.8")
        assert result is None

    def test_add_custom_range(self):
        """Test adding custom IP range."""
        enricher = CloudProviderRangeEnricher()

        enricher.add_custom_range("custom", "192.0.2.0", "192.0.2.255")

        result = enricher.identify_provider("192.0.2.100")
        assert result == "custom"


class TestAssetContextEnricher:
    """Tests for the AssetContextEnricher class."""

    def test_enricher_name(self):
        """Test enricher has correct name."""
        enricher = AssetContextEnricher()
        assert enricher.enricher_name == "asset_context_enricher"

    def test_enrichment_types(self):
        """Test enricher provides correct types."""
        enricher = AssetContextEnricher()
        types = enricher.enrichment_types

        assert EnrichmentType.ASSET_CONTEXT in types
        assert EnrichmentType.BUSINESS_UNIT in types
        assert EnrichmentType.CRITICALITY in types

    def test_enrich_returns_data(self, sample_asset: Asset):
        """Test enricher returns enrichment data."""
        enricher = AssetContextEnricher()

        enrichments = enricher.enrich(sample_asset)

        assert len(enrichments) > 0
        # Should have at least criticality and context
        types = [e.enrichment_type for e in enrichments]
        assert EnrichmentType.CRITICALITY in types
        assert EnrichmentType.ASSET_CONTEXT in types

    def test_production_asset_criticality(self):
        """Test production assets get higher criticality."""
        enricher = AssetContextEnricher()

        asset = Asset(
            id="test",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="prod-data-bucket",
            tags={"environment": "production"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={},
        )

        enrichments = enricher.enrich(asset)

        criticality = next(
            (e for e in enrichments if e.enrichment_type == EnrichmentType.CRITICALITY),
            None
        )
        assert criticality is not None
        assert criticality.data["level"] == "critical"


class TestTagEnricher:
    """Tests for the TagEnricher class."""

    def test_enricher_name(self):
        """Test enricher has correct name."""
        enricher = TagEnricher()
        assert enricher.enricher_name == "tag_enricher"

    def test_enrichment_types(self):
        """Test enricher provides correct types."""
        enricher = TagEnricher()
        types = enricher.enrichment_types

        assert EnrichmentType.ASSET_CONTEXT in types

    def test_check_tag_compliance(self):
        """Test checking for required tags."""
        enricher = TagEnricher(required_tags={
            "test_policy": ["Name", "Environment", "Owner"]
        })

        asset = Asset(
            id="test",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="test-bucket",
            tags={"Name": "test", "Environment": "dev"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={},
        )

        enrichments = enricher.enrich(asset)

        assert len(enrichments) == 1
        compliance = enrichments[0].data["tag_compliance"]["test_policy"]
        assert not compliance["compliant"]
        assert "Owner" in compliance["missing_tags"]


class TestCVEEnricher:
    """Tests for the CVEEnricher class."""

    def test_enricher_name(self):
        """Test enricher has correct name."""
        enricher = CVEEnricher()
        assert enricher.enricher_name == "cve_enricher"

    def test_enrichment_types(self):
        """Test enricher provides correct types."""
        enricher = CVEEnricher()
        types = enricher.enrichment_types

        assert EnrichmentType.CVE_DETAILS in types

    def test_no_enrichment_without_cve(self):
        """Test no enrichment for finding without CVE."""
        enricher = CVEEnricher()

        finding = Finding(
            id="test",
            asset_id="asset1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test finding",
            description="Test",
        )

        enrichments = enricher.enrich(finding)

        assert len(enrichments) == 0


class TestEnrichmentPipeline:
    """Tests for the EnrichmentPipeline class."""

    def test_creation(self):
        """Test pipeline creation."""
        pipeline = EnrichmentPipeline()

        assert len(pipeline.finding_enrichers) == 0
        assert len(pipeline.asset_enrichers) == 0

    def test_add_finding_enricher(self):
        """Test adding finding enricher."""
        pipeline = EnrichmentPipeline()

        pipeline.add_finding_enricher(CVEEnricher())

        assert len(pipeline.finding_enrichers) == 1

    def test_add_asset_enricher(self):
        """Test adding asset enricher."""
        pipeline = EnrichmentPipeline()

        pipeline.add_asset_enricher(AssetContextEnricher())
        pipeline.add_asset_enricher(TagEnricher())

        assert len(pipeline.asset_enrichers) == 2

    def test_enrich_findings(self, finding_collection: FindingCollection):
        """Test processing findings through pipeline."""
        pipeline = EnrichmentPipeline(
            finding_enrichers=[CVEEnricher()]
        )

        enriched = pipeline.enrich_findings(list(finding_collection.findings))

        assert len(enriched) == len(finding_collection.findings)
        for finding in enriched:
            assert isinstance(finding, EnrichedFinding)

    def test_enrich_assets(self, asset_collection: AssetCollection):
        """Test processing assets through pipeline."""
        pipeline = EnrichmentPipeline(
            asset_enrichers=[AssetContextEnricher(), TagEnricher()]
        )

        enriched = pipeline.enrich_assets(list(asset_collection.assets))

        assert len(enriched) == len(asset_collection.assets)
        for asset in enriched:
            assert isinstance(asset, EnrichedAsset)


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_default_pipeline(self):
        """Test creating default enrichment pipeline."""
        pipeline = create_default_pipeline()

        assert pipeline is not None
        assert len(pipeline.finding_enrichers) > 0
        assert len(pipeline.asset_enrichers) > 0

    def test_enrich_findings_function(self):
        """Test enrich_findings convenience function."""
        findings = [
            Finding(
                id="test",
                asset_id="asset1",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title="Test finding",
                description="Test",
            )
        ]

        enriched = enrich_findings(findings)

        assert len(enriched) == 1
        assert isinstance(enriched[0], EnrichedFinding)

    def test_enrich_assets_function(self):
        """Test enrich_assets convenience function."""
        assets = [
            Asset(
                id="test",
                cloud_provider="aws",
                account_id="123",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name="test-bucket",
                tags={},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                raw_config={},
            )
        ]

        enriched = enrich_assets(assets)

        assert len(enriched) == 1
        assert isinstance(enriched[0], EnrichedAsset)
