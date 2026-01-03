"""
Unit tests for Web Dashboard API Enrichment endpoints.

Tests the enrichment API endpoints including:
- /api/enrichment/findings - Enrich findings with threat intelligence
- /api/enrichment/assets - Enrich assets with context info
- /api/enrichment/ip - Look up IP information
- /api/enrichment/cve - Look up CVE details
- /api/enrichment/kev - Check CISA KEV catalog
- /api/enrichment/status - Show enrichment capabilities
"""

from __future__ import annotations

import json
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

from stance.web.server import StanceRequestHandler
from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingType, Severity
from stance.enrichment.base import (
    EnrichedFinding,
    EnrichedAsset,
    EnrichmentData,
    EnrichmentType,
)


class TestEnrichmentFindingsEndpoint:
    """Tests for /api/enrichment/findings endpoint."""

    @pytest.fixture
    def mock_finding(self):
        """Create mock finding."""
        return Finding(
            id="finding-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            finding_type=FindingType.VULNERABILITY,
            cve_id="CVE-2021-44228",
            asset_id="asset-001",
        )

    @pytest.fixture
    def mock_findings_data(self, mock_finding):
        """Create mock findings data."""
        mock_data = MagicMock()
        mock_data.findings = [mock_finding]
        return mock_data

    def test_enrichment_findings_no_findings(self):
        """Test enrichment findings with no findings available."""
        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = None

            result = StanceRequestHandler._enrichment_findings(handler, {})

        assert "error" in result
        assert result["total_findings"] == 0

    def test_enrichment_findings_success(self, mock_findings_data, mock_finding):
        """Test successful finding enrichment."""
        handler = MagicMock(spec=StanceRequestHandler)

        enriched_finding = EnrichedFinding(
            finding=mock_finding,
            enrichments=[
                EnrichmentData(
                    enrichment_type=EnrichmentType.CVE_DETAILS,
                    source="nvd",
                    data={"cvss_v3": {"score": 9.8}},
                    confidence=1.0,
                )
            ],
        )

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            with patch("stance.web.server.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_findings.return_value = [enriched_finding]

                result = StanceRequestHandler._enrichment_findings(handler, {})

        assert result["total_findings"] == 1
        assert result["findings_enriched"] == 1
        assert result["total_enrichments"] == 1

    def test_enrichment_findings_with_types(self, mock_findings_data, mock_finding):
        """Test finding enrichment with specific types."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"types": ["cve,kev"]}

        enriched_finding = EnrichedFinding(finding=mock_finding, enrichments=[])

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            with patch("stance.web.server.CVEEnricher"):
                with patch("stance.web.server.KEVEnricher"):
                    with patch("stance.web.server.EnrichmentPipeline") as mock_pipeline:
                        mock_pipeline.return_value.enrich_findings.return_value = [enriched_finding]

                        result = StanceRequestHandler._enrichment_findings(handler, params)

        assert result["total_findings"] == 1

    def test_enrichment_findings_invalid_types(self, mock_findings_data):
        """Test finding enrichment with invalid types."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"types": ["invalid"]}

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            result = StanceRequestHandler._enrichment_findings(handler, params)

        assert "error" in result
        assert "valid_types" in result

    def test_enrichment_findings_with_finding_id(self, mock_findings_data, mock_finding):
        """Test finding enrichment for specific finding ID."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"finding_id": ["finding-001"]}

        enriched_finding = EnrichedFinding(finding=mock_finding, enrichments=[])

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            with patch("stance.web.server.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_findings.return_value = [enriched_finding]

                result = StanceRequestHandler._enrichment_findings(handler, params)

        assert result["total_findings"] == 1


class TestEnrichmentAssetsEndpoint:
    """Tests for /api/enrichment/assets endpoint."""

    @pytest.fixture
    def mock_asset(self):
        """Create mock asset."""
        return Asset(
            id="asset-001",
            name="test-bucket",
            resource_type="aws_s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
            tags={"environment": "production"},
        )

    @pytest.fixture
    def mock_assets_data(self, mock_asset):
        """Create mock assets data."""
        mock_data = MagicMock()
        mock_data.assets = [mock_asset]
        return mock_data

    def test_enrichment_assets_no_assets(self):
        """Test enrichment assets with no assets available."""
        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = None

            result = StanceRequestHandler._enrichment_assets(handler, {})

        assert "error" in result
        assert result["total_assets"] == 0

    def test_enrichment_assets_success(self, mock_assets_data, mock_asset):
        """Test successful asset enrichment."""
        handler = MagicMock(spec=StanceRequestHandler)

        enriched_asset = EnrichedAsset(
            asset=mock_asset,
            enrichments=[
                EnrichmentData(
                    enrichment_type=EnrichmentType.CRITICALITY,
                    source="criticality_rules",
                    data={"level": "critical"},
                    confidence=0.9,
                )
            ],
        )

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets_data

            with patch("stance.web.server.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_assets.return_value = [enriched_asset]

                result = StanceRequestHandler._enrichment_assets(handler, {})

        assert result["total_assets"] == 1
        assert result["assets_enriched"] == 1

    def test_enrichment_assets_filter_cloud(self, mock_assets_data, mock_asset):
        """Test asset enrichment filtered by cloud provider."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"cloud": ["aws"]}

        enriched_asset = EnrichedAsset(asset=mock_asset, enrichments=[])

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets_data

            with patch("stance.web.server.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_assets.return_value = [enriched_asset]

                result = StanceRequestHandler._enrichment_assets(handler, params)

        assert result["total_assets"] == 1


class TestEnrichmentIPEndpoint:
    """Tests for /api/enrichment/ip endpoint."""

    def test_enrichment_ip_no_ip(self):
        """Test IP lookup without IP address."""
        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._enrichment_ip(handler, {})

        assert "error" in result

    def test_enrichment_ip_success(self):
        """Test successful IP lookup."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"ip": ["8.8.8.8"]}

        mock_result = {
            "ip": "8.8.8.8",
            "is_public": True,
            "is_private": False,
            "version": 4,
            "cloud_provider": None,
            "geolocation": None,
        }

        with patch("stance.web.server.IPEnricher") as mock_enricher:
            mock_enricher.return_value.lookup_ip.return_value = mock_result

            result = StanceRequestHandler._enrichment_ip(handler, params)

        assert result["ip"] == "8.8.8.8"
        assert result["info"]["is_public"] is True

    def test_enrichment_ip_with_geoip_disabled(self):
        """Test IP lookup with GeoIP disabled."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"ip": ["8.8.8.8"], "no_geoip": ["true"]}

        mock_result = {
            "ip": "8.8.8.8",
            "is_public": True,
            "cloud_provider": None,
        }

        with patch("stance.web.server.IPEnricher") as mock_enricher:
            mock_enricher.return_value.lookup_ip.return_value = mock_result

            result = StanceRequestHandler._enrichment_ip(handler, params)

        assert result["ip"] == "8.8.8.8"


class TestEnrichmentCVEEndpoint:
    """Tests for /api/enrichment/cve endpoint."""

    def test_enrichment_cve_no_cve_id(self):
        """Test CVE lookup without CVE ID."""
        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._enrichment_cve(handler, {})

        assert "error" in result

    def test_enrichment_cve_not_found(self):
        """Test CVE lookup for non-existent CVE."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"cve_id": ["CVE-9999-99999"]}

        with patch("stance.web.server.CVEEnricher") as mock_enricher:
            mock_enricher.return_value._lookup_cve.return_value = None

            result = StanceRequestHandler._enrichment_cve(handler, params)

        assert "error" in result
        assert "CVE-9999-99999" in result["cve_id"]

    def test_enrichment_cve_success(self):
        """Test successful CVE lookup."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"cve_id": ["CVE-2021-44228"]}

        mock_result = {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 vulnerability",
            "cvss_v3": {"score": 10.0, "severity": "CRITICAL"},
        }

        with patch("stance.web.server.CVEEnricher") as mock_enricher:
            mock_enricher.return_value._lookup_cve.return_value = mock_result

            result = StanceRequestHandler._enrichment_cve(handler, params)

        assert result["cve_id"] == "CVE-2021-44228"
        assert "details" in result

    def test_enrichment_cve_normalize_id(self):
        """Test CVE lookup normalizes CVE ID."""
        handler = MagicMock(spec=StanceRequestHandler)

        # Without CVE- prefix
        params = {"cve_id": ["2021-44228"]}

        mock_result = {
            "cve_id": "CVE-2021-44228",
            "description": "Test",
        }

        with patch("stance.web.server.CVEEnricher") as mock_enricher:
            mock_enricher.return_value._lookup_cve.return_value = mock_result

            result = StanceRequestHandler._enrichment_cve(handler, params)

        assert result["cve_id"] == "CVE-2021-44228"


class TestEnrichmentKEVEndpoint:
    """Tests for /api/enrichment/kev endpoint."""

    def test_enrichment_kev_no_cve_no_list(self):
        """Test KEV lookup without CVE ID or list flag."""
        handler = MagicMock(spec=StanceRequestHandler)

        with patch("stance.web.server.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = {}

            result = StanceRequestHandler._enrichment_kev(handler, {})

        assert "error" in result

    def test_enrichment_kev_list(self):
        """Test KEV list all entries."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"list": ["true"]}

        mock_kev_data = {
            "CVE-2021-44228": {
                "vendorProject": "Apache",
                "product": "Log4j",
            },
        }

        with patch("stance.web.server.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = mock_kev_data

            result = StanceRequestHandler._enrichment_kev(handler, params)

        assert result["total"] == 1
        assert "vulnerabilities" in result

    def test_enrichment_kev_not_in_catalog(self):
        """Test KEV lookup for CVE not in catalog."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"cve_id": ["CVE-9999-99999"]}

        with patch("stance.web.server.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = {}
            mock_enricher.return_value.is_known_exploited.return_value = False

            result = StanceRequestHandler._enrichment_kev(handler, params)

        assert result["is_known_exploited"] is False

    def test_enrichment_kev_in_catalog(self):
        """Test KEV lookup for CVE in catalog."""
        handler = MagicMock(spec=StanceRequestHandler)

        params = {"cve_id": ["CVE-2021-44228"]}

        mock_kev_entry = {
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
        }

        with patch("stance.web.server.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = {"CVE-2021-44228": mock_kev_entry}
            mock_enricher.return_value.is_known_exploited.return_value = True

            result = StanceRequestHandler._enrichment_kev(handler, params)

        assert result["cve_id"] == "CVE-2021-44228"
        assert result["is_known_exploited"] is True
        assert "kev_details" in result


class TestEnrichmentStatusEndpoint:
    """Tests for /api/enrichment/status endpoint."""

    def test_enrichment_status(self):
        """Test enrichment status endpoint."""
        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._enrichment_status(handler, {})

        assert "enrichers" in result
        assert "finding_enrichers" in result
        assert "asset_enrichers" in result
        assert "enrichment_types" in result

        # Check enricher types
        assert len(result["finding_enrichers"]) >= 4
        assert len(result["asset_enrichers"]) >= 4

        # Check enrichment type options
        assert "findings" in result["enrichment_types"]
        assert "assets" in result["enrichment_types"]

    def test_enrichment_status_enricher_details(self):
        """Test enrichment status includes enricher details."""
        handler = MagicMock(spec=StanceRequestHandler)

        result = StanceRequestHandler._enrichment_status(handler, {})

        for enricher in result["enrichers"]:
            assert "name" in enricher
            assert "type" in enricher
            assert "description" in enricher
            assert "available" in enricher
            assert "enrichment_types" in enricher
            assert "data_sources" in enricher


class TestEnrichmentEndpointEdgeCases:
    """Tests for edge cases in enrichment endpoints."""

    def test_enrichment_findings_limit(self):
        """Test finding enrichment respects limit parameter."""
        handler = MagicMock(spec=StanceRequestHandler)

        # Create multiple findings
        findings = [
            Finding(
                id=f"finding-{i}",
                title=f"Finding {i}",
                description="Test",
                severity=Severity.MEDIUM,
                finding_type=FindingType.MISCONFIGURATION,
                asset_id="asset-001",
            )
            for i in range(10)
        ]

        mock_data = MagicMock()
        mock_data.findings = findings

        params = {"limit": ["5"]}

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_data

            with patch("stance.web.server.create_default_pipeline") as mock_pipeline:
                # Return enriched findings based on input count
                def side_effect(input_findings):
                    return [EnrichedFinding(finding=f, enrichments=[]) for f in input_findings]

                mock_pipeline.return_value.enrich_findings.side_effect = side_effect

                result = StanceRequestHandler._enrichment_findings(handler, params)

        assert result["total_findings"] == 5

    def test_enrichment_assets_limit(self):
        """Test asset enrichment respects limit parameter."""
        handler = MagicMock(spec=StanceRequestHandler)

        # Create multiple assets
        assets = [
            Asset(
                id=f"asset-{i}",
                name=f"asset-{i}",
                resource_type="aws_s3_bucket",
                cloud_provider="aws",
                region="us-east-1",
            )
            for i in range(10)
        ]

        mock_data = MagicMock()
        mock_data.assets = assets

        params = {"limit": ["3"]}

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_data

            with patch("stance.web.server.create_default_pipeline") as mock_pipeline:
                def side_effect(input_assets):
                    return [EnrichedAsset(asset=a, enrichments=[]) for a in input_assets]

                mock_pipeline.return_value.enrich_assets.side_effect = side_effect

                result = StanceRequestHandler._enrichment_assets(handler, params)

        assert result["total_assets"] == 3

    def test_enrichment_findings_not_found(self):
        """Test finding enrichment with non-existent finding ID."""
        handler = MagicMock(spec=StanceRequestHandler)

        mock_data = MagicMock()
        mock_data.findings = []

        params = {"finding_id": ["nonexistent"]}

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_data

            result = StanceRequestHandler._enrichment_findings(handler, params)

        assert result["total_findings"] == 0

    def test_enrichment_assets_not_found(self):
        """Test asset enrichment with non-existent asset ID."""
        handler = MagicMock(spec=StanceRequestHandler)

        mock_data = MagicMock()
        mock_data.assets = []

        params = {"asset_id": ["nonexistent"]}

        with patch("stance.web.server.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_data

            result = StanceRequestHandler._enrichment_assets(handler, params)

        assert result["total_assets"] == 0


class TestEnrichmentAPIRouting:
    """Tests for API routing of enrichment endpoints."""

    def test_api_routes_registered(self):
        """Test that enrichment API routes are properly registered."""
        # These tests verify the routing paths exist
        # Actual routing is tested via integration tests

        enrichment_routes = [
            "/api/enrichment/findings",
            "/api/enrichment/assets",
            "/api/enrichment/ip",
            "/api/enrichment/cve",
            "/api/enrichment/kev",
            "/api/enrichment/status",
        ]

        # Verify route handlers exist
        assert hasattr(StanceRequestHandler, "_enrichment_findings")
        assert hasattr(StanceRequestHandler, "_enrichment_assets")
        assert hasattr(StanceRequestHandler, "_enrichment_ip")
        assert hasattr(StanceRequestHandler, "_enrichment_cve")
        assert hasattr(StanceRequestHandler, "_enrichment_kev")
        assert hasattr(StanceRequestHandler, "_enrichment_status")
