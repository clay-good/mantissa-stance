"""
Unit tests for Web API Scanner endpoints.

Tests the REST API endpoints for the Scanner module.
"""

import pytest
from unittest.mock import MagicMock

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)

    # Copy the actual methods to the mock
    handler._scanner_scanners = StanceRequestHandler._scanner_scanners.__get__(handler)
    handler._scanner_check = StanceRequestHandler._scanner_check.__get__(handler)
    handler._scanner_version = StanceRequestHandler._scanner_version.__get__(handler)
    handler._scanner_enrich = StanceRequestHandler._scanner_enrich.__get__(handler)
    handler._scanner_epss = StanceRequestHandler._scanner_epss.__get__(handler)
    handler._scanner_kev = StanceRequestHandler._scanner_kev.__get__(handler)
    handler._scanner_severity_levels = StanceRequestHandler._scanner_severity_levels.__get__(handler)
    handler._scanner_priority_factors = StanceRequestHandler._scanner_priority_factors.__get__(handler)
    handler._scanner_package_types = StanceRequestHandler._scanner_package_types.__get__(handler)
    handler._scanner_stats = StanceRequestHandler._scanner_stats.__get__(handler)
    handler._scanner_status = StanceRequestHandler._scanner_status.__get__(handler)
    handler._scanner_summary = StanceRequestHandler._scanner_summary.__get__(handler)

    return handler


class TestScannerScannersEndpoint:
    """Tests for /api/scanner/scanners endpoint."""

    def test_scanners_returns_list(self, handler):
        """Test that scanners returns a list."""
        result = handler._scanner_scanners({})
        assert "scanners" in result
        assert "total" in result
        assert "available" in result
        assert isinstance(result["scanners"], list)

    def test_scanners_has_trivy(self, handler):
        """Test that Trivy is listed."""
        result = handler._scanner_scanners({})
        scanner_ids = [s["id"] for s in result["scanners"]]
        assert "trivy" in scanner_ids

    def test_scanners_structure(self, handler):
        """Test scanner structure."""
        result = handler._scanner_scanners({})
        for scanner in result["scanners"]:
            assert "id" in scanner
            assert "name" in scanner
            assert "description" in scanner
            assert "available" in scanner
            assert "install" in scanner
            assert "supported_targets" in scanner

    def test_scanners_total_matches_list(self, handler):
        """Test that total matches list length."""
        result = handler._scanner_scanners({})
        assert result["total"] == len(result["scanners"])


class TestScannerCheckEndpoint:
    """Tests for /api/scanner/check endpoint."""

    def test_check_returns_dict(self, handler):
        """Test that check returns dictionary."""
        result = handler._scanner_check({})
        assert isinstance(result, dict)

    def test_check_structure(self, handler):
        """Test check response structure."""
        result = handler._scanner_check({})
        assert "scanner" in result
        assert "available" in result
        assert "message" in result
        assert result["scanner"] == "trivy"

    def test_check_has_version_when_available(self, handler):
        """Test that version is present in response."""
        result = handler._scanner_check({})
        assert "version" in result
        # Version may be None if Trivy is not installed

    def test_check_message_reflects_availability(self, handler):
        """Test that message reflects scanner availability."""
        result = handler._scanner_check({})
        if result["available"]:
            assert "installed" in result["message"].lower()
        else:
            assert "not installed" in result["message"].lower()


class TestScannerVersionEndpoint:
    """Tests for /api/scanner/version endpoint."""

    def test_version_returns_dict(self, handler):
        """Test that version returns dictionary."""
        result = handler._scanner_version({})
        assert isinstance(result, dict)

    def test_version_structure(self, handler):
        """Test version response structure."""
        result = handler._scanner_version({})
        assert "scanner" in result
        assert "version" in result
        assert "available" in result
        assert result["scanner"] == "trivy"

    def test_version_available_matches_version_presence(self, handler):
        """Test that available matches version presence."""
        result = handler._scanner_version({})
        if result["available"]:
            assert result["version"] is not None
        else:
            assert result["version"] is None


class TestScannerEnrichEndpoint:
    """Tests for /api/scanner/enrich endpoint."""

    def test_enrich_requires_cve_id(self, handler):
        """Test that cve_id is required."""
        result = handler._scanner_enrich({})
        assert "error" in result
        assert "cve_id" in result["error"]

    def test_enrich_invalid_cve_format(self, handler):
        """Test that invalid CVE format is rejected."""
        result = handler._scanner_enrich({"cve_id": "invalid"})
        assert "error" in result
        assert "Invalid CVE ID" in result["error"]

    def test_enrich_valid_cve(self, handler):
        """Test enriching valid CVE."""
        result = handler._scanner_enrich({"cve_id": "CVE-2021-44228"})
        assert "cve_id" in result
        assert result["cve_id"] == "CVE-2021-44228"
        assert "epss" in result
        assert "kev" in result

    def test_enrich_converts_to_uppercase(self, handler):
        """Test that CVE ID is converted to uppercase."""
        result = handler._scanner_enrich({"cve_id": "cve-2021-44228"})
        assert result["cve_id"] == "CVE-2021-44228"

    def test_enrich_kev_structure(self, handler):
        """Test KEV response structure."""
        result = handler._scanner_enrich({"cve_id": "CVE-2021-44228"})
        assert "in_catalog" in result["kev"]


class TestScannerEpssEndpoint:
    """Tests for /api/scanner/epss endpoint."""

    def test_epss_requires_cve_id(self, handler):
        """Test that cve_id is required."""
        result = handler._scanner_epss({})
        assert "error" in result
        assert "cve_id" in result["error"]

    def test_epss_invalid_cve_format(self, handler):
        """Test that invalid CVE format is rejected."""
        result = handler._scanner_epss({"cve_id": "invalid"})
        assert "error" in result
        assert "Invalid CVE ID" in result["error"]

    def test_epss_valid_cve(self, handler):
        """Test EPSS lookup for valid CVE."""
        result = handler._scanner_epss({"cve_id": "CVE-2021-44228"})
        assert "cve_id" in result
        assert result["cve_id"] == "CVE-2021-44228"
        assert "found" in result

    def test_epss_structure(self, handler):
        """Test EPSS response structure."""
        result = handler._scanner_epss({"cve_id": "CVE-2021-44228"})
        assert "score" in result
        assert "percentile" in result
        assert "date" in result

    def test_epss_converts_to_uppercase(self, handler):
        """Test that CVE ID is converted to uppercase."""
        result = handler._scanner_epss({"cve_id": "cve-2021-44228"})
        assert result["cve_id"] == "CVE-2021-44228"


class TestScannerKevEndpoint:
    """Tests for /api/scanner/kev endpoint."""

    def test_kev_requires_cve_id(self, handler):
        """Test that cve_id is required."""
        result = handler._scanner_kev({})
        assert "error" in result
        assert "cve_id" in result["error"]

    def test_kev_invalid_cve_format(self, handler):
        """Test that invalid CVE format is rejected."""
        result = handler._scanner_kev({"cve_id": "invalid"})
        assert "error" in result
        assert "Invalid CVE ID" in result["error"]

    def test_kev_valid_cve(self, handler):
        """Test KEV lookup for valid CVE."""
        result = handler._scanner_kev({"cve_id": "CVE-2021-44228"})
        assert "cve_id" in result
        assert result["cve_id"] == "CVE-2021-44228"
        assert "in_catalog" in result

    def test_kev_known_vuln_has_details(self, handler):
        """Test that known KEV entries have details."""
        result = handler._scanner_kev({"cve_id": "CVE-2021-44228"})
        if result["in_catalog"]:
            assert "vendor" in result
            assert "product" in result
            assert "date_added" in result

    def test_kev_converts_to_uppercase(self, handler):
        """Test that CVE ID is converted to uppercase."""
        result = handler._scanner_kev({"cve_id": "cve-2021-44228"})
        assert result["cve_id"] == "CVE-2021-44228"


class TestScannerSeverityLevelsEndpoint:
    """Tests for /api/scanner/severity-levels endpoint."""

    def test_severity_levels_returns_list(self, handler):
        """Test that severity levels returns list."""
        result = handler._scanner_severity_levels({})
        assert "levels" in result
        assert "total" in result
        assert result["total"] == 5

    def test_severity_levels_structure(self, handler):
        """Test severity level structure."""
        result = handler._scanner_severity_levels({})
        for level in result["levels"]:
            assert "level" in level
            assert "description" in level
            assert "cvss_range" in level
            assert "examples" in level

    def test_severity_levels_include_expected(self, handler):
        """Test that expected levels are included."""
        result = handler._scanner_severity_levels({})
        levels = [l["level"] for l in result["levels"]]
        assert "CRITICAL" in levels
        assert "HIGH" in levels
        assert "MEDIUM" in levels
        assert "LOW" in levels
        assert "UNKNOWN" in levels

    def test_severity_levels_total_matches_list(self, handler):
        """Test that total matches list length."""
        result = handler._scanner_severity_levels({})
        assert result["total"] == len(result["levels"])


class TestScannerPriorityFactorsEndpoint:
    """Tests for /api/scanner/priority-factors endpoint."""

    def test_priority_factors_returns_dict(self, handler):
        """Test that priority factors returns dictionary."""
        result = handler._scanner_priority_factors({})
        assert isinstance(result, dict)

    def test_priority_factors_structure(self, handler):
        """Test priority factors structure."""
        result = handler._scanner_priority_factors({})
        assert "max_score" in result
        assert "factors" in result
        assert result["max_score"] == 100

    def test_priority_factors_list_structure(self, handler):
        """Test priority factor list structure."""
        result = handler._scanner_priority_factors({})
        for factor in result["factors"]:
            assert "factor" in factor
            assert "max_points" in factor
            assert "description" in factor

    def test_priority_factors_includes_expected(self, handler):
        """Test that expected factors are included."""
        result = handler._scanner_priority_factors({})
        factor_names = [f["factor"] for f in result["factors"]]
        assert "Severity" in factor_names
        assert "CVSS Score" in factor_names
        assert "EPSS Score" in factor_names
        assert "KEV Catalog" in factor_names

    def test_priority_factors_count(self, handler):
        """Test that there are 6 priority factors."""
        result = handler._scanner_priority_factors({})
        assert len(result["factors"]) == 6


class TestScannerPackageTypesEndpoint:
    """Tests for /api/scanner/package-types endpoint."""

    def test_package_types_returns_list(self, handler):
        """Test that package types returns list."""
        result = handler._scanner_package_types({})
        assert "package_types" in result
        assert "total" in result
        assert result["total"] == 12

    def test_package_types_structure(self, handler):
        """Test package type structure."""
        result = handler._scanner_package_types({})
        for pt in result["package_types"]:
            assert "type" in pt
            assert "ecosystem" in pt
            assert "description" in pt

    def test_package_types_include_expected(self, handler):
        """Test that expected package types are included."""
        result = handler._scanner_package_types({})
        types = [pt["type"] for pt in result["package_types"]]
        assert "npm" in types
        assert "pip" in types
        assert "gem" in types
        assert "cargo" in types
        assert "go" in types
        assert "maven" in types

    def test_package_types_total_matches_list(self, handler):
        """Test that total matches list length."""
        result = handler._scanner_package_types({})
        assert result["total"] == len(result["package_types"])


class TestScannerStatsEndpoint:
    """Tests for /api/scanner/stats endpoint."""

    def test_stats_returns_dict(self, handler):
        """Test that stats returns dictionary."""
        result = handler._scanner_stats({})
        assert isinstance(result, dict)

    def test_stats_structure(self, handler):
        """Test stats structure."""
        result = handler._scanner_stats({})
        assert "scanner" in result
        assert "available" in result
        assert "severity_levels" in result
        assert "package_types" in result
        assert "enrichment_sources" in result
        assert "priority_factors" in result

    def test_stats_values(self, handler):
        """Test stats values."""
        result = handler._scanner_stats({})
        assert result["scanner"] == "trivy"
        assert result["severity_levels"] == 5
        assert result["package_types"] == 12
        assert result["priority_factors"] == 6

    def test_stats_enrichment_sources(self, handler):
        """Test that enrichment sources are listed."""
        result = handler._scanner_stats({})
        assert "EPSS" in result["enrichment_sources"]
        assert "KEV" in result["enrichment_sources"]

    def test_stats_supported_targets(self, handler):
        """Test that supported targets are listed."""
        result = handler._scanner_stats({})
        assert "supported_targets" in result
        assert "container_images" in result["supported_targets"]


class TestScannerStatusEndpoint:
    """Tests for /api/scanner/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns dictionary."""
        result = handler._scanner_status({})
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._scanner_status({})
        assert "module" in result
        assert "status" in result
        assert "components" in result
        assert "capabilities" in result

    def test_status_module_name(self, handler):
        """Test that module name is scanner."""
        result = handler._scanner_status({})
        assert result["module"] == "scanner"

    def test_status_components(self, handler):
        """Test that components are listed."""
        result = handler._scanner_status({})
        assert "TrivyScanner" in result["components"]
        assert "CVEEnricher" in result["components"]
        assert "EPSSClient" in result["components"]
        assert "KEVClient" in result["components"]

    def test_status_capabilities(self, handler):
        """Test that capabilities are listed."""
        result = handler._scanner_status({})
        assert "container_image_scanning" in result["capabilities"]
        assert "vulnerability_detection" in result["capabilities"]
        assert "cve_enrichment" in result["capabilities"]


class TestScannerSummaryEndpoint:
    """Tests for /api/scanner/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns dictionary."""
        result = handler._scanner_summary({})
        assert isinstance(result, dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._scanner_summary({})
        assert "module" in result
        assert "version" in result
        assert "description" in result
        assert "scanner" in result
        assert "enrichment" in result
        assert "features" in result
        assert "supported_ecosystems" in result

    def test_summary_module_name(self, handler):
        """Test that module name is scanner."""
        result = handler._scanner_summary({})
        assert result["module"] == "scanner"

    def test_summary_scanner_info(self, handler):
        """Test that scanner info is present."""
        result = handler._scanner_summary({})
        assert result["scanner"]["name"] == "Trivy"
        assert "available" in result["scanner"]

    def test_summary_enrichment_sources(self, handler):
        """Test that enrichment sources are documented."""
        result = handler._scanner_summary({})
        assert "epss" in result["enrichment"]
        assert "kev" in result["enrichment"]

    def test_summary_features(self, handler):
        """Test that features are listed."""
        result = handler._scanner_summary({})
        assert len(result["features"]) >= 5

    def test_summary_supported_ecosystems(self, handler):
        """Test that supported ecosystems are listed."""
        result = handler._scanner_summary({})
        ecosystems = result["supported_ecosystems"]
        assert any("npm" in e.lower() for e in ecosystems)
        assert any("pip" in e.lower() for e in ecosystems)


class TestEndpointRouting:
    """Tests for endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all scanner GET endpoints are routed."""
        endpoints = [
            "/api/scanner/scanners",
            "/api/scanner/check",
            "/api/scanner/version",
            "/api/scanner/enrich",
            "/api/scanner/epss",
            "/api/scanner/kev",
            "/api/scanner/severity-levels",
            "/api/scanner/priority-factors",
            "/api/scanner/package-types",
            "/api/scanner/stats",
            "/api/scanner/status",
            "/api/scanner/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_scanner_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"


class TestCVEValidation:
    """Tests for CVE ID validation in API endpoints."""

    def test_enrich_cve_without_prefix(self, handler):
        """Test that enrich rejects CVE without prefix."""
        result = handler._scanner_enrich({"cve_id": "2021-44228"})
        assert "error" in result

    def test_epss_cve_without_prefix(self, handler):
        """Test that EPSS rejects CVE without prefix."""
        result = handler._scanner_epss({"cve_id": "2021-44228"})
        assert "error" in result

    def test_kev_cve_without_prefix(self, handler):
        """Test that KEV rejects CVE without prefix."""
        result = handler._scanner_kev({"cve_id": "2021-44228"})
        assert "error" in result

    def test_enrich_empty_cve_id(self, handler):
        """Test that enrich rejects empty CVE ID."""
        result = handler._scanner_enrich({"cve_id": ""})
        assert "error" in result

    def test_epss_empty_cve_id(self, handler):
        """Test that EPSS rejects empty CVE ID."""
        result = handler._scanner_epss({"cve_id": ""})
        assert "error" in result

    def test_kev_empty_cve_id(self, handler):
        """Test that KEV rejects empty CVE ID."""
        result = handler._scanner_kev({"cve_id": ""})
        assert "error" in result


class TestEdgeCases:
    """Tests for edge cases."""

    def test_scanners_returns_consistent_count(self, handler):
        """Test that scanners returns consistent count."""
        result1 = handler._scanner_scanners({})
        result2 = handler._scanner_scanners({})
        assert result1["total"] == result2["total"]

    def test_severity_levels_ordered(self, handler):
        """Test that severity levels are in expected order."""
        result = handler._scanner_severity_levels({})
        levels = [l["level"] for l in result["levels"]]
        assert levels[0] == "CRITICAL"
        assert levels[4] == "UNKNOWN"

    def test_package_types_have_descriptions(self, handler):
        """Test that all package types have descriptions."""
        result = handler._scanner_package_types({})
        for pt in result["package_types"]:
            assert pt["description"], f"Missing description for {pt['type']}"

    def test_priority_factors_sum_to_max(self, handler):
        """Test that priority factor max points could sum to more than max score."""
        result = handler._scanner_priority_factors({})
        total_points = sum(f["max_points"] for f in result["factors"])
        # Total possible points should be >= max_score
        # (not all factors can be maxed simultaneously)
        assert total_points >= result["max_score"]


class TestIntegration:
    """Integration tests for scanner API endpoints."""

    def test_stats_matches_severity_levels(self, handler):
        """Test that stats severity count matches severity levels."""
        stats = handler._scanner_stats({})
        levels = handler._scanner_severity_levels({})
        assert stats["severity_levels"] == levels["total"]

    def test_stats_matches_package_types(self, handler):
        """Test that stats package type count matches package types."""
        stats = handler._scanner_stats({})
        types = handler._scanner_package_types({})
        assert stats["package_types"] == types["total"]

    def test_status_components_match_summary(self, handler):
        """Test that status and summary are consistent."""
        status = handler._scanner_status({})
        summary = handler._scanner_summary({})
        assert status["module"] == summary["module"]

    def test_check_matches_status_availability(self, handler):
        """Test that check and status report same availability."""
        check = handler._scanner_check({})
        status = handler._scanner_status({})
        # If scanner is available in check, status should be operational
        if check["available"]:
            assert status["status"] == "operational"
        else:
            assert status["status"] == "degraded"
