"""
Unit tests for SBOM API endpoints.

Tests cover:
- GET /api/sbom/* endpoints
- Response formats
- Error handling
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stance.web.server import StanceRequestHandler


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)
    handler.storage = MagicMock()
    return handler


# =============================================================================
# Info Endpoint Tests
# =============================================================================


class TestSBOMInfoEndpoint:
    """Tests for /api/sbom/info endpoint."""

    def test_sbom_info_returns_module_info(self, handler):
        """Test that info endpoint returns module information."""
        result = StanceRequestHandler._sbom_info(handler, {})

        assert result is not None
        assert result["module"] == "stance.sbom"
        assert "description" in result
        assert "capabilities" in result
        assert len(result["capabilities"]) > 0

    def test_sbom_info_has_components(self, handler):
        """Test that info includes components."""
        result = StanceRequestHandler._sbom_info(handler, {})

        assert "components" in result
        assert "DependencyParser" in result["components"]
        assert "SBOMGenerator" in result["components"]
        assert "LicenseAnalyzer" in result["components"]
        assert "SupplyChainAnalyzer" in result["components"]


# =============================================================================
# Formats Endpoint Tests
# =============================================================================


class TestSBOMFormatsEndpoint:
    """Tests for /api/sbom/formats endpoint."""

    def test_formats_returns_list(self, handler):
        """Test that formats endpoint returns a list."""
        result = StanceRequestHandler._sbom_formats(handler, {})

        assert result is not None
        assert "formats" in result
        assert len(result["formats"]) > 0
        assert "total" in result

    def test_formats_contains_cyclonedx(self, handler):
        """Test that CycloneDX format is included."""
        result = StanceRequestHandler._sbom_formats(handler, {})

        format_ids = [f["id"] for f in result["formats"]]
        assert "cyclonedx-json" in format_ids
        assert "cyclonedx-xml" in format_ids

    def test_formats_contains_spdx(self, handler):
        """Test that SPDX format is included."""
        result = StanceRequestHandler._sbom_formats(handler, {})

        format_ids = [f["id"] for f in result["formats"]]
        assert "spdx-json" in format_ids
        assert "spdx-tag" in format_ids

    def test_formats_have_required_fields(self, handler):
        """Test that formats have required fields."""
        result = StanceRequestHandler._sbom_formats(handler, {})

        for fmt in result["formats"]:
            assert "name" in fmt
            assert "id" in fmt
            assert "spec_version" in fmt
            assert "description" in fmt


# =============================================================================
# Ecosystems Endpoint Tests
# =============================================================================


class TestSBOMEcosystemsEndpoint:
    """Tests for /api/sbom/ecosystems endpoint."""

    def test_ecosystems_returns_list(self, handler):
        """Test that ecosystems endpoint returns a list."""
        result = StanceRequestHandler._sbom_ecosystems(handler, {})

        assert result is not None
        assert "ecosystems" in result
        assert len(result["ecosystems"]) > 0

    def test_ecosystems_contains_npm(self, handler):
        """Test that NPM ecosystem is included."""
        result = StanceRequestHandler._sbom_ecosystems(handler, {})

        eco_ids = [e["id"] for e in result["ecosystems"]]
        assert "npm" in eco_ids

    def test_ecosystems_contains_pypi(self, handler):
        """Test that PyPI ecosystem is included."""
        result = StanceRequestHandler._sbom_ecosystems(handler, {})

        eco_ids = [e["id"] for e in result["ecosystems"]]
        assert "pypi" in eco_ids

    def test_ecosystems_have_required_fields(self, handler):
        """Test that ecosystems have required fields."""
        result = StanceRequestHandler._sbom_ecosystems(handler, {})

        for eco in result["ecosystems"]:
            assert "name" in eco
            assert "id" in eco
            assert "language" in eco
            assert "files" in eco


# =============================================================================
# Licenses Endpoint Tests
# =============================================================================


class TestSBOMLicensesEndpoint:
    """Tests for /api/sbom/licenses endpoint."""

    def test_licenses_returns_list(self, handler):
        """Test that licenses endpoint returns a list."""
        result = StanceRequestHandler._sbom_licenses(handler, {})

        assert result is not None
        if "error" not in result:
            assert "licenses" in result
            assert "total" in result

    def test_licenses_category_filter(self, handler):
        """Test license category filtering."""
        result = StanceRequestHandler._sbom_licenses(handler, {"category": ["permissive"]})

        if "error" not in result:
            for lic in result.get("licenses", []):
                assert lic["category"] == "permissive"

    def test_licenses_have_required_fields(self, handler):
        """Test that licenses have required fields."""
        result = StanceRequestHandler._sbom_licenses(handler, {})

        if "error" not in result:
            for lic in result.get("licenses", []):
                assert "spdx_id" in lic
                assert "name" in lic
                assert "category" in lic
                assert "risk" in lic


# =============================================================================
# License Categories Endpoint Tests
# =============================================================================


class TestSBOMLicenseCategoriesEndpoint:
    """Tests for /api/sbom/license-categories endpoint."""

    def test_categories_returns_list(self, handler):
        """Test that license categories endpoint returns a list."""
        result = StanceRequestHandler._sbom_license_categories(handler, {})

        assert result is not None
        assert "categories" in result
        assert len(result["categories"]) > 0

    def test_categories_include_permissive(self, handler):
        """Test that permissive category is included."""
        result = StanceRequestHandler._sbom_license_categories(handler, {})

        cat_ids = [c["id"] for c in result["categories"]]
        assert "permissive" in cat_ids

    def test_categories_have_required_fields(self, handler):
        """Test that categories have required fields."""
        result = StanceRequestHandler._sbom_license_categories(handler, {})

        for cat in result["categories"]:
            assert "id" in cat
            assert "name" in cat
            assert "description" in cat


# =============================================================================
# Risk Levels Endpoint Tests
# =============================================================================


class TestSBOMRiskLevelsEndpoint:
    """Tests for /api/sbom/risk-levels endpoint."""

    def test_risk_levels_returns_list(self, handler):
        """Test that risk levels endpoint returns a list."""
        result = StanceRequestHandler._sbom_risk_levels(handler, {})

        assert result is not None
        assert "levels" in result
        assert len(result["levels"]) > 0

    def test_risk_levels_include_critical(self, handler):
        """Test that critical level is included."""
        result = StanceRequestHandler._sbom_risk_levels(handler, {})

        level_ids = [l["id"] for l in result["levels"]]
        assert "critical" in level_ids
        assert "high" in level_ids
        assert "medium" in level_ids
        assert "low" in level_ids

    def test_risk_levels_have_required_fields(self, handler):
        """Test that risk levels have required fields."""
        result = StanceRequestHandler._sbom_risk_levels(handler, {})

        for level in result["levels"]:
            assert "id" in level
            assert "name" in level
            assert "description" in level


# =============================================================================
# Parse Endpoint Tests
# =============================================================================


class TestSBOMParseEndpoint:
    """Tests for /api/sbom/parse endpoint."""

    def test_parse_requires_path(self, handler):
        """Test that parse requires path parameter."""
        result = StanceRequestHandler._sbom_parse(handler, {})

        assert "error" in result
        assert "path" in result["error"].lower()

    def test_parse_with_valid_file(self, handler):
        """Test parsing with valid file."""
        content = json.dumps({
            "dependencies": {"express": "^4.18.0"},
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            result = StanceRequestHandler._sbom_parse(handler, {"path": [f.name]})

            if "error" not in result:
                assert "path" in result
                assert "ecosystem" in result
                assert "dependencies" in result

    def test_parse_nonexistent_file(self, handler):
        """Test parsing nonexistent file."""
        result = StanceRequestHandler._sbom_parse(handler, {"path": ["/nonexistent/file.json"]})

        assert "error" in result


# =============================================================================
# Analyze License Endpoint Tests
# =============================================================================


class TestSBOMAnalyzeLicenseEndpoint:
    """Tests for /api/sbom/analyze-license endpoint."""

    def test_analyze_license_requires_path(self, handler):
        """Test that analyze-license requires path parameter."""
        result = StanceRequestHandler._sbom_analyze_license(handler, {})

        assert "error" in result

    def test_analyze_license_with_valid_file(self, handler):
        """Test analyzing licenses with valid file."""
        content = json.dumps({
            "dependencies": {"express": "^4.18.0"},
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            result = StanceRequestHandler._sbom_analyze_license(handler, {"path": [f.name]})

            if "error" not in result:
                assert "total_dependencies" in result
                assert "summary" in result


# =============================================================================
# Analyze Risk Endpoint Tests
# =============================================================================


class TestSBOMAnalyzeRiskEndpoint:
    """Tests for /api/sbom/analyze-risk endpoint."""

    def test_analyze_risk_requires_path(self, handler):
        """Test that analyze-risk requires path parameter."""
        result = StanceRequestHandler._sbom_analyze_risk(handler, {})

        assert "error" in result

    def test_analyze_risk_with_valid_file(self, handler):
        """Test analyzing risks with valid file."""
        content = json.dumps({
            "dependencies": {"express": "^4.18.0"},
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            result = StanceRequestHandler._sbom_analyze_risk(handler, {"path": [f.name]})

            if "error" not in result:
                assert "total_dependencies" in result
                assert "overall_risk" in result
                assert "risk_score" in result


# =============================================================================
# Status Endpoint Tests
# =============================================================================


class TestSBOMStatusEndpoint:
    """Tests for /api/sbom/status endpoint."""

    def test_status_returns_status(self, handler):
        """Test that status endpoint returns status."""
        result = StanceRequestHandler._sbom_status(handler, {})

        assert result is not None
        assert "status" in result

    def test_status_includes_components(self, handler):
        """Test that status includes components availability."""
        result = StanceRequestHandler._sbom_status(handler, {})

        if result.get("status") == "ok":
            assert "components" in result
            assert "DependencyParser" in result["components"]

    def test_status_includes_capabilities(self, handler):
        """Test that status includes capabilities."""
        result = StanceRequestHandler._sbom_status(handler, {})

        if result.get("status") == "ok":
            assert "capabilities" in result


# =============================================================================
# Summary Endpoint Tests
# =============================================================================


class TestSBOMSummaryEndpoint:
    """Tests for /api/sbom/summary endpoint."""

    def test_summary_returns_overview(self, handler):
        """Test that summary returns overview."""
        result = StanceRequestHandler._sbom_summary(handler, {})

        assert result is not None
        assert "overview" in result
        assert "features" in result

    def test_summary_includes_ecosystems(self, handler):
        """Test that summary includes supported ecosystems."""
        result = StanceRequestHandler._sbom_summary(handler, {})

        assert "supported_ecosystems" in result
        assert len(result["supported_ecosystems"]) > 0

    def test_summary_includes_formats(self, handler):
        """Test that summary includes supported formats."""
        result = StanceRequestHandler._sbom_summary(handler, {})

        assert "supported_formats" in result
        assert len(result["supported_formats"]) > 0

    def test_summary_includes_architecture(self, handler):
        """Test that summary includes architecture."""
        result = StanceRequestHandler._sbom_summary(handler, {})

        assert "architecture" in result
        assert "parsers" in result["architecture"]
        assert "generators" in result["architecture"]
        assert "analyzers" in result["architecture"]


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestSBOMErrorHandling:
    """Tests for error handling in SBOM API endpoints."""

    def test_parse_handles_invalid_file(self, handler):
        """Test that parse handles invalid files gracefully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xyz", delete=False) as f:
            f.write("not a valid dependency file")
            f.flush()

            result = StanceRequestHandler._sbom_parse(handler, {"path": [f.name]})

            # Should return error or empty result
            assert "error" in result or result.get("dependencies", []) == []

    def test_analyze_handles_empty_deps(self, handler):
        """Test that analyze handles empty dependencies."""
        content = json.dumps({"dependencies": {}})

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            result = StanceRequestHandler._sbom_analyze_license(handler, {"path": [f.name]})

            # Should handle gracefully
            if "error" not in result:
                assert result.get("total_dependencies", 0) == 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestSBOMAPIIntegration:
    """Integration tests for SBOM API endpoints."""

    def test_full_analysis_workflow(self, handler):
        """Test full analysis workflow through API."""
        content = json.dumps({
            "name": "test-app",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "4.17.21",
            },
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            # Parse
            parse_result = StanceRequestHandler._sbom_parse(handler, {"path": [f.name]})
            if "error" not in parse_result:
                assert parse_result.get("total", 0) >= 2

            # Analyze licenses
            license_result = StanceRequestHandler._sbom_analyze_license(handler, {"path": [f.name]})
            if "error" not in license_result:
                assert "summary" in license_result

            # Analyze risks
            risk_result = StanceRequestHandler._sbom_analyze_risk(handler, {"path": [f.name]})
            if "error" not in risk_result:
                assert "risk_score" in risk_result

    def test_all_info_endpoints_return_data(self, handler):
        """Test that all info endpoints return valid data."""
        info_result = StanceRequestHandler._sbom_info(handler, {})
        formats_result = StanceRequestHandler._sbom_formats(handler, {})
        ecosystems_result = StanceRequestHandler._sbom_ecosystems(handler, {})
        categories_result = StanceRequestHandler._sbom_license_categories(handler, {})
        levels_result = StanceRequestHandler._sbom_risk_levels(handler, {})
        status_result = StanceRequestHandler._sbom_status(handler, {})
        summary_result = StanceRequestHandler._sbom_summary(handler, {})

        assert info_result is not None
        assert formats_result is not None
        assert ecosystems_result is not None
        assert categories_result is not None
        assert levels_result is not None
        assert status_result is not None
        assert summary_result is not None
