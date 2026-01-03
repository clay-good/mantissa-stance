"""
Unit tests for Web API Export endpoints.

Tests the REST API endpoints for the Export module.
"""

import pytest
from unittest.mock import MagicMock

from stance.web.server import StanceRequestHandler


@pytest.fixture
def handler():
    """Create a mock request handler."""
    handler = MagicMock(spec=StanceRequestHandler)

    # Copy the actual methods to the mock
    handler._export_formats = StanceRequestHandler._export_formats.__get__(handler)
    handler._export_report_types = StanceRequestHandler._export_report_types.__get__(handler)
    handler._export_options = StanceRequestHandler._export_options.__get__(handler)
    handler._export_capabilities = StanceRequestHandler._export_capabilities.__get__(handler)
    handler._export_pdf_tool = StanceRequestHandler._export_pdf_tool.__get__(handler)
    handler._export_severities = StanceRequestHandler._export_severities.__get__(handler)
    handler._export_preview = StanceRequestHandler._export_preview.__get__(handler)
    handler._export_stats = StanceRequestHandler._export_stats.__get__(handler)
    handler._export_status = StanceRequestHandler._export_status.__get__(handler)
    handler._export_summary = StanceRequestHandler._export_summary.__get__(handler)

    return handler


class TestExportFormatsEndpoint:
    """Tests for /api/export/formats endpoint."""

    def test_formats_returns_list(self, handler):
        """Test that formats returns a list."""
        result = handler._export_formats({})
        assert "formats" in result
        assert "total" in result
        assert isinstance(result["formats"], list)

    def test_formats_has_four_formats(self, handler):
        """Test that there are 4 formats."""
        result = handler._export_formats({})
        assert result["total"] == 4

    def test_formats_structure(self, handler):
        """Test format structure."""
        result = handler._export_formats({})
        for fmt in result["formats"]:
            assert "format" in fmt
            assert "name" in fmt
            assert "description" in fmt
            assert "extension" in fmt
            assert "mime_type" in fmt

    def test_formats_includes_expected(self, handler):
        """Test that expected formats are included."""
        result = handler._export_formats({})
        format_ids = [f["format"] for f in result["formats"]]
        assert "json" in format_ids
        assert "csv" in format_ids
        assert "html" in format_ids
        assert "pdf" in format_ids


class TestExportReportTypesEndpoint:
    """Tests for /api/export/report-types endpoint."""

    def test_report_types_returns_list(self, handler):
        """Test that report types returns list."""
        result = handler._export_report_types({})
        assert "report_types" in result
        assert "total" in result
        assert result["total"] == 5

    def test_report_types_structure(self, handler):
        """Test report type structure."""
        result = handler._export_report_types({})
        for rt in result["report_types"]:
            assert "type" in rt
            assert "name" in rt
            assert "description" in rt
            assert "sections" in rt

    def test_report_types_includes_expected(self, handler):
        """Test that expected report types are included."""
        result = handler._export_report_types({})
        type_ids = [rt["type"] for rt in result["report_types"]]
        assert "full_report" in type_ids
        assert "executive_summary" in type_ids
        assert "findings_detail" in type_ids
        assert "compliance_summary" in type_ids
        assert "asset_inventory" in type_ids

    def test_report_types_have_sections(self, handler):
        """Test that report types have sections."""
        result = handler._export_report_types({})
        for rt in result["report_types"]:
            assert len(rt["sections"]) > 0


class TestExportOptionsEndpoint:
    """Tests for /api/export/options endpoint."""

    def test_options_returns_list(self, handler):
        """Test that options returns list."""
        result = handler._export_options({})
        assert "options" in result
        assert "total" in result
        assert result["total"] == 10

    def test_options_structure(self, handler):
        """Test option structure."""
        result = handler._export_options({})
        for opt in result["options"]:
            assert "option" in opt
            assert "type" in opt
            assert "description" in opt

    def test_options_have_defaults(self, handler):
        """Test that options have defaults."""
        result = handler._export_options({})
        for opt in result["options"]:
            assert "default" in opt

    def test_enum_options_have_values(self, handler):
        """Test that enum options have values."""
        result = handler._export_options({})
        enum_opts = [o for o in result["options"] if o["type"] == "enum"]
        for opt in enum_opts:
            assert "values" in opt
            assert len(opt["values"]) > 0


class TestExportCapabilitiesEndpoint:
    """Tests for /api/export/capabilities endpoint."""

    def test_capabilities_returns_dict(self, handler):
        """Test that capabilities returns dict."""
        result = handler._export_capabilities({})
        assert "capabilities" in result
        assert isinstance(result["capabilities"], dict)

    def test_capabilities_has_all_formats(self, handler):
        """Test that capabilities has all formats."""
        result = handler._export_capabilities({})
        assert "json" in result["capabilities"]
        assert "csv" in result["capabilities"]
        assert "html" in result["capabilities"]
        assert "pdf" in result["capabilities"]

    def test_capabilities_structure(self, handler):
        """Test capability structure."""
        result = handler._export_capabilities({})
        for fmt, caps in result["capabilities"].items():
            assert "charts" in caps
            assert "styling" in caps
            assert "raw_data" in caps
            assert "streaming" in caps
            assert "features" in caps

    def test_json_capabilities(self, handler):
        """Test JSON format capabilities."""
        result = handler._export_capabilities({})
        json_caps = result["capabilities"]["json"]
        assert json_caps["charts"] is False
        assert json_caps["raw_data"] is True
        assert json_caps["streaming"] is True

    def test_html_capabilities(self, handler):
        """Test HTML format capabilities."""
        result = handler._export_capabilities({})
        html_caps = result["capabilities"]["html"]
        assert html_caps["charts"] is True
        assert html_caps["styling"] is True


class TestExportPdfToolEndpoint:
    """Tests for /api/export/pdf-tool endpoint."""

    def test_pdf_tool_returns_dict(self, handler):
        """Test that pdf-tool returns dict."""
        result = handler._export_pdf_tool({})
        assert isinstance(result, dict)

    def test_pdf_tool_structure(self, handler):
        """Test pdf-tool structure."""
        result = handler._export_pdf_tool({})
        assert "pdf_available" in result
        assert "tools_checked" in result
        assert "install_instructions" in result

    def test_pdf_tool_has_tools_checked(self, handler):
        """Test that tools checked are listed."""
        result = handler._export_pdf_tool({})
        assert "wkhtmltopdf" in result["tools_checked"]
        assert "weasyprint" in result["tools_checked"]

    def test_pdf_tool_has_install_instructions(self, handler):
        """Test that install instructions are provided."""
        result = handler._export_pdf_tool({})
        assert "wkhtmltopdf" in result["install_instructions"]
        assert "weasyprint" in result["install_instructions"]


class TestExportSeveritiesEndpoint:
    """Tests for /api/export/severities endpoint."""

    def test_severities_returns_list(self, handler):
        """Test that severities returns list."""
        result = handler._export_severities({})
        assert "severities" in result
        assert "total" in result
        assert result["total"] == 5

    def test_severities_structure(self, handler):
        """Test severity structure."""
        result = handler._export_severities({})
        for sev in result["severities"]:
            assert "level" in sev
            assert "description" in sev
            assert "priority" in sev
            assert "examples" in sev

    def test_severities_ordered(self, handler):
        """Test that severities are ordered by priority."""
        result = handler._export_severities({})
        priorities = [s["priority"] for s in result["severities"]]
        assert priorities == [1, 2, 3, 4, 5]

    def test_severities_include_expected(self, handler):
        """Test that expected severities are included."""
        result = handler._export_severities({})
        levels = [s["level"] for s in result["severities"]]
        assert "critical" in levels
        assert "high" in levels
        assert "medium" in levels
        assert "low" in levels
        assert "info" in levels


class TestExportPreviewEndpoint:
    """Tests for /api/export/preview endpoint."""

    def test_preview_returns_dict(self, handler):
        """Test that preview returns dict."""
        result = handler._export_preview({})
        assert isinstance(result, dict)

    def test_preview_json_format(self, handler):
        """Test preview with JSON format."""
        result = handler._export_preview({"format": ["json"]})
        assert result.get("success") is True
        assert result.get("format") == "json"

    def test_preview_csv_format(self, handler):
        """Test preview with CSV format."""
        result = handler._export_preview({"format": ["csv"]})
        assert result.get("success") is True
        assert result.get("format") == "csv"

    def test_preview_html_format(self, handler):
        """Test preview with HTML format."""
        result = handler._export_preview({"format": ["html"]})
        assert result.get("success") is True
        assert result.get("format") == "html"

    def test_preview_includes_bytes(self, handler):
        """Test that preview includes bytes generated."""
        result = handler._export_preview({"format": ["json"]})
        assert "bytes_generated" in result


class TestExportStatsEndpoint:
    """Tests for /api/export/stats endpoint."""

    def test_stats_returns_dict(self, handler):
        """Test that stats returns dict."""
        result = handler._export_stats({})
        assert isinstance(result, dict)

    def test_stats_structure(self, handler):
        """Test stats structure."""
        result = handler._export_stats({})
        assert "formats_supported" in result
        assert "report_types" in result
        assert "export_options" in result
        assert "severity_levels" in result

    def test_stats_values(self, handler):
        """Test stats values."""
        result = handler._export_stats({})
        assert result["formats_supported"] == 4
        assert result["report_types"] == 5
        assert result["export_options"] == 10
        assert result["severity_levels"] == 5

    def test_stats_has_data_types(self, handler):
        """Test that stats has data types."""
        result = handler._export_stats({})
        assert "supported_data_types" in result
        assert "assets" in result["supported_data_types"]
        assert "findings" in result["supported_data_types"]


class TestExportStatusEndpoint:
    """Tests for /api/export/status endpoint."""

    def test_status_returns_dict(self, handler):
        """Test that status returns dict."""
        result = handler._export_status({})
        assert isinstance(result, dict)

    def test_status_structure(self, handler):
        """Test status structure."""
        result = handler._export_status({})
        assert "module" in result
        assert "status" in result
        assert "components" in result
        assert "capabilities" in result

    def test_status_module_name(self, handler):
        """Test that module name is export."""
        result = handler._export_status({})
        assert result["module"] == "export"

    def test_status_components(self, handler):
        """Test that components are listed."""
        result = handler._export_status({})
        assert "ExportManager" in result["components"]
        assert "CSVExporter" in result["components"]
        assert "JSONExporter" in result["components"]
        assert "HTMLExporter" in result["components"]
        assert "PDFExporter" in result["components"]

    def test_status_has_available_formats(self, handler):
        """Test that available formats are listed."""
        result = handler._export_status({})
        assert "available_formats" in result
        assert len(result["available_formats"]) > 0


class TestExportSummaryEndpoint:
    """Tests for /api/export/summary endpoint."""

    def test_summary_returns_dict(self, handler):
        """Test that summary returns dict."""
        result = handler._export_summary({})
        assert isinstance(result, dict)

    def test_summary_structure(self, handler):
        """Test summary structure."""
        result = handler._export_summary({})
        assert "module" in result
        assert "version" in result
        assert "description" in result
        assert "formats" in result
        assert "report_types" in result
        assert "features" in result

    def test_summary_module_name(self, handler):
        """Test that module name is export."""
        result = handler._export_summary({})
        assert result["module"] == "export"

    def test_summary_formats(self, handler):
        """Test that formats are documented."""
        result = handler._export_summary({})
        assert "json" in result["formats"]
        assert "csv" in result["formats"]
        assert "html" in result["formats"]
        assert "pdf" in result["formats"]

    def test_summary_report_types(self, handler):
        """Test that report types are documented."""
        result = handler._export_summary({})
        assert "full_report" in result["report_types"]
        assert "executive_summary" in result["report_types"]

    def test_summary_features(self, handler):
        """Test that features are listed."""
        result = handler._export_summary({})
        assert len(result["features"]) >= 5

    def test_summary_pdf_status(self, handler):
        """Test that PDF status is included."""
        result = handler._export_summary({})
        assert "pdf_status" in result
        assert "available" in result["pdf_status"]


class TestEndpointRouting:
    """Tests for endpoint routing in do_GET."""

    def test_get_endpoints_exist(self):
        """Test that all export GET endpoints are routed."""
        endpoints = [
            "/api/export/formats",
            "/api/export/report-types",
            "/api/export/options",
            "/api/export/capabilities",
            "/api/export/pdf-tool",
            "/api/export/severities",
            "/api/export/preview",
            "/api/export/stats",
            "/api/export/status",
            "/api/export/summary",
        ]

        for endpoint in endpoints:
            # Handle hyphenated names
            method_name = "_export_" + endpoint.split("/")[-1].replace("-", "_")
            assert hasattr(StanceRequestHandler, method_name), f"Method {method_name} not found"


class TestPreviewReportTypes:
    """Tests for preview with different report types."""

    def test_preview_full_report(self, handler):
        """Test preview with full report."""
        result = handler._export_preview({"report_type": ["full_report"]})
        assert result.get("success") is True

    def test_preview_executive_summary(self, handler):
        """Test preview with executive summary."""
        result = handler._export_preview({"report_type": ["executive_summary"]})
        assert result.get("success") is True

    def test_preview_findings_detail(self, handler):
        """Test preview with findings detail."""
        result = handler._export_preview({"report_type": ["findings_detail"]})
        assert result.get("success") is True

    def test_preview_compliance_summary(self, handler):
        """Test preview with compliance summary."""
        result = handler._export_preview({"report_type": ["compliance_summary"]})
        assert result.get("success") is True

    def test_preview_asset_inventory(self, handler):
        """Test preview with asset inventory."""
        result = handler._export_preview({"report_type": ["asset_inventory"]})
        assert result.get("success") is True


class TestIntegration:
    """Integration tests for export API endpoints."""

    def test_stats_matches_formats(self, handler):
        """Test that stats format count matches formats."""
        stats = handler._export_stats({})
        formats = handler._export_formats({})
        assert stats["formats_supported"] == formats["total"]

    def test_stats_matches_report_types(self, handler):
        """Test that stats report type count matches report types."""
        stats = handler._export_stats({})
        types = handler._export_report_types({})
        assert stats["report_types"] == types["total"]

    def test_stats_matches_severities(self, handler):
        """Test that stats severity count matches severities."""
        stats = handler._export_stats({})
        severities = handler._export_severities({})
        assert stats["severity_levels"] == severities["total"]

    def test_status_components_match_summary(self, handler):
        """Test that status and summary are consistent."""
        status = handler._export_status({})
        summary = handler._export_summary({})
        assert status["module"] == summary["module"]


class TestEdgeCases:
    """Tests for edge cases."""

    def test_preview_defaults_to_json(self, handler):
        """Test that preview defaults to JSON format."""
        result = handler._export_preview({})
        assert result.get("format") == "json"

    def test_preview_defaults_to_executive_summary(self, handler):
        """Test that preview defaults to executive summary."""
        result = handler._export_preview({})
        assert result.get("report_type") == "executive_summary"

    def test_capabilities_features_not_empty(self, handler):
        """Test that capabilities features are not empty."""
        result = handler._export_capabilities({})
        for fmt, caps in result["capabilities"].items():
            assert len(caps["features"]) > 0, f"No features for {fmt}"

    def test_options_total_matches_list(self, handler):
        """Test that options total matches list length."""
        result = handler._export_options({})
        assert result["total"] == len(result["options"])
