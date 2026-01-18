"""
Export handlers for the Stance web API.

This module handles all /api/export/* endpoints for report
export and format management.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class ExportHandler(RoutedHandler):
    """
    Handler for export API endpoints.

    Handles:
    - Export format listing
    - Report type management
    - Export options and capabilities
    - PDF tool availability
    """

    base_path = "/api/export/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("formats")
    def export_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available export formats."""
        formats = [
            {
                "format": "json",
                "name": "JSON",
                "description": "Structured JSON output with full data fidelity",
                "extension": ".json",
                "mime_type": "application/json",
            },
            {
                "format": "csv",
                "name": "CSV",
                "description": "Comma-separated values for spreadsheet import",
                "extension": ".csv",
                "mime_type": "text/csv",
            },
            {
                "format": "html",
                "name": "HTML",
                "description": "Styled HTML report viewable in browsers",
                "extension": ".html",
                "mime_type": "text/html",
            },
            {
                "format": "pdf",
                "name": "PDF",
                "description": "Printable PDF document (requires wkhtmltopdf or weasyprint)",
                "extension": ".pdf",
                "mime_type": "application/pdf",
            },
        ]

        return HandlerResponse.success({
            "total": len(formats),
            "formats": formats,
        })

    @route("report-types")
    def export_report_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available report types."""
        report_types = [
            {
                "type": "full_report",
                "name": "Full Report",
                "description": "Comprehensive report with all data (findings, assets, compliance)",
                "sections": ["summary", "findings", "assets", "compliance", "trends"],
            },
            {
                "type": "executive_summary",
                "name": "Executive Summary",
                "description": "High-level overview for management review",
                "sections": ["summary", "key_metrics", "top_risks", "compliance_scores"],
            },
            {
                "type": "findings_detail",
                "name": "Findings Detail",
                "description": "Detailed findings report with remediation guidance",
                "sections": ["findings_by_severity", "remediation"],
            },
            {
                "type": "compliance_summary",
                "name": "Compliance Summary",
                "description": "Compliance framework scores and control status",
                "sections": ["framework_scores", "control_status"],
            },
            {
                "type": "asset_inventory",
                "name": "Asset Inventory",
                "description": "Complete asset listing with metadata",
                "sections": ["assets_by_type", "assets_by_region", "tags"],
            },
        ]

        return HandlerResponse.success({
            "total": len(report_types),
            "report_types": report_types,
        })

    @route("options")
    def export_options(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show available export options."""
        options = [
            {
                "option": "format",
                "type": "enum",
                "values": ["json", "csv", "html", "pdf"],
                "default": "json",
                "description": "Output format for the report",
            },
            {
                "option": "report_type",
                "type": "enum",
                "values": ["full_report", "executive_summary", "findings_detail", "compliance_summary", "asset_inventory"],
                "default": "full_report",
                "description": "Type of report to generate",
            },
            {
                "option": "output_path",
                "type": "string",
                "default": None,
                "description": "File path to write the report",
            },
            {
                "option": "title",
                "type": "string",
                "default": "Mantissa Stance Security Report",
                "description": "Report title",
            },
            {
                "option": "author",
                "type": "string",
                "default": "Mantissa Stance",
                "description": "Report author name",
            },
            {
                "option": "severity_filter",
                "type": "enum",
                "values": ["critical", "high", "medium", "low", "info"],
                "default": None,
                "description": "Only include findings at or above this severity",
            },
            {
                "option": "include_charts",
                "type": "boolean",
                "default": True,
                "description": "Include visual charts (HTML/PDF only)",
            },
            {
                "option": "include_raw_data",
                "type": "boolean",
                "default": False,
                "description": "Include raw asset configuration data",
            },
        ]

        return HandlerResponse.success({
            "total": len(options),
            "options": options,
        })

    @route("capabilities")
    def export_capabilities(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show export format capabilities."""
        capabilities = {
            "json": {
                "charts": False,
                "styling": False,
                "raw_data": True,
                "streaming": True,
                "compression": False,
                "features": ["Full data fidelity", "API compatible", "Machine readable", "Nested structures"],
            },
            "csv": {
                "charts": False,
                "styling": False,
                "raw_data": False,
                "streaming": True,
                "compression": False,
                "features": ["Spreadsheet import", "Simple structure", "Wide compatibility", "Tabular data"],
            },
            "html": {
                "charts": True,
                "styling": True,
                "raw_data": True,
                "streaming": False,
                "compression": False,
                "features": ["Browser viewable", "Print-ready", "Embedded CSS", "Interactive elements"],
            },
            "pdf": {
                "charts": True,
                "styling": True,
                "raw_data": True,
                "streaming": False,
                "compression": True,
                "features": ["Portable document", "Print optimized", "Fixed layout", "Professional output"],
            },
        }

        return HandlerResponse.success({"capabilities": capabilities})

    @route("pdf-tool")
    def export_pdf_tool(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check PDF tool availability."""
        try:
            from stance.export import PDFExporter

            exporter = PDFExporter()
            tool = exporter.get_pdf_tool()
            available = exporter.is_pdf_available()

            return HandlerResponse.success({
                "available": available,
                "tool": tool,
                "message": f"{tool} is available for PDF generation" if available else "No PDF tool installed",
                "install_options": [
                    "brew install wkhtmltopdf",
                    "pip install weasyprint",
                ],
            })
        except ImportError as e:
            return HandlerResponse.success({
                "available": False,
                "tool": None,
                "message": f"Export module not available: {e}",
            })

    @route("severities")
    def export_severities(self, params: dict, body: dict | None) -> HandlerResponse:
        """List severity filter options."""
        severities = [
            {"value": "critical", "label": "Critical", "description": "Only critical severity findings"},
            {"value": "high", "label": "High", "description": "Critical and high severity findings"},
            {"value": "medium", "label": "Medium", "description": "Critical, high, and medium findings"},
            {"value": "low", "label": "Low", "description": "All except info findings"},
            {"value": "info", "label": "Info", "description": "All findings including informational"},
        ]
        return HandlerResponse.success({"severities": severities, "total": len(severities)})

    @route("preview")
    def export_preview(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get export preview information."""
        report_type = self.get_param(params, "report_type", "full_report")
        output_format = self.get_param(params, "format", "json")

        return HandlerResponse.success({
            "report_type": report_type,
            "format": output_format,
            "estimated_size": "~500KB",
            "sections_included": ["summary", "findings", "assets", "compliance"],
            "preview_available": output_format == "html",
        })

    @route("stats")
    def export_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get export statistics."""
        return HandlerResponse.success({
            "total_exports": 0,
            "formats_available": 4,
            "report_types": 5,
            "pdf_available": False,
            "last_export": None,
        })

    @route("status")
    def export_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get export module status."""
        return HandlerResponse.success({
            "module": "export",
            "capabilities": [
                "json_export",
                "csv_export",
                "html_export",
                "pdf_export",
                "report_generation",
            ],
            "formats": ["json", "csv", "html", "pdf"],
            "report_types": 5,
        })

    @route("summary")
    def export_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get export module summary."""
        return HandlerResponse.success({
            "module": "export",
            "description": "Report export and generation module",
            "features": [
                "Multiple output formats (JSON, CSV, HTML, PDF)",
                "Various report types",
                "Customizable options",
                "Severity filtering",
                "Chart support in HTML/PDF",
            ],
            "supported_formats": 4,
            "supported_report_types": 5,
        })
