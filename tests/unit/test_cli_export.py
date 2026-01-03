"""
Unit tests for Export CLI module.

Tests the command-line interface for report generation and data export.
"""

import pytest
import argparse
import json
from unittest.mock import MagicMock, patch

from stance.cli_export import (
    add_export_parser,
    cmd_export,
    _handle_formats,
    _handle_report_types,
    _handle_options,
    _handle_capabilities,
    _handle_pdf_tool,
    _handle_severities,
    _handle_preview,
    _handle_stats,
    _handle_status,
    _handle_summary,
)


class TestAddExportParser:
    """Tests for add_export_parser function."""

    def test_parser_creation(self):
        """Test that parser is created correctly."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_export_parser(subparsers)

        # Should not raise
        args = parser.parse_args(["export", "status"])
        assert args.export_action == "status"

    def test_all_subcommands_available(self):
        """Test that all subcommands are available."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_export_parser(subparsers)

        commands = [
            ("formats", []),
            ("report-types", []),
            ("options", []),
            ("capabilities", []),
            ("pdf-tool", []),
            ("severities", []),
            ("preview", []),
            ("stats", []),
            ("status", []),
            ("summary", []),
        ]

        for cmd, extra_args in commands:
            args = parser.parse_args(["export", cmd] + extra_args)
            assert args.export_action == cmd


class TestCmdExport:
    """Tests for cmd_export handler."""

    def test_no_action_shows_error(self, capsys):
        """Test that no action shows error."""
        args = argparse.Namespace(export_action=None)
        result = cmd_export(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "No export action specified" in captured.out

    def test_unknown_action_shows_error(self, capsys):
        """Test that unknown action shows error."""
        args = argparse.Namespace(export_action="unknown")
        result = cmd_export(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "Unknown action" in captured.out

    def test_valid_action_routes_correctly(self):
        """Test that valid actions route to correct handlers."""
        args = argparse.Namespace(
            export_action="status",
            format="json",
        )
        result = cmd_export(args)
        assert result == 0


class TestHandleFormats:
    """Tests for formats command handler."""

    def test_formats_table(self, capsys):
        """Test listing formats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_formats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Available Export Formats" in captured.out
        assert "JSON" in captured.out
        assert "CSV" in captured.out
        assert "HTML" in captured.out
        assert "PDF" in captured.out

    def test_formats_json(self, capsys):
        """Test listing formats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_formats(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data
        assert "formats" in data
        assert data["total"] == 4
        assert len(data["formats"]) == 4


class TestHandleReportTypes:
    """Tests for report-types command handler."""

    def test_report_types_table(self, capsys):
        """Test listing report types in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_report_types(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Available Report Types" in captured.out
        assert "Full Report" in captured.out
        assert "Executive Summary" in captured.out

    def test_report_types_json(self, capsys):
        """Test listing report types in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_report_types(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 5
        assert len(data["report_types"]) == 5


class TestHandleOptions:
    """Tests for options command handler."""

    def test_options_table(self, capsys):
        """Test listing options in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_options(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Export Options" in captured.out
        assert "format" in captured.out
        assert "report_type" in captured.out

    def test_options_json(self, capsys):
        """Test listing options in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_options(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "total" in data
        assert "options" in data
        assert data["total"] == 10


class TestHandleCapabilities:
    """Tests for capabilities command handler."""

    def test_capabilities_table(self, capsys):
        """Test listing capabilities in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_capabilities(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Export Format Capabilities" in captured.out
        assert "JSON" in captured.out
        assert "CSV" in captured.out

    def test_capabilities_json(self, capsys):
        """Test listing capabilities in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_capabilities(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "capabilities" in data
        assert "json" in data["capabilities"]
        assert "csv" in data["capabilities"]
        assert "html" in data["capabilities"]
        assert "pdf" in data["capabilities"]


class TestHandlePdfTool:
    """Tests for pdf-tool command handler."""

    def test_pdf_tool_json(self, capsys):
        """Test checking PDF tool in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_pdf_tool(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "pdf_available" in data
        assert "tools_checked" in data
        assert "wkhtmltopdf" in data["tools_checked"]
        assert "weasyprint" in data["tools_checked"]

    def test_pdf_tool_table(self, capsys):
        """Test checking PDF tool in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_pdf_tool(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "PDF Generation Tool Status" in captured.out


class TestHandleSeverities:
    """Tests for severities command handler."""

    def test_severities_table(self, capsys):
        """Test listing severities in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_severities(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Severity Levels" in captured.out
        assert "CRITICAL" in captured.out
        assert "HIGH" in captured.out
        assert "MEDIUM" in captured.out
        assert "LOW" in captured.out
        assert "INFO" in captured.out

    def test_severities_json(self, capsys):
        """Test listing severities in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_severities(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["total"] == 5
        assert len(data["severities"]) == 5


class TestHandlePreview:
    """Tests for preview command handler."""

    def test_preview_json(self, capsys):
        """Test preview with JSON format."""
        args = argparse.Namespace(
            export_format="json",
            report_type="executive_summary",
            format="table",
        )
        result = _handle_preview(args)
        assert result == 0

        captured = capsys.readouterr()
        # Preview outputs the actual content
        assert "metadata" in captured.out or "summary" in captured.out

    def test_preview_csv(self, capsys):
        """Test preview with CSV format."""
        args = argparse.Namespace(
            export_format="csv",
            report_type="findings_detail",
            format="table",
        )
        result = _handle_preview(args)
        assert result == 0

    def test_preview_html(self, capsys):
        """Test preview with HTML format."""
        args = argparse.Namespace(
            export_format="html",
            report_type="full_report",
            format="table",
        )
        result = _handle_preview(args)
        assert result == 0


class TestHandleStats:
    """Tests for stats command handler."""

    def test_stats_table(self, capsys):
        """Test showing stats in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Export Module Statistics" in captured.out
        assert "Formats Supported" in captured.out

    def test_stats_json(self, capsys):
        """Test showing stats in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_stats(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["formats_supported"] == 4
        assert data["report_types"] == 5
        assert data["severity_levels"] == 5


class TestHandleStatus:
    """Tests for status command handler."""

    def test_status_table(self, capsys):
        """Test showing status in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Export Module Status" in captured.out
        assert "Components:" in captured.out

    def test_status_json(self, capsys):
        """Test showing status in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_status(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "export"
        assert "status" in data
        assert "components" in data
        assert "capabilities" in data


class TestHandleSummary:
    """Tests for summary command handler."""

    def test_summary_table(self, capsys):
        """Test showing summary in table format."""
        args = argparse.Namespace(format="table")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "Export Module Summary" in captured.out
        assert "Features:" in captured.out

    def test_summary_json(self, capsys):
        """Test showing summary in JSON format."""
        args = argparse.Namespace(format="json")
        result = _handle_summary(args)
        assert result == 0

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["module"] == "export"
        assert "formats" in data
        assert "report_types" in data
        assert "features" in data


class TestCLIRouting:
    """Tests for CLI command routing."""

    def test_all_handlers_exist(self):
        """Test that all handlers exist."""
        handlers = [
            _handle_formats,
            _handle_report_types,
            _handle_options,
            _handle_capabilities,
            _handle_pdf_tool,
            _handle_severities,
            _handle_preview,
            _handle_stats,
            _handle_status,
            _handle_summary,
        ]

        for handler in handlers:
            assert callable(handler)

    def test_cmd_export_routes_to_all_handlers(self, capsys):
        """Test that cmd_export routes to all handlers."""
        actions = [
            ("status", {}),
            ("summary", {}),
            ("stats", {}),
            ("formats", {}),
            ("report-types", {}),
            ("options", {}),
            ("capabilities", {}),
            ("severities", {}),
        ]

        for action, extra_args in actions:
            args = argparse.Namespace(
                export_action=action,
                format="json",
                **extra_args,
            )
            result = cmd_export(args)
            assert result == 0, f"Handler for {action} failed"


class TestExportModuleIntegration:
    """Integration tests with actual export module."""

    def test_formats_structure(self, capsys):
        """Test formats have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_formats(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for fmt in data["formats"]:
            assert "format" in fmt
            assert "name" in fmt
            assert "description" in fmt
            assert "extension" in fmt
            assert "mime_type" in fmt

    def test_report_types_structure(self, capsys):
        """Test report types have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_report_types(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for rt in data["report_types"]:
            assert "type" in rt
            assert "name" in rt
            assert "description" in rt
            assert "sections" in rt

    def test_options_structure(self, capsys):
        """Test options have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_options(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for opt in data["options"]:
            assert "option" in opt
            assert "type" in opt
            assert "description" in opt

    def test_status_components_structure(self, capsys):
        """Test status components have correct structure."""
        args = argparse.Namespace(format="json")
        _handle_status(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert "ExportManager" in data["components"]
        assert "CSVExporter" in data["components"]
        assert "JSONExporter" in data["components"]
        assert "HTMLExporter" in data["components"]
        assert "PDFExporter" in data["components"]


class TestPreviewFormats:
    """Tests for preview with different formats."""

    def test_preview_json_content(self, capsys):
        """Test preview JSON content structure."""
        args = argparse.Namespace(
            export_format="json",
            report_type="executive_summary",
            format="table",
        )
        result = _handle_preview(args)
        assert result == 0

    def test_preview_asset_inventory(self, capsys):
        """Test preview with asset inventory."""
        args = argparse.Namespace(
            export_format="json",
            report_type="asset_inventory",
            format="table",
        )
        result = _handle_preview(args)
        assert result == 0

    def test_preview_compliance_summary(self, capsys):
        """Test preview with compliance summary."""
        args = argparse.Namespace(
            export_format="json",
            report_type="compliance_summary",
            format="table",
        )
        result = _handle_preview(args)
        assert result == 0


class TestCapabilitiesContent:
    """Tests for capabilities content."""

    def test_all_formats_have_features(self, capsys):
        """Test that all formats have features."""
        args = argparse.Namespace(format="json")
        _handle_capabilities(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for fmt, caps in data["capabilities"].items():
            assert "charts" in caps
            assert "styling" in caps
            assert "raw_data" in caps
            assert "streaming" in caps
            assert "features" in caps
            assert len(caps["features"]) > 0

    def test_json_does_not_support_charts(self, capsys):
        """Test that JSON does not support charts."""
        args = argparse.Namespace(format="json")
        _handle_capabilities(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["capabilities"]["json"]["charts"] is False
        assert data["capabilities"]["csv"]["charts"] is False

    def test_html_supports_charts(self, capsys):
        """Test that HTML supports charts."""
        args = argparse.Namespace(format="json")
        _handle_capabilities(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["capabilities"]["html"]["charts"] is True
        assert data["capabilities"]["pdf"]["charts"] is True


class TestSeveritiesContent:
    """Tests for severities content."""

    def test_severity_priorities_ordered(self, capsys):
        """Test that severity priorities are ordered correctly."""
        args = argparse.Namespace(format="json")
        _handle_severities(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        priorities = [s["priority"] for s in data["severities"]]
        assert priorities == [1, 2, 3, 4, 5]

    def test_all_severities_have_examples(self, capsys):
        """Test that all severities have examples."""
        args = argparse.Namespace(format="json")
        _handle_severities(args)

        captured = capsys.readouterr()
        data = json.loads(captured.out)

        for sev in data["severities"]:
            assert "examples" in sev
            assert len(sev["examples"]) > 0
