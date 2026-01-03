"""
Tests for Mantissa Stance export module.

Tests the export functionality including:
- CSV export
- JSON export
- HTML export
- Export manager
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from stance.export import (
    CSVExporter,
    ExportFormat,
    ExportManager,
    ExportOptions,
    ExportResult,
    HTMLExporter,
    JSONExporter,
    ReportData,
    ReportType,
    create_export_manager,
    export_report,
)
from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingStatus,
    FindingType,
    Severity,
)


class TestReportData:
    """Tests for the ReportData class."""

    def test_report_data_creation(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test ReportData can be created."""
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )

        assert data.assets == asset_collection
        assert data.findings == finding_collection

    def test_get_assets_list(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test get_assets_list returns list."""
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )

        assets = data.get_assets_list()
        assert isinstance(assets, list)
        assert len(assets) == 3

    def test_get_findings_list(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test get_findings_list returns list."""
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )

        findings = data.get_findings_list()
        assert isinstance(findings, list)
        assert len(findings) == 4

    def test_finding_counts_by_severity(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test counting findings by severity."""
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )

        counts = data.get_finding_counts_by_severity()
        assert counts.get("critical", 0) == 1
        assert counts.get("high", 0) == 1
        assert counts.get("medium", 0) == 1
        assert counts.get("low", 0) == 1

    def test_asset_counts_by_type(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test counting assets by type."""
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )

        counts = data.get_asset_counts_by_type()
        assert counts.get("aws_s3_bucket", 0) == 2
        assert counts.get("aws_ec2_instance", 0) == 1


class TestCSVExporter:
    """Tests for the CSVExporter class."""

    def test_exporter_format(self):
        """Test exporter reports correct format."""
        exporter = CSVExporter()
        assert exporter.format == ExportFormat.CSV

    def test_export_findings(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting findings to CSV."""
        exporter = CSVExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.CSV,
            report_type=ReportType.FINDINGS_DETAIL,
        )

        result = exporter.export(data, options)

        assert result.success
        assert result.format == ExportFormat.CSV
        assert result.content is not None
        assert "id,asset_id" in result.content
        assert "finding-001" in result.content

    def test_export_assets(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting assets to CSV."""
        exporter = CSVExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.CSV,
            report_type=ReportType.ASSET_INVENTORY,
        )

        result = exporter.export(data, options)

        assert result.success
        assert result.content is not None
        assert "id,cloud_provider" in result.content
        assert "test-bucket" in result.content

    def test_export_full_report(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting full report to CSV."""
        exporter = CSVExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.CSV,
            report_type=ReportType.FULL_REPORT,
        )

        result = exporter.export(data, options)

        assert result.success
        assert "SUMMARY" in result.content
        assert "FINDINGS" in result.content
        assert "ASSETS" in result.content


class TestJSONExporter:
    """Tests for the JSONExporter class."""

    def test_exporter_format(self):
        """Test exporter reports correct format."""
        exporter = JSONExporter()
        assert exporter.format == ExportFormat.JSON

    def test_export_findings(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting findings to JSON."""
        exporter = JSONExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.JSON,
            report_type=ReportType.FINDINGS_DETAIL,
        )

        result = exporter.export(data, options)

        assert result.success
        assert result.content is not None

        content = json.loads(result.content)
        assert content["metadata"]["type"] == "findings"
        assert len(content["findings"]) == 4

    def test_export_executive_summary(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting executive summary to JSON."""
        exporter = JSONExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.JSON,
            report_type=ReportType.EXECUTIVE_SUMMARY,
        )

        result = exporter.export(data, options)

        assert result.success
        content = json.loads(result.content)
        assert content["metadata"]["type"] == "executive_summary"
        assert "summary" in content
        assert "findings_by_severity" in content
        assert "top_risks" in content

    def test_export_full_report(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting full report to JSON."""
        exporter = JSONExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.JSON,
            report_type=ReportType.FULL_REPORT,
        )

        result = exporter.export(data, options)

        assert result.success
        content = json.loads(result.content)
        assert content["metadata"]["type"] == "full_report"
        assert "findings" in content
        assert "assets" in content
        assert "summary" in content


class TestHTMLExporter:
    """Tests for the HTMLExporter class."""

    def test_exporter_format(self):
        """Test exporter reports correct format."""
        exporter = HTMLExporter()
        assert exporter.format == ExportFormat.HTML

    def test_export_executive_summary(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting executive summary to HTML."""
        exporter = HTMLExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.HTML,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            title="Test Report",
        )

        result = exporter.export(data, options)

        assert result.success
        assert result.content is not None
        assert "<!DOCTYPE html>" in result.content
        assert "Test Report" in result.content
        assert "Executive Summary" in result.content

    def test_export_findings_detail(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting findings detail to HTML."""
        exporter = HTMLExporter()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.HTML,
            report_type=ReportType.FINDINGS_DETAIL,
        )

        result = exporter.export(data, options)

        assert result.success
        assert "Findings Report" in result.content
        assert "CRITICAL" in result.content or "critical" in result.content.lower()

    def test_html_escapes_special_chars(
        self,
        asset_collection: AssetCollection,
    ):
        """Test HTML escapes special characters."""
        # Create finding with special characters
        finding = Finding(
            id="test-finding",
            asset_id="test-asset",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test <script>alert('xss')</script>",
            description="Description with & and < and >",
        )
        findings = FindingCollection([finding])

        exporter = HTMLExporter()
        data = ReportData(assets=asset_collection, findings=findings)
        options = ExportOptions(
            format=ExportFormat.HTML,
            report_type=ReportType.FINDINGS_DETAIL,
        )

        result = exporter.export(data, options)

        assert result.success
        assert "<script>" not in result.content
        assert "&lt;script&gt;" in result.content


class TestExportManager:
    """Tests for the ExportManager class."""

    def test_register_exporter(self):
        """Test registering an exporter."""
        manager = ExportManager()
        exporter = CSVExporter()

        manager.register_exporter(exporter)

        assert manager.get_exporter(ExportFormat.CSV) is exporter

    def test_available_formats(self):
        """Test listing available formats."""
        manager = create_export_manager()

        formats = manager.available_formats()

        assert ExportFormat.CSV in formats
        assert ExportFormat.JSON in formats
        assert ExportFormat.HTML in formats

    def test_export_with_manager(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test exporting through the manager."""
        manager = create_export_manager()
        data = ReportData(
            assets=asset_collection,
            findings=finding_collection,
        )
        options = ExportOptions(
            format=ExportFormat.JSON,
            report_type=ReportType.FULL_REPORT,
        )

        result = manager.export(data, options)

        assert result.success
        assert result.format == ExportFormat.JSON


class TestExportReportFunction:
    """Tests for the export_report convenience function."""

    def test_export_json(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test export_report function with JSON format."""
        result = export_report(
            assets=list(asset_collection.assets),
            findings=list(finding_collection.findings),
            format="json",
            report_type="full_report",
        )

        assert result.success
        assert result.format == ExportFormat.JSON

    def test_export_csv(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test export_report function with CSV format."""
        result = export_report(
            assets=list(asset_collection.assets),
            findings=list(finding_collection.findings),
            format="csv",
            report_type="findings_detail",
        )

        assert result.success
        assert result.format == ExportFormat.CSV

    def test_export_with_severity_filter(
        self,
        asset_collection: AssetCollection,
        finding_collection: FindingCollection,
    ):
        """Test export_report with severity filter."""
        result = export_report(
            assets=list(asset_collection.assets),
            findings=list(finding_collection.findings),
            format="json",
            report_type="findings_detail",
            severity_filter="high",
        )

        assert result.success
        content = json.loads(result.content)
        # Only critical and high findings should be included
        assert len(content["findings"]) == 2
