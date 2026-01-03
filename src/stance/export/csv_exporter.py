"""
CSV export functionality for Mantissa Stance.

Exports assets, findings, and compliance data to CSV format.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Any

from stance.export.base import (
    BaseExporter,
    ExportFormat,
    ExportOptions,
    ExportResult,
    ReportData,
    ReportType,
)
from stance.models.asset import Asset
from stance.models.finding import Finding


class CSVExporter(BaseExporter):
    """
    Exports data to CSV format.

    Supports exporting assets, findings, and compliance status
    as separate CSV files or combined report.
    """

    @property
    def format(self) -> ExportFormat:
        return ExportFormat.CSV

    def export(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> ExportResult:
        """
        Export data to CSV format.

        For FULL_REPORT, creates a combined CSV with sections.
        For specific report types, creates focused CSV output.

        Args:
            data: Report data to export
            options: Export options

        Returns:
            ExportResult with CSV content
        """
        try:
            if options.report_type == ReportType.FINDINGS_DETAIL:
                content = self._export_findings(data, options)
            elif options.report_type == ReportType.ASSET_INVENTORY:
                content = self._export_assets(data, options)
            elif options.report_type == ReportType.COMPLIANCE_SUMMARY:
                content = self._export_compliance(data, options)
            else:
                content = self._export_full_report(data, options)

            output_path, output_content = self._write_output(
                content, options.output_path
            )

            return ExportResult(
                success=True,
                format=ExportFormat.CSV,
                output_path=output_path,
                content=output_content,
                bytes_written=len(content.encode("utf-8")),
            )

        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.CSV,
                error=str(e),
            )

    def _export_findings(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Export findings to CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        headers = [
            "id",
            "asset_id",
            "finding_type",
            "severity",
            "status",
            "title",
            "description",
            "rule_id",
            "cve_id",
            "cvss_score",
            "compliance_frameworks",
            "remediation_guidance",
            "first_seen",
            "last_seen",
        ]
        writer.writerow(headers)

        # Filter and write findings
        findings = self._filter_findings(
            data.get_findings_list(),
            options.severity_filter,
        )

        for finding in findings:
            row = self._finding_to_row(finding)
            writer.writerow(row)

        return output.getvalue()

    def _export_assets(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Export assets to CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        headers = [
            "id",
            "cloud_provider",
            "account_id",
            "region",
            "resource_type",
            "name",
            "network_exposure",
            "tags",
            "created_at",
            "last_seen",
        ]
        writer.writerow(headers)

        # Write assets
        for asset in data.get_assets_list():
            row = self._asset_to_row(asset)
            writer.writerow(row)

        return output.getvalue()

    def _export_compliance(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Export compliance status to CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        headers = [
            "framework",
            "control_id",
            "control_name",
            "status",
            "resources_evaluated",
            "resources_compliant",
            "resources_non_compliant",
        ]
        writer.writerow(headers)

        # Write compliance data
        frameworks = options.frameworks or list(data.compliance_scores.keys())

        for framework in frameworks:
            framework_data = data.compliance_scores.get(framework, {})
            controls = framework_data.get("controls", [])

            for control in controls:
                row = [
                    framework,
                    control.get("control_id", ""),
                    control.get("control_name", ""),
                    control.get("status", ""),
                    control.get("resources_evaluated", 0),
                    control.get("resources_compliant", 0),
                    control.get("resources_non_compliant", 0),
                ]
                writer.writerow(row)

        return output.getvalue()

    def _export_full_report(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> str:
        """Export full report combining all sections."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Report metadata section
        writer.writerow(["MANTISSA STANCE SECURITY REPORT"])
        writer.writerow(["Generated", data.generated_at.isoformat()])
        writer.writerow([])

        # Summary section
        writer.writerow(["SUMMARY"])
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total Assets", len(data.get_assets_list())])
        writer.writerow(["Total Findings", len(data.get_findings_list())])

        counts = data.get_finding_counts_by_severity()
        for severity, count in counts.items():
            writer.writerow([f"  {severity.capitalize()} Findings", count])

        writer.writerow(["Overall Compliance Score", f"{data.get_overall_compliance_score():.1f}%"])
        writer.writerow([])

        # Findings section
        writer.writerow(["FINDINGS"])
        findings_headers = [
            "id",
            "asset_id",
            "severity",
            "status",
            "title",
            "rule_id",
            "cve_id",
        ]
        writer.writerow(findings_headers)

        findings = self._filter_findings(
            data.get_findings_list(),
            options.severity_filter,
        )
        for finding in findings:
            row = [
                finding.id,
                finding.asset_id,
                finding.severity.value,
                finding.status.value,
                finding.title,
                finding.rule_id or "",
                finding.cve_id or "",
            ]
            writer.writerow(row)

        writer.writerow([])

        # Assets section
        writer.writerow(["ASSETS"])
        assets_headers = [
            "id",
            "cloud_provider",
            "region",
            "resource_type",
            "name",
            "network_exposure",
        ]
        writer.writerow(assets_headers)

        for asset in data.get_assets_list():
            row = [
                asset.id,
                asset.cloud_provider,
                asset.region,
                asset.resource_type,
                asset.name,
                asset.network_exposure,
            ]
            writer.writerow(row)

        writer.writerow([])

        # Compliance section
        if data.compliance_scores:
            writer.writerow(["COMPLIANCE"])
            writer.writerow(["Framework", "Score"])
            for framework, framework_data in data.compliance_scores.items():
                score = framework_data.get("score", 0)
                writer.writerow([framework, f"{score:.1f}%"])

        return output.getvalue()

    def _finding_to_row(self, finding: Finding) -> list[Any]:
        """Convert finding to CSV row."""
        frameworks = ",".join(finding.compliance_frameworks) if finding.compliance_frameworks else ""
        return [
            finding.id,
            finding.asset_id,
            finding.finding_type.value,
            finding.severity.value,
            finding.status.value,
            finding.title,
            finding.description,
            finding.rule_id or "",
            finding.cve_id or "",
            finding.cvss_score if finding.cvss_score is not None else "",
            frameworks,
            finding.remediation_guidance,
            finding.first_seen.isoformat() if finding.first_seen else "",
            finding.last_seen.isoformat() if finding.last_seen else "",
        ]

    def _asset_to_row(self, asset: Asset) -> list[Any]:
        """Convert asset to CSV row."""
        tags_str = ",".join(f"{k}={v}" for k, v in asset.tags.items()) if asset.tags else ""
        return [
            asset.id,
            asset.cloud_provider,
            asset.account_id,
            asset.region,
            asset.resource_type,
            asset.name,
            asset.network_exposure,
            tags_str,
            asset.created_at.isoformat() if asset.created_at else "",
            asset.last_seen.isoformat() if asset.last_seen else "",
        ]


def export_findings_to_csv(
    findings: list[Finding],
    output_path: Path | str | None = None,
) -> ExportResult:
    """
    Convenience function to export findings to CSV.

    Args:
        findings: List of findings to export
        output_path: Optional path to write output

    Returns:
        ExportResult with CSV content
    """
    from stance.models.asset import AssetCollection
    from stance.models.finding import FindingCollection

    exporter = CSVExporter()
    data = ReportData(
        assets=AssetCollection(assets=[]),
        findings=FindingCollection(findings=findings),
    )
    options = ExportOptions(
        format=ExportFormat.CSV,
        report_type=ReportType.FINDINGS_DETAIL,
        output_path=output_path,
    )
    return exporter.export(data, options)


def export_assets_to_csv(
    assets: list[Asset],
    output_path: Path | str | None = None,
) -> ExportResult:
    """
    Convenience function to export assets to CSV.

    Args:
        assets: List of assets to export
        output_path: Optional path to write output

    Returns:
        ExportResult with CSV content
    """
    from stance.models.asset import AssetCollection
    from stance.models.finding import FindingCollection

    exporter = CSVExporter()
    data = ReportData(
        assets=AssetCollection(assets=assets),
        findings=FindingCollection(findings=[]),
    )
    options = ExportOptions(
        format=ExportFormat.CSV,
        report_type=ReportType.ASSET_INVENTORY,
        output_path=output_path,
    )
    return exporter.export(data, options)
