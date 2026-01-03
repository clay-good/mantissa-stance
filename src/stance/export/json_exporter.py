"""
JSON export functionality for Mantissa Stance.

Exports assets, findings, and compliance data to JSON format.
"""

from __future__ import annotations

import json
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


class JSONExporter(BaseExporter):
    """
    Exports data to JSON format.

    Produces API-compatible JSON output with full data fidelity.
    """

    @property
    def format(self) -> ExportFormat:
        return ExportFormat.JSON

    def export(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> ExportResult:
        """
        Export data to JSON format.

        Args:
            data: Report data to export
            options: Export options

        Returns:
            ExportResult with JSON content
        """
        try:
            if options.report_type == ReportType.FINDINGS_DETAIL:
                output = self._export_findings(data, options)
            elif options.report_type == ReportType.ASSET_INVENTORY:
                output = self._export_assets(data, options)
            elif options.report_type == ReportType.COMPLIANCE_SUMMARY:
                output = self._export_compliance(data, options)
            elif options.report_type == ReportType.EXECUTIVE_SUMMARY:
                output = self._export_executive_summary(data, options)
            else:
                output = self._export_full_report(data, options)

            content = json.dumps(output, indent=2, default=self._json_serializer)

            output_path, output_content = self._write_output(
                content, options.output_path
            )

            return ExportResult(
                success=True,
                format=ExportFormat.JSON,
                output_path=output_path,
                content=output_content,
                bytes_written=len(content.encode("utf-8")),
            )

        except Exception as e:
            return ExportResult(
                success=False,
                format=ExportFormat.JSON,
                error=str(e),
            )

    def _export_findings(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> dict[str, Any]:
        """Export findings to JSON structure."""
        findings = self._filter_findings(
            data.get_findings_list(),
            options.severity_filter,
        )

        return {
            "metadata": {
                "type": "findings",
                "generated_at": data.generated_at.isoformat(),
                "total_count": len(findings),
            },
            "findings": [self._finding_to_dict(f, options) for f in findings],
        }

    def _export_assets(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> dict[str, Any]:
        """Export assets to JSON structure."""
        assets = data.get_assets_list()

        return {
            "metadata": {
                "type": "assets",
                "generated_at": data.generated_at.isoformat(),
                "total_count": len(assets),
            },
            "assets": [self._asset_to_dict(a, options) for a in assets],
        }

    def _export_compliance(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> dict[str, Any]:
        """Export compliance data to JSON structure."""
        frameworks = options.frameworks or list(data.compliance_scores.keys())
        compliance_data = {}

        for framework in frameworks:
            if framework in data.compliance_scores:
                compliance_data[framework] = data.compliance_scores[framework]

        return {
            "metadata": {
                "type": "compliance",
                "generated_at": data.generated_at.isoformat(),
                "frameworks_count": len(compliance_data),
            },
            "overall_score": data.get_overall_compliance_score(),
            "frameworks": compliance_data,
        }

    def _export_executive_summary(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> dict[str, Any]:
        """Export executive summary to JSON structure."""
        findings = data.get_findings_list()
        assets = data.get_assets_list()

        # Calculate key metrics
        severity_counts = data.get_finding_counts_by_severity()
        status_counts = data.get_finding_counts_by_status()
        asset_type_counts = data.get_asset_counts_by_type()

        # Find internet-facing assets
        internet_facing = [a for a in assets if a.is_internet_facing()]

        # Critical findings on internet-facing assets
        critical_exposed = [
            f for f in findings
            if f.severity.value == "critical"
            and any(a.id == f.asset_id and a.is_internet_facing() for a in assets)
        ]

        return {
            "metadata": {
                "type": "executive_summary",
                "generated_at": data.generated_at.isoformat(),
                "title": options.title,
            },
            "summary": {
                "total_assets": len(assets),
                "total_findings": len(findings),
                "internet_facing_assets": len(internet_facing),
                "critical_findings_on_exposed_assets": len(critical_exposed),
                "overall_compliance_score": data.get_overall_compliance_score(),
            },
            "findings_by_severity": severity_counts,
            "findings_by_status": status_counts,
            "assets_by_type": asset_type_counts,
            "compliance_scores": {
                framework: framework_data.get("score", 0)
                for framework, framework_data in data.compliance_scores.items()
            },
            "top_risks": self._get_top_risks(data),
        }

    def _export_full_report(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> dict[str, Any]:
        """Export full report combining all data."""
        findings = self._filter_findings(
            data.get_findings_list(),
            options.severity_filter,
        )
        assets = data.get_assets_list()

        return {
            "metadata": {
                "type": "full_report",
                "generated_at": data.generated_at.isoformat(),
                "title": options.title,
                "author": options.author,
            },
            "summary": {
                "total_assets": len(assets),
                "total_findings": len(findings),
                "findings_by_severity": data.get_finding_counts_by_severity(),
                "findings_by_status": data.get_finding_counts_by_status(),
                "assets_by_type": data.get_asset_counts_by_type(),
                "overall_compliance_score": data.get_overall_compliance_score(),
            },
            "findings": [self._finding_to_dict(f, options) for f in findings],
            "assets": [self._asset_to_dict(a, options) for a in assets],
            "compliance": data.compliance_scores,
            "trends": data.trends if data.trends else None,
            "scan_metadata": data.scan_metadata if data.scan_metadata else None,
        }

    def _finding_to_dict(
        self,
        finding: Finding,
        options: ExportOptions,
    ) -> dict[str, Any]:
        """Convert finding to dictionary."""
        result = {
            "id": finding.id,
            "asset_id": finding.asset_id,
            "finding_type": finding.finding_type.value,
            "severity": finding.severity.value,
            "status": finding.status.value,
            "title": finding.title,
            "description": finding.description,
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
        }

        # Optional fields
        if finding.rule_id:
            result["rule_id"] = finding.rule_id
        if finding.resource_path:
            result["resource_path"] = finding.resource_path
        if finding.expected_value:
            result["expected_value"] = finding.expected_value
        if finding.actual_value:
            result["actual_value"] = finding.actual_value
        if finding.cve_id:
            result["cve_id"] = finding.cve_id
        if finding.cvss_score is not None:
            result["cvss_score"] = finding.cvss_score
        if finding.package_name:
            result["package_name"] = finding.package_name
        if finding.installed_version:
            result["installed_version"] = finding.installed_version
        if finding.fixed_version:
            result["fixed_version"] = finding.fixed_version
        if finding.compliance_frameworks:
            result["compliance_frameworks"] = finding.compliance_frameworks
        if finding.remediation_guidance:
            result["remediation_guidance"] = finding.remediation_guidance

        return result

    def _asset_to_dict(
        self,
        asset: Asset,
        options: ExportOptions,
    ) -> dict[str, Any]:
        """Convert asset to dictionary."""
        result = {
            "id": asset.id,
            "cloud_provider": asset.cloud_provider,
            "account_id": asset.account_id,
            "region": asset.region,
            "resource_type": asset.resource_type,
            "name": asset.name,
            "network_exposure": asset.network_exposure,
            "tags": asset.tags,
            "created_at": asset.created_at.isoformat() if asset.created_at else None,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
        }

        if options.include_raw_data and asset.raw_config:
            result["raw_config"] = asset.raw_config

        return result

    def _get_top_risks(
        self,
        data: ReportData,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Get top risks for executive summary."""
        findings = data.get_findings_list()
        assets_by_id = {a.id: a for a in data.get_assets_list()}

        # Score findings by severity and exposure
        severity_scores = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "info": 10,
        }

        scored_findings = []
        for finding in findings:
            score = severity_scores.get(finding.severity.value, 0)

            # Boost score for internet-facing assets
            asset = assets_by_id.get(finding.asset_id)
            if asset and asset.is_internet_facing():
                score *= 1.5

            scored_findings.append((score, finding))

        # Sort by score descending
        scored_findings.sort(key=lambda x: x[0], reverse=True)

        return [
            {
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "asset_id": f.asset_id,
                "risk_score": score,
            }
            for score, f in scored_findings[:limit]
        ]

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for non-standard types."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, "value"):  # Enum
            return obj.value
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def export_to_json(
    data: ReportData,
    output_path: Path | str | None = None,
    report_type: ReportType = ReportType.FULL_REPORT,
    include_raw_data: bool = False,
) -> ExportResult:
    """
    Convenience function to export data to JSON.

    Args:
        data: Report data to export
        output_path: Optional path to write output
        report_type: Type of report to generate
        include_raw_data: Whether to include raw asset configurations

    Returns:
        ExportResult with JSON content
    """
    exporter = JSONExporter()
    options = ExportOptions(
        format=ExportFormat.JSON,
        report_type=report_type,
        output_path=output_path,
        include_raw_data=include_raw_data,
    )
    return exporter.export(data, options)
