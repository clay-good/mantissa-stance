"""
Base export functionality for Mantissa Stance.

Provides abstract interfaces and common utilities for exporting
data in various formats (PDF, CSV, JSON).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingCollection, Severity


class ExportFormat(Enum):
    """Supported export formats."""

    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"


class ReportType(Enum):
    """Types of reports that can be generated."""

    EXECUTIVE_SUMMARY = "executive_summary"
    FINDINGS_DETAIL = "findings_detail"
    COMPLIANCE_SUMMARY = "compliance_summary"
    ASSET_INVENTORY = "asset_inventory"
    FULL_REPORT = "full_report"


@dataclass
class ExportOptions:
    """
    Options for export operations.

    Attributes:
        format: Output format
        report_type: Type of report to generate
        include_charts: Whether to include visual charts (PDF/HTML only)
        include_raw_data: Whether to include raw configuration data
        severity_filter: Only include findings at or above this severity
        frameworks: Compliance frameworks to include (empty = all)
        date_range_days: Number of days of historical data to include
        output_path: Where to write the output
        title: Report title
        author: Report author name
    """

    format: ExportFormat = ExportFormat.JSON
    report_type: ReportType = ReportType.FULL_REPORT
    include_charts: bool = True
    include_raw_data: bool = False
    severity_filter: Severity | None = None
    frameworks: list[str] = field(default_factory=list)
    date_range_days: int = 30
    output_path: Path | str | None = None
    title: str = "Mantissa Stance Security Report"
    author: str = "Mantissa Stance"


@dataclass
class ExportResult:
    """
    Result of an export operation.

    Attributes:
        success: Whether export completed successfully
        format: Format used for export
        output_path: Path to output file (if written to disk)
        content: Export content (if not written to disk)
        bytes_written: Size of output in bytes
        generated_at: When the export was generated
        error: Error message if export failed
    """

    success: bool
    format: ExportFormat
    output_path: Path | None = None
    content: bytes | str | None = None
    bytes_written: int = 0
    generated_at: datetime = field(default_factory=datetime.utcnow)
    error: str | None = None


@dataclass
class ReportData:
    """
    Data container for report generation.

    Aggregates all data needed for generating reports.

    Attributes:
        assets: Asset collection
        findings: Finding collection
        compliance_scores: Compliance scores by framework
        scan_metadata: Metadata about the scan
        trends: Historical trend data
        generated_at: When data was collected
    """

    assets: AssetCollection | list[Asset]
    findings: FindingCollection | list[Finding]
    compliance_scores: dict[str, dict[str, Any]] = field(default_factory=dict)
    scan_metadata: dict[str, Any] = field(default_factory=dict)
    trends: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=datetime.utcnow)

    def get_assets_list(self) -> list[Asset]:
        """Get assets as a list."""
        if isinstance(self.assets, AssetCollection):
            return list(self.assets.assets)
        return self.assets

    def get_findings_list(self) -> list[Finding]:
        """Get findings as a list."""
        if isinstance(self.findings, FindingCollection):
            return list(self.findings.findings)
        return self.findings

    def get_finding_counts_by_severity(self) -> dict[str, int]:
        """Get count of findings by severity."""
        counts: dict[str, int] = {}
        for finding in self.get_findings_list():
            sev = finding.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def get_finding_counts_by_status(self) -> dict[str, int]:
        """Get count of findings by status."""
        counts: dict[str, int] = {}
        for finding in self.get_findings_list():
            status = finding.status.value
            counts[status] = counts.get(status, 0) + 1
        return counts

    def get_asset_counts_by_type(self) -> dict[str, int]:
        """Get count of assets by type."""
        counts: dict[str, int] = {}
        for asset in self.get_assets_list():
            counts[asset.resource_type] = counts.get(asset.resource_type, 0) + 1
        return counts

    def get_overall_compliance_score(self) -> float:
        """Calculate overall compliance score across all frameworks."""
        if not self.compliance_scores:
            return 0.0

        total_score = 0.0
        count = 0
        for framework_data in self.compliance_scores.values():
            if "score" in framework_data:
                total_score += framework_data["score"]
                count += 1

        return total_score / count if count > 0 else 0.0


class BaseExporter(ABC):
    """
    Abstract base class for exporters.

    Exporters transform report data into specific output formats.
    """

    @property
    @abstractmethod
    def format(self) -> ExportFormat:
        """Return the export format this exporter produces."""
        pass

    @abstractmethod
    def export(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> ExportResult:
        """
        Export data in the exporter's format.

        Args:
            data: Report data to export
            options: Export options

        Returns:
            ExportResult with success status and output
        """
        pass

    def _filter_findings(
        self,
        findings: list[Finding],
        severity_filter: Severity | None = None,
    ) -> list[Finding]:
        """Filter findings by severity threshold."""
        if severity_filter is None:
            return findings

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        threshold = severity_order.get(severity_filter, 4)

        return [
            f for f in findings
            if severity_order.get(f.severity, 4) <= threshold
        ]

    def _write_output(
        self,
        content: bytes | str,
        output_path: Path | str | None,
    ) -> tuple[Path | None, bytes | str | None]:
        """
        Write content to file or return for in-memory use.

        Args:
            content: Content to write
            output_path: Path to write to (None for in-memory)

        Returns:
            Tuple of (path if written, content if in-memory)
        """
        if output_path is None:
            return None, content

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)

        return path, None


class ExportManager:
    """
    Manages export operations across multiple formats.

    Provides a unified interface for exporting data to various formats.
    """

    def __init__(self):
        """Initialize export manager with registered exporters."""
        self._exporters: dict[ExportFormat, BaseExporter] = {}

    def register_exporter(self, exporter: BaseExporter) -> None:
        """Register an exporter for its format."""
        self._exporters[exporter.format] = exporter

    def get_exporter(self, format: ExportFormat) -> BaseExporter | None:
        """Get exporter for a specific format."""
        return self._exporters.get(format)

    def export(
        self,
        data: ReportData,
        options: ExportOptions,
    ) -> ExportResult:
        """
        Export data using the appropriate exporter.

        Args:
            data: Report data to export
            options: Export options (format determines exporter)

        Returns:
            ExportResult with success status and output
        """
        exporter = self._exporters.get(options.format)
        if exporter is None:
            return ExportResult(
                success=False,
                format=options.format,
                error=f"No exporter registered for format: {options.format.value}",
            )

        return exporter.export(data, options)

    def available_formats(self) -> list[ExportFormat]:
        """Return list of available export formats."""
        return list(self._exporters.keys())
