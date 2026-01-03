"""
Export and reporting module for Mantissa Stance.

Provides export functionality for generating reports in various formats
including PDF, CSV, JSON, and HTML.
"""

from stance.export.base import (
    BaseExporter,
    ExportFormat,
    ExportManager,
    ExportOptions,
    ExportResult,
    ReportData,
    ReportType,
)
from stance.export.csv_exporter import (
    CSVExporter,
    export_assets_to_csv,
    export_findings_to_csv,
)
from stance.export.html_exporter import HTMLExporter, export_to_html
from stance.export.json_exporter import JSONExporter, export_to_json
from stance.export.pdf_exporter import PDFExporter, export_to_pdf

__all__ = [
    # Base classes and types
    "BaseExporter",
    "ExportFormat",
    "ExportManager",
    "ExportOptions",
    "ExportResult",
    "ReportData",
    "ReportType",
    # Exporters
    "CSVExporter",
    "HTMLExporter",
    "JSONExporter",
    "PDFExporter",
    # Convenience functions
    "export_assets_to_csv",
    "export_findings_to_csv",
    "export_to_html",
    "export_to_json",
    "export_to_pdf",
    # Factory function
    "create_export_manager",
    "export_report",
]


def create_export_manager() -> ExportManager:
    """
    Create an export manager with all registered exporters.

    Returns:
        ExportManager configured with all available exporters.
    """
    manager = ExportManager()
    manager.register_exporter(CSVExporter())
    manager.register_exporter(JSONExporter())
    manager.register_exporter(HTMLExporter())
    manager.register_exporter(PDFExporter())
    return manager


def export_report(
    assets: list,
    findings: list,
    output_path: str | None = None,
    format: str = "json",
    report_type: str = "full_report",
    title: str = "Mantissa Stance Security Report",
    compliance_scores: dict | None = None,
    **kwargs,
) -> ExportResult:
    """
    Export a security report in the specified format.

    This is the main convenience function for generating reports.

    Args:
        assets: List of Asset objects
        findings: List of Finding objects
        output_path: Optional path to write the report
        format: Output format ("json", "csv", "html", "pdf")
        report_type: Type of report ("full_report", "executive_summary",
                     "findings_detail", "compliance_summary", "asset_inventory")
        title: Report title
        compliance_scores: Optional compliance scores by framework
        **kwargs: Additional options passed to ExportOptions

    Returns:
        ExportResult with the generated report

    Example:
        from stance.export import export_report

        result = export_report(
            assets=collected_assets,
            findings=detected_findings,
            output_path="report.pdf",
            format="pdf",
            report_type="executive_summary",
            title="Q4 Security Assessment"
        )

        if result.success:
            print(f"Report saved to: {result.output_path}")
        else:
            print(f"Export failed: {result.error}")
    """
    from stance.models.asset import AssetCollection
    from stance.models.finding import FindingCollection, Severity

    # Build report data
    data = ReportData(
        assets=AssetCollection(assets=assets) if isinstance(assets, list) else assets,
        findings=FindingCollection(findings=findings) if isinstance(findings, list) else findings,
        compliance_scores=compliance_scores or {},
    )

    # Parse format
    format_map = {
        "json": ExportFormat.JSON,
        "csv": ExportFormat.CSV,
        "html": ExportFormat.HTML,
        "pdf": ExportFormat.PDF,
    }
    export_format = format_map.get(format.lower(), ExportFormat.JSON)

    # Parse report type
    type_map = {
        "full_report": ReportType.FULL_REPORT,
        "executive_summary": ReportType.EXECUTIVE_SUMMARY,
        "findings_detail": ReportType.FINDINGS_DETAIL,
        "compliance_summary": ReportType.COMPLIANCE_SUMMARY,
        "asset_inventory": ReportType.ASSET_INVENTORY,
    }
    export_report_type = type_map.get(report_type.lower(), ReportType.FULL_REPORT)

    # Parse severity filter if provided
    severity_filter = None
    if "severity_filter" in kwargs:
        sev_str = kwargs.pop("severity_filter")
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity_filter = severity_map.get(sev_str.lower())

    # Build options
    options = ExportOptions(
        format=export_format,
        report_type=export_report_type,
        output_path=output_path,
        title=title,
        severity_filter=severity_filter,
        **kwargs,
    )

    # Get manager and export
    manager = create_export_manager()
    return manager.export(data, options)
