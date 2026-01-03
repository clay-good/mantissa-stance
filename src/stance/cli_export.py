"""
CLI commands for Export module.

Provides command-line interface for report generation and data export:
- Multi-format export (JSON, CSV, HTML, PDF)
- Multiple report types (full, executive, findings, compliance, assets)
- Export configuration and options
- Export module status and capabilities
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_export_parser(subparsers: Any) -> None:
    """Add export parser to CLI subparsers."""
    export_parser = subparsers.add_parser(
        "export",
        help="Report generation and data export (JSON, CSV, HTML, PDF)",
        description="Generate security reports and export data in various formats",
    )

    export_subparsers = export_parser.add_subparsers(
        dest="export_action",
        help="Export action to perform",
    )

    # formats - List available export formats
    formats_parser = export_subparsers.add_parser(
        "formats",
        help="List available export formats",
    )
    formats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # report-types - List available report types
    report_types_parser = export_subparsers.add_parser(
        "report-types",
        help="List available report types",
    )
    report_types_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # generate - Generate a report
    generate_parser = export_subparsers.add_parser(
        "generate",
        help="Generate a security report",
    )
    generate_parser.add_argument(
        "--export-format",
        choices=["json", "csv", "html", "pdf"],
        default="json",
        help="Output format (default: json)",
    )
    generate_parser.add_argument(
        "--report-type",
        choices=["full_report", "executive_summary", "findings_detail",
                 "compliance_summary", "asset_inventory"],
        default="full_report",
        help="Type of report to generate (default: full_report)",
    )
    generate_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (prints to stdout if not specified)",
    )
    generate_parser.add_argument(
        "--title",
        default="Mantissa Stance Security Report",
        help="Report title",
    )
    generate_parser.add_argument(
        "--author",
        default="Mantissa Stance",
        help="Report author",
    )
    generate_parser.add_argument(
        "--severity-filter",
        choices=["critical", "high", "medium", "low", "info"],
        help="Only include findings at or above this severity",
    )
    generate_parser.add_argument(
        "--include-raw-data",
        action="store_true",
        help="Include raw asset configuration data",
    )
    generate_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format for status messages (default: table)",
    )

    # preview - Preview report generation (sample data)
    preview_parser = export_subparsers.add_parser(
        "preview",
        help="Preview report generation with sample data",
    )
    preview_parser.add_argument(
        "--export-format",
        choices=["json", "csv", "html", "pdf"],
        default="json",
        help="Output format to preview (default: json)",
    )
    preview_parser.add_argument(
        "--report-type",
        choices=["full_report", "executive_summary", "findings_detail",
                 "compliance_summary", "asset_inventory"],
        default="executive_summary",
        help="Type of report to preview (default: executive_summary)",
    )
    preview_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format for status (default: table)",
    )

    # options - Show export options
    options_parser = export_subparsers.add_parser(
        "options",
        help="Show available export options",
    )
    options_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # capabilities - Show format capabilities
    capabilities_parser = export_subparsers.add_parser(
        "capabilities",
        help="Show export format capabilities",
    )
    capabilities_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # pdf-tool - Check PDF tool availability
    pdf_tool_parser = export_subparsers.add_parser(
        "pdf-tool",
        help="Check PDF generation tool availability",
    )
    pdf_tool_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # severities - List severity levels for filtering
    severities_parser = export_subparsers.add_parser(
        "severities",
        help="List severity levels for filtering",
    )
    severities_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show export statistics
    stats_parser = export_subparsers.add_parser(
        "stats",
        help="Show export module statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show export module status
    status_parser = export_subparsers.add_parser(
        "status",
        help="Show export module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive export module summary
    summary_parser = export_subparsers.add_parser(
        "summary",
        help="Get comprehensive export module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_export(args: argparse.Namespace) -> int:
    """Handle export commands."""
    action = getattr(args, "export_action", None)

    if not action:
        print("No export action specified. Use 'stance export --help' for options.")
        return 1

    handlers = {
        "formats": _handle_formats,
        "report-types": _handle_report_types,
        "generate": _handle_generate,
        "preview": _handle_preview,
        "options": _handle_options,
        "capabilities": _handle_capabilities,
        "pdf-tool": _handle_pdf_tool,
        "severities": _handle_severities,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown action: {action}")
    return 1


def _handle_formats(args: argparse.Namespace) -> int:
    """Handle formats command."""
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

    if args.format == "json":
        print(json.dumps({"total": len(formats), "formats": formats}, indent=2))
    else:
        print("\nAvailable Export Formats")
        print("=" * 60)
        for fmt in formats:
            print(f"\n{fmt['name']} ({fmt['format']})")
            print(f"  Extension: {fmt['extension']}")
            print(f"  MIME Type: {fmt['mime_type']}")
            print(f"  {fmt['description']}")

    return 0


def _handle_report_types(args: argparse.Namespace) -> int:
    """Handle report-types command."""
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

    if args.format == "json":
        print(json.dumps({"total": len(report_types), "report_types": report_types}, indent=2))
    else:
        print("\nAvailable Report Types")
        print("=" * 60)
        for rt in report_types:
            print(f"\n{rt['name']} ({rt['type']})")
            print(f"  {rt['description']}")
            print(f"  Sections: {', '.join(rt['sections'])}")

    return 0


def _handle_generate(args: argparse.Namespace) -> int:
    """Handle generate command."""
    from stance.export import (
        ExportFormat,
        ExportOptions,
        ReportData,
        ReportType,
        create_export_manager,
    )
    from stance.models.asset import Asset, AssetCollection
    from stance.models.finding import Finding, FindingCollection, Severity, FindingType, FindingStatus

    # Try to get data from storage
    try:
        from stance.storage import create_storage
        storage = create_storage()
        snapshot_id = storage.get_latest_snapshot_id()
        if snapshot_id:
            assets = storage.get_assets(snapshot_id)
            findings = storage.get_findings(snapshot_id)
        else:
            if args.format == "json":
                print(json.dumps({"error": "No snapshots available. Run a scan first or use 'export preview' for sample data."}))
            else:
                print("Error: No snapshots available. Run a scan first or use 'export preview' for sample data.")
            return 1
    except Exception as e:
        if args.format == "json":
            print(json.dumps({"error": f"Could not access storage: {str(e)}"}))
        else:
            print(f"Error: Could not access storage: {str(e)}")
        return 1

    # Parse format
    format_map = {
        "json": ExportFormat.JSON,
        "csv": ExportFormat.CSV,
        "html": ExportFormat.HTML,
        "pdf": ExportFormat.PDF,
    }
    export_format = format_map.get(args.export_format, ExportFormat.JSON)

    # Parse report type
    type_map = {
        "full_report": ReportType.FULL_REPORT,
        "executive_summary": ReportType.EXECUTIVE_SUMMARY,
        "findings_detail": ReportType.FINDINGS_DETAIL,
        "compliance_summary": ReportType.COMPLIANCE_SUMMARY,
        "asset_inventory": ReportType.ASSET_INVENTORY,
    }
    report_type = type_map.get(args.report_type, ReportType.FULL_REPORT)

    # Parse severity filter
    severity_filter = None
    if args.severity_filter:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        severity_filter = severity_map.get(args.severity_filter)

    # Build report data
    data = ReportData(
        assets=assets,
        findings=findings,
    )

    # Build options
    options = ExportOptions(
        format=export_format,
        report_type=report_type,
        output_path=args.output,
        title=args.title,
        author=args.author,
        severity_filter=severity_filter,
        include_raw_data=args.include_raw_data,
    )

    # Generate export
    manager = create_export_manager()
    result = manager.export(data, options)

    if not result.success:
        if args.format == "json":
            print(json.dumps({"success": False, "error": result.error}))
        else:
            print(f"Export failed: {result.error}")
        return 1

    # Output result
    if result.output_path:
        if args.format == "json":
            print(json.dumps({
                "success": True,
                "format": export_format.value,
                "report_type": report_type.value,
                "output_path": str(result.output_path),
                "bytes_written": result.bytes_written,
            }))
        else:
            print(f"Report saved to: {result.output_path}")
            print(f"Format: {export_format.value.upper()}")
            print(f"Size: {result.bytes_written} bytes")
    else:
        # Print content to stdout
        if result.content:
            if isinstance(result.content, bytes):
                sys.stdout.buffer.write(result.content)
            else:
                print(result.content)

    return 0


def _handle_preview(args: argparse.Namespace) -> int:
    """Handle preview command with sample data."""
    from stance.export import (
        ExportFormat,
        ExportOptions,
        ReportData,
        ReportType,
        create_export_manager,
    )
    from stance.models.asset import Asset, AssetCollection
    from stance.models.finding import Finding, FindingCollection, Severity, FindingType, FindingStatus
    from datetime import datetime

    # Create sample assets
    sample_assets = [
        Asset(
            id="asset-001",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="production-logs",
            network_exposure="public",
            tags={"Environment": "Production", "Team": "Security"},
        ),
        Asset(
            id="asset-002",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-west-2",
            resource_type="aws_ec2_instance",
            name="web-server-1",
            network_exposure="internet_facing",
            tags={"Environment": "Production"},
        ),
        Asset(
            id="asset-003",
            cloud_provider="gcp",
            account_id="my-gcp-project",
            region="us-central1",
            resource_type="gcp_compute_instance",
            name="api-server",
            network_exposure="private",
            tags={"Team": "Backend"},
        ),
    ]

    # Create sample findings
    sample_findings = [
        Finding(
            id="finding-001",
            asset_id="asset-001",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="S3 Bucket Publicly Accessible",
            description="S3 bucket allows public read access without authentication",
            rule_id="AWS-S3-001",
            remediation_guidance="Configure bucket policy to restrict public access",
            compliance_frameworks=["CIS AWS", "PCI-DSS"],
        ),
        Finding(
            id="finding-002",
            asset_id="asset-002",
            finding_type=FindingType.VULNERABILITY,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Outdated SSL Certificate",
            description="SSL certificate expires within 30 days",
            rule_id="SSL-001",
            remediation_guidance="Renew SSL certificate before expiration",
        ),
        Finding(
            id="finding-003",
            asset_id="asset-003",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            title="Missing Firewall Rules",
            description="Instance lacks restrictive firewall rules",
            rule_id="GCP-FW-001",
            remediation_guidance="Add firewall rules to restrict ingress traffic",
        ),
    ]

    # Parse format
    format_map = {
        "json": ExportFormat.JSON,
        "csv": ExportFormat.CSV,
        "html": ExportFormat.HTML,
        "pdf": ExportFormat.PDF,
    }
    export_format = format_map.get(args.export_format, ExportFormat.JSON)

    # Parse report type
    type_map = {
        "full_report": ReportType.FULL_REPORT,
        "executive_summary": ReportType.EXECUTIVE_SUMMARY,
        "findings_detail": ReportType.FINDINGS_DETAIL,
        "compliance_summary": ReportType.COMPLIANCE_SUMMARY,
        "asset_inventory": ReportType.ASSET_INVENTORY,
    }
    report_type = type_map.get(args.report_type, ReportType.EXECUTIVE_SUMMARY)

    # Build report data
    data = ReportData(
        assets=AssetCollection(assets=sample_assets),
        findings=FindingCollection(findings=sample_findings),
        compliance_scores={
            "CIS AWS 1.5": {"score": 78.5, "controls": [
                {"control_id": "1.1", "control_name": "IAM Password Policy", "status": "pass", "resources_evaluated": 1, "resources_compliant": 1, "resources_non_compliant": 0},
                {"control_id": "1.2", "control_name": "MFA Enabled", "status": "fail", "resources_evaluated": 5, "resources_compliant": 3, "resources_non_compliant": 2},
            ]},
            "PCI-DSS 3.2": {"score": 65.0, "controls": []},
        },
    )

    # Build options
    options = ExportOptions(
        format=export_format,
        report_type=report_type,
        title="Sample Security Report (Preview)",
        author="Mantissa Stance",
    )

    # Generate export
    manager = create_export_manager()
    result = manager.export(data, options)

    if not result.success:
        if args.format == "json":
            print(json.dumps({"success": False, "error": result.error}))
        else:
            print(f"Preview failed: {result.error}")
        return 1

    # Print content
    if result.content:
        if isinstance(result.content, bytes):
            # For PDF, show info instead of binary
            if args.format == "json":
                print(json.dumps({
                    "success": True,
                    "format": export_format.value,
                    "report_type": report_type.value,
                    "bytes_generated": result.bytes_written,
                    "note": "Binary PDF content generated (not displayed)",
                }))
            else:
                print(f"Preview generated: {export_format.value.upper()} format")
                print(f"Report type: {report_type.value}")
                print(f"Size: {result.bytes_written} bytes")
                print("(Binary content not displayed)")
        else:
            print(result.content)

    return 0


def _handle_options(args: argparse.Namespace) -> int:
    """Handle options command."""
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
            "default": "None (stdout)",
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
            "default": "None (all)",
            "description": "Only include findings at or above this severity",
        },
        {
            "option": "include_charts",
            "type": "boolean",
            "default": "true",
            "description": "Include visual charts (HTML/PDF only)",
        },
        {
            "option": "include_raw_data",
            "type": "boolean",
            "default": "false",
            "description": "Include raw asset configuration data",
        },
        {
            "option": "frameworks",
            "type": "list",
            "default": "[] (all)",
            "description": "Compliance frameworks to include",
        },
        {
            "option": "date_range_days",
            "type": "integer",
            "default": "30",
            "description": "Days of historical data to include",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(options), "options": options}, indent=2))
    else:
        print("\nExport Options")
        print("=" * 70)
        for opt in options:
            print(f"\n{opt['option']} ({opt['type']})")
            print(f"  Default: {opt['default']}")
            if "values" in opt:
                print(f"  Values: {', '.join(opt['values'])}")
            print(f"  {opt['description']}")

    return 0


def _handle_capabilities(args: argparse.Namespace) -> int:
    """Handle capabilities command."""
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

    if args.format == "json":
        print(json.dumps({"capabilities": capabilities}, indent=2))
    else:
        print("\nExport Format Capabilities")
        print("=" * 70)
        print(f"{'Format':<8} {'Charts':<8} {'Styling':<10} {'Raw Data':<10} {'Stream':<8}")
        print("-" * 70)
        for fmt, caps in capabilities.items():
            charts = "Yes" if caps["charts"] else "No"
            styling = "Yes" if caps["styling"] else "No"
            raw_data = "Yes" if caps["raw_data"] else "No"
            streaming = "Yes" if caps["streaming"] else "No"
            print(f"{fmt.upper():<8} {charts:<8} {styling:<10} {raw_data:<10} {streaming:<8}")

        print("\nFeatures by Format:")
        for fmt, caps in capabilities.items():
            print(f"\n{fmt.upper()}:")
            for feature in caps["features"]:
                print(f"  - {feature}")

    return 0


def _handle_pdf_tool(args: argparse.Namespace) -> int:
    """Handle pdf-tool command."""
    from stance.export import PDFExporter

    exporter = PDFExporter()
    tool = exporter.get_pdf_tool()
    available = exporter.is_pdf_available()

    result = {
        "pdf_available": available,
        "tool": tool,
        "tools_checked": ["wkhtmltopdf", "weasyprint"],
        "install_instructions": {
            "wkhtmltopdf": {
                "macos": "brew install wkhtmltopdf",
                "ubuntu": "apt-get install wkhtmltopdf",
                "windows": "Download from wkhtmltopdf.org",
            },
            "weasyprint": {
                "all": "pip install weasyprint",
            },
        },
        "fallback": "HTML with print instructions" if not available else None,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("\nPDF Generation Tool Status")
        print("=" * 50)
        if available:
            print(f"Status: Available")
            print(f"Tool: {tool}")
        else:
            print("Status: Not Available")
            print("Fallback: HTML with print instructions")
            print("\nTo enable native PDF generation, install one of:")
            print("  - wkhtmltopdf: brew install wkhtmltopdf (macOS)")
            print("  - weasyprint: pip install weasyprint")

    return 0


def _handle_severities(args: argparse.Namespace) -> int:
    """Handle severities command."""
    severities = [
        {
            "level": "critical",
            "description": "Severe issues requiring immediate attention",
            "priority": 1,
            "examples": "Public S3 buckets, exposed secrets, RCE vulnerabilities",
        },
        {
            "level": "high",
            "description": "Significant issues requiring prompt remediation",
            "priority": 2,
            "examples": "Overly permissive IAM, missing encryption, privilege escalation",
        },
        {
            "level": "medium",
            "description": "Moderate issues for scheduled remediation",
            "priority": 3,
            "examples": "Missing logging, weak passwords, outdated certificates",
        },
        {
            "level": "low",
            "description": "Minor issues for opportunistic fixing",
            "priority": 4,
            "examples": "Missing tags, minor misconfigurations",
        },
        {
            "level": "info",
            "description": "Informational findings for awareness",
            "priority": 5,
            "examples": "Best practice recommendations, optimization suggestions",
        },
    ]

    if args.format == "json":
        print(json.dumps({"total": len(severities), "severities": severities}, indent=2))
    else:
        print("\nSeverity Levels for Export Filtering")
        print("=" * 60)
        for sev in severities:
            print(f"\n{sev['level'].upper()} (Priority {sev['priority']})")
            print(f"  {sev['description']}")
            print(f"  Examples: {sev['examples']}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    from stance.export import PDFExporter

    pdf_exporter = PDFExporter()

    stats = {
        "formats_supported": 4,
        "report_types": 5,
        "export_options": 10,
        "pdf_tool_available": pdf_exporter.is_pdf_available(),
        "pdf_tool": pdf_exporter.get_pdf_tool(),
        "severity_levels": 5,
        "supported_data_types": ["assets", "findings", "compliance_scores", "trends", "scan_metadata"],
    }

    if args.format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print("\nExport Module Statistics")
        print("=" * 40)
        print(f"Formats Supported: {stats['formats_supported']}")
        print(f"Report Types: {stats['report_types']}")
        print(f"Export Options: {stats['export_options']}")
        print(f"Severity Levels: {stats['severity_levels']}")
        print(f"PDF Tool Available: {'Yes' if stats['pdf_tool_available'] else 'No'}")
        if stats['pdf_tool']:
            print(f"PDF Tool: {stats['pdf_tool']}")
        print(f"Data Types: {', '.join(stats['supported_data_types'])}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    from stance.export import PDFExporter, create_export_manager

    manager = create_export_manager()
    pdf_exporter = PDFExporter()
    available_formats = [f.value for f in manager.available_formats()]

    status = {
        "module": "export",
        "status": "operational",
        "components": {
            "ExportManager": "available",
            "CSVExporter": "available",
            "JSONExporter": "available",
            "HTMLExporter": "available",
            "PDFExporter": "available" if pdf_exporter.is_pdf_available() else "limited",
        },
        "capabilities": [
            "multi_format_export",
            "report_generation",
            "severity_filtering",
            "compliance_reporting",
            "asset_inventory",
            "findings_detail",
            "executive_summary",
        ],
        "available_formats": available_formats,
    }

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nExport Module Status")
        print("=" * 50)
        print(f"Module: {status['module']}")
        print(f"Status: {status['status']}")
        print(f"\nComponents:")
        for comp, state in status["components"].items():
            print(f"  {comp}: {state}")
        print(f"\nAvailable Formats: {', '.join(available_formats)}")
        print(f"\nCapabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    from stance.export import PDFExporter

    pdf_exporter = PDFExporter()

    summary = {
        "module": "export",
        "version": "1.0.0",
        "description": "Multi-format report generation and data export",
        "formats": {
            "json": "Structured JSON with full data fidelity",
            "csv": "Comma-separated values for spreadsheet import",
            "html": "Styled HTML for browser viewing and printing",
            "pdf": "Portable document format (requires tool)",
        },
        "report_types": {
            "full_report": "Comprehensive report with all sections",
            "executive_summary": "High-level overview for management",
            "findings_detail": "Detailed findings with remediation",
            "compliance_summary": "Framework scores and controls",
            "asset_inventory": "Complete asset listing",
        },
        "features": [
            "Multi-format export (JSON, CSV, HTML, PDF)",
            "5 report types for different audiences",
            "Severity-based finding filtering",
            "Compliance framework reporting",
            "Asset inventory generation",
            "Trend data inclusion",
            "Raw configuration export option",
            "Print-ready HTML output",
            "Professional PDF generation",
        ],
        "pdf_status": {
            "available": pdf_exporter.is_pdf_available(),
            "tool": pdf_exporter.get_pdf_tool(),
        },
    }

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nExport Module Summary")
        print("=" * 60)
        print(f"Module: {summary['module']}")
        print(f"Version: {summary['version']}")
        print(f"Description: {summary['description']}")

        print(f"\nExport Formats:")
        for fmt, desc in summary["formats"].items():
            print(f"  {fmt.upper()}: {desc}")

        print(f"\nReport Types:")
        for rt, desc in summary["report_types"].items():
            print(f"  {rt}: {desc}")

        print(f"\nFeatures:")
        for feature in summary["features"]:
            print(f"  - {feature}")

        print(f"\nPDF Generation:")
        if summary["pdf_status"]["available"]:
            print(f"  Status: Available ({summary['pdf_status']['tool']})")
        else:
            print("  Status: Not available (install wkhtmltopdf or weasyprint)")

    return 0
