"""
CLI commands for dashboards module in Mantissa Stance.

Provides command-line interface for managing dashboards, widgets, reports,
scheduled reports, and visualizations.

Part of Phase 91: Advanced Reporting & Dashboards
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


def add_dashboards_parser(subparsers: argparse._SubParsersAction) -> None:
    """
    Add dashboards subcommand parser.

    Args:
        subparsers: Parent subparsers object
    """
    dashboards_parser = subparsers.add_parser(
        "dashboards",
        help="Manage dashboards, widgets, reports, and visualizations",
        description="Create and manage security dashboards, generate reports, and configure scheduled reports.",
    )

    dashboards_subparsers = dashboards_parser.add_subparsers(
        dest="dashboards_command",
        help="Dashboards commands",
    )

    # list - List all dashboards
    list_parser = dashboards_subparsers.add_parser(
        "list",
        help="List all dashboards",
        description="List all available dashboards.",
    )
    list_parser.add_argument(
        "--owner",
        help="Filter by owner",
    )
    list_parser.add_argument(
        "--tag",
        help="Filter by tag",
    )
    list_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # show - Show dashboard details
    show_parser = dashboards_subparsers.add_parser(
        "show",
        help="Show dashboard details",
        description="Display detailed information about a dashboard.",
    )
    show_parser.add_argument(
        "dashboard_id",
        help="Dashboard ID to show",
    )
    show_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # create - Create a new dashboard
    create_parser = dashboards_subparsers.add_parser(
        "create",
        help="Create a new dashboard",
        description="Create a new dashboard from a template or configuration.",
    )
    create_parser.add_argument(
        "--name",
        required=True,
        help="Dashboard name",
    )
    create_parser.add_argument(
        "--template",
        choices=["executive", "security_ops", "compliance", "custom"],
        default="security_ops",
        help="Dashboard template (default: security_ops)",
    )
    create_parser.add_argument(
        "--description",
        default="",
        help="Dashboard description",
    )
    create_parser.add_argument(
        "--theme",
        choices=["light", "dark", "high_contrast"],
        default="light",
        help="Dashboard theme (default: light)",
    )
    create_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # widgets - List widget types
    widgets_parser = dashboards_subparsers.add_parser(
        "widgets",
        help="List available widget types",
        description="List all available widget types and their configurations.",
    )
    widgets_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # charts - List chart types
    charts_parser = dashboards_subparsers.add_parser(
        "charts",
        help="List available chart types",
        description="List all available chart types for visualizations.",
    )
    charts_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # themes - List dashboard themes
    themes_parser = dashboards_subparsers.add_parser(
        "themes",
        help="List dashboard themes",
        description="List all available dashboard themes.",
    )
    themes_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # time-ranges - List time ranges
    timeranges_parser = dashboards_subparsers.add_parser(
        "time-ranges",
        help="List available time ranges",
        description="List all available time ranges for data queries.",
    )
    timeranges_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # reports - List generated reports
    reports_parser = dashboards_subparsers.add_parser(
        "reports",
        help="List generated reports",
        description="List all generated reports.",
    )
    reports_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum reports to show (default: 20)",
    )
    reports_parser.add_argument(
        "--format-filter",
        choices=["pdf", "html", "json", "csv", "markdown", "xlsx"],
        help="Filter by report format",
    )
    reports_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # generate - Generate a report
    generate_parser = dashboards_subparsers.add_parser(
        "generate",
        help="Generate a new report",
        description="Generate a new report using a template.",
    )
    generate_parser.add_argument(
        "--title",
        required=True,
        help="Report title",
    )
    generate_parser.add_argument(
        "--template",
        choices=["executive_summary", "technical_detail", "compliance", "trend"],
        default="executive_summary",
        help="Report template (default: executive_summary)",
    )
    generate_parser.add_argument(
        "--output-format",
        choices=["pdf", "html", "json", "csv", "markdown"],
        default="pdf",
        help="Output format (default: pdf)",
    )
    generate_parser.add_argument(
        "--time-range",
        choices=["last_24_hours", "last_7_days", "last_30_days", "last_90_days"],
        default="last_30_days",
        help="Time range for data (default: last_30_days)",
    )
    generate_parser.add_argument(
        "--output",
        help="Output file path",
    )
    generate_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # schedules - List scheduled reports
    schedules_parser = dashboards_subparsers.add_parser(
        "schedules",
        help="List scheduled reports",
        description="List all scheduled report configurations.",
    )
    schedules_parser.add_argument(
        "--enabled-only",
        action="store_true",
        help="Show only enabled schedules",
    )
    schedules_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # schedule-create - Create a scheduled report
    schedule_create_parser = dashboards_subparsers.add_parser(
        "schedule-create",
        help="Create a scheduled report",
        description="Create a new scheduled report configuration.",
    )
    schedule_create_parser.add_argument(
        "--name",
        required=True,
        help="Schedule name",
    )
    schedule_create_parser.add_argument(
        "--template",
        choices=["executive_summary", "technical_detail", "compliance", "trend"],
        default="executive_summary",
        help="Report template (default: executive_summary)",
    )
    schedule_create_parser.add_argument(
        "--frequency",
        choices=["daily", "weekly", "biweekly", "monthly", "quarterly"],
        default="weekly",
        help="Report frequency (default: weekly)",
    )
    schedule_create_parser.add_argument(
        "--output-format",
        choices=["pdf", "html", "json"],
        default="pdf",
        help="Output format (default: pdf)",
    )
    schedule_create_parser.add_argument(
        "--recipients",
        help="Comma-separated email recipients",
    )
    schedule_create_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # frequencies - List report frequencies
    freq_parser = dashboards_subparsers.add_parser(
        "frequencies",
        help="List report frequencies",
        description="List all available report generation frequencies.",
    )
    freq_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # formats - List report formats
    formats_parser = dashboards_subparsers.add_parser(
        "formats",
        help="List report output formats",
        description="List all available report output formats.",
    )
    formats_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # templates - List report templates
    templates_parser = dashboards_subparsers.add_parser(
        "templates",
        help="List report templates",
        description="List all available report templates.",
    )
    templates_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # metrics - Show dashboard metrics
    metrics_parser = dashboards_subparsers.add_parser(
        "metrics",
        help="Show dashboard metrics summary",
        description="Display summary of key security metrics.",
    )
    metrics_parser.add_argument(
        "--time-range",
        choices=["last_24_hours", "last_7_days", "last_30_days"],
        default="last_7_days",
        help="Time range for metrics (default: last_7_days)",
    )
    metrics_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show module status
    status_parser = dashboards_subparsers.add_parser(
        "status",
        help="Show dashboards module status",
        description="Display the status of the dashboards module.",
    )
    status_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_dashboards(args: argparse.Namespace) -> int:
    """
    Handle dashboards commands.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    command = getattr(args, "dashboards_command", None)

    if not command:
        print("No command specified. Use 'stance dashboards --help' for available commands.")
        return 1

    handlers = {
        "list": _handle_list,
        "show": _handle_show,
        "create": _handle_create,
        "widgets": _handle_widgets,
        "charts": _handle_charts,
        "themes": _handle_themes,
        "time-ranges": _handle_time_ranges,
        "reports": _handle_reports,
        "generate": _handle_generate,
        "schedules": _handle_schedules,
        "schedule-create": _handle_schedule_create,
        "frequencies": _handle_frequencies,
        "formats": _handle_formats,
        "templates": _handle_templates,
        "metrics": _handle_metrics,
        "status": _handle_status,
    }

    handler = handlers.get(command)
    if handler:
        return handler(args)

    print(f"Unknown command: {command}")
    return 1


def _get_sample_dashboards() -> List[Dict[str, Any]]:
    """Get sample dashboard data for demo purposes."""
    return [
        {
            "id": "dash-exec-001",
            "name": "Executive Security Overview",
            "description": "High-level security posture for executives",
            "owner": "security-team",
            "theme": "light",
            "widget_count": 8,
            "time_range": "last_30_days",
            "auto_refresh": 300,
            "is_public": False,
            "tags": ["executive", "overview"],
            "created_at": "2024-12-01T10:00:00Z",
            "updated_at": "2024-12-29T14:30:00Z",
        },
        {
            "id": "dash-secops-001",
            "name": "Security Operations Dashboard",
            "description": "Real-time security operations monitoring",
            "owner": "security-team",
            "theme": "dark",
            "widget_count": 12,
            "time_range": "last_7_days",
            "auto_refresh": 60,
            "is_public": False,
            "tags": ["secops", "monitoring"],
            "created_at": "2024-11-15T08:00:00Z",
            "updated_at": "2024-12-30T09:15:00Z",
        },
        {
            "id": "dash-compliance-001",
            "name": "Compliance Dashboard",
            "description": "Compliance status across frameworks",
            "owner": "compliance-team",
            "theme": "light",
            "widget_count": 10,
            "time_range": "last_90_days",
            "auto_refresh": 3600,
            "is_public": True,
            "tags": ["compliance", "audit"],
            "created_at": "2024-10-01T12:00:00Z",
            "updated_at": "2024-12-28T16:45:00Z",
        },
    ]


def _get_sample_reports() -> List[Dict[str, Any]]:
    """Get sample generated reports for demo purposes."""
    return [
        {
            "id": "rpt-001",
            "title": "Weekly Security Report",
            "format": "pdf",
            "template": "executive_summary",
            "file_size": 1245678,
            "generated_at": "2024-12-30T02:00:00Z",
            "generation_time_seconds": 12.5,
            "sections": ["executive_summary", "findings_overview", "compliance_status", "recommendations"],
        },
        {
            "id": "rpt-002",
            "title": "Technical Findings Detail",
            "format": "html",
            "template": "technical_detail",
            "file_size": 3456789,
            "generated_at": "2024-12-29T14:00:00Z",
            "generation_time_seconds": 25.3,
            "sections": ["findings_detail", "asset_inventory", "vulnerability_analysis", "remediation_steps"],
        },
        {
            "id": "rpt-003",
            "title": "Q4 Compliance Report",
            "format": "pdf",
            "template": "compliance",
            "file_size": 2345678,
            "generated_at": "2024-12-28T10:00:00Z",
            "generation_time_seconds": 18.7,
            "sections": ["compliance_overview", "framework_status", "gap_analysis", "action_items"],
        },
    ]


def _get_sample_schedules() -> List[Dict[str, Any]]:
    """Get sample scheduled reports for demo purposes."""
    return [
        {
            "id": "sched-001",
            "name": "Weekly Executive Summary",
            "frequency": "weekly",
            "template": "executive_summary",
            "format": "pdf",
            "enabled": True,
            "next_run": "2025-01-06T02:00:00Z",
            "last_run": "2024-12-30T02:00:00Z",
            "last_status": "success",
            "run_count": 12,
            "failure_count": 0,
            "recipients": ["ciso@example.com", "security-team@example.com"],
        },
        {
            "id": "sched-002",
            "name": "Daily Security Digest",
            "frequency": "daily",
            "template": "technical_detail",
            "format": "html",
            "enabled": True,
            "next_run": "2025-01-01T06:00:00Z",
            "last_run": "2024-12-31T06:00:00Z",
            "last_status": "success",
            "run_count": 45,
            "failure_count": 1,
            "recipients": ["secops@example.com"],
        },
        {
            "id": "sched-003",
            "name": "Monthly Compliance Report",
            "frequency": "monthly",
            "template": "compliance",
            "format": "pdf",
            "enabled": True,
            "next_run": "2025-02-01T00:00:00Z",
            "last_run": "2025-01-01T00:00:00Z",
            "last_status": "success",
            "run_count": 6,
            "failure_count": 0,
            "recipients": ["compliance@example.com", "audit@example.com"],
        },
    ]


def _handle_list(args: argparse.Namespace) -> int:
    """Handle list command."""
    dashboards = _get_sample_dashboards()

    # Apply filters
    if args.owner:
        dashboards = [d for d in dashboards if d["owner"] == args.owner]
    if args.tag:
        dashboards = [d for d in dashboards if args.tag in d["tags"]]

    if args.format == "json":
        print(json.dumps({
            "dashboards": dashboards,
            "total": len(dashboards),
        }, indent=2))
    else:
        print("\nDashboards")
        print("=" * 80)
        print(f"{'ID':<20} {'Name':<35} {'Widgets':<8} {'Theme':<10} {'Updated':<12}")
        print("-" * 80)
        for d in dashboards:
            updated = d["updated_at"][:10]
            print(f"{d['id']:<20} {d['name'][:34]:<35} {d['widget_count']:<8} {d['theme']:<10} {updated:<12}")
        print(f"\nTotal: {len(dashboards)} dashboards")

    return 0


def _handle_show(args: argparse.Namespace) -> int:
    """Handle show command."""
    dashboards = _get_sample_dashboards()
    dashboard = next((d for d in dashboards if d["id"] == args.dashboard_id), None)

    if not dashboard:
        print(f"Dashboard not found: {args.dashboard_id}")
        return 1

    if args.format == "json":
        print(json.dumps(dashboard, indent=2))
    else:
        print(f"\nDashboard: {dashboard['name']}")
        print("=" * 60)
        print(f"ID: {dashboard['id']}")
        print(f"Description: {dashboard['description']}")
        print(f"Owner: {dashboard['owner']}")
        print(f"Theme: {dashboard['theme']}")
        print(f"Widgets: {dashboard['widget_count']}")
        print(f"Time Range: {dashboard['time_range']}")
        print(f"Auto Refresh: {dashboard['auto_refresh']}s")
        print(f"Public: {dashboard['is_public']}")
        print(f"Tags: {', '.join(dashboard['tags'])}")
        print(f"Created: {dashboard['created_at']}")
        print(f"Updated: {dashboard['updated_at']}")

    return 0


def _handle_create(args: argparse.Namespace) -> int:
    """Handle create command."""
    import uuid

    dashboard = {
        "id": f"dash-{str(uuid.uuid4())[:8]}",
        "name": args.name,
        "description": args.description,
        "template": args.template,
        "theme": args.theme,
        "widget_count": 0,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "created",
    }

    # In real implementation, this would call the dashboards factory
    template_widgets = {
        "executive": 8,
        "security_ops": 12,
        "compliance": 10,
        "custom": 0,
    }
    dashboard["widget_count"] = template_widgets.get(args.template, 0)

    if args.format == "json":
        print(json.dumps(dashboard, indent=2))
    else:
        print(f"\nDashboard Created")
        print("=" * 50)
        print(f"ID: {dashboard['id']}")
        print(f"Name: {dashboard['name']}")
        print(f"Template: {dashboard['template']}")
        print(f"Theme: {dashboard['theme']}")
        print(f"Widgets: {dashboard['widget_count']}")
        print(f"\nUse 'stance dashboards show {dashboard['id']}' to view details.")

    return 0


def _handle_widgets(args: argparse.Namespace) -> int:
    """Handle widgets command."""
    widgets = [
        {"type": "metric", "description": "Single value metric display", "use_case": "KPIs, counts, scores"},
        {"type": "chart", "description": "Data visualization chart", "use_case": "Trends, distributions, comparisons"},
        {"type": "table", "description": "Tabular data display", "use_case": "Findings list, asset inventory"},
        {"type": "list", "description": "Simple list display", "use_case": "Top-N items, recent events"},
        {"type": "gauge", "description": "Gauge/speedometer display", "use_case": "Compliance scores, health"},
        {"type": "heatmap", "description": "Color-coded matrix", "use_case": "Time-based patterns, distributions"},
        {"type": "map", "description": "Geographic visualization", "use_case": "Regional distribution, asset locations"},
        {"type": "timeline", "description": "Chronological event display", "use_case": "Event history, incident timeline"},
        {"type": "text", "description": "Text/markdown content", "use_case": "Descriptions, notes, summaries"},
        {"type": "alert", "description": "Alert/notification panel", "use_case": "Critical alerts, warnings"},
    ]

    if args.format == "json":
        print(json.dumps({"types": widgets, "total": len(widgets)}, indent=2))
    else:
        print("\nWidget Types")
        print("=" * 80)
        print(f"{'Type':<12} {'Description':<35} {'Use Case':<30}")
        print("-" * 80)
        for w in widgets:
            print(f"{w['type']:<12} {w['description']:<35} {w['use_case']:<30}")
        print(f"\nTotal: {len(widgets)} widget types")

    return 0


def _handle_charts(args: argparse.Namespace) -> int:
    """Handle charts command."""
    charts = [
        {"type": "line", "description": "Line chart", "use_case": "Trends over time"},
        {"type": "bar", "description": "Vertical bar chart", "use_case": "Category comparison"},
        {"type": "horizontal_bar", "description": "Horizontal bar chart", "use_case": "Ranked lists"},
        {"type": "pie", "description": "Pie chart", "use_case": "Part-of-whole distribution"},
        {"type": "donut", "description": "Donut chart", "use_case": "Part-of-whole with center metric"},
        {"type": "area", "description": "Area chart", "use_case": "Volume over time"},
        {"type": "stacked_area", "description": "Stacked area chart", "use_case": "Composition over time"},
        {"type": "stacked_bar", "description": "Stacked bar chart", "use_case": "Category composition"},
        {"type": "scatter", "description": "Scatter plot", "use_case": "Correlation analysis"},
        {"type": "bubble", "description": "Bubble chart", "use_case": "Three-variable comparison"},
        {"type": "radar", "description": "Radar/spider chart", "use_case": "Multi-dimensional comparison"},
        {"type": "treemap", "description": "Treemap", "use_case": "Hierarchical proportions"},
        {"type": "funnel", "description": "Funnel chart", "use_case": "Process flow stages"},
        {"type": "sparkline", "description": "Mini inline chart", "use_case": "Inline trends"},
    ]

    if args.format == "json":
        print(json.dumps({"types": charts, "total": len(charts)}, indent=2))
    else:
        print("\nChart Types")
        print("=" * 70)
        print(f"{'Type':<18} {'Description':<25} {'Use Case':<25}")
        print("-" * 70)
        for c in charts:
            print(f"{c['type']:<18} {c['description']:<25} {c['use_case']:<25}")
        print(f"\nTotal: {len(charts)} chart types")

    return 0


def _handle_themes(args: argparse.Namespace) -> int:
    """Handle themes command."""
    themes = [
        {"theme": "light", "description": "Light background theme", "colors": "White bg, dark text"},
        {"theme": "dark", "description": "Dark background theme", "colors": "Dark bg, light text"},
        {"theme": "high_contrast", "description": "High contrast for accessibility", "colors": "Strong contrast"},
        {"theme": "colorblind_safe", "description": "Colorblind-friendly palette", "colors": "Distinguishable colors"},
        {"theme": "print", "description": "Print-optimized theme", "colors": "Black text, white bg"},
    ]

    if args.format == "json":
        print(json.dumps({"themes": themes, "total": len(themes)}, indent=2))
    else:
        print("\nDashboard Themes")
        print("=" * 70)
        print(f"{'Theme':<18} {'Description':<30} {'Colors':<20}")
        print("-" * 70)
        for t in themes:
            print(f"{t['theme']:<18} {t['description']:<30} {t['colors']:<20}")
        print(f"\nTotal: {len(themes)} themes")

    return 0


def _handle_time_ranges(args: argparse.Namespace) -> int:
    """Handle time-ranges command."""
    ranges = [
        {"range": "last_hour", "description": "Last 60 minutes", "duration": "1 hour"},
        {"range": "last_24_hours", "description": "Last 24 hours", "duration": "1 day"},
        {"range": "last_7_days", "description": "Last 7 days", "duration": "1 week"},
        {"range": "last_30_days", "description": "Last 30 days", "duration": "1 month"},
        {"range": "last_90_days", "description": "Last 90 days", "duration": "3 months"},
        {"range": "last_year", "description": "Last 365 days", "duration": "1 year"},
        {"range": "custom", "description": "Custom date range", "duration": "User-defined"},
        {"range": "all_time", "description": "All available data", "duration": "Unlimited"},
    ]

    if args.format == "json":
        print(json.dumps({"ranges": ranges, "total": len(ranges)}, indent=2))
    else:
        print("\nTime Ranges")
        print("=" * 60)
        print(f"{'Range':<18} {'Description':<25} {'Duration':<15}")
        print("-" * 60)
        for r in ranges:
            print(f"{r['range']:<18} {r['description']:<25} {r['duration']:<15}")
        print(f"\nTotal: {len(ranges)} time ranges")

    return 0


def _handle_reports(args: argparse.Namespace) -> int:
    """Handle reports command."""
    reports = _get_sample_reports()

    # Apply filters
    if args.format_filter:
        reports = [r for r in reports if r["format"] == args.format_filter]

    # Apply limit
    reports = reports[:args.limit]

    if args.format == "json":
        print(json.dumps({"reports": reports, "total": len(reports)}, indent=2))
    else:
        print("\nGenerated Reports")
        print("=" * 90)
        print(f"{'ID':<12} {'Title':<35} {'Format':<8} {'Size':<12} {'Generated':<15}")
        print("-" * 90)
        for r in reports:
            size = f"{r['file_size'] / 1024 / 1024:.2f} MB"
            generated = r["generated_at"][:10]
            print(f"{r['id']:<12} {r['title'][:34]:<35} {r['format']:<8} {size:<12} {generated:<15}")
        print(f"\nTotal: {len(reports)} reports")

    return 0


def _handle_generate(args: argparse.Namespace) -> int:
    """Handle generate command."""
    import uuid

    report = {
        "id": f"rpt-{str(uuid.uuid4())[:8]}",
        "title": args.title,
        "template": args.template,
        "format": args.output_format,
        "time_range": args.time_range,
        "status": "generating",
        "started_at": datetime.utcnow().isoformat() + "Z",
    }

    # Simulate report generation
    template_sections = {
        "executive_summary": ["executive_summary", "findings_overview", "compliance_status", "recommendations"],
        "technical_detail": ["findings_detail", "asset_inventory", "vulnerability_analysis", "remediation_steps"],
        "compliance": ["compliance_overview", "framework_status", "gap_analysis", "action_items"],
        "trend": ["trend_analysis", "velocity", "forecasts", "comparison"],
    }

    report["sections"] = template_sections.get(args.template, [])
    report["status"] = "completed"
    report["file_size"] = 1234567
    report["generation_time_seconds"] = 15.2

    if args.output:
        report["file_path"] = args.output

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"\nReport Generated")
        print("=" * 50)
        print(f"ID: {report['id']}")
        print(f"Title: {report['title']}")
        print(f"Template: {report['template']}")
        print(f"Format: {report['format']}")
        print(f"Time Range: {report['time_range']}")
        print(f"Sections: {len(report['sections'])}")
        print(f"Size: {report['file_size'] / 1024 / 1024:.2f} MB")
        print(f"Generation Time: {report['generation_time_seconds']:.1f}s")
        if args.output:
            print(f"Saved to: {report['file_path']}")

    return 0


def _handle_schedules(args: argparse.Namespace) -> int:
    """Handle schedules command."""
    schedules = _get_sample_schedules()

    # Apply filters
    if args.enabled_only:
        schedules = [s for s in schedules if s["enabled"]]

    if args.format == "json":
        print(json.dumps({"schedules": schedules, "total": len(schedules)}, indent=2))
    else:
        print("\nScheduled Reports")
        print("=" * 100)
        print(f"{'ID':<15} {'Name':<30} {'Freq':<10} {'Format':<8} {'Enabled':<8} {'Last Status':<12} {'Next Run':<15}")
        print("-" * 100)
        for s in schedules:
            enabled = "Yes" if s["enabled"] else "No"
            next_run = s["next_run"][:10] if s["next_run"] else "N/A"
            print(f"{s['id']:<15} {s['name'][:29]:<30} {s['frequency']:<10} {s['format']:<8} {enabled:<8} {s['last_status']:<12} {next_run:<15}")
        print(f"\nTotal: {len(schedules)} schedules")

    return 0


def _handle_schedule_create(args: argparse.Namespace) -> int:
    """Handle schedule-create command."""
    import uuid

    schedule = {
        "id": f"sched-{str(uuid.uuid4())[:8]}",
        "name": args.name,
        "template": args.template,
        "frequency": args.frequency,
        "format": args.output_format,
        "enabled": True,
        "recipients": args.recipients.split(",") if args.recipients else [],
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "created",
    }

    # Calculate next run
    freq_deltas = {
        "daily": timedelta(days=1),
        "weekly": timedelta(weeks=1),
        "biweekly": timedelta(weeks=2),
        "monthly": timedelta(days=30),
        "quarterly": timedelta(days=90),
    }
    delta = freq_deltas.get(args.frequency, timedelta(weeks=1))
    schedule["next_run"] = (datetime.utcnow() + delta).isoformat() + "Z"

    if args.format == "json":
        print(json.dumps(schedule, indent=2))
    else:
        print(f"\nScheduled Report Created")
        print("=" * 50)
        print(f"ID: {schedule['id']}")
        print(f"Name: {schedule['name']}")
        print(f"Template: {schedule['template']}")
        print(f"Frequency: {schedule['frequency']}")
        print(f"Format: {schedule['format']}")
        print(f"Next Run: {schedule['next_run']}")
        if schedule["recipients"]:
            print(f"Recipients: {', '.join(schedule['recipients'])}")

    return 0


def _handle_frequencies(args: argparse.Namespace) -> int:
    """Handle frequencies command."""
    frequencies = [
        {"frequency": "once", "description": "One-time generation", "interval": "N/A"},
        {"frequency": "hourly", "description": "Every hour", "interval": "1 hour"},
        {"frequency": "daily", "description": "Every day", "interval": "24 hours"},
        {"frequency": "weekly", "description": "Every week", "interval": "7 days"},
        {"frequency": "biweekly", "description": "Every two weeks", "interval": "14 days"},
        {"frequency": "monthly", "description": "Every month", "interval": "~30 days"},
        {"frequency": "quarterly", "description": "Every quarter", "interval": "~90 days"},
        {"frequency": "yearly", "description": "Every year", "interval": "365 days"},
    ]

    if args.format == "json":
        print(json.dumps({"frequencies": frequencies, "total": len(frequencies)}, indent=2))
    else:
        print("\nReport Frequencies")
        print("=" * 60)
        print(f"{'Frequency':<12} {'Description':<25} {'Interval':<15}")
        print("-" * 60)
        for f in frequencies:
            print(f"{f['frequency']:<12} {f['description']:<25} {f['interval']:<15}")
        print(f"\nTotal: {len(frequencies)} frequencies")

    return 0


def _handle_formats(args: argparse.Namespace) -> int:
    """Handle formats command."""
    formats = [
        {"format": "pdf", "description": "Portable Document Format", "use_case": "Executive reports, printing"},
        {"format": "html", "description": "HTML web page", "use_case": "Interactive viewing, email"},
        {"format": "json", "description": "JSON data format", "use_case": "API integration, automation"},
        {"format": "csv", "description": "Comma-separated values", "use_case": "Data export, spreadsheets"},
        {"format": "markdown", "description": "Markdown text format", "use_case": "Documentation, wikis"},
        {"format": "xlsx", "description": "Excel spreadsheet", "use_case": "Analysis, charts"},
    ]

    if args.format == "json":
        print(json.dumps({"formats": formats, "total": len(formats)}, indent=2))
    else:
        print("\nReport Output Formats")
        print("=" * 70)
        print(f"{'Format':<12} {'Description':<30} {'Use Case':<25}")
        print("-" * 70)
        for f in formats:
            print(f"{f['format']:<12} {f['description']:<30} {f['use_case']:<25}")
        print(f"\nTotal: {len(formats)} formats")

    return 0


def _handle_templates(args: argparse.Namespace) -> int:
    """Handle templates command."""
    templates = [
        {
            "template": "executive_summary",
            "description": "High-level executive summary",
            "sections": ["executive_summary", "findings_overview", "compliance_status", "recommendations"],
            "audience": "Executives, Board",
        },
        {
            "template": "technical_detail",
            "description": "Detailed technical findings report",
            "sections": ["findings_detail", "asset_inventory", "vulnerability_analysis", "remediation_steps"],
            "audience": "Security Engineers",
        },
        {
            "template": "compliance",
            "description": "Compliance framework status report",
            "sections": ["compliance_overview", "framework_status", "gap_analysis", "action_items"],
            "audience": "Compliance, Audit",
        },
        {
            "template": "trend",
            "description": "Security trend analysis report",
            "sections": ["trend_analysis", "velocity", "forecasts", "comparison"],
            "audience": "Security Management",
        },
    ]

    if args.format == "json":
        print(json.dumps({"templates": templates, "total": len(templates)}, indent=2))
    else:
        print("\nReport Templates")
        print("=" * 90)
        print(f"{'Template':<20} {'Description':<35} {'Audience':<20}")
        print("-" * 90)
        for t in templates:
            print(f"{t['template']:<20} {t['description']:<35} {t['audience']:<20}")
            print(f"  Sections: {', '.join(t['sections'])}")
        print(f"\nTotal: {len(templates)} templates")

    return 0


def _handle_metrics(args: argparse.Namespace) -> int:
    """Handle metrics command."""
    metrics = {
        "security_score": {
            "value": 78.5,
            "trend": "improving",
            "change": 3.2,
            "description": "Overall security posture score",
        },
        "total_findings": {
            "value": 156,
            "trend": "improving",
            "change": -12,
            "description": "Total active findings",
        },
        "critical_findings": {
            "value": 5,
            "trend": "stable",
            "change": 0,
            "description": "Critical severity findings",
        },
        "high_findings": {
            "value": 23,
            "trend": "improving",
            "change": -4,
            "description": "High severity findings",
        },
        "compliance_score": {
            "value": 85.2,
            "trend": "improving",
            "change": 2.1,
            "description": "Overall compliance score",
        },
        "assets_scanned": {
            "value": 1247,
            "trend": "stable",
            "change": 5,
            "description": "Total assets in inventory",
        },
        "mttr": {
            "value": 4.2,
            "trend": "improving",
            "change": -0.8,
            "description": "Mean time to remediation (days)",
        },
        "scan_frequency": {
            "value": 2.5,
            "trend": "stable",
            "change": 0,
            "description": "Scans per day",
        },
    }

    if args.format == "json":
        print(json.dumps({
            "time_range": args.time_range,
            "metrics": metrics,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }, indent=2))
    else:
        print(f"\nDashboard Metrics ({args.time_range})")
        print("=" * 70)
        print(f"{'Metric':<20} {'Value':<12} {'Trend':<12} {'Change':<10}")
        print("-" * 70)
        for name, m in metrics.items():
            change_str = f"{m['change']:+.1f}" if isinstance(m['change'], float) else f"{m['change']:+d}"
            print(f"{name:<20} {m['value']:<12} {m['trend']:<12} {change_str:<10}")
        print()

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = {
        "module": "dashboards",
        "version": "1.0.0",
        "status": "operational",
        "components": {
            "Dashboard": "available",
            "Widget": "available",
            "ReportGenerator": "available",
            "ReportScheduler": "available",
            "ChartBuilder": "available",
            "MetricsAggregator": "available",
            "ReportDistributor": "available",
        },
        "capabilities": [
            "dashboard_management",
            "widget_configuration",
            "report_generation",
            "scheduled_reports",
            "chart_visualization",
            "metrics_aggregation",
            "multi_format_export",
            "email_delivery",
            "webhook_delivery",
            "storage_delivery",
        ],
        "statistics": {
            "dashboards": 3,
            "scheduled_reports": 3,
            "generated_reports_30d": 45,
            "widget_types": 10,
            "chart_types": 14,
            "report_formats": 6,
        },
    }

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nDashboards Module Status")
        print("=" * 50)
        print(f"Module: {status['module']}")
        print(f"Version: {status['version']}")
        print(f"Status: {status['status']}")

        print("\nComponents:")
        for comp, state in status["components"].items():
            print(f"  {comp}: {state}")

        print("\nCapabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")

        print("\nStatistics:")
        for stat, value in status["statistics"].items():
            print(f"  {stat.replace('_', ' ').title()}: {value}")

    return 0
