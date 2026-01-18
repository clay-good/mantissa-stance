"""
Dashboard management handlers for the Stance web API.

This module handles all /api/dashboard/* endpoints for dashboard operations
including dashboard listing, widget types, chart types, themes, time ranges,
report generation, scheduling, and metrics aggregation.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class DashboardHandler(RoutedHandler):
    """
    Handler for dashboard management API endpoints.

    Handles:
    - Dashboard listing and management
    - Widget types and chart types
    - Dashboard themes and time ranges
    - Report generation and scheduling
    - Metrics aggregation
    """

    base_path = "/api/dashboard/"

    # =========================================================================
    # Dashboard Listing GET endpoints
    # =========================================================================

    @route("list")
    def dashboard_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all dashboards."""
        try:
            owner = self.get_param(params, "owner", "")
            tag = self.get_param(params, "tag", "")

            # Demo dashboards data
            dashboards = [
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

            if owner:
                dashboards = [d for d in dashboards if d["owner"] == owner]
            if tag:
                dashboards = [d for d in dashboards if tag in d["tags"]]

            return HandlerResponse.success({
                "dashboards": dashboards,
                "total": len(dashboards),
            })
        except Exception as e:
            logger.exception("Failed to list dashboards")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def dashboard_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show dashboard details."""
        try:
            dashboard_id = self.get_param(params, "id", "")

            if not dashboard_id:
                return HandlerResponse.error("id parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "id": dashboard_id,
                "name": "Executive Security Overview",
                "description": "High-level security posture for executives",
                "owner": "security-team",
                "theme": "light",
                "widget_count": 8,
                "time_range": "last_30_days",
                "auto_refresh": 300,
                "is_public": False,
                "tags": ["executive", "overview"],
                "widgets": [
                    {"id": "w1", "type": "metric", "title": "Security Score", "position": {"x": 0, "y": 0}},
                    {"id": "w2", "type": "chart", "title": "Findings Trend", "position": {"x": 1, "y": 0}},
                    {"id": "w3", "type": "gauge", "title": "Compliance", "position": {"x": 2, "y": 0}},
                ],
                "created_at": "2024-12-01T10:00:00Z",
                "updated_at": "2024-12-29T14:30:00Z",
            }

            return HandlerResponse.success({"dashboard": result})
        except Exception as e:
            logger.exception("Failed to get dashboard details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Widget and Chart Types endpoints
    # =========================================================================

    @route("widgets")
    def dashboard_widgets(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available widget types."""
        try:
            widgets = [
                {"type": "metric", "description": "Single value metric display", "use_case": "KPIs, counts, scores"},
                {"type": "chart", "description": "Data visualization chart", "use_case": "Trends, distributions"},
                {"type": "table", "description": "Tabular data display", "use_case": "Findings list, inventory"},
                {"type": "list", "description": "Simple list display", "use_case": "Top-N items, recent events"},
                {"type": "gauge", "description": "Gauge/speedometer display", "use_case": "Compliance scores, health"},
                {"type": "heatmap", "description": "Color-coded matrix", "use_case": "Time-based patterns"},
                {"type": "map", "description": "Geographic visualization", "use_case": "Regional distribution"},
                {"type": "timeline", "description": "Chronological event display", "use_case": "Event history"},
                {"type": "text", "description": "Text/markdown content", "use_case": "Descriptions, notes"},
                {"type": "alert", "description": "Alert/notification panel", "use_case": "Critical alerts"},
            ]

            return HandlerResponse.success({
                "types": widgets,
                "total": len(widgets),
            })
        except Exception as e:
            logger.exception("Failed to get widget types")
            return HandlerResponse.server_error(str(e))

    @route("charts")
    def dashboard_charts(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available chart types."""
        try:
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

            return HandlerResponse.success({
                "types": charts,
                "total": len(charts),
            })
        except Exception as e:
            logger.exception("Failed to get chart types")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Theme and Time Range endpoints
    # =========================================================================

    @route("themes")
    def dashboard_themes(self, params: dict, body: dict | None) -> HandlerResponse:
        """List dashboard themes."""
        try:
            themes = [
                {"theme": "light", "description": "Light background theme", "colors": "White bg, dark text"},
                {"theme": "dark", "description": "Dark background theme", "colors": "Dark bg, light text"},
                {"theme": "high_contrast", "description": "High contrast for accessibility", "colors": "Strong contrast"},
                {"theme": "colorblind_safe", "description": "Colorblind-friendly palette", "colors": "Distinguishable"},
                {"theme": "print", "description": "Print-optimized theme", "colors": "Black text, white bg"},
            ]

            return HandlerResponse.success({
                "themes": themes,
                "total": len(themes),
            })
        except Exception as e:
            logger.exception("Failed to get themes")
            return HandlerResponse.server_error(str(e))

    @route("time-ranges")
    def dashboard_time_ranges(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available time ranges."""
        try:
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

            return HandlerResponse.success({
                "ranges": ranges,
                "total": len(ranges),
            })
        except Exception as e:
            logger.exception("Failed to get time ranges")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Report Listing endpoints
    # =========================================================================

    @route("reports")
    def dashboard_reports(self, params: dict, body: dict | None) -> HandlerResponse:
        """List generated reports."""
        try:
            format_filter = self.get_param(params, "format_filter", "")
            limit = self.get_param_int(params, "limit", 20)

            reports = [
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

            if format_filter:
                reports = [r for r in reports if r["format"] == format_filter]

            reports = reports[:limit]

            return HandlerResponse.success({
                "reports": reports,
                "total": len(reports),
            })
        except Exception as e:
            logger.exception("Failed to list reports")
            return HandlerResponse.server_error(str(e))

    @route("schedules")
    def dashboard_schedules(self, params: dict, body: dict | None) -> HandlerResponse:
        """List scheduled reports."""
        try:
            enabled_only = self.get_param_bool(params, "enabled_only", False)

            schedules = [
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
                    "enabled": False,
                    "next_run": "2025-02-01T00:00:00Z",
                    "last_run": "2025-01-01T00:00:00Z",
                    "last_status": "success",
                    "run_count": 6,
                    "failure_count": 0,
                    "recipients": ["compliance@example.com", "audit@example.com"],
                },
            ]

            if enabled_only:
                schedules = [s for s in schedules if s["enabled"]]

            return HandlerResponse.success({
                "schedules": schedules,
                "total": len(schedules),
            })
        except Exception as e:
            logger.exception("Failed to list schedules")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Metadata endpoints
    # =========================================================================

    @route("frequencies")
    def dashboard_frequencies(self, params: dict, body: dict | None) -> HandlerResponse:
        """List report frequencies."""
        try:
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

            return HandlerResponse.success({
                "frequencies": frequencies,
                "total": len(frequencies),
            })
        except Exception as e:
            logger.exception("Failed to get frequencies")
            return HandlerResponse.server_error(str(e))

    @route("formats")
    def dashboard_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """List report output formats."""
        try:
            formats = [
                {"format": "pdf", "description": "Portable Document Format", "use_case": "Executive reports, printing"},
                {"format": "html", "description": "HTML web page", "use_case": "Interactive viewing, email"},
                {"format": "json", "description": "JSON data format", "use_case": "API integration, automation"},
                {"format": "csv", "description": "Comma-separated values", "use_case": "Data export, spreadsheets"},
                {"format": "markdown", "description": "Markdown text format", "use_case": "Documentation, wikis"},
                {"format": "xlsx", "description": "Excel spreadsheet", "use_case": "Analysis, charts"},
            ]

            return HandlerResponse.success({
                "formats": formats,
                "total": len(formats),
            })
        except Exception as e:
            logger.exception("Failed to get formats")
            return HandlerResponse.server_error(str(e))

    @route("templates")
    def dashboard_templates(self, params: dict, body: dict | None) -> HandlerResponse:
        """List report templates."""
        try:
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

            return HandlerResponse.success({
                "templates": templates,
                "total": len(templates),
            })
        except Exception as e:
            logger.exception("Failed to get templates")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Dashboard Management POST endpoints
    # =========================================================================

    @route("create", methods=["POST"])
    def dashboard_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a new dashboard."""
        try:
            body = body or {}
            name = body.get("name", "")
            template = body.get("template", "security_ops")
            description = body.get("description", "")
            theme = body.get("theme", "light")

            if not name:
                return HandlerResponse.error("name parameter required", HttpStatus.BAD_REQUEST)

            template_widgets = {
                "executive": 8,
                "security_ops": 12,
                "compliance": 10,
                "custom": 0,
            }

            result = {
                "id": f"dash-{name.lower().replace(' ', '-')[:8]}-new",
                "name": name,
                "description": description,
                "template": template,
                "theme": theme,
                "widget_count": template_widgets.get(template, 0),
                "created_at": "2024-12-30T12:00:00Z",
                "status": "created",
            }

            return HandlerResponse.success({"success": True, "dashboard": result}, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create dashboard")
            return HandlerResponse.server_error(str(e))

    @route("generate", methods=["POST"])
    def dashboard_generate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate a new report."""
        try:
            body = body or {}
            title = body.get("title", "")
            template = body.get("template", "executive_summary")
            output_format = body.get("format", "pdf")
            time_range = body.get("time_range", "last_30_days")

            if not title:
                return HandlerResponse.error("title parameter required", HttpStatus.BAD_REQUEST)

            template_sections = {
                "executive_summary": ["executive_summary", "findings_overview", "compliance_status", "recommendations"],
                "technical_detail": ["findings_detail", "asset_inventory", "vulnerability_analysis", "remediation_steps"],
                "compliance": ["compliance_overview", "framework_status", "gap_analysis", "action_items"],
                "trend": ["trend_analysis", "velocity", "forecasts", "comparison"],
            }

            result = {
                "id": f"rpt-{title.lower().replace(' ', '-')[:8]}-new",
                "title": title,
                "template": template,
                "format": output_format,
                "time_range": time_range,
                "sections": template_sections.get(template, []),
                "status": "completed",
                "file_size": 1234567,
                "generation_time_seconds": 15.2,
                "generated_at": "2024-12-30T12:00:00Z",
            }

            return HandlerResponse.success({"success": True, "report": result}, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to generate report")
            return HandlerResponse.server_error(str(e))

    @route("schedule-create", methods=["POST"])
    def dashboard_schedule_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a scheduled report."""
        try:
            body = body or {}
            name = body.get("name", "")
            template = body.get("template", "executive_summary")
            frequency = body.get("frequency", "weekly")
            output_format = body.get("format", "pdf")
            recipients = body.get("recipients", [])

            if not name:
                return HandlerResponse.error("name parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "id": f"sched-{name.lower().replace(' ', '-')[:8]}-new",
                "name": name,
                "template": template,
                "frequency": frequency,
                "format": output_format,
                "enabled": True,
                "recipients": recipients if isinstance(recipients, list) else [],
                "created_at": "2024-12-30T12:00:00Z",
                "status": "created",
            }

            return HandlerResponse.success({"success": True, "schedule": result}, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create schedule")
            return HandlerResponse.server_error(str(e))

    @route("delete", methods=["POST"])
    def dashboard_delete(self, params: dict, body: dict | None) -> HandlerResponse:
        """Delete a dashboard."""
        try:
            body = body or {}
            dashboard_id = body.get("id") or self.get_param(params, "id", "")

            if not dashboard_id:
                return HandlerResponse.error("id required", HttpStatus.BAD_REQUEST)

            return HandlerResponse.success({
                "id": dashboard_id,
                "deleted": True,
                "message": f"Dashboard {dashboard_id} has been deleted",
            })
        except Exception as e:
            logger.exception("Failed to delete dashboard")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Metrics and Status endpoints
    # =========================================================================

    @route("metrics")
    def dashboard_metrics(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show dashboard metrics summary."""
        try:
            time_range = self.get_param(params, "time_range", "last_7_days")

            metrics = {
                "security_score": {"value": 78.5, "trend": "improving", "change": 3.2},
                "total_findings": {"value": 156, "trend": "improving", "change": -12},
                "critical_findings": {"value": 5, "trend": "stable", "change": 0},
                "high_findings": {"value": 23, "trend": "improving", "change": -4},
                "compliance_score": {"value": 85.2, "trend": "improving", "change": 2.1},
                "assets_scanned": {"value": 1247, "trend": "stable", "change": 5},
                "mttr": {"value": 4.2, "trend": "improving", "change": -0.8},
                "scan_frequency": {"value": 2.5, "trend": "stable", "change": 0},
            }

            return HandlerResponse.success({
                "time_range": time_range,
                "metrics": metrics,
                "generated_at": "2024-12-30T12:00:00Z",
            })
        except Exception as e:
            logger.exception("Failed to get metrics")
            return HandlerResponse.server_error(str(e))

    @route("stats")
    def dashboard_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show dashboard statistics."""
        try:
            result = {
                "total_dashboards": 3,
                "public_dashboards": 1,
                "private_dashboards": 2,
                "total_widgets": 30,
                "scheduled_reports": 3,
                "generated_reports_30d": 45,
                "by_owner": {
                    "security-team": 2,
                    "compliance-team": 1,
                },
                "by_theme": {
                    "light": 2,
                    "dark": 1,
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get dashboard stats")
            return HandlerResponse.server_error(str(e))

    @route("status")
    def dashboard_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show dashboards module status."""
        try:
            result = {
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
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get dashboard status")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def dashboard_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive dashboard module summary."""
        try:
            result = {
                "module": "dashboards",
                "version": "1.0.0",
                "description": "Dashboard and reporting management for security visualization",
                "features": [
                    "Customizable dashboard layouts",
                    "Multiple widget types (10 types)",
                    "Multiple chart types (14 types)",
                    "Theme customization (5 themes)",
                    "Flexible time ranges",
                    "Report generation in multiple formats",
                    "Scheduled report delivery",
                    "Metrics aggregation and trending",
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

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get dashboard summary")
            return HandlerResponse.server_error(str(e))
