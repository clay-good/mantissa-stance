"""
Report management handlers for the Stance web API.

This module handles all /api/report/* endpoints for reporting operations
including trend analysis, velocity calculation, improvement tracking,
period comparison, forecasting, and report generation.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class ReportHandler(RoutedHandler):
    """
    Handler for report management API endpoints.

    Handles:
    - Report listing and generation
    - Trend analysis and metrics
    - Findings velocity and improvement tracking
    - Period comparison and forecasting
    - Report templates and formats
    - Report scheduling and exports
    """

    base_path = "/api/report/"

    # =========================================================================
    # Report Listing GET endpoints
    # =========================================================================

    @route("list")
    def report_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available reports."""
        try:
            report_type = self.get_param(params, "type", "")
            status = self.get_param(params, "status", "")
            limit = self.get_param_int(params, "limit", 20)
            offset = self.get_param_int(params, "offset", 0)

            # Demo reports data
            reports = [
                {
                    "id": "report-001",
                    "name": "Weekly Security Summary",
                    "type": "security_summary",
                    "status": "completed",
                    "created_at": "2024-12-30T10:00:00Z",
                    "format": "pdf",
                    "size_bytes": 125000,
                },
                {
                    "id": "report-002",
                    "name": "Monthly Compliance Report",
                    "type": "compliance",
                    "status": "completed",
                    "created_at": "2024-12-28T10:00:00Z",
                    "format": "pdf",
                    "size_bytes": 250000,
                },
                {
                    "id": "report-003",
                    "name": "Trend Analysis Q4 2024",
                    "type": "trend",
                    "status": "completed",
                    "created_at": "2024-12-25T10:00:00Z",
                    "format": "xlsx",
                    "size_bytes": 85000,
                },
                {
                    "id": "report-004",
                    "name": "Executive Dashboard Export",
                    "type": "executive",
                    "status": "generating",
                    "created_at": "2024-12-30T12:00:00Z",
                    "format": "pptx",
                    "size_bytes": 0,
                },
                {
                    "id": "report-005",
                    "name": "Finding Details Export",
                    "type": "findings",
                    "status": "completed",
                    "created_at": "2024-12-29T15:00:00Z",
                    "format": "csv",
                    "size_bytes": 45000,
                },
            ]

            if report_type:
                reports = [r for r in reports if r["type"] == report_type]
            if status:
                reports = [r for r in reports if r["status"] == status]

            total = len(reports)
            reports = reports[offset:offset + limit]

            return HandlerResponse.success({
                "reports": reports,
                "total": total,
                "limit": limit,
                "offset": offset,
            })
        except Exception as e:
            logger.exception("Failed to list reports")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def report_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detailed information for a specific report."""
        try:
            report_id = self.get_param(params, "report_id", "")

            if not report_id:
                return HandlerResponse.error("report_id parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "id": report_id,
                "name": "Weekly Security Summary",
                "type": "security_summary",
                "status": "completed",
                "created_at": "2024-12-30T10:00:00Z",
                "completed_at": "2024-12-30T10:05:00Z",
                "format": "pdf",
                "size_bytes": 125000,
                "download_url": f"/api/report/download/{report_id}",
                "parameters": {
                    "date_range": "2024-12-23 to 2024-12-30",
                    "include_findings": True,
                    "include_compliance": True,
                    "include_trends": True,
                },
                "summary": {
                    "total_findings": 150,
                    "critical_findings": 5,
                    "high_findings": 20,
                    "compliance_score": 78.5,
                    "trend_direction": "improving",
                },
                "generated_by": "scheduled",
                "expires_at": "2025-01-30T10:00:00Z",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get report details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Report Types and Templates endpoints
    # =========================================================================

    @route("types")
    def report_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available report types."""
        try:
            types = [
                {
                    "id": "security_summary",
                    "name": "Security Summary",
                    "description": "Overview of security posture with key metrics",
                    "formats": ["pdf", "html", "json"],
                    "scheduled": True,
                },
                {
                    "id": "compliance",
                    "name": "Compliance Report",
                    "description": "Detailed compliance status across frameworks",
                    "formats": ["pdf", "xlsx", "json"],
                    "scheduled": True,
                },
                {
                    "id": "trend",
                    "name": "Trend Analysis",
                    "description": "Historical trends and forecasts",
                    "formats": ["pdf", "xlsx", "json"],
                    "scheduled": True,
                },
                {
                    "id": "executive",
                    "name": "Executive Dashboard",
                    "description": "High-level metrics for leadership",
                    "formats": ["pdf", "pptx"],
                    "scheduled": True,
                },
                {
                    "id": "findings",
                    "name": "Findings Export",
                    "description": "Detailed findings data export",
                    "formats": ["csv", "xlsx", "json"],
                    "scheduled": False,
                },
                {
                    "id": "assets",
                    "name": "Asset Inventory",
                    "description": "Complete asset inventory report",
                    "formats": ["csv", "xlsx", "json"],
                    "scheduled": False,
                },
                {
                    "id": "remediation",
                    "name": "Remediation Report",
                    "description": "Prioritized remediation recommendations",
                    "formats": ["pdf", "xlsx"],
                    "scheduled": True,
                },
            ]

            return HandlerResponse.success({
                "types": types,
                "total": len(types),
            })
        except Exception as e:
            logger.exception("Failed to get report types")
            return HandlerResponse.server_error(str(e))

    @route("templates")
    def report_templates(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available report templates."""
        try:
            report_type = self.get_param(params, "type", "")

            templates = [
                {
                    "id": "weekly-security",
                    "name": "Weekly Security Summary",
                    "type": "security_summary",
                    "description": "Standard weekly security overview",
                    "sections": ["overview", "findings", "trends", "recommendations"],
                    "default": True,
                },
                {
                    "id": "monthly-compliance",
                    "name": "Monthly Compliance Report",
                    "type": "compliance",
                    "description": "Monthly compliance status across all frameworks",
                    "sections": ["summary", "by_framework", "gaps", "remediation"],
                    "default": True,
                },
                {
                    "id": "quarterly-executive",
                    "name": "Quarterly Executive Summary",
                    "type": "executive",
                    "description": "High-level quarterly summary for leadership",
                    "sections": ["kpis", "trends", "highlights", "roadmap"],
                    "default": True,
                },
                {
                    "id": "custom-findings",
                    "name": "Custom Findings Export",
                    "type": "findings",
                    "description": "Configurable findings export",
                    "sections": ["findings"],
                    "default": False,
                },
            ]

            if report_type:
                templates = [t for t in templates if t["type"] == report_type]

            return HandlerResponse.success({
                "templates": templates,
                "total": len(templates),
            })
        except Exception as e:
            logger.exception("Failed to get report templates")
            return HandlerResponse.server_error(str(e))

    @route("formats")
    def report_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available export formats."""
        try:
            formats = [
                {
                    "id": "pdf",
                    "name": "PDF Document",
                    "mime_type": "application/pdf",
                    "extension": ".pdf",
                    "supports_charts": True,
                },
                {
                    "id": "xlsx",
                    "name": "Excel Spreadsheet",
                    "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "extension": ".xlsx",
                    "supports_charts": True,
                },
                {
                    "id": "csv",
                    "name": "CSV File",
                    "mime_type": "text/csv",
                    "extension": ".csv",
                    "supports_charts": False,
                },
                {
                    "id": "json",
                    "name": "JSON Data",
                    "mime_type": "application/json",
                    "extension": ".json",
                    "supports_charts": False,
                },
                {
                    "id": "html",
                    "name": "HTML Report",
                    "mime_type": "text/html",
                    "extension": ".html",
                    "supports_charts": True,
                },
                {
                    "id": "pptx",
                    "name": "PowerPoint Presentation",
                    "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    "extension": ".pptx",
                    "supports_charts": True,
                },
            ]

            return HandlerResponse.success({
                "formats": formats,
                "total": len(formats),
            })
        except Exception as e:
            logger.exception("Failed to get report formats")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Trend Analysis endpoints
    # =========================================================================

    @route("analyze")
    def report_analyze(self, params: dict, body: dict | None) -> HandlerResponse:
        """Perform full trend analysis."""
        try:
            config = self.get_param(params, "config", "default")
            days = self.get_param_int(params, "days", 30)
            period = self.get_param(params, "period", "daily")

            # Demo analysis result
            result = {
                "config": config,
                "analysis_period": {
                    "days": days,
                    "period": period,
                    "start_date": "2024-12-01",
                    "end_date": "2024-12-30",
                },
                "findings_trend": {
                    "current_total": 150,
                    "previous_total": 165,
                    "change": -15,
                    "change_percent": -9.1,
                    "direction": "improving",
                    "by_severity": {
                        "critical": {"current": 5, "previous": 8, "change": -3},
                        "high": {"current": 20, "previous": 25, "change": -5},
                        "medium": {"current": 55, "previous": 60, "change": -5},
                        "low": {"current": 70, "previous": 72, "change": -2},
                    },
                },
                "compliance_trend": {
                    "current_score": 78.5,
                    "previous_score": 72.0,
                    "change": 6.5,
                    "direction": "improving",
                },
                "velocity": {
                    "findings_per_day": -0.5,
                    "remediation_per_day": 1.2,
                },
                "recommendations": [
                    "Continue current remediation efforts - positive trend observed",
                    "Focus on critical findings - 5 remaining",
                    "Review high-severity items in IAM category",
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to perform trend analysis")
            return HandlerResponse.server_error(str(e))

    @route("velocity")
    def report_velocity(self, params: dict, body: dict | None) -> HandlerResponse:
        """Calculate findings velocity."""
        try:
            config = self.get_param(params, "config", "default")
            days = self.get_param_int(params, "days", 7)

            result = {
                "config": config,
                "days_analyzed": days,
                "velocities": {
                    "total": -0.5,
                    "critical": -0.1,
                    "high": -0.2,
                    "medium": -0.15,
                    "low": -0.05,
                },
                "unit": "findings/day",
                "interpretation": "Negative velocity indicates findings are being resolved faster than new ones are discovered",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to calculate velocity")
            return HandlerResponse.server_error(str(e))

    @route("improvement")
    def report_improvement(self, params: dict, body: dict | None) -> HandlerResponse:
        """Calculate security improvement rate."""
        try:
            config = self.get_param(params, "config", "default")
            days = self.get_param_int(params, "days", 30)

            result = {
                "config": config,
                "days_analyzed": days,
                "improvement_rate": 9.1,
                "unit": "percent",
                "direction": "improving",
                "breakdown": {
                    "findings_reduction": 9.1,
                    "compliance_improvement": 9.0,
                    "remediation_rate": 85.0,
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to calculate improvement rate")
            return HandlerResponse.server_error(str(e))

    @route("compare")
    def report_compare(self, params: dict, body: dict | None) -> HandlerResponse:
        """Compare two time periods."""
        try:
            config = self.get_param(params, "config", "default")
            current_days = self.get_param_int(params, "current_days", 7)
            previous_days = self.get_param_int(params, "previous_days", 7)

            result = {
                "config": config,
                "current_period": {
                    "days": current_days,
                    "findings": 150,
                    "compliance_score": 78.5,
                },
                "previous_period": {
                    "days": previous_days,
                    "findings": 165,
                    "compliance_score": 72.0,
                },
                "comparison": {
                    "findings_change": -15,
                    "findings_change_percent": -9.1,
                    "compliance_change": 6.5,
                    "direction": "improving",
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to compare periods")
            return HandlerResponse.server_error(str(e))

    @route("forecast")
    def report_forecast(self, params: dict, body: dict | None) -> HandlerResponse:
        """Forecast future findings."""
        try:
            config = self.get_param(params, "config", "default")
            history_days = self.get_param_int(params, "history_days", 30)
            forecast_days = self.get_param_int(params, "forecast_days", 7)

            result = {
                "config": config,
                "history_days": history_days,
                "forecast_days": forecast_days,
                "model": "linear_regression",
                "current_findings": 150,
                "forecast": [
                    {"date": "2024-12-31", "predicted_findings": 148, "confidence": 0.85},
                    {"date": "2025-01-01", "predicted_findings": 146, "confidence": 0.82},
                    {"date": "2025-01-02", "predicted_findings": 144, "confidence": 0.79},
                    {"date": "2025-01-03", "predicted_findings": 142, "confidence": 0.76},
                    {"date": "2025-01-04", "predicted_findings": 140, "confidence": 0.73},
                    {"date": "2025-01-05", "predicted_findings": 138, "confidence": 0.70},
                    {"date": "2025-01-06", "predicted_findings": 136, "confidence": 0.67},
                ],
                "trend_direction": "decreasing",
                "confidence_interval": "67-85%",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to generate forecast")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Report Metadata endpoints
    # =========================================================================

    @route("directions")
    def report_directions(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available trend directions."""
        try:
            directions = [
                {
                    "direction": "improving",
                    "description": "Security posture getting better (fewer findings or higher compliance)",
                    "indicator": "Positive trend",
                    "action": "Continue current practices",
                },
                {
                    "direction": "declining",
                    "description": "Security posture getting worse (more findings or lower compliance)",
                    "indicator": "Negative trend",
                    "action": "Investigate and remediate",
                },
                {
                    "direction": "stable",
                    "description": "No significant change in security posture",
                    "indicator": "Neutral trend",
                    "action": "Monitor and maintain",
                },
                {
                    "direction": "insufficient_data",
                    "description": "Not enough data points for reliable trend analysis",
                    "indicator": "Unknown trend",
                    "action": "Collect more scan data",
                },
            ]

            return HandlerResponse.success({
                "directions": directions,
                "total": len(directions),
            })
        except Exception as e:
            logger.exception("Failed to get directions")
            return HandlerResponse.server_error(str(e))

    @route("periods")
    def report_periods(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available trend periods."""
        try:
            periods = [
                {
                    "period": "daily",
                    "description": "Day-by-day trend analysis",
                    "use_case": "Short-term monitoring and rapid response",
                    "recommended_history": "7-14 days",
                },
                {
                    "period": "weekly",
                    "description": "Week-over-week trend analysis",
                    "use_case": "Sprint-level tracking and weekly reports",
                    "recommended_history": "4-8 weeks",
                },
                {
                    "period": "monthly",
                    "description": "Month-over-month trend analysis",
                    "use_case": "Executive reporting and long-term planning",
                    "recommended_history": "3-6 months",
                },
                {
                    "period": "quarterly",
                    "description": "Quarter-over-quarter trend analysis",
                    "use_case": "Strategic planning and compliance reporting",
                    "recommended_history": "4+ quarters",
                },
            ]

            return HandlerResponse.success({
                "periods": periods,
                "total": len(periods),
            })
        except Exception as e:
            logger.exception("Failed to get periods")
            return HandlerResponse.server_error(str(e))

    @route("metrics")
    def report_metrics(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show available trend metrics."""
        try:
            metrics = [
                {"metric": "current_value", "description": "Most recent value from scans", "type": "float"},
                {"metric": "previous_value", "description": "Value from previous period", "type": "float"},
                {"metric": "average", "description": "Average value over the analysis period", "type": "float"},
                {"metric": "min_value", "description": "Minimum value observed", "type": "float"},
                {"metric": "max_value", "description": "Maximum value observed", "type": "float"},
                {"metric": "change", "description": "Absolute change from previous value", "type": "float"},
                {"metric": "change_percent", "description": "Percentage change from previous value", "type": "float"},
                {"metric": "direction", "description": "Trend direction (improving/declining/stable)", "type": "enum"},
                {"metric": "data_points", "description": "Number of data points analyzed", "type": "integer"},
                {"metric": "velocity", "description": "Rate of change per day", "type": "float"},
            ]

            return HandlerResponse.success({
                "metrics": metrics,
                "total": len(metrics),
            })
        except Exception as e:
            logger.exception("Failed to get metrics")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Report Generation endpoints
    # =========================================================================

    @route("generate", methods=["POST"])
    def report_generate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate a new report."""
        try:
            body = body or {}
            report_type = body.get("type", "")
            template_id = body.get("template_id", "")
            format_type = body.get("format", "pdf")
            date_range = body.get("date_range", {})

            if not report_type:
                return HandlerResponse.error("type parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "report_id": f"report-{report_type}-new",
                "type": report_type,
                "template_id": template_id or f"{report_type}-default",
                "format": format_type,
                "status": "generating",
                "created_at": "2024-12-30T12:00:00Z",
                "estimated_completion": "2024-12-30T12:05:00Z",
                "parameters": {
                    "date_range": date_range,
                },
                "message": f"Report generation started for {report_type}",
            }

            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to generate report")
            return HandlerResponse.server_error(str(e))

    @route("schedule", methods=["POST"])
    def report_schedule(self, params: dict, body: dict | None) -> HandlerResponse:
        """Schedule a recurring report."""
        try:
            body = body or {}
            report_type = body.get("type", "")
            schedule = body.get("schedule", "weekly")
            recipients = body.get("recipients", [])

            if not report_type:
                return HandlerResponse.error("type parameter required", HttpStatus.BAD_REQUEST)

            result = {
                "schedule_id": f"schedule-{report_type}-001",
                "type": report_type,
                "schedule": schedule,
                "recipients": recipients,
                "enabled": True,
                "next_run": "2025-01-06T10:00:00Z",
                "created_at": "2024-12-30T12:00:00Z",
                "message": f"Report scheduled: {schedule}",
            }

            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to schedule report")
            return HandlerResponse.server_error(str(e))

    @route("export", methods=["POST"])
    def report_export(self, params: dict, body: dict | None) -> HandlerResponse:
        """Export report data."""
        try:
            body = body or {}
            report_id = body.get("report_id", "")
            format_type = body.get("format", "pdf")

            if not report_id:
                return HandlerResponse.error("report_id required", HttpStatus.BAD_REQUEST)

            if format_type not in ["pdf", "xlsx", "csv", "json", "html", "pptx"]:
                return HandlerResponse.error(f"Invalid format: {format_type}", HttpStatus.BAD_REQUEST)

            result = {
                "export_id": f"export-{report_id}",
                "report_id": report_id,
                "format": format_type,
                "status": "generating",
                "download_url": f"/api/report/download/export-{report_id}.{format_type}",
                "expires_at": "2025-01-01T12:00:00Z",
            }

            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to export report")
            return HandlerResponse.server_error(str(e))

    @route("delete", methods=["POST"])
    def report_delete(self, params: dict, body: dict | None) -> HandlerResponse:
        """Delete a report."""
        try:
            body = body or {}
            report_id = body.get("report_id") or self.get_param(params, "report_id", "")

            if not report_id:
                return HandlerResponse.error("report_id required", HttpStatus.BAD_REQUEST)

            return HandlerResponse.success({
                "report_id": report_id,
                "deleted": True,
                "message": f"Report {report_id} has been deleted",
            })
        except Exception as e:
            logger.exception("Failed to delete report")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Report Statistics endpoints
    # =========================================================================

    @route("stats")
    def report_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show reporting module statistics."""
        try:
            result = {
                "total_reports": 125,
                "reports_this_month": 15,
                "scheduled_reports": 8,
                "by_type": {
                    "security_summary": 45,
                    "compliance": 30,
                    "trend": 25,
                    "executive": 15,
                    "findings": 10,
                },
                "by_format": {
                    "pdf": 80,
                    "xlsx": 25,
                    "csv": 10,
                    "json": 5,
                    "html": 3,
                    "pptx": 2,
                },
                "trend_directions": 4,
                "trend_periods": 4,
                "metrics_tracked": 10,
                "analysis_methods": ["velocity", "improvement_rate", "period_comparison", "forecast"],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get report stats")
            return HandlerResponse.server_error(str(e))

    @route("status")
    def report_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Show reporting module status."""
        try:
            result = {
                "module": "reporting",
                "status": "operational",
                "components": {
                    "TrendAnalyzer": "available",
                    "TrendReport": "available",
                    "TrendMetrics": "available",
                    "ReportGenerator": "available",
                    "ExportManager": "available",
                },
                "capabilities": [
                    "trend_analysis",
                    "velocity_calculation",
                    "improvement_rate",
                    "period_comparison",
                    "linear_regression_forecast",
                    "pdf_generation",
                    "excel_export",
                    "scheduled_reports",
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get report status")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def report_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive reporting module summary."""
        try:
            result = {
                "module": "reporting",
                "version": "1.0.0",
                "description": "Security posture trend analysis and reporting",
                "features": [
                    "Full trend analysis with configurable periods",
                    "Findings velocity calculation (rate of change)",
                    "Security improvement rate tracking",
                    "Period-over-period comparison",
                    "Linear regression forecasting",
                    "Multiple export formats (PDF, Excel, CSV, JSON)",
                    "Scheduled report generation",
                    "Automatic recommendation generation",
                ],
                "analysis_types": {
                    "analyze": "Comprehensive trend analysis with recommendations",
                    "velocity": "Rate of findings change per day",
                    "improvement": "Percentage improvement over time",
                    "compare": "Compare current vs previous period",
                    "forecast": "Project future findings using regression",
                },
                "data_requirements": {
                    "minimum_scans": 2,
                    "recommended_scans": 10,
                    "default_history_days": 30,
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get report summary")
            return HandlerResponse.server_error(str(e))
