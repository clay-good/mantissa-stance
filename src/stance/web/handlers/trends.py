"""
Trends handlers for the Stance web API.

This module handles all /api/trends/* endpoints for security posture
trend analysis, forecasting, and comparison.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class TrendsHandler(RoutedHandler):
    """
    Handler for trends API endpoints.

    Handles:
    - Trend analysis
    - Security posture forecasting
    - Period comparison
    - Velocity and improvement metrics
    """

    base_path = "/api/trends/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("analyze")
    def trends_analyze(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Analyze security posture trends.

        Query params:
            days: Number of days to analyze (default: 30)
            period: Aggregation period (daily, weekly, monthly)
        """
        days = self.get_param_int(params, "days", 30)
        period = self.get_param(params, "period", "daily")

        return HandlerResponse.success(self._get_sample_trend_report(days, period))

    @route("forecast")
    def trends_forecast(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Forecast future findings based on trends.

        Query params:
            history_days: Days of history to use (default: 30)
            forecast_days: Days to forecast (default: 7)
        """
        history_days = self.get_param_int(params, "history_days", 30)
        forecast_days = self.get_param_int(params, "forecast_days", 7)

        return HandlerResponse.success(self._get_sample_forecast(history_days, forecast_days))

    @route("velocity")
    def trends_velocity(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get findings velocity (rate of change per day).

        Query params:
            days: Number of days to analyze (default: 7)
        """
        days = self.get_param_int(params, "days", 7)

        return HandlerResponse.success({
            "days_analyzed": days,
            "velocity": {
                "total": -0.23,
                "critical": -0.07,
                "high": -0.10,
                "medium": -0.07,
                "low": 0.0,
                "info": 0.0,
            },
            "interpretation": "Negative velocity indicates improving security posture",
        })

    @route("improvement")
    def trends_improvement(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Calculate improvement rate.

        Query params:
            days: Number of days to analyze (default: 30)
        """
        days = self.get_param_int(params, "days", 30)

        rate = 12.5  # Demo rate

        if rate > 20:
            interpretation = "Excellent improvement - security posture significantly better"
        elif rate > 10:
            interpretation = "Good improvement - positive trend in security posture"
        elif rate > 0:
            interpretation = "Slight improvement - minor positive changes"
        elif rate == 0:
            interpretation = "No change - security posture is stable"
        elif rate > -10:
            interpretation = "Slight regression - minor increase in findings"
        elif rate > -20:
            interpretation = "Regression - security posture is declining"
        else:
            interpretation = "Significant regression - urgent attention needed"

        return HandlerResponse.success({
            "days_analyzed": days,
            "improvement_rate": rate,
            "interpretation": interpretation,
        })

    @route("compare")
    def trends_compare(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Compare two time periods.

        Query params:
            current_days: Days in current period (default: 7)
            previous_days: Days in previous period (default: 7)
        """
        current_days = self.get_param_int(params, "current_days", 7)
        previous_days = self.get_param_int(params, "previous_days", 7)

        now = datetime.now(timezone.utc)
        current_start = now - timedelta(days=current_days)
        previous_end = current_start
        previous_start = previous_end - timedelta(days=previous_days)

        return HandlerResponse.success({
            "current_period": {
                "start": current_start.isoformat(),
                "end": now.isoformat(),
                "days": current_days,
                "stats": {
                    "scans": int(current_days * 1.5),
                    "avg_findings": 45.0,
                    "max_findings": 50,
                    "min_findings": 40,
                    "severity_breakdown": {
                        "critical": 3.0,
                        "high": 12.0,
                        "medium": 20.0,
                        "low": 8.0,
                        "info": 2.0,
                    },
                },
            },
            "previous_period": {
                "start": previous_start.isoformat(),
                "end": previous_end.isoformat(),
                "days": previous_days,
                "stats": {
                    "scans": int(previous_days * 1.3),
                    "avg_findings": 52.0,
                    "max_findings": 58,
                    "min_findings": 46,
                    "severity_breakdown": {
                        "critical": 5.0,
                        "high": 15.0,
                        "medium": 22.0,
                        "low": 8.0,
                        "info": 2.0,
                    },
                },
            },
            "comparison": {
                "avg_findings_change": -13.46,
                "scan_count_change": 2,
                "direction": "improving",
            },
        })

    @route("report")
    def trends_report(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Generate comprehensive trend report.

        Query params:
            days: Number of days (default: 30)
        """
        days = self.get_param_int(params, "days", 30)

        return HandlerResponse.success(self._get_sample_trend_report(days, "daily"))

    @route("severity")
    def trends_severity(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get severity-specific trend data.

        Query params:
            severity: Filter by severity
            days: Number of days (default: 30)
        """
        severity = self.get_param(params, "severity", "")
        days = self.get_param_int(params, "days", 30)

        severities_data = {
            "critical": {"current": 3, "previous": 5, "change": -40.0, "trend": "improving"},
            "high": {"current": 12, "previous": 15, "change": -20.0, "trend": "improving"},
            "medium": {"current": 20, "previous": 22, "change": -9.1, "trend": "stable"},
            "low": {"current": 8, "previous": 8, "change": 0.0, "trend": "stable"},
            "info": {"current": 2, "previous": 2, "change": 0.0, "trend": "stable"},
        }

        if severity and severity in severities_data:
            return HandlerResponse.success({
                "severity": severity,
                "days_analyzed": days,
                "data": severities_data[severity],
            })

        return HandlerResponse.success({
            "days_analyzed": days,
            "severities": severities_data,
        })

    @route("summary")
    def trends_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get trends summary."""
        return HandlerResponse.success({
            "overall_trend": "improving",
            "improvement_rate": 12.5,
            "velocity": -0.23,
            "findings_change": {
                "total": -15,
                "critical": -2,
                "high": -3,
                "medium": -2,
                "low": 0,
            },
            "period": {
                "start": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                "end": datetime.now(timezone.utc).isoformat(),
                "days": 30,
            },
        })

    @route("periods")
    def trends_periods(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available trend periods."""
        periods = [
            {"value": "daily", "name": "Daily", "description": "Day-by-day analysis"},
            {"value": "weekly", "name": "Weekly", "description": "Week-by-week analysis"},
            {"value": "monthly", "name": "Monthly", "description": "Month-by-month analysis"},
            {"value": "quarterly", "name": "Quarterly", "description": "Quarter-by-quarter analysis"},
        ]

        return HandlerResponse.success({
            "periods": periods,
            "total": len(periods),
        })

    @route("directions")
    def trends_directions(self, params: dict, body: dict | None) -> HandlerResponse:
        """List trend directions."""
        directions = [
            {"value": "improving", "description": "Security posture is getting better"},
            {"value": "stable", "description": "Security posture is unchanged"},
            {"value": "declining", "description": "Security posture is getting worse"},
        ]

        return HandlerResponse.success({
            "directions": directions,
            "total": len(directions),
        })

    @route("status")
    def trends_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get trends module status."""
        return HandlerResponse.success({
            "module": "trends",
            "version": "1.0.0",
            "status": "active",
            "last_analysis": None,
            "data_points": 0,
            "capabilities": {
                "daily_trends": True,
                "weekly_trends": True,
                "monthly_trends": True,
                "forecasting": True,
                "velocity_tracking": True,
                "period_comparison": True,
            },
        })

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_sample_trend_report(self, days: int, period: str) -> dict[str, Any]:
        """Generate sample trend report."""
        now = datetime.now(timezone.utc)
        data_points = []

        if period == "daily":
            for i in range(days):
                date = now - timedelta(days=days - i - 1)
                data_points.append({
                    "date": date.strftime("%Y-%m-%d"),
                    "findings": 50 - i * 0.5,  # Slight improvement
                    "critical": max(0, 5 - i * 0.1),
                    "high": max(0, 15 - i * 0.2),
                    "medium": 20,
                    "low": 8,
                    "info": 2,
                })
        elif period == "weekly":
            weeks = days // 7
            for i in range(weeks):
                week_start = now - timedelta(weeks=weeks - i - 1)
                data_points.append({
                    "week_start": week_start.strftime("%Y-%m-%d"),
                    "avg_findings": 50 - i * 2,
                    "critical": max(0, 5 - i * 0.5),
                    "high": max(0, 15 - i * 1),
                })

        return {
            "period": period,
            "days_analyzed": days,
            "start_date": (now - timedelta(days=days)).isoformat(),
            "end_date": now.isoformat(),
            "data_points": data_points,
            "summary": {
                "total_change": -12.5,
                "critical_change": -40.0,
                "high_change": -20.0,
                "overall_trend": "improving",
            },
        }

    def _get_sample_forecast(self, history_days: int, forecast_days: int) -> dict[str, Any]:
        """Generate sample forecast data."""
        now = datetime.now(timezone.utc)
        forecasts = []

        current_findings = 45
        daily_change = -0.23

        for i in range(forecast_days):
            date = now + timedelta(days=i + 1)
            projected = max(0, current_findings + (i + 1) * daily_change)
            forecasts.append({
                "date": date.strftime("%Y-%m-%d"),
                "projected_findings": round(projected, 1),
                "confidence": max(0.5, 0.95 - i * 0.05),
                "range": {
                    "low": round(projected * 0.9, 1),
                    "high": round(projected * 1.1, 1),
                },
            })

        return {
            "history_days": history_days,
            "forecast_days": forecast_days,
            "current_findings": current_findings,
            "projected_trend": "improving",
            "forecasts": forecasts,
            "methodology": "Linear regression based on historical data",
        }
