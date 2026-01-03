"""
Trend Analysis for Mantissa Stance.

Provides comprehensive trend analysis capabilities for tracking security
posture changes over time, including findings trends, compliance trends,
and statistical metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable

from stance.scheduling.history import ScanHistoryEntry, ScanHistoryManager


class TrendDirection(Enum):
    """Direction of a trend."""

    IMPROVING = "improving"  # Getting better (fewer findings/higher compliance)
    DECLINING = "declining"  # Getting worse (more findings/lower compliance)
    STABLE = "stable"  # No significant change
    INSUFFICIENT_DATA = "insufficient_data"  # Not enough data points


class TrendPeriod(Enum):
    """Time periods for trend analysis."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


@dataclass
class TrendMetrics:
    """
    Statistical metrics for trend analysis.

    Attributes:
        current_value: Most recent value
        previous_value: Value from previous period
        average: Average value over the period
        min_value: Minimum value observed
        max_value: Maximum value observed
        change: Absolute change from previous
        change_percent: Percentage change from previous
        direction: Trend direction
        data_points: Number of data points analyzed
        velocity: Rate of change per day
    """

    current_value: float
    previous_value: float
    average: float
    min_value: float
    max_value: float
    change: float
    change_percent: float
    direction: TrendDirection
    data_points: int
    velocity: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "current_value": self.current_value,
            "previous_value": self.previous_value,
            "average": round(self.average, 2),
            "min_value": self.min_value,
            "max_value": self.max_value,
            "change": self.change,
            "change_percent": round(self.change_percent, 2),
            "direction": self.direction.value,
            "data_points": self.data_points,
            "velocity": round(self.velocity, 4),
        }


@dataclass
class SeverityTrend:
    """
    Trend data for a specific severity level.

    Attributes:
        severity: The severity level
        metrics: Trend metrics for this severity
        history: Historical data points
    """

    severity: str
    metrics: TrendMetrics
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "severity": self.severity,
            "metrics": self.metrics.to_dict(),
            "history": self.history,
        }


@dataclass
class ComplianceTrend:
    """
    Trend data for compliance scores.

    Attributes:
        framework: Compliance framework name
        metrics: Trend metrics for this framework
        current_score: Current compliance score (0-100)
        target_score: Target compliance score
        gap: Gap between current and target
        history: Historical score data
    """

    framework: str
    metrics: TrendMetrics
    current_score: float
    target_score: float = 100.0
    gap: float = 0.0
    history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        """Calculate gap after initialization."""
        self.gap = self.target_score - self.current_score

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework,
            "metrics": self.metrics.to_dict(),
            "current_score": round(self.current_score, 2),
            "target_score": self.target_score,
            "gap": round(self.gap, 2),
            "history": self.history,
        }


@dataclass
class TrendReport:
    """
    Complete trend analysis report.

    Attributes:
        report_id: Unique report identifier
        generated_at: When the report was generated
        period: Time period analyzed
        days_analyzed: Number of days in the analysis
        total_findings: Trend for total findings count
        severity_trends: Trends by severity level
        compliance_trends: Trends by compliance framework
        assets_trend: Trend for assets count
        scan_frequency: Average scans per day
        mean_time_to_remediate: Average time to resolve findings
        risk_score_trend: Overall risk score trend
        summary: Summary insights
        recommendations: Recommendations based on trends
    """

    report_id: str
    generated_at: datetime
    period: TrendPeriod
    days_analyzed: int
    total_findings: TrendMetrics
    severity_trends: dict[str, SeverityTrend] = field(default_factory=dict)
    compliance_trends: dict[str, ComplianceTrend] = field(default_factory=dict)
    assets_trend: TrendMetrics | None = None
    scan_frequency: float = 0.0
    mean_time_to_remediate: float | None = None
    risk_score_trend: TrendMetrics | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "period": self.period.value,
            "days_analyzed": self.days_analyzed,
            "total_findings": self.total_findings.to_dict(),
            "severity_trends": {
                k: v.to_dict() for k, v in self.severity_trends.items()
            },
            "compliance_trends": {
                k: v.to_dict() for k, v in self.compliance_trends.items()
            },
            "assets_trend": self.assets_trend.to_dict() if self.assets_trend else None,
            "scan_frequency": round(self.scan_frequency, 2),
            "mean_time_to_remediate": self.mean_time_to_remediate,
            "risk_score_trend": (
                self.risk_score_trend.to_dict() if self.risk_score_trend else None
            ),
            "summary": self.summary,
            "recommendations": self.recommendations,
        }

    @property
    def overall_direction(self) -> TrendDirection:
        """Get overall trend direction based on total findings."""
        return self.total_findings.direction

    @property
    def is_improving(self) -> bool:
        """Check if overall trend is improving."""
        return self.total_findings.direction == TrendDirection.IMPROVING

    @property
    def critical_severity_change(self) -> float:
        """Get change in critical findings."""
        if "critical" in self.severity_trends:
            return self.severity_trends["critical"].metrics.change
        return 0.0


class TrendAnalyzer:
    """
    Analyzes security posture trends over time.

    Provides comprehensive trend analysis including findings trends,
    severity breakdowns, compliance tracking, and recommendations.
    """

    # Thresholds for trend determination
    CHANGE_THRESHOLD_PERCENT = 5.0  # Minimum % change to be significant
    CRITICAL_VELOCITY_THRESHOLD = 0.5  # Critical findings per day threshold

    def __init__(
        self,
        history_manager: ScanHistoryManager | None = None,
        storage_path: str = "~/.stance/history",
    ):
        """
        Initialize the trend analyzer.

        Args:
            history_manager: Optional history manager instance
            storage_path: Path for history storage if no manager provided
        """
        self._history_manager = history_manager or ScanHistoryManager(storage_path)

    @property
    def history_manager(self) -> ScanHistoryManager:
        """Get the history manager."""
        return self._history_manager

    def analyze(
        self,
        config_name: str = "default",
        days: int = 30,
        period: TrendPeriod = TrendPeriod.DAILY,
        compliance_scores: dict[str, list[dict[str, Any]]] | None = None,
    ) -> TrendReport:
        """
        Perform trend analysis.

        Args:
            config_name: Configuration to analyze
            days: Number of days to include in analysis
            period: Time period granularity
            compliance_scores: Historical compliance scores by framework

        Returns:
            TrendReport with complete analysis
        """
        import uuid

        # Get historical data
        history = self._history_manager.get_history(config_name=config_name)
        since = datetime.utcnow() - timedelta(days=days)
        history = [e for e in history if e.timestamp >= since]

        # Generate report
        report = TrendReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.utcnow(),
            period=period,
            days_analyzed=days,
            total_findings=self._calculate_findings_trend(history),
            severity_trends=self._calculate_severity_trends(history),
            assets_trend=self._calculate_assets_trend(history),
            scan_frequency=self._calculate_scan_frequency(history, days),
        )

        # Add compliance trends if provided
        if compliance_scores:
            report.compliance_trends = self._calculate_compliance_trends(
                compliance_scores
            )

        # Generate summary and recommendations
        report.summary = self._generate_summary(report, history)
        report.recommendations = self._generate_recommendations(report)

        return report

    def analyze_from_entries(
        self,
        entries: list[ScanHistoryEntry],
        period: TrendPeriod = TrendPeriod.DAILY,
    ) -> TrendReport:
        """
        Perform trend analysis from a list of entries.

        Args:
            entries: List of scan history entries
            period: Time period granularity

        Returns:
            TrendReport with complete analysis
        """
        import uuid

        if not entries:
            return self._empty_report(period)

        # Sort entries chronologically
        entries = sorted(entries, key=lambda e: e.timestamp)

        # Calculate days spanned
        days = (entries[-1].timestamp - entries[0].timestamp).days + 1

        report = TrendReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.utcnow(),
            period=period,
            days_analyzed=days,
            total_findings=self._calculate_findings_trend(entries),
            severity_trends=self._calculate_severity_trends(entries),
            assets_trend=self._calculate_assets_trend(entries),
            scan_frequency=self._calculate_scan_frequency(entries, days),
        )

        report.summary = self._generate_summary(report, entries)
        report.recommendations = self._generate_recommendations(report)

        return report

    def get_findings_velocity(
        self,
        config_name: str = "default",
        days: int = 7,
    ) -> dict[str, float]:
        """
        Calculate the velocity of findings changes.

        Velocity is the rate of change per day.

        Args:
            config_name: Configuration to analyze
            days: Number of days to analyze

        Returns:
            Dictionary with velocity for total and each severity
        """
        history = self._get_recent_history(config_name, days)
        if len(history) < 2:
            return {"total": 0.0}

        # Sort chronologically
        history = sorted(history, key=lambda e: e.timestamp)

        # Calculate time span
        time_span = (history[-1].timestamp - history[0].timestamp).total_seconds()
        days_span = time_span / 86400 if time_span > 0 else 1

        # Calculate velocities
        velocities = {
            "total": (history[-1].findings_total - history[0].findings_total) / days_span
        }

        severities = ["critical", "high", "medium", "low", "info"]
        for sev in severities:
            start = history[0].findings_by_severity.get(sev, 0)
            end = history[-1].findings_by_severity.get(sev, 0)
            velocities[sev] = (end - start) / days_span

        return velocities

    def get_improvement_rate(
        self,
        config_name: str = "default",
        days: int = 30,
    ) -> float:
        """
        Calculate the improvement rate.

        Positive values indicate improvement (decreasing findings).
        Negative values indicate regression (increasing findings).

        Args:
            config_name: Configuration to analyze
            days: Number of days to analyze

        Returns:
            Improvement rate as a percentage
        """
        history = self._get_recent_history(config_name, days)
        if len(history) < 2:
            return 0.0

        history = sorted(history, key=lambda e: e.timestamp)

        start = history[0].findings_total
        end = history[-1].findings_total

        if start == 0:
            return -100.0 if end > 0 else 0.0

        # Negative change (fewer findings) = positive improvement
        return ((start - end) / start) * 100

    def compare_periods(
        self,
        config_name: str = "default",
        current_days: int = 7,
        previous_days: int = 7,
    ) -> dict[str, Any]:
        """
        Compare two time periods.

        Args:
            config_name: Configuration to analyze
            current_days: Days in current period
            previous_days: Days in previous period

        Returns:
            Comparison of the two periods
        """
        now = datetime.utcnow()
        current_start = now - timedelta(days=current_days)
        previous_end = current_start
        previous_start = previous_end - timedelta(days=previous_days)

        history = self._history_manager.get_history(config_name=config_name)

        current = [e for e in history if e.timestamp >= current_start]
        previous = [
            e for e in history
            if previous_start <= e.timestamp < previous_end
        ]

        def period_stats(entries: list[ScanHistoryEntry]) -> dict[str, Any]:
            if not entries:
                return {
                    "scans": 0,
                    "avg_findings": 0,
                    "max_findings": 0,
                    "min_findings": 0,
                    "severity_breakdown": {},
                }

            findings = [e.findings_total for e in entries]
            return {
                "scans": len(entries),
                "avg_findings": sum(findings) / len(findings),
                "max_findings": max(findings),
                "min_findings": min(findings),
                "severity_breakdown": self._aggregate_severity(entries),
            }

        current_stats = period_stats(current)
        previous_stats = period_stats(previous)

        # Calculate changes
        avg_change = 0.0
        if previous_stats["avg_findings"] > 0:
            avg_change = (
                (current_stats["avg_findings"] - previous_stats["avg_findings"])
                / previous_stats["avg_findings"]
            ) * 100

        return {
            "current_period": {
                "start": current_start.isoformat(),
                "end": now.isoformat(),
                "days": current_days,
                "stats": current_stats,
            },
            "previous_period": {
                "start": previous_start.isoformat(),
                "end": previous_end.isoformat(),
                "days": previous_days,
                "stats": previous_stats,
            },
            "comparison": {
                "avg_findings_change": round(avg_change, 2),
                "scan_count_change": current_stats["scans"] - previous_stats["scans"],
                "direction": self._determine_direction(
                    previous_stats["avg_findings"],
                    current_stats["avg_findings"],
                ),
            },
        }

    def forecast(
        self,
        config_name: str = "default",
        days_history: int = 30,
        days_forecast: int = 7,
    ) -> dict[str, Any]:
        """
        Forecast future findings based on historical trend.

        Uses linear regression on historical data to project future values.

        Args:
            config_name: Configuration to analyze
            days_history: Days of history to use for forecast
            days_forecast: Days to forecast ahead

        Returns:
            Forecast data including projected values
        """
        history = self._get_recent_history(config_name, days_history)
        if len(history) < 2:
            return {
                "error": "Insufficient data for forecasting",
                "minimum_required": 2,
                "available": len(history),
            }

        history = sorted(history, key=lambda e: e.timestamp)

        # Simple linear regression
        x_values = [
            (e.timestamp - history[0].timestamp).total_seconds() / 86400
            for e in history
        ]
        y_values = [e.findings_total for e in history]

        slope, intercept = self._linear_regression(x_values, y_values)

        # Calculate current position and forecast
        current_x = x_values[-1]
        forecasts = []

        for day in range(1, days_forecast + 1):
            forecast_x = current_x + day
            forecast_y = max(0, slope * forecast_x + intercept)  # Can't be negative
            forecast_date = history[-1].timestamp + timedelta(days=day)
            forecasts.append({
                "date": forecast_date.isoformat(),
                "day": day,
                "projected_findings": round(forecast_y),
            })

        return {
            "model": "linear_regression",
            "data_points": len(history),
            "trend_slope": round(slope, 4),
            "confidence": self._calculate_confidence(x_values, y_values, slope, intercept),
            "current_findings": history[-1].findings_total,
            "forecasts": forecasts,
            "trend_direction": (
                TrendDirection.DECLINING.value if slope > 0
                else TrendDirection.IMPROVING.value if slope < 0
                else TrendDirection.STABLE.value
            ),
        }

    def _get_recent_history(
        self,
        config_name: str,
        days: int,
    ) -> list[ScanHistoryEntry]:
        """Get history entries for recent days."""
        since = datetime.utcnow() - timedelta(days=days)
        history = self._history_manager.get_history(config_name=config_name)
        return [e for e in history if e.timestamp >= since]

    def _calculate_findings_trend(
        self,
        entries: list[ScanHistoryEntry],
    ) -> TrendMetrics:
        """Calculate trend metrics for total findings."""
        if not entries:
            return self._empty_metrics()

        entries = sorted(entries, key=lambda e: e.timestamp)
        values = [e.findings_total for e in entries]

        return self._compute_metrics(values, entries)

    def _calculate_severity_trends(
        self,
        entries: list[ScanHistoryEntry],
    ) -> dict[str, SeverityTrend]:
        """Calculate trends for each severity level."""
        if not entries:
            return {}

        entries = sorted(entries, key=lambda e: e.timestamp)
        severities = ["critical", "high", "medium", "low", "info"]
        trends = {}

        for sev in severities:
            values = [e.findings_by_severity.get(sev, 0) for e in entries]
            metrics = self._compute_metrics(values, entries)
            history = [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "value": e.findings_by_severity.get(sev, 0),
                }
                for e in entries
            ]
            trends[sev] = SeverityTrend(
                severity=sev,
                metrics=metrics,
                history=history,
            )

        return trends

    def _calculate_assets_trend(
        self,
        entries: list[ScanHistoryEntry],
    ) -> TrendMetrics | None:
        """Calculate trend for assets count."""
        if not entries:
            return None

        entries = sorted(entries, key=lambda e: e.timestamp)
        values = [e.assets_scanned for e in entries]

        if all(v == 0 for v in values):
            return None

        return self._compute_metrics(values, entries)

    def _calculate_compliance_trends(
        self,
        compliance_data: dict[str, list[dict[str, Any]]],
    ) -> dict[str, ComplianceTrend]:
        """Calculate compliance trends from historical data."""
        trends = {}

        for framework, history in compliance_data.items():
            if not history:
                continue

            # Sort by timestamp
            history = sorted(history, key=lambda x: x.get("timestamp", ""))
            values = [h.get("score", 0) for h in history]

            if not values:
                continue

            # Create dummy entries for metrics calculation
            metrics = self._compute_metrics_from_values(values)

            trends[framework] = ComplianceTrend(
                framework=framework,
                metrics=metrics,
                current_score=values[-1] if values else 0.0,
                history=history,
            )

        return trends

    def _calculate_scan_frequency(
        self,
        entries: list[ScanHistoryEntry],
        days: int,
    ) -> float:
        """Calculate average scans per day."""
        if days <= 0:
            return 0.0
        return len(entries) / days

    def _compute_metrics(
        self,
        values: list[float],
        entries: list[ScanHistoryEntry],
    ) -> TrendMetrics:
        """Compute trend metrics from values."""
        if not values:
            return self._empty_metrics()

        current = values[-1]
        previous = values[-2] if len(values) > 1 else current

        change = current - previous
        change_percent = (change / previous * 100) if previous != 0 else 0

        # Calculate velocity (change per day)
        velocity = 0.0
        if len(entries) >= 2:
            time_span = (
                entries[-1].timestamp - entries[0].timestamp
            ).total_seconds()
            days_span = time_span / 86400 if time_span > 0 else 1
            velocity = (values[-1] - values[0]) / days_span

        return TrendMetrics(
            current_value=current,
            previous_value=previous,
            average=sum(values) / len(values),
            min_value=min(values),
            max_value=max(values),
            change=change,
            change_percent=change_percent,
            direction=self._determine_direction(previous, current),
            data_points=len(values),
            velocity=velocity,
        )

    def _compute_metrics_from_values(self, values: list[float]) -> TrendMetrics:
        """Compute trend metrics from values only (no entries)."""
        if not values:
            return self._empty_metrics()

        current = values[-1]
        previous = values[-2] if len(values) > 1 else current

        change = current - previous
        change_percent = (change / previous * 100) if previous != 0 else 0

        return TrendMetrics(
            current_value=current,
            previous_value=previous,
            average=sum(values) / len(values),
            min_value=min(values),
            max_value=max(values),
            change=change,
            change_percent=change_percent,
            direction=self._determine_direction_compliance(previous, current),
            data_points=len(values),
            velocity=0.0,
        )

    def _determine_direction(
        self,
        previous: float,
        current: float,
    ) -> TrendDirection:
        """
        Determine trend direction for findings.

        For findings, fewer is better (improving).
        """
        if previous == 0 and current == 0:
            return TrendDirection.STABLE

        if previous == 0:
            return TrendDirection.DECLINING  # Any increase from 0 is decline

        change_percent = ((current - previous) / previous) * 100

        if abs(change_percent) < self.CHANGE_THRESHOLD_PERCENT:
            return TrendDirection.STABLE
        elif change_percent < 0:
            return TrendDirection.IMPROVING  # Fewer findings = improving
        else:
            return TrendDirection.DECLINING  # More findings = declining

    def _determine_direction_compliance(
        self,
        previous: float,
        current: float,
    ) -> TrendDirection:
        """
        Determine trend direction for compliance.

        For compliance, higher is better (improving).
        """
        if previous == 0 and current == 0:
            return TrendDirection.STABLE

        if previous == 0:
            return TrendDirection.IMPROVING if current > 0 else TrendDirection.STABLE

        change_percent = ((current - previous) / previous) * 100

        if abs(change_percent) < self.CHANGE_THRESHOLD_PERCENT:
            return TrendDirection.STABLE
        elif change_percent > 0:
            return TrendDirection.IMPROVING  # Higher compliance = improving
        else:
            return TrendDirection.DECLINING  # Lower compliance = declining

    def _aggregate_severity(
        self,
        entries: list[ScanHistoryEntry],
    ) -> dict[str, float]:
        """Aggregate severity counts across entries."""
        if not entries:
            return {}

        totals: dict[str, float] = {}
        for entry in entries:
            for sev, count in entry.findings_by_severity.items():
                totals[sev] = totals.get(sev, 0) + count

        # Return averages
        return {sev: total / len(entries) for sev, total in totals.items()}

    def _generate_summary(
        self,
        report: TrendReport,
        entries: list[ScanHistoryEntry],
    ) -> dict[str, Any]:
        """Generate summary insights."""
        summary = {
            "overall_direction": report.total_findings.direction.value,
            "total_scans": len(entries),
            "findings_change": report.total_findings.change,
            "findings_change_percent": round(report.total_findings.change_percent, 2),
        }

        # Identify most concerning trend
        if "critical" in report.severity_trends:
            critical = report.severity_trends["critical"]
            if critical.metrics.direction == TrendDirection.DECLINING:
                summary["alert"] = "Critical findings are increasing"
                summary["critical_velocity"] = critical.metrics.velocity

        # Calculate remediation velocity if possible
        if entries and len(entries) >= 2:
            resolved = sum(
                1 for e in entries
                if e.findings_total < entries[0].findings_total
            )
            summary["improving_scans"] = resolved
            summary["improving_scan_rate"] = resolved / len(entries) * 100

        return summary

    def _generate_recommendations(self, report: TrendReport) -> list[str]:
        """Generate recommendations based on trends."""
        recommendations = []

        # Check critical trend
        if "critical" in report.severity_trends:
            critical = report.severity_trends["critical"]
            if critical.metrics.direction == TrendDirection.DECLINING:
                recommendations.append(
                    "Critical findings are increasing. Prioritize immediate remediation "
                    "of critical issues to prevent security incidents."
                )
            elif critical.metrics.current_value > 0:
                recommendations.append(
                    f"There are {int(critical.metrics.current_value)} critical findings. "
                    "Consider a focused remediation sprint to address these first."
                )

        # Check overall trend
        if report.total_findings.direction == TrendDirection.DECLINING:
            velocity = abs(report.total_findings.velocity)
            recommendations.append(
                f"Security posture is declining at {velocity:.1f} findings/day. "
                "Review recent changes and increase security scanning frequency."
            )
        elif report.total_findings.direction == TrendDirection.STABLE:
            if report.total_findings.current_value > 50:
                recommendations.append(
                    "Finding count is stable but high. Consider implementing "
                    "automated remediation for common issues."
                )

        # Check scan frequency
        if report.scan_frequency < 0.5:
            recommendations.append(
                "Scanning frequency is low. Consider implementing scheduled daily scans "
                "for continuous monitoring."
            )

        # Check for high findings
        if "high" in report.severity_trends:
            high = report.severity_trends["high"]
            if high.metrics.current_value > 10:
                recommendations.append(
                    f"There are {int(high.metrics.current_value)} high-severity findings. "
                    "Establish a remediation plan with assigned owners and deadlines."
                )

        # Provide positive feedback if improving
        if report.total_findings.direction == TrendDirection.IMPROVING:
            recommendations.append(
                "Security posture is improving. Continue current practices and consider "
                "expanding security coverage to additional resources."
            )

        return recommendations

    def _empty_metrics(self) -> TrendMetrics:
        """Create empty metrics for no data."""
        return TrendMetrics(
            current_value=0,
            previous_value=0,
            average=0,
            min_value=0,
            max_value=0,
            change=0,
            change_percent=0,
            direction=TrendDirection.INSUFFICIENT_DATA,
            data_points=0,
            velocity=0,
        )

    def _empty_report(self, period: TrendPeriod) -> TrendReport:
        """Create empty report for no data."""
        import uuid

        return TrendReport(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.utcnow(),
            period=period,
            days_analyzed=0,
            total_findings=self._empty_metrics(),
            summary={"error": "No data available for analysis"},
            recommendations=["Begin regular security scanning to collect trend data."],
        )

    def _linear_regression(
        self,
        x: list[float],
        y: list[float],
    ) -> tuple[float, float]:
        """Perform simple linear regression."""
        n = len(x)
        if n < 2:
            return 0.0, y[0] if y else 0.0

        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_xx = sum(xi * xi for xi in x)

        denominator = n * sum_xx - sum_x * sum_x
        if denominator == 0:
            return 0.0, sum_y / n

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        intercept = (sum_y - slope * sum_x) / n

        return slope, intercept

    def _calculate_confidence(
        self,
        x: list[float],
        y: list[float],
        slope: float,
        intercept: float,
    ) -> float:
        """Calculate R-squared confidence score."""
        if len(y) < 2:
            return 0.0

        y_mean = sum(y) / len(y)
        ss_tot = sum((yi - y_mean) ** 2 for yi in y)

        if ss_tot == 0:
            return 1.0  # All values are the same

        ss_res = sum((yi - (slope * xi + intercept)) ** 2 for xi, yi in zip(x, y))
        r_squared = 1 - (ss_res / ss_tot)

        return max(0, min(1, r_squared))  # Clamp to [0, 1]
