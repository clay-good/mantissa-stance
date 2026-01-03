"""
Data Aggregation API for Mantissa Stance Dashboard.

Provides aggregated data from the scheduling, scanning, and reporting
modules for use in the dashboard and API consumers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from stance.scheduling import (
    ScanScheduler,
    ScanHistoryManager,
    ScanJob,
)
from stance.scanning import MultiAccountScanner, OrganizationScan
from stance.reporting import TrendAnalyzer, TrendReport, TrendDirection


@dataclass
class SchedulerStatus:
    """
    Aggregated scheduler status.

    Attributes:
        is_running: Whether scheduler is running
        total_jobs: Total number of jobs
        enabled_jobs: Number of enabled jobs
        pending_jobs: Jobs pending execution
        last_run: Most recent run time
        next_run: Next scheduled run time
        jobs: List of job details
    """

    is_running: bool = False
    total_jobs: int = 0
    enabled_jobs: int = 0
    pending_jobs: int = 0
    last_run: datetime | None = None
    next_run: datetime | None = None
    jobs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_running": self.is_running,
            "total_jobs": self.total_jobs,
            "enabled_jobs": self.enabled_jobs,
            "pending_jobs": self.pending_jobs,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "jobs": self.jobs,
        }


@dataclass
class ScanHistorySummary:
    """
    Aggregated scan history summary.

    Attributes:
        total_scans: Total number of scans
        scans_last_24h: Scans in last 24 hours
        scans_last_7d: Scans in last 7 days
        average_duration: Average scan duration in seconds
        average_findings: Average findings per scan
        latest_scan: Most recent scan details
        history: List of recent scan entries
    """

    total_scans: int = 0
    scans_last_24h: int = 0
    scans_last_7d: int = 0
    average_duration: float = 0.0
    average_findings: float = 0.0
    latest_scan: dict[str, Any] | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_scans": self.total_scans,
            "scans_last_24h": self.scans_last_24h,
            "scans_last_7d": self.scans_last_7d,
            "average_duration": round(self.average_duration, 2),
            "average_findings": round(self.average_findings, 2),
            "latest_scan": self.latest_scan,
            "history": self.history,
        }


@dataclass
class TrendSummary:
    """
    Aggregated trend summary.

    Attributes:
        direction: Overall trend direction
        findings_change: Change in findings count
        findings_change_percent: Percentage change
        period_days: Days analyzed
        is_improving: Whether posture is improving
        severity_trends: Trend by severity
        recommendations: Trend-based recommendations
    """

    direction: str = "stable"
    findings_change: int = 0
    findings_change_percent: float = 0.0
    period_days: int = 7
    is_improving: bool = False
    severity_trends: dict[str, dict[str, Any]] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "direction": self.direction,
            "findings_change": self.findings_change,
            "findings_change_percent": round(self.findings_change_percent, 2),
            "period_days": self.period_days,
            "is_improving": self.is_improving,
            "severity_trends": self.severity_trends,
            "recommendations": self.recommendations,
        }


@dataclass
class MultiAccountSummary:
    """
    Aggregated multi-account summary.

    Attributes:
        total_accounts: Total configured accounts
        accounts_by_provider: Count per cloud provider
        last_org_scan: Most recent organization scan
        accounts_with_findings: Number of accounts with findings
        total_findings: Total findings across accounts
    """

    total_accounts: int = 0
    accounts_by_provider: dict[str, int] = field(default_factory=dict)
    last_org_scan: dict[str, Any] | None = None
    accounts_with_findings: int = 0
    total_findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_accounts": self.total_accounts,
            "accounts_by_provider": self.accounts_by_provider,
            "last_org_scan": self.last_org_scan,
            "accounts_with_findings": self.accounts_with_findings,
            "total_findings": self.total_findings,
        }


@dataclass
class DashboardAggregation:
    """
    Complete dashboard data aggregation.

    Combines data from scheduler, history, trends, and multi-account
    modules into a single response for dashboard consumption.
    """

    generated_at: datetime = field(default_factory=datetime.utcnow)
    scheduler: SchedulerStatus = field(default_factory=SchedulerStatus)
    history: ScanHistorySummary = field(default_factory=ScanHistorySummary)
    trends: TrendSummary = field(default_factory=TrendSummary)
    multi_account: MultiAccountSummary = field(default_factory=MultiAccountSummary)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "scheduler": self.scheduler.to_dict(),
            "history": self.history.to_dict(),
            "trends": self.trends.to_dict(),
            "multi_account": self.multi_account.to_dict(),
        }


class DashboardAggregator:
    """
    Aggregates data from multiple modules for dashboard display.

    Provides a unified interface for gathering data from the scheduler,
    history, trends, and multi-account modules.
    """

    def __init__(
        self,
        scheduler: ScanScheduler | None = None,
        history_manager: ScanHistoryManager | None = None,
        trend_analyzer: TrendAnalyzer | None = None,
        multi_account_scanner: MultiAccountScanner | None = None,
    ):
        """
        Initialize the aggregator.

        Args:
            scheduler: Optional ScanScheduler instance
            history_manager: Optional ScanHistoryManager instance
            trend_analyzer: Optional TrendAnalyzer instance
            multi_account_scanner: Optional MultiAccountScanner instance
        """
        self._scheduler = scheduler
        self._history_manager = history_manager
        self._trend_analyzer = trend_analyzer
        self._multi_account_scanner = multi_account_scanner

    def set_scheduler(self, scheduler: ScanScheduler) -> None:
        """Set the scheduler instance."""
        self._scheduler = scheduler

    def set_history_manager(self, manager: ScanHistoryManager) -> None:
        """Set the history manager instance."""
        self._history_manager = manager

    def set_trend_analyzer(self, analyzer: TrendAnalyzer) -> None:
        """Set the trend analyzer instance."""
        self._trend_analyzer = analyzer

    def set_multi_account_scanner(self, scanner: MultiAccountScanner) -> None:
        """Set the multi-account scanner instance."""
        self._multi_account_scanner = scanner

    def get_aggregation(
        self,
        config_name: str = "default",
        trend_days: int = 7,
        history_limit: int = 10,
    ) -> DashboardAggregation:
        """
        Get complete dashboard aggregation.

        Args:
            config_name: Configuration name for filtering
            trend_days: Days for trend analysis
            history_limit: Maximum history entries

        Returns:
            DashboardAggregation with all data
        """
        return DashboardAggregation(
            generated_at=datetime.utcnow(),
            scheduler=self.get_scheduler_status(),
            history=self.get_history_summary(config_name, history_limit),
            trends=self.get_trend_summary(config_name, trend_days),
            multi_account=self.get_multi_account_summary(),
        )

    def get_scheduler_status(self) -> SchedulerStatus:
        """Get scheduler status."""
        if not self._scheduler:
            return SchedulerStatus()

        status = self._scheduler.get_status()
        jobs = self._scheduler.get_jobs()
        enabled_jobs = self._scheduler.get_enabled_jobs()
        pending_jobs = self._scheduler.get_pending_jobs()

        # Find last and next run times
        last_run = None
        next_run = None
        for job in jobs:
            if job.last_run:
                if last_run is None or job.last_run > last_run:
                    last_run = job.last_run
            if job.next_run and job.enabled:
                if next_run is None or job.next_run < next_run:
                    next_run = job.next_run

        job_details = [
            {
                "id": job.id,
                "name": job.name,
                "schedule": str(job.schedule),
                "enabled": job.enabled,
                "last_run": job.last_run.isoformat() if job.last_run else None,
                "next_run": job.next_run.isoformat() if job.next_run else None,
                "run_count": job.run_count,
            }
            for job in jobs
        ]

        return SchedulerStatus(
            is_running=status.get("running", False),
            total_jobs=len(jobs),
            enabled_jobs=len(enabled_jobs),
            pending_jobs=len(pending_jobs),
            last_run=last_run,
            next_run=next_run,
            jobs=job_details,
        )

    def get_history_summary(
        self,
        config_name: str = "default",
        limit: int = 10,
    ) -> ScanHistorySummary:
        """Get scan history summary."""
        if not self._history_manager:
            return ScanHistorySummary()

        history = self._history_manager.get_history(
            config_name=config_name,
            limit=limit,
        )

        if not history:
            return ScanHistorySummary()

        # Calculate metrics
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)
        last_7d = now - timedelta(days=7)

        scans_24h = sum(1 for h in history if h.timestamp >= last_24h)
        scans_7d = sum(1 for h in history if h.timestamp >= last_7d)

        durations = [h.duration_seconds for h in history if h.duration_seconds > 0]
        findings_counts = [h.findings_total for h in history]

        avg_duration = sum(durations) / len(durations) if durations else 0
        avg_findings = sum(findings_counts) / len(findings_counts) if findings_counts else 0

        # Latest scan
        latest = history[0] if history else None
        latest_scan = None
        if latest:
            latest_scan = {
                "scan_id": latest.scan_id,
                "timestamp": latest.timestamp.isoformat(),
                "duration_seconds": latest.duration_seconds,
                "assets_scanned": latest.assets_scanned,
                "findings_total": latest.findings_total,
                "findings_by_severity": latest.findings_by_severity,
            }

        # Build history list
        history_list = [
            {
                "scan_id": h.scan_id,
                "timestamp": h.timestamp.isoformat(),
                "findings_total": h.findings_total,
                "findings_by_severity": h.findings_by_severity,
            }
            for h in history[:limit]
        ]

        return ScanHistorySummary(
            total_scans=len(history),
            scans_last_24h=scans_24h,
            scans_last_7d=scans_7d,
            average_duration=avg_duration,
            average_findings=avg_findings,
            latest_scan=latest_scan,
            history=history_list,
        )

    def get_trend_summary(
        self,
        config_name: str = "default",
        days: int = 7,
    ) -> TrendSummary:
        """Get trend summary."""
        if not self._trend_analyzer:
            return TrendSummary()

        try:
            report = self._trend_analyzer.analyze(
                config_name=config_name,
                days=days,
            )

            severity_trends = {}
            for sev, trend in report.severity_trends.items():
                severity_trends[sev] = {
                    "current": trend.metrics.current_value,
                    "previous": trend.metrics.previous_value,
                    "change": trend.metrics.change,
                    "direction": trend.metrics.direction.value,
                }

            return TrendSummary(
                direction=report.total_findings.direction.value,
                findings_change=int(report.total_findings.change),
                findings_change_percent=report.total_findings.change_percent,
                period_days=days,
                is_improving=report.is_improving,
                severity_trends=severity_trends,
                recommendations=report.recommendations,
            )
        except Exception:
            return TrendSummary(period_days=days)

    def get_multi_account_summary(self) -> MultiAccountSummary:
        """Get multi-account summary."""
        if not self._multi_account_scanner:
            return MultiAccountSummary()

        try:
            accounts = self._multi_account_scanner.get_accounts_to_scan()

            # Count by provider
            by_provider: dict[str, int] = {}
            for account in accounts:
                provider = account.provider
                by_provider[provider] = by_provider.get(provider, 0) + 1

            return MultiAccountSummary(
                total_accounts=len(accounts),
                accounts_by_provider=by_provider,
            )
        except Exception:
            return MultiAccountSummary()

    def get_forecast(
        self,
        config_name: str = "default",
        history_days: int = 30,
        forecast_days: int = 7,
    ) -> dict[str, Any]:
        """
        Get findings forecast.

        Args:
            config_name: Configuration name
            history_days: Days of history for model
            forecast_days: Days to forecast

        Returns:
            Forecast data
        """
        if not self._trend_analyzer:
            return {"error": "Trend analyzer not configured"}

        try:
            return self._trend_analyzer.forecast(
                config_name=config_name,
                days_history=history_days,
                days_forecast=forecast_days,
            )
        except Exception as e:
            return {"error": str(e)}

    def get_period_comparison(
        self,
        config_name: str = "default",
        current_days: int = 7,
        previous_days: int = 7,
    ) -> dict[str, Any]:
        """
        Get period comparison.

        Args:
            config_name: Configuration name
            current_days: Days in current period
            previous_days: Days in previous period

        Returns:
            Comparison data
        """
        if not self._trend_analyzer:
            return {"error": "Trend analyzer not configured"}

        try:
            return self._trend_analyzer.compare_periods(
                config_name=config_name,
                current_days=current_days,
                previous_days=previous_days,
            )
        except Exception as e:
            return {"error": str(e)}

    def get_velocity_metrics(
        self,
        config_name: str = "default",
        days: int = 7,
    ) -> dict[str, Any]:
        """
        Get findings velocity metrics.

        Args:
            config_name: Configuration name
            days: Days for velocity calculation

        Returns:
            Velocity data by severity
        """
        if not self._trend_analyzer:
            return {"error": "Trend analyzer not configured"}

        try:
            return self._trend_analyzer.get_findings_velocity(
                config_name=config_name,
                days=days,
            )
        except Exception as e:
            return {"error": str(e)}


def create_aggregator(
    history_path: str = "~/.stance/history",
) -> DashboardAggregator:
    """
    Create a dashboard aggregator with default components.

    Args:
        history_path: Path for history storage

    Returns:
        Configured DashboardAggregator
    """
    history_manager = ScanHistoryManager(storage_path=history_path)
    trend_analyzer = TrendAnalyzer(history_manager=history_manager)

    return DashboardAggregator(
        history_manager=history_manager,
        trend_analyzer=trend_analyzer,
    )
