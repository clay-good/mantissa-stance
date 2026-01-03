"""
Notification Handler for Mantissa Stance.

Integrates the scheduling system with the alerting system to provide
automated notifications for scan results, new findings, and security trends.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable

from stance.alerting import AlertRouter, RoutingRule
from stance.models.finding import Finding, FindingCollection, Severity
from stance.scheduling import ScanResult, ScanComparison, ScanHistoryEntry

logger = logging.getLogger(__name__)


class NotificationType(Enum):
    """Types of notifications that can be sent."""

    SCAN_COMPLETE = "scan_complete"  # Scan finished (success or failure)
    SCAN_FAILED = "scan_failed"  # Scan encountered an error
    NEW_FINDINGS = "new_findings"  # New findings detected
    CRITICAL_FINDING = "critical_finding"  # Critical severity finding
    FINDINGS_RESOLVED = "findings_resolved"  # Findings that were resolved
    TREND_ALERT = "trend_alert"  # Security trend alert (improving/declining)
    SCHEDULED_REPORT = "scheduled_report"  # Periodic scheduled report


@dataclass
class NotificationConfig:
    """
    Configuration for notifications.

    Attributes:
        notify_on_scan_complete: Send notification when scan completes
        notify_on_scan_failure: Send notification when scan fails
        notify_on_new_findings: Send notification for new findings
        notify_on_critical: Send notification for critical findings
        notify_on_resolved: Send notification for resolved findings
        notify_on_trend_change: Send notification on trend changes
        min_severity_for_new: Minimum severity to notify on new findings
        critical_threshold: Number of critical findings to trigger alert
        trend_threshold_percent: Percentage change to trigger trend alert
        include_summary: Include summary in notifications
        include_details: Include detailed findings in notifications
        destinations: Override destinations (empty = use router defaults)
    """

    notify_on_scan_complete: bool = True
    notify_on_scan_failure: bool = True
    notify_on_new_findings: bool = True
    notify_on_critical: bool = True
    notify_on_resolved: bool = False
    notify_on_trend_change: bool = True
    min_severity_for_new: Severity = Severity.HIGH
    critical_threshold: int = 1
    trend_threshold_percent: float = 10.0
    include_summary: bool = True
    include_details: bool = False
    destinations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "notify_on_scan_complete": self.notify_on_scan_complete,
            "notify_on_scan_failure": self.notify_on_scan_failure,
            "notify_on_new_findings": self.notify_on_new_findings,
            "notify_on_critical": self.notify_on_critical,
            "notify_on_resolved": self.notify_on_resolved,
            "notify_on_trend_change": self.notify_on_trend_change,
            "min_severity_for_new": self.min_severity_for_new.value,
            "critical_threshold": self.critical_threshold,
            "trend_threshold_percent": self.trend_threshold_percent,
            "include_summary": self.include_summary,
            "include_details": self.include_details,
            "destinations": self.destinations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NotificationConfig:
        """Create from dictionary."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        min_sev = data.get("min_severity_for_new", "high")
        if isinstance(min_sev, str):
            min_sev = severity_map.get(min_sev.lower(), Severity.HIGH)

        return cls(
            notify_on_scan_complete=data.get("notify_on_scan_complete", True),
            notify_on_scan_failure=data.get("notify_on_scan_failure", True),
            notify_on_new_findings=data.get("notify_on_new_findings", True),
            notify_on_critical=data.get("notify_on_critical", True),
            notify_on_resolved=data.get("notify_on_resolved", False),
            notify_on_trend_change=data.get("notify_on_trend_change", True),
            min_severity_for_new=min_sev,
            critical_threshold=data.get("critical_threshold", 1),
            trend_threshold_percent=data.get("trend_threshold_percent", 10.0),
            include_summary=data.get("include_summary", True),
            include_details=data.get("include_details", False),
            destinations=data.get("destinations", []),
        )


@dataclass
class ScanNotification:
    """
    Base notification for scan events.

    Attributes:
        notification_type: Type of notification
        timestamp: When the notification was created
        scan_id: ID of the scan
        job_name: Name of the scheduled job (if applicable)
        config_name: Scan configuration name
        message: Notification message
        details: Additional details
    """

    notification_type: NotificationType
    timestamp: datetime
    scan_id: str
    job_name: str = ""
    config_name: str = "default"
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "notification_type": self.notification_type.value,
            "timestamp": self.timestamp.isoformat(),
            "scan_id": self.scan_id,
            "job_name": self.job_name,
            "config_name": self.config_name,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ScanSummaryNotification(ScanNotification):
    """
    Notification with scan summary.

    Attributes:
        success: Whether scan completed successfully
        duration_seconds: How long the scan took
        assets_scanned: Number of assets scanned
        findings_total: Total findings count
        findings_by_severity: Breakdown by severity
        error_message: Error message if failed
    """

    success: bool = True
    duration_seconds: float = 0.0
    assets_scanned: int = 0
    findings_total: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "assets_scanned": self.assets_scanned,
            "findings_total": self.findings_total,
            "findings_by_severity": self.findings_by_severity,
            "error_message": self.error_message,
        })
        return base


@dataclass
class FindingNotification(ScanNotification):
    """
    Notification for specific findings.

    Attributes:
        findings: List of findings to notify about
        is_new: Whether these are new findings
        is_resolved: Whether these are resolved findings
    """

    findings: list[Finding] = field(default_factory=list)
    is_new: bool = True
    is_resolved: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "findings_count": len(self.findings),
            "finding_ids": [f.id for f in self.findings],
            "is_new": self.is_new,
            "is_resolved": self.is_resolved,
        })
        return base


@dataclass
class TrendNotification(ScanNotification):
    """
    Notification for security trend changes.

    Attributes:
        direction: Trend direction (improving/declining)
        change_percent: Percentage change
        current_findings: Current findings count
        previous_findings: Previous findings count
        period_days: Days in the comparison period
    """

    direction: str = "stable"
    change_percent: float = 0.0
    current_findings: int = 0
    previous_findings: int = 0
    period_days: int = 7

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        base = super().to_dict()
        base.update({
            "direction": self.direction,
            "change_percent": self.change_percent,
            "current_findings": self.current_findings,
            "previous_findings": self.previous_findings,
            "period_days": self.period_days,
        })
        return base


class NotificationHandler:
    """
    Handles notifications for scheduled scans and security events.

    Integrates with the AlertRouter to send notifications through
    configured destinations (Slack, PagerDuty, Email, etc.).

    Example:
        >>> from stance.alerting import AlertRouter, SlackDestination
        >>> from stance.automation import NotificationHandler, NotificationConfig
        >>>
        >>> router = AlertRouter()
        >>> router.add_destination(SlackDestination(webhook_url="..."))
        >>>
        >>> handler = NotificationHandler(router)
        >>> handler.configure(NotificationConfig(notify_on_critical=True))
        >>>
        >>> # Use as scheduler callback
        >>> scheduler.add_callback(handler.on_scan_complete)
    """

    def __init__(
        self,
        router: AlertRouter | None = None,
        config: NotificationConfig | None = None,
    ):
        """
        Initialize the notification handler.

        Args:
            router: AlertRouter for sending notifications
            config: Notification configuration
        """
        self._router = router
        self._config = config or NotificationConfig()
        self._callbacks: list[Callable[[ScanNotification], None]] = []
        self._notification_history: list[ScanNotification] = []
        self._max_history = 1000

    @property
    def config(self) -> NotificationConfig:
        """Get current configuration."""
        return self._config

    def configure(self, config: NotificationConfig) -> None:
        """
        Update notification configuration.

        Args:
            config: New configuration
        """
        self._config = config
        logger.info("Notification configuration updated")

    def set_router(self, router: AlertRouter) -> None:
        """
        Set the alert router.

        Args:
            router: AlertRouter to use for notifications
        """
        self._router = router
        logger.info("Alert router set")

    def add_callback(self, callback: Callable[[ScanNotification], None]) -> None:
        """
        Add a callback for notifications.

        Callbacks are called for every notification, regardless of
        whether it's sent through the router.

        Args:
            callback: Function to call with notification
        """
        self._callbacks.append(callback)

    def on_scan_complete(self, result: ScanResult) -> None:
        """
        Handle scan completion event.

        This method can be registered as a scheduler callback.

        Args:
            result: Result from the completed scan
        """
        if result.success:
            if self._config.notify_on_scan_complete:
                self._send_scan_complete_notification(result)
        else:
            if self._config.notify_on_scan_failure:
                self._send_scan_failed_notification(result)

    def on_findings_detected(
        self,
        scan_id: str,
        findings: FindingCollection,
        comparison: ScanComparison | None = None,
        job_name: str = "",
    ) -> None:
        """
        Handle new findings detected.

        Args:
            scan_id: ID of the scan
            findings: All findings from scan
            comparison: Comparison with previous scan (if available)
            job_name: Name of scheduled job
        """
        if comparison:
            # Notify on new findings
            if self._config.notify_on_new_findings and comparison.new_findings:
                new_findings = [
                    diff.finding for diff in comparison.new_findings
                    if diff.finding and self._meets_severity_threshold(
                        diff.finding.severity,
                        self._config.min_severity_for_new,
                    )
                ]
                if new_findings:
                    self._send_new_findings_notification(
                        scan_id, new_findings, job_name
                    )

            # Notify on resolved findings
            if self._config.notify_on_resolved and comparison.resolved_findings:
                resolved_findings = [
                    diff.finding for diff in comparison.resolved_findings
                    if diff.finding
                ]
                if resolved_findings:
                    self._send_resolved_findings_notification(
                        scan_id, resolved_findings, job_name
                    )

        # Check for critical findings
        if self._config.notify_on_critical:
            critical_findings = [
                f for f in findings.findings
                if f.severity == Severity.CRITICAL
            ]
            if len(critical_findings) >= self._config.critical_threshold:
                self._send_critical_findings_notification(
                    scan_id, critical_findings, job_name
                )

    def on_trend_change(
        self,
        scan_id: str,
        direction: str,
        change_percent: float,
        current_findings: int,
        previous_findings: int,
        period_days: int = 7,
        job_name: str = "",
    ) -> None:
        """
        Handle security trend change.

        Args:
            scan_id: ID of the scan
            direction: Trend direction (improving/declining/stable)
            change_percent: Percentage change
            current_findings: Current findings count
            previous_findings: Previous findings count
            period_days: Days in comparison period
            job_name: Name of scheduled job
        """
        if not self._config.notify_on_trend_change:
            return

        # Only notify if change exceeds threshold
        if abs(change_percent) < self._config.trend_threshold_percent:
            return

        notification = TrendNotification(
            notification_type=NotificationType.TREND_ALERT,
            timestamp=datetime.utcnow(),
            scan_id=scan_id,
            job_name=job_name,
            message=self._format_trend_message(direction, change_percent),
            direction=direction,
            change_percent=change_percent,
            current_findings=current_findings,
            previous_findings=previous_findings,
            period_days=period_days,
        )

        self._send_notification(notification)

    def get_history(
        self,
        limit: int | None = None,
        notification_type: NotificationType | None = None,
    ) -> list[ScanNotification]:
        """
        Get notification history.

        Args:
            limit: Maximum number to return
            notification_type: Filter by type

        Returns:
            List of notifications (most recent first)
        """
        history = list(reversed(self._notification_history))

        if notification_type:
            history = [n for n in history if n.notification_type == notification_type]

        if limit:
            history = history[:limit]

        return history

    def clear_history(self) -> None:
        """Clear notification history."""
        self._notification_history.clear()

    def _send_scan_complete_notification(self, result: ScanResult) -> None:
        """Send notification for successful scan completion."""
        notification = ScanSummaryNotification(
            notification_type=NotificationType.SCAN_COMPLETE,
            timestamp=datetime.utcnow(),
            scan_id=result.scan_id,
            job_name=result.job_id,
            message=self._format_scan_complete_message(result),
            success=True,
            duration_seconds=result.duration.total_seconds() if result.duration else 0,
            assets_scanned=result.assets_scanned,
            findings_total=result.findings_count,
        )

        self._send_notification(notification)

    def _send_scan_failed_notification(self, result: ScanResult) -> None:
        """Send notification for failed scan."""
        notification = ScanSummaryNotification(
            notification_type=NotificationType.SCAN_FAILED,
            timestamp=datetime.utcnow(),
            scan_id=result.scan_id,
            job_name=result.job_id,
            message=self._format_scan_failed_message(result),
            success=False,
            error_message=result.error or "Unknown error",
        )

        self._send_notification(notification)

    def _send_new_findings_notification(
        self,
        scan_id: str,
        findings: list[Finding],
        job_name: str,
    ) -> None:
        """Send notification for new findings."""
        notification = FindingNotification(
            notification_type=NotificationType.NEW_FINDINGS,
            timestamp=datetime.utcnow(),
            scan_id=scan_id,
            job_name=job_name,
            message=self._format_new_findings_message(findings),
            findings=findings,
            is_new=True,
        )

        self._send_notification(notification)

        # Also route individual critical findings through the router
        if self._router and self._config.include_details:
            for finding in findings:
                if finding.severity == Severity.CRITICAL:
                    self._router.route(finding, {"notification_type": "new_finding"})

    def _send_resolved_findings_notification(
        self,
        scan_id: str,
        findings: list[Finding],
        job_name: str,
    ) -> None:
        """Send notification for resolved findings."""
        notification = FindingNotification(
            notification_type=NotificationType.FINDINGS_RESOLVED,
            timestamp=datetime.utcnow(),
            scan_id=scan_id,
            job_name=job_name,
            message=self._format_resolved_findings_message(findings),
            findings=findings,
            is_new=False,
            is_resolved=True,
        )

        self._send_notification(notification)

    def _send_critical_findings_notification(
        self,
        scan_id: str,
        findings: list[Finding],
        job_name: str,
    ) -> None:
        """Send notification for critical findings."""
        notification = FindingNotification(
            notification_type=NotificationType.CRITICAL_FINDING,
            timestamp=datetime.utcnow(),
            scan_id=scan_id,
            job_name=job_name,
            message=self._format_critical_findings_message(findings),
            findings=findings,
            is_new=True,
        )

        self._send_notification(notification)

        # Route individual findings through the router
        if self._router:
            for finding in findings:
                self._router.route(finding, {"notification_type": "critical_finding"})

    def _send_notification(self, notification: ScanNotification) -> None:
        """Send notification through all channels."""
        # Add to history
        self._notification_history.append(notification)
        if len(self._notification_history) > self._max_history:
            self._notification_history = self._notification_history[-self._max_history:]

        # Call registered callbacks
        for callback in self._callbacks:
            try:
                callback(notification)
            except Exception as e:
                logger.error(f"Notification callback failed: {e}")

        # Log the notification
        logger.info(
            f"Notification sent: {notification.notification_type.value} - "
            f"{notification.message}"
        )

    def _format_scan_complete_message(self, result: ScanResult) -> str:
        """Format scan complete message."""
        duration = result.duration.total_seconds() if result.duration else 0
        return (
            f"Scan completed successfully. "
            f"Scanned {result.assets_scanned} assets, "
            f"found {result.findings_count} findings "
            f"in {duration:.1f}s."
        )

    def _format_scan_failed_message(self, result: ScanResult) -> str:
        """Format scan failed message."""
        return f"Scan failed: {result.error or 'Unknown error'}"

    def _format_new_findings_message(self, findings: list[Finding]) -> str:
        """Format new findings message."""
        by_severity = self._count_by_severity(findings)
        severity_str = ", ".join(
            f"{count} {sev}" for sev, count in by_severity.items() if count > 0
        )
        return f"Detected {len(findings)} new findings: {severity_str}"

    def _format_resolved_findings_message(self, findings: list[Finding]) -> str:
        """Format resolved findings message."""
        return f"Resolved {len(findings)} findings"

    def _format_critical_findings_message(self, findings: list[Finding]) -> str:
        """Format critical findings message."""
        return (
            f"ALERT: {len(findings)} critical findings detected! "
            f"Immediate attention required."
        )

    def _format_trend_message(self, direction: str, change_percent: float) -> str:
        """Format trend message."""
        if direction == "improving":
            return (
                f"Security posture improving: "
                f"{abs(change_percent):.1f}% reduction in findings"
            )
        elif direction == "declining":
            return (
                f"Security posture declining: "
                f"{abs(change_percent):.1f}% increase in findings"
            )
        else:
            return "Security posture stable"

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for finding in findings:
            sev = finding.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _meets_severity_threshold(
        self,
        severity: Severity,
        threshold: Severity,
    ) -> bool:
        """Check if severity meets threshold."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return severity_order.get(severity, 4) <= severity_order.get(threshold, 4)


def create_scheduler_callback(
    handler: NotificationHandler,
) -> Callable[[ScanResult], None]:
    """
    Create a callback function for the scheduler.

    Args:
        handler: NotificationHandler to use

    Returns:
        Callback function suitable for ScanScheduler.add_callback()
    """
    return handler.on_scan_complete
