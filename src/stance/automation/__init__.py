"""
Automation module for Mantissa Stance.

Provides integration between scheduling, scanning, alerting, and reporting
components to enable end-to-end automated security workflows.
"""

from stance.automation.notification_handler import (
    NotificationHandler,
    ScanNotification,
    NotificationType,
    NotificationConfig,
    ScanSummaryNotification,
    FindingNotification,
    TrendNotification,
)

__all__ = [
    "NotificationHandler",
    "ScanNotification",
    "NotificationType",
    "NotificationConfig",
    "ScanSummaryNotification",
    "FindingNotification",
    "TrendNotification",
]
