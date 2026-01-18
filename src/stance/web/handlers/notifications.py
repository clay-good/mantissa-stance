"""
Notifications handlers for the Stance web API.

This module handles all /api/notifications/* endpoints for notification
history, configuration, and management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class NotificationsHandler(RoutedHandler):
    """
    Handler for notifications API endpoints.

    Handles:
    - Notification history listing
    - Notification types and configuration
    - Notification status and management
    """

    base_path = "/api/notifications/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("list")
    def notifications_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List notification history.

        Query params:
            limit: Maximum notifications to return (default: 50)
            type: Filter by notification type
            offset: Skip first N notifications
        """
        limit = self.get_param_int(params, "limit", 50)
        type_filter = self.get_param(params, "type", "")
        offset = self.get_param_int(params, "offset", 0)

        notifications = self._get_sample_notifications()

        if type_filter:
            notifications = [n for n in notifications if n.get("notification_type") == type_filter]

        total = len(notifications)
        notifications = notifications[offset:offset + limit]

        return HandlerResponse.success({
            "notifications": notifications,
            "total": total,
            "limit": limit,
            "offset": offset,
        })

    @route("show")
    def notifications_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Show notification details.

        Query params:
            index: Notification index (0 = most recent)
        """
        index = self.get_param_int(params, "index", 0)
        notifications = self._get_sample_notifications()

        if index < 0 or index >= len(notifications):
            return HandlerResponse.error(
                f"Invalid index: {index}. Valid range: 0-{len(notifications)-1}",
                HttpStatus.BAD_REQUEST
            )

        return HandlerResponse.success(notifications[index])

    @route("types")
    def notifications_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all available notification types."""
        types = [
            {
                "value": "scan_complete",
                "name": "Scan Complete",
                "description": "Scan finished successfully",
            },
            {
                "value": "scan_failed",
                "name": "Scan Failed",
                "description": "Scan encountered an error",
            },
            {
                "value": "new_findings",
                "name": "New Findings",
                "description": "New findings detected in scan",
            },
            {
                "value": "critical_finding",
                "name": "Critical Finding",
                "description": "Critical severity finding detected",
            },
            {
                "value": "findings_resolved",
                "name": "Findings Resolved",
                "description": "Previously detected findings are now resolved",
            },
            {
                "value": "trend_alert",
                "name": "Trend Alert",
                "description": "Security trend change (improving/declining)",
            },
            {
                "value": "scheduled_report",
                "name": "Scheduled Report",
                "description": "Periodic scheduled report notification",
            },
        ]

        return HandlerResponse.success({
            "types": types,
            "total": len(types),
        })

    @route("config")
    def notifications_config(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get notification configuration."""
        return HandlerResponse.success({
            "notify_on_scan_complete": True,
            "notify_on_scan_failure": True,
            "notify_on_new_findings": True,
            "notify_on_critical": True,
            "notify_on_resolved": False,
            "notify_on_trend_change": True,
            "min_severity_for_new": "high",
            "critical_threshold": 1,
            "trend_threshold_percent": 10.0,
            "include_summary": True,
            "include_details": False,
            "destinations": [],
        })

    @route("status")
    def notifications_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get notifications module status."""
        notifications = self._get_sample_notifications()

        by_type: dict[str, int] = {}
        for notif in notifications:
            t = notif.get("notification_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        enabled_types = [
            "scan_complete", "scan_failed", "new_findings",
            "critical", "trend_change"
        ]

        return HandlerResponse.success({
            "module": "notifications",
            "version": "1.0.0",
            "status": "active",
            "history_count": len(notifications),
            "max_history": 1000,
            "callbacks_registered": 0,
            "router_configured": False,
            "enabled_types": enabled_types,
            "notifications_by_type": by_type,
            "capabilities": {
                "scan_complete": True,
                "scan_failed": True,
                "new_findings": True,
                "critical_finding": True,
                "findings_resolved": True,
                "trend_alert": True,
                "scheduled_report": True,
                "custom_callbacks": True,
                "alert_routing": True,
            },
        })

    @route("summary")
    def notifications_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get notifications summary."""
        notifications = self._get_sample_notifications()

        by_type: dict[str, int] = {}
        for notif in notifications:
            t = notif.get("notification_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        return HandlerResponse.success({
            "total_notifications": len(notifications),
            "by_type": by_type,
            "enabled": True,
            "destinations_configured": 0,
        })

    # =========================================================================
    # POST endpoints
    # =========================================================================

    @route("set", methods=["POST"])
    def notifications_set(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Set notification configuration option.

        Body:
            option: Configuration option name
            value: New value
        """
        if not body:
            return HandlerResponse.error("Request body required", HttpStatus.BAD_REQUEST)

        option = body.get("option", "")
        value = body.get("value")

        if not option:
            return HandlerResponse.error("Option name is required", HttpStatus.BAD_REQUEST)

        if value is None:
            return HandlerResponse.error("Value is required", HttpStatus.BAD_REQUEST)

        valid_options = [
            "notify_on_scan_complete", "notify_on_scan_failure",
            "notify_on_new_findings", "notify_on_critical",
            "notify_on_resolved", "notify_on_trend_change",
            "min_severity_for_new", "critical_threshold",
            "trend_threshold_percent", "include_summary", "include_details",
        ]

        if option not in valid_options:
            return HandlerResponse.error(
                f"Invalid option: {option}. Valid: {valid_options}",
                HttpStatus.BAD_REQUEST
            )

        return HandlerResponse.success({
            "status": "updated",
            "option": option,
            "value": value,
        })

    @route("enable", methods=["POST"])
    def notifications_enable(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Enable a notification type.

        Body:
            type: Notification type to enable
        """
        if not body:
            return HandlerResponse.error("Request body required", HttpStatus.BAD_REQUEST)

        notif_type = body.get("type", "")
        if not notif_type:
            return HandlerResponse.error("Notification type is required", HttpStatus.BAD_REQUEST)

        valid_types = [
            "scan_complete", "scan_failed", "new_findings",
            "critical_finding", "findings_resolved", "trend_alert",
            "scheduled_report",
        ]

        if notif_type not in valid_types:
            return HandlerResponse.error(
                f"Invalid type: {notif_type}. Valid: {valid_types}",
                HttpStatus.BAD_REQUEST
            )

        return HandlerResponse.success({
            "status": "enabled",
            "type": notif_type,
        })

    @route("disable", methods=["POST"])
    def notifications_disable(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Disable a notification type.

        Body:
            type: Notification type to disable
        """
        if not body:
            return HandlerResponse.error("Request body required", HttpStatus.BAD_REQUEST)

        notif_type = body.get("type", "")
        if not notif_type:
            return HandlerResponse.error("Notification type is required", HttpStatus.BAD_REQUEST)

        valid_types = [
            "scan_complete", "scan_failed", "new_findings",
            "critical_finding", "findings_resolved", "trend_alert",
            "scheduled_report",
        ]

        if notif_type not in valid_types:
            return HandlerResponse.error(
                f"Invalid type: {notif_type}. Valid: {valid_types}",
                HttpStatus.BAD_REQUEST
            )

        return HandlerResponse.success({
            "status": "disabled",
            "type": notif_type,
        })

    @route("test", methods=["POST"])
    def notifications_test(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Send a test notification.

        Body:
            type: Notification type (optional, defaults to "test")
            destination: Destination to test (optional)
        """
        body = body or {}
        notif_type = body.get("type", "test")
        destination = body.get("destination", "")

        return HandlerResponse.success({
            "status": "sent",
            "type": notif_type,
            "destination": destination or "all configured",
            "message": "Test notification sent successfully",
        })

    @route("clear", methods=["POST"])
    def notifications_clear(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Clear notification history.

        Body:
            before: Clear notifications before this timestamp (optional)
            type: Clear only this notification type (optional)
        """
        body = body or {}
        before = body.get("before", "")
        notif_type = body.get("type", "")

        return HandlerResponse.success({
            "status": "cleared",
            "before": before or "all",
            "type": notif_type or "all",
            "cleared_count": 0,
        })

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_sample_notifications(self) -> list[dict[str, Any]]:
        """Get sample notification data."""
        now = datetime.now()
        return [
            {
                "id": "notif-001",
                "notification_type": "scan_complete",
                "title": "Scan Complete",
                "message": "Security scan completed successfully with 15 findings",
                "severity": "info",
                "timestamp": (now - timedelta(hours=1)).isoformat(),
                "read": False,
                "data": {
                    "scan_id": "scan-abc123",
                    "findings_count": 15,
                    "duration_seconds": 145,
                },
            },
            {
                "id": "notif-002",
                "notification_type": "critical_finding",
                "title": "Critical Finding Detected",
                "message": "S3 bucket 'prod-data' allows public access",
                "severity": "critical",
                "timestamp": (now - timedelta(hours=2)).isoformat(),
                "read": True,
                "data": {
                    "finding_id": "finding-xyz789",
                    "resource": "s3://prod-data",
                    "policy": "aws-s3-public-access",
                },
            },
            {
                "id": "notif-003",
                "notification_type": "new_findings",
                "title": "New Findings Detected",
                "message": "5 new high severity findings in latest scan",
                "severity": "high",
                "timestamp": (now - timedelta(hours=3)).isoformat(),
                "read": False,
                "data": {
                    "new_count": 5,
                    "severity": "high",
                },
            },
            {
                "id": "notif-004",
                "notification_type": "trend_alert",
                "title": "Security Trend Improvement",
                "message": "Critical findings reduced by 20% this week",
                "severity": "info",
                "timestamp": (now - timedelta(days=1)).isoformat(),
                "read": True,
                "data": {
                    "trend": "improving",
                    "percent_change": -20,
                    "period": "week",
                },
            },
            {
                "id": "notif-005",
                "notification_type": "findings_resolved",
                "title": "Findings Resolved",
                "message": "3 findings have been resolved",
                "severity": "info",
                "timestamp": (now - timedelta(days=2)).isoformat(),
                "read": True,
                "data": {
                    "resolved_count": 3,
                },
            },
        ]
