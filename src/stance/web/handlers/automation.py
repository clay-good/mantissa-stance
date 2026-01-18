"""
Automation handlers for the Stance web API.

This module handles all /api/automation/* endpoints for automation
triggers, workflows, callbacks, and scheduled tasks.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class AutomationHandler(RoutedHandler):
    """
    Handler for automation API endpoints.

    Handles:
    - Automation configuration and types
    - Trigger management
    - Callback configuration
    - Workflow management
    - Automation history
    """

    base_path = "/api/automation/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("config")
    def automation_config(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get automation configuration."""
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

    @route("types")
    def automation_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List automation trigger types."""
        types = [
            {
                "value": "scan_complete",
                "description": "Trigger when a scan completes successfully",
                "trigger": "Scan finishes without errors",
            },
            {
                "value": "scan_failed",
                "description": "Trigger when a scan fails",
                "trigger": "Scan encounters an error",
            },
            {
                "value": "new_findings",
                "description": "Trigger for newly detected findings",
                "trigger": "New findings detected above severity threshold",
            },
            {
                "value": "critical_finding",
                "description": "Trigger for critical severity findings",
                "trigger": "Critical findings count exceeds threshold",
            },
            {
                "value": "findings_resolved",
                "description": "Trigger when findings are resolved",
                "trigger": "Previously detected findings no longer present",
            },
            {
                "value": "trend_alert",
                "description": "Trigger for security trend changes",
                "trigger": "Finding count changes by more than threshold percent",
            },
            {
                "value": "scheduled_report",
                "description": "Scheduled periodic security report",
                "trigger": "Scheduled time reached",
            },
        ]

        return HandlerResponse.success({
            "types": types,
            "total": len(types),
        })

    @route("history")
    def automation_history(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get automation execution history.

        Query params:
            type: Filter by automation type
            limit: Maximum entries to return (default: 50)
        """
        automation_type = self.get_param(params, "type", "")
        limit = self.get_param_int(params, "limit", 50)

        now = datetime.now(timezone.utc)
        history = [
            {
                "automation_type": "scan_complete",
                "timestamp": (now - timedelta(hours=1)).isoformat(),
                "scan_id": "scan-001",
                "job_name": "daily-security-scan",
                "message": "Scan completed successfully. Scanned 150 assets, found 23 findings.",
                "status": "success",
            },
            {
                "automation_type": "critical_finding",
                "timestamp": (now - timedelta(hours=2)).isoformat(),
                "scan_id": "scan-001",
                "job_name": "daily-security-scan",
                "message": "ALERT: 2 critical findings detected! Immediate attention required.",
                "status": "triggered",
            },
            {
                "automation_type": "new_findings",
                "timestamp": (now - timedelta(hours=3)).isoformat(),
                "scan_id": "scan-002",
                "job_name": "aws-account-scan",
                "message": "Detected 5 new findings: 1 critical, 2 high, 2 medium",
                "status": "triggered",
            },
            {
                "automation_type": "trend_alert",
                "timestamp": (now - timedelta(hours=6)).isoformat(),
                "scan_id": "scan-003",
                "job_name": "weekly-trend-analysis",
                "message": "Security posture improving: 15.3% reduction in findings",
                "status": "triggered",
            },
            {
                "automation_type": "scan_failed",
                "timestamp": (now - timedelta(hours=12)).isoformat(),
                "scan_id": "scan-004",
                "job_name": "gcp-project-scan",
                "message": "Scan failed: GCP credentials expired",
                "status": "error",
            },
        ]

        if automation_type:
            history = [h for h in history if h["automation_type"] == automation_type]

        return HandlerResponse.success({
            "history": history[:limit],
            "total": len(history),
        })

    @route("thresholds")
    def automation_thresholds(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get automation thresholds configuration."""
        thresholds = [
            {
                "name": "min_severity_for_new",
                "value": "high",
                "description": "Minimum severity level to trigger new findings automation",
                "type": "enum",
                "options": ["critical", "high", "medium", "low", "info"],
            },
            {
                "name": "critical_threshold",
                "value": 1,
                "description": "Number of critical findings to trigger alert",
                "type": "integer",
                "min": 1,
                "max": 100,
            },
            {
                "name": "trend_threshold_percent",
                "value": 10.0,
                "description": "Percentage change to trigger trend alert",
                "type": "float",
                "min": 1.0,
                "max": 100.0,
            },
        ]

        return HandlerResponse.success({
            "thresholds": thresholds,
            "total": len(thresholds),
        })

    @route("triggers")
    def automation_triggers(self, params: dict, body: dict | None) -> HandlerResponse:
        """List configured automation triggers."""
        triggers = [
            {
                "id": "trigger-001",
                "name": "Critical Finding Alert",
                "type": "critical_finding",
                "enabled": True,
                "threshold": 1,
                "actions": ["slack_notify", "email_alert"],
                "created_at": "2026-01-01T00:00:00Z",
            },
            {
                "id": "trigger-002",
                "name": "Daily Scan Complete",
                "type": "scan_complete",
                "enabled": True,
                "threshold": None,
                "actions": ["slack_notify"],
                "created_at": "2026-01-01T00:00:00Z",
            },
            {
                "id": "trigger-003",
                "name": "New High Findings",
                "type": "new_findings",
                "enabled": True,
                "threshold": "high",
                "actions": ["jira_ticket", "email_alert"],
                "created_at": "2026-01-01T00:00:00Z",
            },
        ]

        return HandlerResponse.success({
            "triggers": triggers,
            "total": len(triggers),
            "enabled_count": sum(1 for t in triggers if t["enabled"]),
        })

    @route("callbacks")
    def automation_callbacks(self, params: dict, body: dict | None) -> HandlerResponse:
        """List configured automation callbacks."""
        callbacks = [
            {
                "id": "callback-001",
                "name": "Slack Notification",
                "type": "webhook",
                "url": "https://hooks.slack.com/services/xxx",
                "enabled": True,
            },
            {
                "id": "callback-002",
                "name": "Email Alert",
                "type": "email",
                "recipients": ["security@example.com"],
                "enabled": True,
            },
            {
                "id": "callback-003",
                "name": "Jira Ticket",
                "type": "jira",
                "project": "SEC",
                "enabled": False,
            },
        ]

        return HandlerResponse.success({
            "callbacks": callbacks,
            "total": len(callbacks),
        })

    @route("severities")
    def automation_severities(self, params: dict, body: dict | None) -> HandlerResponse:
        """List severity levels for automation."""
        severities = [
            {"value": "critical", "priority": 1, "color": "#dc3545"},
            {"value": "high", "priority": 2, "color": "#fd7e14"},
            {"value": "medium", "priority": 3, "color": "#ffc107"},
            {"value": "low", "priority": 4, "color": "#28a745"},
            {"value": "info", "priority": 5, "color": "#17a2b8"},
        ]

        return HandlerResponse.success({
            "severities": severities,
            "total": len(severities),
        })

    @route("status")
    def automation_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get automation module status."""
        return HandlerResponse.success({
            "module": "automation",
            "version": "1.0.0",
            "status": "active",
            "triggers_enabled": 3,
            "callbacks_configured": 3,
            "last_execution": None,
            "capabilities": {
                "scan_triggers": True,
                "finding_triggers": True,
                "trend_triggers": True,
                "webhook_callbacks": True,
                "email_callbacks": True,
                "jira_integration": True,
                "scheduled_automation": True,
            },
        })

    @route("test")
    def automation_test(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Test an automation trigger.

        Query params:
            type: Trigger type to test
            callback: Callback to test (optional)
        """
        trigger_type = self.get_param(params, "type", "scan_complete")
        callback = self.get_param(params, "callback", "")

        return HandlerResponse.success({
            "status": "test_sent",
            "type": trigger_type,
            "callback": callback or "all configured",
            "message": f"Test automation triggered for '{trigger_type}'",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    @route("summary")
    def automation_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get automation summary."""
        return HandlerResponse.success({
            "total_triggers": 3,
            "enabled_triggers": 3,
            "total_callbacks": 3,
            "enabled_callbacks": 2,
            "executions_today": 15,
            "executions_this_week": 87,
            "success_rate": 98.5,
        })

    @route("workflows")
    def automation_workflows(self, params: dict, body: dict | None) -> HandlerResponse:
        """List automation workflows."""
        workflows = [
            {
                "id": "workflow-001",
                "name": "Critical Finding Response",
                "description": "Automated response to critical findings",
                "enabled": True,
                "steps": [
                    {"order": 1, "action": "create_ticket", "config": {"project": "SEC"}},
                    {"order": 2, "action": "notify_slack", "config": {"channel": "#security"}},
                    {"order": 3, "action": "send_email", "config": {"to": "security@example.com"}},
                ],
            },
            {
                "id": "workflow-002",
                "name": "Weekly Report",
                "description": "Generate and distribute weekly security report",
                "enabled": True,
                "steps": [
                    {"order": 1, "action": "generate_report", "config": {"format": "pdf"}},
                    {"order": 2, "action": "send_email", "config": {"to": "leadership@example.com"}},
                ],
            },
        ]

        return HandlerResponse.success({
            "workflows": workflows,
            "total": len(workflows),
        })

    @route("events")
    def automation_events(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List automation events.

        Query params:
            limit: Maximum events to return (default: 50)
        """
        limit = self.get_param_int(params, "limit", 50)

        now = datetime.now(timezone.utc)
        events = [
            {
                "id": "event-001",
                "type": "trigger_fired",
                "trigger_id": "trigger-001",
                "timestamp": (now - timedelta(hours=1)).isoformat(),
                "status": "success",
            },
            {
                "id": "event-002",
                "type": "callback_executed",
                "callback_id": "callback-001",
                "timestamp": (now - timedelta(hours=1)).isoformat(),
                "status": "success",
            },
            {
                "id": "event-003",
                "type": "workflow_started",
                "workflow_id": "workflow-001",
                "timestamp": (now - timedelta(hours=2)).isoformat(),
                "status": "completed",
            },
        ]

        return HandlerResponse.success({
            "events": events[:limit],
            "total": len(events),
        })
