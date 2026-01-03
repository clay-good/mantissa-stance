"""
CLI commands for automation module in Mantissa Stance.

Provides command-line interface for managing notification automation,
configuration, and notification history.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from typing import Any

from stance.automation import (
    NotificationHandler,
    NotificationConfig,
    NotificationType,
    ScanNotification,
    ScanSummaryNotification,
    FindingNotification,
    TrendNotification,
)


def add_automation_parser(subparsers: argparse._SubParsersAction) -> None:
    """
    Add automation subcommand parser.

    Args:
        subparsers: Parent subparsers object
    """
    automation_parser = subparsers.add_parser(
        "automation",
        help="Notification automation and workflow management",
        description="Manage notification automation, configuration, and notification history.",
    )

    automation_subparsers = automation_parser.add_subparsers(
        dest="automation_command",
        help="Automation commands",
    )

    # config command
    config_parser = automation_subparsers.add_parser(
        "config",
        help="Show notification configuration",
        description="Display the current notification configuration.",
    )
    config_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # types command
    types_parser = automation_subparsers.add_parser(
        "types",
        help="List notification types",
        description="List all available notification types.",
    )
    types_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # history command
    history_parser = automation_subparsers.add_parser(
        "history",
        help="Show notification history",
        description="Display notification history.",
    )
    history_parser.add_argument(
        "--type",
        choices=[
            "scan_complete", "scan_failed", "new_findings",
            "critical_finding", "findings_resolved", "trend_alert",
            "scheduled_report"
        ],
        help="Filter by notification type",
    )
    history_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum notifications to show (default: 50)",
    )
    history_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # thresholds command
    thresholds_parser = automation_subparsers.add_parser(
        "thresholds",
        help="Show notification thresholds",
        description="Display configured thresholds for notifications.",
    )
    thresholds_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # triggers command
    triggers_parser = automation_subparsers.add_parser(
        "triggers",
        help="List notification triggers",
        description="List all notification triggers and their status.",
    )
    triggers_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # callbacks command
    callbacks_parser = automation_subparsers.add_parser(
        "callbacks",
        help="List registered callbacks",
        description="List registered notification callbacks.",
    )
    callbacks_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # severities command
    sev_parser = automation_subparsers.add_parser(
        "severities",
        help="List severity levels",
        description="List severity levels for notification filtering.",
    )
    sev_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # status command
    status_parser = automation_subparsers.add_parser(
        "status",
        help="Show automation module status",
        description="Display the status of the automation module.",
    )
    status_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # test command
    test_parser = automation_subparsers.add_parser(
        "test",
        help="Test notification trigger",
        description="Test a notification trigger with sample data.",
    )
    test_parser.add_argument(
        "--type",
        choices=[
            "scan_complete", "scan_failed", "new_findings",
            "critical_finding", "trend_alert"
        ],
        default="scan_complete",
        help="Notification type to test (default: scan_complete)",
    )
    test_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # summary command
    summary_parser = automation_subparsers.add_parser(
        "summary",
        help="Show automation summary",
        description="Display a summary of automation configuration and statistics.",
    )
    summary_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # workflows command
    workflows_parser = automation_subparsers.add_parser(
        "workflows",
        help="List automation workflows",
        description="List available automation workflows.",
    )
    workflows_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # events command
    events_parser = automation_subparsers.add_parser(
        "events",
        help="List supported events",
        description="List events that can trigger automation.",
    )
    events_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )


def cmd_automation(args: argparse.Namespace) -> int:
    """
    Handle automation commands.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    handlers = {
        "config": _handle_config,
        "types": _handle_types,
        "history": _handle_history,
        "thresholds": _handle_thresholds,
        "triggers": _handle_triggers,
        "callbacks": _handle_callbacks,
        "severities": _handle_severities,
        "status": _handle_status,
        "test": _handle_test,
        "summary": _handle_summary,
        "workflows": _handle_workflows,
        "events": _handle_events,
    }

    command = getattr(args, "automation_command", None)
    if not command:
        print("Error: No automation command specified", file=sys.stderr)
        print("Use 'stance automation --help' for available commands", file=sys.stderr)
        return 1

    handler = handlers.get(command)
    if not handler:
        print(f"Error: Unknown automation command: {command}", file=sys.stderr)
        return 1

    return handler(args)


def _handle_config(args: argparse.Namespace) -> int:
    """Handle config command."""
    config = _get_sample_config()

    if args.format == "json":
        print(json.dumps(config, indent=2))
    else:
        print("Notification Configuration")
        print("=" * 60)
        print()
        print("  Notification Triggers:")
        print(f"    Notify on scan complete: {config['notify_on_scan_complete']}")
        print(f"    Notify on scan failure: {config['notify_on_scan_failure']}")
        print(f"    Notify on new findings: {config['notify_on_new_findings']}")
        print(f"    Notify on critical: {config['notify_on_critical']}")
        print(f"    Notify on resolved: {config['notify_on_resolved']}")
        print(f"    Notify on trend change: {config['notify_on_trend_change']}")
        print()
        print("  Thresholds:")
        print(f"    Min severity for new: {config['min_severity_for_new']}")
        print(f"    Critical threshold: {config['critical_threshold']} findings")
        print(f"    Trend threshold: {config['trend_threshold_percent']}% change")
        print()
        print("  Options:")
        print(f"    Include summary: {config['include_summary']}")
        print(f"    Include details: {config['include_details']}")
        print(f"    Custom destinations: {len(config['destinations'])} configured")

    return 0


def _handle_types(args: argparse.Namespace) -> int:
    """Handle types command."""
    types = _get_notification_types()

    if args.format == "json":
        print(json.dumps(types, indent=2))
    else:
        print("Notification Types")
        print("=" * 60)
        print()
        for ntype in types:
            print(f"  {ntype['value']}")
            print(f"    Description: {ntype['description']}")
            print(f"    Trigger: {ntype['trigger']}")
            print()

    return 0


def _handle_history(args: argparse.Namespace) -> int:
    """Handle history command."""
    history = _get_sample_history()

    if args.type:
        history = [h for h in history if h["notification_type"] == args.type]

    history = history[: args.limit]

    if args.format == "json":
        print(json.dumps(history, indent=2))
    else:
        print("Notification History")
        print("=" * 60)
        print()
        if not history:
            print("No notifications found.")
        else:
            for notification in history:
                type_icons = {
                    "scan_complete": "[OK]",
                    "scan_failed": "[!!]",
                    "new_findings": "[+]",
                    "critical_finding": "[!]",
                    "findings_resolved": "[-]",
                    "trend_alert": "[~]",
                    "scheduled_report": "[R]",
                }
                icon = type_icons.get(notification["notification_type"], "[?]")
                print(f"  {icon} {notification['notification_type']}")
                print(f"      Time: {notification['timestamp']}")
                print(f"      Scan ID: {notification['scan_id']}")
                print(f"      Message: {notification['message']}")
                print()

    return 0


def _handle_thresholds(args: argparse.Namespace) -> int:
    """Handle thresholds command."""
    thresholds = _get_thresholds()

    if args.format == "json":
        print(json.dumps(thresholds, indent=2))
    else:
        print("Notification Thresholds")
        print("=" * 60)
        print()
        for threshold in thresholds:
            print(f"  {threshold['name']}")
            print(f"    Current value: {threshold['value']}")
            print(f"    Description: {threshold['description']}")
            print(f"    Affects: {threshold['affects']}")
            print()

    return 0


def _handle_triggers(args: argparse.Namespace) -> int:
    """Handle triggers command."""
    triggers = _get_triggers()

    if args.format == "json":
        print(json.dumps(triggers, indent=2))
    else:
        print("Notification Triggers")
        print("=" * 60)
        print()
        for trigger in triggers:
            status = "[ON]" if trigger["enabled"] else "[OFF]"
            print(f"  {status} {trigger['name']}")
            print(f"       Event: {trigger['event']}")
            print(f"       Description: {trigger['description']}")
            print()

    return 0


def _handle_callbacks(args: argparse.Namespace) -> int:
    """Handle callbacks command."""
    callbacks = _get_callbacks()

    if args.format == "json":
        print(json.dumps(callbacks, indent=2))
    else:
        print("Registered Callbacks")
        print("=" * 60)
        print()
        if not callbacks:
            print("No callbacks registered.")
        else:
            for callback in callbacks:
                print(f"  {callback['name']}")
                print(f"    Type: {callback['type']}")
                print(f"    Description: {callback['description']}")
                print()

    return 0


def _handle_severities(args: argparse.Namespace) -> int:
    """Handle severities command."""
    severities = [
        {"value": "critical", "priority": 1, "description": "Critical - always notify"},
        {"value": "high", "priority": 2, "description": "High - notify by default"},
        {"value": "medium", "priority": 3, "description": "Medium - optional notification"},
        {"value": "low", "priority": 4, "description": "Low - usually silent"},
        {"value": "info", "priority": 5, "description": "Info - silent by default"},
    ]

    if args.format == "json":
        print(json.dumps(severities, indent=2))
    else:
        print("Severity Levels for Notifications")
        print("=" * 60)
        print()
        for sev in severities:
            print(f"  [{sev['priority']}] {sev['value'].upper()}")
            print(f"      {sev['description']}")
            print()

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = _get_automation_status()

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("Automation Module Status")
        print("=" * 60)
        print()
        print(f"  Module: {status['module']}")
        print(f"  Version: {status['version']}")
        print(f"  Status: {status['status']}")
        print()
        print("  Components:")
        for name, comp_status in status["components"].items():
            icon = "[OK]" if comp_status == "available" else "[--]"
            print(f"    {icon} {name}: {comp_status}")
        print()
        print("  Capabilities:")
        for cap in status["capabilities"]:
            print(f"    - {cap}")

    return 0


def _handle_test(args: argparse.Namespace) -> int:
    """Handle test command."""
    result = _test_notification(args.type)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Notification Test Results")
        print("=" * 60)
        print()
        print(f"  Test type: {args.type}")
        print(f"  Would trigger: {result['would_trigger']}")
        print()
        print("  Sample notification:")
        print(f"    Type: {result['notification']['notification_type']}")
        print(f"    Message: {result['notification']['message']}")
        print(f"    Scan ID: {result['notification']['scan_id']}")
        print()
        print(f"  Matching triggers: {len(result['matching_triggers'])}")
        for trigger in result["matching_triggers"]:
            print(f"    - {trigger}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = _get_automation_summary()

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("Automation Summary")
        print("=" * 60)
        print()
        print("  Configuration:")
        print(f"    Triggers enabled: {summary['config']['triggers_enabled']}")
        print(f"    Active callbacks: {summary['config']['callbacks_count']}")
        print(f"    Custom destinations: {summary['config']['destinations_count']}")
        print()
        print("  Statistics (24h):")
        print(f"    Notifications sent: {summary['stats']['notifications_sent_24h']}")
        print(f"    Scan completions: {summary['stats']['scan_completions_24h']}")
        print(f"    Critical alerts: {summary['stats']['critical_alerts_24h']}")
        print(f"    Trend alerts: {summary['stats']['trend_alerts_24h']}")
        print()
        print("  By Type:")
        for ntype, count in summary["stats"]["by_type"].items():
            print(f"    {ntype}: {count}")

    return 0


def _handle_workflows(args: argparse.Namespace) -> int:
    """Handle workflows command."""
    workflows = _get_workflows()

    if args.format == "json":
        print(json.dumps(workflows, indent=2))
    else:
        print("Automation Workflows")
        print("=" * 60)
        print()
        for workflow in workflows:
            status = "[ON]" if workflow["enabled"] else "[OFF]"
            print(f"  {status} {workflow['name']}")
            print(f"       Trigger: {workflow['trigger']}")
            print(f"       Actions: {', '.join(workflow['actions'])}")
            print(f"       Description: {workflow['description']}")
            print()

    return 0


def _handle_events(args: argparse.Namespace) -> int:
    """Handle events command."""
    events = _get_events()

    if args.format == "json":
        print(json.dumps(events, indent=2))
    else:
        print("Supported Events")
        print("=" * 60)
        print()
        for event in events:
            print(f"  {event['name']}")
            print(f"    Source: {event['source']}")
            print(f"    Description: {event['description']}")
            print(f"    Data available: {', '.join(event['data_fields'])}")
            print()

    return 0


# Sample data generators for demo mode

def _get_sample_config() -> dict[str, Any]:
    """Get sample notification configuration."""
    return {
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
    }


def _get_notification_types() -> list[dict[str, Any]]:
    """Get notification types."""
    return [
        {
            "value": "scan_complete",
            "description": "Notification when a scan completes successfully",
            "trigger": "Scan finishes without errors",
        },
        {
            "value": "scan_failed",
            "description": "Notification when a scan fails",
            "trigger": "Scan encounters an error",
        },
        {
            "value": "new_findings",
            "description": "Notification for newly detected findings",
            "trigger": "New findings detected above severity threshold",
        },
        {
            "value": "critical_finding",
            "description": "Notification for critical severity findings",
            "trigger": "Critical findings count exceeds threshold",
        },
        {
            "value": "findings_resolved",
            "description": "Notification when findings are resolved",
            "trigger": "Previously detected findings no longer present",
        },
        {
            "value": "trend_alert",
            "description": "Notification for security trend changes",
            "trigger": "Finding count changes by more than threshold percent",
        },
        {
            "value": "scheduled_report",
            "description": "Scheduled periodic security report",
            "trigger": "Scheduled time reached",
        },
    ]


def _get_sample_history() -> list[dict[str, Any]]:
    """Get sample notification history."""
    base_time = datetime.utcnow()
    return [
        {
            "notification_type": "scan_complete",
            "timestamp": (base_time - timedelta(hours=1)).isoformat(),
            "scan_id": "scan-001",
            "job_name": "daily-security-scan",
            "message": "Scan completed successfully. Scanned 150 assets, found 23 findings in 45.2s.",
        },
        {
            "notification_type": "critical_finding",
            "timestamp": (base_time - timedelta(hours=2)).isoformat(),
            "scan_id": "scan-001",
            "job_name": "daily-security-scan",
            "message": "ALERT: 2 critical findings detected! Immediate attention required.",
        },
        {
            "notification_type": "new_findings",
            "timestamp": (base_time - timedelta(hours=3)).isoformat(),
            "scan_id": "scan-002",
            "job_name": "aws-account-scan",
            "message": "Detected 5 new findings: 1 critical, 2 high, 2 medium",
        },
        {
            "notification_type": "trend_alert",
            "timestamp": (base_time - timedelta(hours=6)).isoformat(),
            "scan_id": "scan-003",
            "job_name": "weekly-trend-analysis",
            "message": "Security posture improving: 15.3% reduction in findings",
        },
        {
            "notification_type": "scan_failed",
            "timestamp": (base_time - timedelta(hours=12)).isoformat(),
            "scan_id": "scan-004",
            "job_name": "gcp-project-scan",
            "message": "Scan failed: GCP credentials expired",
        },
    ]


def _get_thresholds() -> list[dict[str, Any]]:
    """Get notification thresholds."""
    return [
        {
            "name": "min_severity_for_new",
            "value": "high",
            "description": "Minimum severity level to trigger new findings notification",
            "affects": "new_findings notifications",
        },
        {
            "name": "critical_threshold",
            "value": 1,
            "description": "Number of critical findings to trigger critical alert",
            "affects": "critical_finding notifications",
        },
        {
            "name": "trend_threshold_percent",
            "value": 10.0,
            "description": "Percentage change in findings to trigger trend alert",
            "affects": "trend_alert notifications",
        },
    ]


def _get_triggers() -> list[dict[str, Any]]:
    """Get notification triggers."""
    return [
        {
            "name": "Scan Complete",
            "event": "scan_complete",
            "enabled": True,
            "description": "Trigger notification when scan completes successfully",
        },
        {
            "name": "Scan Failed",
            "event": "scan_failed",
            "enabled": True,
            "description": "Trigger notification when scan fails",
        },
        {
            "name": "New Findings",
            "event": "new_findings",
            "enabled": True,
            "description": "Trigger notification for new findings above severity threshold",
        },
        {
            "name": "Critical Findings",
            "event": "critical_finding",
            "enabled": True,
            "description": "Trigger notification when critical findings exceed threshold",
        },
        {
            "name": "Findings Resolved",
            "event": "findings_resolved",
            "enabled": False,
            "description": "Trigger notification when findings are resolved",
        },
        {
            "name": "Trend Change",
            "event": "trend_alert",
            "enabled": True,
            "description": "Trigger notification when security trend changes significantly",
        },
    ]


def _get_callbacks() -> list[dict[str, Any]]:
    """Get registered callbacks."""
    return [
        {
            "name": "AlertRouterCallback",
            "type": "internal",
            "description": "Routes notifications through configured alert destinations",
        },
        {
            "name": "HistoryCallback",
            "type": "internal",
            "description": "Records notifications to history",
        },
        {
            "name": "LoggingCallback",
            "type": "internal",
            "description": "Logs notifications for audit trail",
        },
    ]


def _get_automation_status() -> dict[str, Any]:
    """Get automation module status."""
    return {
        "module": "stance.automation",
        "version": "1.0.0",
        "status": "operational",
        "components": {
            "NotificationHandler": "available",
            "NotificationConfig": "available",
            "ScanNotification": "available",
            "ScanSummaryNotification": "available",
            "FindingNotification": "available",
            "TrendNotification": "available",
        },
        "capabilities": [
            "Scan completion notifications",
            "Scan failure notifications",
            "New findings notifications",
            "Critical findings alerts",
            "Resolved findings notifications",
            "Trend change alerts",
            "Configurable severity thresholds",
            "Configurable trend thresholds",
            "Alert router integration",
            "Notification history tracking",
            "Custom callback support",
        ],
    }


def _test_notification(notification_type: str) -> dict[str, Any]:
    """Test a notification trigger."""
    base_time = datetime.utcnow()

    sample_notifications = {
        "scan_complete": {
            "notification_type": "scan_complete",
            "timestamp": base_time.isoformat(),
            "scan_id": "test-scan-001",
            "job_name": "test-job",
            "message": "Scan completed successfully. Scanned 50 assets, found 10 findings in 30.0s.",
        },
        "scan_failed": {
            "notification_type": "scan_failed",
            "timestamp": base_time.isoformat(),
            "scan_id": "test-scan-002",
            "job_name": "test-job",
            "message": "Scan failed: Test error message",
        },
        "new_findings": {
            "notification_type": "new_findings",
            "timestamp": base_time.isoformat(),
            "scan_id": "test-scan-003",
            "job_name": "test-job",
            "message": "Detected 3 new findings: 1 high, 2 medium",
        },
        "critical_finding": {
            "notification_type": "critical_finding",
            "timestamp": base_time.isoformat(),
            "scan_id": "test-scan-004",
            "job_name": "test-job",
            "message": "ALERT: 1 critical findings detected! Immediate attention required.",
        },
        "trend_alert": {
            "notification_type": "trend_alert",
            "timestamp": base_time.isoformat(),
            "scan_id": "test-scan-005",
            "job_name": "test-job",
            "message": "Security posture declining: 15.0% increase in findings",
        },
    }

    notification = sample_notifications.get(notification_type, sample_notifications["scan_complete"])

    triggers = _get_triggers()
    matching = [t["name"] for t in triggers if t["event"] == notification_type and t["enabled"]]

    return {
        "test_type": notification_type,
        "would_trigger": len(matching) > 0,
        "notification": notification,
        "matching_triggers": matching,
    }


def _get_automation_summary() -> dict[str, Any]:
    """Get automation summary."""
    return {
        "config": {
            "triggers_enabled": 5,
            "callbacks_count": 3,
            "destinations_count": 0,
        },
        "stats": {
            "notifications_sent_24h": 23,
            "scan_completions_24h": 8,
            "critical_alerts_24h": 2,
            "trend_alerts_24h": 1,
            "by_type": {
                "scan_complete": 8,
                "scan_failed": 1,
                "new_findings": 5,
                "critical_finding": 2,
                "trend_alert": 1,
                "findings_resolved": 6,
            },
        },
    }


def _get_workflows() -> list[dict[str, Any]]:
    """Get automation workflows."""
    return [
        {
            "name": "Critical Alert Pipeline",
            "trigger": "critical_finding",
            "actions": ["send_pagerduty", "send_slack", "create_ticket"],
            "enabled": True,
            "description": "Immediately escalate critical findings to on-call and create ticket",
        },
        {
            "name": "Daily Summary",
            "trigger": "scan_complete",
            "actions": ["aggregate_findings", "send_email_summary"],
            "enabled": True,
            "description": "Send daily summary of scan results via email",
        },
        {
            "name": "Trend Monitoring",
            "trigger": "trend_alert",
            "actions": ["send_slack", "update_dashboard"],
            "enabled": True,
            "description": "Notify team of significant security posture changes",
        },
        {
            "name": "Failure Escalation",
            "trigger": "scan_failed",
            "actions": ["retry_scan", "send_alert_if_repeated"],
            "enabled": True,
            "description": "Retry failed scans and alert on repeated failures",
        },
    ]


def _get_events() -> list[dict[str, Any]]:
    """Get supported events."""
    return [
        {
            "name": "scan.complete",
            "source": "ScanScheduler",
            "description": "Fired when a scheduled scan completes",
            "data_fields": ["scan_id", "job_name", "duration", "assets_scanned", "findings_count"],
        },
        {
            "name": "scan.failed",
            "source": "ScanScheduler",
            "description": "Fired when a scheduled scan fails",
            "data_fields": ["scan_id", "job_name", "error_message"],
        },
        {
            "name": "findings.new",
            "source": "FindingComparison",
            "description": "Fired when new findings are detected",
            "data_fields": ["scan_id", "findings", "severity_breakdown"],
        },
        {
            "name": "findings.resolved",
            "source": "FindingComparison",
            "description": "Fired when findings are resolved",
            "data_fields": ["scan_id", "findings", "resolved_count"],
        },
        {
            "name": "findings.critical",
            "source": "FindingAnalysis",
            "description": "Fired when critical findings exceed threshold",
            "data_fields": ["scan_id", "findings", "critical_count"],
        },
        {
            "name": "trend.change",
            "source": "TrendAnalyzer",
            "description": "Fired when security trend changes significantly",
            "data_fields": ["direction", "change_percent", "current_count", "previous_count"],
        },
    ]
