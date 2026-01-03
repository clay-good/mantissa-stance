"""
CLI commands for Notifications management.

Provides command-line interface for managing notifications configuration,
viewing notification history, and controlling notification behavior.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
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
from stance.models.finding import Severity


# Global notification handler instance
_notification_handler: NotificationHandler | None = None


def get_notification_handler() -> NotificationHandler:
    """Get or create the global notification handler."""
    global _notification_handler
    if _notification_handler is None:
        _notification_handler = NotificationHandler()
    return _notification_handler


def _format_notification_table(notifications: list[ScanNotification]) -> str:
    """Format notifications as a table."""
    if not notifications:
        return "No notifications found."

    # Calculate column widths
    type_width = max(len(n.notification_type.value) for n in notifications)
    scan_id_width = min(max(len(n.scan_id[:12]) for n in notifications), 12)

    # Build table
    lines = []
    header = f"{'Type':<{type_width}}  {'Scan ID':<{scan_id_width}}  {'Timestamp':<20}  Message"
    lines.append(header)
    lines.append("-" * max(len(header), 80))

    for notif in notifications:
        scan_id = notif.scan_id[:12] if notif.scan_id else ""
        timestamp = notif.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        message = notif.message[:50]
        if len(notif.message) > 50:
            message += "..."

        line = f"{notif.notification_type.value:<{type_width}}  {scan_id:<{scan_id_width}}  {timestamp:<20}  {message}"
        lines.append(line)

    return "\n".join(lines)


def _format_notification_detail(notif: ScanNotification, verbose: bool = False) -> str:
    """Format notification details."""
    lines = []
    lines.append(f"Type: {notif.notification_type.value}")
    lines.append(f"Timestamp: {notif.timestamp.isoformat()}")
    lines.append(f"Scan ID: {notif.scan_id}")
    if notif.job_name:
        lines.append(f"Job Name: {notif.job_name}")
    lines.append(f"Config Name: {notif.config_name}")
    lines.append(f"Message: {notif.message}")

    # Type-specific details
    if isinstance(notif, ScanSummaryNotification):
        lines.append(f"Success: {notif.success}")
        lines.append(f"Duration: {notif.duration_seconds:.2f}s")
        lines.append(f"Assets Scanned: {notif.assets_scanned}")
        lines.append(f"Total Findings: {notif.findings_total}")
        if notif.findings_by_severity:
            lines.append(f"By Severity: {json.dumps(notif.findings_by_severity)}")
        if notif.error_message:
            lines.append(f"Error: {notif.error_message}")

    elif isinstance(notif, FindingNotification):
        lines.append(f"Is New: {notif.is_new}")
        lines.append(f"Is Resolved: {notif.is_resolved}")
        lines.append(f"Findings Count: {len(notif.findings)}")
        if verbose and notif.findings:
            lines.append("Finding IDs:")
            for f in notif.findings[:10]:  # Limit to first 10
                lines.append(f"  - {f.id}")
            if len(notif.findings) > 10:
                lines.append(f"  ... and {len(notif.findings) - 10} more")

    elif isinstance(notif, TrendNotification):
        lines.append(f"Direction: {notif.direction}")
        lines.append(f"Change: {notif.change_percent:.1f}%")
        lines.append(f"Current Findings: {notif.current_findings}")
        lines.append(f"Previous Findings: {notif.previous_findings}")
        lines.append(f"Period: {notif.period_days} days")

    if verbose and notif.details:
        lines.append(f"Details: {json.dumps(notif.details, indent=2)}")

    return "\n".join(lines)


def _format_config(config: NotificationConfig) -> str:
    """Format notification configuration."""
    lines = []
    lines.append("Notification Configuration:")
    lines.append("-" * 40)
    lines.append(f"  Notify on scan complete: {config.notify_on_scan_complete}")
    lines.append(f"  Notify on scan failure: {config.notify_on_scan_failure}")
    lines.append(f"  Notify on new findings: {config.notify_on_new_findings}")
    lines.append(f"  Notify on critical: {config.notify_on_critical}")
    lines.append(f"  Notify on resolved: {config.notify_on_resolved}")
    lines.append(f"  Notify on trend change: {config.notify_on_trend_change}")
    lines.append(f"  Min severity for new: {config.min_severity_for_new.value}")
    lines.append(f"  Critical threshold: {config.critical_threshold}")
    lines.append(f"  Trend threshold percent: {config.trend_threshold_percent}%")
    lines.append(f"  Include summary: {config.include_summary}")
    lines.append(f"  Include details: {config.include_details}")
    if config.destinations:
        lines.append(f"  Destinations: {', '.join(config.destinations)}")
    return "\n".join(lines)


def cmd_notifications(args: argparse.Namespace) -> int:
    """Handle notifications commands."""
    action = getattr(args, 'notifications_action', None)

    if action is None:
        print("Usage: stance notifications <command>")
        print("\nCommands:")
        print("  list         List notification history")
        print("  show         Show notification details")
        print("  types        List notification types")
        print("  config       Show current configuration")
        print("  set          Set configuration option")
        print("  enable       Enable a notification type")
        print("  disable      Disable a notification type")
        print("  clear        Clear notification history")
        print("  test         Send a test notification")
        print("  status       Show notifications module status")
        return 0

    handlers = {
        'list': _handle_notifications_list,
        'show': _handle_notifications_show,
        'types': _handle_notifications_types,
        'config': _handle_notifications_config,
        'set': _handle_notifications_set,
        'enable': _handle_notifications_enable,
        'disable': _handle_notifications_disable,
        'clear': _handle_notifications_clear,
        'test': _handle_notifications_test,
        'status': _handle_notifications_status,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)
    else:
        print(f"Unknown notifications action: {action}", file=sys.stderr)
        return 1


def _handle_notifications_list(args: argparse.Namespace) -> int:
    """Handle notifications list command."""
    output_format = getattr(args, 'format', 'table')
    limit = getattr(args, 'limit', 50)
    notification_type = getattr(args, 'type', None)
    demo = getattr(args, 'demo', False)

    if demo:
        # Demo mode: generate sample notifications
        notifications = _get_demo_notifications()
    else:
        handler = get_notification_handler()
        type_filter = None
        if notification_type:
            try:
                type_filter = NotificationType(notification_type)
            except ValueError:
                print(f"Invalid notification type: {notification_type}", file=sys.stderr)
                return 1

        notifications = handler.get_history(limit=limit, notification_type=type_filter)

    if output_format == 'json':
        output = [n.to_dict() for n in notifications]
        print(json.dumps(output, indent=2, default=str))
    else:
        print(_format_notification_table(notifications))
        print(f"\nTotal: {len(notifications)} notifications")

    return 0


def _handle_notifications_show(args: argparse.Namespace) -> int:
    """Handle notifications show command."""
    index = getattr(args, 'index', 0)
    verbose = getattr(args, 'verbose', False)
    output_format = getattr(args, 'format', 'text')
    demo = getattr(args, 'demo', False)

    if demo:
        notifications = _get_demo_notifications()
    else:
        handler = get_notification_handler()
        notifications = handler.get_history()

    if not notifications:
        print("No notifications found.", file=sys.stderr)
        return 1

    if index < 0 or index >= len(notifications):
        print(f"Invalid index: {index}. Valid range: 0-{len(notifications)-1}", file=sys.stderr)
        return 1

    notif = notifications[index]

    if output_format == 'json':
        print(json.dumps(notif.to_dict(), indent=2, default=str))
    else:
        print(_format_notification_detail(notif, verbose))

    return 0


def _handle_notifications_types(args: argparse.Namespace) -> int:
    """Handle notifications types command."""
    output_format = getattr(args, 'format', 'table')

    types_info = [
        {
            "value": NotificationType.SCAN_COMPLETE.value,
            "name": "Scan Complete",
            "description": "Scan finished successfully",
        },
        {
            "value": NotificationType.SCAN_FAILED.value,
            "name": "Scan Failed",
            "description": "Scan encountered an error",
        },
        {
            "value": NotificationType.NEW_FINDINGS.value,
            "name": "New Findings",
            "description": "New findings detected in scan",
        },
        {
            "value": NotificationType.CRITICAL_FINDING.value,
            "name": "Critical Finding",
            "description": "Critical severity finding detected",
        },
        {
            "value": NotificationType.FINDINGS_RESOLVED.value,
            "name": "Findings Resolved",
            "description": "Previously detected findings are now resolved",
        },
        {
            "value": NotificationType.TREND_ALERT.value,
            "name": "Trend Alert",
            "description": "Security trend change (improving/declining)",
        },
        {
            "value": NotificationType.SCHEDULED_REPORT.value,
            "name": "Scheduled Report",
            "description": "Periodic scheduled report notification",
        },
    ]

    if output_format == 'json':
        print(json.dumps(types_info, indent=2))
    else:
        print("Notification Types:")
        print("-" * 60)
        for t in types_info:
            print(f"  {t['value']:<20} - {t['description']}")

    return 0


def _handle_notifications_config(args: argparse.Namespace) -> int:
    """Handle notifications config command."""
    output_format = getattr(args, 'format', 'text')
    demo = getattr(args, 'demo', False)

    if demo:
        config = NotificationConfig()
    else:
        handler = get_notification_handler()
        config = handler.config

    if output_format == 'json':
        print(json.dumps(config.to_dict(), indent=2))
    else:
        print(_format_config(config))

    return 0


def _handle_notifications_set(args: argparse.Namespace) -> int:
    """Handle notifications set command."""
    option = getattr(args, 'option', None)
    value = getattr(args, 'value', None)
    demo = getattr(args, 'demo', False)

    if not option or value is None:
        print("Usage: stance notifications set <option> <value>", file=sys.stderr)
        print("\nAvailable options:")
        print("  notify_on_scan_complete <true|false>")
        print("  notify_on_scan_failure <true|false>")
        print("  notify_on_new_findings <true|false>")
        print("  notify_on_critical <true|false>")
        print("  notify_on_resolved <true|false>")
        print("  notify_on_trend_change <true|false>")
        print("  min_severity <critical|high|medium|low|info>")
        print("  critical_threshold <number>")
        print("  trend_threshold <percent>")
        print("  include_summary <true|false>")
        print("  include_details <true|false>")
        return 1

    if demo:
        print(f"[Demo] Would set {option} = {value}")
        return 0

    handler = get_notification_handler()
    config = handler.config

    # Parse and apply setting
    bool_options = {
        'notify_on_scan_complete': 'notify_on_scan_complete',
        'notify_on_scan_failure': 'notify_on_scan_failure',
        'notify_on_new_findings': 'notify_on_new_findings',
        'notify_on_critical': 'notify_on_critical',
        'notify_on_resolved': 'notify_on_resolved',
        'notify_on_trend_change': 'notify_on_trend_change',
        'include_summary': 'include_summary',
        'include_details': 'include_details',
    }

    if option in bool_options:
        bool_value = value.lower() in ('true', '1', 'yes', 'on')
        setattr(config, bool_options[option], bool_value)
        print(f"Set {option} = {bool_value}")

    elif option == 'min_severity':
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO,
        }
        if value.lower() not in severity_map:
            print(f"Invalid severity: {value}", file=sys.stderr)
            return 1
        config.min_severity_for_new = severity_map[value.lower()]
        print(f"Set min_severity = {value}")

    elif option == 'critical_threshold':
        try:
            config.critical_threshold = int(value)
            print(f"Set critical_threshold = {config.critical_threshold}")
        except ValueError:
            print(f"Invalid number: {value}", file=sys.stderr)
            return 1

    elif option == 'trend_threshold':
        try:
            config.trend_threshold_percent = float(value)
            print(f"Set trend_threshold = {config.trend_threshold_percent}%")
        except ValueError:
            print(f"Invalid number: {value}", file=sys.stderr)
            return 1

    else:
        print(f"Unknown option: {option}", file=sys.stderr)
        return 1

    handler.configure(config)
    return 0


def _handle_notifications_enable(args: argparse.Namespace) -> int:
    """Handle notifications enable command."""
    notification_type = getattr(args, 'type', None)
    demo = getattr(args, 'demo', False)

    if not notification_type:
        print("Usage: stance notifications enable <type>", file=sys.stderr)
        print("\nAvailable types:")
        print("  scan_complete    - Notify when scan completes")
        print("  scan_failed      - Notify when scan fails")
        print("  new_findings     - Notify on new findings")
        print("  critical         - Notify on critical findings")
        print("  resolved         - Notify on resolved findings")
        print("  trend_change     - Notify on trend changes")
        print("  all              - Enable all notification types")
        return 1

    if demo:
        print(f"[Demo] Would enable notification type: {notification_type}")
        return 0

    handler = get_notification_handler()
    config = handler.config

    type_map = {
        'scan_complete': 'notify_on_scan_complete',
        'scan_failed': 'notify_on_scan_failure',
        'new_findings': 'notify_on_new_findings',
        'critical': 'notify_on_critical',
        'resolved': 'notify_on_resolved',
        'trend_change': 'notify_on_trend_change',
    }

    if notification_type == 'all':
        for attr in type_map.values():
            setattr(config, attr, True)
        print("Enabled all notification types")
    elif notification_type in type_map:
        setattr(config, type_map[notification_type], True)
        print(f"Enabled {notification_type} notifications")
    else:
        print(f"Unknown notification type: {notification_type}", file=sys.stderr)
        return 1

    handler.configure(config)
    return 0


def _handle_notifications_disable(args: argparse.Namespace) -> int:
    """Handle notifications disable command."""
    notification_type = getattr(args, 'type', None)
    demo = getattr(args, 'demo', False)

    if not notification_type:
        print("Usage: stance notifications disable <type>", file=sys.stderr)
        print("\nAvailable types:")
        print("  scan_complete    - Notify when scan completes")
        print("  scan_failed      - Notify when scan fails")
        print("  new_findings     - Notify on new findings")
        print("  critical         - Notify on critical findings")
        print("  resolved         - Notify on resolved findings")
        print("  trend_change     - Notify on trend changes")
        print("  all              - Disable all notification types")
        return 1

    if demo:
        print(f"[Demo] Would disable notification type: {notification_type}")
        return 0

    handler = get_notification_handler()
    config = handler.config

    type_map = {
        'scan_complete': 'notify_on_scan_complete',
        'scan_failed': 'notify_on_scan_failure',
        'new_findings': 'notify_on_new_findings',
        'critical': 'notify_on_critical',
        'resolved': 'notify_on_resolved',
        'trend_change': 'notify_on_trend_change',
    }

    if notification_type == 'all':
        for attr in type_map.values():
            setattr(config, attr, False)
        print("Disabled all notification types")
    elif notification_type in type_map:
        setattr(config, type_map[notification_type], False)
        print(f"Disabled {notification_type} notifications")
    else:
        print(f"Unknown notification type: {notification_type}", file=sys.stderr)
        return 1

    handler.configure(config)
    return 0


def _handle_notifications_clear(args: argparse.Namespace) -> int:
    """Handle notifications clear command."""
    demo = getattr(args, 'demo', False)
    force = getattr(args, 'force', False)

    if demo:
        print("[Demo] Would clear notification history")
        return 0

    if not force:
        print("This will clear all notification history. Use --force to confirm.", file=sys.stderr)
        return 1

    handler = get_notification_handler()
    handler.clear_history()
    print("Notification history cleared.")
    return 0


def _handle_notifications_test(args: argparse.Namespace) -> int:
    """Handle notifications test command."""
    notification_type = getattr(args, 'type', 'scan_complete')
    demo = getattr(args, 'demo', False)

    if demo:
        print(f"[Demo] Would send test notification of type: {notification_type}")
        _print_test_notification(notification_type)
        return 0

    # Create and send a test notification
    handler = get_notification_handler()

    test_notif = _create_test_notification(notification_type)
    if test_notif is None:
        print(f"Unknown notification type: {notification_type}", file=sys.stderr)
        return 1

    # Add to history manually for test
    handler._notification_history.append(test_notif)
    print(f"Test notification sent: {notification_type}")
    print(_format_notification_detail(test_notif))
    return 0


def _handle_notifications_status(args: argparse.Namespace) -> int:
    """Handle notifications status command."""
    output_format = getattr(args, 'format', 'text')
    demo = getattr(args, 'demo', False)

    if demo:
        handler = NotificationHandler()
        history_count = 5  # Demo count
    else:
        handler = get_notification_handler()
        history_count = len(handler._notification_history)

    config = handler.config

    status = {
        "module": "notifications",
        "status": "active",
        "history_count": history_count,
        "max_history": handler._max_history,
        "callbacks_registered": len(handler._callbacks),
        "router_configured": handler._router is not None,
        "config": config.to_dict(),
        "enabled_types": [],
    }

    # Determine enabled types
    if config.notify_on_scan_complete:
        status["enabled_types"].append("scan_complete")
    if config.notify_on_scan_failure:
        status["enabled_types"].append("scan_failed")
    if config.notify_on_new_findings:
        status["enabled_types"].append("new_findings")
    if config.notify_on_critical:
        status["enabled_types"].append("critical")
    if config.notify_on_resolved:
        status["enabled_types"].append("resolved")
    if config.notify_on_trend_change:
        status["enabled_types"].append("trend_change")

    if output_format == 'json':
        print(json.dumps(status, indent=2))
    else:
        print("Notifications Module Status")
        print("=" * 40)
        print(f"  Status: {status['status']}")
        print(f"  History count: {status['history_count']}/{status['max_history']}")
        print(f"  Callbacks registered: {status['callbacks_registered']}")
        print(f"  Router configured: {status['router_configured']}")
        print(f"  Enabled types: {', '.join(status['enabled_types']) if status['enabled_types'] else 'none'}")
        print()
        print(_format_config(config))

    return 0


def _get_demo_notifications() -> list[ScanNotification]:
    """Generate demo notifications."""
    now = datetime.now(timezone.utc)

    return [
        ScanSummaryNotification(
            notification_type=NotificationType.SCAN_COMPLETE,
            timestamp=now,
            scan_id="scan-demo-001",
            job_name="daily-security-scan",
            config_name="default",
            message="Scan completed successfully. Scanned 150 assets, found 23 findings in 45.2s.",
            success=True,
            duration_seconds=45.2,
            assets_scanned=150,
            findings_total=23,
            findings_by_severity={"critical": 2, "high": 5, "medium": 8, "low": 8},
        ),
        FindingNotification(
            notification_type=NotificationType.CRITICAL_FINDING,
            timestamp=now,
            scan_id="scan-demo-001",
            job_name="daily-security-scan",
            config_name="default",
            message="ALERT: 2 critical findings detected! Immediate attention required.",
            findings=[],
            is_new=True,
        ),
        FindingNotification(
            notification_type=NotificationType.NEW_FINDINGS,
            timestamp=now,
            scan_id="scan-demo-001",
            job_name="daily-security-scan",
            config_name="default",
            message="Detected 5 new findings: 1 critical, 2 high, 2 medium",
            findings=[],
            is_new=True,
        ),
        TrendNotification(
            notification_type=NotificationType.TREND_ALERT,
            timestamp=now,
            scan_id="scan-demo-002",
            job_name="weekly-trend-analysis",
            config_name="default",
            message="Security posture declining: 15.3% increase in findings",
            direction="declining",
            change_percent=15.3,
            current_findings=45,
            previous_findings=39,
            period_days=7,
        ),
        ScanSummaryNotification(
            notification_type=NotificationType.SCAN_FAILED,
            timestamp=now,
            scan_id="scan-demo-003",
            job_name="aws-account-scan",
            config_name="aws-production",
            message="Scan failed: AWS credentials expired",
            success=False,
            error_message="AWS credentials expired",
        ),
    ]


def _create_test_notification(notification_type: str) -> ScanNotification | None:
    """Create a test notification of the specified type."""
    now = datetime.now(timezone.utc)

    type_map = {
        'scan_complete': lambda: ScanSummaryNotification(
            notification_type=NotificationType.SCAN_COMPLETE,
            timestamp=now,
            scan_id=f"test-{now.strftime('%Y%m%d%H%M%S')}",
            message="Test: Scan completed successfully.",
            success=True,
            duration_seconds=10.0,
            assets_scanned=10,
            findings_total=3,
        ),
        'scan_failed': lambda: ScanSummaryNotification(
            notification_type=NotificationType.SCAN_FAILED,
            timestamp=now,
            scan_id=f"test-{now.strftime('%Y%m%d%H%M%S')}",
            message="Test: Scan failed.",
            success=False,
            error_message="Test error message",
        ),
        'new_findings': lambda: FindingNotification(
            notification_type=NotificationType.NEW_FINDINGS,
            timestamp=now,
            scan_id=f"test-{now.strftime('%Y%m%d%H%M%S')}",
            message="Test: 3 new findings detected.",
            findings=[],
            is_new=True,
        ),
        'critical': lambda: FindingNotification(
            notification_type=NotificationType.CRITICAL_FINDING,
            timestamp=now,
            scan_id=f"test-{now.strftime('%Y%m%d%H%M%S')}",
            message="Test: ALERT - Critical finding detected!",
            findings=[],
            is_new=True,
        ),
        'resolved': lambda: FindingNotification(
            notification_type=NotificationType.FINDINGS_RESOLVED,
            timestamp=now,
            scan_id=f"test-{now.strftime('%Y%m%d%H%M%S')}",
            message="Test: 2 findings resolved.",
            findings=[],
            is_resolved=True,
        ),
        'trend_alert': lambda: TrendNotification(
            notification_type=NotificationType.TREND_ALERT,
            timestamp=now,
            scan_id=f"test-{now.strftime('%Y%m%d%H%M%S')}",
            message="Test: Security posture improving.",
            direction="improving",
            change_percent=-10.5,
            current_findings=18,
            previous_findings=20,
            period_days=7,
        ),
    }

    creator = type_map.get(notification_type)
    return creator() if creator else None


def _print_test_notification(notification_type: str) -> None:
    """Print a preview of a test notification."""
    notif = _create_test_notification(notification_type)
    if notif:
        print("\nTest notification preview:")
        print("-" * 40)
        print(_format_notification_detail(notif))


def add_notifications_parser(subparsers: Any) -> None:
    """Add notifications command parser."""
    parser = subparsers.add_parser(
        'notifications',
        help='Manage notifications',
        description='Manage notification configuration, history, and settings',
    )
    parser.set_defaults(func=cmd_notifications)

    notifications_subparsers = parser.add_subparsers(
        dest='notifications_action',
        title='commands',
    )

    # List command
    list_parser = notifications_subparsers.add_parser(
        'list',
        help='List notification history',
        description='List notification history with optional filtering',
    )
    list_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )
    list_parser.add_argument(
        '--limit', '-n',
        type=int,
        default=50,
        help='Maximum notifications to show (default: 50)',
    )
    list_parser.add_argument(
        '--type', '-t',
        help='Filter by notification type',
    )
    list_parser.add_argument(
        '--demo',
        action='store_true',
        help='Use demo data',
    )

    # Show command
    show_parser = notifications_subparsers.add_parser(
        'show',
        help='Show notification details',
        description='Show detailed information about a notification',
    )
    show_parser.add_argument(
        'index',
        type=int,
        nargs='?',
        default=0,
        help='Notification index (0 = most recent)',
    )
    show_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
    show_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose details',
    )
    show_parser.add_argument(
        '--demo',
        action='store_true',
        help='Use demo data',
    )

    # Types command
    types_parser = notifications_subparsers.add_parser(
        'types',
        help='List notification types',
        description='List all available notification types',
    )
    types_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )

    # Config command
    config_parser = notifications_subparsers.add_parser(
        'config',
        help='Show current configuration',
        description='Show current notification configuration',
    )
    config_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
    config_parser.add_argument(
        '--demo',
        action='store_true',
        help='Use demo data',
    )

    # Set command
    set_parser = notifications_subparsers.add_parser(
        'set',
        help='Set configuration option',
        description='Set a notification configuration option',
    )
    set_parser.add_argument(
        'option',
        nargs='?',
        help='Configuration option name',
    )
    set_parser.add_argument(
        'value',
        nargs='?',
        help='Configuration value',
    )
    set_parser.add_argument(
        '--demo',
        action='store_true',
        help='Demo mode (no changes)',
    )

    # Enable command
    enable_parser = notifications_subparsers.add_parser(
        'enable',
        help='Enable a notification type',
        description='Enable notifications for a specific type',
    )
    enable_parser.add_argument(
        'type',
        nargs='?',
        help='Notification type to enable (or "all")',
    )
    enable_parser.add_argument(
        '--demo',
        action='store_true',
        help='Demo mode (no changes)',
    )

    # Disable command
    disable_parser = notifications_subparsers.add_parser(
        'disable',
        help='Disable a notification type',
        description='Disable notifications for a specific type',
    )
    disable_parser.add_argument(
        'type',
        nargs='?',
        help='Notification type to disable (or "all")',
    )
    disable_parser.add_argument(
        '--demo',
        action='store_true',
        help='Demo mode (no changes)',
    )

    # Clear command
    clear_parser = notifications_subparsers.add_parser(
        'clear',
        help='Clear notification history',
        description='Clear all notification history',
    )
    clear_parser.add_argument(
        '--force',
        action='store_true',
        help='Force clear without confirmation',
    )
    clear_parser.add_argument(
        '--demo',
        action='store_true',
        help='Demo mode (no changes)',
    )

    # Test command
    test_parser = notifications_subparsers.add_parser(
        'test',
        help='Send a test notification',
        description='Send a test notification of the specified type',
    )
    test_parser.add_argument(
        '--type', '-t',
        default='scan_complete',
        choices=['scan_complete', 'scan_failed', 'new_findings', 'critical', 'resolved', 'trend_alert'],
        help='Type of test notification to send (default: scan_complete)',
    )
    test_parser.add_argument(
        '--demo',
        action='store_true',
        help='Demo mode (preview only)',
    )

    # Status command
    status_parser = notifications_subparsers.add_parser(
        'status',
        help='Show notifications module status',
        description='Show status of the notifications module',
    )
    status_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
    status_parser.add_argument(
        '--demo',
        action='store_true',
        help='Use demo data',
    )
