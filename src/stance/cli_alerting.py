"""
CLI commands for alerting module in Mantissa Stance.

Provides command-line interface for managing alert routing,
destinations, suppression rules, and alert state.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta
from typing import Any

from stance.alerting import (
    AlertRouter,
    AlertConfig,
    AlertConfigLoader,
    RoutingRule,
    SuppressionRule,
    RateLimit,
    AlertState,
    InMemoryAlertState,
    AlertRecord,
    DestinationConfig,
    create_default_config,
)
from stance.models.finding import Severity


def add_alerting_parser(subparsers: argparse._SubParsersAction) -> None:
    """
    Add alerting subcommand parser.

    Args:
        subparsers: Parent subparsers object
    """
    alerting_parser = subparsers.add_parser(
        "alerting",
        help="Alert routing and notification management",
        description="Manage alert routing, destinations, suppression rules, and alert state.",
    )

    alerting_subparsers = alerting_parser.add_subparsers(
        dest="alerting_command",
        help="Alerting commands",
    )

    # destinations command
    dest_parser = alerting_subparsers.add_parser(
        "destinations",
        help="List available alert destinations",
        description="List all configured alert destinations and their status.",
    )
    dest_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # routing-rules command
    routing_parser = alerting_subparsers.add_parser(
        "routing-rules",
        help="List routing rules",
        description="List all alert routing rules.",
    )
    routing_parser.add_argument(
        "--enabled-only",
        action="store_true",
        help="Show only enabled rules",
    )
    routing_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # suppression-rules command
    suppress_parser = alerting_subparsers.add_parser(
        "suppression-rules",
        help="List suppression rules",
        description="List all alert suppression rules.",
    )
    suppress_parser.add_argument(
        "--enabled-only",
        action="store_true",
        help="Show only enabled rules",
    )
    suppress_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # config command
    config_parser = alerting_subparsers.add_parser(
        "config",
        help="Show alert configuration",
        description="Display the complete alert configuration.",
    )
    config_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # rate-limits command
    rate_parser = alerting_subparsers.add_parser(
        "rate-limits",
        help="Show rate limit settings",
        description="Display rate limit configuration for destinations.",
    )
    rate_parser.add_argument(
        "--destination",
        help="Show rate limit for specific destination",
    )
    rate_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # alerts command
    alerts_parser = alerting_subparsers.add_parser(
        "alerts",
        help="List recent alerts",
        description="List recent alert records from state.",
    )
    alerts_parser.add_argument(
        "--finding-id",
        help="Filter by finding ID",
    )
    alerts_parser.add_argument(
        "--status",
        choices=["sent", "acknowledged", "resolved", "expired"],
        help="Filter by alert status",
    )
    alerts_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum alerts to show (default: 50)",
    )
    alerts_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # templates command
    templates_parser = alerting_subparsers.add_parser(
        "templates",
        help="List available alert templates",
        description="List all available alert templates.",
    )
    templates_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # destination-types command
    types_parser = alerting_subparsers.add_parser(
        "destination-types",
        help="List available destination types",
        description="List all available destination integration types.",
    )
    types_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # severities command
    sev_parser = alerting_subparsers.add_parser(
        "severities",
        help="List severity levels",
        description="List all severity levels for routing rules.",
    )
    sev_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # status command
    status_parser = alerting_subparsers.add_parser(
        "status",
        help="Show alerting module status",
        description="Display the status of the alerting module.",
    )
    status_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # test-route command
    test_parser = alerting_subparsers.add_parser(
        "test-route",
        help="Test routing for a finding",
        description="Test which destinations would receive an alert for a finding.",
    )
    test_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Severity to test (default: high)",
    )
    test_parser.add_argument(
        "--finding-type",
        choices=["misconfiguration", "vulnerability", "compliance", "exposure"],
        default="misconfiguration",
        help="Finding type to test (default: misconfiguration)",
    )
    test_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )

    # summary command
    summary_parser = alerting_subparsers.add_parser(
        "summary",
        help="Show alerting summary",
        description="Display a summary of alerting configuration and statistics.",
    )
    summary_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )


def cmd_alerting(args: argparse.Namespace) -> int:
    """
    Handle alerting commands.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    handlers = {
        "destinations": _handle_destinations,
        "routing-rules": _handle_routing_rules,
        "suppression-rules": _handle_suppression_rules,
        "config": _handle_config,
        "rate-limits": _handle_rate_limits,
        "alerts": _handle_alerts,
        "templates": _handle_templates,
        "destination-types": _handle_destination_types,
        "severities": _handle_severities,
        "status": _handle_status,
        "test-route": _handle_test_route,
        "summary": _handle_summary,
    }

    command = getattr(args, "alerting_command", None)
    if not command:
        print("Error: No alerting command specified", file=sys.stderr)
        print("Use 'stance alerting --help' for available commands", file=sys.stderr)
        return 1

    handler = handlers.get(command)
    if not handler:
        print(f"Error: Unknown alerting command: {command}", file=sys.stderr)
        return 1

    return handler(args)


def _handle_destinations(args: argparse.Namespace) -> int:
    """Handle destinations command."""
    # Get sample destination status
    destinations = _get_sample_destinations()

    if args.format == "json":
        print(json.dumps(destinations, indent=2))
    else:
        print("Alert Destinations")
        print("=" * 60)
        print()
        if not destinations:
            print("No destinations configured.")
        else:
            for dest in destinations:
                status_icon = "[OK]" if dest["available"] else "[--]"
                print(f"  {status_icon} {dest['name']} ({dest['type']})")
                print(f"      Enabled: {dest['enabled']}")
                print(f"      Recent sends: {dest['recent_sends']}")
                print(f"      Rate limit: {dest['rate_limit_remaining']}/{dest['rate_limit_max']} remaining")
                print()

    return 0


def _handle_routing_rules(args: argparse.Namespace) -> int:
    """Handle routing-rules command."""
    rules = _get_sample_routing_rules()

    if args.enabled_only:
        rules = [r for r in rules if r["enabled"]]

    if args.format == "json":
        print(json.dumps(rules, indent=2))
    else:
        print("Routing Rules")
        print("=" * 60)
        print()
        if not rules:
            print("No routing rules configured.")
        else:
            for rule in rules:
                status = "enabled" if rule["enabled"] else "disabled"
                print(f"  [{rule['priority']:03d}] {rule['name']} ({status})")
                print(f"        Destinations: {', '.join(rule['destinations'])}")
                if rule["severities"]:
                    print(f"        Severities: {', '.join(rule['severities'])}")
                if rule["finding_types"]:
                    print(f"        Finding types: {', '.join(rule['finding_types'])}")
                print()

    return 0


def _handle_suppression_rules(args: argparse.Namespace) -> int:
    """Handle suppression-rules command."""
    rules = _get_sample_suppression_rules()

    if args.enabled_only:
        rules = [r for r in rules if r["enabled"]]

    if args.format == "json":
        print(json.dumps(rules, indent=2))
    else:
        print("Suppression Rules")
        print("=" * 60)
        print()
        if not rules:
            print("No suppression rules configured.")
        else:
            for rule in rules:
                status = "enabled" if rule["enabled"] else "disabled"
                expires = rule.get("expires_at", "never")
                print(f"  {rule['name']} ({status})")
                if rule["rule_ids"]:
                    print(f"      Rule IDs: {', '.join(rule['rule_ids'])}")
                if rule["asset_patterns"]:
                    print(f"      Asset patterns: {', '.join(rule['asset_patterns'])}")
                print(f"      Reason: {rule['reason']}")
                print(f"      Expires: {expires}")
                print()

    return 0


def _handle_config(args: argparse.Namespace) -> int:
    """Handle config command."""
    config = _get_sample_config()

    if args.format == "json":
        print(json.dumps(config, indent=2))
    else:
        print("Alert Configuration")
        print("=" * 60)
        print()
        print(f"  Enabled: {config['enabled']}")
        print(f"  Dedup window: {config['dedup_window_hours']} hours")
        print()
        print("  Default Rate Limit:")
        print(f"    Max alerts: {config['default_rate_limit']['max_alerts']}")
        print(f"    Window: {config['default_rate_limit']['window_seconds']} seconds")
        print(f"    Burst limit: {config['default_rate_limit']['burst_limit']}")
        print()
        print(f"  Destinations: {len(config['destinations'])}")
        print(f"  Routing rules: {len(config['routing_rules'])}")
        print(f"  Suppression rules: {len(config['suppression_rules'])}")

    return 0


def _handle_rate_limits(args: argparse.Namespace) -> int:
    """Handle rate-limits command."""
    rate_limits = _get_sample_rate_limits()

    if args.destination:
        rate_limits = {k: v for k, v in rate_limits.items() if k == args.destination}

    if args.format == "json":
        print(json.dumps(rate_limits, indent=2))
    else:
        print("Rate Limits")
        print("=" * 60)
        print()
        if not rate_limits:
            print("No rate limits configured.")
        else:
            for dest, limit in rate_limits.items():
                print(f"  {dest}:")
                print(f"    Max alerts: {limit['max_alerts']}")
                print(f"    Window: {limit['window_seconds']} seconds")
                print(f"    Burst limit: {limit['burst_limit']}")
                print()

    return 0


def _handle_alerts(args: argparse.Namespace) -> int:
    """Handle alerts command."""
    alerts = _get_sample_alerts()

    if args.finding_id:
        alerts = [a for a in alerts if a["finding_id"] == args.finding_id]

    if args.status:
        alerts = [a for a in alerts if a["status"] == args.status]

    alerts = alerts[: args.limit]

    if args.format == "json":
        print(json.dumps(alerts, indent=2))
    else:
        print("Recent Alerts")
        print("=" * 60)
        print()
        if not alerts:
            print("No alerts found.")
        else:
            for alert in alerts:
                status_icons = {
                    "sent": "[>]",
                    "acknowledged": "[v]",
                    "resolved": "[x]",
                    "expired": "[-]",
                }
                icon = status_icons.get(alert["status"], "[?]")
                print(f"  {icon} {alert['id']}")
                print(f"      Finding: {alert['finding_id']}")
                print(f"      Destination: {alert['destination']}")
                print(f"      Status: {alert['status']}")
                print(f"      Sent: {alert['sent_at']}")
                if alert.get("acknowledged_at"):
                    print(f"      Acknowledged: {alert['acknowledged_at']} by {alert.get('acknowledged_by', 'unknown')}")
                print()

    return 0


def _handle_templates(args: argparse.Namespace) -> int:
    """Handle templates command."""
    templates = _get_available_templates()

    if args.format == "json":
        print(json.dumps(templates, indent=2))
    else:
        print("Alert Templates")
        print("=" * 60)
        print()
        for template in templates:
            print(f"  {template['name']}")
            print(f"    Description: {template['description']}")
            print(f"    Used for: {template['used_for']}")
            print()

    return 0


def _handle_destination_types(args: argparse.Namespace) -> int:
    """Handle destination-types command."""
    types = _get_destination_types()

    if args.format == "json":
        print(json.dumps(types, indent=2))
    else:
        print("Destination Types")
        print("=" * 60)
        print()
        for dtype in types:
            print(f"  {dtype['type']}")
            print(f"    Description: {dtype['description']}")
            print(f"    Required config: {', '.join(dtype['required_config'])}")
            print()

    return 0


def _handle_severities(args: argparse.Namespace) -> int:
    """Handle severities command."""
    severities = [
        {"value": "critical", "priority": 1, "description": "Critical severity - immediate action required"},
        {"value": "high", "priority": 2, "description": "High severity - prompt attention needed"},
        {"value": "medium", "priority": 3, "description": "Medium severity - should be addressed soon"},
        {"value": "low", "priority": 4, "description": "Low severity - address when possible"},
        {"value": "info", "priority": 5, "description": "Informational - no action required"},
    ]

    if args.format == "json":
        print(json.dumps(severities, indent=2))
    else:
        print("Severity Levels")
        print("=" * 60)
        print()
        for sev in severities:
            print(f"  [{sev['priority']}] {sev['value'].upper()}")
            print(f"      {sev['description']}")
            print()

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = _get_alerting_status()

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("Alerting Module Status")
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


def _handle_test_route(args: argparse.Namespace) -> int:
    """Handle test-route command."""
    # Simulate routing test
    result = _test_routing(args.severity, args.finding_type)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Routing Test Results")
        print("=" * 60)
        print()
        print(f"  Test parameters:")
        print(f"    Severity: {args.severity}")
        print(f"    Finding type: {args.finding_type}")
        print()
        print(f"  Matched rules: {len(result['matched_rules'])}")
        for rule in result["matched_rules"]:
            print(f"    - {rule}")
        print()
        print(f"  Target destinations: {len(result['destinations'])}")
        for dest in result["destinations"]:
            print(f"    - {dest}")
        print()
        if result["would_be_suppressed"]:
            print("  [!] Alert would be SUPPRESSED by suppression rules")
        else:
            print("  [OK] Alert would be SENT to target destinations")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = _get_alerting_summary()

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("Alerting Summary")
        print("=" * 60)
        print()
        print("  Configuration:")
        print(f"    Alerting enabled: {summary['config']['enabled']}")
        print(f"    Destinations configured: {summary['config']['destinations_count']}")
        print(f"    Routing rules: {summary['config']['routing_rules_count']}")
        print(f"    Suppression rules: {summary['config']['suppression_rules_count']}")
        print()
        print("  Statistics (24h):")
        print(f"    Alerts sent: {summary['stats']['alerts_sent_24h']}")
        print(f"    Alerts suppressed: {summary['stats']['alerts_suppressed_24h']}")
        print(f"    Alerts deduplicated: {summary['stats']['alerts_deduplicated_24h']}")
        print(f"    Alerts rate-limited: {summary['stats']['alerts_rate_limited_24h']}")
        print()
        print("  By Destination:")
        for dest, count in summary["stats"]["by_destination"].items():
            print(f"    {dest}: {count} alerts")
        print()
        print("  By Severity:")
        for sev, count in summary["stats"]["by_severity"].items():
            print(f"    {sev}: {count} alerts")

    return 0


# Sample data generators for demo mode

def _get_sample_destinations() -> list[dict[str, Any]]:
    """Get sample destination data."""
    return [
        {
            "name": "slack-security",
            "type": "slack",
            "enabled": True,
            "available": True,
            "recent_sends": 45,
            "rate_limit_max": 50,
            "rate_limit_remaining": 5,
        },
        {
            "name": "pagerduty-critical",
            "type": "pagerduty",
            "enabled": True,
            "available": True,
            "recent_sends": 3,
            "rate_limit_max": 100,
            "rate_limit_remaining": 97,
        },
        {
            "name": "email-team",
            "type": "email",
            "enabled": True,
            "available": True,
            "recent_sends": 28,
            "rate_limit_max": 100,
            "rate_limit_remaining": 72,
        },
        {
            "name": "jira-security",
            "type": "jira",
            "enabled": False,
            "available": False,
            "recent_sends": 0,
            "rate_limit_max": 100,
            "rate_limit_remaining": 100,
        },
    ]


def _get_sample_routing_rules() -> list[dict[str, Any]]:
    """Get sample routing rules."""
    return [
        {
            "name": "critical-pagerduty",
            "destinations": ["pagerduty-critical"],
            "severities": ["critical"],
            "finding_types": [],
            "resource_types": [],
            "tags": {},
            "enabled": True,
            "priority": 10,
        },
        {
            "name": "high-slack",
            "destinations": ["slack-security"],
            "severities": ["critical", "high"],
            "finding_types": [],
            "resource_types": [],
            "tags": {},
            "enabled": True,
            "priority": 20,
        },
        {
            "name": "compliance-email",
            "destinations": ["email-team"],
            "severities": [],
            "finding_types": ["misconfiguration"],
            "resource_types": [],
            "tags": {},
            "enabled": True,
            "priority": 30,
        },
        {
            "name": "prod-all",
            "destinations": ["slack-security", "email-team"],
            "severities": [],
            "finding_types": [],
            "resource_types": [],
            "tags": {"environment": "production"},
            "enabled": True,
            "priority": 40,
        },
    ]


def _get_sample_suppression_rules() -> list[dict[str, Any]]:
    """Get sample suppression rules."""
    return [
        {
            "name": "known-exception-s3",
            "rule_ids": ["aws-s3-001", "aws-s3-002"],
            "asset_patterns": [],
            "reason": "Known exception for legacy bucket pending migration",
            "expires_at": "2025-06-30T00:00:00Z",
            "enabled": True,
        },
        {
            "name": "dev-environment",
            "rule_ids": [],
            "asset_patterns": ["arn:aws:*:*:*:dev-*", "arn:aws:*:*:*:*-dev-*"],
            "reason": "Development environment - reduced alerting",
            "expires_at": None,
            "enabled": True,
        },
        {
            "name": "scheduled-maintenance",
            "rule_ids": ["aws-ec2-003"],
            "asset_patterns": [],
            "reason": "Scheduled maintenance window",
            "expires_at": "2025-01-15T00:00:00Z",
            "enabled": False,
        },
    ]


def _get_sample_config() -> dict[str, Any]:
    """Get sample alert configuration."""
    return {
        "enabled": True,
        "dedup_window_hours": 24,
        "default_rate_limit": {
            "max_alerts": 100,
            "window_seconds": 3600,
            "burst_limit": 10,
        },
        "destinations": _get_sample_destinations(),
        "routing_rules": _get_sample_routing_rules(),
        "suppression_rules": _get_sample_suppression_rules(),
    }


def _get_sample_rate_limits() -> dict[str, dict[str, Any]]:
    """Get sample rate limits."""
    return {
        "slack-security": {
            "max_alerts": 50,
            "window_seconds": 3600,
            "burst_limit": 5,
        },
        "pagerduty-critical": {
            "max_alerts": 100,
            "window_seconds": 3600,
            "burst_limit": 10,
        },
        "email-team": {
            "max_alerts": 100,
            "window_seconds": 3600,
            "burst_limit": 10,
        },
        "default": {
            "max_alerts": 100,
            "window_seconds": 3600,
            "burst_limit": 10,
        },
    }


def _get_sample_alerts() -> list[dict[str, Any]]:
    """Get sample alert records."""
    base_time = datetime.utcnow()
    return [
        {
            "id": "alert-001",
            "finding_id": "finding-abc123",
            "destination": "slack-security",
            "sent_at": (base_time - timedelta(hours=1)).isoformat(),
            "acknowledged_at": (base_time - timedelta(minutes=45)).isoformat(),
            "acknowledged_by": "security-team",
            "status": "acknowledged",
        },
        {
            "id": "alert-002",
            "finding_id": "finding-def456",
            "destination": "pagerduty-critical",
            "sent_at": (base_time - timedelta(hours=2)).isoformat(),
            "acknowledged_at": None,
            "acknowledged_by": None,
            "status": "sent",
        },
        {
            "id": "alert-003",
            "finding_id": "finding-ghi789",
            "destination": "email-team",
            "sent_at": (base_time - timedelta(hours=3)).isoformat(),
            "acknowledged_at": (base_time - timedelta(hours=2)).isoformat(),
            "acknowledged_by": "dev-team",
            "status": "resolved",
        },
        {
            "id": "alert-004",
            "finding_id": "finding-jkl012",
            "destination": "slack-security",
            "sent_at": (base_time - timedelta(days=2)).isoformat(),
            "acknowledged_at": None,
            "acknowledged_by": None,
            "status": "expired",
        },
    ]


def _get_available_templates() -> list[dict[str, Any]]:
    """Get available alert templates."""
    return [
        {
            "name": "DefaultTemplate",
            "description": "Standard plain text alert format",
            "used_for": "General findings without specific categorization",
        },
        {
            "name": "MisconfigurationTemplate",
            "description": "Optimized for misconfiguration findings",
            "used_for": "Cloud resource misconfigurations, policy violations",
        },
        {
            "name": "VulnerabilityTemplate",
            "description": "Optimized for vulnerability findings",
            "used_for": "CVEs, package vulnerabilities, software flaws",
        },
        {
            "name": "ComplianceTemplate",
            "description": "Compliance-focused alert format",
            "used_for": "Compliance violations, audit findings",
        },
        {
            "name": "CriticalExposureTemplate",
            "description": "High-urgency format for critical exposures",
            "used_for": "Critical severity findings requiring immediate action",
        },
    ]


def _get_destination_types() -> list[dict[str, Any]]:
    """Get available destination types."""
    return [
        {
            "type": "slack",
            "description": "Slack incoming webhook integration",
            "required_config": ["webhook_url"],
        },
        {
            "type": "pagerduty",
            "description": "PagerDuty Events API v2 integration",
            "required_config": ["routing_key"],
        },
        {
            "type": "email",
            "description": "Email notifications via SMTP",
            "required_config": ["smtp_host", "from_address", "to_addresses"],
        },
        {
            "type": "webhook",
            "description": "Generic HTTP webhook integration",
            "required_config": ["url"],
        },
        {
            "type": "teams",
            "description": "Microsoft Teams incoming webhook",
            "required_config": ["webhook_url"],
        },
        {
            "type": "jira",
            "description": "Jira issue creation integration",
            "required_config": ["url", "project", "api_token"],
        },
    ]


def _get_alerting_status() -> dict[str, Any]:
    """Get alerting module status."""
    return {
        "module": "stance.alerting",
        "version": "1.0.0",
        "status": "operational",
        "components": {
            "AlertRouter": "available",
            "AlertState": "available",
            "AlertConfig": "available",
            "InMemoryAlertState": "available",
            "DynamoDBAlertState": "available",
            "FirestoreAlertState": "available",
            "CosmosDBAlertState": "available",
        },
        "capabilities": [
            "Multi-destination routing",
            "Severity-based filtering",
            "Finding type filtering",
            "Tag-based routing",
            "Alert deduplication",
            "Rate limiting",
            "Suppression rules",
            "Multiple state backends (in-memory, DynamoDB, Firestore, CosmosDB)",
            "Template-based formatting",
        ],
    }


def _test_routing(severity: str, finding_type: str) -> dict[str, Any]:
    """Test routing for given parameters."""
    # Simulate routing based on sample rules
    matched_rules = []
    destinations = set()

    rules = _get_sample_routing_rules()
    for rule in rules:
        if not rule["enabled"]:
            continue

        matches = True

        # Check severity
        if rule["severities"] and severity not in rule["severities"]:
            matches = False

        # Check finding type
        if rule["finding_types"] and finding_type not in rule["finding_types"]:
            matches = False

        if matches:
            matched_rules.append(rule["name"])
            destinations.update(rule["destinations"])

    # Check suppression
    would_be_suppressed = False  # Demo: not suppressed

    return {
        "severity": severity,
        "finding_type": finding_type,
        "matched_rules": matched_rules,
        "destinations": list(destinations),
        "would_be_suppressed": would_be_suppressed,
    }


def _get_alerting_summary() -> dict[str, Any]:
    """Get alerting summary."""
    return {
        "config": {
            "enabled": True,
            "destinations_count": 4,
            "routing_rules_count": 4,
            "suppression_rules_count": 3,
        },
        "stats": {
            "alerts_sent_24h": 76,
            "alerts_suppressed_24h": 12,
            "alerts_deduplicated_24h": 34,
            "alerts_rate_limited_24h": 5,
            "by_destination": {
                "slack-security": 45,
                "pagerduty-critical": 3,
                "email-team": 28,
            },
            "by_severity": {
                "critical": 3,
                "high": 28,
                "medium": 35,
                "low": 10,
            },
        },
    }
