"""
Alert management handlers for the Stance web API.

This module handles all /api/alerting/* endpoints for alert routing,
destinations, suppression rules, and alert management.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class AlertHandler(RoutedHandler):
    """
    Handler for alerting API endpoints.

    Handles:
    - Alert destinations configuration
    - Alert routing rules
    - Alert suppression rules
    - Alert history and status
    - Alert testing and configuration
    """

    base_path = "/api/alerting/"

    # =========================================================================
    # Destination Management endpoints
    # =========================================================================

    @route("destinations")
    def alerting_destinations(self, params: dict, body: dict | None) -> HandlerResponse:
        """List configured alert destinations."""
        try:
            destinations = self._get_sample_alerting_destinations()
            return HandlerResponse.success({
                "destinations": destinations,
                "total": len(destinations),
            })
        except Exception as e:
            logger.exception("Failed to list alert destinations")
            return HandlerResponse.server_error(str(e))

    @route("destination-types")
    def alerting_destination_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available destination types with configuration requirements."""
        try:
            types = [
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

            return HandlerResponse.success({
                "types": types,
                "total": len(types),
            })
        except Exception as e:
            logger.exception("Failed to list destination types")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Routing Rules endpoints
    # =========================================================================

    @route("routing-rules")
    def alerting_routing_rules(self, params: dict, body: dict | None) -> HandlerResponse:
        """List alert routing rules."""
        try:
            enabled_only = self.get_param(params, "enabled_only", "false").lower() == "true"

            rules = self._get_sample_routing_rules()
            if enabled_only:
                rules = [r for r in rules if r["enabled"]]

            return HandlerResponse.success({
                "rules": rules,
                "total": len(rules),
            })
        except Exception as e:
            logger.exception("Failed to list routing rules")
            return HandlerResponse.server_error(str(e))

    @route("suppression-rules")
    def alerting_suppression_rules(self, params: dict, body: dict | None) -> HandlerResponse:
        """List alert suppression rules."""
        try:
            enabled_only = self.get_param(params, "enabled_only", "false").lower() == "true"

            rules = self._get_sample_suppression_rules()
            if enabled_only:
                rules = [r for r in rules if r["enabled"]]

            return HandlerResponse.success({
                "rules": rules,
                "total": len(rules),
            })
        except Exception as e:
            logger.exception("Failed to list suppression rules")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Configuration endpoints
    # =========================================================================

    @route("config")
    def alerting_config(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get complete alert configuration."""
        try:
            return HandlerResponse.success({
                "enabled": True,
                "dedup_window_hours": 24,
                "default_rate_limit": {
                    "max_alerts": 100,
                    "window_seconds": 3600,
                    "burst_limit": 10,
                },
                "destinations_count": len(self._get_sample_alerting_destinations()),
                "routing_rules_count": len(self._get_sample_routing_rules()),
                "suppression_rules_count": len(self._get_sample_suppression_rules()),
            })
        except Exception as e:
            logger.exception("Failed to get alert config")
            return HandlerResponse.server_error(str(e))

    @route("rate-limits")
    def alerting_rate_limits(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get rate limit settings for destinations."""
        try:
            destination = self.get_param(params, "destination", "")

            rate_limits = {
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

            if destination:
                if destination in rate_limits:
                    return HandlerResponse.success({
                        "rate_limits": {destination: rate_limits[destination]}
                    })
                return HandlerResponse.success({
                    "rate_limits": {},
                    "error": f"Destination not found: {destination}"
                })

            return HandlerResponse.success({"rate_limits": rate_limits})
        except Exception as e:
            logger.exception("Failed to get rate limits")
            return HandlerResponse.server_error(str(e))

    @route("severities")
    def alerting_severities(self, params: dict, body: dict | None) -> HandlerResponse:
        """List severity levels for routing rules."""
        try:
            severities = [
                {"value": "critical", "priority": 1, "description": "Critical severity - immediate action required"},
                {"value": "high", "priority": 2, "description": "High severity - prompt attention needed"},
                {"value": "medium", "priority": 3, "description": "Medium severity - should be addressed soon"},
                {"value": "low", "priority": 4, "description": "Low severity - address when possible"},
                {"value": "info", "priority": 5, "description": "Informational - no action required"},
            ]

            return HandlerResponse.success({
                "severities": severities,
                "total": len(severities),
            })
        except Exception as e:
            logger.exception("Failed to list severities")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Alert Records endpoints
    # =========================================================================

    @route("alerts")
    def alerting_alerts(self, params: dict, body: dict | None) -> HandlerResponse:
        """List recent alert records."""
        try:
            finding_id = self.get_param(params, "finding_id", "")
            status = self.get_param(params, "status", "")
            limit = self.get_param_int(params, "limit", 50)

            now = datetime.utcnow()
            alerts = [
                {
                    "id": "alert-001",
                    "finding_id": "finding-abc123",
                    "destination": "slack-security",
                    "sent_at": (now - timedelta(hours=1)).isoformat(),
                    "acknowledged_at": (now - timedelta(minutes=45)).isoformat(),
                    "acknowledged_by": "security-team",
                    "status": "acknowledged",
                },
                {
                    "id": "alert-002",
                    "finding_id": "finding-def456",
                    "destination": "pagerduty-critical",
                    "sent_at": (now - timedelta(hours=2)).isoformat(),
                    "acknowledged_at": None,
                    "acknowledged_by": None,
                    "status": "sent",
                },
                {
                    "id": "alert-003",
                    "finding_id": "finding-ghi789",
                    "destination": "email-team",
                    "sent_at": (now - timedelta(hours=3)).isoformat(),
                    "acknowledged_at": (now - timedelta(hours=2)).isoformat(),
                    "acknowledged_by": "dev-team",
                    "status": "resolved",
                },
                {
                    "id": "alert-004",
                    "finding_id": "finding-jkl012",
                    "destination": "slack-security",
                    "sent_at": (now - timedelta(days=2)).isoformat(),
                    "acknowledged_at": None,
                    "acknowledged_by": None,
                    "status": "expired",
                },
            ]

            if finding_id:
                alerts = [a for a in alerts if a["finding_id"] == finding_id]
            if status:
                alerts = [a for a in alerts if a["status"] == status]

            alerts = alerts[:limit]

            return HandlerResponse.success({
                "alerts": alerts,
                "total": len(alerts),
            })
        except Exception as e:
            logger.exception("Failed to list alerts")
            return HandlerResponse.server_error(str(e))

    @route("templates")
    def alerting_templates(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available alert templates."""
        try:
            templates = [
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

            return HandlerResponse.success({
                "templates": templates,
                "total": len(templates),
            })
        except Exception as e:
            logger.exception("Failed to list templates")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Testing and Status endpoints
    # =========================================================================

    @route("test-route")
    def alerting_test_route(self, params: dict, body: dict | None) -> HandlerResponse:
        """Test routing for a finding with given severity and type."""
        try:
            severity = self.get_param(params, "severity", "high")
            finding_type = self.get_param(params, "finding_type", "misconfiguration")

            # Simulate routing based on sample rules
            matched_rules = []
            destinations: set[str] = set()

            rules = self._get_sample_routing_rules()
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

            return HandlerResponse.success({
                "severity": severity,
                "finding_type": finding_type,
                "matched_rules": matched_rules,
                "destinations": list(destinations),
                "would_be_suppressed": False,
            })
        except Exception as e:
            logger.exception("Failed to test route")
            return HandlerResponse.server_error(str(e))

    @route("status")
    def alerting_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get alerting module status and capabilities."""
        try:
            return HandlerResponse.success({
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
            })
        except Exception as e:
            logger.exception("Failed to get alerting status")
            return HandlerResponse.server_error(str(e))

    @route("summary")
    def alerting_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get alerting configuration and statistics summary."""
        try:
            return HandlerResponse.success({
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
            })
        except Exception as e:
            logger.exception("Failed to get alerting summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_sample_alerting_destinations(self) -> list[dict[str, Any]]:
        """Get sample destination data for demo mode."""
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

    def _get_sample_routing_rules(self) -> list[dict[str, Any]]:
        """Get sample routing rules for demo mode."""
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

    def _get_sample_suppression_rules(self) -> list[dict[str, Any]]:
        """Get sample suppression rules for demo mode."""
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
