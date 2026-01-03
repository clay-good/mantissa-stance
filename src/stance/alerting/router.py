"""
Alert router for Mantissa Stance.

Routes security findings to multiple notification destinations based
on configurable rules, severity, and deduplication settings.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Protocol

from stance.models.finding import Finding, Severity, FindingStatus

logger = logging.getLogger(__name__)


class AlertDestination(Protocol):
    """Protocol for alert destinations."""

    @property
    def name(self) -> str:
        """Destination name."""
        ...

    def send(self, finding: Finding, context: dict[str, Any]) -> bool:
        """
        Send alert to destination.

        Args:
            finding: Finding to alert on
            context: Additional context for the alert

        Returns:
            True if alert was sent successfully
        """
        ...

    def test_connection(self) -> bool:
        """Test if destination is reachable."""
        ...


@dataclass
class RoutingRule:
    """
    Rule for routing findings to destinations.

    Attributes:
        name: Rule name for identification
        destinations: List of destination names to route to
        severities: Severities this rule applies to (empty = all)
        finding_types: Finding types to match (empty = all)
        resource_types: Resource types to match (empty = all)
        tags: Asset tags to match (empty = all)
        enabled: Whether this rule is active
        priority: Rule priority (lower = higher priority)
    """

    name: str
    destinations: list[str]
    severities: list[Severity] = field(default_factory=list)
    finding_types: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    priority: int = 100


@dataclass
class SuppressionRule:
    """
    Rule for suppressing alerts.

    Attributes:
        name: Rule name
        rule_ids: Policy rule IDs to suppress
        asset_patterns: Asset ID patterns to suppress
        reason: Reason for suppression
        expires_at: When suppression expires (None = permanent)
        enabled: Whether suppression is active
    """

    name: str
    rule_ids: list[str] = field(default_factory=list)
    asset_patterns: list[str] = field(default_factory=list)
    reason: str = ""
    expires_at: datetime | None = None
    enabled: bool = True


@dataclass
class RateLimit:
    """
    Rate limit configuration for a destination.

    Attributes:
        max_alerts: Maximum alerts in the window
        window_seconds: Time window in seconds
        burst_limit: Maximum burst of alerts
    """

    max_alerts: int = 100
    window_seconds: int = 3600
    burst_limit: int = 10


@dataclass
class AlertResult:
    """
    Result of sending an alert.

    Attributes:
        finding_id: ID of the finding
        destination: Destination name
        success: Whether alert was sent
        error: Error message if failed
        deduplicated: Whether alert was skipped due to deduplication
        suppressed: Whether alert was suppressed
        rate_limited: Whether alert was rate limited
        timestamp: When the alert was processed
    """

    finding_id: str
    destination: str
    success: bool = True
    error: str = ""
    deduplicated: bool = False
    suppressed: bool = False
    rate_limited: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class RoutingResult:
    """
    Result of routing a finding.

    Attributes:
        finding_id: ID of the finding
        results: Results for each destination
        matched_rules: Rules that matched
        total_destinations: Total destinations targeted
        successful_destinations: Number of successful sends
    """

    finding_id: str
    results: list[AlertResult] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)
    total_destinations: int = 0
    successful_destinations: int = 0


class AlertRouter:
    """
    Routes findings to configured alert destinations.

    The router evaluates findings against routing rules, applies
    suppression and deduplication, respects rate limits, and
    sends alerts to appropriate destinations.

    Example:
        >>> router = AlertRouter()
        >>> router.add_destination(SlackDestination(webhook_url="..."))
        >>> router.add_routing_rule(RoutingRule(
        ...     name="critical-to-slack",
        ...     destinations=["slack"],
        ...     severities=[Severity.CRITICAL]
        ... ))
        >>> result = router.route(finding)
        >>> print(f"Sent to {result.successful_destinations} destinations")
    """

    def __init__(
        self,
        dedup_window_hours: int = 24,
        default_rate_limit: RateLimit | None = None,
    ) -> None:
        """
        Initialize the alert router.

        Args:
            dedup_window_hours: Hours to deduplicate alerts
            default_rate_limit: Default rate limit for destinations
        """
        self._destinations: dict[str, AlertDestination] = {}
        self._routing_rules: list[RoutingRule] = []
        self._suppression_rules: list[SuppressionRule] = []
        self._rate_limits: dict[str, RateLimit] = {}
        self._dedup_window = timedelta(hours=dedup_window_hours)
        self._default_rate_limit = default_rate_limit or RateLimit()

        # State tracking
        self._sent_alerts: dict[str, datetime] = {}  # dedup_key -> timestamp
        self._rate_limit_counters: dict[str, list[datetime]] = {}  # dest -> timestamps

    def add_destination(self, destination: AlertDestination) -> None:
        """
        Add an alert destination.

        Args:
            destination: Destination to add
        """
        self._destinations[destination.name] = destination
        logger.info(f"Added destination: {destination.name}")

    def remove_destination(self, name: str) -> None:
        """Remove a destination by name."""
        if name in self._destinations:
            del self._destinations[name]
            logger.info(f"Removed destination: {name}")

    def add_routing_rule(self, rule: RoutingRule) -> None:
        """
        Add a routing rule.

        Args:
            rule: Routing rule to add
        """
        self._routing_rules.append(rule)
        # Sort by priority
        self._routing_rules.sort(key=lambda r: r.priority)
        logger.info(f"Added routing rule: {rule.name}")

    def add_suppression_rule(self, rule: SuppressionRule) -> None:
        """
        Add a suppression rule.

        Args:
            rule: Suppression rule to add
        """
        self._suppression_rules.append(rule)
        logger.info(f"Added suppression rule: {rule.name}")

    def set_rate_limit(self, destination: str, limit: RateLimit) -> None:
        """
        Set rate limit for a destination.

        Args:
            destination: Destination name
            limit: Rate limit configuration
        """
        self._rate_limits[destination] = limit

    def route(
        self,
        finding: Finding,
        context: dict[str, Any] | None = None,
    ) -> RoutingResult:
        """
        Route a finding to appropriate destinations.

        Args:
            finding: Finding to route
            context: Additional context (asset info, etc.)

        Returns:
            RoutingResult with details of routing
        """
        result = RoutingResult(finding_id=finding.id)
        context = context or {}

        # Check suppression first
        if self._is_suppressed(finding):
            logger.debug(f"Finding {finding.id} is suppressed")
            result.results.append(
                AlertResult(
                    finding_id=finding.id,
                    destination="",
                    suppressed=True,
                )
            )
            return result

        # Find matching rules
        matched_destinations: set[str] = set()
        for rule in self._routing_rules:
            if not rule.enabled:
                continue

            if self._rule_matches(rule, finding, context):
                result.matched_rules.append(rule.name)
                for dest_name in rule.destinations:
                    matched_destinations.add(dest_name)

        result.total_destinations = len(matched_destinations)

        # Send to each matched destination
        for dest_name in matched_destinations:
            if dest_name not in self._destinations:
                logger.warning(f"Destination not found: {dest_name}")
                continue

            alert_result = self._send_to_destination(
                finding, dest_name, context
            )
            result.results.append(alert_result)

            if alert_result.success:
                result.successful_destinations += 1

        return result

    def route_batch(
        self,
        findings: list[Finding],
        context: dict[str, Any] | None = None,
    ) -> list[RoutingResult]:
        """
        Route multiple findings.

        Args:
            findings: List of findings to route
            context: Additional context

        Returns:
            List of routing results
        """
        return [self.route(finding, context) for finding in findings]

    def _rule_matches(
        self,
        rule: RoutingRule,
        finding: Finding,
        context: dict[str, Any],
    ) -> bool:
        """Check if a routing rule matches a finding."""
        # Check severity
        if rule.severities and finding.severity not in rule.severities:
            return False

        # Check finding type
        if rule.finding_types:
            if finding.finding_type.value not in rule.finding_types:
                return False

        # Check resource type (from context)
        if rule.resource_types:
            resource_type = context.get("resource_type", "")
            if resource_type not in rule.resource_types:
                return False

        # Check tags (from context)
        if rule.tags:
            asset_tags = context.get("tags", {})
            for key, value in rule.tags.items():
                if asset_tags.get(key) != value:
                    return False

        return True

    def _is_suppressed(self, finding: Finding) -> bool:
        """Check if finding is suppressed."""
        now = datetime.utcnow()

        for rule in self._suppression_rules:
            if not rule.enabled:
                continue

            # Check expiration
            if rule.expires_at and rule.expires_at < now:
                continue

            # Check rule ID match
            if rule.rule_ids and finding.rule_id:
                if finding.rule_id in rule.rule_ids:
                    return True

            # Check asset pattern match
            if rule.asset_patterns:
                for pattern in rule.asset_patterns:
                    if self._matches_pattern(finding.asset_id, pattern):
                        return True

        return False

    def _matches_pattern(self, value: str, pattern: str) -> bool:
        """Simple wildcard pattern matching."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return value.startswith(pattern[:-1])
        if pattern.startswith("*"):
            return value.endswith(pattern[1:])
        return value == pattern

    def _send_to_destination(
        self,
        finding: Finding,
        dest_name: str,
        context: dict[str, Any],
    ) -> AlertResult:
        """Send alert to a specific destination."""
        destination = self._destinations[dest_name]

        # Check deduplication
        dedup_key = self._get_dedup_key(finding, dest_name)
        if self._is_deduplicated(dedup_key):
            return AlertResult(
                finding_id=finding.id,
                destination=dest_name,
                deduplicated=True,
            )

        # Check rate limit
        if self._is_rate_limited(dest_name):
            return AlertResult(
                finding_id=finding.id,
                destination=dest_name,
                rate_limited=True,
            )

        # Send the alert
        try:
            success = destination.send(finding, context)

            if success:
                # Record for deduplication
                self._sent_alerts[dedup_key] = datetime.utcnow()
                # Record for rate limiting
                self._record_send(dest_name)

            return AlertResult(
                finding_id=finding.id,
                destination=dest_name,
                success=success,
            )

        except Exception as e:
            logger.error(f"Failed to send alert to {dest_name}: {e}")
            return AlertResult(
                finding_id=finding.id,
                destination=dest_name,
                success=False,
                error=str(e),
            )

    def _get_dedup_key(self, finding: Finding, destination: str) -> str:
        """Generate deduplication key for a finding+destination."""
        key_parts = [
            finding.id,
            destination,
            finding.severity.value,
            finding.rule_id or "",
        ]
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def _is_deduplicated(self, dedup_key: str) -> bool:
        """Check if alert was recently sent."""
        if dedup_key not in self._sent_alerts:
            return False

        sent_time = self._sent_alerts[dedup_key]
        if datetime.utcnow() - sent_time < self._dedup_window:
            return True

        # Clean up old entry
        del self._sent_alerts[dedup_key]
        return False

    def _is_rate_limited(self, destination: str) -> bool:
        """Check if destination is rate limited."""
        limit = self._rate_limits.get(destination, self._default_rate_limit)
        window = timedelta(seconds=limit.window_seconds)
        now = datetime.utcnow()
        cutoff = now - window

        if destination not in self._rate_limit_counters:
            return False

        # Count recent sends
        recent_sends = [
            ts for ts in self._rate_limit_counters[destination] if ts > cutoff
        ]
        self._rate_limit_counters[destination] = recent_sends

        return len(recent_sends) >= limit.max_alerts

    def _record_send(self, destination: str) -> None:
        """Record a send for rate limiting."""
        if destination not in self._rate_limit_counters:
            self._rate_limit_counters[destination] = []
        self._rate_limit_counters[destination].append(datetime.utcnow())

    def test_destination(self, destination_name: str) -> bool:
        """
        Test if a destination is reachable.

        Args:
            destination_name: Name of destination to test

        Returns:
            True if destination is reachable
        """
        if destination_name not in self._destinations:
            return False

        try:
            return self._destinations[destination_name].test_connection()
        except Exception as e:
            logger.error(f"Destination test failed: {e}")
            return False

    def get_destination_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all destinations."""
        status: dict[str, dict[str, Any]] = {}

        for name, dest in self._destinations.items():
            rate_limit = self._rate_limits.get(name, self._default_rate_limit)
            recent_sends = len(
                self._rate_limit_counters.get(name, [])
            )

            status[name] = {
                "available": True,
                "rate_limit_max": rate_limit.max_alerts,
                "rate_limit_window_seconds": rate_limit.window_seconds,
                "recent_sends": recent_sends,
            }

        return status

    def list_routing_rules(self) -> list[dict[str, Any]]:
        """List all routing rules."""
        return [
            {
                "name": rule.name,
                "destinations": rule.destinations,
                "severities": [s.value for s in rule.severities],
                "finding_types": rule.finding_types,
                "enabled": rule.enabled,
                "priority": rule.priority,
            }
            for rule in self._routing_rules
        ]

    def list_suppression_rules(self) -> list[dict[str, Any]]:
        """List all suppression rules."""
        return [
            {
                "name": rule.name,
                "rule_ids": rule.rule_ids,
                "asset_patterns": rule.asset_patterns,
                "reason": rule.reason,
                "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
                "enabled": rule.enabled,
            }
            for rule in self._suppression_rules
        ]

    def clear_dedup_cache(self) -> None:
        """Clear the deduplication cache."""
        self._sent_alerts.clear()
        logger.info("Deduplication cache cleared")

    def clear_rate_limit_counters(self) -> None:
        """Clear rate limit counters."""
        self._rate_limit_counters.clear()
        logger.info("Rate limit counters cleared")
