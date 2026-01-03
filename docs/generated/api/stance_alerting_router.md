# stance.alerting.router

Alert router for Mantissa Stance.

Routes security findings to multiple notification destinations based
on configurable rules, severity, and deduplication settings.

## Contents

### Classes

- [AlertDestination](#alertdestination)
- [RoutingRule](#routingrule)
- [SuppressionRule](#suppressionrule)
- [RateLimit](#ratelimit)
- [AlertResult](#alertresult)
- [RoutingResult](#routingresult)
- [AlertRouter](#alertrouter)

## AlertDestination

**Inherits from:** Protocol

Protocol for alert destinations.

### Properties

#### `name(self) -> str`

Destination name.

**Returns:**

`str`

### Methods

#### `send(self, finding: Finding, context: dict[(str, Any)]) -> bool`

Send alert to destination.

**Parameters:**

- `finding` (`Finding`) - Finding to alert on
- `context` (`dict[(str, Any)]`) - Additional context for the alert

**Returns:**

`bool` - True if alert was sent successfully

#### `test_connection(self) -> bool`

Test if destination is reachable.

**Returns:**

`bool`

## RoutingRule

**Tags:** dataclass

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

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `destinations` | `list[str]` | - |
| `severities` | `list[Severity]` | `field(...)` |
| `finding_types` | `list[str]` | `field(...)` |
| `resource_types` | `list[str]` | `field(...)` |
| `tags` | `dict[(str, str)]` | `field(...)` |
| `enabled` | `bool` | `True` |
| `priority` | `int` | `100` |

## SuppressionRule

**Tags:** dataclass

Rule for suppressing alerts.

Attributes:
    name: Rule name
    rule_ids: Policy rule IDs to suppress
    asset_patterns: Asset ID patterns to suppress
    reason: Reason for suppression
    expires_at: When suppression expires (None = permanent)
    enabled: Whether suppression is active

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `rule_ids` | `list[str]` | `field(...)` |
| `asset_patterns` | `list[str]` | `field(...)` |
| `reason` | `str` | `` |
| `expires_at` | `datetime | None` | - |
| `enabled` | `bool` | `True` |

## RateLimit

**Tags:** dataclass

Rate limit configuration for a destination.

Attributes:
    max_alerts: Maximum alerts in the window
    window_seconds: Time window in seconds
    burst_limit: Maximum burst of alerts

### Attributes

| Name | Type | Default |
|------|------|---------|
| `max_alerts` | `int` | `100` |
| `window_seconds` | `int` | `3600` |
| `burst_limit` | `int` | `10` |

## AlertResult

**Tags:** dataclass

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

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `destination` | `str` | - |
| `success` | `bool` | `True` |
| `error` | `str` | `` |
| `deduplicated` | `bool` | `False` |
| `suppressed` | `bool` | `False` |
| `rate_limited` | `bool` | `False` |
| `timestamp` | `datetime` | `field(...)` |

## RoutingResult

**Tags:** dataclass

Result of routing a finding.

Attributes:
    finding_id: ID of the finding
    results: Results for each destination
    matched_rules: Rules that matched
    total_destinations: Total destinations targeted
    successful_destinations: Number of successful sends

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `results` | `list[AlertResult]` | `field(...)` |
| `matched_rules` | `list[str]` | `field(...)` |
| `total_destinations` | `int` | `0` |
| `successful_destinations` | `int` | `0` |

## AlertRouter

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

### Methods

#### `__init__(self, dedup_window_hours: int = 24, default_rate_limit: RateLimit | None) -> None`

Initialize the alert router.

**Parameters:**

- `dedup_window_hours` (`int`) - default: `24` - Hours to deduplicate alerts
- `default_rate_limit` (`RateLimit | None`) - Default rate limit for destinations

**Returns:**

`None`

#### `add_destination(self, destination: AlertDestination) -> None`

Add an alert destination.

**Parameters:**

- `destination` (`AlertDestination`) - Destination to add

**Returns:**

`None`

#### `remove_destination(self, name: str) -> None`

Remove a destination by name.

**Parameters:**

- `name` (`str`)

**Returns:**

`None`

#### `add_routing_rule(self, rule: RoutingRule) -> None`

Add a routing rule.

**Parameters:**

- `rule` (`RoutingRule`) - Routing rule to add

**Returns:**

`None`

#### `add_suppression_rule(self, rule: SuppressionRule) -> None`

Add a suppression rule.

**Parameters:**

- `rule` (`SuppressionRule`) - Suppression rule to add

**Returns:**

`None`

#### `set_rate_limit(self, destination: str, limit: RateLimit) -> None`

Set rate limit for a destination.

**Parameters:**

- `destination` (`str`) - Destination name
- `limit` (`RateLimit`) - Rate limit configuration

**Returns:**

`None`

#### `route(self, finding: Finding, context: dict[(str, Any)] | None) -> RoutingResult`

Route a finding to appropriate destinations.

**Parameters:**

- `finding` (`Finding`) - Finding to route
- `context` (`dict[(str, Any)] | None`) - Additional context (asset info, etc.)

**Returns:**

`RoutingResult` - RoutingResult with details of routing

#### `route_batch(self, findings: list[Finding], context: dict[(str, Any)] | None) -> list[RoutingResult]`

Route multiple findings.

**Parameters:**

- `findings` (`list[Finding]`) - List of findings to route
- `context` (`dict[(str, Any)] | None`) - Additional context

**Returns:**

`list[RoutingResult]` - List of routing results

#### `test_destination(self, destination_name: str) -> bool`

Test if a destination is reachable.

**Parameters:**

- `destination_name` (`str`) - Name of destination to test

**Returns:**

`bool` - True if destination is reachable

#### `get_destination_status(self) -> dict[(str, dict[(str, Any)])]`

Get status of all destinations.

**Returns:**

`dict[(str, dict[(str, Any)])]`

#### `list_routing_rules(self) -> list[dict[(str, Any)]]`

List all routing rules.

**Returns:**

`list[dict[(str, Any)]]`

#### `list_suppression_rules(self) -> list[dict[(str, Any)]]`

List all suppression rules.

**Returns:**

`list[dict[(str, Any)]]`

#### `clear_dedup_cache(self) -> None`

Clear the deduplication cache.

**Returns:**

`None`

#### `clear_rate_limit_counters(self) -> None`

Clear rate limit counters.

**Returns:**

`None`
