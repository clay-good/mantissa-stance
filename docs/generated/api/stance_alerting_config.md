# stance.alerting.config

Alert configuration for Mantissa Stance.

Provides configuration dataclasses and loader for alert routing settings.

## Contents

### Classes

- [DestinationConfig](#destinationconfig)
- [AlertConfig](#alertconfig)
- [AlertConfigLoader](#alertconfigloader)

### Functions

- [create_default_config](#create_default_config)

## Constants

### `EXAMPLE_CONFIG`

Type: `str`

Value: `
{
  "enabled": true,
  "dedup_window_hours": 24,
  "default_rate_limit": {
    "max_alerts": 100,
    "window_seconds": 3600,
    "burst_limit": 10
  },
  "destinations": [
    {
      "name": "slack-security",
      "type": "slack",
      "enabled": true,
      "config": {
        "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
        "channel": "#security-alerts"
      }
    },
    {
      "name": "pagerduty-critical",
      "type": "pagerduty",
      "enabled": true,
      "config": {
        "routing_key": "your-pagerduty-routing-key"
      }
    },
    {
      "name": "email-team",
      "type": "email",
      "enabled": true,
      "config": {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "from_address": "stance@example.com",
        "to_addresses": ["security-team@example.com"]
      }
    }
  ],
  "routing_rules": [
    {
      "name": "critical-pagerduty",
      "destinations": ["pagerduty-critical"],
      "severities": ["critical"],
      "priority": 10,
      "enabled": true
    },
    {
      "name": "high-slack",
      "destinations": ["slack-security"],
      "severities": ["critical", "high"],
      "priority": 20,
      "enabled": true
    },
    {
      "name": "compliance-email",
      "destinations": ["email-team"],
      "finding_types": ["misconfiguration"],
      "priority": 30,
      "enabled": true
    }
  ],
  "suppression_rules": [
    {
      "name": "known-issue",
      "rule_ids": ["aws-s3-001"],
      "reason": "Known exception for legacy bucket",
      "expires_at": "2025-12-31T00:00:00Z",
      "enabled": true
    }
  ],
  "rate_limits": {
    "slack-security": {
      "max_alerts": 50,
      "window_seconds": 3600,
      "burst_limit": 5
    }
  }
}
`

## DestinationConfig

**Tags:** dataclass

Configuration for an alert destination.

Attributes:
    name: Unique destination name
    type: Destination type (slack, pagerduty, email, jira, teams, webhook)
    enabled: Whether destination is active
    config: Destination-specific configuration

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `type` | `str` | - |
| `enabled` | `bool` | `True` |
| `config` | `dict[(str, Any)]` | `field(...)` |

## AlertConfig

**Tags:** dataclass

Complete alert configuration.

Attributes:
    destinations: List of configured destinations
    routing_rules: Rules for routing findings
    suppression_rules: Rules for suppressing alerts
    rate_limits: Rate limits per destination
    default_rate_limit: Default rate limit
    dedup_window_hours: Deduplication time window
    enabled: Whether alerting is enabled globally

### Attributes

| Name | Type | Default |
|------|------|---------|
| `destinations` | `list[DestinationConfig]` | `field(...)` |
| `routing_rules` | `list[RoutingRule]` | `field(...)` |
| `suppression_rules` | `list[SuppressionRule]` | `field(...)` |
| `rate_limits` | `dict[(str, RateLimit)]` | `field(...)` |
| `default_rate_limit` | `RateLimit` | `field(...)` |
| `dedup_window_hours` | `int` | `24` |
| `enabled` | `bool` | `True` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary representation.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> AlertConfig`

**Decorators:** @classmethod

Create AlertConfig from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`AlertConfig`

## AlertConfigLoader

Loads and saves alert configuration.

Supports loading from JSON/YAML files and environment variables.

### Methods

#### `__init__(self, config_path: str | Path | None) -> None`

Initialize the config loader.

**Parameters:**

- `config_path` (`str | Path | None`) - Path to configuration file

**Returns:**

`None`

#### `load(self) -> AlertConfig`

Load configuration from file.

**Returns:**

`AlertConfig` - AlertConfig instance

#### `save(self, config: AlertConfig, path: Path | None) -> None`

Save configuration to file.

**Parameters:**

- `config` (`AlertConfig`) - Configuration to save
- `path` (`Path | None`) - Path to save to (uses config_path if not specified)

**Returns:**

`None`

#### `get_config(self) -> AlertConfig`

Get the current configuration.

**Returns:**

`AlertConfig`

#### `reload(self) -> AlertConfig`

Reload configuration from source.

**Returns:**

`AlertConfig`

### `create_default_config() -> AlertConfig`

Create a default alert configuration.

**Returns:**

`AlertConfig` - AlertConfig with sensible defaults
