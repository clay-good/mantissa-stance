"""
Alert configuration for Mantissa Stance.

Provides configuration dataclasses and loader for alert routing settings.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from stance.models.finding import Severity
from stance.alerting.router import RoutingRule, SuppressionRule, RateLimit

logger = logging.getLogger(__name__)


@dataclass
class DestinationConfig:
    """
    Configuration for an alert destination.

    Attributes:
        name: Unique destination name
        type: Destination type (slack, pagerduty, email, jira, teams, webhook)
        enabled: Whether destination is active
        config: Destination-specific configuration
    """

    name: str
    type: str
    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class AlertConfig:
    """
    Complete alert configuration.

    Attributes:
        destinations: List of configured destinations
        routing_rules: Rules for routing findings
        suppression_rules: Rules for suppressing alerts
        rate_limits: Rate limits per destination
        default_rate_limit: Default rate limit
        dedup_window_hours: Deduplication time window
        enabled: Whether alerting is enabled globally
    """

    destinations: list[DestinationConfig] = field(default_factory=list)
    routing_rules: list[RoutingRule] = field(default_factory=list)
    suppression_rules: list[SuppressionRule] = field(default_factory=list)
    rate_limits: dict[str, RateLimit] = field(default_factory=dict)
    default_rate_limit: RateLimit = field(default_factory=RateLimit)
    dedup_window_hours: int = 24
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "enabled": self.enabled,
            "dedup_window_hours": self.dedup_window_hours,
            "default_rate_limit": {
                "max_alerts": self.default_rate_limit.max_alerts,
                "window_seconds": self.default_rate_limit.window_seconds,
                "burst_limit": self.default_rate_limit.burst_limit,
            },
            "destinations": [
                {
                    "name": d.name,
                    "type": d.type,
                    "enabled": d.enabled,
                    "config": d.config,
                }
                for d in self.destinations
            ],
            "routing_rules": [
                {
                    "name": r.name,
                    "destinations": r.destinations,
                    "severities": [s.value for s in r.severities],
                    "finding_types": r.finding_types,
                    "resource_types": r.resource_types,
                    "tags": r.tags,
                    "enabled": r.enabled,
                    "priority": r.priority,
                }
                for r in self.routing_rules
            ],
            "suppression_rules": [
                {
                    "name": s.name,
                    "rule_ids": s.rule_ids,
                    "asset_patterns": s.asset_patterns,
                    "reason": s.reason,
                    "expires_at": s.expires_at.isoformat() if s.expires_at else None,
                    "enabled": s.enabled,
                }
                for s in self.suppression_rules
            ],
            "rate_limits": {
                name: {
                    "max_alerts": limit.max_alerts,
                    "window_seconds": limit.window_seconds,
                    "burst_limit": limit.burst_limit,
                }
                for name, limit in self.rate_limits.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertConfig:
        """Create AlertConfig from dictionary."""
        # Parse destinations
        destinations = []
        for d in data.get("destinations", []):
            destinations.append(
                DestinationConfig(
                    name=d["name"],
                    type=d["type"],
                    enabled=d.get("enabled", True),
                    config=d.get("config", {}),
                )
            )

        # Parse routing rules
        routing_rules = []
        for r in data.get("routing_rules", []):
            severities = []
            for s in r.get("severities", []):
                try:
                    severities.append(Severity.from_string(s))
                except ValueError:
                    logger.warning(f"Unknown severity: {s}")

            routing_rules.append(
                RoutingRule(
                    name=r["name"],
                    destinations=r.get("destinations", []),
                    severities=severities,
                    finding_types=r.get("finding_types", []),
                    resource_types=r.get("resource_types", []),
                    tags=r.get("tags", {}),
                    enabled=r.get("enabled", True),
                    priority=r.get("priority", 100),
                )
            )

        # Parse suppression rules
        suppression_rules = []
        for s in data.get("suppression_rules", []):
            expires_at = None
            if s.get("expires_at"):
                expires_at = datetime.fromisoformat(s["expires_at"])

            suppression_rules.append(
                SuppressionRule(
                    name=s["name"],
                    rule_ids=s.get("rule_ids", []),
                    asset_patterns=s.get("asset_patterns", []),
                    reason=s.get("reason", ""),
                    expires_at=expires_at,
                    enabled=s.get("enabled", True),
                )
            )

        # Parse rate limits
        rate_limits = {}
        for name, limit_data in data.get("rate_limits", {}).items():
            rate_limits[name] = RateLimit(
                max_alerts=limit_data.get("max_alerts", 100),
                window_seconds=limit_data.get("window_seconds", 3600),
                burst_limit=limit_data.get("burst_limit", 10),
            )

        # Parse default rate limit
        default_limit_data = data.get("default_rate_limit", {})
        default_rate_limit = RateLimit(
            max_alerts=default_limit_data.get("max_alerts", 100),
            window_seconds=default_limit_data.get("window_seconds", 3600),
            burst_limit=default_limit_data.get("burst_limit", 10),
        )

        return cls(
            destinations=destinations,
            routing_rules=routing_rules,
            suppression_rules=suppression_rules,
            rate_limits=rate_limits,
            default_rate_limit=default_rate_limit,
            dedup_window_hours=data.get("dedup_window_hours", 24),
            enabled=data.get("enabled", True),
        )


class AlertConfigLoader:
    """
    Loads and saves alert configuration.

    Supports loading from JSON/YAML files and environment variables.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        """
        Initialize the config loader.

        Args:
            config_path: Path to configuration file
        """
        self._config_path = Path(config_path) if config_path else None
        self._config: AlertConfig | None = None

    def load(self) -> AlertConfig:
        """
        Load configuration from file.

        Returns:
            AlertConfig instance
        """
        if self._config_path and self._config_path.exists():
            return self._load_from_file(self._config_path)
        else:
            return self._load_from_env()

    def _load_from_file(self, path: Path) -> AlertConfig:
        """Load configuration from file."""
        content = path.read_text()

        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                raise ImportError("PyYAML is required to load YAML config files")
        else:
            data = json.loads(content)

        config = AlertConfig.from_dict(data)
        self._config = config
        logger.info(f"Loaded alert config from {path}")
        return config

    def _load_from_env(self) -> AlertConfig:
        """Load minimal configuration from environment variables."""
        import os

        config = AlertConfig()

        # Check for Slack webhook
        slack_webhook = os.environ.get("STANCE_SLACK_WEBHOOK")
        if slack_webhook:
            config.destinations.append(
                DestinationConfig(
                    name="slack",
                    type="slack",
                    config={"webhook_url": slack_webhook},
                )
            )
            # Add default routing rule
            config.routing_rules.append(
                RoutingRule(
                    name="default-slack",
                    destinations=["slack"],
                    severities=[Severity.CRITICAL, Severity.HIGH],
                )
            )

        # Check for PagerDuty
        pd_key = os.environ.get("STANCE_PAGERDUTY_KEY")
        if pd_key:
            config.destinations.append(
                DestinationConfig(
                    name="pagerduty",
                    type="pagerduty",
                    config={"routing_key": pd_key},
                )
            )
            config.routing_rules.append(
                RoutingRule(
                    name="critical-pagerduty",
                    destinations=["pagerduty"],
                    severities=[Severity.CRITICAL],
                    priority=10,
                )
            )

        # Check for email
        smtp_host = os.environ.get("STANCE_SMTP_HOST")
        if smtp_host:
            config.destinations.append(
                DestinationConfig(
                    name="email",
                    type="email",
                    config={
                        "smtp_host": smtp_host,
                        "smtp_port": int(os.environ.get("STANCE_SMTP_PORT", "587")),
                        "from_address": os.environ.get("STANCE_EMAIL_FROM", "stance@localhost"),
                        "to_addresses": os.environ.get("STANCE_EMAIL_TO", "").split(","),
                    },
                )
            )

        self._config = config
        logger.info("Loaded alert config from environment")
        return config

    def save(self, config: AlertConfig, path: Path | None = None) -> None:
        """
        Save configuration to file.

        Args:
            config: Configuration to save
            path: Path to save to (uses config_path if not specified)
        """
        save_path = path or self._config_path
        if not save_path:
            raise ValueError("No path specified for saving config")

        data = config.to_dict()

        if save_path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                content = yaml.dump(data, default_flow_style=False)
            except ImportError:
                raise ImportError("PyYAML is required to save YAML config files")
        else:
            content = json.dumps(data, indent=2)

        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(content)
        logger.info(f"Saved alert config to {save_path}")

    def get_config(self) -> AlertConfig:
        """Get the current configuration."""
        if self._config is None:
            self._config = self.load()
        return self._config

    def reload(self) -> AlertConfig:
        """Reload configuration from source."""
        self._config = None
        return self.load()


def create_default_config() -> AlertConfig:
    """
    Create a default alert configuration.

    Returns:
        AlertConfig with sensible defaults
    """
    return AlertConfig(
        destinations=[],
        routing_rules=[
            # Critical findings to all destinations
            RoutingRule(
                name="critical-all",
                destinations=[],  # Will match any configured destination
                severities=[Severity.CRITICAL],
                priority=10,
            ),
            # High findings to primary destinations
            RoutingRule(
                name="high-primary",
                destinations=[],
                severities=[Severity.HIGH],
                priority=20,
            ),
        ],
        suppression_rules=[],
        rate_limits={},
        default_rate_limit=RateLimit(
            max_alerts=100,
            window_seconds=3600,
            burst_limit=10,
        ),
        dedup_window_hours=24,
        enabled=True,
    )


# Example configuration template
EXAMPLE_CONFIG = """
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
"""
