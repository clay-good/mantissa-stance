"""
Alert destinations for Mantissa Stance.

Provides integrations for sending security alerts to various
notification platforms and services.
"""

from stance.alerting.destinations.base import (
    BaseDestination,
    AlertPayload,
)
from stance.alerting.destinations.slack import SlackDestination
from stance.alerting.destinations.pagerduty import PagerDutyDestination
from stance.alerting.destinations.email import EmailDestination
from stance.alerting.destinations.webhook import (
    WebhookDestination,
    TeamsDestination,
    JiraDestination,
)

__all__ = [
    # Base
    "BaseDestination",
    "AlertPayload",
    # Destinations
    "SlackDestination",
    "PagerDutyDestination",
    "EmailDestination",
    "WebhookDestination",
    "TeamsDestination",
    "JiraDestination",
]


def create_destination(
    destination_type: str,
    name: str,
    config: dict,
) -> BaseDestination:
    """
    Factory function to create destination by type.

    Args:
        destination_type: Type of destination (slack, pagerduty, email, etc.)
        name: Destination name
        config: Destination configuration

    Returns:
        Configured destination instance

    Raises:
        ValueError: If destination type is unknown
    """
    destinations = {
        "slack": SlackDestination,
        "pagerduty": PagerDutyDestination,
        "email": EmailDestination,
        "webhook": WebhookDestination,
        "teams": TeamsDestination,
        "jira": JiraDestination,
    }

    if destination_type not in destinations:
        raise ValueError(
            f"Unknown destination type: {destination_type}. "
            f"Available: {', '.join(destinations.keys())}"
        )

    return destinations[destination_type](name=name, config=config)
