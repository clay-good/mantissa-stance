"""
Alert routing and notifications for Mantissa Stance.

Provides alert routing, destination integrations, and templates
for sending security finding notifications to various platforms.
"""

from stance.alerting.router import (
    AlertRouter,
    AlertDestination,
    RoutingRule,
    SuppressionRule,
    RateLimit,
    AlertResult,
    RoutingResult,
)
from stance.alerting.config import (
    AlertConfig,
    AlertConfigLoader,
    DestinationConfig,
    create_default_config,
)
from stance.alerting.state import (
    AlertState,
    AlertRecord,
    AlertStateBackend,
    InMemoryAlertState,
    DynamoDBAlertState,
    FirestoreAlertState,
    CosmosDBAlertState,
)
from stance.alerting.destinations import (
    BaseDestination,
    SlackDestination,
    PagerDutyDestination,
    EmailDestination,
    WebhookDestination,
    TeamsDestination,
    JiraDestination,
    create_destination,
)
from stance.alerting.templates import (
    AlertTemplate,
    TemplateContext,
    DefaultTemplate,
    MisconfigurationTemplate,
    VulnerabilityTemplate,
    ComplianceTemplate,
    CriticalExposureTemplate,
    get_template_for_finding,
)

__all__ = [
    # Router
    "AlertRouter",
    "AlertDestination",
    "RoutingRule",
    "SuppressionRule",
    "RateLimit",
    "AlertResult",
    "RoutingResult",
    # Config
    "AlertConfig",
    "AlertConfigLoader",
    "DestinationConfig",
    "create_default_config",
    # State
    "AlertState",
    "AlertRecord",
    "AlertStateBackend",
    "InMemoryAlertState",
    "DynamoDBAlertState",
    "FirestoreAlertState",
    "CosmosDBAlertState",
    # Destinations
    "BaseDestination",
    "SlackDestination",
    "PagerDutyDestination",
    "EmailDestination",
    "WebhookDestination",
    "TeamsDestination",
    "JiraDestination",
    "create_destination",
    # Templates
    "AlertTemplate",
    "TemplateContext",
    "DefaultTemplate",
    "MisconfigurationTemplate",
    "VulnerabilityTemplate",
    "ComplianceTemplate",
    "CriticalExposureTemplate",
    "get_template_for_finding",
]
