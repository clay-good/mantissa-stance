"""
Secret Rotation Monitoring module for Mantissa Stance.

Provides comprehensive secret lifecycle management including:
- Secret inventory across cloud providers
- Age tracking and rotation monitoring
- Policy-based rotation enforcement
- Expiration alerting and notifications

Components:
- Secret Inventory: Track secrets across AWS, Azure, GCP, and Kubernetes
- Age Tracker: Monitor secret creation and last rotation dates
- Rotation Policy: Define and enforce rotation requirements
- Expiration Alerts: Proactive alerting for expiring secrets
"""

from stance.secrets.inventory import (
    SecretType,
    SecretSource,
    SecretStatus,
    SecretMetadata,
    SecretInventoryItem,
    SecretInventory,
    SecretInventoryCollector,
)

from stance.secrets.age_tracker import (
    SecretAge,
    AgeStatus,
    SecretAgeReport,
    SecretAgeTracker,
)

from stance.secrets.rotation_policy import (
    RotationRequirement,
    RotationFrequency,
    RotationPolicy,
    RotationPolicySet,
    PolicyViolation,
    RotationPolicyEnforcer,
)

from stance.secrets.expiration_alerting import (
    ExpirationAlert,
    AlertPriority,
    AlertChannel,
    ExpirationAlertRule,
    ExpirationAlerter,
)

__all__ = [
    # Inventory
    "SecretType",
    "SecretSource",
    "SecretStatus",
    "SecretMetadata",
    "SecretInventoryItem",
    "SecretInventory",
    "SecretInventoryCollector",
    # Age Tracker
    "SecretAge",
    "AgeStatus",
    "SecretAgeReport",
    "SecretAgeTracker",
    # Rotation Policy
    "RotationRequirement",
    "RotationFrequency",
    "RotationPolicy",
    "RotationPolicySet",
    "PolicyViolation",
    "RotationPolicyEnforcer",
    # Expiration Alerting
    "ExpirationAlert",
    "AlertPriority",
    "AlertChannel",
    "ExpirationAlertRule",
    "ExpirationAlerter",
]
