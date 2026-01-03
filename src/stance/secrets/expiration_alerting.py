"""
Expiration Alerting Module

Provides alerting functionality for secret expirations, rotation deadlines,
and policy violations with configurable alert channels and escalation.

Part of Phase 82: Secret Rotation Monitoring
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Callable, Tuple
import json
import logging
import hashlib

from stance.secrets.inventory import (
    SecretInventory,
    SecretInventoryItem,
    SecretType,
    SecretSource,
    SecretStatus,
)
from stance.secrets.age_tracker import (
    SecretAgeTracker,
    SecretAge,
    AgeStatus,
)
from stance.secrets.rotation_policy import (
    RotationPolicyEnforcer,
    PolicyViolation,
    PolicySeverity,
)


logger = logging.getLogger(__name__)


class AlertPriority(Enum):
    """Priority level for alerts."""
    CRITICAL = "critical"  # Immediate action required
    HIGH = "high"  # Action required within 24 hours
    MEDIUM = "medium"  # Action required within 1 week
    LOW = "low"  # Informational, no immediate action
    INFO = "info"  # For logging/tracking only


class AlertType(Enum):
    """Type of alert being generated."""
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    ROTATION_OVERDUE = "rotation_overdue"
    ROTATION_WARNING = "rotation_warning"
    POLICY_VIOLATION = "policy_violation"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    KEY_AGE_CRITICAL = "key_age_critical"
    COMPLIANCE_RISK = "compliance_risk"
    BULK_EXPIRATION = "bulk_expiration"  # Multiple secrets expiring together


class AlertChannel(Enum):
    """Notification channels for alerts."""
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"
    SNS = "sns"  # AWS SNS
    PUBSUB = "pubsub"  # GCP Pub/Sub
    EVENTBRIDGE = "eventbridge"  # AWS EventBridge
    TEAMS = "teams"  # Microsoft Teams
    OPSGENIE = "opsgenie"
    JIRA = "jira"  # Create tickets
    LOG = "log"  # Just log the alert


class AlertStatus(Enum):
    """Status of an alert."""
    PENDING = "pending"
    SENT = "sent"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"
    FAILED = "failed"


@dataclass
class AlertRecipient:
    """Defines a recipient for alerts."""
    recipient_id: str
    name: str
    channel: AlertChannel
    address: str  # Email, webhook URL, channel ID, etc.

    # Filtering
    min_priority: AlertPriority = AlertPriority.LOW
    alert_types: Set[AlertType] = field(default_factory=set)  # Empty = all types
    secret_types: Set[SecretType] = field(default_factory=set)  # Empty = all types
    sources: Set[SecretSource] = field(default_factory=set)  # Empty = all sources

    # Schedule
    enabled: bool = True
    quiet_hours_start: Optional[int] = None  # Hour (0-23) to start quiet period
    quiet_hours_end: Optional[int] = None  # Hour (0-23) to end quiet period

    def should_receive(
        self,
        priority: AlertPriority,
        alert_type: AlertType,
        secret_type: Optional[SecretType] = None,
        source: Optional[SecretSource] = None,
    ) -> bool:
        """Check if this recipient should receive an alert."""
        if not self.enabled:
            return False

        # Check priority
        priority_order = [
            AlertPriority.INFO,
            AlertPriority.LOW,
            AlertPriority.MEDIUM,
            AlertPriority.HIGH,
            AlertPriority.CRITICAL,
        ]
        if priority_order.index(priority) < priority_order.index(self.min_priority):
            return False

        # Check alert type filter
        if self.alert_types and alert_type not in self.alert_types:
            return False

        # Check secret type filter
        if self.secret_types and secret_type and secret_type not in self.secret_types:
            return False

        # Check source filter
        if self.sources and source and source not in self.sources:
            return False

        # Check quiet hours
        if self.quiet_hours_start is not None and self.quiet_hours_end is not None:
            current_hour = datetime.utcnow().hour
            if self.quiet_hours_start <= current_hour < self.quiet_hours_end:
                # Only allow critical alerts during quiet hours
                if priority != AlertPriority.CRITICAL:
                    return False

        return True


@dataclass
class ExpirationAlert:
    """Represents an expiration or rotation alert."""
    alert_id: str
    alert_type: AlertType
    priority: AlertPriority
    status: AlertStatus = AlertStatus.PENDING

    # Secret information
    secret_id: str = ""
    secret_name: str = ""
    secret_type: Optional[SecretType] = None
    source: Optional[SecretSource] = None

    # Alert details
    title: str = ""
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    # Timing
    days_until_event: int = 0  # Days until expiration/rotation due
    event_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    sent_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    # Tracking
    notification_count: int = 0
    last_notification_at: Optional[datetime] = None
    escalation_level: int = 0

    # Related alerts (for bulk alerts)
    related_secret_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "priority": self.priority.value,
            "status": self.status.value,
            "secret_id": self.secret_id,
            "secret_name": self.secret_name,
            "secret_type": self.secret_type.value if self.secret_type else None,
            "source": self.source.value if self.source else None,
            "title": self.title,
            "message": self.message,
            "days_until_event": self.days_until_event,
            "event_date": self.event_date.isoformat() if self.event_date else None,
            "created_at": self.created_at.isoformat(),
            "notification_count": self.notification_count,
            "escalation_level": self.escalation_level,
        }

    def to_slack_block(self) -> Dict[str, Any]:
        """Format alert for Slack."""
        priority_emoji = {
            AlertPriority.CRITICAL: ":rotating_light:",
            AlertPriority.HIGH: ":warning:",
            AlertPriority.MEDIUM: ":large_yellow_circle:",
            AlertPriority.LOW: ":large_blue_circle:",
            AlertPriority.INFO: ":information_source:",
        }

        return {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{priority_emoji.get(self.priority, '')} {self.title}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": self.message,
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Secret:* {self.secret_name}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Type:* {self.secret_type.value if self.secret_type else 'Unknown'}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Priority:* {self.priority.value.upper()}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Days Until Event:* {self.days_until_event}",
                        },
                    ],
                },
            ],
        }

    def to_pagerduty_event(self) -> Dict[str, Any]:
        """Format alert for PagerDuty."""
        severity_map = {
            AlertPriority.CRITICAL: "critical",
            AlertPriority.HIGH: "error",
            AlertPriority.MEDIUM: "warning",
            AlertPriority.LOW: "info",
            AlertPriority.INFO: "info",
        }

        return {
            "routing_key": "",  # To be filled by sender
            "event_action": "trigger",
            "dedup_key": self.alert_id,
            "payload": {
                "summary": self.title,
                "severity": severity_map.get(self.priority, "warning"),
                "source": f"secret-rotation-monitor",
                "custom_details": {
                    "secret_id": self.secret_id,
                    "secret_name": self.secret_name,
                    "secret_type": self.secret_type.value if self.secret_type else None,
                    "message": self.message,
                    "days_until_event": self.days_until_event,
                },
            },
        }


@dataclass
class ExpirationAlertRule:
    """Defines when to generate alerts for expirations."""
    rule_id: str
    name: str
    description: str
    enabled: bool = True

    # Trigger conditions
    alert_type: AlertType = AlertType.EXPIRING_SOON
    days_before_expiration: List[int] = field(default_factory=lambda: [30, 14, 7, 3, 1])
    applies_to_types: Set[SecretType] = field(default_factory=set)
    applies_to_sources: Set[SecretSource] = field(default_factory=set)

    # Alert configuration
    priority_by_days: Dict[int, AlertPriority] = field(default_factory=dict)

    # Notification settings
    recipients: List[AlertRecipient] = field(default_factory=list)
    escalation_enabled: bool = True
    escalation_days: List[int] = field(default_factory=lambda: [7, 3, 1])

    # Deduplication
    cooldown_hours: int = 24  # Don't re-alert for same secret within this period

    def __post_init__(self):
        """Set default priority mapping if not provided."""
        if not self.priority_by_days:
            self.priority_by_days = {
                30: AlertPriority.LOW,
                14: AlertPriority.MEDIUM,
                7: AlertPriority.HIGH,
                3: AlertPriority.HIGH,
                1: AlertPriority.CRITICAL,
                0: AlertPriority.CRITICAL,
            }

    def get_priority_for_days(self, days: int) -> AlertPriority:
        """Get the appropriate priority for days until expiration."""
        for threshold, priority in sorted(self.priority_by_days.items(), reverse=True):
            if days <= threshold:
                return priority
        return AlertPriority.LOW


@dataclass
class AlertDigest:
    """Aggregated alert summary for digest notifications."""
    digest_id: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None

    # Summary counts
    total_alerts: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # By type
    expiring_count: int = 0
    expired_count: int = 0
    rotation_overdue_count: int = 0

    # Alert list
    alerts: List[ExpirationAlert] = field(default_factory=list)

    # Top items needing attention
    urgent_secrets: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert digest to dictionary."""
        return {
            "digest_id": self.digest_id,
            "generated_at": self.generated_at.isoformat(),
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "summary": {
                "total_alerts": self.total_alerts,
                "by_priority": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                },
                "by_type": {
                    "expiring": self.expiring_count,
                    "expired": self.expired_count,
                    "rotation_overdue": self.rotation_overdue_count,
                },
            },
            "urgent_secrets": self.urgent_secrets,
        }


class ExpirationAlerter:
    """
    Manages expiration and rotation alerts for secrets.

    Generates alerts based on configurable rules, handles notifications
    through multiple channels, and tracks alert state.
    """

    def __init__(
        self,
        age_tracker: Optional[SecretAgeTracker] = None,
        policy_enforcer: Optional[RotationPolicyEnforcer] = None,
    ):
        """
        Initialize the alerter.

        Args:
            age_tracker: SecretAgeTracker for age analysis
            policy_enforcer: RotationPolicyEnforcer for policy violations
        """
        self.age_tracker = age_tracker or SecretAgeTracker()
        self.policy_enforcer = policy_enforcer

        # Alert rules
        self.rules: List[ExpirationAlertRule] = []
        self._init_default_rules()

        # Recipients
        self.recipients: List[AlertRecipient] = []

        # Alert tracking
        self.active_alerts: Dict[str, ExpirationAlert] = {}
        self.alert_history: List[ExpirationAlert] = []
        self.last_alert_times: Dict[str, datetime] = {}  # secret_id -> last alert time

        # Notification handlers
        self.notification_handlers: Dict[AlertChannel, Callable] = {}

    def _init_default_rules(self) -> None:
        """Initialize default alerting rules."""
        # Expiration alerts
        self.rules.append(ExpirationAlertRule(
            rule_id="rule-expiration-default",
            name="Default Expiration Alerts",
            description="Alert on secrets approaching expiration",
            alert_type=AlertType.EXPIRING_SOON,
            days_before_expiration=[60, 30, 14, 7, 3, 1],
            priority_by_days={
                60: AlertPriority.INFO,
                30: AlertPriority.LOW,
                14: AlertPriority.MEDIUM,
                7: AlertPriority.HIGH,
                3: AlertPriority.HIGH,
                1: AlertPriority.CRITICAL,
                0: AlertPriority.CRITICAL,
            },
        ))

        # Certificate-specific rules (more lead time)
        self.rules.append(ExpirationAlertRule(
            rule_id="rule-cert-expiration",
            name="Certificate Expiration Alerts",
            description="Extended lead time for certificate expirations",
            alert_type=AlertType.CERTIFICATE_EXPIRING,
            days_before_expiration=[90, 60, 30, 14, 7, 3, 1],
            applies_to_types={SecretType.TLS_CERTIFICATE, SecretType.SSL_CERTIFICATE},
            priority_by_days={
                90: AlertPriority.INFO,
                60: AlertPriority.LOW,
                30: AlertPriority.MEDIUM,
                14: AlertPriority.HIGH,
                7: AlertPriority.HIGH,
                3: AlertPriority.CRITICAL,
                1: AlertPriority.CRITICAL,
            },
        ))

        # Rotation overdue alerts
        self.rules.append(ExpirationAlertRule(
            rule_id="rule-rotation-overdue",
            name="Rotation Overdue Alerts",
            description="Alert when secrets are overdue for rotation",
            alert_type=AlertType.ROTATION_OVERDUE,
            days_before_expiration=[0, -7, -14, -30],  # Negative = days overdue
            priority_by_days={
                0: AlertPriority.MEDIUM,
                -7: AlertPriority.HIGH,
                -14: AlertPriority.HIGH,
                -30: AlertPriority.CRITICAL,
            },
        ))

        # Critical key age alerts
        self.rules.append(ExpirationAlertRule(
            rule_id="rule-key-age-critical",
            name="Critical Key Age Alerts",
            description="Alert when critical keys are aging",
            alert_type=AlertType.KEY_AGE_CRITICAL,
            applies_to_types={
                SecretType.AWS_ACCESS_KEY,
                SecretType.AWS_SECRET_KEY,
                SecretType.GCP_SERVICE_ACCOUNT_KEY,
                SecretType.SSH_PRIVATE_KEY,
            },
            days_before_expiration=[90, 60, 30],  # Based on age thresholds
            priority_by_days={
                90: AlertPriority.LOW,
                60: AlertPriority.MEDIUM,
                30: AlertPriority.HIGH,
            },
        ))

    def add_rule(self, rule: ExpirationAlertRule) -> None:
        """Add an alerting rule."""
        self.rules.append(rule)

    def add_recipient(self, recipient: AlertRecipient) -> None:
        """Add an alert recipient."""
        self.recipients.append(recipient)

    def register_handler(
        self,
        channel: AlertChannel,
        handler: Callable[[ExpirationAlert, AlertRecipient], bool],
    ) -> None:
        """Register a notification handler for a channel."""
        self.notification_handlers[channel] = handler

    def check_inventory(
        self,
        inventory: SecretInventory,
        send_notifications: bool = True,
    ) -> List[ExpirationAlert]:
        """
        Check inventory and generate alerts.

        Args:
            inventory: Secret inventory to check
            send_notifications: Whether to send notifications for new alerts

        Returns:
            List of generated alerts
        """
        generated_alerts: List[ExpirationAlert] = []
        now = datetime.utcnow()

        for secret in inventory.secrets:
            for rule in self.rules:
                if not rule.enabled:
                    continue

                # Check if rule applies to this secret
                if rule.applies_to_types and secret.secret_type not in rule.applies_to_types:
                    continue
                if rule.applies_to_sources and secret.source not in rule.applies_to_sources:
                    continue

                # Check cooldown
                cooldown_key = f"{secret.secret_id}:{rule.rule_id}"
                last_alert = self.last_alert_times.get(cooldown_key)
                if last_alert and (now - last_alert).total_seconds() < rule.cooldown_hours * 3600:
                    continue

                # Generate alert if conditions are met
                alert = self._check_secret_for_rule(secret, rule)
                if alert:
                    generated_alerts.append(alert)
                    self.active_alerts[alert.alert_id] = alert
                    self.last_alert_times[cooldown_key] = now

                    if send_notifications:
                        self._send_alert(alert)

        return generated_alerts

    def _check_secret_for_rule(
        self,
        secret: SecretInventoryItem,
        rule: ExpirationAlertRule,
    ) -> Optional[ExpirationAlert]:
        """Check if a secret triggers an alert rule."""
        if rule.alert_type in {AlertType.EXPIRING_SOON, AlertType.CERTIFICATE_EXPIRING}:
            return self._check_expiration_alert(secret, rule)
        elif rule.alert_type == AlertType.ROTATION_OVERDUE:
            return self._check_rotation_alert(secret, rule)
        elif rule.alert_type == AlertType.KEY_AGE_CRITICAL:
            return self._check_age_alert(secret, rule)
        return None

    def _check_expiration_alert(
        self,
        secret: SecretInventoryItem,
        rule: ExpirationAlertRule,
    ) -> Optional[ExpirationAlert]:
        """Check for expiration-based alerts."""
        if not secret.metadata or not secret.metadata.expires_at:
            return None

        now = datetime.utcnow()
        days_until = (secret.metadata.expires_at - now).days

        # Check if we should alert at this threshold
        alert_threshold = None
        for threshold in sorted(rule.days_before_expiration, reverse=True):
            if days_until <= threshold:
                alert_threshold = threshold
                break

        if alert_threshold is None:
            return None

        # Already expired?
        if days_until < 0:
            alert_type = AlertType.EXPIRED
            title = f"SECRET EXPIRED: {secret.name}"
            message = f"Secret '{secret.name}' expired {abs(days_until)} days ago"
            priority = AlertPriority.CRITICAL
        else:
            alert_type = rule.alert_type
            title = f"Secret Expiring: {secret.name}"
            message = f"Secret '{secret.name}' will expire in {days_until} days"
            priority = rule.get_priority_for_days(days_until)

        alert_id = self._generate_alert_id(secret, rule, days_until)

        return ExpirationAlert(
            alert_id=alert_id,
            alert_type=alert_type,
            priority=priority,
            secret_id=secret.secret_id,
            secret_name=secret.name,
            secret_type=secret.secret_type,
            source=secret.source,
            title=title,
            message=message,
            days_until_event=days_until,
            event_date=secret.metadata.expires_at,
            details={
                "rule_id": rule.rule_id,
                "threshold": alert_threshold,
                "expiration_date": secret.metadata.expires_at.isoformat(),
            },
        )

    def _check_rotation_alert(
        self,
        secret: SecretInventoryItem,
        rule: ExpirationAlertRule,
    ) -> Optional[ExpirationAlert]:
        """Check for rotation-based alerts."""
        # Use age tracker to get rotation info
        secret_age = self.age_tracker._analyze_secret_age(secret)

        if secret_age.days_since_rotation < 0:
            return None

        # Check if rotation is overdue based on age status
        if secret_age.rotation_status not in {AgeStatus.STALE, AgeStatus.CRITICAL}:
            return None

        days_overdue = secret_age.days_since_rotation - 90  # Assuming 90-day policy

        # Find matching threshold
        alert_threshold = None
        for threshold in sorted(rule.days_before_expiration):
            if days_overdue >= abs(threshold):
                alert_threshold = threshold

        if alert_threshold is None:
            return None

        priority = rule.get_priority_for_days(-days_overdue)
        alert_id = self._generate_alert_id(secret, rule, -days_overdue)

        return ExpirationAlert(
            alert_id=alert_id,
            alert_type=AlertType.ROTATION_OVERDUE,
            priority=priority,
            secret_id=secret.secret_id,
            secret_name=secret.name,
            secret_type=secret.secret_type,
            source=secret.source,
            title=f"Rotation Overdue: {secret.name}",
            message=f"Secret '{secret.name}' is {days_overdue} days overdue for rotation",
            days_until_event=-days_overdue,
            details={
                "rule_id": rule.rule_id,
                "days_since_rotation": secret_age.days_since_rotation,
                "rotation_status": secret_age.rotation_status.value,
            },
        )

    def _check_age_alert(
        self,
        secret: SecretInventoryItem,
        rule: ExpirationAlertRule,
    ) -> Optional[ExpirationAlert]:
        """Check for age-based alerts on critical keys."""
        secret_age = self.age_tracker._analyze_secret_age(secret)

        if secret_age.age_days < 0:
            return None

        # Check age thresholds
        alert_threshold = None
        for threshold in sorted(rule.days_before_expiration, reverse=True):
            if secret_age.age_days >= threshold:
                alert_threshold = threshold
                break

        if alert_threshold is None:
            return None

        priority = rule.get_priority_for_days(alert_threshold)
        alert_id = self._generate_alert_id(secret, rule, secret_age.age_days)

        return ExpirationAlert(
            alert_id=alert_id,
            alert_type=AlertType.KEY_AGE_CRITICAL,
            priority=priority,
            secret_id=secret.secret_id,
            secret_name=secret.name,
            secret_type=secret.secret_type,
            source=secret.source,
            title=f"Aging Key: {secret.name}",
            message=f"Key '{secret.name}' is {secret_age.age_days} days old and should be rotated",
            days_until_event=0,
            details={
                "rule_id": rule.rule_id,
                "age_days": secret_age.age_days,
                "age_status": secret_age.age_status.value,
                "risk_score": secret_age.risk_score,
            },
        )

    def _generate_alert_id(
        self,
        secret: SecretInventoryItem,
        rule: ExpirationAlertRule,
        threshold: int,
    ) -> str:
        """Generate a unique alert ID for deduplication."""
        content = f"{secret.secret_id}:{rule.rule_id}:{threshold}"
        return f"alert-{hashlib.md5(content.encode()).hexdigest()[:12]}"

    def _send_alert(self, alert: ExpirationAlert) -> None:
        """Send alert to appropriate recipients."""
        sent_count = 0

        for recipient in self.recipients:
            if not recipient.should_receive(
                alert.priority,
                alert.alert_type,
                alert.secret_type,
                alert.source,
            ):
                continue

            handler = self.notification_handlers.get(recipient.channel)
            if handler:
                try:
                    success = handler(alert, recipient)
                    if success:
                        sent_count += 1
                except Exception as e:
                    logger.error(f"Failed to send alert via {recipient.channel}: {e}")
            else:
                # Default: log the alert
                self._log_alert(alert, recipient)
                sent_count += 1

        alert.notification_count += 1
        alert.last_notification_at = datetime.utcnow()

        if sent_count > 0:
            alert.status = AlertStatus.SENT
            alert.sent_at = datetime.utcnow()

    def _log_alert(self, alert: ExpirationAlert, recipient: AlertRecipient) -> None:
        """Log an alert (default handler)."""
        log_func = {
            AlertPriority.CRITICAL: logger.critical,
            AlertPriority.HIGH: logger.error,
            AlertPriority.MEDIUM: logger.warning,
            AlertPriority.LOW: logger.info,
            AlertPriority.INFO: logger.info,
        }.get(alert.priority, logger.info)

        log_func(
            f"[{alert.alert_type.value.upper()}] {alert.title}: {alert.message} "
            f"(Secret: {alert.secret_name}, Recipient: {recipient.name})"
        )

    def acknowledge_alert(self, alert_id: str, acknowledged_by: str = "") -> bool:
        """Mark an alert as acknowledged."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_at = datetime.utcnow()
            alert.details["acknowledged_by"] = acknowledged_by
            return True
        return False

    def resolve_alert(self, alert_id: str, resolution_note: str = "") -> bool:
        """Mark an alert as resolved."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()
            alert.details["resolution_note"] = resolution_note
            self.alert_history.append(alert)
            del self.active_alerts[alert_id]
            return True
        return False

    def generate_digest(
        self,
        period_hours: int = 24,
        include_resolved: bool = False,
    ) -> AlertDigest:
        """Generate an alert digest for a time period."""
        now = datetime.utcnow()
        period_start = now - timedelta(hours=period_hours)

        # Collect relevant alerts
        alerts = []
        for alert in self.active_alerts.values():
            if alert.created_at >= period_start:
                alerts.append(alert)

        if include_resolved:
            for alert in self.alert_history:
                if alert.created_at >= period_start:
                    alerts.append(alert)

        # Create digest
        digest = AlertDigest(
            digest_id=f"digest-{now.strftime('%Y%m%d%H%M%S')}",
            period_start=period_start,
            period_end=now,
            total_alerts=len(alerts),
            alerts=alerts,
        )

        # Count by priority
        for alert in alerts:
            if alert.priority == AlertPriority.CRITICAL:
                digest.critical_count += 1
            elif alert.priority == AlertPriority.HIGH:
                digest.high_count += 1
            elif alert.priority == AlertPriority.MEDIUM:
                digest.medium_count += 1
            else:
                digest.low_count += 1

        # Count by type
        for alert in alerts:
            if alert.alert_type == AlertType.EXPIRING_SOON:
                digest.expiring_count += 1
            elif alert.alert_type == AlertType.EXPIRED:
                digest.expired_count += 1
            elif alert.alert_type == AlertType.ROTATION_OVERDUE:
                digest.rotation_overdue_count += 1

        # Get urgent secrets (critical/high priority)
        urgent = sorted(
            [a for a in alerts if a.priority in {AlertPriority.CRITICAL, AlertPriority.HIGH}],
            key=lambda a: (a.priority.value, a.days_until_event),
        )
        digest.urgent_secrets = [
            {
                "secret_name": a.secret_name,
                "alert_type": a.alert_type.value,
                "priority": a.priority.value,
                "days_until_event": a.days_until_event,
            }
            for a in urgent[:10]  # Top 10
        ]

        return digest

    def get_active_alerts(
        self,
        priority: Optional[AlertPriority] = None,
        alert_type: Optional[AlertType] = None,
    ) -> List[ExpirationAlert]:
        """Get active alerts, optionally filtered."""
        alerts = list(self.active_alerts.values())

        if priority:
            alerts = [a for a in alerts if a.priority == priority]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]

        return sorted(alerts, key=lambda a: (a.priority.value, a.created_at), reverse=True)

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alert status."""
        active = list(self.active_alerts.values())

        return {
            "total_active": len(active),
            "by_priority": {
                "critical": sum(1 for a in active if a.priority == AlertPriority.CRITICAL),
                "high": sum(1 for a in active if a.priority == AlertPriority.HIGH),
                "medium": sum(1 for a in active if a.priority == AlertPriority.MEDIUM),
                "low": sum(1 for a in active if a.priority == AlertPriority.LOW),
            },
            "by_status": {
                "pending": sum(1 for a in active if a.status == AlertStatus.PENDING),
                "sent": sum(1 for a in active if a.status == AlertStatus.SENT),
                "acknowledged": sum(1 for a in active if a.status == AlertStatus.ACKNOWLEDGED),
            },
            "by_type": {
                "expiring_soon": sum(1 for a in active if a.alert_type == AlertType.EXPIRING_SOON),
                "expired": sum(1 for a in active if a.alert_type == AlertType.EXPIRED),
                "rotation_overdue": sum(1 for a in active if a.alert_type == AlertType.ROTATION_OVERDUE),
                "key_age_critical": sum(1 for a in active if a.alert_type == AlertType.KEY_AGE_CRITICAL),
            },
            "total_historical": len(self.alert_history),
            "rules_count": len(self.rules),
            "recipients_count": len(self.recipients),
        }

    def check_bulk_expirations(
        self,
        inventory: SecretInventory,
        days_window: int = 7,
        threshold_count: int = 5,
    ) -> Optional[ExpirationAlert]:
        """
        Check for bulk expirations (many secrets expiring around same time).

        Args:
            inventory: Secret inventory
            days_window: Window to group expirations
            threshold_count: Minimum secrets to trigger bulk alert

        Returns:
            Bulk expiration alert if threshold met
        """
        now = datetime.utcnow()
        window_end = now + timedelta(days=days_window)

        expiring_soon = []
        for secret in inventory.secrets:
            if secret.metadata and secret.metadata.expires_at:
                if now <= secret.metadata.expires_at <= window_end:
                    expiring_soon.append(secret)

        if len(expiring_soon) >= threshold_count:
            alert_id = f"bulk-{now.strftime('%Y%m%d')}-{len(expiring_soon)}"

            return ExpirationAlert(
                alert_id=alert_id,
                alert_type=AlertType.BULK_EXPIRATION,
                priority=AlertPriority.HIGH,
                title=f"Bulk Expiration Warning: {len(expiring_soon)} secrets",
                message=f"{len(expiring_soon)} secrets will expire within the next {days_window} days",
                days_until_event=days_window,
                related_secret_ids=[s.secret_id for s in expiring_soon],
                details={
                    "secret_names": [s.name for s in expiring_soon],
                    "window_days": days_window,
                },
            )

        return None

    def export_alerts(self, format: str = "json") -> str:
        """Export active alerts in specified format."""
        alerts = [a.to_dict() for a in self.active_alerts.values()]

        if format == "json":
            return json.dumps(alerts, indent=2)
        elif format == "csv":
            if not alerts:
                return "alert_id,alert_type,priority,secret_name,days_until_event\n"

            lines = ["alert_id,alert_type,priority,secret_name,days_until_event"]
            for a in alerts:
                lines.append(
                    f"{a['alert_id']},{a['alert_type']},{a['priority']},"
                    f"{a['secret_name']},{a['days_until_event']}"
                )
            return "\n".join(lines)
        else:
            return json.dumps(alerts, indent=2)
