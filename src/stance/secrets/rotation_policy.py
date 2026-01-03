"""
Rotation Policy Enforcement Module

Defines and enforces rotation policies for secrets based on type,
sensitivity, compliance requirements, and organizational standards.

Part of Phase 82: Secret Rotation Monitoring
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
import re
import logging

from stance.secrets.inventory import (
    SecretInventory,
    SecretInventoryItem,
    SecretType,
    SecretSource,
    SecretStatus,
)


logger = logging.getLogger(__name__)


class RotationFrequency(Enum):
    """Standard rotation frequency options."""
    DAILY = "daily"
    WEEKLY = "weekly"
    BIWEEKLY = "biweekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMI_ANNUAL = "semi_annual"
    ANNUAL = "annual"
    NEVER = "never"  # For secrets that shouldn't be rotated
    CUSTOM = "custom"  # Custom interval in days


class PolicySeverity(Enum):
    """Severity level of policy violations."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EnforcementAction(Enum):
    """Actions to take when policy is violated."""
    ALERT_ONLY = "alert_only"  # Just notify
    WARN = "warn"  # Warn but allow
    BLOCK = "block"  # Block operations until rotated
    AUTO_ROTATE = "auto_rotate"  # Trigger automatic rotation
    DISABLE = "disable"  # Disable the secret
    REVOKE = "revoke"  # Revoke access


class ComplianceFramework(Enum):
    """Compliance frameworks that may require specific rotation policies."""
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST_800_53 = "nist_800_53"
    CIS = "cis"
    ISO_27001 = "iso_27001"
    FedRAMP = "fedramp"
    SOX = "sox"


@dataclass
class RotationRequirement:
    """Defines a rotation requirement from a compliance framework."""
    framework: ComplianceFramework
    control_id: str
    description: str
    max_rotation_days: int
    applies_to: List[SecretType]
    severity: PolicySeverity = PolicySeverity.HIGH
    reference_url: str = ""


@dataclass
class RotationPolicy:
    """
    Defines a rotation policy for secrets.

    Policies can be based on secret type, source, tags, or custom criteria.
    """
    policy_id: str
    name: str
    description: str

    # Rotation requirements
    frequency: RotationFrequency = RotationFrequency.QUARTERLY
    max_age_days: int = 90  # Maximum days before rotation required
    warning_days: int = 14  # Days before max_age to start warning
    grace_period_days: int = 7  # Grace period after max_age before enforcement

    # Scope - what this policy applies to
    applies_to_types: Set[SecretType] = field(default_factory=set)
    applies_to_sources: Set[SecretSource] = field(default_factory=set)
    applies_to_tags: Set[str] = field(default_factory=set)
    applies_to_name_patterns: List[str] = field(default_factory=list)

    # Exclusions
    exclude_types: Set[SecretType] = field(default_factory=set)
    exclude_sources: Set[SecretSource] = field(default_factory=set)
    exclude_tags: Set[str] = field(default_factory=set)
    exclude_name_patterns: List[str] = field(default_factory=list)

    # Enforcement
    enforcement_action: EnforcementAction = EnforcementAction.ALERT_ONLY
    severity: PolicySeverity = PolicySeverity.MEDIUM
    enabled: bool = True

    # Compliance
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    compliance_control_ids: List[str] = field(default_factory=list)

    # Metadata
    owner: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0"

    def applies_to_secret(self, secret: SecretInventoryItem) -> bool:
        """Check if this policy applies to a specific secret."""
        # Check exclusions first
        if secret.secret_type in self.exclude_types:
            return False
        if secret.source in self.exclude_sources:
            return False
        if self.exclude_tags and secret.tags:
            if self.exclude_tags & set(secret.tags):
                return False
        for pattern in self.exclude_name_patterns:
            if re.match(pattern, secret.name, re.IGNORECASE):
                return False

        # Check inclusions
        type_match = not self.applies_to_types or secret.secret_type in self.applies_to_types
        source_match = not self.applies_to_sources or secret.source in self.applies_to_sources

        tag_match = True
        if self.applies_to_tags and secret.tags:
            tag_match = bool(self.applies_to_tags & set(secret.tags))
        elif self.applies_to_tags and not secret.tags:
            tag_match = False

        name_match = True
        if self.applies_to_name_patterns:
            name_match = any(
                re.match(pattern, secret.name, re.IGNORECASE)
                for pattern in self.applies_to_name_patterns
            )

        return type_match and source_match and tag_match and name_match

    def get_days_until_rotation_due(self, secret: SecretInventoryItem) -> int:
        """Calculate days until rotation is due for a secret."""
        if not secret.metadata:
            return -1

        last_rotation = secret.metadata.last_rotated_at or secret.metadata.created_at
        if not last_rotation:
            return -1

        age_days = (datetime.utcnow() - last_rotation).days
        return self.max_age_days - age_days

    def is_rotation_due(self, secret: SecretInventoryItem) -> bool:
        """Check if rotation is due for a secret."""
        days_until_due = self.get_days_until_rotation_due(secret)
        return days_until_due <= 0

    def is_in_warning_period(self, secret: SecretInventoryItem) -> bool:
        """Check if secret is in warning period."""
        days_until_due = self.get_days_until_rotation_due(secret)
        return 0 < days_until_due <= self.warning_days

    def is_in_grace_period(self, secret: SecretInventoryItem) -> bool:
        """Check if secret is in grace period (past due but within grace)."""
        days_until_due = self.get_days_until_rotation_due(secret)
        return -self.grace_period_days <= days_until_due < 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "frequency": self.frequency.value,
            "max_age_days": self.max_age_days,
            "warning_days": self.warning_days,
            "grace_period_days": self.grace_period_days,
            "applies_to_types": [t.value for t in self.applies_to_types],
            "applies_to_sources": [s.value for s in self.applies_to_sources],
            "enforcement_action": self.enforcement_action.value,
            "severity": self.severity.value,
            "enabled": self.enabled,
            "compliance_frameworks": [f.value for f in self.compliance_frameworks],
        }


@dataclass
class PolicyViolation:
    """Represents a policy violation for a secret."""
    violation_id: str
    policy: RotationPolicy
    secret: SecretInventoryItem

    # Violation details
    violation_type: str  # "rotation_overdue", "rotation_warning", "no_rotation_history"
    severity: PolicySeverity
    days_overdue: int = 0
    days_until_due: int = 0

    # Timestamps
    detected_at: datetime = field(default_factory=datetime.utcnow)
    due_date: Optional[datetime] = None

    # Enforcement
    enforcement_action: EnforcementAction = EnforcementAction.ALERT_ONLY
    action_taken: bool = False
    action_result: str = ""

    # Context
    message: str = ""
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert violation to dictionary."""
        return {
            "violation_id": self.violation_id,
            "policy_id": self.policy.policy_id,
            "policy_name": self.policy.name,
            "secret_id": self.secret.secret_id,
            "secret_name": self.secret.name,
            "secret_type": self.secret.secret_type.value,
            "violation_type": self.violation_type,
            "severity": self.severity.value,
            "days_overdue": self.days_overdue,
            "detected_at": self.detected_at.isoformat(),
            "message": self.message,
            "remediation_steps": self.remediation_steps,
        }


@dataclass
class RotationPolicySet:
    """
    A collection of rotation policies with priority ordering.

    When multiple policies apply to a secret, the most restrictive
    (lowest max_age_days) takes precedence.
    """
    name: str
    description: str
    policies: List[RotationPolicy] = field(default_factory=list)

    # Default policy for secrets with no matching policies
    default_policy: Optional[RotationPolicy] = None

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0"

    def add_policy(self, policy: RotationPolicy) -> None:
        """Add a policy to the set."""
        self.policies.append(policy)

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID."""
        for i, policy in enumerate(self.policies):
            if policy.policy_id == policy_id:
                del self.policies[i]
                return True
        return False

    def get_policy(self, policy_id: str) -> Optional[RotationPolicy]:
        """Get a policy by ID."""
        for policy in self.policies:
            if policy.policy_id == policy_id:
                return policy
        return None

    def get_applicable_policies(
        self,
        secret: SecretInventoryItem,
    ) -> List[RotationPolicy]:
        """Get all policies that apply to a secret."""
        return [
            policy for policy in self.policies
            if policy.enabled and policy.applies_to_secret(secret)
        ]

    def get_most_restrictive_policy(
        self,
        secret: SecretInventoryItem,
    ) -> Optional[RotationPolicy]:
        """Get the most restrictive policy that applies to a secret."""
        applicable = self.get_applicable_policies(secret)
        if not applicable:
            return self.default_policy
        return min(applicable, key=lambda p: p.max_age_days)


class RotationPolicyEnforcer:
    """
    Enforces rotation policies against a secret inventory.

    Identifies violations, generates reports, and optionally triggers
    enforcement actions.
    """

    def __init__(
        self,
        policy_set: Optional[RotationPolicySet] = None,
        auto_rotate_callback: Optional[Callable[[SecretInventoryItem], bool]] = None,
    ):
        """
        Initialize the policy enforcer.

        Args:
            policy_set: Policy set to enforce
            auto_rotate_callback: Callback function for auto-rotation
        """
        self.policy_set = policy_set or self._create_default_policy_set()
        self.auto_rotate_callback = auto_rotate_callback
        self.violation_history: List[PolicyViolation] = []

    def _create_default_policy_set(self) -> RotationPolicySet:
        """Create a default policy set based on security best practices."""
        policy_set = RotationPolicySet(
            name="Default Security Policies",
            description="Standard rotation policies based on industry best practices",
        )

        # Critical credentials - 90 day rotation
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-critical-90",
            name="Critical Credentials - 90 Days",
            description="Critical credentials require rotation every 90 days",
            frequency=RotationFrequency.QUARTERLY,
            max_age_days=90,
            warning_days=14,
            grace_period_days=7,
            applies_to_types={
                SecretType.AWS_ACCESS_KEY,
                SecretType.AWS_SECRET_KEY,
                SecretType.GCP_SERVICE_ACCOUNT_KEY,
                SecretType.DATABASE_PASSWORD,
                SecretType.MYSQL_PASSWORD,
                SecretType.POSTGRESQL_PASSWORD,
                SecretType.MONGODB_PASSWORD,
                SecretType.SSH_PRIVATE_KEY,
            },
            enforcement_action=EnforcementAction.ALERT_ONLY,
            severity=PolicySeverity.HIGH,
            compliance_frameworks=[
                ComplianceFramework.PCI_DSS,
                ComplianceFramework.SOC2,
                ComplianceFramework.NIST_800_53,
            ],
        ))

        # Azure credentials - 180 days (Azure recommends longer cycles)
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-azure-180",
            name="Azure Credentials - 180 Days",
            description="Azure credentials rotation every 180 days",
            frequency=RotationFrequency.SEMI_ANNUAL,
            max_age_days=180,
            warning_days=30,
            grace_period_days=14,
            applies_to_types={
                SecretType.AZURE_CLIENT_SECRET,
                SecretType.AZURE_STORAGE_KEY,
            },
            enforcement_action=EnforcementAction.ALERT_ONLY,
            severity=PolicySeverity.MEDIUM,
        ))

        # API Keys - 180 days
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-api-180",
            name="API Keys - 180 Days",
            description="API keys rotation every 180 days",
            frequency=RotationFrequency.SEMI_ANNUAL,
            max_age_days=180,
            warning_days=30,
            grace_period_days=14,
            applies_to_types={
                SecretType.API_KEY,
                SecretType.GITHUB_TOKEN,
                SecretType.SLACK_TOKEN,
                SecretType.STRIPE_KEY,
                SecretType.TWILIO_AUTH_TOKEN,
                SecretType.SENDGRID_API_KEY,
            },
            enforcement_action=EnforcementAction.WARN,
            severity=PolicySeverity.MEDIUM,
        ))

        # JWT Secrets - 30 days (high security)
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-jwt-30",
            name="JWT Secrets - 30 Days",
            description="JWT signing secrets require frequent rotation",
            frequency=RotationFrequency.MONTHLY,
            max_age_days=30,
            warning_days=7,
            grace_period_days=3,
            applies_to_types={
                SecretType.JWT_SECRET,
            },
            enforcement_action=EnforcementAction.ALERT_ONLY,
            severity=PolicySeverity.HIGH,
        ))

        # OAuth Tokens - depends on type
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-oauth-14",
            name="OAuth Tokens - 14 Days",
            description="OAuth tokens should be refreshed regularly",
            frequency=RotationFrequency.BIWEEKLY,
            max_age_days=14,
            warning_days=3,
            grace_period_days=1,
            applies_to_types={
                SecretType.OAUTH_TOKEN,
            },
            enforcement_action=EnforcementAction.WARN,
            severity=PolicySeverity.MEDIUM,
        ))

        # Refresh tokens - 90 days
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-refresh-90",
            name="Refresh Tokens - 90 Days",
            description="OAuth refresh tokens rotation",
            frequency=RotationFrequency.QUARTERLY,
            max_age_days=90,
            warning_days=14,
            grace_period_days=7,
            applies_to_types={
                SecretType.OAUTH_REFRESH_TOKEN,
            },
            enforcement_action=EnforcementAction.WARN,
            severity=PolicySeverity.MEDIUM,
        ))

        # Certificates - 365 days
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-certs-365",
            name="Certificates - 365 Days",
            description="TLS/SSL certificates annual renewal",
            frequency=RotationFrequency.ANNUAL,
            max_age_days=365,
            warning_days=60,
            grace_period_days=30,
            applies_to_types={
                SecretType.TLS_CERTIFICATE,
                SecretType.SSL_CERTIFICATE,
            },
            enforcement_action=EnforcementAction.ALERT_ONLY,
            severity=PolicySeverity.HIGH,
            compliance_frameworks=[
                ComplianceFramework.PCI_DSS,
            ],
        ))

        # Encryption keys - 730 days (2 years)
        policy_set.add_policy(RotationPolicy(
            policy_id="pol-encryption-730",
            name="Encryption Keys - 2 Years",
            description="Encryption keys rotation every 2 years",
            frequency=RotationFrequency.CUSTOM,
            max_age_days=730,
            warning_days=90,
            grace_period_days=30,
            applies_to_types={
                SecretType.ENCRYPTION_KEY,
                SecretType.PGP_PRIVATE_KEY,
            },
            enforcement_action=EnforcementAction.WARN,
            severity=PolicySeverity.MEDIUM,
        ))

        # Default catch-all policy
        policy_set.default_policy = RotationPolicy(
            policy_id="pol-default",
            name="Default Policy",
            description="Default rotation policy for unclassified secrets",
            frequency=RotationFrequency.SEMI_ANNUAL,
            max_age_days=180,
            warning_days=30,
            grace_period_days=14,
            enforcement_action=EnforcementAction.ALERT_ONLY,
            severity=PolicySeverity.LOW,
        )

        return policy_set

    def enforce(
        self,
        inventory: SecretInventory,
        execute_actions: bool = False,
    ) -> Dict[str, Any]:
        """
        Enforce policies against the inventory.

        Args:
            inventory: Secret inventory to check
            execute_actions: Whether to execute enforcement actions

        Returns:
            Enforcement results with violations and actions taken
        """
        violations: List[PolicyViolation] = []
        warnings: List[PolicyViolation] = []
        compliant: List[SecretInventoryItem] = []
        no_policy: List[SecretInventoryItem] = []

        for secret in inventory.secrets:
            policy = self.policy_set.get_most_restrictive_policy(secret)

            if not policy:
                no_policy.append(secret)
                continue

            # Check policy compliance
            result = self._check_secret_compliance(secret, policy)

            if result["status"] == "violation":
                violation = self._create_violation(
                    secret, policy, result
                )
                violations.append(violation)

                if execute_actions:
                    self._execute_enforcement_action(violation)

            elif result["status"] == "warning":
                warning = self._create_violation(
                    secret, policy, result
                )
                warnings.append(warning)
            else:
                compliant.append(secret)

        # Update violation history
        self.violation_history.extend(violations)

        # Generate summary
        return {
            "total_secrets": len(inventory.secrets),
            "compliant_count": len(compliant),
            "violation_count": len(violations),
            "warning_count": len(warnings),
            "no_policy_count": len(no_policy),
            "compliance_rate": (
                len(compliant) / (len(compliant) + len(violations)) * 100
                if (len(compliant) + len(violations)) > 0 else 100.0
            ),
            "violations": [v.to_dict() for v in violations],
            "warnings": [w.to_dict() for w in warnings],
            "by_severity": self._count_by_severity(violations),
            "by_policy": self._count_by_policy(violations),
            "actions_executed": execute_actions,
        }

    def _check_secret_compliance(
        self,
        secret: SecretInventoryItem,
        policy: RotationPolicy,
    ) -> Dict[str, Any]:
        """Check if a secret complies with a policy."""
        days_until_due = policy.get_days_until_rotation_due(secret)

        # No rotation data available
        if days_until_due == -1:
            return {
                "status": "warning",
                "type": "no_rotation_history",
                "message": "No rotation history available for this secret",
                "days_overdue": 0,
                "days_until_due": -1,
            }

        # Past due date + grace period
        if days_until_due < -policy.grace_period_days:
            return {
                "status": "violation",
                "type": "rotation_overdue",
                "message": f"Secret is {abs(days_until_due)} days overdue for rotation",
                "days_overdue": abs(days_until_due),
                "days_until_due": days_until_due,
            }

        # Past due but within grace period
        if days_until_due < 0:
            return {
                "status": "violation",
                "type": "rotation_overdue_grace",
                "message": f"Secret is {abs(days_until_due)} days overdue (within grace period)",
                "days_overdue": abs(days_until_due),
                "days_until_due": days_until_due,
            }

        # Within warning period
        if days_until_due <= policy.warning_days:
            return {
                "status": "warning",
                "type": "rotation_warning",
                "message": f"Secret rotation due in {days_until_due} days",
                "days_overdue": 0,
                "days_until_due": days_until_due,
            }

        # Compliant
        return {
            "status": "compliant",
            "type": "compliant",
            "message": f"Secret is compliant, rotation due in {days_until_due} days",
            "days_overdue": 0,
            "days_until_due": days_until_due,
        }

    def _create_violation(
        self,
        secret: SecretInventoryItem,
        policy: RotationPolicy,
        result: Dict[str, Any],
    ) -> PolicyViolation:
        """Create a policy violation record."""
        # Calculate due date
        due_date = None
        if secret.metadata and (secret.metadata.last_rotated_at or secret.metadata.created_at):
            last_rotation = secret.metadata.last_rotated_at or secret.metadata.created_at
            due_date = last_rotation + timedelta(days=policy.max_age_days)

        # Generate remediation steps
        remediation_steps = self._generate_remediation_steps(secret, policy, result)

        return PolicyViolation(
            violation_id=f"viol-{secret.secret_id}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            policy=policy,
            secret=secret,
            violation_type=result["type"],
            severity=policy.severity,
            days_overdue=result["days_overdue"],
            days_until_due=result["days_until_due"],
            due_date=due_date,
            enforcement_action=policy.enforcement_action,
            message=result["message"],
            remediation_steps=remediation_steps,
        )

    def _generate_remediation_steps(
        self,
        secret: SecretInventoryItem,
        policy: RotationPolicy,
        result: Dict[str, Any],
    ) -> List[str]:
        """Generate remediation steps for a violation."""
        steps = []

        # Source-specific rotation instructions
        source_instructions = {
            SecretSource.AWS_SECRETS_MANAGER: [
                "1. Navigate to AWS Secrets Manager console",
                "2. Select the secret and click 'Rotate secret immediately'",
                "3. Or use AWS CLI: aws secretsmanager rotate-secret --secret-id <secret-id>",
            ],
            SecretSource.AWS_IAM: [
                "1. Navigate to AWS IAM console",
                "2. Select the user and go to 'Security credentials'",
                "3. Create a new access key and deactivate the old one",
                "4. Update all applications using this key",
                "5. Delete the old access key after verification",
            ],
            SecretSource.AZURE_KEY_VAULT: [
                "1. Navigate to Azure Key Vault",
                "2. Select the secret and create a new version",
                "3. Update applications to use the new version",
                "4. Disable the old version after verification",
            ],
            SecretSource.GCP_SECRET_MANAGER: [
                "1. Navigate to GCP Secret Manager",
                "2. Add a new secret version",
                "3. Update applications to use the new version",
                "4. Disable or destroy old versions",
            ],
            SecretSource.KUBERNETES_SECRET: [
                "1. Generate new secret value",
                "2. Update the Kubernetes Secret: kubectl create secret generic <name> --from-literal=<key>=<new-value> --dry-run=client -o yaml | kubectl apply -f -",
                "3. Restart pods using the secret or wait for automatic refresh",
            ],
            SecretSource.HASHICORP_VAULT: [
                "1. Generate new secret value",
                "2. Write to Vault: vault kv put <path> <key>=<new-value>",
                "3. Applications using dynamic secrets will auto-refresh",
            ],
        }

        if secret.source in source_instructions:
            steps.extend(source_instructions[secret.source])
        else:
            steps.extend([
                "1. Identify all applications using this secret",
                "2. Generate a new secret value",
                "3. Update the secret in the secret store",
                "4. Update all dependent applications",
                "5. Verify functionality after rotation",
                "6. Remove/disable the old secret value",
            ])

        # Add type-specific notes
        if secret.secret_type in {SecretType.DATABASE_PASSWORD, SecretType.MYSQL_PASSWORD,
                                   SecretType.POSTGRESQL_PASSWORD}:
            steps.append("Note: Consider using connection pooling to minimize downtime during rotation")

        if secret.secret_type in {SecretType.TLS_CERTIFICATE, SecretType.SSL_CERTIFICATE}:
            steps.append("Note: Ensure certificate chain is complete and trusted")

        return steps

    def _execute_enforcement_action(self, violation: PolicyViolation) -> None:
        """Execute the enforcement action for a violation."""
        action = violation.enforcement_action

        if action == EnforcementAction.ALERT_ONLY:
            logger.warning(
                f"Policy violation alert: {violation.message} "
                f"(Secret: {violation.secret.name}, Policy: {violation.policy.name})"
            )
            violation.action_taken = True
            violation.action_result = "Alert logged"

        elif action == EnforcementAction.WARN:
            logger.warning(
                f"Policy violation warning: {violation.message} "
                f"(Secret: {violation.secret.name}, Policy: {violation.policy.name})"
            )
            violation.action_taken = True
            violation.action_result = "Warning issued"

        elif action == EnforcementAction.AUTO_ROTATE:
            if self.auto_rotate_callback:
                try:
                    success = self.auto_rotate_callback(violation.secret)
                    violation.action_taken = True
                    violation.action_result = "Auto-rotation succeeded" if success else "Auto-rotation failed"
                except Exception as e:
                    violation.action_result = f"Auto-rotation error: {str(e)}"
            else:
                violation.action_result = "Auto-rotation not configured"

        elif action == EnforcementAction.BLOCK:
            logger.error(
                f"Policy violation BLOCKED: {violation.message} "
                f"(Secret: {violation.secret.name}, Policy: {violation.policy.name})"
            )
            violation.action_taken = True
            violation.action_result = "Operations blocked"

        elif action == EnforcementAction.DISABLE:
            logger.critical(
                f"Policy violation - SECRET SHOULD BE DISABLED: {violation.message} "
                f"(Secret: {violation.secret.name})"
            )
            violation.action_taken = True
            violation.action_result = "Disable recommended"

        elif action == EnforcementAction.REVOKE:
            logger.critical(
                f"Policy violation - ACCESS SHOULD BE REVOKED: {violation.message} "
                f"(Secret: {violation.secret.name})"
            )
            violation.action_taken = True
            violation.action_result = "Revocation recommended"

    def _count_by_severity(
        self,
        violations: List[PolicyViolation],
    ) -> Dict[str, int]:
        """Count violations by severity."""
        counts = {s.value: 0 for s in PolicySeverity}
        for v in violations:
            counts[v.severity.value] += 1
        return counts

    def _count_by_policy(
        self,
        violations: List[PolicyViolation],
    ) -> Dict[str, int]:
        """Count violations by policy."""
        counts: Dict[str, int] = {}
        for v in violations:
            policy_id = v.policy.policy_id
            counts[policy_id] = counts.get(policy_id, 0) + 1
        return counts

    def get_compliance_requirements(
        self,
        framework: ComplianceFramework,
    ) -> List[RotationRequirement]:
        """Get rotation requirements for a compliance framework."""
        requirements = {
            ComplianceFramework.PCI_DSS: [
                RotationRequirement(
                    framework=ComplianceFramework.PCI_DSS,
                    control_id="8.2.4",
                    description="Change user passwords at least every 90 days",
                    max_rotation_days=90,
                    applies_to=[
                        SecretType.DATABASE_PASSWORD,
                        SecretType.LDAP_PASSWORD,
                    ],
                    severity=PolicySeverity.HIGH,
                    reference_url="https://www.pcisecuritystandards.org/",
                ),
                RotationRequirement(
                    framework=ComplianceFramework.PCI_DSS,
                    control_id="3.6.4",
                    description="Cryptographic key changes when keys reach end of cryptoperiod",
                    max_rotation_days=365,
                    applies_to=[
                        SecretType.ENCRYPTION_KEY,
                        SecretType.TLS_CERTIFICATE,
                    ],
                    severity=PolicySeverity.HIGH,
                ),
            ],
            ComplianceFramework.SOC2: [
                RotationRequirement(
                    framework=ComplianceFramework.SOC2,
                    control_id="CC6.1",
                    description="Logical access security - credential rotation",
                    max_rotation_days=90,
                    applies_to=[
                        SecretType.AWS_ACCESS_KEY,
                        SecretType.DATABASE_PASSWORD,
                        SecretType.API_KEY,
                    ],
                    severity=PolicySeverity.MEDIUM,
                ),
            ],
            ComplianceFramework.NIST_800_53: [
                RotationRequirement(
                    framework=ComplianceFramework.NIST_800_53,
                    control_id="IA-5(1)",
                    description="Authenticator Management - password rotation",
                    max_rotation_days=60,
                    applies_to=[
                        SecretType.DATABASE_PASSWORD,
                        SecretType.LDAP_PASSWORD,
                    ],
                    severity=PolicySeverity.HIGH,
                ),
                RotationRequirement(
                    framework=ComplianceFramework.NIST_800_53,
                    control_id="SC-12",
                    description="Cryptographic Key Establishment and Management",
                    max_rotation_days=365,
                    applies_to=[
                        SecretType.ENCRYPTION_KEY,
                        SecretType.SSH_PRIVATE_KEY,
                    ],
                    severity=PolicySeverity.MEDIUM,
                ),
            ],
            ComplianceFramework.HIPAA: [
                RotationRequirement(
                    framework=ComplianceFramework.HIPAA,
                    control_id="164.312(d)",
                    description="Person or entity authentication",
                    max_rotation_days=90,
                    applies_to=[
                        SecretType.DATABASE_PASSWORD,
                        SecretType.API_KEY,
                    ],
                    severity=PolicySeverity.HIGH,
                ),
            ],
            ComplianceFramework.CIS: [
                RotationRequirement(
                    framework=ComplianceFramework.CIS,
                    control_id="1.14",
                    description="Ensure access keys are rotated every 90 days or less",
                    max_rotation_days=90,
                    applies_to=[
                        SecretType.AWS_ACCESS_KEY,
                        SecretType.AWS_SECRET_KEY,
                    ],
                    severity=PolicySeverity.HIGH,
                    reference_url="https://www.cisecurity.org/",
                ),
            ],
        }

        return requirements.get(framework, [])

    def create_compliance_policy_set(
        self,
        frameworks: List[ComplianceFramework],
    ) -> RotationPolicySet:
        """Create a policy set based on compliance framework requirements."""
        policy_set = RotationPolicySet(
            name="Compliance-Driven Policies",
            description=f"Policies derived from: {', '.join(f.value for f in frameworks)}",
        )

        # Collect all requirements and find most restrictive per type
        type_requirements: Dict[SecretType, Tuple[int, RotationRequirement]] = {}

        for framework in frameworks:
            for req in self.get_compliance_requirements(framework):
                for secret_type in req.applies_to:
                    current = type_requirements.get(secret_type)
                    if not current or req.max_rotation_days < current[0]:
                        type_requirements[secret_type] = (req.max_rotation_days, req)

        # Create policies from requirements
        for secret_type, (max_days, req) in type_requirements.items():
            policy = RotationPolicy(
                policy_id=f"pol-{req.framework.value}-{secret_type.value}",
                name=f"{req.framework.value.upper()} - {secret_type.value}",
                description=f"{req.description} ({req.control_id})",
                max_age_days=max_days,
                warning_days=min(14, max_days // 6),
                grace_period_days=min(7, max_days // 12),
                applies_to_types={secret_type},
                severity=req.severity,
                compliance_frameworks=[req.framework],
                compliance_control_ids=[req.control_id],
            )
            policy_set.add_policy(policy)

        return policy_set

    def generate_policy_report(self) -> Dict[str, Any]:
        """Generate a report of all configured policies."""
        policies = []

        for policy in self.policy_set.policies:
            policies.append({
                "policy_id": policy.policy_id,
                "name": policy.name,
                "max_age_days": policy.max_age_days,
                "applies_to_types": [t.value for t in policy.applies_to_types],
                "severity": policy.severity.value,
                "enforcement_action": policy.enforcement_action.value,
                "enabled": policy.enabled,
            })

        return {
            "policy_set_name": self.policy_set.name,
            "total_policies": len(self.policy_set.policies),
            "policies": policies,
            "default_policy": self.policy_set.default_policy.to_dict() if self.policy_set.default_policy else None,
            "violation_history_count": len(self.violation_history),
        }
