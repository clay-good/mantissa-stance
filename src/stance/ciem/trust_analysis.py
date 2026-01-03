"""
Cross-account trust relationship analysis for CIEM.

Identifies and analyzes trust relationships between accounts,
roles, and external identities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)


class TrustType(Enum):
    """Type of trust relationship."""

    SAME_ACCOUNT = "same_account"
    CROSS_ACCOUNT = "cross_account"
    EXTERNAL_IDENTITY = "external_identity"
    SERVICE_PRINCIPAL = "service_principal"
    FEDERATED = "federated"
    PUBLIC = "public"


class TrustRisk(Enum):
    """Risk level of a trust relationship."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TrustRelationship:
    """
    A trust relationship from one identity to another.

    Attributes:
        source_id: The trusting resource (e.g., role ARN)
        source_name: Human-readable name
        source_account: Account ID of the source
        target_principal: Who is trusted (account ID, ARN, or "*")
        target_type: Type of the trusted principal
        trust_type: Classification of the trust
        conditions: Conditions on the trust
        permissions: What the trusted entity can do
        risk: Risk level of this trust
    """

    source_id: str
    source_name: str
    source_account: str
    target_principal: str
    target_type: str
    trust_type: TrustType
    conditions: dict[str, Any] = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    risk: TrustRisk = TrustRisk.LOW

    @property
    def is_cross_account(self) -> bool:
        """Check if this is a cross-account trust."""
        return self.trust_type == TrustType.CROSS_ACCOUNT

    @property
    def is_public(self) -> bool:
        """Check if this is a public trust."""
        return self.trust_type == TrustType.PUBLIC

    @property
    def has_conditions(self) -> bool:
        """Check if trust has conditions."""
        return len(self.conditions) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "source_account": self.source_account,
            "target_principal": self.target_principal,
            "target_type": self.target_type,
            "trust_type": self.trust_type.value,
            "conditions": self.conditions,
            "permissions": self.permissions,
            "risk": self.risk.value,
            "is_cross_account": self.is_cross_account,
            "has_conditions": self.has_conditions,
        }


@dataclass
class CrossAccountAccess:
    """
    Summary of cross-account access for an account.

    Attributes:
        account_id: The account being analyzed
        trusts_out: Accounts this account trusts
        trusts_in: Accounts that trust this account
        high_risk_trusts: Trust relationships with high risk
        public_trusts: Publicly accessible trusts
    """

    account_id: str
    trusts_out: list[TrustRelationship] = field(default_factory=list)
    trusts_in: list[TrustRelationship] = field(default_factory=list)
    high_risk_trusts: list[TrustRelationship] = field(default_factory=list)
    public_trusts: list[TrustRelationship] = field(default_factory=list)

    @property
    def external_account_count(self) -> int:
        """Count unique external accounts with access."""
        return len(set(t.target_principal for t in self.trusts_out if t.is_cross_account))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "account_id": self.account_id,
            "trusts_out_count": len(self.trusts_out),
            "trusts_in_count": len(self.trusts_in),
            "high_risk_count": len(self.high_risk_trusts),
            "public_count": len(self.public_trusts),
            "external_account_count": self.external_account_count,
        }


class TrustAnalyzer:
    """
    Analyzes trust relationships across cloud accounts.

    Identifies cross-account access, external trusts, and
    risky trust configurations.
    """

    def __init__(self, own_accounts: list[str] | None = None):
        """
        Initialize analyzer.

        Args:
            own_accounts: List of account IDs owned by the organization
        """
        self.own_accounts = set(own_accounts or [])

    def analyze_role(self, role: Asset) -> list[TrustRelationship]:
        """
        Analyze trust relationships for a role.

        Args:
            role: The IAM role asset

        Returns:
            List of trust relationships
        """
        trusts: list[TrustRelationship] = []

        trust_policy = role.properties.get("assume_role_policy", {})
        statements = trust_policy.get("Statement", [])

        source_account = self._extract_account_id(role.id)

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principals = statement.get("Principal", {})
            conditions = statement.get("Condition", {})

            # Handle different principal formats
            if isinstance(principals, str):
                if principals == "*":
                    principals = {"AWS": "*"}
                else:
                    principals = {"AWS": [principals]}

            # Process AWS principals
            aws_principals = principals.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for principal in aws_principals:
                trust = self._create_trust_relationship(
                    role=role,
                    source_account=source_account,
                    principal=principal,
                    principal_type="AWS",
                    conditions=conditions,
                )
                trusts.append(trust)

            # Process Service principals
            service_principals = principals.get("Service", [])
            if isinstance(service_principals, str):
                service_principals = [service_principals]

            for principal in service_principals:
                trust = self._create_trust_relationship(
                    role=role,
                    source_account=source_account,
                    principal=principal,
                    principal_type="Service",
                    conditions=conditions,
                )
                trusts.append(trust)

            # Process Federated principals
            federated_principals = principals.get("Federated", [])
            if isinstance(federated_principals, str):
                federated_principals = [federated_principals]

            for principal in federated_principals:
                trust = self._create_trust_relationship(
                    role=role,
                    source_account=source_account,
                    principal=principal,
                    principal_type="Federated",
                    conditions=conditions,
                )
                trusts.append(trust)

        return trusts

    def analyze_all(self, roles: AssetCollection) -> list[TrustRelationship]:
        """
        Analyze all roles for trust relationships.

        Args:
            roles: Collection of role assets

        Returns:
            All trust relationships found
        """
        all_trusts: list[TrustRelationship] = []

        for role in roles:
            if role.resource_type not in ["aws_iam_role", "gcp_iam_role", "azure_role"]:
                continue

            try:
                trusts = self.analyze_role(role)
                all_trusts.extend(trusts)
            except Exception as e:
                logger.warning(f"Failed to analyze role {role.id}: {e}")

        return all_trusts

    def get_cross_account_summary(
        self,
        trusts: list[TrustRelationship],
        account_id: str,
    ) -> CrossAccountAccess:
        """
        Get cross-account access summary for an account.

        Args:
            trusts: All trust relationships
            account_id: Account to analyze

        Returns:
            CrossAccountAccess summary
        """
        trusts_out = [t for t in trusts if t.source_account == account_id]
        trusts_in = [
            t for t in trusts
            if t.source_account != account_id
            and (account_id in t.target_principal or t.target_principal == "*")
        ]

        high_risk = [
            t for t in trusts_out
            if t.risk in [TrustRisk.HIGH, TrustRisk.CRITICAL]
        ]

        public = [t for t in trusts_out if t.is_public]

        return CrossAccountAccess(
            account_id=account_id,
            trusts_out=trusts_out,
            trusts_in=trusts_in,
            high_risk_trusts=high_risk,
            public_trusts=public,
        )

    def generate_findings(
        self,
        trusts: list[TrustRelationship],
    ) -> list[Finding]:
        """
        Generate findings for risky trust relationships.

        Args:
            trusts: All trust relationships

        Returns:
            List of findings
        """
        findings: list[Finding] = []

        for trust in trusts:
            if trust.risk == TrustRisk.CRITICAL:
                findings.append(
                    Finding(
                        id=f"trust-critical-{trust.source_id}",
                        rule_id="ciem-trust-001",
                        resource_id=trust.source_id,
                        resource_type="aws_iam_role",
                        finding_type=FindingType.MISCONFIGURATION,
                        severity=Severity.CRITICAL,
                        title=f"Critical trust relationship: {trust.source_name}",
                        description=(
                            f"Role {trust.source_name} has a critical trust "
                            f"configuration allowing {trust.target_principal} "
                            f"to assume it."
                        ),
                        recommendation=(
                            "Review and restrict the trust policy. "
                            "Add conditions to limit who can assume this role."
                        ),
                    )
                )
            elif trust.risk == TrustRisk.HIGH:
                findings.append(
                    Finding(
                        id=f"trust-high-{trust.source_id}",
                        rule_id="ciem-trust-002",
                        resource_id=trust.source_id,
                        resource_type="aws_iam_role",
                        finding_type=FindingType.MISCONFIGURATION,
                        severity=Severity.HIGH,
                        title=f"High-risk trust relationship: {trust.source_name}",
                        description=(
                            f"Role {trust.source_name} trusts "
                            f"{trust.target_principal} without conditions."
                        ),
                        recommendation=(
                            "Add conditions like sts:ExternalId to the trust policy."
                        ),
                    )
                )

        return findings

    def _create_trust_relationship(
        self,
        role: Asset,
        source_account: str,
        principal: str,
        principal_type: str,
        conditions: dict[str, Any],
    ) -> TrustRelationship:
        """Create a TrustRelationship from parsed data."""
        # Determine trust type
        if principal == "*":
            trust_type = TrustType.PUBLIC
            risk = TrustRisk.CRITICAL
        elif principal_type == "Service":
            trust_type = TrustType.SERVICE_PRINCIPAL
            risk = TrustRisk.LOW
        elif principal_type == "Federated":
            trust_type = TrustType.FEDERATED
            risk = TrustRisk.MEDIUM if not conditions else TrustRisk.LOW
        else:
            target_account = self._extract_account_id(principal)
            if target_account == source_account:
                trust_type = TrustType.SAME_ACCOUNT
                risk = TrustRisk.LOW
            elif target_account in self.own_accounts:
                trust_type = TrustType.CROSS_ACCOUNT
                risk = TrustRisk.LOW if conditions else TrustRisk.MEDIUM
            else:
                trust_type = TrustType.EXTERNAL_IDENTITY
                risk = TrustRisk.MEDIUM if conditions else TrustRisk.HIGH

        return TrustRelationship(
            source_id=role.id,
            source_name=role.name,
            source_account=source_account,
            target_principal=principal,
            target_type=principal_type,
            trust_type=trust_type,
            conditions=conditions,
            risk=risk,
        )

    def _extract_account_id(self, arn_or_id: str) -> str:
        """Extract account ID from an ARN or return the ID."""
        if arn_or_id.startswith("arn:aws:"):
            parts = arn_or_id.split(":")
            if len(parts) >= 5:
                return parts[4]
        elif arn_or_id.isdigit() and len(arn_or_id) == 12:
            return arn_or_id
        return "unknown"
