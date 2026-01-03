"""
Effective permissions calculator for CIEM.

Calculates the actual permissions an identity has by evaluating
all attached policies, group memberships, and permission boundaries.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.models.asset import Asset, AssetCollection

logger = logging.getLogger(__name__)


class PermissionEffect(Enum):
    """Effect of a permission statement."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Permission:
    """
    A single permission.

    Attributes:
        service: AWS service (e.g., "s3", "ec2")
        action: Action within the service (e.g., "GetObject", "*")
        resource: Resource ARN pattern
        effect: Allow or Deny
        conditions: IAM conditions attached to this permission
    """

    service: str
    action: str
    resource: str
    effect: PermissionEffect
    conditions: dict[str, Any] = field(default_factory=dict)

    @property
    def is_wildcard_action(self) -> bool:
        """Check if action is a wildcard."""
        return self.action == "*" or self.action.endswith(":*")

    @property
    def is_wildcard_resource(self) -> bool:
        """Check if resource is a wildcard."""
        return self.resource == "*"

    @property
    def is_admin(self) -> bool:
        """Check if this is an admin-level permission."""
        return (
            self.service == "*"
            and self.action == "*"
            and self.resource == "*"
            and self.effect == PermissionEffect.ALLOW
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "service": self.service,
            "action": self.action,
            "resource": self.resource,
            "effect": self.effect.value,
            "conditions": self.conditions,
        }


@dataclass
class PermissionSet:
    """
    A set of permissions for an identity.

    Attributes:
        identity_id: The identity (user/role) ID
        identity_type: Type of identity (user, role, group)
        permissions: List of individual permissions
        sources: Where each permission came from (policy ARNs)
    """

    identity_id: str
    identity_type: str
    permissions: list[Permission] = field(default_factory=list)
    sources: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_admin_access(self) -> bool:
        """Check if identity has admin access."""
        return any(p.is_admin for p in self.permissions if p.effect == PermissionEffect.ALLOW)

    @property
    def service_count(self) -> int:
        """Count unique services with permissions."""
        return len(set(p.service for p in self.permissions))

    @property
    def action_count(self) -> int:
        """Count total actions allowed."""
        return len([p for p in self.permissions if p.effect == PermissionEffect.ALLOW])

    def get_services(self) -> set[str]:
        """Get all services with permissions."""
        return set(p.service for p in self.permissions)

    def get_actions_for_service(self, service: str) -> list[str]:
        """Get all actions for a specific service."""
        return [
            p.action
            for p in self.permissions
            if p.service == service and p.effect == PermissionEffect.ALLOW
        ]


@dataclass
class EffectiveAccess:
    """
    Effective access summary for an identity.

    Attributes:
        identity_id: The identity ID
        identity_name: Human-readable name
        identity_type: user, role, or service_account
        permission_set: Calculated permissions
        is_admin: Whether identity has admin access
        sensitive_permissions: List of sensitive permissions held
        risk_score: Calculated risk score (0-100)
    """

    identity_id: str
    identity_name: str
    identity_type: str
    permission_set: PermissionSet
    is_admin: bool = False
    sensitive_permissions: list[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "identity_type": self.identity_type,
            "is_admin": self.is_admin,
            "service_count": self.permission_set.service_count,
            "action_count": self.permission_set.action_count,
            "sensitive_permissions": self.sensitive_permissions,
            "risk_score": self.risk_score,
        }


class EffectivePermissionsCalculator:
    """
    Calculates effective permissions for cloud identities.

    Evaluates all attached policies, group memberships, and
    permission boundaries to determine actual access.
    """

    # Sensitive permissions that warrant attention
    SENSITIVE_PERMISSIONS = {
        "aws": [
            "iam:CreateUser",
            "iam:CreateRole",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutRolePolicy",
            "iam:CreateAccessKey",
            "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole",
            "lambda:CreateFunction",
            "lambda:UpdateFunctionCode",
            "ec2:RunInstances",
            "s3:PutBucketPolicy",
            "kms:Decrypt",
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter",
        ],
        "gcp": [
            "iam.roles.create",
            "iam.serviceAccounts.create",
            "iam.serviceAccountKeys.create",
            "resourcemanager.projects.setIamPolicy",
            "compute.instances.create",
            "storage.buckets.setIamPolicy",
            "cloudkms.cryptoKeys.decrypt",
            "secretmanager.versions.access",
        ],
        "azure": [
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.Authorization/roleDefinitions/write",
            "Microsoft.Compute/virtualMachines/write",
            "Microsoft.Storage/storageAccounts/listKeys/action",
            "Microsoft.KeyVault/vaults/secrets/read",
        ],
    }

    def __init__(self, provider: str = "aws"):
        """
        Initialize calculator.

        Args:
            provider: Cloud provider (aws, gcp, azure)
        """
        self.provider = provider

    def calculate_effective_permissions(
        self,
        identity: Asset,
        policies: list[Asset],
        groups: list[Asset] | None = None,
        permission_boundary: Asset | None = None,
    ) -> EffectiveAccess:
        """
        Calculate effective permissions for an identity.

        Args:
            identity: The identity asset (user/role)
            policies: Attached policies
            groups: Group memberships (for users)
            permission_boundary: Permission boundary (if any)

        Returns:
            EffectiveAccess with calculated permissions
        """
        permissions: list[Permission] = []
        sources: dict[str, list[str]] = {}

        # Collect permissions from directly attached policies
        for policy in policies:
            policy_permissions = self._parse_policy(policy)
            permissions.extend(policy_permissions)
            policy_arn = policy.properties.get("arn", policy.id)
            for p in policy_permissions:
                key = f"{p.service}:{p.action}"
                if key not in sources:
                    sources[key] = []
                sources[key].append(policy_arn)

        # Collect permissions from group memberships
        if groups:
            for group in groups:
                group_policies = group.properties.get("attached_policies", [])
                for policy_arn in group_policies:
                    # Would need to resolve policy ARN to policy document
                    pass

        # Apply permission boundary (intersection of allowed permissions)
        if permission_boundary:
            boundary_permissions = self._parse_policy(permission_boundary)
            permissions = self._apply_boundary(permissions, boundary_permissions)

        # Create permission set
        permission_set = PermissionSet(
            identity_id=identity.id,
            identity_type=identity.resource_type.split("_")[-1],
            permissions=permissions,
            sources=sources,
        )

        # Check for admin access
        is_admin = permission_set.has_admin_access

        # Find sensitive permissions
        sensitive = self._find_sensitive_permissions(permissions)

        # Calculate risk score
        risk_score = self._calculate_risk_score(permission_set, is_admin, sensitive)

        return EffectiveAccess(
            identity_id=identity.id,
            identity_name=identity.name,
            identity_type=permission_set.identity_type,
            permission_set=permission_set,
            is_admin=is_admin,
            sensitive_permissions=sensitive,
            risk_score=risk_score,
        )

    def calculate_all(
        self,
        identities: AssetCollection,
        policies: AssetCollection,
    ) -> list[EffectiveAccess]:
        """
        Calculate effective permissions for all identities.

        Args:
            identities: Collection of identity assets
            policies: Collection of policy assets

        Returns:
            List of EffectiveAccess for each identity
        """
        results: list[EffectiveAccess] = []

        # Filter to identity types
        identity_types = [
            f"{self.provider}_iam_user",
            f"{self.provider}_iam_role",
            f"{self.provider}_service_account",
        ]

        for identity in identities:
            if identity.resource_type not in identity_types:
                continue

            # Get attached policies for this identity
            attached_policy_arns = identity.properties.get("attached_policies", [])
            attached_policies = [
                p for p in policies
                if p.properties.get("arn") in attached_policy_arns
            ]

            try:
                access = self.calculate_effective_permissions(
                    identity=identity,
                    policies=attached_policies,
                )
                results.append(access)
            except Exception as e:
                logger.warning(
                    f"Failed to calculate permissions for {identity.id}: {e}"
                )

        return results

    def _parse_policy(self, policy: Asset) -> list[Permission]:
        """Parse a policy into individual permissions."""
        permissions: list[Permission] = []

        document = policy.properties.get("policy_document", {})
        statements = document.get("Statement", [])

        for statement in statements:
            effect = PermissionEffect.ALLOW if statement.get("Effect") == "Allow" else PermissionEffect.DENY

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]

            conditions = statement.get("Condition", {})

            for action in actions:
                # Parse service:action format
                if ":" in action:
                    service, action_name = action.split(":", 1)
                else:
                    service = "*"
                    action_name = action

                for resource in resources:
                    permissions.append(
                        Permission(
                            service=service,
                            action=action_name,
                            resource=resource,
                            effect=effect,
                            conditions=conditions,
                        )
                    )

        return permissions

    def _apply_boundary(
        self,
        permissions: list[Permission],
        boundary: list[Permission],
    ) -> list[Permission]:
        """Apply permission boundary to permissions."""
        # Permission boundary acts as a maximum permissions set
        # Only permissions that are in BOTH the identity's policies
        # AND the boundary are effective
        boundary_allowed = set()
        for p in boundary:
            if p.effect == PermissionEffect.ALLOW:
                boundary_allowed.add(f"{p.service}:{p.action}")

        return [
            p for p in permissions
            if p.effect == PermissionEffect.DENY
            or f"{p.service}:{p.action}" in boundary_allowed
            or f"{p.service}:*" in boundary_allowed
            or "*:*" in boundary_allowed
        ]

    def _find_sensitive_permissions(
        self,
        permissions: list[Permission],
    ) -> list[str]:
        """Find sensitive permissions in the permission set."""
        sensitive = []
        sensitive_list = self.SENSITIVE_PERMISSIONS.get(self.provider, [])

        for p in permissions:
            if p.effect != PermissionEffect.ALLOW:
                continue

            full_action = f"{p.service}:{p.action}"
            if full_action in sensitive_list:
                sensitive.append(full_action)
            elif p.is_wildcard_action and p.service != "*":
                # Check if any sensitive permission matches this service
                for sens in sensitive_list:
                    if sens.startswith(f"{p.service}:"):
                        if full_action not in sensitive:
                            sensitive.append(full_action)
                        break

        return sensitive

    def _calculate_risk_score(
        self,
        permission_set: PermissionSet,
        is_admin: bool,
        sensitive_permissions: list[str],
    ) -> float:
        """Calculate risk score for an identity."""
        score = 0.0

        # Admin access is highest risk
        if is_admin:
            return 100.0

        # Sensitive permissions add significant risk
        score += len(sensitive_permissions) * 10

        # Wide access (many services) adds risk
        if permission_set.service_count > 10:
            score += 20
        elif permission_set.service_count > 5:
            score += 10

        # Many actions adds risk
        if permission_set.action_count > 100:
            score += 15
        elif permission_set.action_count > 50:
            score += 10

        return min(score, 99.0)  # Cap at 99, only admin gets 100
