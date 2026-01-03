"""
Privilege escalation path detection for CIEM.

Identifies paths through which an identity could escalate
their privileges to gain higher access.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingType, Severity

logger = logging.getLogger(__name__)


class EscalationType(Enum):
    """Type of privilege escalation."""

    CREATE_POLICY = "create_policy"
    ATTACH_POLICY = "attach_policy"
    CREATE_ACCESS_KEY = "create_access_key"
    ASSUME_ROLE = "assume_role"
    PASS_ROLE = "pass_role"
    UPDATE_FUNCTION = "update_function"
    CREATE_INSTANCE = "create_instance"
    MODIFY_TRUST = "modify_trust"


@dataclass
class EscalationStep:
    """
    A single step in a privilege escalation path.

    Attributes:
        order: Step number in the path
        action: The action taken
        permission_used: Permission enabling this step
        target: The target of the action
        description: Human-readable description
    """

    order: int
    action: str
    permission_used: str
    target: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "order": self.order,
            "action": self.action,
            "permission_used": self.permission_used,
            "target": self.target,
            "description": self.description,
        }


@dataclass
class EscalationPath:
    """
    A complete privilege escalation path.

    Attributes:
        identity_id: The starting identity
        identity_name: Human-readable name
        escalation_type: Primary escalation technique
        steps: Steps to achieve escalation
        final_access: What access is gained
        severity: How serious this escalation is
    """

    identity_id: str
    identity_name: str
    escalation_type: EscalationType
    steps: list[EscalationStep] = field(default_factory=list)
    final_access: str = ""
    severity: Severity = Severity.HIGH

    def to_finding(self) -> Finding:
        """Convert to a Finding object."""
        steps_desc = " → ".join(s.action for s in self.steps)

        return Finding(
            id=f"privesc-{self.identity_id}-{self.escalation_type.value}",
            rule_id="ciem-privesc-001",
            resource_id=self.identity_id,
            resource_type="iam_identity",
            finding_type=FindingType.VULNERABILITY,
            severity=self.severity,
            title=f"Privilege escalation path: {self.identity_name}",
            description=(
                f"{self.identity_name} can escalate privileges via "
                f"{self.escalation_type.value}: {steps_desc}. "
                f"Final access: {self.final_access}"
            ),
            recommendation=(
                f"Remove the permission that enables this escalation: "
                f"{self.steps[0].permission_used if self.steps else 'unknown'}"
            ),
            properties={
                "escalation_type": self.escalation_type.value,
                "steps": [s.to_dict() for s in self.steps],
                "final_access": self.final_access,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "escalation_type": self.escalation_type.value,
            "steps": [s.to_dict() for s in self.steps],
            "final_access": self.final_access,
            "severity": self.severity.value,
        }


class PrivilegeEscalationAnalyzer:
    """
    Analyzes identities for potential privilege escalation paths.

    Based on known IAM privilege escalation techniques documented by
    security researchers.
    """

    # Permissions that enable privilege escalation
    ESCALATION_PERMISSIONS = {
        "aws": {
            EscalationType.CREATE_POLICY: [
                "iam:CreatePolicy",
                "iam:CreatePolicyVersion",
            ],
            EscalationType.ATTACH_POLICY: [
                "iam:AttachUserPolicy",
                "iam:AttachRolePolicy",
                "iam:AttachGroupPolicy",
                "iam:PutUserPolicy",
                "iam:PutRolePolicy",
                "iam:PutGroupPolicy",
            ],
            EscalationType.CREATE_ACCESS_KEY: [
                "iam:CreateAccessKey",
            ],
            EscalationType.ASSUME_ROLE: [
                "sts:AssumeRole",
            ],
            EscalationType.PASS_ROLE: [
                "iam:PassRole",
            ],
            EscalationType.UPDATE_FUNCTION: [
                "lambda:UpdateFunctionCode",
                "lambda:UpdateFunctionConfiguration",
            ],
            EscalationType.CREATE_INSTANCE: [
                "ec2:RunInstances",
            ],
            EscalationType.MODIFY_TRUST: [
                "iam:UpdateAssumeRolePolicy",
            ],
        },
        "gcp": {
            EscalationType.CREATE_POLICY: [
                "iam.roles.create",
                "iam.roles.update",
            ],
            EscalationType.ATTACH_POLICY: [
                "resourcemanager.projects.setIamPolicy",
                "resourcemanager.folders.setIamPolicy",
                "resourcemanager.organizations.setIamPolicy",
            ],
            EscalationType.CREATE_ACCESS_KEY: [
                "iam.serviceAccountKeys.create",
            ],
            EscalationType.ASSUME_ROLE: [
                "iam.serviceAccounts.getAccessToken",
                "iam.serviceAccounts.implicitDelegation",
            ],
        },
    }

    def __init__(self, provider: str = "aws"):
        """
        Initialize analyzer.

        Args:
            provider: Cloud provider (aws, gcp, azure)
        """
        self.provider = provider
        self.escalation_permissions = self.ESCALATION_PERMISSIONS.get(provider, {})

    def analyze(
        self,
        identity: Asset,
        permissions: list[str],
        roles: AssetCollection | None = None,
    ) -> list[EscalationPath]:
        """
        Analyze an identity for privilege escalation paths.

        Args:
            identity: The identity to analyze
            permissions: Permissions the identity has
            roles: Available roles (for assume role analysis)

        Returns:
            List of possible escalation paths
        """
        paths: list[EscalationPath] = []

        permission_set = set(permissions)

        # Check each escalation type
        for esc_type, required_perms in self.escalation_permissions.items():
            matching_perms = [p for p in required_perms if p in permission_set]

            if not matching_perms:
                continue

            path = self._build_escalation_path(
                identity=identity,
                escalation_type=esc_type,
                permissions=matching_perms,
                roles=roles,
            )

            if path:
                paths.append(path)

        return paths

    def analyze_all(
        self,
        identities: AssetCollection,
        permissions_map: dict[str, list[str]],
        roles: AssetCollection | None = None,
    ) -> list[EscalationPath]:
        """
        Analyze all identities for privilege escalation.

        Args:
            identities: Collection of identity assets
            permissions_map: Map of identity_id -> permissions
            roles: Available roles

        Returns:
            All escalation paths found
        """
        all_paths: list[EscalationPath] = []

        for identity in identities:
            permissions = permissions_map.get(identity.id, [])
            if not permissions:
                continue

            try:
                paths = self.analyze(identity, permissions, roles)
                all_paths.extend(paths)
            except Exception as e:
                logger.warning(f"Failed to analyze {identity.id}: {e}")

        # Sort by severity
        all_paths.sort(
            key=lambda p: ["low", "medium", "high", "critical"].index(p.severity.value),
            reverse=True,
        )

        return all_paths

    def _build_escalation_path(
        self,
        identity: Asset,
        escalation_type: EscalationType,
        permissions: list[str],
        roles: AssetCollection | None,
    ) -> EscalationPath | None:
        """Build an escalation path for a specific technique."""
        steps: list[EscalationStep] = []
        final_access = ""
        severity = Severity.HIGH

        if escalation_type == EscalationType.CREATE_POLICY:
            steps = [
                EscalationStep(
                    order=1,
                    action="Create malicious policy",
                    permission_used=permissions[0],
                    target="New IAM policy",
                    description="Create a policy granting admin access",
                ),
                EscalationStep(
                    order=2,
                    action="Attach policy to self",
                    permission_used="(requires attach permission)",
                    target=identity.name,
                    description="Attach the policy to gain elevated access",
                ),
            ]
            final_access = "Admin access (if attach permission exists)"
            severity = Severity.HIGH

        elif escalation_type == EscalationType.ATTACH_POLICY:
            steps = [
                EscalationStep(
                    order=1,
                    action="Attach admin policy",
                    permission_used=permissions[0],
                    target=identity.name,
                    description="Attach AdministratorAccess to self",
                ),
            ]
            final_access = "Admin access"
            severity = Severity.CRITICAL

        elif escalation_type == EscalationType.CREATE_ACCESS_KEY:
            steps = [
                EscalationStep(
                    order=1,
                    action="Create access key for other user",
                    permission_used=permissions[0],
                    target="Target user",
                    description="Create access key for a more privileged user",
                ),
            ]
            final_access = "Access as target user"
            severity = Severity.HIGH

        elif escalation_type == EscalationType.ASSUME_ROLE:
            # Check for assumable high-privilege roles
            assumable_admin_roles = []
            if roles:
                for role in roles:
                    if self._is_admin_role(role):
                        assumable_admin_roles.append(role.name)

            if assumable_admin_roles:
                steps = [
                    EscalationStep(
                        order=1,
                        action="Assume admin role",
                        permission_used=permissions[0],
                        target=assumable_admin_roles[0],
                        description=f"Assume role: {assumable_admin_roles[0]}",
                    ),
                ]
                final_access = f"Admin access via role assumption"
                severity = Severity.CRITICAL
            else:
                return None

        elif escalation_type == EscalationType.PASS_ROLE:
            steps = [
                EscalationStep(
                    order=1,
                    action="Pass admin role to service",
                    permission_used=permissions[0],
                    target="Lambda/EC2/ECS",
                    description="Pass high-privilege role to a compute resource",
                ),
                EscalationStep(
                    order=2,
                    action="Execute code with role",
                    permission_used="Service execution",
                    target="Compute resource",
                    description="Execute code that uses the passed role",
                ),
            ]
            final_access = "Admin access via service"
            severity = Severity.HIGH

        elif escalation_type == EscalationType.UPDATE_FUNCTION:
            steps = [
                EscalationStep(
                    order=1,
                    action="Update Lambda function code",
                    permission_used=permissions[0],
                    target="Lambda function",
                    description="Replace Lambda code with malicious version",
                ),
                EscalationStep(
                    order=2,
                    action="Invoke function",
                    permission_used="Function execution",
                    target="Lambda function",
                    description="Execute to gain function's role permissions",
                ),
            ]
            final_access = "Access as Lambda execution role"
            severity = Severity.HIGH

        elif escalation_type == EscalationType.MODIFY_TRUST:
            steps = [
                EscalationStep(
                    order=1,
                    action="Modify trust policy",
                    permission_used=permissions[0],
                    target="Target role",
                    description="Add self to role's trust policy",
                ),
                EscalationStep(
                    order=2,
                    action="Assume modified role",
                    permission_used="sts:AssumeRole",
                    target="Target role",
                    description="Assume the role with modified trust",
                ),
            ]
            final_access = "Access as target role"
            severity = Severity.CRITICAL

        else:
            return None

        return EscalationPath(
            identity_id=identity.id,
            identity_name=identity.name,
            escalation_type=escalation_type,
            steps=steps,
            final_access=final_access,
            severity=severity,
        )

    def _is_admin_role(self, role: Asset) -> bool:
        """Check if a role has admin-level permissions."""
        attached_policies = role.properties.get("attached_policies", [])

        admin_policies = [
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess",
        ]

        return any(p in admin_policies for p in attached_policies)
