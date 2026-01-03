"""
Overprivileged identity detection for CIEM.

Identifies identities with permissions they don't use, enabling
least privilege recommendations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingType, Severity
from stance.ciem.effective_permissions import EffectiveAccess, Permission

logger = logging.getLogger(__name__)


@dataclass
class UnusedPermission:
    """
    A permission that has not been used.

    Attributes:
        service: AWS/GCP/Azure service
        action: The action (e.g., "s3:GetObject")
        last_used: When the permission was last used (None if never)
        days_unused: Days since last use
        source_policy: Policy granting this permission
    """

    service: str
    action: str
    last_used: datetime | None
    days_unused: int
    source_policy: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "service": self.service,
            "action": self.action,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "days_unused": self.days_unused,
            "source_policy": self.source_policy,
        }


@dataclass
class OverprivilegedFinding:
    """
    Finding for an overprivileged identity.

    Attributes:
        identity_id: The identity ID
        identity_name: Human-readable name
        identity_type: user, role, or service_account
        unused_permissions: List of unused permissions
        unused_services: Services with no activity
        total_permissions: Total permissions granted
        used_permissions: Permissions actually used
        risk_reduction: Estimated risk reduction if fixed (0-100)
        recommendation: What to do about it
    """

    identity_id: str
    identity_name: str
    identity_type: str
    unused_permissions: list[UnusedPermission] = field(default_factory=list)
    unused_services: list[str] = field(default_factory=list)
    total_permissions: int = 0
    used_permissions: int = 0
    risk_reduction: float = 0.0
    recommendation: str = ""

    @property
    def unused_percentage(self) -> float:
        """Calculate percentage of permissions unused."""
        if self.total_permissions == 0:
            return 0.0
        return (len(self.unused_permissions) / self.total_permissions) * 100

    @property
    def severity(self) -> Severity:
        """Determine severity based on unused percentage."""
        if self.unused_percentage > 80:
            return Severity.HIGH
        elif self.unused_percentage > 50:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def to_finding(self) -> Finding:
        """Convert to a Finding object."""
        return Finding(
            id=f"overprivileged-{self.identity_id}",
            rule_id="ciem-overprivileged-001",
            resource_id=self.identity_id,
            resource_type=f"iam_{self.identity_type}",
            finding_type=FindingType.MISCONFIGURATION,
            severity=self.severity,
            title=f"Overprivileged {self.identity_type}: {self.identity_name}",
            description=(
                f"Identity has {len(self.unused_permissions)} unused permissions "
                f"({self.unused_percentage:.1f}% of total). "
                f"Unused services: {', '.join(self.unused_services[:5])}"
            ),
            recommendation=self.recommendation,
            properties={
                "unused_permissions_count": len(self.unused_permissions),
                "unused_services": self.unused_services,
                "total_permissions": self.total_permissions,
                "used_permissions": self.used_permissions,
                "risk_reduction": self.risk_reduction,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "identity_id": self.identity_id,
            "identity_name": self.identity_name,
            "identity_type": self.identity_type,
            "unused_permissions": [p.to_dict() for p in self.unused_permissions],
            "unused_services": self.unused_services,
            "total_permissions": self.total_permissions,
            "used_permissions": self.used_permissions,
            "unused_percentage": self.unused_percentage,
            "severity": self.severity.value,
            "risk_reduction": self.risk_reduction,
            "recommendation": self.recommendation,
        }


class OverprivilegedDetector:
    """
    Detects overprivileged identities by comparing granted
    permissions to actual usage from cloud audit logs.
    """

    def __init__(
        self,
        lookback_days: int = 90,
        unused_threshold_days: int = 90,
        min_unused_percentage: float = 20.0,
    ):
        """
        Initialize detector.

        Args:
            lookback_days: Days of usage data to analyze
            unused_threshold_days: Days without use to consider unused
            min_unused_percentage: Minimum unused % to report
        """
        self.lookback_days = lookback_days
        self.unused_threshold_days = unused_threshold_days
        self.min_unused_percentage = min_unused_percentage

    def detect(
        self,
        effective_access: EffectiveAccess,
        usage_data: dict[str, datetime] | None = None,
    ) -> OverprivilegedFinding | None:
        """
        Detect if an identity is overprivileged.

        Args:
            effective_access: Calculated effective permissions
            usage_data: Map of action -> last_used timestamp

        Returns:
            OverprivilegedFinding if overprivileged, None otherwise
        """
        if usage_data is None:
            usage_data = {}

        now = datetime.now(timezone.utc)
        unused_threshold = now - timedelta(days=self.unused_threshold_days)

        unused_permissions: list[UnusedPermission] = []
        used_permissions = 0
        unused_services: set[str] = set()
        used_services: set[str] = set()

        permission_set = effective_access.permission_set

        for permission in permission_set.permissions:
            if permission.effect.value != "allow":
                continue

            action_key = f"{permission.service}:{permission.action}"
            last_used = usage_data.get(action_key)

            if last_used is None or last_used < unused_threshold:
                # Permission is unused
                days_unused = (
                    self.lookback_days
                    if last_used is None
                    else (now - last_used).days
                )

                source_policies = permission_set.sources.get(action_key, ["unknown"])
                source_policy = source_policies[0] if source_policies else "unknown"

                unused_permissions.append(
                    UnusedPermission(
                        service=permission.service,
                        action=permission.action,
                        last_used=last_used,
                        days_unused=days_unused,
                        source_policy=source_policy,
                    )
                )
                unused_services.add(permission.service)
            else:
                used_permissions += 1
                used_services.add(permission.service)

        # Remove services that are actually used
        unused_services = unused_services - used_services

        total_permissions = len(unused_permissions) + used_permissions

        if total_permissions == 0:
            return None

        unused_percentage = (len(unused_permissions) / total_permissions) * 100

        if unused_percentage < self.min_unused_percentage:
            return None

        # Generate recommendation
        recommendation = self._generate_recommendation(
            effective_access.identity_name,
            unused_services,
            unused_permissions,
        )

        # Calculate risk reduction
        risk_reduction = self._calculate_risk_reduction(
            effective_access.risk_score,
            unused_permissions,
            total_permissions,
        )

        return OverprivilegedFinding(
            identity_id=effective_access.identity_id,
            identity_name=effective_access.identity_name,
            identity_type=effective_access.identity_type,
            unused_permissions=unused_permissions,
            unused_services=list(unused_services),
            total_permissions=total_permissions,
            used_permissions=used_permissions,
            risk_reduction=risk_reduction,
            recommendation=recommendation,
        )

    def detect_all(
        self,
        effective_access_list: list[EffectiveAccess],
        usage_data: dict[str, dict[str, datetime]] | None = None,
    ) -> list[OverprivilegedFinding]:
        """
        Detect overprivileged identities across all identities.

        Args:
            effective_access_list: List of effective access calculations
            usage_data: Map of identity_id -> action -> last_used

        Returns:
            List of findings for overprivileged identities
        """
        if usage_data is None:
            usage_data = {}

        findings: list[OverprivilegedFinding] = []

        for access in effective_access_list:
            identity_usage = usage_data.get(access.identity_id, {})
            finding = self.detect(access, identity_usage)
            if finding:
                findings.append(finding)

        # Sort by unused percentage descending
        findings.sort(key=lambda f: f.unused_percentage, reverse=True)

        return findings

    def _generate_recommendation(
        self,
        identity_name: str,
        unused_services: set[str],
        unused_permissions: list[UnusedPermission],
    ) -> str:
        """Generate a recommendation for fixing overprivileged identity."""
        if not unused_services:
            return (
                f"Review and remove {len(unused_permissions)} unused permissions "
                f"from {identity_name}."
            )

        services_list = ", ".join(list(unused_services)[:5])
        if len(unused_services) > 5:
            services_list += f" and {len(unused_services) - 5} more"

        return (
            f"Create a least-privilege policy for {identity_name}. "
            f"Remove access to unused services: {services_list}. "
            f"Consider using AWS Access Analyzer or similar tools to "
            f"generate a policy based on actual usage."
        )

    def _calculate_risk_reduction(
        self,
        current_risk: float,
        unused_permissions: list[UnusedPermission],
        total_permissions: int,
    ) -> float:
        """Calculate estimated risk reduction if permissions are removed."""
        if total_permissions == 0:
            return 0.0

        unused_ratio = len(unused_permissions) / total_permissions
        return current_risk * unused_ratio * 0.8  # 80% of proportional reduction
