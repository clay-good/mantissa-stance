"""
Cloud Infrastructure Entitlement Management (CIEM) for Mantissa Stance.

This module provides identity and access management analysis including:

- Effective permissions calculation across complex IAM policies
- Overprivileged identity detection (unused permissions)
- Cross-account trust relationship analysis
- Privilege escalation path identification
- Least privilege recommendations
"""

from stance.ciem.effective_permissions import (
    EffectivePermissionsCalculator,
    PermissionSet,
    EffectiveAccess,
)
from stance.ciem.overprivileged import (
    OverprivilegedDetector,
    OverprivilegedFinding,
    UnusedPermission,
)
from stance.ciem.trust_analysis import (
    TrustAnalyzer,
    TrustRelationship,
    CrossAccountAccess,
    TrustRisk,
)
from stance.ciem.privilege_escalation import (
    PrivilegeEscalationAnalyzer,
    EscalationPath,
)

__all__ = [
    # Effective permissions
    "EffectivePermissionsCalculator",
    "PermissionSet",
    "EffectiveAccess",
    # Overprivileged detection
    "OverprivilegedDetector",
    "OverprivilegedFinding",
    "UnusedPermission",
    # Trust analysis
    "TrustAnalyzer",
    "TrustRelationship",
    "CrossAccountAccess",
    "TrustRisk",
    # Privilege escalation
    "PrivilegeEscalationAnalyzer",
    "EscalationPath",
]
