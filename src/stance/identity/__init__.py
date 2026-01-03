"""
Identity Security module for Mantissa Stance.

Provides capabilities for mapping data access permissions and identifying
over-privileged access to sensitive resources.

Features:
- Data access mapping (who can access this resource?)
- Principal data exposure (what data can this identity access?)
- Over-privileged access detection
- DSPM integration for sensitivity correlation
"""

from stance.identity.base import (
    IdentityConfig,
    Principal,
    PrincipalType,
    PermissionLevel,
    ResourceAccess,
    DataAccessMapping,
    DataAccessFinding,
    DataAccessResult,
    FindingType,
    BaseDataAccessMapper,
)
from stance.identity.aws_mapper import AWSDataAccessMapper
from stance.identity.gcp_mapper import GCPDataAccessMapper
from stance.identity.azure_mapper import AzureDataAccessMapper
from stance.identity.exposure import (
    ExposureSeverity,
    ResourceClassification,
    ExposedResource,
    ExposureFinding,
    ExposureSummary,
    ExposureResult,
    PrincipalExposureAnalyzer,
    create_classifications_from_scan_results,
)
from stance.identity.overprivileged import (
    OverPrivilegedConfig,
    OverPrivilegedFindingType,
    OverPrivilegedSeverity,
    UsagePattern,
    OverPrivilegedFinding,
    OverPrivilegedSummary,
    OverPrivilegedResult,
    OverPrivilegedAnalyzer,
    create_usage_patterns_from_access_review,
)

__all__ = [
    # Base classes and models
    "IdentityConfig",
    "Principal",
    "PrincipalType",
    "PermissionLevel",
    "ResourceAccess",
    "DataAccessMapping",
    "DataAccessFinding",
    "DataAccessResult",
    "FindingType",
    "BaseDataAccessMapper",
    # Cloud-specific mappers
    "AWSDataAccessMapper",
    "GCPDataAccessMapper",
    "AzureDataAccessMapper",
    # Principal exposure analysis
    "ExposureSeverity",
    "ResourceClassification",
    "ExposedResource",
    "ExposureFinding",
    "ExposureSummary",
    "ExposureResult",
    "PrincipalExposureAnalyzer",
    "create_classifications_from_scan_results",
    # Over-privileged detection
    "OverPrivilegedConfig",
    "OverPrivilegedFindingType",
    "OverPrivilegedSeverity",
    "UsagePattern",
    "OverPrivilegedFinding",
    "OverPrivilegedSummary",
    "OverPrivilegedResult",
    "OverPrivilegedAnalyzer",
    "create_usage_patterns_from_access_review",
]
