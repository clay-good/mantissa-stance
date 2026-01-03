"""
DSPM Access Review module for Mantissa Stance.

Analyzes cloud access logs to identify stale permissions and unused access,
helping organizations maintain least-privilege access to sensitive data.

Features:
- CloudTrail analysis for AWS S3 access
- Cloud Audit Logs analysis for GCS access
- Activity Log analysis for Azure Blob access
- Stale access detection
- Unused role identification
- Over-privileged access detection
"""

from stance.dspm.access.base import (
    AccessReviewConfig,
    AccessEvent,
    AccessSummary,
    StaleAccessFinding,
    AccessReviewResult,
    FindingType,
    BaseAccessAnalyzer,
)
from stance.dspm.access.cloudtrail import CloudTrailAccessAnalyzer
from stance.dspm.access.gcp_audit import GCPAuditLogAnalyzer
from stance.dspm.access.azure_activity import AzureActivityLogAnalyzer

__all__ = [
    # Base classes
    "AccessReviewConfig",
    "AccessEvent",
    "AccessSummary",
    "StaleAccessFinding",
    "AccessReviewResult",
    "FindingType",
    "BaseAccessAnalyzer",
    # Cloud-specific analyzers
    "CloudTrailAccessAnalyzer",
    "GCPAuditLogAnalyzer",
    "AzureActivityLogAnalyzer",
]
