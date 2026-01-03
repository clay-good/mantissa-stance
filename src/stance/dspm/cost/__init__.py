"""
DSPM Cost Analysis module.

Provides capabilities for analyzing cloud storage costs and identifying
cold data that can be archived or deleted to save costs.

Features:
- Cold data detection (objects not accessed in X days)
- Storage cost estimation per bucket/container
- Archive candidate identification (Glacier, Nearline, Cool tier)
- Delete candidate identification (old unused data)
"""

from stance.dspm.cost.base import (
    CostAnalysisConfig,
    StorageMetrics,
    ObjectAccessInfo,
    ColdDataFinding,
    CostAnalysisResult,
    FindingType,
    StorageTier,
    BaseCostAnalyzer,
)
from stance.dspm.cost.s3_cost import S3CostAnalyzer
from stance.dspm.cost.gcs_cost import GCSCostAnalyzer
from stance.dspm.cost.azure_cost import AzureCostAnalyzer

__all__ = [
    # Base classes and models
    "CostAnalysisConfig",
    "StorageMetrics",
    "ObjectAccessInfo",
    "ColdDataFinding",
    "CostAnalysisResult",
    "FindingType",
    "StorageTier",
    "BaseCostAnalyzer",
    # Cloud-specific analyzers
    "S3CostAnalyzer",
    "GCSCostAnalyzer",
    "AzureCostAnalyzer",
]
