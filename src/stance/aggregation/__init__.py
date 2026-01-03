"""
Cross-cloud aggregation for Mantissa Stance.

Provides multi-cloud findings aggregation, cross-cloud synchronization,
and federated query capabilities for unified security posture management.
"""

from stance.aggregation.aggregator import (
    FindingsAggregator,
    CloudAccount,
    AggregationResult,
    NormalizedFinding,
)
from stance.aggregation.sync import (
    CrossCloudSync,
    SyncConfig,
    SyncResult,
    SyncRecord,
    SyncDirection,
    ConflictResolution,
    StorageAdapter,
    S3StorageAdapter,
    GCSStorageAdapter,
    AzureBlobStorageAdapter,
)
from stance.aggregation.federation import (
    FederatedQuery,
    FederatedQueryResult,
    BackendConfig,
    QueryStrategy,
    MergeStrategy,
)

__all__ = [
    # Aggregator
    "FindingsAggregator",
    "CloudAccount",
    "AggregationResult",
    "NormalizedFinding",
    # Sync
    "CrossCloudSync",
    "SyncConfig",
    "SyncResult",
    "SyncRecord",
    "SyncDirection",
    "ConflictResolution",
    "StorageAdapter",
    "S3StorageAdapter",
    "GCSStorageAdapter",
    "AzureBlobStorageAdapter",
    # Federation
    "FederatedQuery",
    "FederatedQueryResult",
    "BackendConfig",
    "QueryStrategy",
    "MergeStrategy",
]
