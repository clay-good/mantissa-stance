"""
Data Security Posture Management (DSPM) for Mantissa Stance.

Provides capabilities for discovering, classifying, and protecting
sensitive data across cloud environments.

Features:
- Data classification (PII, PCI, PHI, confidential)
- Sensitive data discovery in storage services
- Cloud storage scanning (S3, GCS, Azure Blob)
- Data flow analysis
- Data residency compliance
- Data access analysis
- Access review (stale permissions, unused access)
- Cost analysis (cold data detection, storage optimization)
- Extended sources: Snowflake, Google Drive, RDS, Cloud SQL, Azure SQL
"""

from stance.dspm.classifier import (
    DataClassifier,
    DataClassification,
    ClassificationLevel,
    DataCategory,
    ClassificationResult,
    ClassificationRule,
)
from stance.dspm.detector import (
    SensitiveDataDetector,
    DetectionResult,
    DataPattern,
    PatternMatch,
)
from stance.dspm.analyzer import (
    DataFlowAnalyzer,
    DataFlow,
    DataResidencyChecker,
    ResidencyViolation,
    DataAccessAnalyzer,
    AccessPattern,
)
from stance.dspm.scanners import (
    BaseDataScanner,
    ScanConfig,
    ScanResult,
    ScanFinding,
    ScanSummary,
    FindingSeverity,
    S3DataScanner,
    GCSDataScanner,
    AzureBlobDataScanner,
)
from stance.dspm.access import (
    AccessReviewConfig,
    AccessEvent,
    AccessSummary,
    StaleAccessFinding,
    AccessReviewResult,
    FindingType,
    BaseAccessAnalyzer,
    CloudTrailAccessAnalyzer,
    GCPAuditLogAnalyzer,
    AzureActivityLogAnalyzer,
)
from stance.dspm.cost import (
    CostAnalysisConfig,
    StorageMetrics,
    ObjectAccessInfo,
    ColdDataFinding,
    CostAnalysisResult,
    FindingType as CostFindingType,
    StorageTier,
    BaseCostAnalyzer,
    S3CostAnalyzer,
    GCSCostAnalyzer,
    AzureCostAnalyzer,
)
from stance.dspm.extended import (
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
    BaseExtendedScanner,
    SnowflakeConfig,
    SnowflakeScanner,
    SnowflakeTableInfo,
    SnowflakeColumnInfo,
    GoogleDriveConfig,
    GoogleDriveScanner,
    DriveFileInfo,
    DatabaseType,
    DatabaseConfig,
    DatabaseScanner,
    RDSScanner,
    CloudSQLScanner,
    AzureSQLScanner,
    TableInfo,
    ColumnInfo,
)

__all__ = [
    # Classifier
    "DataClassifier",
    "DataClassification",
    "ClassificationLevel",
    "DataCategory",
    "ClassificationResult",
    "ClassificationRule",
    # Detector
    "SensitiveDataDetector",
    "DetectionResult",
    "DataPattern",
    "PatternMatch",
    # Analyzer
    "DataFlowAnalyzer",
    "DataFlow",
    "DataResidencyChecker",
    "ResidencyViolation",
    "DataAccessAnalyzer",
    "AccessPattern",
    # Scanners
    "BaseDataScanner",
    "ScanConfig",
    "ScanResult",
    "ScanFinding",
    "ScanSummary",
    "FindingSeverity",
    "S3DataScanner",
    "GCSDataScanner",
    "AzureBlobDataScanner",
    # Access Review
    "AccessReviewConfig",
    "AccessEvent",
    "AccessSummary",
    "StaleAccessFinding",
    "AccessReviewResult",
    "FindingType",
    "BaseAccessAnalyzer",
    "CloudTrailAccessAnalyzer",
    "GCPAuditLogAnalyzer",
    "AzureActivityLogAnalyzer",
    # Cost Analysis
    "CostAnalysisConfig",
    "StorageMetrics",
    "ObjectAccessInfo",
    "ColdDataFinding",
    "CostAnalysisResult",
    "CostFindingType",
    "StorageTier",
    "BaseCostAnalyzer",
    "S3CostAnalyzer",
    "GCSCostAnalyzer",
    "AzureCostAnalyzer",
    # Extended Sources
    "ExtendedSourceType",
    "ExtendedScanConfig",
    "ExtendedScanResult",
    "ExtendedScanFinding",
    "ExtendedScanSummary",
    "BaseExtendedScanner",
    # Snowflake
    "SnowflakeConfig",
    "SnowflakeScanner",
    "SnowflakeTableInfo",
    "SnowflakeColumnInfo",
    # Google Drive
    "GoogleDriveConfig",
    "GoogleDriveScanner",
    "DriveFileInfo",
    # Databases
    "DatabaseType",
    "DatabaseConfig",
    "DatabaseScanner",
    "RDSScanner",
    "CloudSQLScanner",
    "AzureSQLScanner",
    "TableInfo",
    "ColumnInfo",
]
