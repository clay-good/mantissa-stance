"""
DSPM Extended Sources for Mantissa Stance.

Provides additional data source connectors beyond cloud storage for
comprehensive sensitive data discovery.

Extended Sources:
- Snowflake: Data warehouse scanning with read-only queries
- Google Drive: SaaS file sampling via API
- Databases: Column sampling for RDS, Cloud SQL, Azure SQL
"""

from stance.dspm.extended.base import (
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
    BaseExtendedScanner,
)
from stance.dspm.extended.snowflake import (
    SnowflakeConfig,
    SnowflakeScanner,
    SnowflakeTableInfo,
    SnowflakeColumnInfo,
)
from stance.dspm.extended.google_drive import (
    GoogleDriveConfig,
    GoogleDriveScanner,
    DriveFileInfo,
)
from stance.dspm.extended.databases import (
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
    # Base
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
