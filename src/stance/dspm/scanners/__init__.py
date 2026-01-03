"""
DSPM Storage Scanners for Mantissa Stance.

Provides cloud storage scanning capabilities for sensitive data discovery.
Scanners sample data from cloud storage services and use the DSPM
classifier/detector to identify sensitive information.

Supported storage services:
- AWS S3
- Google Cloud Storage
- Azure Blob Storage
"""

from stance.dspm.scanners.base import (
    BaseDataScanner,
    ScanConfig,
    ScanResult,
    ScanFinding,
    ScanSummary,
    FindingSeverity,
)
from stance.dspm.scanners.s3 import S3DataScanner
from stance.dspm.scanners.gcs import GCSDataScanner
from stance.dspm.scanners.azure_blob import AzureBlobDataScanner

__all__ = [
    # Base
    "BaseDataScanner",
    "ScanConfig",
    "ScanResult",
    "ScanFinding",
    "ScanSummary",
    "FindingSeverity",
    # Cloud Scanners
    "S3DataScanner",
    "GCSDataScanner",
    "AzureBlobDataScanner",
]
