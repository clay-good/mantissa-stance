"""
Exposure Management module for Mantissa Stance.

Provides capabilities for discovering and analyzing publicly accessible
cloud resources and correlating with data sensitivity for risk assessment.

Features:
- Public asset inventory (what's exposed to the internet?)
- Sensitive data exposure detection (PII/PCI/PHI on public resources)
- Risk scoring based on exposure type and data classification
- DSPM integration for data sensitivity correlation
- Certificate monitoring (expiring, weak algorithms)
- DNS inventory and dangling DNS detection
"""

from stance.exposure.base import (
    ExposureType,
    ExposureSeverity,
    ExposureFindingType,
    ExposureConfig,
    PublicAsset,
    ExposureFinding,
    ExposureInventorySummary,
    ExposureInventoryResult,
    BaseExposureAnalyzer,
)
from stance.exposure.inventory import (
    DSPMClassification,
    PublicAssetInventory,
    create_inventory_from_assets,
    RESOURCE_TYPE_TO_EXPOSURE,
)
from stance.exposure.sensitive import (
    SensitiveExposureType,
    ExposureRiskLevel,
    SensitiveExposureConfig,
    SensitiveDataMatch,
    SensitiveExposureFinding,
    SensitiveExposureSummary,
    SensitiveExposureResult,
    SensitiveDataExposureAnalyzer,
    correlate_exposure_with_dspm,
)
from stance.exposure.certificates import (
    CertificateStatus,
    CertificateType,
    CertificateFindingType,
    CertificateSeverity,
    CertificateConfig,
    Certificate,
    CertificateFinding,
    CertificateSummary,
    CertificateMonitoringResult,
    BaseCertificateCollector,
    CertificateMonitor,
    AWSCertificateCollector,
    GCPCertificateCollector,
    AzureCertificateCollector,
    monitor_certificates,
)
from stance.exposure.dns import (
    DNSRecordType,
    DNSFindingType,
    DNSSeverity,
    DNSConfig,
    DNSZone,
    DNSRecord,
    DNSFinding,
    DNSSummary,
    DNSInventoryResult,
    BaseDNSCollector,
    DNSInventory,
    AWSRoute53Collector,
    GCPCloudDNSCollector,
    AzureDNSCollector,
    CLOUD_SERVICE_PATTERNS,
    scan_dns_inventory,
)

__all__ = [
    # Base classes and enums
    "ExposureType",
    "ExposureSeverity",
    "ExposureFindingType",
    "ExposureConfig",
    "PublicAsset",
    "ExposureFinding",
    "ExposureInventorySummary",
    "ExposureInventoryResult",
    "BaseExposureAnalyzer",
    # Inventory
    "DSPMClassification",
    "PublicAssetInventory",
    "create_inventory_from_assets",
    "RESOURCE_TYPE_TO_EXPOSURE",
    # Sensitive data exposure
    "SensitiveExposureType",
    "ExposureRiskLevel",
    "SensitiveExposureConfig",
    "SensitiveDataMatch",
    "SensitiveExposureFinding",
    "SensitiveExposureSummary",
    "SensitiveExposureResult",
    "SensitiveDataExposureAnalyzer",
    "correlate_exposure_with_dspm",
    # Certificate monitoring
    "CertificateStatus",
    "CertificateType",
    "CertificateFindingType",
    "CertificateSeverity",
    "CertificateConfig",
    "Certificate",
    "CertificateFinding",
    "CertificateSummary",
    "CertificateMonitoringResult",
    "BaseCertificateCollector",
    "CertificateMonitor",
    "AWSCertificateCollector",
    "GCPCertificateCollector",
    "AzureCertificateCollector",
    "monitor_certificates",
    # DNS inventory
    "DNSRecordType",
    "DNSFindingType",
    "DNSSeverity",
    "DNSConfig",
    "DNSZone",
    "DNSRecord",
    "DNSFinding",
    "DNSSummary",
    "DNSInventoryResult",
    "BaseDNSCollector",
    "DNSInventory",
    "AWSRoute53Collector",
    "GCPCloudDNSCollector",
    "AzureDNSCollector",
    "CLOUD_SERVICE_PATTERNS",
    "scan_dns_inventory",
]
