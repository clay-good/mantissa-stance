"""
Attack Surface Management (ASM) for Mantissa Stance.

This module provides external attack surface discovery and monitoring capabilities,
complementing CSPM's internal cloud resource assessment with an outside-in view.

ASM discovers and monitors:
- External-facing assets via certificate transparency logs
- DNS records and subdomain enumeration
- Cloud provider IP range detection
- Technology fingerprinting
- Port scanning (opt-in with ownership verification)

The ASM module integrates with existing CSPM data to:
- Detect shadow IT (assets visible externally but not in CSPM inventory)
- Correlate external exposure with internal asset configuration
- Provide unified attack surface visibility
"""

from stance.asm.models import (
    ASMScanMode,
    ASMScanStatus,
    ASMScanResult,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.findings import (
    ASMFindingType,
    ASM_FINDING_SEVERITY_MAP,
    ASM_FINDING_REMEDIATION_MAP,
    create_asm_finding,
)
from stance.asm.config import (
    ASMConfiguration,
    ASMOwnershipVerification,
    load_asm_config,
    validate_asm_config,
)
from stance.asm.storage import (
    ASMStorageAdapter,
    ASMScanInfo,
    generate_scan_id,
)
from stance.asm.drift import (
    ASMDriftDetector,
    DriftReport,
    DriftSummary,
    AssetChange,
    PortChange,
    CertificateChange,
    ChangeType,
    DriftSeverity,
)
from stance.asm.correlation import (
    ASMCSPMCorrelator,
    CorrelationResult,
    MatchedAsset,
    MatchMethod,
    create_unified_inventory,
    detect_shadow_it,
    get_attack_surface,
)
from stance.asm.notifications import (
    ASMNotificationManager,
    ASMAlertContext,
    ScanSummary,
    create_certificate_expiry_report,
    create_attack_surface_summary,
)
from stance.asm.risk import (
    ASMRiskScorer,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    RiskTrend,
    calculate_attack_surface_risk,
)

__all__ = [
    # Models
    "ASMScanMode",
    "ASMScanStatus",
    "ASMScanResult",
    "CertificateInfo",
    "ExternalAsset",
    "ExternalAssetCollection",
    # Findings
    "ASMFindingType",
    "ASM_FINDING_SEVERITY_MAP",
    "ASM_FINDING_REMEDIATION_MAP",
    "create_asm_finding",
    # Configuration
    "ASMConfiguration",
    "ASMOwnershipVerification",
    "load_asm_config",
    "validate_asm_config",
    # Storage
    "ASMStorageAdapter",
    "ASMScanInfo",
    "generate_scan_id",
    # Drift Detection
    "ASMDriftDetector",
    "DriftReport",
    "DriftSummary",
    "AssetChange",
    "PortChange",
    "CertificateChange",
    "ChangeType",
    "DriftSeverity",
    # Correlation
    "ASMCSPMCorrelator",
    "CorrelationResult",
    "MatchedAsset",
    "MatchMethod",
    "create_unified_inventory",
    "detect_shadow_it",
    "get_attack_surface",
    # Notifications
    "ASMNotificationManager",
    "ASMAlertContext",
    "ScanSummary",
    "create_certificate_expiry_report",
    "create_attack_surface_summary",
    # Risk Scoring
    "ASMRiskScorer",
    "RiskAssessment",
    "RiskFactor",
    "RiskLevel",
    "RiskTrend",
    "calculate_attack_surface_risk",
]

__version__ = "0.1.0"
