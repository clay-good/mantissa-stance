"""
CSPM Benchmark Automation module for Mantissa Stance.

Provides automated compliance benchmark scanning, regulatory control
validation, and continuous compliance monitoring for cloud security
posture management.

Components:
- CIS Benchmark Automation: Automated CIS benchmark scanning with full control catalogs
- SOC 2 Compliance: Detailed Trust Services Criteria (TSC) mapping and validation
- Regulatory Controls: HIPAA Security Rule and PCI-DSS requirement validation
- Attestation Engine: Automated compliance attestation generation
- Continuous Monitoring: Real-time compliance state tracking and alerting
"""

from stance.cspm.cis_benchmark import (
    CISBenchmark,
    CISControl,
    CISSection,
    CISProfile,
    CISAssessmentResult,
    CISBenchmarkScanner,
    BenchmarkType,
)

from stance.cspm.soc2_compliance import (
    SOC2Criteria,
    SOC2Category,
    TrustServicesPrinciple,
    SOC2Control,
    SOC2Assessment,
    SOC2ComplianceMapper,
)

from stance.cspm.regulatory_controls import (
    HIPAAControl,
    HIPAASafeguard,
    HIPAARule,
    PCIDSSRequirement,
    PCIDSSControl,
    RegulatoryFramework,
    RegulatoryControlValidator,
)

from stance.cspm.attestation import (
    AttestationScope,
    AttestationType,
    AttestationEvidence,
    ComplianceAttestation,
    AttestationEngine,
)

from stance.cspm.continuous_monitoring import (
    ComplianceState,
    ComplianceAlert,
    ComplianceDrift,
    ComplianceBaseline,
    ContinuousComplianceMonitor,
)

__all__ = [
    # CIS Benchmark
    "CISBenchmark",
    "CISControl",
    "CISSection",
    "CISProfile",
    "CISAssessmentResult",
    "CISBenchmarkScanner",
    "BenchmarkType",
    # SOC 2
    "SOC2Criteria",
    "SOC2Category",
    "TrustServicesPrinciple",
    "SOC2Control",
    "SOC2Assessment",
    "SOC2ComplianceMapper",
    # Regulatory
    "HIPAAControl",
    "HIPAASafeguard",
    "HIPAARule",
    "PCIDSSRequirement",
    "PCIDSSControl",
    "RegulatoryFramework",
    "RegulatoryControlValidator",
    # Attestation
    "AttestationScope",
    "AttestationType",
    "AttestationEvidence",
    "ComplianceAttestation",
    "AttestationEngine",
    # Continuous Monitoring
    "ComplianceState",
    "ComplianceAlert",
    "ComplianceDrift",
    "ComplianceBaseline",
    "ContinuousComplianceMonitor",
]
