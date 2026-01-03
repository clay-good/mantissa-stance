"""
Regulatory Control Validation for Mantissa Stance.

Provides detailed HIPAA Security Rule and PCI-DSS v4.0
control validation and compliance assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RegulatoryFramework(Enum):
    """Supported regulatory frameworks."""

    HIPAA = "hipaa"
    PCI_DSS = "pci-dss"
    GDPR = "gdpr"
    SOX = "sox"
    GLBA = "glba"
    FERPA = "ferpa"
    CCPA = "ccpa"


class HIPAARule(Enum):
    """HIPAA Rule categories."""

    SECURITY = "Security Rule"
    PRIVACY = "Privacy Rule"
    BREACH_NOTIFICATION = "Breach Notification Rule"


class HIPAASafeguard(Enum):
    """HIPAA Security Rule safeguard categories."""

    ADMINISTRATIVE = "Administrative Safeguards"
    PHYSICAL = "Physical Safeguards"
    TECHNICAL = "Technical Safeguards"
    ORGANIZATIONAL = "Organizational Requirements"
    POLICIES = "Policies and Procedures"


class ControlRequirement(Enum):
    """Control requirement level."""

    REQUIRED = "Required"
    ADDRESSABLE = "Addressable"
    OPTIONAL = "Optional"


class ValidationStatus(Enum):
    """Control validation status."""

    VALIDATED = "validated"
    FAILED = "failed"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"
    EXCEPTION = "exception"


@dataclass
class HIPAAControl:
    """HIPAA Security Rule control specification."""

    id: str
    section: str
    title: str
    description: str
    safeguard: HIPAASafeguard
    rule: HIPAARule
    requirement: ControlRequirement
    implementation_specifications: list[str] = field(default_factory=list)
    automated_checks: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    phi_impact: str = ""  # Description of PHI impact
    risk_level: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "section": self.section,
            "title": self.title,
            "description": self.description,
            "safeguard": self.safeguard.value,
            "rule": self.rule.value,
            "requirement": self.requirement.value,
            "implementation_specifications": self.implementation_specifications,
            "automated_checks": self.automated_checks,
            "evidence_requirements": self.evidence_requirements,
            "phi_impact": self.phi_impact,
            "risk_level": self.risk_level,
        }


@dataclass
class PCIDSSRequirement:
    """PCI-DSS v4.0 requirement category."""

    id: str
    title: str
    description: str
    goal: str
    controls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "goal": self.goal,
            "controls": self.controls,
        }


@dataclass
class PCIDSSControl:
    """PCI-DSS v4.0 control specification."""

    id: str
    requirement_id: str
    title: str
    description: str
    testing_procedure: str
    guidance: str
    version: str = "4.0"
    defined_approach_requirements: list[str] = field(default_factory=list)
    customized_approach_objective: str = ""
    automated_checks: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    applicability: str = "all"  # all, service_provider, merchant

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "requirement_id": self.requirement_id,
            "title": self.title,
            "description": self.description,
            "testing_procedure": self.testing_procedure,
            "guidance": self.guidance,
            "version": self.version,
            "defined_approach_requirements": self.defined_approach_requirements,
            "customized_approach_objective": self.customized_approach_objective,
            "automated_checks": self.automated_checks,
            "evidence_requirements": self.evidence_requirements,
            "applicability": self.applicability,
        }


@dataclass
class ControlValidation:
    """Validation result for a single control."""

    control_id: str
    control_title: str
    framework: RegulatoryFramework
    status: ValidationStatus
    resources_evaluated: int = 0
    resources_compliant: int = 0
    resources_non_compliant: int = 0
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    validated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    validation_notes: str = ""
    compensating_controls: list[str] = field(default_factory=list)
    remediation_plan: str | None = None

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        if self.resources_evaluated == 0:
            return 100.0 if self.status == ValidationStatus.VALIDATED else 0.0
        return (self.resources_compliant / self.resources_evaluated) * 100


@dataclass
class SafeguardAssessment:
    """Assessment for a HIPAA safeguard category."""

    safeguard: HIPAASafeguard
    control_validations: list[ControlValidation] = field(default_factory=list)

    @property
    def controls_validated(self) -> int:
        """Count of validated controls."""
        return sum(
            1 for cv in self.control_validations
            if cv.status == ValidationStatus.VALIDATED
        )

    @property
    def controls_failed(self) -> int:
        """Count of failed controls."""
        return sum(
            1 for cv in self.control_validations
            if cv.status == ValidationStatus.FAILED
        )

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        applicable = [
            cv for cv in self.control_validations
            if cv.status not in (ValidationStatus.NOT_APPLICABLE, ValidationStatus.NOT_TESTED)
        ]
        if not applicable:
            return 100.0
        validated = sum(1 for cv in applicable if cv.status == ValidationStatus.VALIDATED)
        return (validated / len(applicable)) * 100


@dataclass
class RequirementAssessment:
    """Assessment for a PCI-DSS requirement category."""

    requirement: PCIDSSRequirement
    control_validations: list[ControlValidation] = field(default_factory=list)

    @property
    def controls_validated(self) -> int:
        """Count of validated controls."""
        return sum(
            1 for cv in self.control_validations
            if cv.status == ValidationStatus.VALIDATED
        )

    @property
    def controls_failed(self) -> int:
        """Count of failed controls."""
        return sum(
            1 for cv in self.control_validations
            if cv.status == ValidationStatus.FAILED
        )

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        applicable = [
            cv for cv in self.control_validations
            if cv.status not in (ValidationStatus.NOT_APPLICABLE, ValidationStatus.NOT_TESTED)
        ]
        if not applicable:
            return 100.0
        validated = sum(1 for cv in applicable if cv.status == ValidationStatus.VALIDATED)
        return (validated / len(applicable)) * 100


@dataclass
class HIPAAAssessment:
    """Complete HIPAA Security Rule assessment."""

    organization_name: str
    assessment_date: datetime
    safeguard_assessments: list[SafeguardAssessment] = field(default_factory=list)
    risk_analysis_date: datetime | None = None
    covered_entity_type: str = ""  # healthcare provider, health plan, clearinghouse
    business_associate: bool = False
    phi_types: list[str] = field(default_factory=list)
    exceptions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def overall_compliance(self) -> float:
        """Calculate overall compliance percentage."""
        if not self.safeguard_assessments:
            return 100.0
        total = sum(sa.compliance_percentage for sa in self.safeguard_assessments)
        return total / len(self.safeguard_assessments)

    @property
    def total_controls(self) -> int:
        """Get total controls assessed."""
        return sum(len(sa.control_validations) for sa in self.safeguard_assessments)

    @property
    def controls_validated(self) -> int:
        """Get total validated controls."""
        return sum(sa.controls_validated for sa in self.safeguard_assessments)

    @property
    def controls_failed(self) -> int:
        """Get total failed controls."""
        return sum(sa.controls_failed for sa in self.safeguard_assessments)

    @property
    def risk_status(self) -> str:
        """Determine risk status based on compliance."""
        if self.overall_compliance >= 95:
            return "Low Risk"
        elif self.overall_compliance >= 80:
            return "Moderate Risk"
        elif self.overall_compliance >= 60:
            return "High Risk"
        else:
            return "Critical Risk"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "organization_name": self.organization_name,
            "assessment_date": self.assessment_date.isoformat(),
            "overall_compliance": round(self.overall_compliance, 2),
            "risk_status": self.risk_status,
            "total_controls": self.total_controls,
            "controls_validated": self.controls_validated,
            "controls_failed": self.controls_failed,
            "covered_entity_type": self.covered_entity_type,
            "business_associate": self.business_associate,
            "phi_types": self.phi_types,
            "safeguard_assessments": [
                {
                    "safeguard": sa.safeguard.value,
                    "compliance_percentage": round(sa.compliance_percentage, 2),
                    "controls_validated": sa.controls_validated,
                    "controls_failed": sa.controls_failed,
                    "control_validations": [
                        {
                            "control_id": cv.control_id,
                            "control_title": cv.control_title,
                            "status": cv.status.value,
                            "compliance_percentage": round(cv.compliance_percentage, 2),
                        }
                        for cv in sa.control_validations
                    ],
                }
                for sa in self.safeguard_assessments
            ],
            "exceptions": self.exceptions,
        }


@dataclass
class PCIDSSAssessment:
    """Complete PCI-DSS v4.0 assessment."""

    organization_name: str
    assessment_date: datetime
    requirement_assessments: list[RequirementAssessment] = field(default_factory=list)
    merchant_level: int = 1  # 1-4
    service_provider_level: int | None = None  # 1-2
    saq_type: str = ""  # A, A-EP, B, B-IP, C, C-VT, D, P2PE
    roc_required: bool = False
    cardholder_data_environment: str = ""
    exceptions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def overall_compliance(self) -> float:
        """Calculate overall compliance percentage."""
        if not self.requirement_assessments:
            return 100.0
        total = sum(ra.compliance_percentage for ra in self.requirement_assessments)
        return total / len(self.requirement_assessments)

    @property
    def total_controls(self) -> int:
        """Get total controls assessed."""
        return sum(len(ra.control_validations) for ra in self.requirement_assessments)

    @property
    def controls_validated(self) -> int:
        """Get total validated controls."""
        return sum(ra.controls_validated for ra in self.requirement_assessments)

    @property
    def controls_failed(self) -> int:
        """Get total failed controls."""
        return sum(ra.controls_failed for ra in self.requirement_assessments)

    @property
    def compliance_status(self) -> str:
        """Determine compliance status."""
        if self.overall_compliance == 100:
            return "Compliant"
        elif self.overall_compliance >= 95:
            return "Substantially Compliant"
        elif self.overall_compliance >= 80:
            return "Partially Compliant"
        else:
            return "Non-Compliant"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "organization_name": self.organization_name,
            "assessment_date": self.assessment_date.isoformat(),
            "pci_dss_version": "4.0",
            "overall_compliance": round(self.overall_compliance, 2),
            "compliance_status": self.compliance_status,
            "total_controls": self.total_controls,
            "controls_validated": self.controls_validated,
            "controls_failed": self.controls_failed,
            "merchant_level": self.merchant_level,
            "service_provider_level": self.service_provider_level,
            "saq_type": self.saq_type,
            "roc_required": self.roc_required,
            "requirement_assessments": [
                {
                    "requirement_id": ra.requirement.id,
                    "requirement_title": ra.requirement.title,
                    "compliance_percentage": round(ra.compliance_percentage, 2),
                    "controls_validated": ra.controls_validated,
                    "controls_failed": ra.controls_failed,
                    "control_validations": [
                        {
                            "control_id": cv.control_id,
                            "control_title": cv.control_title,
                            "status": cv.status.value,
                            "compliance_percentage": round(cv.compliance_percentage, 2),
                        }
                        for cv in ra.control_validations
                    ],
                }
                for ra in self.requirement_assessments
            ],
            "exceptions": self.exceptions,
        }


class RegulatoryControlValidator:
    """
    Regulatory control validator for HIPAA and PCI-DSS.

    Validates cloud resources against regulatory requirements
    and generates compliance assessment reports.
    """

    # HIPAA Security Rule control catalog
    HIPAA_CONTROLS: dict[str, HIPAAControl] = {}

    # PCI-DSS v4.0 requirements and controls
    PCI_REQUIREMENTS: dict[str, PCIDSSRequirement] = {}
    PCI_CONTROLS: dict[str, PCIDSSControl] = {}

    def __init__(self) -> None:
        """Initialize the regulatory control validator."""
        self._initialize_hipaa_controls()
        self._initialize_pci_controls()

    def _initialize_hipaa_controls(self) -> None:
        """Initialize HIPAA Security Rule controls."""
        # Administrative Safeguards (164.308)
        self.HIPAA_CONTROLS["164.308(a)(1)(i)"] = HIPAAControl(
            id="164.308(a)(1)(i)",
            section="164.308(a)(1)",
            title="Security Management Process",
            description="Implement policies and procedures to prevent, detect, contain, and correct security violations.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Risk Analysis (Required)",
                "Risk Management (Required)",
                "Sanction Policy (Required)",
                "Information System Activity Review (Required)",
            ],
            automated_checks=[
                "security-policy-exists",
                "risk-assessment-conducted",
            ],
            evidence_requirements=[
                "Security policies and procedures",
                "Risk analysis documentation",
                "Sanction policy",
                "System activity review logs",
            ],
            phi_impact="Protects PHI from unauthorized access through security management",
            risk_level="high",
        )

        self.HIPAA_CONTROLS["164.308(a)(1)(ii)(A)"] = HIPAAControl(
            id="164.308(a)(1)(ii)(A)",
            section="164.308(a)(1)",
            title="Risk Analysis",
            description="Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of ePHI.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            automated_checks=[
                "vulnerability-scanning-enabled",
                "security-assessment-completed",
            ],
            evidence_requirements=[
                "Risk assessment report",
                "Vulnerability scan results",
                "Threat analysis documentation",
            ],
            phi_impact="Identifies risks to PHI confidentiality, integrity, and availability",
            risk_level="critical",
        )

        self.HIPAA_CONTROLS["164.308(a)(1)(ii)(B)"] = HIPAAControl(
            id="164.308(a)(1)(ii)(B)",
            section="164.308(a)(1)",
            title="Risk Management",
            description="Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            automated_checks=[
                "security-controls-implemented",
                "remediation-tracking",
            ],
            evidence_requirements=[
                "Risk treatment plan",
                "Security control documentation",
                "Remediation tracking records",
            ],
            phi_impact="Mitigates identified risks to PHI",
            risk_level="high",
        )

        self.HIPAA_CONTROLS["164.308(a)(3)(i)"] = HIPAAControl(
            id="164.308(a)(3)(i)",
            section="164.308(a)(3)",
            title="Workforce Security",
            description="Implement policies and procedures to ensure that workforce members have appropriate access to ePHI.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Authorization and/or Supervision (Addressable)",
                "Workforce Clearance Procedure (Addressable)",
                "Termination Procedures (Addressable)",
            ],
            automated_checks=[
                "iam-user-management",
                "access-reviews-conducted",
            ],
            evidence_requirements=[
                "Access control policy",
                "Authorization procedures",
                "Termination checklists",
            ],
            phi_impact="Ensures only authorized workforce access to PHI",
            risk_level="high",
        )

        self.HIPAA_CONTROLS["164.308(a)(4)(i)"] = HIPAAControl(
            id="164.308(a)(4)(i)",
            section="164.308(a)(4)",
            title="Information Access Management",
            description="Implement policies and procedures for authorizing access to ePHI.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Isolating Health Care Clearinghouse Functions (Required)",
                "Access Authorization (Addressable)",
                "Access Establishment and Modification (Addressable)",
            ],
            automated_checks=[
                "iam-least-privilege",
                "access-logging-enabled",
            ],
            evidence_requirements=[
                "Access authorization procedures",
                "Role definitions",
                "Access modification records",
            ],
            phi_impact="Controls access to PHI based on job function",
            risk_level="high",
        )

        self.HIPAA_CONTROLS["164.308(a)(5)(i)"] = HIPAAControl(
            id="164.308(a)(5)(i)",
            section="164.308(a)(5)",
            title="Security Awareness and Training",
            description="Implement a security awareness and training program for workforce members.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Security Reminders (Addressable)",
                "Protection from Malicious Software (Addressable)",
                "Log-in Monitoring (Addressable)",
                "Password Management (Addressable)",
            ],
            automated_checks=[
                "training-records-exist",
            ],
            evidence_requirements=[
                "Training program documentation",
                "Training completion records",
                "Security awareness materials",
            ],
            phi_impact="Educates workforce on PHI protection",
            risk_level="medium",
        )

        self.HIPAA_CONTROLS["164.308(a)(6)(i)"] = HIPAAControl(
            id="164.308(a)(6)(i)",
            section="164.308(a)(6)",
            title="Security Incident Procedures",
            description="Implement policies and procedures to address security incidents.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Response and Reporting (Required)",
            ],
            automated_checks=[
                "incident-response-plan",
                "security-monitoring-enabled",
            ],
            evidence_requirements=[
                "Incident response plan",
                "Incident tracking system",
                "Incident reports",
            ],
            phi_impact="Enables rapid response to PHI security incidents",
            risk_level="critical",
        )

        self.HIPAA_CONTROLS["164.308(a)(7)(i)"] = HIPAAControl(
            id="164.308(a)(7)(i)",
            section="164.308(a)(7)",
            title="Contingency Plan",
            description="Establish policies and procedures for responding to emergencies that damage systems containing ePHI.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Data Backup Plan (Required)",
                "Disaster Recovery Plan (Required)",
                "Emergency Mode Operation Plan (Required)",
                "Testing and Revision Procedures (Addressable)",
                "Applications and Data Criticality Analysis (Addressable)",
            ],
            automated_checks=[
                "backup-enabled",
                "disaster-recovery-plan",
                "backup-testing",
            ],
            evidence_requirements=[
                "Contingency plan",
                "Backup procedures",
                "DR test results",
            ],
            phi_impact="Ensures PHI availability during emergencies",
            risk_level="critical",
        )

        self.HIPAA_CONTROLS["164.308(a)(8)"] = HIPAAControl(
            id="164.308(a)(8)",
            section="164.308(a)(8)",
            title="Evaluation",
            description="Perform periodic technical and nontechnical evaluation based on standards.",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            automated_checks=[
                "security-assessment-periodic",
                "compliance-monitoring",
            ],
            evidence_requirements=[
                "Evaluation reports",
                "Assessment schedules",
                "Remediation tracking",
            ],
            phi_impact="Validates ongoing PHI protection",
            risk_level="medium",
        )

        # Physical Safeguards (164.310)
        self.HIPAA_CONTROLS["164.310(a)(1)"] = HIPAAControl(
            id="164.310(a)(1)",
            section="164.310(a)",
            title="Facility Access Controls",
            description="Implement policies and procedures to limit physical access to electronic information systems.",
            safeguard=HIPAASafeguard.PHYSICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Contingency Operations (Addressable)",
                "Facility Security Plan (Addressable)",
                "Access Control and Validation Procedures (Addressable)",
                "Maintenance Records (Addressable)",
            ],
            evidence_requirements=[
                "Facility security plan",
                "Access logs",
                "Maintenance records",
            ],
            phi_impact="Protects physical access to PHI systems",
            risk_level="high",
        )

        self.HIPAA_CONTROLS["164.310(b)"] = HIPAAControl(
            id="164.310(b)",
            section="164.310(b)",
            title="Workstation Use",
            description="Implement policies and procedures for proper workstation use.",
            safeguard=HIPAASafeguard.PHYSICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            evidence_requirements=[
                "Workstation use policy",
                "Acceptable use policy",
            ],
            phi_impact="Controls workstation access to PHI",
            risk_level="medium",
        )

        self.HIPAA_CONTROLS["164.310(c)"] = HIPAAControl(
            id="164.310(c)",
            section="164.310(c)",
            title="Workstation Security",
            description="Implement physical safeguards for workstations accessing ePHI.",
            safeguard=HIPAASafeguard.PHYSICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            automated_checks=[
                "endpoint-protection",
                "screen-lock-enabled",
            ],
            evidence_requirements=[
                "Workstation security procedures",
                "Physical security measures",
            ],
            phi_impact="Physically secures workstations with PHI access",
            risk_level="medium",
        )

        self.HIPAA_CONTROLS["164.310(d)(1)"] = HIPAAControl(
            id="164.310(d)(1)",
            section="164.310(d)",
            title="Device and Media Controls",
            description="Implement policies and procedures for receipt and removal of hardware and electronic media.",
            safeguard=HIPAASafeguard.PHYSICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Disposal (Required)",
                "Media Re-use (Required)",
                "Accountability (Addressable)",
                "Data Backup and Storage (Addressable)",
            ],
            automated_checks=[
                "data-disposal-procedures",
                "encryption-at-rest",
            ],
            evidence_requirements=[
                "Media handling procedures",
                "Disposal records",
                "Asset tracking",
            ],
            phi_impact="Ensures proper handling of PHI on devices and media",
            risk_level="high",
        )

        # Technical Safeguards (164.312)
        self.HIPAA_CONTROLS["164.312(a)(1)"] = HIPAAControl(
            id="164.312(a)(1)",
            section="164.312(a)",
            title="Access Control",
            description="Implement technical policies and procedures for electronic information systems.",
            safeguard=HIPAASafeguard.TECHNICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Unique User Identification (Required)",
                "Emergency Access Procedure (Required)",
                "Automatic Logoff (Addressable)",
                "Encryption and Decryption (Addressable)",
            ],
            automated_checks=[
                "iam-unique-users",
                "session-timeout-enabled",
                "encryption-at-rest",
            ],
            evidence_requirements=[
                "Access control policy",
                "User identification procedures",
                "Encryption standards",
            ],
            phi_impact="Controls technical access to PHI",
            risk_level="critical",
        )

        self.HIPAA_CONTROLS["164.312(b)"] = HIPAAControl(
            id="164.312(b)",
            section="164.312(b)",
            title="Audit Controls",
            description="Implement hardware, software, and procedural mechanisms to record and examine activity.",
            safeguard=HIPAASafeguard.TECHNICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            automated_checks=[
                "cloudtrail-enabled",
                "logging-enabled",
                "log-retention",
            ],
            evidence_requirements=[
                "Audit logging configuration",
                "Audit log retention policy",
                "Audit review procedures",
            ],
            phi_impact="Creates audit trail for PHI access",
            risk_level="critical",
        )

        self.HIPAA_CONTROLS["164.312(c)(1)"] = HIPAAControl(
            id="164.312(c)(1)",
            section="164.312(c)",
            title="Integrity",
            description="Implement policies and procedures to protect ePHI from improper alteration or destruction.",
            safeguard=HIPAASafeguard.TECHNICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Mechanism to Authenticate ePHI (Addressable)",
            ],
            automated_checks=[
                "data-integrity-checks",
                "backup-integrity",
            ],
            evidence_requirements=[
                "Integrity procedures",
                "Hash verification logs",
                "Change detection records",
            ],
            phi_impact="Protects PHI from unauthorized modification",
            risk_level="high",
        )

        self.HIPAA_CONTROLS["164.312(d)"] = HIPAAControl(
            id="164.312(d)",
            section="164.312(d)",
            title="Person or Entity Authentication",
            description="Implement procedures to verify persons seeking access to ePHI.",
            safeguard=HIPAASafeguard.TECHNICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            automated_checks=[
                "mfa-enabled",
                "strong-authentication",
            ],
            evidence_requirements=[
                "Authentication policy",
                "MFA configuration",
                "Authentication logs",
            ],
            phi_impact="Verifies identity before PHI access",
            risk_level="critical",
        )

        self.HIPAA_CONTROLS["164.312(e)(1)"] = HIPAAControl(
            id="164.312(e)(1)",
            section="164.312(e)",
            title="Transmission Security",
            description="Implement technical security measures to guard against unauthorized access to ePHI transmitted over networks.",
            safeguard=HIPAASafeguard.TECHNICAL,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            implementation_specifications=[
                "Integrity Controls (Addressable)",
                "Encryption (Addressable)",
            ],
            automated_checks=[
                "encryption-in-transit",
                "tls-required",
                "vpn-enabled",
            ],
            evidence_requirements=[
                "Transmission security policy",
                "Encryption configuration",
                "Network security documentation",
            ],
            phi_impact="Protects PHI during network transmission",
            risk_level="critical",
        )

    def _initialize_pci_controls(self) -> None:
        """Initialize PCI-DSS v4.0 requirements and controls."""
        # Requirement 1: Install and Maintain Network Security Controls
        self.PCI_REQUIREMENTS["1"] = PCIDSSRequirement(
            id="1",
            title="Install and Maintain Network Security Controls",
            description="Network security controls (NSCs) are network policy enforcement points that control traffic between two or more subnets, such as firewalls, routers, and proxies.",
            goal="Build and Maintain a Secure Network and Systems",
            controls=["1.1", "1.2", "1.3", "1.4", "1.5"],
        )

        self.PCI_CONTROLS["1.2.1"] = PCIDSSControl(
            id="1.2.1",
            requirement_id="1",
            title="Configuration standards for NSC rulesets",
            description="Configuration standards for NSC rulesets are defined, implemented, and maintained.",
            testing_procedure="Examine configuration standards and settings to verify rulesets are defined and implemented.",
            guidance="Having documented standards for configuring NSCs helps ensure consistent configuration.",
            automated_checks=[
                "security-group-rules-documented",
                "firewall-rules-reviewed",
            ],
            evidence_requirements=[
                "NSC configuration standards",
                "Firewall rule documentation",
            ],
        )

        self.PCI_CONTROLS["1.3.1"] = PCIDSSControl(
            id="1.3.1",
            requirement_id="1",
            title="Inbound traffic restricted to CDE",
            description="Inbound traffic to the cardholder data environment is restricted.",
            testing_procedure="Examine NSC configurations to verify inbound traffic is restricted.",
            guidance="Restricting inbound traffic limits the attack surface of the CDE.",
            automated_checks=[
                "security-group-restricted-inbound",
                "no-unrestricted-ingress",
            ],
            evidence_requirements=[
                "NSC configurations",
                "Network diagrams",
            ],
        )

        self.PCI_CONTROLS["1.4.1"] = PCIDSSControl(
            id="1.4.1",
            requirement_id="1",
            title="NSCs between wireless and CDE",
            description="NSCs are implemented between wireless networks and the CDE.",
            testing_procedure="Examine NSC configurations for wireless network segmentation.",
            guidance="Wireless networks are inherently less secure and need additional protection.",
            automated_checks=[
                "wireless-network-segmented",
            ],
            evidence_requirements=[
                "Wireless network architecture",
                "Segmentation configuration",
            ],
        )

        # Requirement 2: Apply Secure Configurations
        self.PCI_REQUIREMENTS["2"] = PCIDSSRequirement(
            id="2",
            title="Apply Secure Configurations to All System Components",
            description="Malicious individuals often use default passwords and other vendor default settings to compromise systems.",
            goal="Build and Maintain a Secure Network and Systems",
            controls=["2.1", "2.2", "2.3"],
        )

        self.PCI_CONTROLS["2.2.1"] = PCIDSSControl(
            id="2.2.1",
            requirement_id="2",
            title="Configuration standards developed",
            description="Configuration standards are developed, implemented, and maintained for system components.",
            testing_procedure="Examine configuration standards to verify they are documented and maintained.",
            guidance="Configuration standards help ensure consistent secure configurations.",
            automated_checks=[
                "hardening-standards-applied",
                "cis-benchmark-compliance",
            ],
            evidence_requirements=[
                "Configuration standards",
                "Hardening guides",
            ],
        )

        self.PCI_CONTROLS["2.2.2"] = PCIDSSControl(
            id="2.2.2",
            requirement_id="2",
            title="Vendor default accounts managed",
            description="Vendor default accounts are managed.",
            testing_procedure="Verify default accounts are disabled or passwords changed.",
            guidance="Default accounts are commonly targeted by attackers.",
            automated_checks=[
                "no-default-credentials",
                "default-accounts-disabled",
            ],
            evidence_requirements=[
                "Account inventory",
                "Password change records",
            ],
        )

        # Requirement 3: Protect Stored Account Data
        self.PCI_REQUIREMENTS["3"] = PCIDSSRequirement(
            id="3",
            title="Protect Stored Account Data",
            description="Protection methods such as encryption, truncation, masking, and hashing are critical components of cardholder data protection.",
            goal="Protect Account Data",
            controls=["3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7"],
        )

        self.PCI_CONTROLS["3.4.1"] = PCIDSSControl(
            id="3.4.1",
            requirement_id="3",
            title="PAN is rendered unreadable",
            description="PAN is rendered unreadable anywhere it is stored using strong cryptography.",
            testing_procedure="Examine data stores and verify PAN is rendered unreadable.",
            guidance="Encrypted PAN is useless to attackers without the encryption keys.",
            automated_checks=[
                "encryption-at-rest",
                "database-encryption",
                "field-level-encryption",
            ],
            evidence_requirements=[
                "Encryption configuration",
                "Key management documentation",
            ],
        )

        self.PCI_CONTROLS["3.5.1"] = PCIDSSControl(
            id="3.5.1",
            requirement_id="3",
            title="Sensitive authentication data not stored after authorization",
            description="Sensitive authentication data (SAD) is not stored after authorization.",
            testing_procedure="Verify SAD is not stored or is deleted after authorization.",
            guidance="SAD should never be stored as it enables fraudulent transactions.",
            automated_checks=[
                "no-sad-storage",
            ],
            evidence_requirements=[
                "Data flow diagrams",
                "Storage configuration",
            ],
        )

        # Requirement 4: Protect Cardholder Data with Strong Cryptography
        self.PCI_REQUIREMENTS["4"] = PCIDSSRequirement(
            id="4",
            title="Protect Cardholder Data with Strong Cryptography During Transmission Over Open, Public Networks",
            description="Use of strong cryptography provides greater assurance in preserving data confidentiality, integrity, and non-repudiation.",
            goal="Protect Account Data",
            controls=["4.1", "4.2"],
        )

        self.PCI_CONTROLS["4.2.1"] = PCIDSSControl(
            id="4.2.1",
            requirement_id="4",
            title="Strong cryptography protects PAN during transmission",
            description="Strong cryptography is used to protect PAN during transmission over open, public networks.",
            testing_procedure="Verify strong cryptography is used for transmission.",
            guidance="Strong cryptography protects data from interception during transmission.",
            automated_checks=[
                "tls-1.2-minimum",
                "encryption-in-transit",
                "ssl-certificate-valid",
            ],
            evidence_requirements=[
                "TLS configuration",
                "Certificate inventory",
            ],
        )

        # Requirement 5: Protect All Systems and Networks from Malicious Software
        self.PCI_REQUIREMENTS["5"] = PCIDSSRequirement(
            id="5",
            title="Protect All Systems and Networks from Malicious Software",
            description="Malicious software, including viruses, worms, and Trojans, can enter the network via many business-approved activities.",
            goal="Maintain a Vulnerability Management Program",
            controls=["5.1", "5.2", "5.3", "5.4"],
        )

        self.PCI_CONTROLS["5.2.1"] = PCIDSSControl(
            id="5.2.1",
            requirement_id="5",
            title="Anti-malware solution deployed",
            description="An anti-malware solution is deployed on all system components.",
            testing_procedure="Verify anti-malware is deployed and active.",
            guidance="Anti-malware protects systems from known malicious software.",
            automated_checks=[
                "antimalware-enabled",
                "endpoint-protection",
            ],
            evidence_requirements=[
                "Anti-malware deployment records",
                "Scan logs",
            ],
        )

        self.PCI_CONTROLS["5.3.1"] = PCIDSSControl(
            id="5.3.1",
            requirement_id="5",
            title="Anti-malware mechanisms current",
            description="Anti-malware mechanisms are kept current.",
            testing_procedure="Verify anti-malware signatures and software are current.",
            guidance="Current anti-malware detects the latest threats.",
            automated_checks=[
                "antimalware-updated",
            ],
            evidence_requirements=[
                "Update logs",
                "Version records",
            ],
        )

        # Requirement 6: Develop and Maintain Secure Systems and Software
        self.PCI_REQUIREMENTS["6"] = PCIDSSRequirement(
            id="6",
            title="Develop and Maintain Secure Systems and Software",
            description="Attackers exploit vulnerabilities to gain privileged access to systems.",
            goal="Maintain a Vulnerability Management Program",
            controls=["6.1", "6.2", "6.3", "6.4", "6.5"],
        )

        self.PCI_CONTROLS["6.2.1"] = PCIDSSControl(
            id="6.2.1",
            requirement_id="6",
            title="Software developed securely",
            description="Bespoke and custom software is developed securely.",
            testing_procedure="Verify secure development practices are followed.",
            guidance="Secure development prevents introduction of vulnerabilities.",
            automated_checks=[
                "secure-development-lifecycle",
                "code-review-required",
            ],
            evidence_requirements=[
                "SDLC documentation",
                "Code review records",
            ],
        )

        self.PCI_CONTROLS["6.3.1"] = PCIDSSControl(
            id="6.3.1",
            requirement_id="6",
            title="Security vulnerabilities identified and addressed",
            description="Security vulnerabilities are identified and addressed.",
            testing_procedure="Verify vulnerability identification and remediation processes.",
            guidance="Timely remediation reduces exposure to known vulnerabilities.",
            automated_checks=[
                "vulnerability-scanning",
                "patch-management",
            ],
            evidence_requirements=[
                "Vulnerability scan reports",
                "Patch records",
            ],
        )

        # Requirement 7: Restrict Access to System Components and Cardholder Data
        self.PCI_REQUIREMENTS["7"] = PCIDSSRequirement(
            id="7",
            title="Restrict Access to System Components and Cardholder Data by Business Need to Know",
            description="Systems and processes must be in place to limit access based on need to know and according to job responsibilities.",
            goal="Implement Strong Access Control Measures",
            controls=["7.1", "7.2", "7.3"],
        )

        self.PCI_CONTROLS["7.2.1"] = PCIDSSControl(
            id="7.2.1",
            requirement_id="7",
            title="Access control model defined",
            description="An access control model is defined and includes granting access based on job function.",
            testing_procedure="Verify access control model is defined and implemented.",
            guidance="Role-based access ensures appropriate access levels.",
            automated_checks=[
                "iam-role-based-access",
                "least-privilege",
            ],
            evidence_requirements=[
                "Access control policy",
                "Role definitions",
            ],
        )

        self.PCI_CONTROLS["7.2.2"] = PCIDSSControl(
            id="7.2.2",
            requirement_id="7",
            title="Access assigned based on personnel classification",
            description="Access is assigned to users based on job classification and function.",
            testing_procedure="Verify access assignments align with job functions.",
            guidance="Proper access assignment prevents unauthorized access.",
            automated_checks=[
                "access-reviews-conducted",
            ],
            evidence_requirements=[
                "Access assignments",
                "Job classifications",
            ],
        )

        # Requirement 8: Identify Users and Authenticate Access
        self.PCI_REQUIREMENTS["8"] = PCIDSSRequirement(
            id="8",
            title="Identify Users and Authenticate Access to System Components",
            description="Two fundamental principles of identifying and authenticating users are: 1) establishing the identity of an individual or process, and 2) proving the identity is valid.",
            goal="Implement Strong Access Control Measures",
            controls=["8.1", "8.2", "8.3", "8.4", "8.5", "8.6"],
        )

        self.PCI_CONTROLS["8.2.1"] = PCIDSSControl(
            id="8.2.1",
            requirement_id="8",
            title="Unique user IDs assigned",
            description="All users are assigned a unique ID before access to system components.",
            testing_procedure="Verify all users have unique IDs.",
            guidance="Unique IDs enable individual accountability.",
            automated_checks=[
                "iam-unique-users",
                "no-shared-accounts",
            ],
            evidence_requirements=[
                "User ID list",
                "Account creation procedures",
            ],
        )

        self.PCI_CONTROLS["8.3.1"] = PCIDSSControl(
            id="8.3.1",
            requirement_id="8",
            title="Strong authentication for user access",
            description="Strong authentication is used for all access to the CDE.",
            testing_procedure="Verify authentication mechanisms meet requirements.",
            guidance="Strong authentication prevents unauthorized access.",
            automated_checks=[
                "mfa-enabled",
                "password-policy-compliant",
            ],
            evidence_requirements=[
                "Authentication configuration",
                "MFA enrollment records",
            ],
        )

        self.PCI_CONTROLS["8.3.6"] = PCIDSSControl(
            id="8.3.6",
            requirement_id="8",
            title="MFA for CDE access",
            description="MFA is implemented for all access into the CDE.",
            testing_procedure="Verify MFA is required for CDE access.",
            guidance="MFA provides additional layer of authentication.",
            automated_checks=[
                "mfa-required-cde",
            ],
            evidence_requirements=[
                "MFA configuration",
                "Access logs",
            ],
        )

        # Requirement 10: Log and Monitor All Access
        self.PCI_REQUIREMENTS["10"] = PCIDSSRequirement(
            id="10",
            title="Log and Monitor All Access to System Components and Cardholder Data",
            description="Logging mechanisms and the ability to track user activities are critical for preventing, detecting, and minimizing the impact of a data compromise.",
            goal="Regularly Monitor and Test Networks",
            controls=["10.1", "10.2", "10.3", "10.4", "10.5", "10.6", "10.7"],
        )

        self.PCI_CONTROLS["10.2.1"] = PCIDSSControl(
            id="10.2.1",
            requirement_id="10",
            title="Audit logs enabled",
            description="Audit logs are enabled and active for all system components.",
            testing_procedure="Verify audit logs are enabled on all components.",
            guidance="Audit logs provide evidence of activity for investigation.",
            automated_checks=[
                "cloudtrail-enabled",
                "logging-enabled",
                "audit-logging-configured",
            ],
            evidence_requirements=[
                "Logging configuration",
                "Log samples",
            ],
        )

        self.PCI_CONTROLS["10.3.1"] = PCIDSSControl(
            id="10.3.1",
            requirement_id="10",
            title="Audit logs capture required events",
            description="Audit logs capture user identification, event type, date/time, success/failure, origination, and identity/name of affected data.",
            testing_procedure="Verify log entries contain required information.",
            guidance="Complete log entries enable effective investigation.",
            automated_checks=[
                "log-format-compliant",
            ],
            evidence_requirements=[
                "Log format documentation",
                "Sample log entries",
            ],
        )

        self.PCI_CONTROLS["10.5.1"] = PCIDSSControl(
            id="10.5.1",
            requirement_id="10",
            title="Audit log history retained",
            description="Audit log history is retained for at least 12 months.",
            testing_procedure="Verify log retention meets 12-month requirement.",
            guidance="Historical logs support investigation of past incidents.",
            automated_checks=[
                "log-retention-12-months",
            ],
            evidence_requirements=[
                "Retention configuration",
                "Archived logs",
            ],
        )

        # Requirement 11: Test Security of Systems and Networks Regularly
        self.PCI_REQUIREMENTS["11"] = PCIDSSRequirement(
            id="11",
            title="Test Security of Systems and Networks Regularly",
            description="Vulnerabilities are being discovered continually, and these processes ensure that systems and networks are tested for weaknesses.",
            goal="Regularly Monitor and Test Networks",
            controls=["11.1", "11.2", "11.3", "11.4", "11.5", "11.6"],
        )

        self.PCI_CONTROLS["11.3.1"] = PCIDSSControl(
            id="11.3.1",
            requirement_id="11",
            title="Internal vulnerability scans performed",
            description="Internal vulnerability scans are performed at least quarterly.",
            testing_procedure="Verify quarterly internal scans are performed.",
            guidance="Regular scans identify new vulnerabilities.",
            automated_checks=[
                "vulnerability-scanning-quarterly",
            ],
            evidence_requirements=[
                "Scan reports",
                "Scan schedule",
            ],
        )

        self.PCI_CONTROLS["11.3.2"] = PCIDSSControl(
            id="11.3.2",
            requirement_id="11",
            title="External vulnerability scans performed",
            description="External vulnerability scans are performed at least quarterly by an ASV.",
            testing_procedure="Verify quarterly ASV scans are performed.",
            guidance="ASV scans validate external security posture.",
            automated_checks=[
                "asv-scans-quarterly",
            ],
            evidence_requirements=[
                "ASV scan reports",
                "Attestations",
            ],
        )

        self.PCI_CONTROLS["11.4.1"] = PCIDSSControl(
            id="11.4.1",
            requirement_id="11",
            title="Penetration testing performed",
            description="Penetration testing is performed annually and after significant changes.",
            testing_procedure="Verify annual penetration tests are performed.",
            guidance="Penetration testing identifies exploitable vulnerabilities.",
            automated_checks=[
                "pentest-annual",
            ],
            evidence_requirements=[
                "Penetration test reports",
                "Remediation records",
            ],
        )

        # Requirement 12: Support Information Security with Organizational Policies
        self.PCI_REQUIREMENTS["12"] = PCIDSSRequirement(
            id="12",
            title="Support Information Security with Organizational Policies and Programs",
            description="A strong security policy sets the security tone for the whole entity and informs personnel what is expected of them.",
            goal="Maintain an Information Security Policy",
            controls=["12.1", "12.2", "12.3", "12.4", "12.5", "12.6", "12.7", "12.8", "12.9", "12.10"],
        )

        self.PCI_CONTROLS["12.1.1"] = PCIDSSControl(
            id="12.1.1",
            requirement_id="12",
            title="Information security policy established",
            description="An overall information security policy is established, published, maintained, and disseminated.",
            testing_procedure="Verify security policy is documented and distributed.",
            guidance="Policy provides foundation for security program.",
            automated_checks=[
                "security-policy-exists",
            ],
            evidence_requirements=[
                "Security policy",
                "Distribution records",
            ],
        )

        self.PCI_CONTROLS["12.6.1"] = PCIDSSControl(
            id="12.6.1",
            requirement_id="12",
            title="Security awareness program implemented",
            description="A formal security awareness program is implemented.",
            testing_procedure="Verify security awareness training is provided.",
            guidance="Awareness training reduces human-factor risks.",
            automated_checks=[
                "security-awareness-training",
            ],
            evidence_requirements=[
                "Training materials",
                "Completion records",
            ],
        )

        self.PCI_CONTROLS["12.10.1"] = PCIDSSControl(
            id="12.10.1",
            requirement_id="12",
            title="Incident response plan established",
            description="An incident response plan exists and is ready for activation.",
            testing_procedure="Verify incident response plan is documented and tested.",
            guidance="Prepared response minimizes impact of incidents.",
            automated_checks=[
                "incident-response-plan",
            ],
            evidence_requirements=[
                "Incident response plan",
                "Test records",
            ],
        )

    def get_hipaa_control(self, control_id: str) -> HIPAAControl | None:
        """Get a specific HIPAA control."""
        return self.HIPAA_CONTROLS.get(control_id)

    def get_hipaa_controls_by_safeguard(
        self, safeguard: HIPAASafeguard
    ) -> list[HIPAAControl]:
        """Get all HIPAA controls for a safeguard category."""
        return [
            c for c in self.HIPAA_CONTROLS.values()
            if c.safeguard == safeguard
        ]

    def get_pci_requirement(self, requirement_id: str) -> PCIDSSRequirement | None:
        """Get a specific PCI-DSS requirement."""
        return self.PCI_REQUIREMENTS.get(requirement_id)

    def get_pci_control(self, control_id: str) -> PCIDSSControl | None:
        """Get a specific PCI-DSS control."""
        return self.PCI_CONTROLS.get(control_id)

    def get_pci_controls_by_requirement(
        self, requirement_id: str
    ) -> list[PCIDSSControl]:
        """Get all PCI-DSS controls for a requirement."""
        return [
            c for c in self.PCI_CONTROLS.values()
            if c.requirement_id == requirement_id
        ]

    def validate_hipaa(
        self,
        policies: Any,  # PolicyCollection
        findings: Any,  # FindingCollection
        organization_name: str = "",
        covered_entity_type: str = "",
    ) -> HIPAAAssessment:
        """
        Perform HIPAA Security Rule validation.

        Args:
            policies: Collection of policies
            findings: Collection of findings
            organization_name: Name of organization
            covered_entity_type: Type of covered entity

        Returns:
            HIPAAAssessment with detailed results
        """
        now = datetime.now(timezone.utc)
        safeguard_assessments: list[SafeguardAssessment] = []

        for safeguard in HIPAASafeguard:
            controls = self.get_hipaa_controls_by_safeguard(safeguard)
            control_validations: list[ControlValidation] = []

            for control in controls:
                validation = self._validate_hipaa_control(control, policies, findings)
                control_validations.append(validation)

            safeguard_assessments.append(
                SafeguardAssessment(
                    safeguard=safeguard,
                    control_validations=control_validations,
                )
            )

        return HIPAAAssessment(
            organization_name=organization_name,
            assessment_date=now,
            safeguard_assessments=safeguard_assessments,
            covered_entity_type=covered_entity_type,
        )

    def _validate_hipaa_control(
        self,
        control: HIPAAControl,
        policies: Any,
        findings: Any,
    ) -> ControlValidation:
        """Validate a single HIPAA control."""
        if not control.automated_checks:
            return ControlValidation(
                control_id=control.id,
                control_title=control.title,
                framework=RegulatoryFramework.HIPAA,
                status=ValidationStatus.NOT_TESTED,
                validation_notes="No automated checks available for this control",
            )

        resources_evaluated = 0
        resources_compliant = 0
        related_findings: list[str] = []

        for check_id in control.automated_checks:
            # Find matching policy
            policy = None
            for p in policies:
                if p.id == check_id or check_id in getattr(p, "tags", []):
                    policy = p
                    break

            if not policy:
                continue

            resources_evaluated += 1

            # Check for findings
            policy_findings = [f for f in findings if f.rule_id == policy.id]

            if not policy_findings:
                resources_compliant += 1
            else:
                for f in policy_findings:
                    related_findings.append(f.id)

        if resources_evaluated == 0:
            status = ValidationStatus.NOT_TESTED
        elif resources_compliant == resources_evaluated:
            status = ValidationStatus.VALIDATED
        elif resources_compliant > 0:
            status = ValidationStatus.PARTIAL
        else:
            status = ValidationStatus.FAILED

        return ControlValidation(
            control_id=control.id,
            control_title=control.title,
            framework=RegulatoryFramework.HIPAA,
            status=status,
            resources_evaluated=resources_evaluated,
            resources_compliant=resources_compliant,
            resources_non_compliant=resources_evaluated - resources_compliant,
            findings=related_findings,
        )

    def validate_pci_dss(
        self,
        policies: Any,  # PolicyCollection
        findings: Any,  # FindingCollection
        organization_name: str = "",
        merchant_level: int = 1,
    ) -> PCIDSSAssessment:
        """
        Perform PCI-DSS v4.0 validation.

        Args:
            policies: Collection of policies
            findings: Collection of findings
            organization_name: Name of organization
            merchant_level: Merchant level (1-4)

        Returns:
            PCIDSSAssessment with detailed results
        """
        now = datetime.now(timezone.utc)
        requirement_assessments: list[RequirementAssessment] = []

        for req_id, requirement in self.PCI_REQUIREMENTS.items():
            controls = self.get_pci_controls_by_requirement(req_id)
            control_validations: list[ControlValidation] = []

            for control in controls:
                validation = self._validate_pci_control(control, policies, findings)
                control_validations.append(validation)

            requirement_assessments.append(
                RequirementAssessment(
                    requirement=requirement,
                    control_validations=control_validations,
                )
            )

        return PCIDSSAssessment(
            organization_name=organization_name,
            assessment_date=now,
            requirement_assessments=requirement_assessments,
            merchant_level=merchant_level,
            roc_required=merchant_level == 1,
        )

    def _validate_pci_control(
        self,
        control: PCIDSSControl,
        policies: Any,
        findings: Any,
    ) -> ControlValidation:
        """Validate a single PCI-DSS control."""
        if not control.automated_checks:
            return ControlValidation(
                control_id=control.id,
                control_title=control.title,
                framework=RegulatoryFramework.PCI_DSS,
                status=ValidationStatus.NOT_TESTED,
                validation_notes="No automated checks available for this control",
            )

        resources_evaluated = 0
        resources_compliant = 0
        related_findings: list[str] = []

        for check_id in control.automated_checks:
            # Find matching policy
            policy = None
            for p in policies:
                if p.id == check_id or check_id in getattr(p, "tags", []):
                    policy = p
                    break

            if not policy:
                continue

            resources_evaluated += 1

            # Check for findings
            policy_findings = [f for f in findings if f.rule_id == policy.id]

            if not policy_findings:
                resources_compliant += 1
            else:
                for f in policy_findings:
                    related_findings.append(f.id)

        if resources_evaluated == 0:
            status = ValidationStatus.NOT_TESTED
        elif resources_compliant == resources_evaluated:
            status = ValidationStatus.VALIDATED
        elif resources_compliant > 0:
            status = ValidationStatus.PARTIAL
        else:
            status = ValidationStatus.FAILED

        return ControlValidation(
            control_id=control.id,
            control_title=control.title,
            framework=RegulatoryFramework.PCI_DSS,
            status=status,
            resources_evaluated=resources_evaluated,
            resources_compliant=resources_compliant,
            resources_non_compliant=resources_evaluated - resources_compliant,
            findings=related_findings,
        )

    def get_hipaa_control_matrix(self) -> list[dict[str, Any]]:
        """Generate HIPAA control matrix for documentation."""
        matrix = []
        for control in self.HIPAA_CONTROLS.values():
            matrix.append({
                "control_id": control.id,
                "section": control.section,
                "title": control.title,
                "safeguard": control.safeguard.value,
                "requirement": control.requirement.value,
                "automated_checks": control.automated_checks,
                "evidence_requirements": control.evidence_requirements,
                "risk_level": control.risk_level,
            })
        return matrix

    def get_pci_control_matrix(self) -> list[dict[str, Any]]:
        """Generate PCI-DSS control matrix for documentation."""
        matrix = []
        for control in self.PCI_CONTROLS.values():
            requirement = self.get_pci_requirement(control.requirement_id)
            matrix.append({
                "control_id": control.id,
                "requirement_id": control.requirement_id,
                "requirement_title": requirement.title if requirement else "",
                "control_title": control.title,
                "automated_checks": control.automated_checks,
                "evidence_requirements": control.evidence_requirements,
                "applicability": control.applicability,
            })
        return matrix

    def generate_gap_analysis(
        self,
        hipaa_assessment: HIPAAAssessment | None = None,
        pci_assessment: PCIDSSAssessment | None = None,
    ) -> dict[str, Any]:
        """Generate gap analysis report."""
        gaps = {
            "summary": {},
            "hipaa_gaps": [],
            "pci_gaps": [],
            "recommendations": [],
        }

        if hipaa_assessment:
            gaps["summary"]["hipaa_compliance"] = round(hipaa_assessment.overall_compliance, 2)
            gaps["summary"]["hipaa_risk_status"] = hipaa_assessment.risk_status

            for sa in hipaa_assessment.safeguard_assessments:
                for cv in sa.control_validations:
                    if cv.status in (ValidationStatus.FAILED, ValidationStatus.PARTIAL):
                        control = self.get_hipaa_control(cv.control_id)
                        gaps["hipaa_gaps"].append({
                            "control_id": cv.control_id,
                            "control_title": cv.control_title,
                            "status": cv.status.value,
                            "safeguard": sa.safeguard.value,
                            "risk_level": control.risk_level if control else "unknown",
                            "remediation_steps": control.evidence_requirements if control else [],
                        })

        if pci_assessment:
            gaps["summary"]["pci_compliance"] = round(pci_assessment.overall_compliance, 2)
            gaps["summary"]["pci_status"] = pci_assessment.compliance_status

            for ra in pci_assessment.requirement_assessments:
                for cv in ra.control_validations:
                    if cv.status in (ValidationStatus.FAILED, ValidationStatus.PARTIAL):
                        control = self.get_pci_control(cv.control_id)
                        gaps["pci_gaps"].append({
                            "control_id": cv.control_id,
                            "control_title": cv.control_title,
                            "status": cv.status.value,
                            "requirement": ra.requirement.title,
                            "guidance": control.guidance if control else "",
                        })

        # Generate prioritized recommendations
        all_gaps = gaps["hipaa_gaps"] + gaps["pci_gaps"]
        for gap in sorted(all_gaps, key=lambda x: (
            0 if x.get("risk_level") == "critical" else
            1 if x.get("risk_level") == "high" else
            2 if x.get("status") == "failed" else 3
        ))[:10]:
            gaps["recommendations"].append({
                "control_id": gap["control_id"],
                "priority": "High" if gap.get("risk_level") in ("critical", "high") else "Medium",
                "action": f"Remediate {gap['control_title']}",
            })

        return gaps
