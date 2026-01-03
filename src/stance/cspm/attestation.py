"""
Compliance Attestation Engine for Mantissa Stance.

Provides automated compliance attestation generation, evidence
collection, and audit support documentation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import hashlib
import json


class AttestationType(Enum):
    """Types of compliance attestations."""

    SOC2_TYPE1 = "SOC 2 Type I"
    SOC2_TYPE2 = "SOC 2 Type II"
    PCI_DSS_AOC = "PCI DSS AOC"
    PCI_DSS_ROC = "PCI DSS ROC"
    PCI_DSS_SAQ = "PCI DSS SAQ"
    HIPAA_BAA = "HIPAA BAA"
    ISO27001 = "ISO 27001"
    CIS_BENCHMARK = "CIS Benchmark"
    CUSTOM = "Custom"


class AttestationScope(Enum):
    """Scope of attestation coverage."""

    FULL = "Full Organization"
    PARTIAL = "Partial Coverage"
    SYSTEM = "Specific System"
    SERVICE = "Specific Service"
    PRODUCT = "Specific Product"


class EvidenceType(Enum):
    """Types of compliance evidence."""

    POLICY = "Policy Document"
    PROCEDURE = "Procedure Document"
    SCREENSHOT = "Screenshot"
    LOG = "System Log"
    CONFIGURATION = "Configuration Export"
    SCAN_RESULT = "Security Scan Result"
    ASSESSMENT = "Assessment Report"
    CERTIFICATE = "Certificate"
    TRAINING_RECORD = "Training Record"
    AUDIT_REPORT = "Audit Report"
    CONTRACT = "Contract/Agreement"
    ATTESTATION = "Third-Party Attestation"


class EvidenceStatus(Enum):
    """Status of evidence collection."""

    COLLECTED = "Collected"
    PENDING = "Pending"
    EXPIRED = "Expired"
    INSUFFICIENT = "Insufficient"
    NOT_APPLICABLE = "Not Applicable"


@dataclass
class AttestationEvidence:
    """Evidence item for compliance attestation."""

    id: str
    evidence_type: EvidenceType
    title: str
    description: str
    control_ids: list[str]  # Related control IDs
    collected_at: datetime
    expires_at: datetime | None = None
    status: EvidenceStatus = EvidenceStatus.COLLECTED
    source: str = ""  # Where evidence was collected from
    file_path: str | None = None
    file_hash: str | None = None  # SHA-256 hash for integrity
    metadata: dict[str, Any] = field(default_factory=dict)
    collector: str = ""  # Who collected the evidence
    reviewer: str = ""  # Who reviewed the evidence
    reviewed_at: datetime | None = None

    @property
    def is_expired(self) -> bool:
        """Check if evidence has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if evidence is valid."""
        return (
            self.status == EvidenceStatus.COLLECTED
            and not self.is_expired
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.value,
            "title": self.title,
            "description": self.description,
            "control_ids": self.control_ids,
            "collected_at": self.collected_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status.value,
            "source": self.source,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "metadata": self.metadata,
            "collector": self.collector,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "is_valid": self.is_valid,
        }


@dataclass
class AttestationSection:
    """Section of an attestation document."""

    id: str
    title: str
    description: str
    control_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    compliance_status: str = "compliant"
    findings: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class ComplianceAttestation:
    """Complete compliance attestation document."""

    id: str
    attestation_type: AttestationType
    title: str
    organization_name: str
    scope: AttestationScope
    system_description: str
    period_start: datetime
    period_end: datetime
    issued_at: datetime
    expires_at: datetime | None = None
    sections: list[AttestationSection] = field(default_factory=list)
    evidence_items: list[AttestationEvidence] = field(default_factory=list)
    overall_status: str = "compliant"  # compliant, qualified, adverse
    exceptions: list[dict[str, Any]] = field(default_factory=list)
    auditor_name: str = ""
    auditor_organization: str = ""
    management_assertion: str = ""
    signature_hash: str | None = None

    @property
    def is_valid(self) -> bool:
        """Check if attestation is currently valid."""
        now = datetime.now(timezone.utc)
        if self.expires_at and now > self.expires_at:
            return False
        return self.overall_status == "compliant"

    @property
    def evidence_coverage(self) -> float:
        """Calculate evidence coverage percentage."""
        if not self.evidence_items:
            return 0.0
        valid_evidence = sum(1 for e in self.evidence_items if e.is_valid)
        return (valid_evidence / len(self.evidence_items)) * 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "attestation_type": self.attestation_type.value,
            "title": self.title,
            "organization_name": self.organization_name,
            "scope": self.scope.value,
            "system_description": self.system_description,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "overall_status": self.overall_status,
            "evidence_coverage": round(self.evidence_coverage, 2),
            "is_valid": self.is_valid,
            "sections": [
                {
                    "id": s.id,
                    "title": s.title,
                    "description": s.description,
                    "control_ids": s.control_ids,
                    "evidence_ids": s.evidence_ids,
                    "compliance_status": s.compliance_status,
                    "findings": s.findings,
                    "notes": s.notes,
                }
                for s in self.sections
            ],
            "evidence_items": [e.to_dict() for e in self.evidence_items],
            "exceptions": self.exceptions,
            "auditor_name": self.auditor_name,
            "auditor_organization": self.auditor_organization,
            "management_assertion": self.management_assertion,
            "signature_hash": self.signature_hash,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class AttestationEngine:
    """
    Compliance attestation engine.

    Generates automated compliance attestations with evidence
    collection and audit documentation support.
    """

    def __init__(self) -> None:
        """Initialize the attestation engine."""
        self._evidence_store: dict[str, AttestationEvidence] = {}
        self._attestation_store: dict[str, ComplianceAttestation] = {}
        self._evidence_counter = 0
        self._attestation_counter = 0

    def collect_evidence(
        self,
        evidence_type: EvidenceType,
        title: str,
        description: str,
        control_ids: list[str],
        source: str = "",
        file_path: str | None = None,
        content: bytes | None = None,
        validity_days: int = 365,
        collector: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AttestationEvidence:
        """
        Collect evidence for compliance attestation.

        Args:
            evidence_type: Type of evidence
            title: Evidence title
            description: Evidence description
            control_ids: Related control IDs
            source: Source of evidence
            file_path: Path to evidence file
            content: Content for hash calculation
            validity_days: Days until evidence expires
            collector: Who collected the evidence
            metadata: Additional metadata

        Returns:
            AttestationEvidence item
        """
        self._evidence_counter += 1
        evidence_id = f"EVD-{self._evidence_counter:06d}"

        now = datetime.now(timezone.utc)
        expires_at = None
        if validity_days > 0:
            from datetime import timedelta
            expires_at = now + timedelta(days=validity_days)

        # Calculate file hash if content provided
        file_hash = None
        if content:
            file_hash = hashlib.sha256(content).hexdigest()

        evidence = AttestationEvidence(
            id=evidence_id,
            evidence_type=evidence_type,
            title=title,
            description=description,
            control_ids=control_ids,
            collected_at=now,
            expires_at=expires_at,
            status=EvidenceStatus.COLLECTED,
            source=source,
            file_path=file_path,
            file_hash=file_hash,
            metadata=metadata or {},
            collector=collector,
        )

        self._evidence_store[evidence_id] = evidence
        return evidence

    def review_evidence(
        self,
        evidence_id: str,
        reviewer: str,
        approved: bool = True,
        notes: str = "",
    ) -> AttestationEvidence:
        """
        Review and approve/reject evidence.

        Args:
            evidence_id: Evidence ID to review
            reviewer: Reviewer name
            approved: Whether evidence is approved
            notes: Review notes

        Returns:
            Updated AttestationEvidence
        """
        if evidence_id not in self._evidence_store:
            raise ValueError(f"Evidence not found: {evidence_id}")

        evidence = self._evidence_store[evidence_id]
        evidence.reviewer = reviewer
        evidence.reviewed_at = datetime.now(timezone.utc)

        if approved:
            evidence.status = EvidenceStatus.COLLECTED
        else:
            evidence.status = EvidenceStatus.INSUFFICIENT
            if notes:
                evidence.metadata["rejection_reason"] = notes

        return evidence

    def get_evidence(self, evidence_id: str) -> AttestationEvidence | None:
        """Get evidence by ID."""
        return self._evidence_store.get(evidence_id)

    def get_evidence_for_control(self, control_id: str) -> list[AttestationEvidence]:
        """Get all evidence for a control."""
        return [
            e for e in self._evidence_store.values()
            if control_id in e.control_ids
        ]

    def get_expiring_evidence(self, days: int = 30) -> list[AttestationEvidence]:
        """Get evidence expiring within specified days."""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) + timedelta(days=days)

        return [
            e for e in self._evidence_store.values()
            if e.expires_at and e.expires_at <= cutoff
        ]

    def generate_attestation(
        self,
        attestation_type: AttestationType,
        organization_name: str,
        system_description: str,
        scope: AttestationScope = AttestationScope.FULL,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
        assessment_result: Any = None,  # CIS/SOC2/HIPAA/PCI assessment
        evidence_ids: list[str] | None = None,
        management_assertion: str = "",
        auditor_name: str = "",
        auditor_organization: str = "",
    ) -> ComplianceAttestation:
        """
        Generate a compliance attestation.

        Args:
            attestation_type: Type of attestation
            organization_name: Organization name
            system_description: Description of system in scope
            scope: Scope of attestation
            period_start: Assessment period start
            period_end: Assessment period end
            assessment_result: Assessment result object
            evidence_ids: Evidence IDs to include
            management_assertion: Management assertion statement
            auditor_name: Auditor name
            auditor_organization: Auditor organization

        Returns:
            ComplianceAttestation document
        """
        self._attestation_counter += 1
        attestation_id = f"ATT-{self._attestation_counter:06d}"

        now = datetime.now(timezone.utc)
        if period_start is None:
            from datetime import timedelta
            period_start = now - timedelta(days=365)
        if period_end is None:
            period_end = now

        # Collect evidence items
        evidence_items = []
        if evidence_ids:
            for eid in evidence_ids:
                evidence = self.get_evidence(eid)
                if evidence:
                    evidence_items.append(evidence)

        # Generate sections based on attestation type
        sections = self._generate_sections(attestation_type, assessment_result)

        # Determine overall status
        overall_status = self._determine_status(assessment_result)

        # Generate management assertion if not provided
        if not management_assertion:
            management_assertion = self._generate_management_assertion(
                attestation_type, organization_name, scope
            )

        attestation = ComplianceAttestation(
            id=attestation_id,
            attestation_type=attestation_type,
            title=f"{attestation_type.value} Attestation - {organization_name}",
            organization_name=organization_name,
            scope=scope,
            system_description=system_description,
            period_start=period_start,
            period_end=period_end,
            issued_at=now,
            expires_at=self._calculate_expiration(attestation_type, now),
            sections=sections,
            evidence_items=evidence_items,
            overall_status=overall_status,
            exceptions=self._extract_exceptions(assessment_result),
            auditor_name=auditor_name,
            auditor_organization=auditor_organization,
            management_assertion=management_assertion,
        )

        # Generate signature hash
        attestation.signature_hash = self._generate_signature_hash(attestation)

        self._attestation_store[attestation_id] = attestation
        return attestation

    def _generate_sections(
        self,
        attestation_type: AttestationType,
        assessment_result: Any,
    ) -> list[AttestationSection]:
        """Generate attestation sections based on type."""
        sections = []

        if attestation_type in (AttestationType.SOC2_TYPE1, AttestationType.SOC2_TYPE2):
            sections = [
                AttestationSection(
                    id="section1",
                    title="Independent Service Auditor's Report",
                    description="Opinion on management's description and control design/operation",
                ),
                AttestationSection(
                    id="section2",
                    title="Management's Assertion",
                    description="Management's assertion regarding system description and controls",
                ),
                AttestationSection(
                    id="section3",
                    title="Description of System",
                    description="Description of the service organization's system",
                ),
                AttestationSection(
                    id="section4",
                    title="Trust Services Criteria and Related Controls",
                    description="Controls mapped to applicable Trust Services Criteria",
                ),
            ]

            if attestation_type == AttestationType.SOC2_TYPE2:
                sections.append(
                    AttestationSection(
                        id="section5",
                        title="Tests of Controls and Results",
                        description="Description of tests performed and results",
                    )
                )

        elif attestation_type == AttestationType.PCI_DSS_AOC:
            sections = [
                AttestationSection(
                    id="section1",
                    title="Merchant/Service Provider Information",
                    description="Information about the assessed entity",
                ),
                AttestationSection(
                    id="section2",
                    title="Executive Summary",
                    description="Summary of assessment results",
                ),
                AttestationSection(
                    id="section3",
                    title="Scope of Assessment",
                    description="Description of the cardholder data environment",
                ),
                AttestationSection(
                    id="section4",
                    title="Findings and Observations",
                    description="Detailed findings from the assessment",
                ),
            ]

        elif attestation_type == AttestationType.HIPAA_BAA:
            sections = [
                AttestationSection(
                    id="section1",
                    title="Covered Entity Information",
                    description="Information about the covered entity",
                ),
                AttestationSection(
                    id="section2",
                    title="Security Rule Compliance",
                    description="Assessment of Security Rule safeguards",
                ),
                AttestationSection(
                    id="section3",
                    title="Risk Assessment Summary",
                    description="Summary of risk analysis results",
                ),
                AttestationSection(
                    id="section4",
                    title="Breach Notification Procedures",
                    description="Description of breach notification procedures",
                ),
            ]

        elif attestation_type == AttestationType.CIS_BENCHMARK:
            sections = [
                AttestationSection(
                    id="section1",
                    title="Assessment Summary",
                    description="Summary of CIS benchmark assessment",
                ),
                AttestationSection(
                    id="section2",
                    title="Profile and Scope",
                    description="Description of benchmark profile and assessment scope",
                ),
                AttestationSection(
                    id="section3",
                    title="Control Results",
                    description="Detailed results for each control section",
                ),
                AttestationSection(
                    id="section4",
                    title="Remediation Recommendations",
                    description="Recommendations for addressing findings",
                ),
            ]

        return sections

    def _determine_status(self, assessment_result: Any) -> str:
        """Determine overall attestation status from assessment."""
        if assessment_result is None:
            return "qualified"

        # Check for overall compliance percentage
        if hasattr(assessment_result, "overall_compliance"):
            compliance = assessment_result.overall_compliance
            if compliance >= 95:
                return "compliant"
            elif compliance >= 80:
                return "qualified"
            else:
                return "adverse"

        if hasattr(assessment_result, "overall_score"):
            score = assessment_result.overall_score
            if score >= 95:
                return "compliant"
            elif score >= 80:
                return "qualified"
            else:
                return "adverse"

        return "qualified"

    def _calculate_expiration(
        self,
        attestation_type: AttestationType,
        issued_at: datetime,
    ) -> datetime:
        """Calculate attestation expiration date."""
        from datetime import timedelta

        # Default expiration periods
        expiration_days = {
            AttestationType.SOC2_TYPE1: 365,
            AttestationType.SOC2_TYPE2: 365,
            AttestationType.PCI_DSS_AOC: 365,
            AttestationType.PCI_DSS_ROC: 365,
            AttestationType.PCI_DSS_SAQ: 365,
            AttestationType.HIPAA_BAA: 365,
            AttestationType.ISO27001: 365 * 3,
            AttestationType.CIS_BENCHMARK: 90,
            AttestationType.CUSTOM: 365,
        }

        days = expiration_days.get(attestation_type, 365)
        return issued_at + timedelta(days=days)

    def _generate_management_assertion(
        self,
        attestation_type: AttestationType,
        organization_name: str,
        scope: AttestationScope,
    ) -> str:
        """Generate standard management assertion."""
        assertions = {
            AttestationType.SOC2_TYPE1: (
                f"{organization_name} asserts that the accompanying description of "
                f"the system fairly presents the {organization_name} system that was "
                f"designed and implemented throughout the specified period. The controls "
                f"stated in the description were suitably designed to provide reasonable "
                f"assurance that the service commitments and system requirements were "
                f"achieved based on the applicable trust services criteria."
            ),
            AttestationType.SOC2_TYPE2: (
                f"{organization_name} asserts that the accompanying description of "
                f"the system fairly presents the {organization_name} system that was "
                f"designed, implemented, and operated throughout the specified period. "
                f"The controls stated in the description were suitably designed and "
                f"operated effectively to provide reasonable assurance that the service "
                f"commitments and system requirements were achieved."
            ),
            AttestationType.PCI_DSS_AOC: (
                f"{organization_name} confirms that the assessment covered all "
                f"systems and processes that store, process, or transmit cardholder "
                f"data and/or sensitive authentication data, as well as systems that "
                f"are connected to or could impact the security of cardholder data."
            ),
            AttestationType.HIPAA_BAA: (
                f"{organization_name} confirms that appropriate administrative, "
                f"physical, and technical safeguards have been implemented to ensure "
                f"the confidentiality, integrity, and availability of electronic "
                f"protected health information (ePHI) in accordance with the HIPAA "
                f"Security Rule."
            ),
        }

        return assertions.get(
            attestation_type,
            f"{organization_name} asserts compliance with applicable requirements.",
        )

    def _extract_exceptions(self, assessment_result: Any) -> list[dict[str, Any]]:
        """Extract exceptions from assessment result."""
        exceptions = []

        if assessment_result is None:
            return exceptions

        if hasattr(assessment_result, "exceptions"):
            return assessment_result.exceptions

        # Extract from failing controls
        if hasattr(assessment_result, "controls_failed"):
            if assessment_result.controls_failed > 0:
                exceptions.append({
                    "type": "control_failure",
                    "count": assessment_result.controls_failed,
                    "description": f"{assessment_result.controls_failed} controls did not meet requirements",
                })

        return exceptions

    def _generate_signature_hash(self, attestation: ComplianceAttestation) -> str:
        """Generate signature hash for attestation integrity."""
        content = json.dumps({
            "id": attestation.id,
            "type": attestation.attestation_type.value,
            "organization": attestation.organization_name,
            "period_start": attestation.period_start.isoformat(),
            "period_end": attestation.period_end.isoformat(),
            "status": attestation.overall_status,
        }, sort_keys=True)

        return hashlib.sha256(content.encode()).hexdigest()

    def get_attestation(self, attestation_id: str) -> ComplianceAttestation | None:
        """Get attestation by ID."""
        return self._attestation_store.get(attestation_id)

    def get_valid_attestations(
        self,
        organization_name: str | None = None,
        attestation_type: AttestationType | None = None,
    ) -> list[ComplianceAttestation]:
        """Get all valid attestations."""
        attestations = list(self._attestation_store.values())

        if organization_name:
            attestations = [
                a for a in attestations
                if a.organization_name == organization_name
            ]

        if attestation_type:
            attestations = [
                a for a in attestations
                if a.attestation_type == attestation_type
            ]

        return [a for a in attestations if a.is_valid]

    def get_expiring_attestations(
        self, days: int = 30
    ) -> list[ComplianceAttestation]:
        """Get attestations expiring within specified days."""
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) + timedelta(days=days)

        return [
            a for a in self._attestation_store.values()
            if a.expires_at and a.expires_at <= cutoff
        ]

    def generate_evidence_matrix(
        self,
        control_framework: str = "all",
    ) -> list[dict[str, Any]]:
        """Generate evidence matrix showing control-to-evidence mapping."""
        matrix = []

        # Group evidence by control
        control_evidence: dict[str, list[AttestationEvidence]] = {}
        for evidence in self._evidence_store.values():
            for control_id in evidence.control_ids:
                if control_id not in control_evidence:
                    control_evidence[control_id] = []
                control_evidence[control_id].append(evidence)

        for control_id, evidence_list in sorted(control_evidence.items()):
            valid_evidence = [e for e in evidence_list if e.is_valid]
            matrix.append({
                "control_id": control_id,
                "total_evidence": len(evidence_list),
                "valid_evidence": len(valid_evidence),
                "evidence_types": list(set(e.evidence_type.value for e in evidence_list)),
                "coverage_status": "covered" if valid_evidence else "gap",
            })

        return matrix

    def export_audit_package(
        self,
        attestation_id: str,
        include_evidence: bool = True,
    ) -> dict[str, Any]:
        """Export complete audit package for an attestation."""
        attestation = self.get_attestation(attestation_id)
        if not attestation:
            raise ValueError(f"Attestation not found: {attestation_id}")

        package = {
            "attestation": attestation.to_dict(),
            "evidence_summary": [],
            "control_coverage": {},
            "export_metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "package_hash": "",
            },
        }

        if include_evidence:
            for evidence in attestation.evidence_items:
                package["evidence_summary"].append({
                    "id": evidence.id,
                    "type": evidence.evidence_type.value,
                    "title": evidence.title,
                    "controls": evidence.control_ids,
                    "status": evidence.status.value,
                    "collected_at": evidence.collected_at.isoformat(),
                })

        # Generate package hash
        package_content = json.dumps(package, sort_keys=True)
        package["export_metadata"]["package_hash"] = hashlib.sha256(
            package_content.encode()
        ).hexdigest()

        return package
