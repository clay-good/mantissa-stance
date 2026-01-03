"""
Unit tests for CSPM Benchmark Automation module.

Tests CIS Benchmark automation, SOC 2 compliance mapping,
HIPAA/PCI-DSS control validation, attestation engine,
and continuous compliance monitoring.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from stance.cspm.cis_benchmark import (
    BenchmarkType,
    CISAssessmentResult,
    CISBenchmark,
    CISBenchmarkScanner,
    CISControl,
    CISProfile,
    CISSection,
    ControlAssessment,
    ControlStatus,
    SectionAssessment,
)
from stance.cspm.soc2_compliance import (
    ControlTestStatus,
    CriteriaAssessment,
    PrincipleAssessment,
    SOC2Assessment,
    SOC2Category,
    SOC2ComplianceMapper,
    SOC2Criteria,
    TrustServicesPrinciple,
)
from stance.cspm.regulatory_controls import (
    ControlRequirement,
    HIPAAAssessment,
    HIPAAControl,
    HIPAARule,
    HIPAASafeguard,
    PCIDSSAssessment,
    PCIDSSControl,
    PCIDSSRequirement,
    RegulatoryControlValidator,
    RegulatoryFramework,
    ValidationStatus,
)
from stance.cspm.attestation import (
    AttestationEngine,
    AttestationEvidence,
    AttestationScope,
    AttestationType,
    ComplianceAttestation,
    EvidenceStatus,
    EvidenceType,
)
from stance.cspm.continuous_monitoring import (
    AlertSeverity,
    ComplianceAlert,
    ComplianceBaseline,
    ComplianceDrift,
    ComplianceSnapshot,
    ComplianceState,
    ContinuousComplianceMonitor,
    DriftType,
    MonitoringThreshold,
)


# ============================================================================
# CIS Benchmark Tests
# ============================================================================


class TestCISControl:
    """Tests for CISControl dataclass."""

    def test_control_creation(self):
        """Test creating a CIS control."""
        control = CISControl(
            id="1.1",
            title="Test Control",
            description="Test description",
            rationale="Test rationale",
            profile=CISProfile.LEVEL_1,
            section_id="1",
            automated=True,
            scored=True,
            resource_types=["aws_iam_user"],
        )

        assert control.id == "1.1"
        assert control.title == "Test Control"
        assert control.profile == CISProfile.LEVEL_1
        assert control.automated is True
        assert control.scored is True
        assert "aws_iam_user" in control.resource_types

    def test_control_to_dict(self):
        """Test converting control to dictionary."""
        control = CISControl(
            id="1.2",
            title="Security Contact",
            description="Ensure security contact info",
            rationale="For incident response",
            profile=CISProfile.LEVEL_1,
            section_id="1",
        )

        data = control.to_dict()
        assert data["id"] == "1.2"
        assert data["profile"] == "Level 1"
        assert data["automated"] is True


class TestCISSection:
    """Tests for CISSection dataclass."""

    def test_section_counts(self):
        """Test section control counting."""
        controls = [
            CISControl(
                id="1.1", title="C1", description="D1", rationale="R1",
                profile=CISProfile.LEVEL_1, section_id="1", automated=True, scored=True
            ),
            CISControl(
                id="1.2", title="C2", description="D2", rationale="R2",
                profile=CISProfile.LEVEL_1, section_id="1", automated=False, scored=True
            ),
            CISControl(
                id="1.3", title="C3", description="D3", rationale="R3",
                profile=CISProfile.LEVEL_2, section_id="1", automated=True, scored=False
            ),
        ]

        section = CISSection(
            id="1",
            title="Test Section",
            description="Test description",
            controls=controls,
        )

        assert section.control_count == 3
        assert section.automated_count == 2
        assert section.scored_count == 2


class TestCISBenchmark:
    """Tests for CISBenchmark dataclass."""

    def test_benchmark_totals(self):
        """Test benchmark control totals."""
        section1 = CISSection(
            id="1", title="S1", description="D1",
            controls=[
                CISControl(id="1.1", title="C1", description="D1", rationale="R1",
                          profile=CISProfile.LEVEL_1, section_id="1", automated=True, scored=True),
                CISControl(id="1.2", title="C2", description="D2", rationale="R2",
                          profile=CISProfile.LEVEL_1, section_id="1", automated=True, scored=True),
            ]
        )
        section2 = CISSection(
            id="2", title="S2", description="D2",
            controls=[
                CISControl(id="2.1", title="C3", description="D3", rationale="R3",
                          profile=CISProfile.LEVEL_2, section_id="2", automated=False, scored=True),
            ]
        )

        benchmark = CISBenchmark(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            version="1.5.0",
            release_date="2022-08-16",
            title="Test Benchmark",
            description="Test description",
            sections=[section1, section2],
        )

        assert benchmark.total_controls == 3
        assert benchmark.automated_controls == 2
        assert benchmark.scored_controls == 3

    def test_get_control(self):
        """Test finding a control by ID."""
        control = CISControl(
            id="1.4", title="Root Access Keys", description="No root keys",
            rationale="Security", profile=CISProfile.LEVEL_1, section_id="1"
        )
        section = CISSection(id="1", title="S1", description="D1", controls=[control])
        benchmark = CISBenchmark(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            version="1.5.0",
            release_date="2022-08-16",
            title="Test",
            description="Test",
            sections=[section],
        )

        found = benchmark.get_control("1.4")
        assert found is not None
        assert found.title == "Root Access Keys"

        not_found = benchmark.get_control("99.99")
        assert not_found is None

    def test_get_controls_by_profile(self):
        """Test filtering controls by profile."""
        controls = [
            CISControl(id="1.1", title="C1", description="D1", rationale="R1",
                      profile=CISProfile.LEVEL_1, section_id="1"),
            CISControl(id="1.2", title="C2", description="D2", rationale="R2",
                      profile=CISProfile.LEVEL_2, section_id="1"),
        ]
        section = CISSection(id="1", title="S1", description="D1", controls=controls)
        benchmark = CISBenchmark(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            version="1.5.0",
            release_date="2022-08-16",
            title="Test",
            description="Test",
            sections=[section],
        )

        level1_controls = benchmark.get_controls_by_profile(CISProfile.LEVEL_1)
        assert len(level1_controls) == 1
        assert level1_controls[0].id == "1.1"

        level2_controls = benchmark.get_controls_by_profile(CISProfile.LEVEL_2)
        assert len(level2_controls) == 2  # Level 2 includes Level 1


class TestCISAssessmentResult:
    """Tests for CISAssessmentResult."""

    def test_assessment_metrics(self):
        """Test assessment metric calculations."""
        control_assessments = [
            ControlAssessment(control_id="1.1", control_title="C1", status=ControlStatus.PASS),
            ControlAssessment(control_id="1.2", control_title="C2", status=ControlStatus.FAIL),
            ControlAssessment(control_id="1.3", control_title="C3", status=ControlStatus.MANUAL),
            ControlAssessment(control_id="1.4", control_title="C4", status=ControlStatus.PASS),
        ]
        section = SectionAssessment(
            section_id="1",
            section_title="Section 1",
            control_assessments=control_assessments,
        )

        result = CISAssessmentResult(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            benchmark_version="1.5.0",
            profile=CISProfile.LEVEL_1,
            assessed_at=datetime.now(timezone.utc),
            account_id="123456789012",
            region="us-east-1",
            section_assessments=[section],
        )

        assert result.total_controls == 4
        assert result.controls_passed == 2
        assert result.controls_failed == 1
        assert result.controls_manual == 1

    def test_overall_score_calculation(self):
        """Test overall score calculation."""
        assessments = [
            ControlAssessment(control_id="1.1", control_title="C1", status=ControlStatus.PASS),
            ControlAssessment(control_id="1.2", control_title="C2", status=ControlStatus.PASS),
            ControlAssessment(control_id="1.3", control_title="C3", status=ControlStatus.FAIL),
            ControlAssessment(control_id="1.4", control_title="C4", status=ControlStatus.NOT_APPLICABLE),
        ]
        section = SectionAssessment(
            section_id="1", section_title="Section 1", control_assessments=assessments
        )

        result = CISAssessmentResult(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            benchmark_version="1.5.0",
            profile=CISProfile.LEVEL_1,
            assessed_at=datetime.now(timezone.utc),
            account_id="123456789012",
            region=None,
            section_assessments=[section],
        )

        # 2 pass out of 3 applicable (excluding N/A) = 66.67%
        assert 66 < result.overall_score < 67

    def test_grade_assignment(self):
        """Test letter grade assignment."""
        # Create result with 95% score
        assessments = [
            ControlAssessment(control_id=f"1.{i}", control_title=f"C{i}", status=ControlStatus.PASS)
            for i in range(19)
        ]
        assessments.append(
            ControlAssessment(control_id="1.20", control_title="C20", status=ControlStatus.FAIL)
        )
        section = SectionAssessment(
            section_id="1", section_title="Section 1", control_assessments=assessments
        )

        result = CISAssessmentResult(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            benchmark_version="1.5.0",
            profile=CISProfile.LEVEL_1,
            assessed_at=datetime.now(timezone.utc),
            account_id="123456789012",
            region=None,
            section_assessments=[section],
        )

        assert result.grade == "A"  # 95% = A


class TestCISBenchmarkScanner:
    """Tests for CISBenchmarkScanner."""

    def test_scanner_initialization(self):
        """Test scanner initializes with benchmarks."""
        scanner = CISBenchmarkScanner()

        assert BenchmarkType.AWS_FOUNDATIONS in scanner.BENCHMARKS
        assert BenchmarkType.AZURE_FOUNDATIONS in scanner.BENCHMARKS
        assert BenchmarkType.KUBERNETES in scanner.BENCHMARKS

    def test_list_benchmarks(self):
        """Test listing available benchmarks."""
        scanner = CISBenchmarkScanner()
        benchmarks = scanner.list_benchmarks()

        assert len(benchmarks) >= 5
        aws_benchmark = next(
            (b for b in benchmarks if b["type"] == "cis-aws-foundations"),
            None
        )
        assert aws_benchmark is not None
        assert aws_benchmark["version"] == "1.5.0"

    def test_get_benchmark(self):
        """Test getting a specific benchmark."""
        scanner = CISBenchmarkScanner()
        benchmark = scanner.get_benchmark(BenchmarkType.AWS_FOUNDATIONS)

        assert benchmark is not None
        assert benchmark.version == "1.5.0"
        assert benchmark.total_controls > 0

    def test_scan_with_resources(self):
        """Test scanning resources against benchmark."""
        scanner = CISBenchmarkScanner()

        # Create mock resources
        resources = [
            MagicMock(
                resource_type="aws_iam_account_summary",
                data={"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
            ),
            MagicMock(
                resource_type="aws_iam_account_password_policy",
                data={"MinimumPasswordLength": 14}
            ),
        ]

        result = scanner.scan(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            resources=resources,
            profile=CISProfile.LEVEL_1,
            account_id="123456789012",
        )

        assert result.benchmark_type == BenchmarkType.AWS_FOUNDATIONS
        assert result.account_id == "123456789012"
        assert len(result.section_assessments) > 0

    def test_root_mfa_check(self):
        """Test root MFA check function."""
        scanner = CISBenchmarkScanner()

        # MFA enabled
        resources_mfa = [
            MagicMock(
                resource_type="aws_iam_account_summary",
                data={"AccountMFAEnabled": 1}
            )
        ]

        control = scanner.get_benchmark(BenchmarkType.AWS_FOUNDATIONS).get_control("1.5")
        result = scanner._check_root_mfa(control, resources_mfa)

        assert result.status == ControlStatus.PASS

        # MFA disabled
        resources_no_mfa = [
            MagicMock(
                resource_type="aws_iam_account_summary",
                data={"AccountMFAEnabled": 0}
            )
        ]

        result = scanner._check_root_mfa(control, resources_no_mfa)
        assert result.status == ControlStatus.FAIL

    def test_s3_encryption_check(self):
        """Test S3 encryption check."""
        scanner = CISBenchmarkScanner()

        # Encrypted bucket
        resources_encrypted = [
            MagicMock(
                resource_type="aws_s3_bucket",
                data={
                    "Name": "test-bucket",
                    "ServerSideEncryptionConfiguration": {"Rules": []}
                }
            )
        ]

        control = scanner.get_benchmark(BenchmarkType.AWS_FOUNDATIONS).get_control("2.1.4")
        result = scanner._check_s3_encryption(control, resources_encrypted)

        assert result.status == ControlStatus.PASS

        # Unencrypted bucket
        resources_unencrypted = [
            MagicMock(
                resource_type="aws_s3_bucket",
                data={"Name": "test-bucket", "ServerSideEncryptionConfiguration": None}
            )
        ]

        result = scanner._check_s3_encryption(control, resources_unencrypted)
        assert result.status == ControlStatus.FAIL

    def test_generate_report(self):
        """Test report generation."""
        scanner = CISBenchmarkScanner()

        assessments = [
            ControlAssessment(
                control_id="1.1", control_title="Test Control",
                status=ControlStatus.PASS,
                resources_evaluated=10, resources_compliant=10, resources_non_compliant=0
            ),
        ]
        section = SectionAssessment(
            section_id="1", section_title="Test Section", control_assessments=assessments
        )

        result = CISAssessmentResult(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            benchmark_version="1.5.0",
            profile=CISProfile.LEVEL_1,
            assessed_at=datetime.now(timezone.utc),
            account_id="123456789012",
            region="us-east-1",
            section_assessments=[section],
        )

        report_json = scanner.generate_report(result, format="json")
        data = json.loads(report_json)
        assert data["benchmark_type"] == "cis-aws-foundations"

        report_text = scanner.generate_report(result, format="text")
        assert "CIS Benchmark Assessment Report" in report_text


# ============================================================================
# SOC 2 Compliance Tests
# ============================================================================


class TestSOC2Criteria:
    """Tests for SOC2Criteria."""

    def test_criteria_creation(self):
        """Test creating SOC 2 criteria."""
        criteria = SOC2Criteria(
            id="CC1.1",
            category=SOC2Category.CC1,
            title="Integrity and Ethics",
            description="Demonstrates commitment to integrity",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=["Sets Tone at Top", "Standards of Conduct"],
        )

        assert criteria.id == "CC1.1"
        assert criteria.category == SOC2Category.CC1
        assert criteria.principle == TrustServicesPrinciple.SECURITY
        assert len(criteria.points_of_focus) == 2


class TestSOC2ComplianceMapper:
    """Tests for SOC2ComplianceMapper."""

    def test_mapper_initialization(self):
        """Test mapper initializes with criteria catalog."""
        mapper = SOC2ComplianceMapper()

        assert len(mapper.CRITERIA_CATALOG) > 0
        assert "CC1.1" in mapper.CRITERIA_CATALOG
        assert "CC6.1" in mapper.CRITERIA_CATALOG

    def test_get_criteria(self):
        """Test getting criteria by ID."""
        mapper = SOC2ComplianceMapper()

        criteria = mapper.get_criteria("CC6.1")
        assert criteria is not None
        assert criteria.title == "Implements Logical Access Security Software"

        not_found = mapper.get_criteria("XX99.99")
        assert not_found is None

    def test_get_criteria_by_category(self):
        """Test getting criteria by category."""
        mapper = SOC2ComplianceMapper()

        cc6_criteria = mapper.get_criteria_by_category(SOC2Category.CC6)
        assert len(cc6_criteria) > 0
        assert all(c.category == SOC2Category.CC6 for c in cc6_criteria)

    def test_get_criteria_by_principle(self):
        """Test getting criteria by principle."""
        mapper = SOC2ComplianceMapper()

        security_criteria = mapper.get_criteria_by_principle(TrustServicesPrinciple.SECURITY)
        assert len(security_criteria) > 0
        assert all(c.principle == TrustServicesPrinciple.SECURITY for c in security_criteria)

    def test_policy_mapping(self):
        """Test policy to criteria mapping."""
        mapper = SOC2ComplianceMapper()

        mapper.map_policy_to_criteria("aws-iam-mfa", ["CC6.1", "CC6.2"])
        mapper.map_policy_to_criteria("aws-s3-encryption", ["CC6.1"])

        policies = mapper.get_policies_for_criteria("CC6.1")
        assert "aws-iam-mfa" in policies
        assert "aws-s3-encryption" in policies

    def test_assess_soc2(self):
        """Test SOC 2 assessment."""
        mapper = SOC2ComplianceMapper()

        # Mock policies and findings
        policies = [
            MagicMock(id="iam-mfa-enabled", tags=["iam-mfa-enabled"]),
        ]
        findings = []  # No findings = compliant

        assessment = mapper.assess(
            policies=policies,
            findings=findings,
            principles_in_scope=[TrustServicesPrinciple.SECURITY],
            organization_name="Test Org",
        )

        assert isinstance(assessment, SOC2Assessment)
        assert assessment.organization_name == "Test Org"
        assert len(assessment.principle_assessments) == 1

    def test_generate_report(self):
        """Test SOC 2 report generation."""
        mapper = SOC2ComplianceMapper()

        assessment = SOC2Assessment(
            assessment_type="Type II",
            assessment_period_start=datetime.now(timezone.utc) - timedelta(days=365),
            assessment_period_end=datetime.now(timezone.utc),
            organization_name="Test Org",
            system_description="Test system",
            principles_in_scope=[TrustServicesPrinciple.SECURITY],
        )

        report = mapper.generate_report(assessment)
        assert "recommendations" in report
        assert "organization_name" in report

    def test_control_matrix(self):
        """Test control matrix generation."""
        mapper = SOC2ComplianceMapper()

        matrix = mapper.get_control_matrix([TrustServicesPrinciple.SECURITY])
        assert len(matrix) > 0
        assert all("criteria_id" in item for item in matrix)


# ============================================================================
# Regulatory Controls Tests
# ============================================================================


class TestHIPAAControl:
    """Tests for HIPAAControl."""

    def test_control_creation(self):
        """Test creating HIPAA control."""
        control = HIPAAControl(
            id="164.308(a)(1)(i)",
            section="164.308(a)(1)",
            title="Security Management Process",
            description="Implement security policies",
            safeguard=HIPAASafeguard.ADMINISTRATIVE,
            rule=HIPAARule.SECURITY,
            requirement=ControlRequirement.REQUIRED,
            phi_impact="Protects PHI access",
            risk_level="high",
        )

        assert control.id == "164.308(a)(1)(i)"
        assert control.safeguard == HIPAASafeguard.ADMINISTRATIVE
        assert control.requirement == ControlRequirement.REQUIRED
        assert control.risk_level == "high"


class TestPCIDSSControl:
    """Tests for PCIDSSControl."""

    def test_control_creation(self):
        """Test creating PCI-DSS control."""
        control = PCIDSSControl(
            id="1.2.1",
            requirement_id="1",
            title="NSC Configuration Standards",
            description="Configuration standards for NSC rulesets",
            testing_procedure="Examine configuration standards",
            guidance="Standards ensure consistency",
            version="4.0",
        )

        assert control.id == "1.2.1"
        assert control.requirement_id == "1"
        assert control.version == "4.0"


class TestRegulatoryControlValidator:
    """Tests for RegulatoryControlValidator."""

    def test_validator_initialization(self):
        """Test validator initializes with control catalogs."""
        validator = RegulatoryControlValidator()

        assert len(validator.HIPAA_CONTROLS) > 0
        assert len(validator.PCI_CONTROLS) > 0
        assert len(validator.PCI_REQUIREMENTS) > 0

    def test_get_hipaa_control(self):
        """Test getting HIPAA control."""
        validator = RegulatoryControlValidator()

        control = validator.get_hipaa_control("164.308(a)(1)(i)")
        assert control is not None
        assert control.title == "Security Management Process"

    def test_get_hipaa_controls_by_safeguard(self):
        """Test getting HIPAA controls by safeguard."""
        validator = RegulatoryControlValidator()

        admin_controls = validator.get_hipaa_controls_by_safeguard(HIPAASafeguard.ADMINISTRATIVE)
        assert len(admin_controls) > 0
        assert all(c.safeguard == HIPAASafeguard.ADMINISTRATIVE for c in admin_controls)

    def test_get_pci_control(self):
        """Test getting PCI-DSS control."""
        validator = RegulatoryControlValidator()

        control = validator.get_pci_control("3.4.1")
        assert control is not None
        assert "PAN" in control.title

    def test_get_pci_controls_by_requirement(self):
        """Test getting PCI-DSS controls by requirement."""
        validator = RegulatoryControlValidator()

        req1_controls = validator.get_pci_controls_by_requirement("1")
        assert len(req1_controls) > 0
        assert all(c.requirement_id == "1" for c in req1_controls)

    def test_validate_hipaa(self):
        """Test HIPAA validation."""
        validator = RegulatoryControlValidator()

        policies = []
        findings = []

        assessment = validator.validate_hipaa(
            policies=policies,
            findings=findings,
            organization_name="Test Hospital",
            covered_entity_type="healthcare provider",
        )

        assert isinstance(assessment, HIPAAAssessment)
        assert assessment.organization_name == "Test Hospital"
        assert len(assessment.safeguard_assessments) > 0

    def test_validate_pci_dss(self):
        """Test PCI-DSS validation."""
        validator = RegulatoryControlValidator()

        policies = []
        findings = []

        assessment = validator.validate_pci_dss(
            policies=policies,
            findings=findings,
            organization_name="Test Merchant",
            merchant_level=2,
        )

        assert isinstance(assessment, PCIDSSAssessment)
        assert assessment.merchant_level == 2
        assert len(assessment.requirement_assessments) > 0

    def test_hipaa_control_matrix(self):
        """Test HIPAA control matrix generation."""
        validator = RegulatoryControlValidator()

        matrix = validator.get_hipaa_control_matrix()
        assert len(matrix) > 0
        assert all("control_id" in item for item in matrix)
        assert all("safeguard" in item for item in matrix)

    def test_pci_control_matrix(self):
        """Test PCI-DSS control matrix generation."""
        validator = RegulatoryControlValidator()

        matrix = validator.get_pci_control_matrix()
        assert len(matrix) > 0
        assert all("control_id" in item for item in matrix)
        assert all("requirement_id" in item for item in matrix)

    def test_gap_analysis(self):
        """Test gap analysis generation."""
        validator = RegulatoryControlValidator()

        hipaa_assessment = validator.validate_hipaa([], [], "Test Org")
        pci_assessment = validator.validate_pci_dss([], [], "Test Org")

        gaps = validator.generate_gap_analysis(hipaa_assessment, pci_assessment)

        assert "summary" in gaps
        assert "hipaa_gaps" in gaps
        assert "pci_gaps" in gaps
        assert "recommendations" in gaps


# ============================================================================
# Attestation Tests
# ============================================================================


class TestAttestationEvidence:
    """Tests for AttestationEvidence."""

    def test_evidence_creation(self):
        """Test creating attestation evidence."""
        now = datetime.now(timezone.utc)
        evidence = AttestationEvidence(
            id="EVD-001",
            evidence_type=EvidenceType.POLICY,
            title="Security Policy",
            description="Information security policy document",
            control_ids=["CC1.1", "CC5.3"],
            collected_at=now,
            status=EvidenceStatus.COLLECTED,
            source="SharePoint",
        )

        assert evidence.id == "EVD-001"
        assert evidence.evidence_type == EvidenceType.POLICY
        assert len(evidence.control_ids) == 2
        assert evidence.is_valid is True

    def test_evidence_expiration(self):
        """Test evidence expiration check."""
        past = datetime.now(timezone.utc) - timedelta(days=30)
        expired_date = datetime.now(timezone.utc) - timedelta(days=1)

        evidence = AttestationEvidence(
            id="EVD-002",
            evidence_type=EvidenceType.SCAN_RESULT,
            title="Vulnerability Scan",
            description="Q4 vulnerability scan",
            control_ids=["CC7.1"],
            collected_at=past,
            expires_at=expired_date,
        )

        assert evidence.is_expired is True
        assert evidence.is_valid is False


class TestAttestationEngine:
    """Tests for AttestationEngine."""

    def test_collect_evidence(self):
        """Test evidence collection."""
        engine = AttestationEngine()

        evidence = engine.collect_evidence(
            evidence_type=EvidenceType.CONFIGURATION,
            title="Firewall Rules",
            description="Export of firewall configuration",
            control_ids=["CC6.6"],
            source="AWS Console",
            validity_days=90,
            collector="security-team",
        )

        assert evidence.id.startswith("EVD-")
        assert evidence.status == EvidenceStatus.COLLECTED
        assert evidence.expires_at is not None

    def test_review_evidence(self):
        """Test evidence review."""
        engine = AttestationEngine()

        evidence = engine.collect_evidence(
            evidence_type=EvidenceType.LOG,
            title="Audit Logs",
            description="CloudTrail logs",
            control_ids=["CC7.2"],
            source="S3",
        )

        reviewed = engine.review_evidence(
            evidence_id=evidence.id,
            reviewer="auditor@company.com",
            approved=True,
        )

        assert reviewed.reviewer == "auditor@company.com"
        assert reviewed.reviewed_at is not None

    def test_get_evidence_for_control(self):
        """Test getting evidence for a control."""
        engine = AttestationEngine()

        engine.collect_evidence(
            evidence_type=EvidenceType.POLICY,
            title="Access Policy",
            description="Access control policy",
            control_ids=["CC6.1", "CC6.2"],
            source="Confluence",
        )

        engine.collect_evidence(
            evidence_type=EvidenceType.SCREENSHOT,
            title="MFA Configuration",
            description="Screenshot of MFA settings",
            control_ids=["CC6.1"],
            source="AWS Console",
        )

        evidence = engine.get_evidence_for_control("CC6.1")
        assert len(evidence) == 2

    def test_generate_attestation(self):
        """Test attestation generation."""
        engine = AttestationEngine()

        # Collect some evidence
        evidence = engine.collect_evidence(
            evidence_type=EvidenceType.ASSESSMENT,
            title="SOC 2 Assessment",
            description="Annual SOC 2 assessment results",
            control_ids=["CC1.1", "CC2.1"],
            source="Auditor",
        )

        attestation = engine.generate_attestation(
            attestation_type=AttestationType.SOC2_TYPE2,
            organization_name="Test Corp",
            system_description="Cloud platform services",
            scope=AttestationScope.FULL,
            evidence_ids=[evidence.id],
            auditor_name="John Auditor",
            auditor_organization="Big4 Firm",
        )

        assert attestation.id.startswith("ATT-")
        assert attestation.attestation_type == AttestationType.SOC2_TYPE2
        assert attestation.organization_name == "Test Corp"
        assert len(attestation.sections) > 0
        assert attestation.signature_hash is not None

    def test_attestation_validity(self):
        """Test attestation validity check."""
        engine = AttestationEngine()

        attestation = engine.generate_attestation(
            attestation_type=AttestationType.CIS_BENCHMARK,
            organization_name="Test Corp",
            system_description="AWS Infrastructure",
        )

        assert attestation.is_valid is True  # Assuming qualified status

    def test_get_expiring_attestations(self):
        """Test getting expiring attestations."""
        engine = AttestationEngine()

        # Generate attestation (CIS has 90-day expiration)
        engine.generate_attestation(
            attestation_type=AttestationType.CIS_BENCHMARK,
            organization_name="Test Corp",
            system_description="AWS Infrastructure",
        )

        expiring = engine.get_expiring_attestations(days=100)
        assert len(expiring) == 1

    def test_export_audit_package(self):
        """Test audit package export."""
        engine = AttestationEngine()

        evidence = engine.collect_evidence(
            evidence_type=EvidenceType.AUDIT_REPORT,
            title="Internal Audit",
            description="Annual internal audit report",
            control_ids=["CC4.1"],
            source="Internal Audit",
        )

        attestation = engine.generate_attestation(
            attestation_type=AttestationType.SOC2_TYPE1,
            organization_name="Test Corp",
            system_description="Platform services",
            evidence_ids=[evidence.id],
        )

        package = engine.export_audit_package(attestation.id)

        assert "attestation" in package
        assert "evidence_summary" in package
        assert "export_metadata" in package
        assert package["export_metadata"]["package_hash"] is not None


# ============================================================================
# Continuous Monitoring Tests
# ============================================================================


class TestComplianceAlert:
    """Tests for ComplianceAlert."""

    def test_alert_creation(self):
        """Test creating compliance alert."""
        alert = ComplianceAlert(
            id="ALERT-001",
            alert_type=DriftType.CONTROL_FAILURE,
            severity=AlertSeverity.HIGH,
            title="Control Failure Detected",
            description="Control CC6.1 failed validation",
            framework="soc2",
            control_id="CC6.1",
        )

        assert alert.is_active is True
        assert alert.age_hours >= 0

    def test_alert_lifecycle(self):
        """Test alert resolution."""
        alert = ComplianceAlert(
            id="ALERT-002",
            alert_type=DriftType.SCORE_DECREASE,
            severity=AlertSeverity.MEDIUM,
            title="Score Decreased",
            description="Compliance score dropped by 5%",
            framework="cis-aws",
        )

        assert alert.is_active is True

        alert.resolved_at = datetime.now(timezone.utc)
        assert alert.is_active is False


class TestMonitoringThreshold:
    """Tests for MonitoringThreshold."""

    def test_threshold_below(self):
        """Test threshold evaluation for below comparison."""
        threshold = MonitoringThreshold(
            name="Score Threshold",
            metric="overall_score",
            warning_threshold=90.0,
            critical_threshold=80.0,
            comparison="below",
        )

        assert threshold.evaluate(95) is None
        assert threshold.evaluate(85) == AlertSeverity.HIGH
        assert threshold.evaluate(75) == AlertSeverity.CRITICAL

    def test_threshold_above(self):
        """Test threshold evaluation for above comparison."""
        threshold = MonitoringThreshold(
            name="Finding Count",
            metric="findings",
            warning_threshold=5,
            critical_threshold=10,
            comparison="above",
        )

        assert threshold.evaluate(3) is None
        assert threshold.evaluate(7) == AlertSeverity.HIGH
        assert threshold.evaluate(15) == AlertSeverity.CRITICAL

    def test_threshold_change(self):
        """Test threshold evaluation for change comparison."""
        threshold = MonitoringThreshold(
            name="Score Change",
            metric="score_change",
            warning_threshold=5.0,
            critical_threshold=10.0,
            comparison="change",
        )

        assert threshold.evaluate(90, 92) is None  # 2% change
        assert threshold.evaluate(85, 92) == AlertSeverity.HIGH  # 7% change
        assert threshold.evaluate(80, 92) == AlertSeverity.CRITICAL  # 12% change


class TestContinuousComplianceMonitor:
    """Tests for ContinuousComplianceMonitor."""

    def test_monitor_initialization(self):
        """Test monitor initialization."""
        monitor = ContinuousComplianceMonitor()

        assert len(monitor._thresholds) > 0
        assert len(monitor._baselines) == 0

    def test_set_baseline(self):
        """Test setting compliance baseline."""
        monitor = ContinuousComplianceMonitor()

        assessment = MagicMock()
        assessment.overall_score = 92.5
        assessment.section_assessments = []

        baseline = monitor.set_baseline(
            framework="cis-aws",
            assessment_result=assessment,
            version="1.0",
        )

        assert baseline.framework == "cis-aws"
        assert baseline.overall_score == 92.5

    def test_capture_snapshot(self):
        """Test capturing compliance snapshot."""
        monitor = ContinuousComplianceMonitor()

        assessment = MagicMock()
        assessment.overall_score = 88.0
        assessment.controls_passed = 44
        assessment.controls_failed = 6
        assessment.total_controls = 50

        snapshot = monitor.capture_snapshot(
            framework="cis-aws",
            assessment_result=assessment,
        )

        assert snapshot.framework == "cis-aws"
        assert snapshot.overall_score == 88.0
        assert snapshot.state == ComplianceState.AT_RISK

    def test_drift_detection(self):
        """Test compliance drift detection."""
        monitor = ContinuousComplianceMonitor()

        # Set baseline
        baseline_assessment = MagicMock()
        baseline_assessment.overall_score = 95.0
        baseline_assessment.section_assessments = []
        monitor.set_baseline("soc2", baseline_assessment)

        # Capture snapshot with lower score
        current_assessment = MagicMock()
        current_assessment.overall_score = 82.0
        current_assessment.controls_passed = 41
        current_assessment.controls_failed = 9
        current_assessment.total_controls = 50

        monitor.capture_snapshot("soc2", current_assessment)

        # Should have generated alerts
        alerts = monitor.get_active_alerts(framework="soc2")
        assert len(alerts) > 0

    def test_alert_management(self):
        """Test alert acknowledgment and resolution."""
        monitor = ContinuousComplianceMonitor()

        # Create alert by triggering threshold
        assessment = MagicMock()
        assessment.overall_score = 75.0
        assessment.controls_passed = 37
        assessment.controls_failed = 13
        assessment.total_controls = 50

        monitor.capture_snapshot("pci-dss", assessment)

        alerts = monitor.get_active_alerts()
        assert len(alerts) > 0

        alert = alerts[0]

        # Acknowledge
        monitor.acknowledge_alert(alert.id, "security-admin")
        assert alert.acknowledged is True

        # Resolve
        monitor.resolve_alert(alert.id, "Fixed configuration")
        assert alert.is_active is False

    def test_compliance_trend(self):
        """Test compliance trend tracking."""
        monitor = ContinuousComplianceMonitor()

        # Capture multiple snapshots
        for score in [90, 88, 85, 87, 89]:
            assessment = MagicMock()
            assessment.overall_score = score
            assessment.controls_passed = int(score / 2)
            assessment.controls_failed = 50 - int(score / 2)
            assessment.total_controls = 50

            monitor.capture_snapshot("hipaa", assessment)

        trend = monitor.get_compliance_trend("hipaa", days=30)
        assert len(trend) == 5

    def test_framework_status(self):
        """Test framework status retrieval."""
        monitor = ContinuousComplianceMonitor()

        # Set baseline and capture snapshot
        baseline = MagicMock()
        baseline.overall_score = 90.0
        baseline.section_assessments = []
        monitor.set_baseline("iso27001", baseline)

        current = MagicMock()
        current.overall_score = 92.0
        current.controls_passed = 46
        current.controls_failed = 4
        current.total_controls = 50

        monitor.capture_snapshot("iso27001", current)

        status = monitor.get_framework_status("iso27001")

        assert status["framework"] == "iso27001"
        assert status["current_score"] == 92.0
        assert status["baseline_score"] == 90.0
        assert status["score_trend"] == 2.0

    def test_dashboard_data(self):
        """Test dashboard data generation."""
        monitor = ContinuousComplianceMonitor()

        # Add some data
        for framework in ["cis-aws", "soc2", "hipaa"]:
            assessment = MagicMock()
            assessment.overall_score = 85.0
            assessment.controls_passed = 42
            assessment.controls_failed = 8
            assessment.total_controls = 50

            monitor.capture_snapshot(framework, assessment)

        dashboard = monitor.get_dashboard_data()

        assert "overall_compliance_score" in dashboard
        assert "frameworks_monitored" in dashboard
        assert dashboard["frameworks_monitored"] == 3
        assert "alerts" in dashboard

    def test_register_alert_handler(self):
        """Test alert handler registration."""
        monitor = ContinuousComplianceMonitor()
        alerts_received = []

        def handler(alert: ComplianceAlert):
            alerts_received.append(alert)

        monitor.register_alert_handler(handler)

        # Trigger alert
        assessment = MagicMock()
        assessment.overall_score = 70.0
        assessment.controls_passed = 35
        assessment.controls_failed = 15
        assessment.total_controls = 50

        monitor.capture_snapshot("gdpr", assessment)

        assert len(alerts_received) > 0


# ============================================================================
# Integration Tests
# ============================================================================


class TestCSPMIntegration:
    """Integration tests for CSPM modules."""

    def test_end_to_end_cis_workflow(self):
        """Test end-to-end CIS benchmark workflow."""
        scanner = CISBenchmarkScanner()
        engine = AttestationEngine()
        monitor = ContinuousComplianceMonitor()

        # 1. Scan resources
        resources = [
            MagicMock(
                resource_type="aws_iam_account_summary",
                data={"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
            ),
        ]

        result = scanner.scan(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            resources=resources,
            account_id="123456789012",
        )

        # 2. Set baseline
        monitor.set_baseline("cis-aws", result)

        # 3. Capture snapshot
        snapshot = monitor.capture_snapshot("cis-aws", result)

        # 4. Generate attestation
        attestation = engine.generate_attestation(
            attestation_type=AttestationType.CIS_BENCHMARK,
            organization_name="Test Corp",
            system_description="AWS Infrastructure",
            assessment_result=result,
        )

        assert snapshot.framework == "cis-aws"
        assert attestation.attestation_type == AttestationType.CIS_BENCHMARK

    def test_regulatory_compliance_workflow(self):
        """Test regulatory compliance workflow."""
        validator = RegulatoryControlValidator()
        engine = AttestationEngine()

        # 1. Validate HIPAA
        hipaa_result = validator.validate_hipaa(
            policies=[],
            findings=[],
            organization_name="Test Hospital",
        )

        # 2. Validate PCI-DSS
        pci_result = validator.validate_pci_dss(
            policies=[],
            findings=[],
            organization_name="Test Merchant",
        )

        # 3. Generate gap analysis
        gaps = validator.generate_gap_analysis(hipaa_result, pci_result)

        # 4. Collect evidence for gaps
        for gap in gaps.get("hipaa_gaps", [])[:3]:
            engine.collect_evidence(
                evidence_type=EvidenceType.PROCEDURE,
                title=f"Remediation for {gap['control_id']}",
                description=f"Procedure document for {gap['control_title']}",
                control_ids=[gap["control_id"]],
                source="SharePoint",
            )

        # 5. Generate attestation
        attestation = engine.generate_attestation(
            attestation_type=AttestationType.HIPAA_BAA,
            organization_name="Test Hospital",
            system_description="EHR System",
            assessment_result=hipaa_result,
        )

        assert "summary" in gaps
        assert attestation.attestation_type == AttestationType.HIPAA_BAA

    def test_soc2_assessment_workflow(self):
        """Test SOC 2 assessment workflow."""
        mapper = SOC2ComplianceMapper()
        engine = AttestationEngine()
        monitor = ContinuousComplianceMonitor()

        # 1. Perform SOC 2 assessment
        assessment = mapper.assess(
            policies=[],
            findings=[],
            principles_in_scope=[
                TrustServicesPrinciple.SECURITY,
                TrustServicesPrinciple.AVAILABILITY,
            ],
            organization_name="SaaS Corp",
            assessment_type="Type II",
        )

        # 2. Generate report
        report = mapper.generate_report(assessment)

        # 3. Set baseline and monitor
        monitor.set_baseline("soc2", assessment)
        monitor.capture_snapshot("soc2", assessment)

        # 4. Generate attestation
        attestation = engine.generate_attestation(
            attestation_type=AttestationType.SOC2_TYPE2,
            organization_name="SaaS Corp",
            system_description="SaaS Platform",
            assessment_result=assessment,
        )

        assert "recommendations" in report
        assert attestation.attestation_type == AttestationType.SOC2_TYPE2

        # 5. Get dashboard data
        dashboard = monitor.get_dashboard_data()
        assert dashboard["frameworks_monitored"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
