"""
CIS Benchmark Automation for Mantissa Stance.

Provides automated CIS benchmark scanning with comprehensive control
catalogs for AWS, Azure, GCP, Kubernetes, and Docker.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


class BenchmarkType(Enum):
    """Supported CIS benchmark types."""

    AWS_FOUNDATIONS = "cis-aws-foundations"
    AWS_COMPUTE = "cis-aws-compute"
    AZURE_FOUNDATIONS = "cis-azure-foundations"
    GCP_FOUNDATIONS = "cis-gcp-foundations"
    KUBERNETES = "cis-kubernetes"
    DOCKER = "cis-docker"
    EKS = "cis-eks"
    AKS = "cis-aks"
    GKE = "cis-gke"


class CISProfile(Enum):
    """CIS benchmark profile levels."""

    LEVEL_1 = "Level 1"
    LEVEL_2 = "Level 2"


class ControlStatus(Enum):
    """Control assessment status."""

    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    MANUAL = "manual"
    ERROR = "error"


@dataclass
class CISControl:
    """Individual CIS benchmark control."""

    id: str
    title: str
    description: str
    rationale: str
    profile: CISProfile
    section_id: str
    automated: bool = True
    scored: bool = True
    audit_procedure: str = ""
    remediation: str = ""
    impact: str = ""
    default_value: str = ""
    references: list[str] = field(default_factory=list)
    cis_controls_v8: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)
    check_function: str | None = None  # Function name for automated check

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "rationale": self.rationale,
            "profile": self.profile.value,
            "section_id": self.section_id,
            "automated": self.automated,
            "scored": self.scored,
            "audit_procedure": self.audit_procedure,
            "remediation": self.remediation,
            "impact": self.impact,
            "default_value": self.default_value,
            "references": self.references,
            "cis_controls_v8": self.cis_controls_v8,
            "resource_types": self.resource_types,
        }


@dataclass
class CISSection:
    """CIS benchmark section grouping controls."""

    id: str
    title: str
    description: str
    controls: list[CISControl] = field(default_factory=list)

    @property
    def control_count(self) -> int:
        """Get total control count."""
        return len(self.controls)

    @property
    def automated_count(self) -> int:
        """Get automated control count."""
        return sum(1 for c in self.controls if c.automated)

    @property
    def scored_count(self) -> int:
        """Get scored control count."""
        return sum(1 for c in self.controls if c.scored)


@dataclass
class CISBenchmark:
    """Complete CIS benchmark definition."""

    benchmark_type: BenchmarkType
    version: str
    release_date: str
    title: str
    description: str
    sections: list[CISSection] = field(default_factory=list)
    profiles: dict[CISProfile, str] = field(default_factory=dict)

    @property
    def total_controls(self) -> int:
        """Get total control count."""
        return sum(s.control_count for s in self.sections)

    @property
    def automated_controls(self) -> int:
        """Get automated control count."""
        return sum(s.automated_count for s in self.sections)

    @property
    def scored_controls(self) -> int:
        """Get scored control count."""
        return sum(s.scored_count for s in self.sections)

    def get_control(self, control_id: str) -> CISControl | None:
        """Get a specific control by ID."""
        for section in self.sections:
            for control in section.controls:
                if control.id == control_id:
                    return control
        return None

    def get_controls_by_profile(self, profile: CISProfile) -> list[CISControl]:
        """Get all controls for a specific profile."""
        controls = []
        for section in self.sections:
            for control in section.controls:
                if control.profile == profile or profile == CISProfile.LEVEL_2:
                    controls.append(control)
        return controls

    def get_controls_by_resource_type(self, resource_type: str) -> list[CISControl]:
        """Get controls applicable to a resource type."""
        controls = []
        for section in self.sections:
            for control in section.controls:
                if resource_type in control.resource_types or "*" in control.resource_types:
                    controls.append(control)
        return controls

    def to_dict(self) -> dict[str, Any]:
        """Convert benchmark to dictionary."""
        return {
            "benchmark_type": self.benchmark_type.value,
            "version": self.version,
            "release_date": self.release_date,
            "title": self.title,
            "description": self.description,
            "total_controls": self.total_controls,
            "automated_controls": self.automated_controls,
            "scored_controls": self.scored_controls,
            "sections": [
                {
                    "id": s.id,
                    "title": s.title,
                    "description": s.description,
                    "control_count": s.control_count,
                    "controls": [c.to_dict() for c in s.controls],
                }
                for s in self.sections
            ],
        }


@dataclass
class ControlAssessment:
    """Assessment result for a single control."""

    control_id: str
    control_title: str
    status: ControlStatus
    resources_evaluated: int = 0
    resources_compliant: int = 0
    resources_non_compliant: int = 0
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_message: str | None = None

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage."""
        if self.resources_evaluated == 0:
            return 100.0 if self.status == ControlStatus.PASS else 0.0
        return (self.resources_compliant / self.resources_evaluated) * 100


@dataclass
class SectionAssessment:
    """Assessment result for a benchmark section."""

    section_id: str
    section_title: str
    control_assessments: list[ControlAssessment] = field(default_factory=list)

    @property
    def controls_passed(self) -> int:
        """Get count of passing controls."""
        return sum(1 for ca in self.control_assessments if ca.status == ControlStatus.PASS)

    @property
    def controls_failed(self) -> int:
        """Get count of failing controls."""
        return sum(1 for ca in self.control_assessments if ca.status == ControlStatus.FAIL)

    @property
    def controls_manual(self) -> int:
        """Get count of manual controls."""
        return sum(1 for ca in self.control_assessments if ca.status == ControlStatus.MANUAL)

    @property
    def compliance_percentage(self) -> float:
        """Calculate section compliance percentage."""
        applicable = [
            ca for ca in self.control_assessments
            if ca.status not in (ControlStatus.NOT_APPLICABLE, ControlStatus.MANUAL)
        ]
        if not applicable:
            return 100.0
        passed = sum(1 for ca in applicable if ca.status == ControlStatus.PASS)
        return (passed / len(applicable)) * 100


@dataclass
class CISAssessmentResult:
    """Complete CIS benchmark assessment result."""

    benchmark_type: BenchmarkType
    benchmark_version: str
    profile: CISProfile
    assessed_at: datetime
    account_id: str
    region: str | None
    section_assessments: list[SectionAssessment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_controls(self) -> int:
        """Get total controls assessed."""
        return sum(len(sa.control_assessments) for sa in self.section_assessments)

    @property
    def controls_passed(self) -> int:
        """Get total passing controls."""
        return sum(sa.controls_passed for sa in self.section_assessments)

    @property
    def controls_failed(self) -> int:
        """Get total failing controls."""
        return sum(sa.controls_failed for sa in self.section_assessments)

    @property
    def controls_manual(self) -> int:
        """Get total manual controls."""
        return sum(sa.controls_manual for sa in self.section_assessments)

    @property
    def overall_score(self) -> float:
        """Calculate overall compliance score."""
        applicable = self.total_controls - self.controls_manual
        na_count = sum(
            1 for sa in self.section_assessments
            for ca in sa.control_assessments
            if ca.status == ControlStatus.NOT_APPLICABLE
        )
        applicable -= na_count
        if applicable <= 0:
            return 100.0
        return (self.controls_passed / applicable) * 100

    @property
    def grade(self) -> str:
        """Get letter grade for compliance score."""
        score = self.overall_score
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def get_critical_findings(self) -> list[ControlAssessment]:
        """Get assessments for critical failing controls."""
        critical = []
        for sa in self.section_assessments:
            for ca in sa.control_assessments:
                if ca.status == ControlStatus.FAIL and ca.resources_non_compliant > 0:
                    critical.append(ca)
        return sorted(critical, key=lambda x: x.resources_non_compliant, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "benchmark_type": self.benchmark_type.value,
            "benchmark_version": self.benchmark_version,
            "profile": self.profile.value,
            "assessed_at": self.assessed_at.isoformat(),
            "account_id": self.account_id,
            "region": self.region,
            "overall_score": round(self.overall_score, 2),
            "grade": self.grade,
            "total_controls": self.total_controls,
            "controls_passed": self.controls_passed,
            "controls_failed": self.controls_failed,
            "controls_manual": self.controls_manual,
            "section_assessments": [
                {
                    "section_id": sa.section_id,
                    "section_title": sa.section_title,
                    "compliance_percentage": round(sa.compliance_percentage, 2),
                    "controls_passed": sa.controls_passed,
                    "controls_failed": sa.controls_failed,
                    "control_assessments": [
                        {
                            "control_id": ca.control_id,
                            "control_title": ca.control_title,
                            "status": ca.status.value,
                            "resources_evaluated": ca.resources_evaluated,
                            "resources_compliant": ca.resources_compliant,
                            "resources_non_compliant": ca.resources_non_compliant,
                            "findings": ca.findings,
                        }
                        for ca in sa.control_assessments
                    ],
                }
                for sa in self.section_assessments
            ],
            "metadata": self.metadata,
        }


class CISBenchmarkScanner:
    """
    Automated CIS benchmark scanner.

    Evaluates cloud resources against CIS benchmark controls
    and generates comprehensive assessment reports.
    """

    # Built-in benchmark definitions
    BENCHMARKS: dict[BenchmarkType, CISBenchmark] = {}

    def __init__(self) -> None:
        """Initialize the scanner with benchmark catalogs."""
        self._initialize_benchmarks()
        self._check_functions: dict[str, Callable[..., ControlAssessment]] = {}
        self._register_default_checks()

    def _initialize_benchmarks(self) -> None:
        """Initialize built-in benchmark definitions."""
        # CIS AWS Foundations Benchmark v1.5.0
        self.BENCHMARKS[BenchmarkType.AWS_FOUNDATIONS] = self._create_aws_foundations_benchmark()
        # CIS Azure Foundations Benchmark v2.0.0
        self.BENCHMARKS[BenchmarkType.AZURE_FOUNDATIONS] = self._create_azure_foundations_benchmark()
        # CIS GCP Foundations Benchmark v2.0.0
        self.BENCHMARKS[BenchmarkType.GCP_FOUNDATIONS] = self._create_gcp_foundations_benchmark()
        # CIS Kubernetes Benchmark v1.8.0
        self.BENCHMARKS[BenchmarkType.KUBERNETES] = self._create_kubernetes_benchmark()
        # CIS Docker Benchmark v1.6.0
        self.BENCHMARKS[BenchmarkType.DOCKER] = self._create_docker_benchmark()

    def _create_aws_foundations_benchmark(self) -> CISBenchmark:
        """Create AWS Foundations benchmark definition."""
        return CISBenchmark(
            benchmark_type=BenchmarkType.AWS_FOUNDATIONS,
            version="1.5.0",
            release_date="2022-08-16",
            title="CIS Amazon Web Services Foundations Benchmark",
            description="The CIS AWS Foundations Benchmark provides prescriptive guidance for configuring security options for a subset of Amazon Web Services.",
            profiles={
                CISProfile.LEVEL_1: "Level 1 - Base recommendations",
                CISProfile.LEVEL_2: "Level 2 - Includes Level 1 plus additional recommendations",
            },
            sections=[
                CISSection(
                    id="1",
                    title="Identity and Access Management",
                    description="This section contains recommendations for configuring identity and access management related options.",
                    controls=[
                        CISControl(
                            id="1.1",
                            title="Maintain current contact details",
                            description="Ensure contact email and telephone details for AWS accounts are current.",
                            rationale="AWS needs accurate account information to contact the account owner for any security issues.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=False,
                            scored=True,
                            resource_types=["aws_account"],
                            check_function="check_aws_account_contact",
                        ),
                        CISControl(
                            id="1.2",
                            title="Ensure security contact information is registered",
                            description="AWS provides customers with the option of specifying the contact information for account's security team.",
                            rationale="Security-related issues reported to AWS will be sent to this contact.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_account"],
                            check_function="check_aws_security_contact",
                        ),
                        CISControl(
                            id="1.3",
                            title="Ensure security questions are registered in the AWS account",
                            description="Security questions provide an additional layer of protection for account recovery.",
                            rationale="The security questions help verify identity for account recovery.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=False,
                            scored=False,
                            resource_types=["aws_account"],
                        ),
                        CISControl(
                            id="1.4",
                            title="Ensure no 'root' user account access key exists",
                            description="The root account should not have access keys for programmatic access.",
                            rationale="Root account has unrestricted access to all resources.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_account_summary"],
                            check_function="check_root_access_keys",
                            remediation="Delete root account access keys via IAM console.",
                            cis_controls_v8=["3.3", "5.4"],
                        ),
                        CISControl(
                            id="1.5",
                            title="Ensure MFA is enabled for the 'root' user account",
                            description="Multi-factor authentication (MFA) should be enabled for the root account.",
                            rationale="MFA adds an extra layer of security for the most privileged account.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_account_summary"],
                            check_function="check_root_mfa",
                            remediation="Enable MFA for root account in IAM console.",
                            cis_controls_v8=["6.3", "6.5"],
                        ),
                        CISControl(
                            id="1.6",
                            title="Ensure hardware MFA is enabled for the 'root' user account",
                            description="Hardware MFA should be enabled for the root account for additional security.",
                            rationale="Hardware MFA is more secure than virtual MFA.",
                            profile=CISProfile.LEVEL_2,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_account_summary", "aws_iam_virtual_mfa_device"],
                            check_function="check_root_hardware_mfa",
                            cis_controls_v8=["6.5"],
                        ),
                        CISControl(
                            id="1.7",
                            title="Eliminate use of the 'root' user for administrative and daily tasks",
                            description="Root account should not be used for everyday administrative tasks.",
                            rationale="Using root for daily tasks increases risk of compromise.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudtrail_event"],
                            check_function="check_root_usage",
                            cis_controls_v8=["5.4"],
                        ),
                        CISControl(
                            id="1.8",
                            title="Ensure IAM password policy requires minimum length of 14 or greater",
                            description="Password policy should require minimum password length.",
                            rationale="Strong password policy reduces risk of password compromise.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_account_password_policy"],
                            check_function="check_password_length",
                            cis_controls_v8=["5.2"],
                        ),
                        CISControl(
                            id="1.9",
                            title="Ensure IAM password policy prevents password reuse",
                            description="Password policy should prevent reuse of previous passwords.",
                            rationale="Preventing reuse reduces risk from compromised old passwords.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_account_password_policy"],
                            check_function="check_password_reuse",
                            cis_controls_v8=["5.2"],
                        ),
                        CISControl(
                            id="1.10",
                            title="Ensure multi-factor authentication (MFA) is enabled for all IAM users with console password",
                            description="All IAM users with console access should have MFA enabled.",
                            rationale="MFA provides additional security for all user accounts.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_user"],
                            check_function="check_user_mfa",
                            cis_controls_v8=["6.3", "6.5"],
                        ),
                        CISControl(
                            id="1.11",
                            title="Do not setup access keys during initial user setup",
                            description="Access keys should not be created during initial user setup.",
                            rationale="Access keys created at setup may not be properly secured.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=False,
                            scored=False,
                            resource_types=["aws_iam_user"],
                        ),
                        CISControl(
                            id="1.12",
                            title="Ensure credentials unused for 45 days or greater are disabled",
                            description="Inactive credentials should be disabled after 45 days.",
                            rationale="Unused credentials may be compromised without detection.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_credential_report"],
                            check_function="check_inactive_credentials",
                            cis_controls_v8=["5.3"],
                        ),
                        CISControl(
                            id="1.13",
                            title="Ensure there is only one active access key per IAM user",
                            description="Users should have at most one active access key.",
                            rationale="Multiple keys increase attack surface and complicate rotation.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_user"],
                            check_function="check_single_access_key",
                            cis_controls_v8=["5.4"],
                        ),
                        CISControl(
                            id="1.14",
                            title="Ensure access keys are rotated every 90 days or less",
                            description="Access keys should be rotated within 90 days.",
                            rationale="Regular rotation limits exposure from compromised keys.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_credential_report"],
                            check_function="check_key_rotation",
                            cis_controls_v8=["5.2"],
                        ),
                        CISControl(
                            id="1.15",
                            title="Ensure IAM Users Receive Permissions Only Through Groups",
                            description="IAM users should receive permissions via groups, not direct attachment.",
                            rationale="Group-based permissions are easier to audit and manage.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_user"],
                            check_function="check_group_permissions",
                            cis_controls_v8=["6.8"],
                        ),
                        CISControl(
                            id="1.16",
                            title="Ensure IAM policies with full administrative privileges are not attached",
                            description="Policies granting full admin access should not be broadly attached.",
                            rationale="Full admin privileges should be restricted to specific use cases.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_policy"],
                            check_function="check_admin_policies",
                            cis_controls_v8=["3.3", "6.8"],
                        ),
                        CISControl(
                            id="1.17",
                            title="Ensure a support role has been created to manage incidents",
                            description="A support role should exist for AWS Support access.",
                            rationale="Dedicated support role allows controlled access to AWS Support.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_role"],
                            check_function="check_support_role",
                            cis_controls_v8=["6.8"],
                        ),
                        CISControl(
                            id="1.18",
                            title="Ensure IAM instance roles are used for AWS resource access",
                            description="EC2 instances should use IAM roles, not access keys.",
                            rationale="Instance roles provide automatic credential rotation.",
                            profile=CISProfile.LEVEL_2,
                            section_id="1",
                            automated=False,
                            scored=False,
                            resource_types=["aws_ec2_instance"],
                        ),
                        CISControl(
                            id="1.19",
                            title="Ensure that all expired certificates stored in IAM are removed",
                            description="Expired SSL/TLS certificates should be removed from IAM.",
                            rationale="Expired certificates may be accidentally used.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_iam_server_certificate"],
                            check_function="check_expired_certificates",
                            cis_controls_v8=["3.1"],
                        ),
                        CISControl(
                            id="1.20",
                            title="Ensure IAM Access Analyzer is enabled for all regions",
                            description="IAM Access Analyzer should be enabled in all regions.",
                            rationale="Access Analyzer identifies external access to resources.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["aws_accessanalyzer_analyzer"],
                            check_function="check_access_analyzer",
                            cis_controls_v8=["3.3"],
                        ),
                    ],
                ),
                CISSection(
                    id="2",
                    title="Storage",
                    description="This section contains recommendations for configuring storage related options.",
                    controls=[
                        CISControl(
                            id="2.1.1",
                            title="Ensure S3 Bucket Policy is set to deny HTTP requests",
                            description="S3 bucket policies should deny unencrypted HTTP requests.",
                            rationale="HTTP requests expose data in transit.",
                            profile=CISProfile.LEVEL_2,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["aws_s3_bucket"],
                            check_function="check_s3_https",
                            cis_controls_v8=["3.10"],
                        ),
                        CISControl(
                            id="2.1.2",
                            title="Ensure MFA Delete is enabled on S3 buckets",
                            description="MFA Delete should be enabled for sensitive S3 buckets.",
                            rationale="MFA Delete prevents accidental or malicious deletion.",
                            profile=CISProfile.LEVEL_2,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["aws_s3_bucket"],
                            check_function="check_s3_mfa_delete",
                            cis_controls_v8=["3.3"],
                        ),
                        CISControl(
                            id="2.1.3",
                            title="Ensure S3 Buckets are configured with Block Public Access",
                            description="S3 buckets should have public access blocked.",
                            rationale="Public access to S3 buckets can expose sensitive data.",
                            profile=CISProfile.LEVEL_1,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["aws_s3_bucket"],
                            check_function="check_s3_public_access",
                            cis_controls_v8=["3.3"],
                        ),
                        CISControl(
                            id="2.1.4",
                            title="Ensure S3 buckets have server-side encryption enabled",
                            description="S3 buckets should have default encryption enabled.",
                            rationale="Encryption protects data at rest.",
                            profile=CISProfile.LEVEL_1,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["aws_s3_bucket"],
                            check_function="check_s3_encryption",
                            cis_controls_v8=["3.11"],
                        ),
                        CISControl(
                            id="2.2.1",
                            title="Ensure EBS volume encryption is enabled in all regions",
                            description="EBS volume encryption by default should be enabled.",
                            rationale="Ensures all new EBS volumes are encrypted.",
                            profile=CISProfile.LEVEL_1,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["aws_ec2_ebs_encryption_by_default"],
                            check_function="check_ebs_encryption",
                            cis_controls_v8=["3.11"],
                        ),
                        CISControl(
                            id="2.3.1",
                            title="Ensure RDS instances have encryption enabled",
                            description="RDS database instances should be encrypted.",
                            rationale="Encryption protects database data at rest.",
                            profile=CISProfile.LEVEL_1,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["aws_db_instance"],
                            check_function="check_rds_encryption",
                            cis_controls_v8=["3.11"],
                        ),
                    ],
                ),
                CISSection(
                    id="3",
                    title="Logging",
                    description="This section contains recommendations for configuring logging related options.",
                    controls=[
                        CISControl(
                            id="3.1",
                            title="Ensure CloudTrail is enabled in all regions",
                            description="CloudTrail should be enabled for all regions.",
                            rationale="Multi-region logging captures activity across all regions.",
                            profile=CISProfile.LEVEL_1,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudtrail"],
                            check_function="check_cloudtrail_multiregion",
                            cis_controls_v8=["8.2", "8.5"],
                        ),
                        CISControl(
                            id="3.2",
                            title="Ensure CloudTrail log file validation is enabled",
                            description="Log file integrity validation should be enabled.",
                            rationale="Validation detects tampering with log files.",
                            profile=CISProfile.LEVEL_2,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudtrail"],
                            check_function="check_cloudtrail_validation",
                            cis_controls_v8=["8.2"],
                        ),
                        CISControl(
                            id="3.3",
                            title="Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
                            description="CloudTrail S3 bucket should not allow public access.",
                            rationale="Public access to logs exposes sensitive audit data.",
                            profile=CISProfile.LEVEL_1,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_s3_bucket"],
                            check_function="check_cloudtrail_s3_public",
                            cis_controls_v8=["3.3", "8.2"],
                        ),
                        CISControl(
                            id="3.4",
                            title="Ensure CloudTrail trails are integrated with CloudWatch Logs",
                            description="CloudTrail should stream logs to CloudWatch Logs.",
                            rationale="CloudWatch enables real-time monitoring of CloudTrail.",
                            profile=CISProfile.LEVEL_1,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudtrail"],
                            check_function="check_cloudtrail_cloudwatch",
                            cis_controls_v8=["8.2", "8.9"],
                        ),
                        CISControl(
                            id="3.5",
                            title="Ensure AWS Config is enabled in all regions",
                            description="AWS Config should be enabled for resource tracking.",
                            rationale="Config provides resource configuration history.",
                            profile=CISProfile.LEVEL_1,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_config_recorder"],
                            check_function="check_config_enabled",
                            cis_controls_v8=["1.1", "4.1"],
                        ),
                        CISControl(
                            id="3.6",
                            title="Ensure CloudTrail logs are encrypted with KMS CMKs",
                            description="CloudTrail logs should be encrypted with KMS.",
                            rationale="KMS encryption provides additional protection.",
                            profile=CISProfile.LEVEL_2,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudtrail"],
                            check_function="check_cloudtrail_kms",
                            cis_controls_v8=["3.11"],
                        ),
                        CISControl(
                            id="3.7",
                            title="Ensure rotation for customer-created symmetric CMKs is enabled",
                            description="KMS key rotation should be enabled for symmetric keys.",
                            rationale="Key rotation limits exposure from compromised keys.",
                            profile=CISProfile.LEVEL_2,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_kms_key"],
                            check_function="check_kms_rotation",
                            cis_controls_v8=["3.6"],
                        ),
                        CISControl(
                            id="3.8",
                            title="Ensure VPC flow logging is enabled in all VPCs",
                            description="VPC Flow Logs should be enabled for network visibility.",
                            rationale="Flow logs provide network traffic visibility.",
                            profile=CISProfile.LEVEL_2,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_vpc"],
                            check_function="check_vpc_flow_logs",
                            cis_controls_v8=["8.2", "13.6"],
                        ),
                        CISControl(
                            id="3.9",
                            title="Ensure S3 bucket access logging is enabled",
                            description="S3 bucket access logging should be enabled.",
                            rationale="Access logs provide visibility into bucket usage.",
                            profile=CISProfile.LEVEL_1,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["aws_s3_bucket"],
                            check_function="check_s3_access_logging",
                            cis_controls_v8=["8.2"],
                        ),
                    ],
                ),
                CISSection(
                    id="4",
                    title="Monitoring",
                    description="This section contains recommendations for configuring monitoring related options.",
                    controls=[
                        CISControl(
                            id="4.1",
                            title="Ensure a log metric filter and alarm exist for unauthorized API calls",
                            description="Monitor unauthorized API calls via CloudWatch alarms.",
                            rationale="Detects unauthorized access attempts.",
                            profile=CISProfile.LEVEL_1,
                            section_id="4",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"],
                            check_function="check_alarm_unauthorized_api",
                            cis_controls_v8=["8.11"],
                        ),
                        CISControl(
                            id="4.2",
                            title="Ensure a log metric filter and alarm exist for console sign-in without MFA",
                            description="Monitor console sign-ins without MFA.",
                            rationale="Detects sign-ins that bypass MFA.",
                            profile=CISProfile.LEVEL_1,
                            section_id="4",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"],
                            check_function="check_alarm_no_mfa_signin",
                            cis_controls_v8=["8.11"],
                        ),
                        CISControl(
                            id="4.3",
                            title="Ensure a log metric filter and alarm exist for usage of 'root' account",
                            description="Monitor root account usage.",
                            rationale="Root account usage should be rare and monitored.",
                            profile=CISProfile.LEVEL_1,
                            section_id="4",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"],
                            check_function="check_alarm_root_usage",
                            cis_controls_v8=["8.11"],
                        ),
                        CISControl(
                            id="4.4",
                            title="Ensure a log metric filter and alarm exist for IAM policy changes",
                            description="Monitor IAM policy changes.",
                            rationale="Detects unauthorized permission changes.",
                            profile=CISProfile.LEVEL_1,
                            section_id="4",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"],
                            check_function="check_alarm_iam_changes",
                            cis_controls_v8=["8.11"],
                        ),
                        CISControl(
                            id="4.5",
                            title="Ensure a log metric filter and alarm exist for CloudTrail configuration changes",
                            description="Monitor CloudTrail configuration changes.",
                            rationale="Detects tampering with audit logging.",
                            profile=CISProfile.LEVEL_1,
                            section_id="4",
                            automated=True,
                            scored=True,
                            resource_types=["aws_cloudwatch_log_metric_filter", "aws_cloudwatch_metric_alarm"],
                            check_function="check_alarm_cloudtrail_changes",
                            cis_controls_v8=["8.11"],
                        ),
                    ],
                ),
                CISSection(
                    id="5",
                    title="Networking",
                    description="This section contains recommendations for configuring networking related options.",
                    controls=[
                        CISControl(
                            id="5.1",
                            title="Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote admin ports",
                            description="NACLs should not allow unrestricted admin port access.",
                            rationale="Open admin ports expose systems to attack.",
                            profile=CISProfile.LEVEL_1,
                            section_id="5",
                            automated=True,
                            scored=True,
                            resource_types=["aws_network_acl"],
                            check_function="check_nacl_admin_ports",
                            cis_controls_v8=["12.1"],
                        ),
                        CISControl(
                            id="5.2",
                            title="Ensure no security groups allow ingress from 0.0.0.0/0 to SSH port 22",
                            description="Security groups should not allow unrestricted SSH.",
                            rationale="Open SSH exposes systems to brute force attacks.",
                            profile=CISProfile.LEVEL_1,
                            section_id="5",
                            automated=True,
                            scored=True,
                            resource_types=["aws_security_group"],
                            check_function="check_sg_ssh",
                            cis_controls_v8=["12.1"],
                        ),
                        CISControl(
                            id="5.3",
                            title="Ensure no security groups allow ingress from 0.0.0.0/0 to RDP port 3389",
                            description="Security groups should not allow unrestricted RDP.",
                            rationale="Open RDP exposes systems to attacks.",
                            profile=CISProfile.LEVEL_1,
                            section_id="5",
                            automated=True,
                            scored=True,
                            resource_types=["aws_security_group"],
                            check_function="check_sg_rdp",
                            cis_controls_v8=["12.1"],
                        ),
                        CISControl(
                            id="5.4",
                            title="Ensure the default security group of every VPC restricts all traffic",
                            description="Default security groups should have no rules.",
                            rationale="Default SGs should not be used for permissive rules.",
                            profile=CISProfile.LEVEL_2,
                            section_id="5",
                            automated=True,
                            scored=True,
                            resource_types=["aws_security_group"],
                            check_function="check_default_sg",
                            cis_controls_v8=["12.2"],
                        ),
                        CISControl(
                            id="5.5",
                            title="Ensure routing tables for VPC peering are least access",
                            description="VPC peering routes should follow least privilege.",
                            rationale="Overly permissive peering routes expand attack surface.",
                            profile=CISProfile.LEVEL_2,
                            section_id="5",
                            automated=False,
                            scored=False,
                            resource_types=["aws_route_table"],
                        ),
                        CISControl(
                            id="5.6",
                            title="Ensure EC2 metadata service IMDSv2 is used",
                            description="EC2 instances should use IMDSv2.",
                            rationale="IMDSv2 provides improved security for metadata.",
                            profile=CISProfile.LEVEL_1,
                            section_id="5",
                            automated=True,
                            scored=True,
                            resource_types=["aws_ec2_instance"],
                            check_function="check_imdsv2",
                            cis_controls_v8=["4.7"],
                        ),
                    ],
                ),
            ],
        )

    def _create_azure_foundations_benchmark(self) -> CISBenchmark:
        """Create Azure Foundations benchmark definition."""
        return CISBenchmark(
            benchmark_type=BenchmarkType.AZURE_FOUNDATIONS,
            version="2.0.0",
            release_date="2022-09-22",
            title="CIS Microsoft Azure Foundations Benchmark",
            description="The CIS Microsoft Azure Foundations Benchmark provides prescriptive guidance for configuring security options for Microsoft Azure.",
            profiles={
                CISProfile.LEVEL_1: "Level 1 - Base recommendations",
                CISProfile.LEVEL_2: "Level 2 - Includes Level 1 plus additional recommendations",
            },
            sections=[
                CISSection(
                    id="1",
                    title="Identity and Access Management",
                    description="Identity and access management recommendations.",
                    controls=[
                        CISControl(
                            id="1.1",
                            title="Ensure Security Defaults is enabled on Azure AD",
                            description="Security defaults provide basic identity protection.",
                            rationale="Enables baseline security for Azure AD.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["azure_ad_security_defaults"],
                            check_function="check_azure_security_defaults",
                        ),
                        CISControl(
                            id="1.2",
                            title="Ensure MFA is enabled for all users",
                            description="All users should have MFA enabled.",
                            rationale="MFA significantly reduces account compromise risk.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["azure_ad_user"],
                            check_function="check_azure_user_mfa",
                        ),
                        CISControl(
                            id="1.3",
                            title="Ensure guest users are reviewed regularly",
                            description="Guest user access should be reviewed periodically.",
                            rationale="Guest access may persist beyond business need.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["azure_ad_user"],
                            check_function="check_azure_guest_review",
                        ),
                    ],
                ),
                CISSection(
                    id="2",
                    title="Microsoft Defender",
                    description="Microsoft Defender for Cloud recommendations.",
                    controls=[
                        CISControl(
                            id="2.1",
                            title="Ensure Microsoft Defender for Cloud is enabled",
                            description="Defender for Cloud should be enabled.",
                            rationale="Provides security monitoring and recommendations.",
                            profile=CISProfile.LEVEL_1,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["azure_security_center"],
                            check_function="check_azure_defender",
                        ),
                    ],
                ),
                CISSection(
                    id="3",
                    title="Storage Accounts",
                    description="Storage account security recommendations.",
                    controls=[
                        CISControl(
                            id="3.1",
                            title="Ensure 'Secure transfer required' is enabled",
                            description="Storage accounts should require HTTPS.",
                            rationale="HTTPS encrypts data in transit.",
                            profile=CISProfile.LEVEL_1,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["azure_storage_account"],
                            check_function="check_azure_storage_https",
                        ),
                        CISControl(
                            id="3.2",
                            title="Ensure storage account encryption is enabled",
                            description="Storage accounts should use encryption.",
                            rationale="Encryption protects data at rest.",
                            profile=CISProfile.LEVEL_1,
                            section_id="3",
                            automated=True,
                            scored=True,
                            resource_types=["azure_storage_account"],
                            check_function="check_azure_storage_encryption",
                        ),
                    ],
                ),
            ],
        )

    def _create_gcp_foundations_benchmark(self) -> CISBenchmark:
        """Create GCP Foundations benchmark definition."""
        return CISBenchmark(
            benchmark_type=BenchmarkType.GCP_FOUNDATIONS,
            version="2.0.0",
            release_date="2022-07-12",
            title="CIS Google Cloud Platform Foundation Benchmark",
            description="The CIS GCP Foundation Benchmark provides prescriptive guidance for configuring security options for Google Cloud Platform.",
            profiles={
                CISProfile.LEVEL_1: "Level 1 - Base recommendations",
                CISProfile.LEVEL_2: "Level 2 - Includes Level 1 plus additional recommendations",
            },
            sections=[
                CISSection(
                    id="1",
                    title="Identity and Access Management",
                    description="IAM recommendations for GCP.",
                    controls=[
                        CISControl(
                            id="1.1",
                            title="Ensure corporate login credentials are used",
                            description="Cloud Identity or G Suite should be used for access.",
                            rationale="Corporate identity provides better access control.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=False,
                            scored=True,
                            resource_types=["gcp_iam_policy"],
                        ),
                        CISControl(
                            id="1.2",
                            title="Ensure MFA is enforced for all users",
                            description="All users should have MFA enabled.",
                            rationale="MFA prevents unauthorized access.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["gcp_organization"],
                            check_function="check_gcp_mfa",
                        ),
                        CISControl(
                            id="1.3",
                            title="Ensure service account keys are managed properly",
                            description="Service account keys should be rotated.",
                            rationale="Old keys may be compromised.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["gcp_service_account_key"],
                            check_function="check_gcp_sa_keys",
                        ),
                    ],
                ),
                CISSection(
                    id="2",
                    title="Logging and Monitoring",
                    description="Logging and monitoring recommendations.",
                    controls=[
                        CISControl(
                            id="2.1",
                            title="Ensure Cloud Audit Logging is enabled",
                            description="Audit logging should be enabled for all services.",
                            rationale="Audit logs provide visibility into activity.",
                            profile=CISProfile.LEVEL_1,
                            section_id="2",
                            automated=True,
                            scored=True,
                            resource_types=["gcp_project"],
                            check_function="check_gcp_audit_logging",
                        ),
                    ],
                ),
            ],
        )

    def _create_kubernetes_benchmark(self) -> CISBenchmark:
        """Create Kubernetes benchmark definition."""
        return CISBenchmark(
            benchmark_type=BenchmarkType.KUBERNETES,
            version="1.8.0",
            release_date="2023-08-01",
            title="CIS Kubernetes Benchmark",
            description="The CIS Kubernetes Benchmark provides prescriptive guidance for establishing a secure configuration posture for Kubernetes.",
            profiles={
                CISProfile.LEVEL_1: "Level 1 - Base recommendations",
                CISProfile.LEVEL_2: "Level 2 - Includes Level 1 plus additional recommendations",
            },
            sections=[
                CISSection(
                    id="1",
                    title="Control Plane Components",
                    description="Control plane component security recommendations.",
                    controls=[
                        CISControl(
                            id="1.1.1",
                            title="Ensure API server pod specification file permissions are set to 644 or more restrictive",
                            description="API server pod spec should have restricted permissions.",
                            rationale="Prevents unauthorized modification of API server config.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["kubernetes_node"],
                            check_function="check_k8s_api_permissions",
                        ),
                        CISControl(
                            id="1.2.1",
                            title="Ensure anonymous requests are disabled",
                            description="Anonymous authentication should be disabled.",
                            rationale="Prevents unauthenticated API access.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["kubernetes_api_server"],
                            check_function="check_k8s_anonymous_auth",
                        ),
                    ],
                ),
                CISSection(
                    id="5",
                    title="Policies",
                    description="Kubernetes policy recommendations.",
                    controls=[
                        CISControl(
                            id="5.1.1",
                            title="Ensure cluster-admin role is used only where required",
                            description="Cluster-admin should be restricted.",
                            rationale="Limits blast radius of compromise.",
                            profile=CISProfile.LEVEL_1,
                            section_id="5",
                            automated=True,
                            scored=True,
                            resource_types=["kubernetes_clusterrolebinding"],
                            check_function="check_k8s_cluster_admin",
                        ),
                        CISControl(
                            id="5.2.1",
                            title="Ensure Pod Security Standards are enforced",
                            description="PSS should be enforced at namespace level.",
                            rationale="Ensures pods follow security best practices.",
                            profile=CISProfile.LEVEL_1,
                            section_id="5",
                            automated=True,
                            scored=True,
                            resource_types=["kubernetes_namespace"],
                            check_function="check_k8s_pss",
                        ),
                    ],
                ),
            ],
        )

    def _create_docker_benchmark(self) -> CISBenchmark:
        """Create Docker benchmark definition."""
        return CISBenchmark(
            benchmark_type=BenchmarkType.DOCKER,
            version="1.6.0",
            release_date="2023-01-01",
            title="CIS Docker Benchmark",
            description="The CIS Docker Benchmark provides prescriptive guidance for establishing a secure configuration posture for Docker.",
            profiles={
                CISProfile.LEVEL_1: "Level 1 - Base recommendations",
                CISProfile.LEVEL_2: "Level 2 - Includes Level 1 plus additional recommendations",
            },
            sections=[
                CISSection(
                    id="1",
                    title="Host Configuration",
                    description="Docker host configuration recommendations.",
                    controls=[
                        CISControl(
                            id="1.1.1",
                            title="Ensure a separate partition for containers has been created",
                            description="Containers should use a dedicated partition.",
                            rationale="Prevents container filling host filesystem.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["docker_host"],
                            check_function="check_docker_partition",
                        ),
                        CISControl(
                            id="1.1.2",
                            title="Ensure the Docker daemon audit configuration is hardened",
                            description="Docker daemon should be audited.",
                            rationale="Enables detection of suspicious activity.",
                            profile=CISProfile.LEVEL_1,
                            section_id="1",
                            automated=True,
                            scored=True,
                            resource_types=["docker_host"],
                            check_function="check_docker_audit",
                        ),
                    ],
                ),
                CISSection(
                    id="4",
                    title="Container Images and Build File",
                    description="Container image security recommendations.",
                    controls=[
                        CISControl(
                            id="4.1",
                            title="Ensure a user for the container has been created",
                            description="Containers should run as non-root.",
                            rationale="Non-root reduces privilege escalation risk.",
                            profile=CISProfile.LEVEL_1,
                            section_id="4",
                            automated=True,
                            scored=True,
                            resource_types=["docker_image"],
                            check_function="check_docker_user",
                        ),
                        CISControl(
                            id="4.2",
                            title="Ensure containers use trusted base images",
                            description="Base images should be from trusted sources.",
                            rationale="Reduces supply chain risk.",
                            profile=CISProfile.LEVEL_1,
                            section_id="4",
                            automated=True,
                            scored=True,
                            resource_types=["docker_image"],
                            check_function="check_docker_base_image",
                        ),
                    ],
                ),
            ],
        )

    def _register_default_checks(self) -> None:
        """Register default check functions."""
        # AWS Checks
        self._check_functions["check_root_access_keys"] = self._check_root_access_keys
        self._check_functions["check_root_mfa"] = self._check_root_mfa
        self._check_functions["check_password_length"] = self._check_password_length
        self._check_functions["check_user_mfa"] = self._check_user_mfa
        self._check_functions["check_s3_encryption"] = self._check_s3_encryption
        self._check_functions["check_s3_public_access"] = self._check_s3_public_access
        self._check_functions["check_cloudtrail_multiregion"] = self._check_cloudtrail_multiregion
        self._check_functions["check_sg_ssh"] = self._check_sg_ssh
        self._check_functions["check_sg_rdp"] = self._check_sg_rdp

    def get_benchmark(self, benchmark_type: BenchmarkType) -> CISBenchmark | None:
        """Get a benchmark definition."""
        return self.BENCHMARKS.get(benchmark_type)

    def list_benchmarks(self) -> list[dict[str, Any]]:
        """List all available benchmarks."""
        return [
            {
                "type": b.benchmark_type.value,
                "version": b.version,
                "title": b.title,
                "total_controls": b.total_controls,
                "automated_controls": b.automated_controls,
            }
            for b in self.BENCHMARKS.values()
        ]

    def scan(
        self,
        benchmark_type: BenchmarkType,
        resources: Any,  # ResourceCollection or similar
        profile: CISProfile = CISProfile.LEVEL_1,
        account_id: str = "",
        region: str | None = None,
    ) -> CISAssessmentResult:
        """
        Perform a CIS benchmark scan.

        Args:
            benchmark_type: Type of benchmark to run
            resources: Collection of resources to evaluate
            profile: CIS profile level to assess
            account_id: Account/project identifier
            region: Region being assessed

        Returns:
            CISAssessmentResult with detailed findings
        """
        benchmark = self.get_benchmark(benchmark_type)
        if not benchmark:
            raise ValueError(f"Unknown benchmark type: {benchmark_type}")

        now = datetime.now(timezone.utc)
        section_assessments: list[SectionAssessment] = []

        for section in benchmark.sections:
            control_assessments: list[ControlAssessment] = []

            for control in section.controls:
                # Filter by profile
                if profile == CISProfile.LEVEL_1 and control.profile == CISProfile.LEVEL_2:
                    continue

                assessment = self._assess_control(control, resources)
                control_assessments.append(assessment)

            section_assessments.append(
                SectionAssessment(
                    section_id=section.id,
                    section_title=section.title,
                    control_assessments=control_assessments,
                )
            )

        return CISAssessmentResult(
            benchmark_type=benchmark_type,
            benchmark_version=benchmark.version,
            profile=profile,
            assessed_at=now,
            account_id=account_id,
            region=region,
            section_assessments=section_assessments,
            metadata={
                "scanner_version": "1.0.0",
                "benchmark_title": benchmark.title,
            },
        )

    def _assess_control(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Assess a single control against resources."""
        if not control.automated:
            return ControlAssessment(
                control_id=control.id,
                control_title=control.title,
                status=ControlStatus.MANUAL,
                evidence={"reason": "Manual assessment required"},
            )

        if control.check_function and control.check_function in self._check_functions:
            try:
                return self._check_functions[control.check_function](control, resources)
            except Exception as e:
                return ControlAssessment(
                    control_id=control.id,
                    control_title=control.title,
                    status=ControlStatus.ERROR,
                    error_message=str(e),
                )

        # Default: look for matching resources and evaluate
        return self._default_assess(control, resources)

    def _default_assess(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Default assessment logic when no specific check function exists."""
        matching_resources = []
        if hasattr(resources, "__iter__"):
            for resource in resources:
                resource_type = getattr(resource, "resource_type", None)
                if resource_type and resource_type in control.resource_types:
                    matching_resources.append(resource)

        if not matching_resources:
            return ControlAssessment(
                control_id=control.id,
                control_title=control.title,
                status=ControlStatus.NOT_APPLICABLE,
                evidence={"reason": "No matching resources found"},
            )

        # Assume passing if resources exist (specific checks should override)
        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.PASS,
            resources_evaluated=len(matching_resources),
            resources_compliant=len(matching_resources),
            resources_non_compliant=0,
        )

    # --- Specific check functions ---

    def _check_root_access_keys(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check if root account has access keys."""
        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_iam_account_summary":
                summary = getattr(resource, "data", {})
                has_keys = summary.get("AccountAccessKeysPresent", 0) > 0

                return ControlAssessment(
                    control_id=control.id,
                    control_title=control.title,
                    status=ControlStatus.FAIL if has_keys else ControlStatus.PASS,
                    resources_evaluated=1,
                    resources_compliant=0 if has_keys else 1,
                    resources_non_compliant=1 if has_keys else 0,
                    evidence={"root_access_keys_present": has_keys},
                )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.NOT_APPLICABLE,
        )

    def _check_root_mfa(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check if root account has MFA enabled."""
        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_iam_account_summary":
                summary = getattr(resource, "data", {})
                mfa_enabled = summary.get("AccountMFAEnabled", 0) > 0

                return ControlAssessment(
                    control_id=control.id,
                    control_title=control.title,
                    status=ControlStatus.PASS if mfa_enabled else ControlStatus.FAIL,
                    resources_evaluated=1,
                    resources_compliant=1 if mfa_enabled else 0,
                    resources_non_compliant=0 if mfa_enabled else 1,
                    evidence={"root_mfa_enabled": mfa_enabled},
                )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.NOT_APPLICABLE,
        )

    def _check_password_length(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check IAM password policy minimum length."""
        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_iam_account_password_policy":
                policy = getattr(resource, "data", {})
                min_length = policy.get("MinimumPasswordLength", 0)
                compliant = min_length >= 14

                return ControlAssessment(
                    control_id=control.id,
                    control_title=control.title,
                    status=ControlStatus.PASS if compliant else ControlStatus.FAIL,
                    resources_evaluated=1,
                    resources_compliant=1 if compliant else 0,
                    resources_non_compliant=0 if compliant else 1,
                    evidence={"minimum_password_length": min_length},
                )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.NOT_APPLICABLE,
        )

    def _check_user_mfa(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check if IAM users with console access have MFA."""
        users_evaluated = 0
        users_compliant = 0
        non_compliant_users = []

        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_iam_user":
                data = getattr(resource, "data", {})
                has_password = data.get("PasswordEnabled", False)

                if has_password:
                    users_evaluated += 1
                    has_mfa = len(data.get("MFADevices", [])) > 0

                    if has_mfa:
                        users_compliant += 1
                    else:
                        non_compliant_users.append(data.get("UserName", "unknown"))

        if users_evaluated == 0:
            return ControlAssessment(
                control_id=control.id,
                control_title=control.title,
                status=ControlStatus.NOT_APPLICABLE,
            )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.PASS if not non_compliant_users else ControlStatus.FAIL,
            resources_evaluated=users_evaluated,
            resources_compliant=users_compliant,
            resources_non_compliant=len(non_compliant_users),
            evidence={"non_compliant_users": non_compliant_users},
        )

    def _check_s3_encryption(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check if S3 buckets have encryption enabled."""
        buckets_evaluated = 0
        buckets_compliant = 0
        non_compliant_buckets = []

        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_s3_bucket":
                buckets_evaluated += 1
                data = getattr(resource, "data", {})
                encryption = data.get("ServerSideEncryptionConfiguration")

                if encryption:
                    buckets_compliant += 1
                else:
                    non_compliant_buckets.append(data.get("Name", "unknown"))

        if buckets_evaluated == 0:
            return ControlAssessment(
                control_id=control.id,
                control_title=control.title,
                status=ControlStatus.NOT_APPLICABLE,
            )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.PASS if not non_compliant_buckets else ControlStatus.FAIL,
            resources_evaluated=buckets_evaluated,
            resources_compliant=buckets_compliant,
            resources_non_compliant=len(non_compliant_buckets),
            evidence={"non_compliant_buckets": non_compliant_buckets},
        )

    def _check_s3_public_access(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check if S3 buckets have public access blocked."""
        buckets_evaluated = 0
        buckets_compliant = 0
        non_compliant_buckets = []

        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_s3_bucket":
                buckets_evaluated += 1
                data = getattr(resource, "data", {})
                public_block = data.get("PublicAccessBlockConfiguration", {})

                is_blocked = (
                    public_block.get("BlockPublicAcls", False)
                    and public_block.get("BlockPublicPolicy", False)
                    and public_block.get("IgnorePublicAcls", False)
                    and public_block.get("RestrictPublicBuckets", False)
                )

                if is_blocked:
                    buckets_compliant += 1
                else:
                    non_compliant_buckets.append(data.get("Name", "unknown"))

        if buckets_evaluated == 0:
            return ControlAssessment(
                control_id=control.id,
                control_title=control.title,
                status=ControlStatus.NOT_APPLICABLE,
            )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.PASS if not non_compliant_buckets else ControlStatus.FAIL,
            resources_evaluated=buckets_evaluated,
            resources_compliant=buckets_compliant,
            resources_non_compliant=len(non_compliant_buckets),
            evidence={"non_compliant_buckets": non_compliant_buckets},
        )

    def _check_cloudtrail_multiregion(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check if CloudTrail is enabled for all regions."""
        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_cloudtrail":
                data = getattr(resource, "data", {})
                is_multiregion = data.get("IsMultiRegionTrail", False)
                is_logging = data.get("IsLogging", False)

                compliant = is_multiregion and is_logging

                return ControlAssessment(
                    control_id=control.id,
                    control_title=control.title,
                    status=ControlStatus.PASS if compliant else ControlStatus.FAIL,
                    resources_evaluated=1,
                    resources_compliant=1 if compliant else 0,
                    resources_non_compliant=0 if compliant else 1,
                    evidence={
                        "is_multiregion": is_multiregion,
                        "is_logging": is_logging,
                    },
                )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.FAIL,
            evidence={"reason": "No CloudTrail found"},
        )

    def _check_sg_ssh(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check security groups for open SSH access."""
        sgs_evaluated = 0
        sgs_compliant = 0
        non_compliant_sgs = []

        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_security_group":
                sgs_evaluated += 1
                data = getattr(resource, "data", {})
                has_open_ssh = False

                for rule in data.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 0)

                    if from_port <= 22 <= to_port:
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                has_open_ssh = True
                                break

                if has_open_ssh:
                    non_compliant_sgs.append(data.get("GroupId", "unknown"))
                else:
                    sgs_compliant += 1

        if sgs_evaluated == 0:
            return ControlAssessment(
                control_id=control.id,
                control_title=control.title,
                status=ControlStatus.NOT_APPLICABLE,
            )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.PASS if not non_compliant_sgs else ControlStatus.FAIL,
            resources_evaluated=sgs_evaluated,
            resources_compliant=sgs_compliant,
            resources_non_compliant=len(non_compliant_sgs),
            evidence={"non_compliant_security_groups": non_compliant_sgs},
        )

    def _check_sg_rdp(
        self, control: CISControl, resources: Any
    ) -> ControlAssessment:
        """Check security groups for open RDP access."""
        sgs_evaluated = 0
        sgs_compliant = 0
        non_compliant_sgs = []

        for resource in resources:
            if getattr(resource, "resource_type", "") == "aws_security_group":
                sgs_evaluated += 1
                data = getattr(resource, "data", {})
                has_open_rdp = False

                for rule in data.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 0)

                    if from_port <= 3389 <= to_port:
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                has_open_rdp = True
                                break

                if has_open_rdp:
                    non_compliant_sgs.append(data.get("GroupId", "unknown"))
                else:
                    sgs_compliant += 1

        if sgs_evaluated == 0:
            return ControlAssessment(
                control_id=control.id,
                control_title=control.title,
                status=ControlStatus.NOT_APPLICABLE,
            )

        return ControlAssessment(
            control_id=control.id,
            control_title=control.title,
            status=ControlStatus.PASS if not non_compliant_sgs else ControlStatus.FAIL,
            resources_evaluated=sgs_evaluated,
            resources_compliant=sgs_compliant,
            resources_non_compliant=len(non_compliant_sgs),
            evidence={"non_compliant_security_groups": non_compliant_sgs},
        )

    def register_check_function(
        self, name: str, func: Callable[..., ControlAssessment]
    ) -> None:
        """Register a custom check function."""
        self._check_functions[name] = func

    def generate_report(
        self,
        result: CISAssessmentResult,
        format: str = "json",
    ) -> str:
        """Generate a formatted report from assessment results."""
        if format == "json":
            import json
            return json.dumps(result.to_dict(), indent=2)

        # Text format
        lines = [
            f"CIS Benchmark Assessment Report",
            f"================================",
            f"",
            f"Benchmark: {result.benchmark_type.value}",
            f"Version: {result.benchmark_version}",
            f"Profile: {result.profile.value}",
            f"Assessed: {result.assessed_at.isoformat()}",
            f"Account: {result.account_id}",
            f"",
            f"SUMMARY",
            f"-------",
            f"Overall Score: {result.overall_score:.1f}% (Grade: {result.grade})",
            f"Controls Passed: {result.controls_passed}/{result.total_controls}",
            f"Controls Failed: {result.controls_failed}",
            f"Manual Review: {result.controls_manual}",
            f"",
        ]

        for sa in result.section_assessments:
            lines.append(f"Section {sa.section_id}: {sa.section_title}")
            lines.append(f"  Compliance: {sa.compliance_percentage:.1f}%")
            lines.append(f"  Passed: {sa.controls_passed}, Failed: {sa.controls_failed}")
            lines.append("")

            for ca in sa.control_assessments:
                status_symbol = {
                    ControlStatus.PASS: "[PASS]",
                    ControlStatus.FAIL: "[FAIL]",
                    ControlStatus.MANUAL: "[MANUAL]",
                    ControlStatus.NOT_APPLICABLE: "[N/A]",
                    ControlStatus.ERROR: "[ERROR]",
                }.get(ca.status, "[?]")

                lines.append(f"  {status_symbol} {ca.control_id}: {ca.control_title}")

                if ca.status == ControlStatus.FAIL and ca.resources_non_compliant > 0:
                    lines.append(f"         Resources: {ca.resources_non_compliant} non-compliant")

            lines.append("")

        return "\n".join(lines)
