"""
SOC 2 Compliance Mapping for Mantissa Stance.

Provides detailed Trust Services Criteria (TSC) 2017 mapping
and validation for SOC 2 Type I and Type II assessments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class TrustServicesPrinciple(Enum):
    """SOC 2 Trust Services Principles (Categories)."""

    SECURITY = "Security"
    AVAILABILITY = "Availability"
    PROCESSING_INTEGRITY = "Processing Integrity"
    CONFIDENTIALITY = "Confidentiality"
    PRIVACY = "Privacy"


class SOC2Category(Enum):
    """SOC 2 Common Criteria categories."""

    # Control Environment
    CC1 = "CC1"  # Control Environment
    # Communication and Information
    CC2 = "CC2"  # Communication and Information
    # Risk Assessment
    CC3 = "CC3"  # Risk Assessment
    # Monitoring Activities
    CC4 = "CC4"  # Monitoring Activities
    # Control Activities
    CC5 = "CC5"  # Control Activities
    # Logical and Physical Access Controls
    CC6 = "CC6"  # Logical and Physical Access Controls
    # System Operations
    CC7 = "CC7"  # System Operations
    # Change Management
    CC8 = "CC8"  # Change Management
    # Risk Mitigation
    CC9 = "CC9"  # Risk Mitigation
    # Availability
    A1 = "A1"  # Availability
    # Processing Integrity
    PI1 = "PI1"  # Processing Integrity
    # Confidentiality
    C1 = "C1"  # Confidentiality
    # Privacy
    P1 = "P1"  # Privacy - Notice and Choice
    P2 = "P2"  # Privacy - Collection
    P3 = "P3"  # Privacy - Use, Retention, Disposal
    P4 = "P4"  # Privacy - Access
    P5 = "P5"  # Privacy - Disclosure and Notification
    P6 = "P6"  # Privacy - Quality
    P7 = "P7"  # Privacy - Monitoring and Enforcement
    P8 = "P8"  # Privacy - Security for Privacy


class ControlTestStatus(Enum):
    """Status of SOC 2 control testing."""

    NOT_TESTED = "not_tested"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    EXCEPTION = "exception"


@dataclass
class SOC2Criteria:
    """Individual SOC 2 Trust Services Criteria."""

    id: str
    category: SOC2Category
    title: str
    description: str
    principle: TrustServicesPrinciple
    points_of_focus: list[str] = field(default_factory=list)
    related_criteria: list[str] = field(default_factory=list)
    automated_checks: list[str] = field(default_factory=list)  # Policy IDs
    evidence_requirements: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "principle": self.principle.value,
            "points_of_focus": self.points_of_focus,
            "related_criteria": self.related_criteria,
            "automated_checks": self.automated_checks,
            "evidence_requirements": self.evidence_requirements,
        }


@dataclass
class SOC2Control:
    """A specific control implementation for SOC 2 criteria."""

    control_id: str
    criteria_id: str
    description: str
    control_owner: str = ""
    implementation_status: str = "implemented"
    test_procedures: list[str] = field(default_factory=list)
    evidence_collected: list[str] = field(default_factory=list)
    last_tested: datetime | None = None
    test_result: ControlTestStatus = ControlTestStatus.NOT_TESTED
    exceptions: list[str] = field(default_factory=list)
    remediation_plan: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "criteria_id": self.criteria_id,
            "description": self.description,
            "control_owner": self.control_owner,
            "implementation_status": self.implementation_status,
            "test_procedures": self.test_procedures,
            "evidence_collected": self.evidence_collected,
            "last_tested": self.last_tested.isoformat() if self.last_tested else None,
            "test_result": self.test_result.value,
            "exceptions": self.exceptions,
            "remediation_plan": self.remediation_plan,
        }


@dataclass
class CriteriaAssessment:
    """Assessment result for a single SOC 2 criteria."""

    criteria_id: str
    criteria_title: str
    category: SOC2Category
    principle: TrustServicesPrinciple
    status: ControlTestStatus
    controls_tested: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage for this criteria."""
        if self.controls_tested == 0:
            return 100.0 if self.status == ControlTestStatus.PASSED else 0.0
        return (self.controls_passed / self.controls_tested) * 100


@dataclass
class PrincipleAssessment:
    """Assessment result for a Trust Services Principle."""

    principle: TrustServicesPrinciple
    criteria_assessments: list[CriteriaAssessment] = field(default_factory=list)

    @property
    def criteria_passed(self) -> int:
        """Get count of passing criteria."""
        return sum(
            1 for ca in self.criteria_assessments
            if ca.status == ControlTestStatus.PASSED
        )

    @property
    def criteria_failed(self) -> int:
        """Get count of failing criteria."""
        return sum(
            1 for ca in self.criteria_assessments
            if ca.status == ControlTestStatus.FAILED
        )

    @property
    def compliance_percentage(self) -> float:
        """Calculate compliance percentage for this principle."""
        applicable = [
            ca for ca in self.criteria_assessments
            if ca.status not in (ControlTestStatus.NOT_APPLICABLE, ControlTestStatus.NOT_TESTED)
        ]
        if not applicable:
            return 100.0
        passed = sum(1 for ca in applicable if ca.status == ControlTestStatus.PASSED)
        return (passed / len(applicable)) * 100


@dataclass
class SOC2Assessment:
    """Complete SOC 2 assessment result."""

    assessment_type: str  # "Type I" or "Type II"
    assessment_period_start: datetime
    assessment_period_end: datetime
    organization_name: str
    system_description: str
    principles_in_scope: list[TrustServicesPrinciple]
    principle_assessments: list[PrincipleAssessment] = field(default_factory=list)
    auditor: str = ""
    report_date: datetime | None = None
    management_assertion: str = ""
    exceptions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def overall_compliance(self) -> float:
        """Calculate overall compliance percentage."""
        if not self.principle_assessments:
            return 100.0
        total = sum(pa.compliance_percentage for pa in self.principle_assessments)
        return total / len(self.principle_assessments)

    @property
    def total_criteria(self) -> int:
        """Get total criteria assessed."""
        return sum(len(pa.criteria_assessments) for pa in self.principle_assessments)

    @property
    def criteria_passed(self) -> int:
        """Get total passing criteria."""
        return sum(pa.criteria_passed for pa in self.principle_assessments)

    @property
    def criteria_failed(self) -> int:
        """Get total failing criteria."""
        return sum(pa.criteria_failed for pa in self.principle_assessments)

    @property
    def opinion(self) -> str:
        """Generate audit opinion based on results."""
        if self.overall_compliance >= 95:
            return "Unqualified"
        elif self.overall_compliance >= 80:
            return "Qualified"
        else:
            return "Adverse"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assessment_type": self.assessment_type,
            "assessment_period_start": self.assessment_period_start.isoformat(),
            "assessment_period_end": self.assessment_period_end.isoformat(),
            "organization_name": self.organization_name,
            "system_description": self.system_description,
            "principles_in_scope": [p.value for p in self.principles_in_scope],
            "overall_compliance": round(self.overall_compliance, 2),
            "total_criteria": self.total_criteria,
            "criteria_passed": self.criteria_passed,
            "criteria_failed": self.criteria_failed,
            "opinion": self.opinion,
            "auditor": self.auditor,
            "report_date": self.report_date.isoformat() if self.report_date else None,
            "principle_assessments": [
                {
                    "principle": pa.principle.value,
                    "compliance_percentage": round(pa.compliance_percentage, 2),
                    "criteria_passed": pa.criteria_passed,
                    "criteria_failed": pa.criteria_failed,
                    "criteria_assessments": [
                        {
                            "criteria_id": ca.criteria_id,
                            "criteria_title": ca.criteria_title,
                            "status": ca.status.value,
                            "controls_tested": ca.controls_tested,
                            "controls_passed": ca.controls_passed,
                            "compliance_percentage": round(ca.compliance_percentage, 2),
                        }
                        for ca in pa.criteria_assessments
                    ],
                }
                for pa in self.principle_assessments
            ],
            "exceptions": self.exceptions,
        }


class SOC2ComplianceMapper:
    """
    SOC 2 Trust Services Criteria compliance mapper.

    Maps security controls and policies to SOC 2 TSC 2017
    criteria and provides assessment capabilities.
    """

    # Trust Services Criteria catalog (TSC 2017)
    CRITERIA_CATALOG: dict[str, SOC2Criteria] = {}

    def __init__(self) -> None:
        """Initialize the SOC 2 compliance mapper."""
        self._initialize_criteria_catalog()
        self._policy_mappings: dict[str, list[str]] = {}  # policy_id -> criteria_ids

    def _initialize_criteria_catalog(self) -> None:
        """Initialize the TSC 2017 criteria catalog."""
        # CC1 - Control Environment
        self.CRITERIA_CATALOG["CC1.1"] = SOC2Criteria(
            id="CC1.1",
            category=SOC2Category.CC1,
            title="Demonstrates Commitment to Integrity and Ethical Values",
            description="The entity demonstrates a commitment to integrity and ethical values.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Sets the Tone at the Top",
                "Establishes Standards of Conduct",
                "Evaluates Adherence to Standards of Conduct",
                "Addresses Deviations in a Timely Manner",
            ],
            evidence_requirements=[
                "Code of conduct documentation",
                "Ethics training records",
                "Disciplinary action records",
            ],
        )

        self.CRITERIA_CATALOG["CC1.2"] = SOC2Criteria(
            id="CC1.2",
            category=SOC2Category.CC1,
            title="Exercises Oversight Responsibility",
            description="The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal control.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Establishes Oversight Responsibilities",
                "Applies Relevant Expertise",
                "Operates Independently",
            ],
            evidence_requirements=[
                "Board meeting minutes",
                "Audit committee charter",
                "Board composition documentation",
            ],
        )

        self.CRITERIA_CATALOG["CC1.3"] = SOC2Criteria(
            id="CC1.3",
            category=SOC2Category.CC1,
            title="Establishes Structure, Authority, and Responsibility",
            description="Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities in the pursuit of objectives.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Considers All Structures of the Entity",
                "Establishes Reporting Lines",
                "Defines, Assigns, and Limits Authorities and Responsibilities",
            ],
            evidence_requirements=[
                "Organization chart",
                "Job descriptions",
                "Authority matrix",
            ],
        )

        self.CRITERIA_CATALOG["CC1.4"] = SOC2Criteria(
            id="CC1.4",
            category=SOC2Category.CC1,
            title="Demonstrates Commitment to Competence",
            description="The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Establishes Policies and Practices",
                "Evaluates Competence and Addresses Shortcomings",
                "Attracts, Develops, and Retains Individuals",
                "Plans and Prepares for Succession",
            ],
            evidence_requirements=[
                "HR policies",
                "Training records",
                "Performance evaluations",
                "Succession planning documentation",
            ],
        )

        self.CRITERIA_CATALOG["CC1.5"] = SOC2Criteria(
            id="CC1.5",
            category=SOC2Category.CC1,
            title="Enforces Accountability",
            description="The entity holds individuals accountable for their internal control responsibilities in the pursuit of objectives.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Enforces Accountability Through Structures, Authorities, and Responsibilities",
                "Establishes Performance Measures, Incentives, and Rewards",
                "Evaluates Performance Measures, Incentives, and Rewards for Ongoing Relevance",
                "Considers Excessive Pressures",
            ],
            evidence_requirements=[
                "Performance review documentation",
                "Incentive program documentation",
                "Accountability records",
            ],
        )

        # CC2 - Communication and Information
        self.CRITERIA_CATALOG["CC2.1"] = SOC2Criteria(
            id="CC2.1",
            category=SOC2Category.CC2,
            title="Obtains or Generates Relevant Information",
            description="The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Identifies Information Requirements",
                "Captures Internal and External Sources of Data",
                "Processes Relevant Data Into Information",
                "Maintains Quality Throughout Processing",
            ],
            evidence_requirements=[
                "Information flow diagrams",
                "Data quality procedures",
                "System documentation",
            ],
        )

        self.CRITERIA_CATALOG["CC2.2"] = SOC2Criteria(
            id="CC2.2",
            category=SOC2Category.CC2,
            title="Communicates Internally",
            description="The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal control.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Communicates Internal Control Information",
                "Communicates With the Board of Directors",
                "Provides Separate Communication Lines",
                "Selects Relevant Method of Communication",
            ],
            evidence_requirements=[
                "Internal communications",
                "Policy distribution records",
                "Training materials",
            ],
        )

        self.CRITERIA_CATALOG["CC2.3"] = SOC2Criteria(
            id="CC2.3",
            category=SOC2Category.CC2,
            title="Communicates Externally",
            description="The entity communicates with external parties regarding matters affecting the functioning of internal control.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Communicates to External Parties",
                "Enables Inbound Communications",
                "Communicates With the Board of Directors",
                "Provides Separate Communication Lines",
            ],
            evidence_requirements=[
                "External communications policy",
                "Incident notification procedures",
                "Customer communication records",
            ],
        )

        # CC3 - Risk Assessment
        self.CRITERIA_CATALOG["CC3.1"] = SOC2Criteria(
            id="CC3.1",
            category=SOC2Category.CC3,
            title="Specifies Objectives",
            description="The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Operations Objectives",
                "External Financial Reporting Objectives",
                "External Nonfinancial Reporting Objectives",
                "Internal Reporting Objectives",
                "Compliance Objectives",
            ],
            evidence_requirements=[
                "Strategic plan",
                "Security objectives documentation",
                "Risk appetite statement",
            ],
        )

        self.CRITERIA_CATALOG["CC3.2"] = SOC2Criteria(
            id="CC3.2",
            category=SOC2Category.CC3,
            title="Identifies and Analyzes Risk",
            description="The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Includes Entity, Subsidiary, Division, Operating Unit, and Functional Levels",
                "Analyzes Internal and External Factors",
                "Involves Appropriate Levels of Management",
                "Estimates Significance of Risks Identified",
                "Determines How to Respond to Risks",
            ],
            automated_checks=[
                "aws-guardduty-enabled",
                "azure-defender-enabled",
                "vulnerability-scanning-enabled",
            ],
            evidence_requirements=[
                "Risk assessment reports",
                "Threat modeling documentation",
                "Vulnerability scan results",
            ],
        )

        self.CRITERIA_CATALOG["CC3.3"] = SOC2Criteria(
            id="CC3.3",
            category=SOC2Category.CC3,
            title="Considers Potential for Fraud",
            description="The entity considers the potential for fraud in assessing risks to the achievement of objectives.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Considers Various Types of Fraud",
                "Assesses Incentives and Pressures",
                "Assesses Opportunities",
                "Assesses Attitudes and Rationalizations",
            ],
            evidence_requirements=[
                "Fraud risk assessment",
                "Anti-fraud controls documentation",
                "Segregation of duties matrix",
            ],
        )

        self.CRITERIA_CATALOG["CC3.4"] = SOC2Criteria(
            id="CC3.4",
            category=SOC2Category.CC3,
            title="Identifies and Assesses Significant Change",
            description="The entity identifies and assesses changes that could significantly impact the system of internal control.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Assesses Changes in the External Environment",
                "Assesses Changes in the Business Model",
                "Assesses Changes in Leadership",
            ],
            automated_checks=[
                "config-enabled",
                "cloudtrail-enabled",
            ],
            evidence_requirements=[
                "Change management records",
                "Environmental scan reports",
                "Business continuity plans",
            ],
        )

        # CC4 - Monitoring Activities
        self.CRITERIA_CATALOG["CC4.1"] = SOC2Criteria(
            id="CC4.1",
            category=SOC2Category.CC4,
            title="Selects, Develops, and Performs Evaluations",
            description="The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Considers a Mix of Ongoing and Separate Evaluations",
                "Considers Rate of Change",
                "Establishes Baseline Understanding",
                "Uses Knowledgeable Personnel",
                "Integrates With Business Processes",
                "Adjusts Scope and Frequency",
                "Objectively Evaluates",
            ],
            automated_checks=[
                "security-hub-enabled",
                "continuous-monitoring-enabled",
            ],
            evidence_requirements=[
                "Internal audit reports",
                "Penetration test results",
                "Monitoring dashboards",
            ],
        )

        self.CRITERIA_CATALOG["CC4.2"] = SOC2Criteria(
            id="CC4.2",
            category=SOC2Category.CC4,
            title="Evaluates and Communicates Deficiencies",
            description="The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Assesses Results",
                "Communicates Deficiencies",
                "Monitors Corrective Action",
            ],
            evidence_requirements=[
                "Deficiency tracking system",
                "Remediation plans",
                "Management response documentation",
            ],
        )

        # CC5 - Control Activities
        self.CRITERIA_CATALOG["CC5.1"] = SOC2Criteria(
            id="CC5.1",
            category=SOC2Category.CC5,
            title="Selects and Develops Control Activities",
            description="The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Integrates With Risk Assessment",
                "Considers Entity-Specific Factors",
                "Determines Relevant Business Processes",
                "Evaluates a Mix of Control Activity Types",
                "Considers at What Level Activities Are Applied",
                "Addresses Segregation of Duties",
            ],
            evidence_requirements=[
                "Control design documentation",
                "Risk-control matrix",
                "Segregation of duties matrix",
            ],
        )

        self.CRITERIA_CATALOG["CC5.2"] = SOC2Criteria(
            id="CC5.2",
            category=SOC2Category.CC5,
            title="Selects and Develops Technology Controls",
            description="The entity also selects and develops general control activities over technology to support the achievement of objectives.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Determines Dependency Between the Use of Technology in Business Processes and Technology General Controls",
                "Establishes Relevant Technology Infrastructure Control Activities",
                "Establishes Relevant Security Management Process Control Activities",
                "Establishes Relevant Technology Acquisition, Development, and Maintenance Process Control Activities",
            ],
            automated_checks=[
                "encryption-at-rest",
                "encryption-in-transit",
                "patch-management",
            ],
            evidence_requirements=[
                "IT general controls documentation",
                "Security architecture documentation",
                "Technology standards",
            ],
        )

        self.CRITERIA_CATALOG["CC5.3"] = SOC2Criteria(
            id="CC5.3",
            category=SOC2Category.CC5,
            title="Deploys Through Policies and Procedures",
            description="The entity deploys control activities through policies that establish what is expected and procedures that put policies into action.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Establishes Policies and Procedures to Support Deployment of Management's Directives",
                "Establishes Responsibility and Accountability for Executing Policies and Procedures",
                "Performs in a Timely Manner",
                "Takes Corrective Action",
                "Performs Using Competent Personnel",
                "Reassesses Policies and Procedures",
            ],
            evidence_requirements=[
                "Security policies",
                "Operating procedures",
                "Policy acknowledgment records",
            ],
        )

        # CC6 - Logical and Physical Access Controls
        self.CRITERIA_CATALOG["CC6.1"] = SOC2Criteria(
            id="CC6.1",
            category=SOC2Category.CC6,
            title="Implements Logical Access Security Software",
            description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Identifies and Manages the Inventory of Information Assets",
                "Restricts Logical Access",
                "Identifies and Authenticates Users",
                "Considers Network Segmentation",
                "Manages Points of Access",
                "Restricts Access to Information Assets",
                "Manages Identification and Authentication",
                "Manages Credentials for Infrastructure and Software",
                "Uses Encryption to Protect Data",
                "Protects Encryption Keys",
            ],
            automated_checks=[
                "iam-mfa-enabled",
                "iam-password-policy",
                "s3-encryption",
                "rds-encryption",
                "network-segmentation",
            ],
            evidence_requirements=[
                "Access control policy",
                "User access reviews",
                "Encryption standards",
                "Network diagrams",
            ],
        )

        self.CRITERIA_CATALOG["CC6.2"] = SOC2Criteria(
            id="CC6.2",
            category=SOC2Category.CC6,
            title="Registers and Authorizes Users",
            description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Controls Access Credentials to Protected Assets",
                "Removes Access to Protected Assets When Appropriate",
                "Reviews Appropriateness of Access Credentials",
            ],
            automated_checks=[
                "iam-user-permissions-boundary",
                "iam-least-privilege",
            ],
            evidence_requirements=[
                "User provisioning procedures",
                "Access request forms",
                "Termination procedures",
            ],
        )

        self.CRITERIA_CATALOG["CC6.3"] = SOC2Criteria(
            id="CC6.3",
            category=SOC2Category.CC6,
            title="Authorizes Access Based on Need",
            description="The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to the concepts of least privilege and segregation of duties.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Creates or Modifies Access to Protected Information Assets",
                "Removes Access to Protected Information Assets",
                "Uses Role-Based Access Controls",
                "Reviews Access Roles and Rules",
            ],
            automated_checks=[
                "iam-no-admin-policies",
                "iam-role-based-access",
            ],
            evidence_requirements=[
                "Role definitions",
                "Access review records",
                "Change authorization records",
            ],
        )

        self.CRITERIA_CATALOG["CC6.4"] = SOC2Criteria(
            id="CC6.4",
            category=SOC2Category.CC6,
            title="Restricts Physical Access",
            description="The entity restricts physical access to facilities and protected information assets to authorized personnel.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Creates or Modifies Physical Access",
                "Removes Physical Access",
                "Reviews Physical Access",
            ],
            evidence_requirements=[
                "Physical access policy",
                "Badge access logs",
                "Visitor logs",
            ],
        )

        self.CRITERIA_CATALOG["CC6.5"] = SOC2Criteria(
            id="CC6.5",
            category=SOC2Category.CC6,
            title="Disposes of Protected Assets",
            description="The entity disposes of data, software, hardware, and other protected assets to meet the entity's objectives.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Identifies Data and Software for Disposal",
                "Removes Data from Entity Control",
                "Renders Data and Software Unreadable",
            ],
            evidence_requirements=[
                "Data disposal policy",
                "Hardware disposal records",
                "Data sanitization certificates",
            ],
        )

        self.CRITERIA_CATALOG["CC6.6"] = SOC2Criteria(
            id="CC6.6",
            category=SOC2Category.CC6,
            title="Manages Threats from Outside System Boundaries",
            description="The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Restricts Access",
                "Protects Identification and Authentication Credentials",
                "Requires Additional Authentication or Credentials",
                "Implements Boundary Protection Systems",
            ],
            automated_checks=[
                "security-group-restricted",
                "no-public-ssh",
                "no-public-rdp",
                "waf-enabled",
            ],
            evidence_requirements=[
                "Firewall rules",
                "IDS/IPS configuration",
                "WAF configuration",
            ],
        )

        self.CRITERIA_CATALOG["CC6.7"] = SOC2Criteria(
            id="CC6.7",
            category=SOC2Category.CC6,
            title="Manages Transmission of Data",
            description="The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Restricts the Ability to Perform Transmission",
                "Uses Encryption Technologies or Secure Communication Channels",
                "Protects Removal Media",
                "Protects Mobile Devices",
            ],
            automated_checks=[
                "s3-https-only",
                "elb-ssl-certificate",
                "tls-version",
            ],
            evidence_requirements=[
                "Data transfer policy",
                "Encryption standards",
                "Mobile device policy",
            ],
        )

        self.CRITERIA_CATALOG["CC6.8"] = SOC2Criteria(
            id="CC6.8",
            category=SOC2Category.CC6,
            title="Prevents and Detects Unauthorized Software",
            description="The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Restricts Application and Software Installation",
                "Detects Unauthorized Changes to Software and Configuration Parameters",
                "Uses a Defined Change Control Process",
                "Uses Antivirus and Anti-Malware Software",
                "Scans Information Assets from Outside the Entity for Malware and Other Unauthorized Software",
            ],
            automated_checks=[
                "ami-vulnerability-scan",
                "ecr-image-scan",
                "guardduty-enabled",
            ],
            evidence_requirements=[
                "Change management policy",
                "Antivirus reports",
                "Software whitelist",
            ],
        )

        # CC7 - System Operations
        self.CRITERIA_CATALOG["CC7.1"] = SOC2Criteria(
            id="CC7.1",
            category=SOC2Category.CC7,
            title="Manages Vulnerabilities",
            description="To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities and susceptibilities to newly discovered vulnerabilities.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Uses Defined Configuration Standards",
                "Monitors Infrastructure and Software",
                "Implements Change-Detection Mechanisms",
                "Detects Unknown or Unauthorized Components",
                "Conducts Vulnerability Scans",
            ],
            automated_checks=[
                "inspector-enabled",
                "patch-compliance",
                "config-drift-detection",
            ],
            evidence_requirements=[
                "Vulnerability scan reports",
                "Patch management records",
                "Configuration standards",
            ],
        )

        self.CRITERIA_CATALOG["CC7.2"] = SOC2Criteria(
            id="CC7.2",
            category=SOC2Category.CC7,
            title="Monitors System Components",
            description="The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Implements Detection Policies, Procedures, and Tools",
                "Designs Detection Measures",
                "Implements Filters to Analyze Anomalies",
                "Monitors Detection Tools for Effective Operation",
            ],
            automated_checks=[
                "cloudtrail-enabled",
                "cloudwatch-alarms",
                "guardduty-enabled",
                "security-hub-enabled",
            ],
            evidence_requirements=[
                "Monitoring architecture",
                "Alert rules",
                "SIEM configuration",
            ],
        )

        self.CRITERIA_CATALOG["CC7.3"] = SOC2Criteria(
            id="CC7.3",
            category=SOC2Category.CC7,
            title="Evaluates Security Events",
            description="The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Responds to Security Incidents",
                "Communicates and Reviews Detected Security Events",
                "Develops and Implements Procedures to Analyze Security Incidents",
                "Assesses the Impact on Personal Information",
                "Determines Personal Information Used or Disclosed",
            ],
            evidence_requirements=[
                "Incident response plan",
                "Security event logs",
                "Incident reports",
            ],
        )

        self.CRITERIA_CATALOG["CC7.4"] = SOC2Criteria(
            id="CC7.4",
            category=SOC2Category.CC7,
            title="Responds to Security Incidents",
            description="The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents, as appropriate.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Assigns Roles and Responsibilities",
                "Contains Security Incidents",
                "Mitigates Ongoing Security Incidents",
                "Ends Threats Posed by Security Incidents",
                "Restores Operations",
                "Develops and Implements Communication Protocols for Security Incidents",
                "Obtains Understanding of Nature of Incident and Determines Containment Strategy",
                "Remediates Identified Vulnerabilities",
                "Communicates Remediation Activities",
                "Evaluates the Effectiveness of Incident Response",
                "Periodically Evaluates Incidents",
            ],
            evidence_requirements=[
                "Incident response procedures",
                "Communication templates",
                "Post-incident reviews",
            ],
        )

        self.CRITERIA_CATALOG["CC7.5"] = SOC2Criteria(
            id="CC7.5",
            category=SOC2Category.CC7,
            title="Recovers from Security Incidents",
            description="The entity identifies, develops, and implements activities to recover from identified security incidents.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Restores the Affected Environment",
                "Communicates Information About the Event",
                "Determines Root Cause of the Event",
                "Implements Changes to Prevent and Detect Recurrences",
            ],
            automated_checks=[
                "backup-enabled",
                "disaster-recovery",
            ],
            evidence_requirements=[
                "Recovery procedures",
                "Root cause analysis reports",
                "Lessons learned documentation",
            ],
        )

        # CC8 - Change Management
        self.CRITERIA_CATALOG["CC8.1"] = SOC2Criteria(
            id="CC8.1",
            category=SOC2Category.CC8,
            title="Authorizes, Designs, and Develops Changes",
            description="The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure and software.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Manages Changes Throughout the System Life Cycle",
                "Authorizes Changes",
                "Designs and Develops Changes",
                "Documents Changes",
                "Tracks System Changes",
                "Configures Software",
                "Tests System Changes",
                "Approves System Changes",
                "Deploys System Changes",
                "Identifies and Evaluates System Changes",
                "Identifies Changes in Infrastructure, Data, Software, and Procedures Required to Remediate Incidents",
            ],
            automated_checks=[
                "code-review-required",
                "ci-cd-pipeline",
            ],
            evidence_requirements=[
                "Change management policy",
                "Change request records",
                "Test documentation",
                "Deployment records",
            ],
        )

        # CC9 - Risk Mitigation
        self.CRITERIA_CATALOG["CC9.1"] = SOC2Criteria(
            id="CC9.1",
            category=SOC2Category.CC9,
            title="Identifies and Manages Vendor Risk",
            description="The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Considers Mitigation Through Business Processes, Replacement, and Insurance",
            ],
            evidence_requirements=[
                "Vendor management policy",
                "Vendor risk assessments",
                "Business impact analysis",
            ],
        )

        self.CRITERIA_CATALOG["CC9.2"] = SOC2Criteria(
            id="CC9.2",
            category=SOC2Category.CC9,
            title="Manages Business Disruption Risk",
            description="The entity assesses and manages risks associated with vendors and business partners.",
            principle=TrustServicesPrinciple.SECURITY,
            points_of_focus=[
                "Establishes Requirements for Vendor and Business Partner Engagements",
                "Assesses Vendor and Business Partner Risks",
                "Assigns Responsibility and Accountability for Managing Vendors and Business Partners",
                "Establishes Communication Protocols for Vendors and Business Partners",
                "Establishes Exception Handling Procedures From Vendor and Business Partners",
                "Assesses Vendor and Business Partner Performance",
                "Implements Procedures for Addressing Issues Identified During Vendor and Business Partner Assessments",
                "Implements Procedures for Terminating Vendor and Business Partner Relationships",
            ],
            evidence_requirements=[
                "Vendor contracts",
                "SLA documentation",
                "Vendor performance reviews",
            ],
        )

        # A1 - Availability
        self.CRITERIA_CATALOG["A1.1"] = SOC2Criteria(
            id="A1.1",
            category=SOC2Category.A1,
            title="Maintains Infrastructure for Availability",
            description="The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity to help meet its objectives.",
            principle=TrustServicesPrinciple.AVAILABILITY,
            points_of_focus=[
                "Measures Current Usage",
                "Forecasts Capacity",
                "Makes Changes Based on Forecasts",
            ],
            automated_checks=[
                "auto-scaling-enabled",
                "capacity-monitoring",
            ],
            evidence_requirements=[
                "Capacity planning documentation",
                "Performance monitoring data",
                "Scaling policies",
            ],
        )

        self.CRITERIA_CATALOG["A1.2"] = SOC2Criteria(
            id="A1.2",
            category=SOC2Category.A1,
            title="Manages Environmental Threats",
            description="The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure to meet its objectives.",
            principle=TrustServicesPrinciple.AVAILABILITY,
            points_of_focus=[
                "Identifies Environmental Threats",
                "Designs Detection Measures for Environmental Threats",
                "Implements and Maintains Environmental Protection Mechanisms",
                "Implements Alerts to Analyze Anomalies",
                "Responds to Environmental Threat Events",
                "Communicates and Reviews Detected Environmental Threat Events",
                "Determines Data Requiring Backup",
                "Performs Data Backup",
                "Addresses Offsite Storage",
                "Implements Alternate Processing Infrastructure",
            ],
            automated_checks=[
                "backup-enabled",
                "multi-az-enabled",
                "cross-region-backup",
            ],
            evidence_requirements=[
                "Backup procedures",
                "Recovery testing records",
                "Environmental protection documentation",
            ],
        )

        self.CRITERIA_CATALOG["A1.3"] = SOC2Criteria(
            id="A1.3",
            category=SOC2Category.A1,
            title="Implements Recovery Procedures",
            description="The entity tests recovery plan procedures supporting system recovery to meet its objectives.",
            principle=TrustServicesPrinciple.AVAILABILITY,
            points_of_focus=[
                "Implements Business Continuity Plan Testing",
                "Tests Integrity and Completeness of Backup Data",
                "Tests Recovery Plan Procedures",
            ],
            automated_checks=[
                "dr-test-enabled",
            ],
            evidence_requirements=[
                "DR test results",
                "BCP documentation",
                "Recovery time objectives",
            ],
        )

        # C1 - Confidentiality
        self.CRITERIA_CATALOG["C1.1"] = SOC2Criteria(
            id="C1.1",
            category=SOC2Category.C1,
            title="Identifies Confidential Information",
            description="The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.",
            principle=TrustServicesPrinciple.CONFIDENTIALITY,
            points_of_focus=[
                "Identifies Confidential Information",
                "Classifies Confidential Information",
                "Labels Confidential Information",
            ],
            automated_checks=[
                "data-classification",
                "macie-enabled",
            ],
            evidence_requirements=[
                "Data classification policy",
                "Data inventory",
                "Classification labels",
            ],
        )

        self.CRITERIA_CATALOG["C1.2"] = SOC2Criteria(
            id="C1.2",
            category=SOC2Category.C1,
            title="Disposes of Confidential Information",
            description="The entity disposes of confidential information to meet the entity's objectives related to confidentiality.",
            principle=TrustServicesPrinciple.CONFIDENTIALITY,
            points_of_focus=[
                "Identifies Confidential Information for Disposal",
                "Disposes of Confidential Information",
            ],
            evidence_requirements=[
                "Data retention policy",
                "Disposal procedures",
                "Disposal records",
            ],
        )

        # PI1 - Processing Integrity
        self.CRITERIA_CATALOG["PI1.1"] = SOC2Criteria(
            id="PI1.1",
            category=SOC2Category.PI1,
            title="Obtains Data for Processing",
            description="The entity obtains data for processing to meet the entity's objectives related to processing integrity.",
            principle=TrustServicesPrinciple.PROCESSING_INTEGRITY,
            points_of_focus=[
                "Defines Characteristics of Processing Inputs",
                "Evaluates Processing Inputs",
                "Records Input Data",
            ],
            evidence_requirements=[
                "Input validation procedures",
                "Data quality standards",
                "Input audit trails",
            ],
        )

        self.CRITERIA_CATALOG["PI1.2"] = SOC2Criteria(
            id="PI1.2",
            category=SOC2Category.PI1,
            title="Implements Processing Activities",
            description="The entity implements policies and procedures over system processing to result in products, services, and reporting to meet the entity's objectives.",
            principle=TrustServicesPrinciple.PROCESSING_INTEGRITY,
            points_of_focus=[
                "Defines Processing Specifications",
                "Defines Processing Activities",
                "Defines Outputs",
                "Records and Documents Processing",
            ],
            evidence_requirements=[
                "Processing documentation",
                "System specifications",
                "Output validation procedures",
            ],
        )

        self.CRITERIA_CATALOG["PI1.3"] = SOC2Criteria(
            id="PI1.3",
            category=SOC2Category.PI1,
            title="Provides Processing Outputs",
            description="The entity provides outputs completely, accurately, and timely to meet the entity's objectives related to processing integrity.",
            principle=TrustServicesPrinciple.PROCESSING_INTEGRITY,
            points_of_focus=[
                "Protects Outputs",
                "Distributes Outputs Only to Intended Recipients",
                "Distributes Outputs Completely and Accurately",
                "Creates and Maintains Records of System Output Activities",
            ],
            evidence_requirements=[
                "Output distribution procedures",
                "Reconciliation records",
                "Delivery confirmation",
            ],
        )

        self.CRITERIA_CATALOG["PI1.4"] = SOC2Criteria(
            id="PI1.4",
            category=SOC2Category.PI1,
            title="Enables Tracing of Information",
            description="The entity implements policies and procedures to make available or deliver output completely, accurately, and timely.",
            principle=TrustServicesPrinciple.PROCESSING_INTEGRITY,
            points_of_focus=[
                "Restricts Access to Output",
                "Locates and Retrieves Information",
                "Maintains Records of System Output Activities",
            ],
            evidence_requirements=[
                "Audit trail documentation",
                "Data lineage records",
                "Archive procedures",
            ],
        )

        self.CRITERIA_CATALOG["PI1.5"] = SOC2Criteria(
            id="PI1.5",
            category=SOC2Category.PI1,
            title="Stores Data",
            description="The entity stores inputs, items in processing, and outputs completely, accurately, and timely.",
            principle=TrustServicesPrinciple.PROCESSING_INTEGRITY,
            points_of_focus=[
                "Protects Stored Items",
                "Archives and Protects System Records",
                "Stores Data Completely, Accurately, and Timely",
            ],
            automated_checks=[
                "s3-versioning",
                "backup-retention",
            ],
            evidence_requirements=[
                "Storage procedures",
                "Retention schedules",
                "Archival records",
            ],
        )

    def get_criteria(self, criteria_id: str) -> SOC2Criteria | None:
        """Get a specific criteria by ID."""
        return self.CRITERIA_CATALOG.get(criteria_id)

    def get_criteria_by_category(self, category: SOC2Category) -> list[SOC2Criteria]:
        """Get all criteria for a category."""
        return [
            c for c in self.CRITERIA_CATALOG.values()
            if c.category == category
        ]

    def get_criteria_by_principle(
        self, principle: TrustServicesPrinciple
    ) -> list[SOC2Criteria]:
        """Get all criteria for a principle."""
        return [
            c for c in self.CRITERIA_CATALOG.values()
            if c.principle == principle
        ]

    def map_policy_to_criteria(
        self, policy_id: str, criteria_ids: list[str]
    ) -> None:
        """Map a policy to SOC 2 criteria."""
        self._policy_mappings[policy_id] = criteria_ids

    def get_policies_for_criteria(self, criteria_id: str) -> list[str]:
        """Get policies mapped to a criteria."""
        policies = []
        for policy_id, mapped_criteria in self._policy_mappings.items():
            if criteria_id in mapped_criteria:
                policies.append(policy_id)

        # Also include automated checks from catalog
        criteria = self.get_criteria(criteria_id)
        if criteria:
            policies.extend(criteria.automated_checks)

        return list(set(policies))

    def assess(
        self,
        policies: Any,  # PolicyCollection
        findings: Any,  # FindingCollection
        principles_in_scope: list[TrustServicesPrinciple] | None = None,
        organization_name: str = "",
        assessment_type: str = "Type II",
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> SOC2Assessment:
        """
        Perform SOC 2 assessment.

        Args:
            policies: Collection of policies to evaluate
            findings: Collection of findings from evaluation
            principles_in_scope: Which principles to assess
            organization_name: Name of organization
            assessment_type: Type I or Type II
            period_start: Assessment period start
            period_end: Assessment period end

        Returns:
            SOC2Assessment with detailed results
        """
        if principles_in_scope is None:
            principles_in_scope = [TrustServicesPrinciple.SECURITY]

        if period_start is None:
            period_start = datetime.now(timezone.utc)
        if period_end is None:
            period_end = datetime.now(timezone.utc)

        principle_assessments: list[PrincipleAssessment] = []

        for principle in principles_in_scope:
            criteria_list = self.get_criteria_by_principle(principle)
            criteria_assessments: list[CriteriaAssessment] = []

            for criteria in criteria_list:
                assessment = self._assess_criteria(criteria, policies, findings)
                criteria_assessments.append(assessment)

            principle_assessments.append(
                PrincipleAssessment(
                    principle=principle,
                    criteria_assessments=criteria_assessments,
                )
            )

        return SOC2Assessment(
            assessment_type=assessment_type,
            assessment_period_start=period_start,
            assessment_period_end=period_end,
            organization_name=organization_name,
            system_description="",
            principles_in_scope=principles_in_scope,
            principle_assessments=principle_assessments,
        )

    def _assess_criteria(
        self,
        criteria: SOC2Criteria,
        policies: Any,
        findings: Any,
    ) -> CriteriaAssessment:
        """Assess a single SOC 2 criteria."""
        related_policies = self.get_policies_for_criteria(criteria.id)

        if not related_policies:
            return CriteriaAssessment(
                criteria_id=criteria.id,
                criteria_title=criteria.title,
                category=criteria.category,
                principle=criteria.principle,
                status=ControlTestStatus.NOT_TESTED,
                notes="No automated controls mapped to this criteria",
            )

        controls_tested = 0
        controls_passed = 0
        related_findings: list[str] = []

        for policy_id in related_policies:
            # Find policy
            policy = None
            for p in policies:
                if p.id == policy_id:
                    policy = p
                    break

            if not policy:
                continue

            controls_tested += 1

            # Check for findings
            policy_findings = [f for f in findings if f.rule_id == policy_id]

            if not policy_findings:
                controls_passed += 1
            else:
                for f in policy_findings:
                    related_findings.append(f.id)

        if controls_tested == 0:
            status = ControlTestStatus.NOT_TESTED
        elif controls_passed == controls_tested:
            status = ControlTestStatus.PASSED
        else:
            status = ControlTestStatus.FAILED

        return CriteriaAssessment(
            criteria_id=criteria.id,
            criteria_title=criteria.title,
            category=criteria.category,
            principle=criteria.principle,
            status=status,
            controls_tested=controls_tested,
            controls_passed=controls_passed,
            controls_failed=controls_tested - controls_passed,
            findings=related_findings,
        )

    def generate_report(
        self,
        assessment: SOC2Assessment,
        include_evidence: bool = True,
    ) -> dict[str, Any]:
        """Generate a detailed SOC 2 report."""
        report = assessment.to_dict()

        if include_evidence:
            report["evidence_summary"] = self._generate_evidence_summary(assessment)

        report["recommendations"] = self._generate_recommendations(assessment)

        return report

    def _generate_evidence_summary(
        self, assessment: SOC2Assessment
    ) -> dict[str, list[str]]:
        """Generate evidence requirements summary."""
        evidence: dict[str, list[str]] = {}

        for pa in assessment.principle_assessments:
            for ca in pa.criteria_assessments:
                criteria = self.get_criteria(ca.criteria_id)
                if criteria and criteria.evidence_requirements:
                    evidence[ca.criteria_id] = criteria.evidence_requirements

        return evidence

    def _generate_recommendations(
        self, assessment: SOC2Assessment
    ) -> list[dict[str, Any]]:
        """Generate recommendations based on assessment."""
        recommendations = []

        for pa in assessment.principle_assessments:
            for ca in pa.criteria_assessments:
                if ca.status == ControlTestStatus.FAILED:
                    recommendations.append({
                        "criteria_id": ca.criteria_id,
                        "criteria_title": ca.criteria_title,
                        "priority": "high",
                        "finding_count": ca.controls_failed,
                        "recommendation": f"Remediate {ca.controls_failed} failing controls for {ca.criteria_title}",
                    })
                elif ca.status == ControlTestStatus.NOT_TESTED:
                    recommendations.append({
                        "criteria_id": ca.criteria_id,
                        "criteria_title": ca.criteria_title,
                        "priority": "medium",
                        "finding_count": 0,
                        "recommendation": f"Implement automated controls for {ca.criteria_title}",
                    })

        return sorted(recommendations, key=lambda x: (
            0 if x["priority"] == "high" else 1,
            -x["finding_count"],
        ))

    def get_control_matrix(
        self, principles: list[TrustServicesPrinciple] | None = None
    ) -> list[dict[str, Any]]:
        """Generate a control matrix for documentation."""
        if principles is None:
            principles = list(TrustServicesPrinciple)

        matrix = []
        for principle in principles:
            for criteria in self.get_criteria_by_principle(principle):
                policies = self.get_policies_for_criteria(criteria.id)
                matrix.append({
                    "principle": principle.value,
                    "category": criteria.category.value,
                    "criteria_id": criteria.id,
                    "criteria_title": criteria.title,
                    "points_of_focus": criteria.points_of_focus,
                    "automated_controls": policies,
                    "evidence_requirements": criteria.evidence_requirements,
                })

        return matrix
