"""
Certificate monitoring for Exposure Management.

Discovers SSL/TLS certificates from cloud resources (load balancers, CDNs,
app services) and generates findings for expiring or misconfigured certificates.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class CertificateStatus(Enum):
    """Status of a certificate."""

    ACTIVE = "active"  # Valid and in use
    EXPIRED = "expired"  # Past expiration date
    EXPIRING_SOON = "expiring_soon"  # Within threshold
    REVOKED = "revoked"  # Certificate revoked
    PENDING = "pending"  # Pending issuance/validation
    FAILED = "failed"  # Issuance/validation failed
    INACTIVE = "inactive"  # Not in use
    UNKNOWN = "unknown"  # Status unknown


class CertificateType(Enum):
    """Type of certificate."""

    MANAGED = "managed"  # Cloud-managed (auto-renewed)
    IMPORTED = "imported"  # User-imported
    SELF_SIGNED = "self_signed"  # Self-signed
    PRIVATE_CA = "private_ca"  # From private CA


class CertificateFindingType(Enum):
    """Types of certificate-related findings."""

    # Expiration
    CERT_EXPIRING_30_DAYS = "cert_expiring_30_days"
    CERT_EXPIRING_14_DAYS = "cert_expiring_14_days"
    CERT_EXPIRING_7_DAYS = "cert_expiring_7_days"
    CERT_EXPIRED = "cert_expired"

    # Security
    CERT_WEAK_ALGORITHM = "cert_weak_algorithm"  # SHA-1, MD5, etc.
    CERT_SHORT_KEY = "cert_short_key"  # RSA < 2048, ECDSA < 256
    CERT_SELF_SIGNED = "cert_self_signed_public"  # Self-signed on public endpoint

    # Configuration
    CERT_NOT_IN_USE = "cert_not_in_use"  # Certificate not attached
    CERT_PENDING_VALIDATION = "cert_pending_validation"  # DNS/email validation needed
    CERT_RENEWAL_FAILED = "cert_renewal_failed"  # Auto-renewal failed


class CertificateSeverity(Enum):
    """Severity levels for certificate findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison."""
        ranks = {
            CertificateSeverity.CRITICAL: 5,
            CertificateSeverity.HIGH: 4,
            CertificateSeverity.MEDIUM: 3,
            CertificateSeverity.LOW: 2,
            CertificateSeverity.INFO: 1,
        }
        return ranks.get(self, 0)

    def __gt__(self, other: "CertificateSeverity") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "CertificateSeverity") -> bool:
        return self.rank >= other.rank

    def __lt__(self, other: "CertificateSeverity") -> bool:
        return self.rank < other.rank

    def __le__(self, other: "CertificateSeverity") -> bool:
        return self.rank <= other.rank


@dataclass
class CertificateConfig:
    """
    Configuration for certificate monitoring.

    Attributes:
        warning_threshold_days: Days before expiration to warn
        critical_threshold_days: Days before expiration for critical
        check_key_strength: Whether to check key strength
        check_algorithm: Whether to check signature algorithm
        min_rsa_key_size: Minimum RSA key size in bits
        min_ecdsa_key_size: Minimum ECDSA key size in bits
        weak_algorithms: Algorithms considered weak
        include_inactive: Whether to include inactive certificates
        cloud_providers: Cloud providers to check
    """

    warning_threshold_days: int = 30
    critical_threshold_days: int = 7
    check_key_strength: bool = True
    check_algorithm: bool = True
    min_rsa_key_size: int = 2048
    min_ecdsa_key_size: int = 256
    weak_algorithms: list[str] = field(
        default_factory=lambda: ["sha1", "md5", "sha1WithRSAEncryption", "md5WithRSAEncryption"]
    )
    include_inactive: bool = False
    cloud_providers: list[str] = field(default_factory=lambda: ["aws", "gcp", "azure"])


@dataclass
class Certificate:
    """
    Represents an SSL/TLS certificate.

    Attributes:
        certificate_id: Unique identifier (ARN, resource ID, etc.)
        name: Human-readable name or domain
        cloud_provider: Cloud provider (aws, gcp, azure)
        account_id: Account/project ID
        region: Region where certificate is located
        certificate_type: Type of certificate
        status: Current status
        domains: List of domains covered
        primary_domain: Primary/common name domain
        not_before: Certificate valid from
        not_after: Certificate expires at
        days_until_expiry: Days until expiration (negative if expired)
        issuer: Certificate issuer
        key_algorithm: Key algorithm (RSA, ECDSA)
        key_size: Key size in bits
        signature_algorithm: Signature algorithm
        is_managed: Whether auto-renewed
        attached_resources: Resources using this certificate
        serial_number: Certificate serial number
        thumbprint: Certificate thumbprint/fingerprint
        detected_at: When certificate was discovered
        metadata: Additional metadata
    """

    certificate_id: str
    name: str
    cloud_provider: str
    account_id: str
    region: str
    certificate_type: CertificateType
    status: CertificateStatus
    domains: list[str]
    primary_domain: str
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_until_expiry: int = 0
    issuer: str = ""
    key_algorithm: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    is_managed: bool = False
    attached_resources: list[str] = field(default_factory=list)
    serial_number: str = ""
    thumbprint: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Calculate days until expiry if not_after is set."""
        if self.not_after:
            now = datetime.now(timezone.utc)
            if self.not_after.tzinfo is None:
                not_after = self.not_after.replace(tzinfo=timezone.utc)
            else:
                not_after = self.not_after
            delta = not_after - now
            self.days_until_expiry = delta.days

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        return self.days_until_expiry < 0

    @property
    def is_expiring_soon(self) -> bool:
        """Check if certificate expires within 30 days."""
        return 0 <= self.days_until_expiry <= 30

    @property
    def is_in_use(self) -> bool:
        """Check if certificate is attached to resources."""
        return len(self.attached_resources) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "certificate_id": self.certificate_id,
            "name": self.name,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "region": self.region,
            "certificate_type": self.certificate_type.value,
            "status": self.status.value,
            "domains": self.domains,
            "primary_domain": self.primary_domain,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_until_expiry": self.days_until_expiry,
            "issuer": self.issuer,
            "key_algorithm": self.key_algorithm,
            "key_size": self.key_size,
            "signature_algorithm": self.signature_algorithm,
            "is_managed": self.is_managed,
            "attached_resources": self.attached_resources,
            "serial_number": self.serial_number,
            "thumbprint": self.thumbprint,
            "detected_at": self.detected_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class CertificateFinding:
    """
    A finding about a certificate issue.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level
        title: Short title
        description: Detailed description
        certificate_id: Affected certificate ID
        certificate_name: Certificate name/domain
        cloud_provider: Cloud provider
        region: Region
        days_until_expiry: Days until expiration
        attached_resources: Resources using this certificate
        recommended_action: Suggested remediation
        detected_at: When finding was generated
        metadata: Additional context
    """

    finding_id: str
    finding_type: CertificateFindingType
    severity: CertificateSeverity
    title: str
    description: str
    certificate_id: str
    certificate_name: str
    cloud_provider: str
    region: str
    days_until_expiry: int = 0
    attached_resources: list[str] = field(default_factory=list)
    recommended_action: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "certificate_id": self.certificate_id,
            "certificate_name": self.certificate_name,
            "cloud_provider": self.cloud_provider,
            "region": self.region,
            "days_until_expiry": self.days_until_expiry,
            "attached_resources": self.attached_resources,
            "recommended_action": self.recommended_action,
            "detected_at": self.detected_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class CertificateSummary:
    """
    Summary statistics for certificate monitoring.

    Attributes:
        total_certificates: Total number of certificates
        active_certificates: Certificates in active status
        expired_certificates: Expired certificates
        expiring_7_days: Expiring within 7 days
        expiring_14_days: Expiring within 14 days
        expiring_30_days: Expiring within 30 days
        managed_certificates: Auto-renewed certificates
        imported_certificates: User-imported certificates
        certificates_by_cloud: Count by cloud provider
        certificates_by_region: Count by region
        findings_by_severity: Count of findings by severity
    """

    total_certificates: int = 0
    active_certificates: int = 0
    expired_certificates: int = 0
    expiring_7_days: int = 0
    expiring_14_days: int = 0
    expiring_30_days: int = 0
    managed_certificates: int = 0
    imported_certificates: int = 0
    certificates_by_cloud: dict[str, int] = field(default_factory=dict)
    certificates_by_region: dict[str, int] = field(default_factory=dict)
    findings_by_severity: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_certificates": self.total_certificates,
            "active_certificates": self.active_certificates,
            "expired_certificates": self.expired_certificates,
            "expiring_7_days": self.expiring_7_days,
            "expiring_14_days": self.expiring_14_days,
            "expiring_30_days": self.expiring_30_days,
            "managed_certificates": self.managed_certificates,
            "imported_certificates": self.imported_certificates,
            "certificates_by_cloud": self.certificates_by_cloud,
            "certificates_by_region": self.certificates_by_region,
            "findings_by_severity": self.findings_by_severity,
        }


@dataclass
class CertificateMonitoringResult:
    """
    Result of certificate monitoring.

    Attributes:
        result_id: Unique identifier
        config: Configuration used
        started_at: Monitoring start time
        completed_at: Monitoring completion time
        certificates: List of certificates discovered
        findings: List of certificate findings
        summary: Summary statistics
        errors: Errors encountered
    """

    result_id: str
    config: CertificateConfig
    started_at: datetime
    completed_at: datetime | None = None
    certificates: list[Certificate] = field(default_factory=list)
    findings: list[CertificateFinding] = field(default_factory=list)
    summary: CertificateSummary = field(default_factory=CertificateSummary)
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Check if monitoring has any findings."""
        return len(self.findings) > 0

    @property
    def critical_findings(self) -> list[CertificateFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == CertificateSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[CertificateFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == CertificateSeverity.HIGH]

    @property
    def expiring_certificates(self) -> list[Certificate]:
        """Get certificates expiring within threshold."""
        return [c for c in self.certificates if c.is_expiring_soon]

    @property
    def expired_certificates(self) -> list[Certificate]:
        """Get expired certificates."""
        return [c for c in self.certificates if c.is_expired]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "result_id": self.result_id,
            "config": {
                "warning_threshold_days": self.config.warning_threshold_days,
                "critical_threshold_days": self.config.critical_threshold_days,
                "check_key_strength": self.config.check_key_strength,
                "check_algorithm": self.config.check_algorithm,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_certificates": len(self.certificates),
            "certificates": [c.to_dict() for c in self.certificates],
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
            "errors": self.errors,
        }


class BaseCertificateCollector(ABC):
    """
    Abstract base class for certificate collectors.

    Subclasses implement cloud-specific logic for discovering certificates.
    """

    collector_name = "base"

    def __init__(self, config: CertificateConfig | None = None):
        """
        Initialize the certificate collector.

        Args:
            config: Optional configuration for collection
        """
        self._config = config or CertificateConfig()

    @property
    def config(self) -> CertificateConfig:
        """Get the collection configuration."""
        return self._config

    @abstractmethod
    def collect_certificates(self) -> Iterator[Certificate]:
        """
        Collect certificates from the cloud provider.

        Yields:
            Certificates discovered
        """
        pass


class CertificateMonitor:
    """
    Monitors certificates across cloud providers.

    Aggregates certificates from multiple collectors and generates
    findings for expiring or misconfigured certificates.
    """

    def __init__(
        self,
        certificates: list[Certificate] | None = None,
        config: CertificateConfig | None = None,
    ):
        """
        Initialize the certificate monitor.

        Args:
            certificates: List of certificates to monitor
            config: Optional configuration
        """
        self._certificates = certificates or []
        self._config = config or CertificateConfig()

    @property
    def certificates(self) -> list[Certificate]:
        """Get the list of certificates."""
        return self._certificates

    @property
    def config(self) -> CertificateConfig:
        """Get the configuration."""
        return self._config

    def add_certificates(self, certificates: list[Certificate]) -> None:
        """Add certificates to monitor."""
        self._certificates.extend(certificates)

    def analyze(self) -> CertificateMonitoringResult:
        """
        Analyze certificates and generate findings.

        Returns:
            Certificate monitoring result with findings
        """
        started_at = datetime.now(timezone.utc)
        findings: list[CertificateFinding] = []

        for cert in self._certificates:
            cert_findings = self._analyze_certificate(cert)
            findings.extend(cert_findings)

        summary = self._build_summary(self._certificates, findings)
        completed_at = datetime.now(timezone.utc)

        return CertificateMonitoringResult(
            result_id=str(uuid.uuid4()),
            config=self._config,
            started_at=started_at,
            completed_at=completed_at,
            certificates=self._certificates,
            findings=findings,
            summary=summary,
        )

    def _analyze_certificate(self, cert: Certificate) -> list[CertificateFinding]:
        """Analyze a single certificate for issues."""
        findings: list[CertificateFinding] = []

        # Check expiration
        expiry_finding = self._check_expiration(cert)
        if expiry_finding:
            findings.append(expiry_finding)

        # Check key strength
        if self._config.check_key_strength:
            key_finding = self._check_key_strength(cert)
            if key_finding:
                findings.append(key_finding)

        # Check signature algorithm
        if self._config.check_algorithm:
            algo_finding = self._check_algorithm(cert)
            if algo_finding:
                findings.append(algo_finding)

        # Check for self-signed on public endpoints
        if cert.certificate_type == CertificateType.SELF_SIGNED and cert.is_in_use:
            findings.append(self._create_self_signed_finding(cert))

        # Check for pending validation
        if cert.status == CertificateStatus.PENDING:
            findings.append(self._create_pending_validation_finding(cert))

        return findings

    def _check_expiration(self, cert: Certificate) -> CertificateFinding | None:
        """Check certificate expiration status."""
        if cert.is_expired:
            return CertificateFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=CertificateFindingType.CERT_EXPIRED,
                severity=CertificateSeverity.CRITICAL,
                title=f"Certificate expired: {cert.primary_domain}",
                description=(
                    f"Certificate for {cert.primary_domain} expired "
                    f"{abs(cert.days_until_expiry)} days ago."
                ),
                certificate_id=cert.certificate_id,
                certificate_name=cert.name,
                cloud_provider=cert.cloud_provider,
                region=cert.region,
                days_until_expiry=cert.days_until_expiry,
                attached_resources=cert.attached_resources,
                recommended_action="Renew or replace the certificate immediately.",
            )

        if cert.days_until_expiry <= self._config.critical_threshold_days:
            return CertificateFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=CertificateFindingType.CERT_EXPIRING_7_DAYS,
                severity=CertificateSeverity.CRITICAL,
                title=f"Certificate expiring in {cert.days_until_expiry} days: {cert.primary_domain}",
                description=(
                    f"Certificate for {cert.primary_domain} expires in "
                    f"{cert.days_until_expiry} days."
                ),
                certificate_id=cert.certificate_id,
                certificate_name=cert.name,
                cloud_provider=cert.cloud_provider,
                region=cert.region,
                days_until_expiry=cert.days_until_expiry,
                attached_resources=cert.attached_resources,
                recommended_action="Renew the certificate before expiration.",
            )

        if cert.days_until_expiry <= 14:
            return CertificateFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=CertificateFindingType.CERT_EXPIRING_14_DAYS,
                severity=CertificateSeverity.HIGH,
                title=f"Certificate expiring in {cert.days_until_expiry} days: {cert.primary_domain}",
                description=(
                    f"Certificate for {cert.primary_domain} expires in "
                    f"{cert.days_until_expiry} days."
                ),
                certificate_id=cert.certificate_id,
                certificate_name=cert.name,
                cloud_provider=cert.cloud_provider,
                region=cert.region,
                days_until_expiry=cert.days_until_expiry,
                attached_resources=cert.attached_resources,
                recommended_action="Plan certificate renewal soon.",
            )

        if cert.days_until_expiry <= self._config.warning_threshold_days:
            return CertificateFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=CertificateFindingType.CERT_EXPIRING_30_DAYS,
                severity=CertificateSeverity.MEDIUM,
                title=f"Certificate expiring in {cert.days_until_expiry} days: {cert.primary_domain}",
                description=(
                    f"Certificate for {cert.primary_domain} expires in "
                    f"{cert.days_until_expiry} days."
                ),
                certificate_id=cert.certificate_id,
                certificate_name=cert.name,
                cloud_provider=cert.cloud_provider,
                region=cert.region,
                days_until_expiry=cert.days_until_expiry,
                attached_resources=cert.attached_resources,
                recommended_action="Schedule certificate renewal.",
            )

        return None

    def _check_key_strength(self, cert: Certificate) -> CertificateFinding | None:
        """Check certificate key strength."""
        if not cert.key_algorithm or not cert.key_size:
            return None

        is_weak = False
        if cert.key_algorithm.upper() == "RSA" and cert.key_size < self._config.min_rsa_key_size:
            is_weak = True
        elif (
            cert.key_algorithm.upper() in ("ECDSA", "EC")
            and cert.key_size < self._config.min_ecdsa_key_size
        ):
            is_weak = True

        if is_weak:
            return CertificateFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=CertificateFindingType.CERT_SHORT_KEY,
                severity=CertificateSeverity.HIGH,
                title=f"Weak key strength: {cert.primary_domain}",
                description=(
                    f"Certificate for {cert.primary_domain} uses {cert.key_algorithm} "
                    f"with {cert.key_size}-bit key. Minimum recommended is "
                    f"{self._config.min_rsa_key_size} bits for RSA or "
                    f"{self._config.min_ecdsa_key_size} bits for ECDSA."
                ),
                certificate_id=cert.certificate_id,
                certificate_name=cert.name,
                cloud_provider=cert.cloud_provider,
                region=cert.region,
                days_until_expiry=cert.days_until_expiry,
                attached_resources=cert.attached_resources,
                recommended_action="Replace with a certificate using stronger key.",
                metadata={"key_algorithm": cert.key_algorithm, "key_size": cert.key_size},
            )

        return None

    def _check_algorithm(self, cert: Certificate) -> CertificateFinding | None:
        """Check certificate signature algorithm."""
        if not cert.signature_algorithm:
            return None

        for weak_algo in self._config.weak_algorithms:
            if weak_algo.lower() in cert.signature_algorithm.lower():
                return CertificateFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=CertificateFindingType.CERT_WEAK_ALGORITHM,
                    severity=CertificateSeverity.HIGH,
                    title=f"Weak signature algorithm: {cert.primary_domain}",
                    description=(
                        f"Certificate for {cert.primary_domain} uses weak signature "
                        f"algorithm: {cert.signature_algorithm}. This is vulnerable to "
                        "collision attacks."
                    ),
                    certificate_id=cert.certificate_id,
                    certificate_name=cert.name,
                    cloud_provider=cert.cloud_provider,
                    region=cert.region,
                    days_until_expiry=cert.days_until_expiry,
                    attached_resources=cert.attached_resources,
                    recommended_action="Replace with a certificate using SHA-256 or better.",
                    metadata={"signature_algorithm": cert.signature_algorithm},
                )

        return None

    def _create_self_signed_finding(self, cert: Certificate) -> CertificateFinding:
        """Create finding for self-signed certificate on public endpoint."""
        return CertificateFinding(
            finding_id=str(uuid.uuid4()),
            finding_type=CertificateFindingType.CERT_SELF_SIGNED,
            severity=CertificateSeverity.MEDIUM,
            title=f"Self-signed certificate in use: {cert.primary_domain}",
            description=(
                f"Self-signed certificate for {cert.primary_domain} is attached to "
                f"{len(cert.attached_resources)} resource(s). Self-signed certificates "
                "cause browser warnings and may indicate a security issue."
            ),
            certificate_id=cert.certificate_id,
            certificate_name=cert.name,
            cloud_provider=cert.cloud_provider,
            region=cert.region,
            days_until_expiry=cert.days_until_expiry,
            attached_resources=cert.attached_resources,
            recommended_action="Replace with a certificate from a trusted CA.",
        )

    def _create_pending_validation_finding(self, cert: Certificate) -> CertificateFinding:
        """Create finding for certificate pending validation."""
        return CertificateFinding(
            finding_id=str(uuid.uuid4()),
            finding_type=CertificateFindingType.CERT_PENDING_VALIDATION,
            severity=CertificateSeverity.MEDIUM,
            title=f"Certificate pending validation: {cert.primary_domain}",
            description=(
                f"Certificate for {cert.primary_domain} is pending domain validation. "
                "Complete the DNS or email validation to activate the certificate."
            ),
            certificate_id=cert.certificate_id,
            certificate_name=cert.name,
            cloud_provider=cert.cloud_provider,
            region=cert.region,
            days_until_expiry=cert.days_until_expiry,
            attached_resources=cert.attached_resources,
            recommended_action="Complete domain validation (DNS or email).",
        )

    def _build_summary(
        self,
        certificates: list[Certificate],
        findings: list[CertificateFinding],
    ) -> CertificateSummary:
        """Build summary statistics."""
        summary = CertificateSummary(total_certificates=len(certificates))

        for cert in certificates:
            # Status counts
            if cert.status == CertificateStatus.ACTIVE:
                summary.active_certificates += 1
            if cert.is_expired:
                summary.expired_certificates += 1

            # Expiration counts
            if 0 <= cert.days_until_expiry <= 7:
                summary.expiring_7_days += 1
            elif 7 < cert.days_until_expiry <= 14:
                summary.expiring_14_days += 1
            elif 14 < cert.days_until_expiry <= 30:
                summary.expiring_30_days += 1

            # Type counts
            if cert.is_managed:
                summary.managed_certificates += 1
            if cert.certificate_type == CertificateType.IMPORTED:
                summary.imported_certificates += 1

            # Cloud counts
            summary.certificates_by_cloud[cert.cloud_provider] = (
                summary.certificates_by_cloud.get(cert.cloud_provider, 0) + 1
            )

            # Region counts
            summary.certificates_by_region[cert.region] = (
                summary.certificates_by_region.get(cert.region, 0) + 1
            )

        # Finding severity counts
        for finding in findings:
            severity = finding.severity.value
            summary.findings_by_severity[severity] = (
                summary.findings_by_severity.get(severity, 0) + 1
            )

        return summary

    def get_expiring_certificates(self, within_days: int = 30) -> list[Certificate]:
        """Get certificates expiring within specified days."""
        return [c for c in self._certificates if 0 <= c.days_until_expiry <= within_days]

    def get_certificates_by_cloud(self, cloud_provider: str) -> list[Certificate]:
        """Get certificates for a specific cloud provider."""
        return [c for c in self._certificates if c.cloud_provider == cloud_provider]

    def get_certificates_by_domain(self, domain: str) -> list[Certificate]:
        """Get certificates covering a specific domain."""
        return [c for c in self._certificates if domain in c.domains or domain == c.primary_domain]


class AWSCertificateCollector(BaseCertificateCollector):
    """
    Collects certificates from AWS (ACM, CloudFront, ELB).

    Discovers certificates from:
    - AWS Certificate Manager (ACM)
    - CloudFront distributions
    - Classic and Application Load Balancers
    """

    collector_name = "aws_certificates"

    def __init__(
        self,
        session: Any = None,
        region: str = "us-east-1",
        config: CertificateConfig | None = None,
    ):
        """
        Initialize the AWS certificate collector.

        Args:
            session: Optional boto3 session
            region: AWS region (default: us-east-1)
            config: Optional configuration
        """
        super().__init__(config)
        self._session = session
        self._region = region
        self._account_id: str | None = None
        self._clients: dict[str, Any] = {}

    def _get_client(self, service: str, region: str | None = None) -> Any:
        """Get a boto3 client for the specified service."""
        if self._session is None:
            try:
                import boto3

                self._session = boto3.Session()
            except ImportError:
                raise ImportError("boto3 is required for AWS certificate collection")

        use_region = region or self._region
        cache_key = f"{service}:{use_region}"
        if cache_key not in self._clients:
            self._clients[cache_key] = self._session.client(service, region_name=use_region)
        return self._clients[cache_key]

    @property
    def account_id(self) -> str:
        """Get the AWS account ID."""
        if self._account_id is None:
            sts = self._get_client("sts")
            identity = sts.get_caller_identity()
            self._account_id = identity["Account"]
        return self._account_id

    def collect_certificates(self) -> Iterator[Certificate]:
        """Collect certificates from ACM."""
        yield from self._collect_acm_certificates()

    def _collect_acm_certificates(self) -> Iterator[Certificate]:
        """Collect certificates from AWS Certificate Manager."""
        acm = self._get_client("acm")

        try:
            paginator = acm.get_paginator("list_certificates")
            for page in paginator.paginate():
                for cert_summary in page.get("CertificateSummaryList", []):
                    cert_arn = cert_summary.get("CertificateArn", "")
                    try:
                        cert_details = acm.describe_certificate(CertificateArn=cert_arn)
                        cert = cert_details.get("Certificate", {})
                        yield self._parse_acm_certificate(cert)
                    except Exception as e:
                        logger.warning(f"Failed to get certificate details for {cert_arn}: {e}")
        except Exception as e:
            logger.error(f"Failed to list ACM certificates: {e}")

    def _parse_acm_certificate(self, cert: dict[str, Any]) -> Certificate:
        """Parse ACM certificate details into Certificate model."""
        cert_arn = cert.get("CertificateArn", "")
        domain_name = cert.get("DomainName", "")

        # Determine certificate type
        cert_type_str = cert.get("Type", "")
        if cert_type_str == "AMAZON_ISSUED":
            cert_type = CertificateType.MANAGED
        elif cert_type_str == "IMPORTED":
            cert_type = CertificateType.IMPORTED
        elif cert_type_str == "PRIVATE":
            cert_type = CertificateType.PRIVATE_CA
        else:
            cert_type = CertificateType.IMPORTED

        # Determine status
        status_str = cert.get("Status", "")
        status_map = {
            "ISSUED": CertificateStatus.ACTIVE,
            "PENDING_VALIDATION": CertificateStatus.PENDING,
            "INACTIVE": CertificateStatus.INACTIVE,
            "EXPIRED": CertificateStatus.EXPIRED,
            "VALIDATION_TIMED_OUT": CertificateStatus.FAILED,
            "REVOKED": CertificateStatus.REVOKED,
            "FAILED": CertificateStatus.FAILED,
        }
        status = status_map.get(status_str, CertificateStatus.UNKNOWN)

        # Collect domains
        domains = [domain_name]
        for san in cert.get("SubjectAlternativeNames", []):
            if san not in domains:
                domains.append(san)

        # Get attached resources
        attached_resources = cert.get("InUseBy", [])

        # Parse dates
        not_before = cert.get("NotBefore")
        not_after = cert.get("NotAfter")

        # Get key algorithm info
        key_algo = cert.get("KeyAlgorithm", "")
        key_algorithm = ""
        key_size = 0
        if key_algo:
            if "RSA" in key_algo.upper():
                key_algorithm = "RSA"
                # Extract size (e.g., RSA_2048 -> 2048)
                parts = key_algo.split("_")
                if len(parts) > 1 and parts[1].isdigit():
                    key_size = int(parts[1])
            elif "EC" in key_algo.upper() or "ECDSA" in key_algo.upper():
                key_algorithm = "ECDSA"
                parts = key_algo.split("_")
                if len(parts) > 1 and parts[1].isdigit():
                    key_size = int(parts[1])

        return Certificate(
            certificate_id=cert_arn,
            name=domain_name,
            cloud_provider="aws",
            account_id=self.account_id,
            region=self._region,
            certificate_type=cert_type,
            status=status,
            domains=domains,
            primary_domain=domain_name,
            not_before=not_before,
            not_after=not_after,
            issuer=cert.get("Issuer", ""),
            key_algorithm=key_algorithm,
            key_size=key_size,
            signature_algorithm=cert.get("SignatureAlgorithm", ""),
            is_managed=cert_type == CertificateType.MANAGED,
            attached_resources=attached_resources,
            serial_number=cert.get("Serial", ""),
            metadata={
                "renewal_eligibility": cert.get("RenewalEligibility", ""),
                "renewal_status": cert.get("RenewalSummary", {}).get("RenewalStatus", ""),
                "domain_validation_options": cert.get("DomainValidationOptions", []),
            },
        )


class GCPCertificateCollector(BaseCertificateCollector):
    """
    Collects certificates from GCP (Compute SSL, Certificate Manager).

    Discovers certificates from:
    - Compute Engine SSL certificates
    - Certificate Manager
    - Load Balancers
    """

    collector_name = "gcp_certificates"

    def __init__(
        self,
        project_id: str | None = None,
        credentials: Any = None,
        config: CertificateConfig | None = None,
    ):
        """
        Initialize the GCP certificate collector.

        Args:
            project_id: GCP project ID
            credentials: Optional GCP credentials
            config: Optional configuration
        """
        super().__init__(config)
        self._project_id = project_id
        self._credentials = credentials
        self._compute_client: Any = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        if self._project_id is None:
            raise ValueError("project_id is required for GCP certificate collection")
        return self._project_id

    def _get_compute_client(self) -> Any:
        """Get Compute Engine client."""
        if self._compute_client is None:
            try:
                from google.cloud import compute_v1

                self._compute_client = compute_v1.SslCertificatesClient(
                    credentials=self._credentials
                )
            except ImportError:
                raise ImportError(
                    "google-cloud-compute is required for GCP certificate collection"
                )
        return self._compute_client

    def collect_certificates(self) -> Iterator[Certificate]:
        """Collect certificates from GCP."""
        yield from self._collect_compute_ssl_certificates()

    def _collect_compute_ssl_certificates(self) -> Iterator[Certificate]:
        """Collect SSL certificates from Compute Engine."""
        try:
            client = self._get_compute_client()
            request = {"project": self.project_id}

            for cert in client.list(request=request):
                yield self._parse_compute_certificate(cert)
        except Exception as e:
            logger.error(f"Failed to list GCP SSL certificates: {e}")

    def _parse_compute_certificate(self, cert: Any) -> Certificate:
        """Parse GCP Compute SSL certificate."""
        # Determine if managed or self-managed
        is_managed = getattr(cert, "managed", None) is not None
        cert_type = CertificateType.MANAGED if is_managed else CertificateType.IMPORTED

        # Get domains
        domains = []
        if is_managed and cert.managed:
            domains = list(getattr(cert.managed, "domains", []))
        primary_domain = domains[0] if domains else cert.name

        # Parse expiration
        not_after = None
        expire_time = getattr(cert, "expire_time", None)
        if expire_time:
            try:
                not_after = datetime.fromisoformat(expire_time.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        # Determine status
        status = CertificateStatus.ACTIVE
        if is_managed and cert.managed:
            managed_status = getattr(cert.managed, "status", "")
            if managed_status == "PROVISIONING":
                status = CertificateStatus.PENDING
            elif managed_status == "PROVISIONING_FAILED":
                status = CertificateStatus.FAILED

        return Certificate(
            certificate_id=f"projects/{self.project_id}/global/sslCertificates/{cert.name}",
            name=cert.name,
            cloud_provider="gcp",
            account_id=self.project_id,
            region="global",
            certificate_type=cert_type,
            status=status,
            domains=domains,
            primary_domain=primary_domain,
            not_after=not_after,
            is_managed=is_managed,
            metadata={
                "self_link": getattr(cert, "self_link", ""),
                "creation_timestamp": getattr(cert, "creation_timestamp", ""),
            },
        )


class AzureCertificateCollector(BaseCertificateCollector):
    """
    Collects certificates from Azure (App Service, Front Door, Key Vault).

    Discovers certificates from:
    - App Service certificates
    - Azure Front Door
    - Key Vault certificates
    """

    collector_name = "azure_certificates"

    def __init__(
        self,
        subscription_id: str | None = None,
        credential: Any = None,
        config: CertificateConfig | None = None,
    ):
        """
        Initialize the Azure certificate collector.

        Args:
            subscription_id: Azure subscription ID
            credential: Optional Azure credential
            config: Optional configuration
        """
        super().__init__(config)
        self._subscription_id = subscription_id
        self._credential = credential
        self._web_client: Any = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        if self._subscription_id is None:
            raise ValueError("subscription_id is required for Azure certificate collection")
        return self._subscription_id

    def _get_web_client(self) -> Any:
        """Get Web Site Management client."""
        if self._web_client is None:
            try:
                from azure.mgmt.web import WebSiteManagementClient

                if self._credential is None:
                    from azure.identity import DefaultAzureCredential

                    self._credential = DefaultAzureCredential()
                self._web_client = WebSiteManagementClient(
                    self._credential, self._subscription_id
                )
            except ImportError:
                raise ImportError(
                    "azure-mgmt-web is required for Azure certificate collection"
                )
        return self._web_client

    def collect_certificates(self) -> Iterator[Certificate]:
        """Collect certificates from Azure."""
        yield from self._collect_app_service_certificates()

    def _collect_app_service_certificates(self) -> Iterator[Certificate]:
        """Collect App Service certificates."""
        try:
            client = self._get_web_client()
            for cert in client.certificates.list():
                yield self._parse_app_service_certificate(cert)
        except Exception as e:
            logger.error(f"Failed to list Azure App Service certificates: {e}")

    def _parse_app_service_certificate(self, cert: Any) -> Certificate:
        """Parse Azure App Service certificate."""
        # Determine certificate type
        cert_type = CertificateType.IMPORTED
        if getattr(cert, "server_farm_id", None):
            cert_type = CertificateType.MANAGED

        # Get domains
        domains = list(getattr(cert, "host_names", []))
        primary_domain = domains[0] if domains else getattr(cert, "name", "")

        # Parse dates
        not_before = getattr(cert, "valid_from", None)
        not_after = getattr(cert, "expiration_date", None)

        # Determine status
        status = CertificateStatus.ACTIVE
        if not_after:
            if datetime.now(timezone.utc) > not_after.replace(tzinfo=timezone.utc):
                status = CertificateStatus.EXPIRED

        # Extract location/region
        location = getattr(cert, "location", "unknown")

        return Certificate(
            certificate_id=getattr(cert, "id", ""),
            name=getattr(cert, "name", ""),
            cloud_provider="azure",
            account_id=self._subscription_id,
            region=location,
            certificate_type=cert_type,
            status=status,
            domains=domains,
            primary_domain=primary_domain,
            not_before=not_before,
            not_after=not_after,
            issuer=getattr(cert, "issuer", ""),
            thumbprint=getattr(cert, "thumbprint", ""),
            is_managed=cert_type == CertificateType.MANAGED,
            metadata={
                "resource_group": getattr(cert, "resource_group", ""),
                "subject_name": getattr(cert, "subject_name", ""),
                "key_vault_id": getattr(cert, "key_vault_id", ""),
            },
        )


def monitor_certificates(
    certificates: list[Certificate],
    config: CertificateConfig | None = None,
) -> CertificateMonitoringResult:
    """
    Monitor certificates for expiration and security issues.

    Convenience function for certificate monitoring.

    Args:
        certificates: List of certificates to monitor
        config: Optional configuration

    Returns:
        Certificate monitoring result
    """
    monitor = CertificateMonitor(certificates=certificates, config=config)
    return monitor.analyze()
