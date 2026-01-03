"""
Unit tests for certificate monitoring in exposure management.

Tests the CertificateMonitor, Certificate models, and cloud-specific collectors.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.exposure.certificates import (
    AWSCertificateCollector,
    AzureCertificateCollector,
    BaseCertificateCollector,
    Certificate,
    CertificateConfig,
    CertificateFinding,
    CertificateFindingType,
    CertificateMonitor,
    CertificateMonitoringResult,
    CertificateSeverity,
    CertificateStatus,
    CertificateSummary,
    CertificateType,
    GCPCertificateCollector,
    monitor_certificates,
)


class TestCertificateStatus:
    """Tests for CertificateStatus enum."""

    def test_all_statuses_exist(self) -> None:
        """Test all expected statuses are defined."""
        expected = ["ACTIVE", "EXPIRED", "EXPIRING_SOON", "REVOKED", "PENDING", "FAILED", "INACTIVE", "UNKNOWN"]
        for status in expected:
            assert hasattr(CertificateStatus, status)

    def test_status_values(self) -> None:
        """Test status values are lowercase."""
        assert CertificateStatus.ACTIVE.value == "active"
        assert CertificateStatus.EXPIRED.value == "expired"


class TestCertificateType:
    """Tests for CertificateType enum."""

    def test_all_types_exist(self) -> None:
        """Test all expected types are defined."""
        expected = ["MANAGED", "IMPORTED", "SELF_SIGNED", "PRIVATE_CA"]
        for cert_type in expected:
            assert hasattr(CertificateType, cert_type)

    def test_type_values(self) -> None:
        """Test type values are lowercase."""
        assert CertificateType.MANAGED.value == "managed"
        assert CertificateType.IMPORTED.value == "imported"


class TestCertificateFindingType:
    """Tests for CertificateFindingType enum."""

    def test_expiration_types(self) -> None:
        """Test expiration-related finding types."""
        assert CertificateFindingType.CERT_EXPIRING_30_DAYS.value == "cert_expiring_30_days"
        assert CertificateFindingType.CERT_EXPIRING_14_DAYS.value == "cert_expiring_14_days"
        assert CertificateFindingType.CERT_EXPIRING_7_DAYS.value == "cert_expiring_7_days"
        assert CertificateFindingType.CERT_EXPIRED.value == "cert_expired"

    def test_security_types(self) -> None:
        """Test security-related finding types."""
        assert CertificateFindingType.CERT_WEAK_ALGORITHM.value == "cert_weak_algorithm"
        assert CertificateFindingType.CERT_SHORT_KEY.value == "cert_short_key"
        assert CertificateFindingType.CERT_SELF_SIGNED.value == "cert_self_signed_public"


class TestCertificateSeverity:
    """Tests for CertificateSeverity enum."""

    def test_severity_ranking(self) -> None:
        """Test severity comparison operators."""
        assert CertificateSeverity.CRITICAL > CertificateSeverity.HIGH
        assert CertificateSeverity.HIGH > CertificateSeverity.MEDIUM
        assert CertificateSeverity.MEDIUM > CertificateSeverity.LOW
        assert CertificateSeverity.LOW > CertificateSeverity.INFO

    def test_severity_ranks(self) -> None:
        """Test severity rank values."""
        assert CertificateSeverity.CRITICAL.rank == 5
        assert CertificateSeverity.HIGH.rank == 4
        assert CertificateSeverity.MEDIUM.rank == 3
        assert CertificateSeverity.LOW.rank == 2
        assert CertificateSeverity.INFO.rank == 1


class TestCertificateConfig:
    """Tests for CertificateConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = CertificateConfig()
        assert config.warning_threshold_days == 30
        assert config.critical_threshold_days == 7
        assert config.check_key_strength is True
        assert config.check_algorithm is True
        assert config.min_rsa_key_size == 2048
        assert config.min_ecdsa_key_size == 256
        assert "sha1" in config.weak_algorithms
        assert config.include_inactive is False

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = CertificateConfig(
            warning_threshold_days=60,
            critical_threshold_days=14,
            min_rsa_key_size=4096,
        )
        assert config.warning_threshold_days == 60
        assert config.critical_threshold_days == 14
        assert config.min_rsa_key_size == 4096


class TestCertificate:
    """Tests for Certificate dataclass."""

    def test_certificate_creation(self) -> None:
        """Test basic certificate creation."""
        cert = Certificate(
            certificate_id="arn:aws:acm:us-east-1:123456789:certificate/abc",
            name="example.com",
            cloud_provider="aws",
            account_id="123456789",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com", "*.example.com"],
            primary_domain="example.com",
        )
        assert cert.certificate_id == "arn:aws:acm:us-east-1:123456789:certificate/abc"
        assert cert.name == "example.com"
        assert cert.cloud_provider == "aws"
        assert cert.is_managed is False  # is_managed attribute, not computed

    def test_days_until_expiry_calculation(self) -> None:
        """Test automatic days until expiry calculation."""
        future = datetime.now(timezone.utc) + timedelta(days=15)
        cert = Certificate(
            certificate_id="cert-123",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com"],
            primary_domain="example.com",
            not_after=future,
        )
        assert cert.days_until_expiry == 14 or cert.days_until_expiry == 15

    def test_is_expired(self) -> None:
        """Test is_expired property."""
        past = datetime.now(timezone.utc) - timedelta(days=10)
        cert = Certificate(
            certificate_id="cert-123",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.EXPIRED,
            domains=["example.com"],
            primary_domain="example.com",
            not_after=past,
        )
        assert cert.is_expired is True
        assert cert.days_until_expiry < 0

    def test_is_expiring_soon(self) -> None:
        """Test is_expiring_soon property."""
        future = datetime.now(timezone.utc) + timedelta(days=20)
        cert = Certificate(
            certificate_id="cert-123",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com"],
            primary_domain="example.com",
            not_after=future,
        )
        assert cert.is_expiring_soon is True

    def test_is_in_use(self) -> None:
        """Test is_in_use property."""
        cert = Certificate(
            certificate_id="cert-123",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com"],
            primary_domain="example.com",
            attached_resources=["arn:aws:elasticloadbalancing:..."],
        )
        assert cert.is_in_use is True

        cert_unused = Certificate(
            certificate_id="cert-456",
            name="example2.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example2.com"],
            primary_domain="example2.com",
        )
        assert cert_unused.is_in_use is False

    def test_to_dict(self) -> None:
        """Test certificate to_dict method."""
        cert = Certificate(
            certificate_id="cert-123",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com"],
            primary_domain="example.com",
        )
        result = cert.to_dict()
        assert result["certificate_id"] == "cert-123"
        assert result["certificate_type"] == "managed"
        assert result["status"] == "active"


class TestCertificateFinding:
    """Tests for CertificateFinding dataclass."""

    def test_finding_creation(self) -> None:
        """Test certificate finding creation."""
        finding = CertificateFinding(
            finding_id=str(uuid.uuid4()),
            finding_type=CertificateFindingType.CERT_EXPIRED,
            severity=CertificateSeverity.CRITICAL,
            title="Certificate expired: example.com",
            description="Certificate expired 5 days ago.",
            certificate_id="cert-123",
            certificate_name="example.com",
            cloud_provider="aws",
            region="us-east-1",
            days_until_expiry=-5,
        )
        assert finding.severity == CertificateSeverity.CRITICAL
        assert finding.finding_type == CertificateFindingType.CERT_EXPIRED

    def test_finding_to_dict(self) -> None:
        """Test finding to_dict method."""
        finding = CertificateFinding(
            finding_id="find-123",
            finding_type=CertificateFindingType.CERT_EXPIRING_7_DAYS,
            severity=CertificateSeverity.CRITICAL,
            title="Expiring soon",
            description="Certificate expiring.",
            certificate_id="cert-123",
            certificate_name="example.com",
            cloud_provider="aws",
            region="us-east-1",
        )
        result = finding.to_dict()
        assert result["finding_id"] == "find-123"
        assert result["severity"] == "critical"
        assert result["finding_type"] == "cert_expiring_7_days"


class TestCertificateSummary:
    """Tests for CertificateSummary dataclass."""

    def test_summary_defaults(self) -> None:
        """Test summary default values."""
        summary = CertificateSummary()
        assert summary.total_certificates == 0
        assert summary.expired_certificates == 0
        assert summary.expiring_7_days == 0

    def test_summary_to_dict(self) -> None:
        """Test summary to_dict method."""
        summary = CertificateSummary(
            total_certificates=10,
            active_certificates=8,
            expired_certificates=1,
            expiring_7_days=1,
        )
        result = summary.to_dict()
        assert result["total_certificates"] == 10
        assert result["active_certificates"] == 8


class TestCertificateMonitoringResult:
    """Tests for CertificateMonitoringResult dataclass."""

    def test_result_creation(self) -> None:
        """Test result creation."""
        result = CertificateMonitoringResult(
            result_id=str(uuid.uuid4()),
            config=CertificateConfig(),
            started_at=datetime.now(timezone.utc),
        )
        assert result.has_findings is False
        assert len(result.certificates) == 0

    def test_result_with_findings(self) -> None:
        """Test result with findings."""
        finding = CertificateFinding(
            finding_id="find-1",
            finding_type=CertificateFindingType.CERT_EXPIRED,
            severity=CertificateSeverity.CRITICAL,
            title="Expired",
            description="Expired",
            certificate_id="cert-1",
            certificate_name="example.com",
            cloud_provider="aws",
            region="us-east-1",
        )
        result = CertificateMonitoringResult(
            result_id="res-1",
            config=CertificateConfig(),
            started_at=datetime.now(timezone.utc),
            findings=[finding],
        )
        assert result.has_findings is True
        assert len(result.critical_findings) == 1


class TestCertificateMonitor:
    """Tests for CertificateMonitor class."""

    def _create_certificate(
        self,
        days_until_expiry: int = 60,
        cert_type: CertificateType = CertificateType.MANAGED,
        status: CertificateStatus = CertificateStatus.ACTIVE,
        key_algorithm: str = "RSA",
        key_size: int = 2048,
        signature_algorithm: str = "SHA256withRSA",
        attached_resources: list[str] | None = None,
    ) -> Certificate:
        """Create a test certificate."""
        not_after = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
        return Certificate(
            certificate_id=f"cert-{uuid.uuid4().hex[:8]}",
            name="example.com",
            cloud_provider="aws",
            account_id="123456789",
            region="us-east-1",
            certificate_type=cert_type,
            status=status,
            domains=["example.com"],
            primary_domain="example.com",
            not_after=not_after,
            key_algorithm=key_algorithm,
            key_size=key_size,
            signature_algorithm=signature_algorithm,
            attached_resources=attached_resources or [],
        )

    def test_monitor_initialization(self) -> None:
        """Test monitor initialization."""
        monitor = CertificateMonitor()
        assert len(monitor.certificates) == 0
        assert monitor.config.warning_threshold_days == 30

    def test_add_certificates(self) -> None:
        """Test adding certificates to monitor."""
        monitor = CertificateMonitor()
        certs = [self._create_certificate() for _ in range(3)]
        monitor.add_certificates(certs)
        assert len(monitor.certificates) == 3

    def test_analyze_healthy_certificates(self) -> None:
        """Test analyzing healthy certificates (no findings)."""
        cert = self._create_certificate(days_until_expiry=90)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        assert len(result.findings) == 0
        assert result.summary.total_certificates == 1

    def test_analyze_expired_certificate(self) -> None:
        """Test analyzing expired certificate."""
        cert = self._create_certificate(days_until_expiry=-5)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        assert len(result.findings) == 1
        assert result.findings[0].finding_type == CertificateFindingType.CERT_EXPIRED
        assert result.findings[0].severity == CertificateSeverity.CRITICAL

    def test_analyze_expiring_7_days(self) -> None:
        """Test analyzing certificate expiring within 7 days."""
        cert = self._create_certificate(days_until_expiry=5)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        assert len(result.findings) == 1
        assert result.findings[0].finding_type == CertificateFindingType.CERT_EXPIRING_7_DAYS
        assert result.findings[0].severity == CertificateSeverity.CRITICAL

    def test_analyze_expiring_14_days(self) -> None:
        """Test analyzing certificate expiring within 14 days."""
        cert = self._create_certificate(days_until_expiry=10)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        assert len(result.findings) == 1
        assert result.findings[0].finding_type == CertificateFindingType.CERT_EXPIRING_14_DAYS
        assert result.findings[0].severity == CertificateSeverity.HIGH

    def test_analyze_expiring_30_days(self) -> None:
        """Test analyzing certificate expiring within 30 days."""
        cert = self._create_certificate(days_until_expiry=20)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        assert len(result.findings) == 1
        assert result.findings[0].finding_type == CertificateFindingType.CERT_EXPIRING_30_DAYS
        assert result.findings[0].severity == CertificateSeverity.MEDIUM

    def test_analyze_weak_key_rsa(self) -> None:
        """Test analyzing certificate with weak RSA key."""
        cert = self._create_certificate(key_algorithm="RSA", key_size=1024)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        key_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_SHORT_KEY
        ]
        assert len(key_findings) == 1
        assert key_findings[0].severity == CertificateSeverity.HIGH

    def test_analyze_weak_key_ecdsa(self) -> None:
        """Test analyzing certificate with weak ECDSA key."""
        cert = self._create_certificate(key_algorithm="ECDSA", key_size=128)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        key_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_SHORT_KEY
        ]
        assert len(key_findings) == 1

    def test_analyze_weak_algorithm_sha1(self) -> None:
        """Test analyzing certificate with SHA-1 signature."""
        cert = self._create_certificate(signature_algorithm="sha1WithRSAEncryption")
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        algo_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_WEAK_ALGORITHM
        ]
        assert len(algo_findings) == 1
        assert algo_findings[0].severity == CertificateSeverity.HIGH

    def test_analyze_weak_algorithm_md5(self) -> None:
        """Test analyzing certificate with MD5 signature."""
        cert = self._create_certificate(signature_algorithm="md5WithRSAEncryption")
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        algo_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_WEAK_ALGORITHM
        ]
        assert len(algo_findings) == 1

    def test_analyze_self_signed_in_use(self) -> None:
        """Test analyzing self-signed certificate attached to resources."""
        cert = self._create_certificate(
            cert_type=CertificateType.SELF_SIGNED,
            attached_resources=["arn:aws:elasticloadbalancing:..."],
        )
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        self_signed_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_SELF_SIGNED
        ]
        assert len(self_signed_findings) == 1
        assert self_signed_findings[0].severity == CertificateSeverity.MEDIUM

    def test_analyze_pending_validation(self) -> None:
        """Test analyzing certificate pending validation."""
        cert = self._create_certificate(status=CertificateStatus.PENDING)
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        pending_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_PENDING_VALIDATION
        ]
        assert len(pending_findings) == 1

    def test_analyze_multiple_issues(self) -> None:
        """Test analyzing certificate with multiple issues."""
        cert = self._create_certificate(
            days_until_expiry=5,  # Expiring soon
            key_size=1024,  # Weak key
            signature_algorithm="sha1WithRSAEncryption",  # Weak algo
        )
        monitor = CertificateMonitor(certificates=[cert])
        result = monitor.analyze()

        # Should have 3 findings
        assert len(result.findings) == 3

    def test_analyze_disable_key_strength_check(self) -> None:
        """Test disabling key strength check."""
        config = CertificateConfig(check_key_strength=False)
        cert = self._create_certificate(key_size=1024)
        monitor = CertificateMonitor(certificates=[cert], config=config)
        result = monitor.analyze()

        key_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_SHORT_KEY
        ]
        assert len(key_findings) == 0

    def test_analyze_disable_algorithm_check(self) -> None:
        """Test disabling algorithm check."""
        config = CertificateConfig(check_algorithm=False)
        cert = self._create_certificate(signature_algorithm="sha1WithRSAEncryption")
        monitor = CertificateMonitor(certificates=[cert], config=config)
        result = monitor.analyze()

        algo_findings = [
            f for f in result.findings if f.finding_type == CertificateFindingType.CERT_WEAK_ALGORITHM
        ]
        assert len(algo_findings) == 0

    def test_get_expiring_certificates(self) -> None:
        """Test getting expiring certificates."""
        certs = [
            self._create_certificate(days_until_expiry=5),
            self._create_certificate(days_until_expiry=20),
            self._create_certificate(days_until_expiry=60),
        ]
        monitor = CertificateMonitor(certificates=certs)

        expiring = monitor.get_expiring_certificates(within_days=30)
        assert len(expiring) == 2

        expiring_7 = monitor.get_expiring_certificates(within_days=7)
        assert len(expiring_7) == 1

    def test_get_certificates_by_cloud(self) -> None:
        """Test getting certificates by cloud provider."""
        cert1 = self._create_certificate()
        cert1 = Certificate(
            certificate_id="cert-1",
            name="aws.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["aws.com"],
            primary_domain="aws.com",
        )
        cert2 = Certificate(
            certificate_id="cert-2",
            name="gcp.com",
            cloud_provider="gcp",
            account_id="proj-1",
            region="us-central1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["gcp.com"],
            primary_domain="gcp.com",
        )
        monitor = CertificateMonitor(certificates=[cert1, cert2])

        aws_certs = monitor.get_certificates_by_cloud("aws")
        assert len(aws_certs) == 1
        assert aws_certs[0].name == "aws.com"

    def test_get_certificates_by_domain(self) -> None:
        """Test getting certificates by domain."""
        cert = Certificate(
            certificate_id="cert-1",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com", "*.example.com", "api.example.com"],
            primary_domain="example.com",
        )
        monitor = CertificateMonitor(certificates=[cert])

        # Find by primary domain
        certs = monitor.get_certificates_by_domain("example.com")
        assert len(certs) == 1

        # Find by SAN
        certs = monitor.get_certificates_by_domain("api.example.com")
        assert len(certs) == 1

    def test_summary_statistics(self) -> None:
        """Test summary statistics are calculated correctly."""
        certs = [
            self._create_certificate(days_until_expiry=5),  # expiring 7
            self._create_certificate(days_until_expiry=10),  # expiring 14
            self._create_certificate(days_until_expiry=25),  # expiring 30
            self._create_certificate(days_until_expiry=-5),  # expired
            self._create_certificate(days_until_expiry=90),  # healthy
        ]
        monitor = CertificateMonitor(certificates=certs)
        result = monitor.analyze()

        assert result.summary.total_certificates == 5
        assert result.summary.expired_certificates == 1
        assert result.summary.expiring_7_days == 1
        assert result.summary.expiring_14_days == 1
        assert result.summary.expiring_30_days == 1


class TestMonitorCertificatesFunction:
    """Tests for monitor_certificates convenience function."""

    def test_monitor_certificates(self) -> None:
        """Test monitor_certificates function."""
        cert = Certificate(
            certificate_id="cert-1",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com"],
            primary_domain="example.com",
            not_after=datetime.now(timezone.utc) + timedelta(days=5),
        )
        result = monitor_certificates([cert])

        assert result.summary.total_certificates == 1
        assert len(result.findings) == 1


class TestAWSCertificateCollector:
    """Tests for AWS certificate collector."""

    def test_collector_initialization(self) -> None:
        """Test collector initialization."""
        mock_session = MagicMock()
        collector = AWSCertificateCollector(session=mock_session, region="us-west-2")
        assert collector._region == "us-west-2"

    def test_parse_acm_certificate_issued(self) -> None:
        """Test parsing issued ACM certificate."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {"Account": "123456789"}
        collector = AWSCertificateCollector(session=mock_session)

        acm_cert = {
            "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/abc",
            "DomainName": "example.com",
            "Type": "AMAZON_ISSUED",
            "Status": "ISSUED",
            "SubjectAlternativeNames": ["example.com", "*.example.com"],
            "KeyAlgorithm": "RSA_2048",
            "SignatureAlgorithm": "SHA256WITHRSA",
            "Issuer": "Amazon",
            "NotBefore": datetime.now(timezone.utc),
            "NotAfter": datetime.now(timezone.utc) + timedelta(days=365),
            "InUseBy": ["arn:aws:elasticloadbalancing:..."],
        }
        cert = collector._parse_acm_certificate(acm_cert)

        assert cert.certificate_type == CertificateType.MANAGED
        assert cert.status == CertificateStatus.ACTIVE
        assert cert.is_managed is True
        assert "*.example.com" in cert.domains

    def test_parse_acm_certificate_imported(self) -> None:
        """Test parsing imported ACM certificate."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {"Account": "123456789"}
        collector = AWSCertificateCollector(session=mock_session)

        acm_cert = {
            "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/def",
            "DomainName": "imported.com",
            "Type": "IMPORTED",
            "Status": "ISSUED",
            "SubjectAlternativeNames": ["imported.com"],
        }
        cert = collector._parse_acm_certificate(acm_cert)

        assert cert.certificate_type == CertificateType.IMPORTED
        assert cert.is_managed is False

    def test_parse_acm_certificate_pending(self) -> None:
        """Test parsing pending validation certificate."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {"Account": "123456789"}
        collector = AWSCertificateCollector(session=mock_session)

        acm_cert = {
            "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/ghi",
            "DomainName": "pending.com",
            "Type": "AMAZON_ISSUED",
            "Status": "PENDING_VALIDATION",
            "SubjectAlternativeNames": ["pending.com"],
        }
        cert = collector._parse_acm_certificate(acm_cert)

        assert cert.status == CertificateStatus.PENDING

    def test_parse_acm_certificate_ec_key(self) -> None:
        """Test parsing certificate with EC key."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {"Account": "123456789"}
        collector = AWSCertificateCollector(session=mock_session)

        acm_cert = {
            "CertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/jkl",
            "DomainName": "ec.com",
            "Type": "AMAZON_ISSUED",
            "Status": "ISSUED",
            "KeyAlgorithm": "EC_prime256v1",
            "SubjectAlternativeNames": ["ec.com"],
        }
        cert = collector._parse_acm_certificate(acm_cert)

        assert cert.key_algorithm == "ECDSA"


class TestGCPCertificateCollector:
    """Tests for GCP certificate collector."""

    def test_collector_initialization(self) -> None:
        """Test collector initialization."""
        collector = GCPCertificateCollector(project_id="my-project")
        assert collector.project_id == "my-project"

    def test_project_id_required(self) -> None:
        """Test project_id is required."""
        collector = GCPCertificateCollector()
        with pytest.raises(ValueError, match="project_id is required"):
            _ = collector.project_id

    def test_parse_compute_certificate_managed(self) -> None:
        """Test parsing managed compute certificate."""
        collector = GCPCertificateCollector(project_id="my-project")

        mock_cert = MagicMock()
        mock_cert.name = "my-cert"
        mock_cert.managed = MagicMock()
        mock_cert.managed.domains = ["example.com", "www.example.com"]
        mock_cert.managed.status = "ACTIVE"
        mock_cert.expire_time = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
        mock_cert.self_link = "https://..."

        cert = collector._parse_compute_certificate(mock_cert)

        assert cert.cloud_provider == "gcp"
        assert cert.is_managed is True
        assert "example.com" in cert.domains

    def test_parse_compute_certificate_self_managed(self) -> None:
        """Test parsing self-managed compute certificate."""
        collector = GCPCertificateCollector(project_id="my-project")

        mock_cert = MagicMock()
        mock_cert.name = "self-managed-cert"
        mock_cert.managed = None
        mock_cert.expire_time = None
        mock_cert.self_link = "https://..."

        cert = collector._parse_compute_certificate(mock_cert)

        assert cert.certificate_type == CertificateType.IMPORTED
        assert cert.is_managed is False


class TestAzureCertificateCollector:
    """Tests for Azure certificate collector."""

    def test_collector_initialization(self) -> None:
        """Test collector initialization."""
        collector = AzureCertificateCollector(subscription_id="sub-123")
        assert collector.subscription_id == "sub-123"

    def test_subscription_id_required(self) -> None:
        """Test subscription_id is required."""
        collector = AzureCertificateCollector()
        with pytest.raises(ValueError, match="subscription_id is required"):
            _ = collector.subscription_id

    def test_parse_app_service_certificate(self) -> None:
        """Test parsing App Service certificate."""
        collector = AzureCertificateCollector(subscription_id="sub-123")

        mock_cert = MagicMock()
        mock_cert.id = "/subscriptions/sub-123/..."
        mock_cert.name = "my-app-cert"
        mock_cert.location = "eastus"
        mock_cert.host_names = ["example.com", "www.example.com"]
        mock_cert.valid_from = datetime.now(timezone.utc) - timedelta(days=30)
        mock_cert.expiration_date = datetime.now(timezone.utc) + timedelta(days=335)
        mock_cert.issuer = "DigiCert"
        mock_cert.thumbprint = "ABC123"
        mock_cert.server_farm_id = None

        cert = collector._parse_app_service_certificate(mock_cert)

        assert cert.cloud_provider == "azure"
        assert cert.region == "eastus"
        assert len(cert.domains) == 2


class TestCertificateMonitoringIntegration:
    """Integration tests for certificate monitoring."""

    def test_full_monitoring_workflow(self) -> None:
        """Test complete monitoring workflow."""
        # Create various certificates
        certs = [
            Certificate(
                certificate_id="cert-1",
                name="healthy.com",
                cloud_provider="aws",
                account_id="123",
                region="us-east-1",
                certificate_type=CertificateType.MANAGED,
                status=CertificateStatus.ACTIVE,
                domains=["healthy.com"],
                primary_domain="healthy.com",
                not_after=datetime.now(timezone.utc) + timedelta(days=90),
                key_algorithm="RSA",
                key_size=2048,
                signature_algorithm="SHA256withRSA",
            ),
            Certificate(
                certificate_id="cert-2",
                name="expiring.com",
                cloud_provider="gcp",
                account_id="proj-1",
                region="global",
                certificate_type=CertificateType.MANAGED,
                status=CertificateStatus.ACTIVE,
                domains=["expiring.com"],
                primary_domain="expiring.com",
                not_after=datetime.now(timezone.utc) + timedelta(days=5),
            ),
            Certificate(
                certificate_id="cert-3",
                name="weak.com",
                cloud_provider="azure",
                account_id="sub-1",
                region="eastus",
                certificate_type=CertificateType.IMPORTED,
                status=CertificateStatus.ACTIVE,
                domains=["weak.com"],
                primary_domain="weak.com",
                not_after=datetime.now(timezone.utc) + timedelta(days=180),
                key_algorithm="RSA",
                key_size=1024,
                signature_algorithm="sha1WithRSAEncryption",
            ),
        ]

        # Run monitoring
        result = monitor_certificates(certs)

        # Verify results
        assert result.summary.total_certificates == 3
        assert result.summary.certificates_by_cloud["aws"] == 1
        assert result.summary.certificates_by_cloud["gcp"] == 1
        assert result.summary.certificates_by_cloud["azure"] == 1

        # Should have findings for expiring and weak certificates
        assert len(result.findings) >= 2
        assert len(result.critical_findings) >= 1  # Expiring in 5 days

    def test_result_serialization(self) -> None:
        """Test result can be serialized to dict."""
        cert = Certificate(
            certificate_id="cert-1",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            region="us-east-1",
            certificate_type=CertificateType.MANAGED,
            status=CertificateStatus.ACTIVE,
            domains=["example.com"],
            primary_domain="example.com",
            not_after=datetime.now(timezone.utc) + timedelta(days=5),
        )
        result = monitor_certificates([cert])
        result_dict = result.to_dict()

        assert "result_id" in result_dict
        assert "certificates" in result_dict
        assert "findings" in result_dict
        assert "summary" in result_dict
        assert result_dict["total_certificates"] == 1
