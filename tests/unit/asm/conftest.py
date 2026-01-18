"""
Pytest fixtures for ASM unit tests.

Provides common fixtures for external assets, certificates, scan results,
and mock data for ASM testing.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest

from stance.asm.models import (
    ASMScanMode,
    ASMScanResult,
    ASMScanStatus,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.models.asset import Asset, AssetCollection


# Time helpers
NOW = datetime.now(timezone.utc)
ONE_DAY_AGO = NOW - timedelta(days=1)
ONE_WEEK_AGO = NOW - timedelta(days=7)
ONE_MONTH_AGO = NOW - timedelta(days=30)


@pytest.fixture
def valid_certificate() -> CertificateInfo:
    """Return a valid certificate expiring in 90 days."""
    return CertificateInfo(
        subject="CN=api.example.com",
        issuer="CN=DigiCert",
        not_before=NOW - timedelta(days=275),
        not_after=NOW + timedelta(days=90),
        san_domains=("api.example.com", "www.api.example.com"),
        fingerprint_sha256="abc123def456",
        is_self_signed=False,
        key_algorithm="RSA",
        key_size=2048,
    )


@pytest.fixture
def expiring_certificate() -> CertificateInfo:
    """Return a certificate expiring in 5 days."""
    return CertificateInfo(
        subject="CN=legacy.example.com",
        issuer="CN=Lets Encrypt",
        not_before=NOW - timedelta(days=360),
        not_after=NOW + timedelta(days=5),
        san_domains=("legacy.example.com",),
        fingerprint_sha256="def456abc789",
        is_self_signed=False,
        key_algorithm="RSA",
        key_size=2048,
    )


@pytest.fixture
def expired_certificate() -> CertificateInfo:
    """Return an expired certificate."""
    return CertificateInfo(
        subject="CN=old.example.com",
        issuer="CN=old.example.com",
        not_before=NOW - timedelta(days=400),
        not_after=NOW - timedelta(days=10),
        san_domains=(),
        fingerprint_sha256="expired123",
        is_self_signed=True,
        key_algorithm="RSA",
        key_size=1024,  # Weak key
    )


@pytest.fixture
def web_asset(valid_certificate: CertificateInfo) -> ExternalAsset:
    """Return a standard web asset."""
    return ExternalAsset(
        id="ext-web-001",
        domain="www.example.com",
        ip_address="203.0.113.10",
        port=443,
        protocol="https",
        service="nginx",
        technology_stack=("nginx", "React", "Node.js"),
        cloud_provider="aws",
        cloud_region="us-east-1",
        first_seen=ONE_MONTH_AGO,
        last_seen=NOW,
        certificate_info=valid_certificate,
        risk_score=2.5,
        source="cert_transparency",
    )


@pytest.fixture
def api_asset(expiring_certificate: CertificateInfo) -> ExternalAsset:
    """Return an API asset with expiring certificate."""
    return ExternalAsset(
        id="ext-api-001",
        domain="api.example.com",
        ip_address="203.0.113.20",
        port=443,
        protocol="https",
        service="nginx",
        technology_stack=("nginx", "Python", "FastAPI"),
        cloud_provider="aws",
        cloud_region="us-east-1",
        first_seen=ONE_WEEK_AGO,
        last_seen=NOW,
        certificate_info=expiring_certificate,
        risk_score=4.5,
        source="dns_enumeration",
    )


@pytest.fixture
def database_asset() -> ExternalAsset:
    """Return a database asset (high risk)."""
    return ExternalAsset(
        id="ext-db-001",
        domain="db.example.com",
        ip_address="203.0.113.30",
        port=3306,
        protocol="mysql",
        service="MySQL 8.0",
        technology_stack=("MySQL",),
        cloud_provider="aws",
        cloud_region="us-east-1",
        first_seen=ONE_DAY_AGO,
        last_seen=NOW,
        risk_score=8.0,
        source="port_scan",
    )


@pytest.fixture
def shadow_it_asset(expired_certificate: CertificateInfo) -> ExternalAsset:
    """Return a shadow IT asset (not in CSPM)."""
    return ExternalAsset(
        id="ext-shadow-001",
        domain="unknown-app.example.com",
        ip_address="198.51.100.50",
        port=8080,
        protocol="http",
        service="Apache Tomcat",
        technology_stack=("Tomcat", "Java"),
        cloud_provider="gcp",
        cloud_region="us-central1",
        first_seen=ONE_WEEK_AGO,
        last_seen=NOW,
        certificate_info=expired_certificate,
        risk_score=7.5,
        source="dns_enumeration",
        is_verified=False,
    )


@pytest.fixture
def rdp_asset() -> ExternalAsset:
    """Return an RDP asset (critical risk)."""
    return ExternalAsset(
        id="ext-rdp-001",
        domain="rdp.example.com",
        ip_address="203.0.113.40",
        port=3389,
        protocol="rdp",
        service="Microsoft Terminal Services",
        technology_stack=("Windows Server",),
        cloud_provider="azure",
        cloud_region="eastus",
        first_seen=ONE_WEEK_AGO,
        last_seen=NOW,
        risk_score=9.0,
        source="port_scan",
    )


@pytest.fixture
def external_asset_collection(
    web_asset: ExternalAsset,
    api_asset: ExternalAsset,
    database_asset: ExternalAsset,
    shadow_it_asset: ExternalAsset,
) -> ExternalAssetCollection:
    """Return a collection of external assets."""
    return ExternalAssetCollection([
        web_asset,
        api_asset,
        database_asset,
        shadow_it_asset,
    ])


@pytest.fixture
def asm_scan_result(external_asset_collection: ExternalAssetCollection) -> ASMScanResult:
    """Return a completed ASM scan result."""
    result = ASMScanResult(
        scan_id="asm-20260108-120000-abc123",
        started_at=NOW - timedelta(minutes=5),
        target_domains=["example.com"],
        scan_mode=ASMScanMode.PASSIVE,
    )
    result.start()
    result.complete(external_asset_collection, findings_count=3)
    return result


# CSPM assets for correlation testing


@pytest.fixture
def cspm_ec2_asset() -> Asset:
    """Return a CSPM EC2 instance asset."""
    return Asset(
        id="arn:aws:ec2:us-east-1:123456789012:instance/i-abc123",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_ec2_instance",
        name="web-server-1",
        tags={"Name": "web-server-1", "Domain": "www.example.com"},
        network_exposure="internet_facing",
        raw_config={
            "public_ip_address": "203.0.113.10",
            "public_dns_name": "ec2-203-0-113-10.compute-1.amazonaws.com",
            "private_ip_address": "10.0.1.10",
        },
    )


@pytest.fixture
def cspm_alb_asset() -> Asset:
    """Return a CSPM ALB asset."""
    return Asset(
        id="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/api-alb/abc123",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_alb",
        name="api-alb",
        tags={},
        network_exposure="internet_facing",
        raw_config={
            "dns_name": "api.example.com",
        },
    )


@pytest.fixture
def cspm_rds_asset() -> Asset:
    """Return a CSPM RDS asset."""
    return Asset(
        id="arn:aws:rds:us-east-1:123456789012:db:prod-db",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_rds_instance",
        name="prod-db",
        tags={},
        network_exposure="internal",
        raw_config={
            "endpoint": {
                "address": "prod-db.abc123.us-east-1.rds.amazonaws.com",
                "port": 3306,
            },
            "publicly_accessible": False,
        },
    )


@pytest.fixture
def cspm_asset_collection(
    cspm_ec2_asset: Asset,
    cspm_alb_asset: Asset,
    cspm_rds_asset: Asset,
) -> AssetCollection:
    """Return a CSPM asset collection."""
    return AssetCollection([
        cspm_ec2_asset,
        cspm_alb_asset,
        cspm_rds_asset,
    ])


@pytest.fixture
def temp_db_path() -> Generator[str, None, None]:
    """Return a temporary database path for storage tests."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name
