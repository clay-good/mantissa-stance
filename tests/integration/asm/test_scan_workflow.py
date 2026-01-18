"""
Integration tests for ASM scanning workflows.

Tests cover end-to-end workflows for:
- Full passive scan workflow
- Scan with storage persistence
- Scan with CSPM correlation
- Scan output formats
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stance.asm.models import (
    ASMScanMode,
    ASMScanResult,
    ASMScanStatus,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.storage import ASMStorageAdapter, generate_scan_id
from stance.asm.correlation import (
    ASMCSPMCorrelator,
    CorrelationResult,
    create_unified_inventory,
    detect_shadow_it,
)
from stance.asm.drift import ASMDriftDetector, DriftReport
from stance.asm.risk import ASMRiskScorer, calculate_attack_surface_risk
from stance.models.asset import Asset, AssetCollection


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_db_path():
    """Create a temporary database path."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield f.name


@pytest.fixture
def mock_external_assets():
    """Create mock external assets for testing."""
    now = datetime.now(timezone.utc)

    cert = CertificateInfo(
        subject="CN=api.example.com",
        issuer="CN=DigiCert",
        not_before=now - timedelta(days=180),
        not_after=now + timedelta(days=180),
        san_domains=("api.example.com", "www.api.example.com"),
        fingerprint_sha256="abc123def456",
        is_self_signed=False,
        key_algorithm="RSA",
        key_size=2048,
    )

    assets = [
        ExternalAsset(
            id="ext-web-001",
            domain="www.example.com",
            ip_address="203.0.113.10",
            port=443,
            protocol="https",
            service="nginx",
            technology_stack=("nginx", "React", "Node.js"),
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=now - timedelta(days=30),
            last_seen=now,
            certificate_info=cert,
            risk_score=2.5,
            source="cert_transparency",
        ),
        ExternalAsset(
            id="ext-api-001",
            domain="api.example.com",
            ip_address="203.0.113.20",
            port=443,
            protocol="https",
            service="nginx",
            technology_stack=("nginx", "Python", "FastAPI"),
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=now - timedelta(days=7),
            last_seen=now,
            certificate_info=cert,
            risk_score=4.5,
            source="dns_enumeration",
        ),
        ExternalAsset(
            id="ext-db-001",
            domain="db.example.com",
            ip_address="203.0.113.30",
            port=3306,
            protocol="mysql",
            service="MySQL 8.0",
            technology_stack=("MySQL",),
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=now - timedelta(days=1),
            last_seen=now,
            risk_score=8.0,
            source="port_scan",
        ),
    ]

    return ExternalAssetCollection(assets)


@pytest.fixture
def mock_cspm_assets():
    """Create mock CSPM assets for correlation testing."""
    return AssetCollection([
        Asset(
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
            },
        ),
        Asset(
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
        ),
        Asset(
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
        ),
    ])


# =============================================================================
# Passive Scan Workflow Tests
# =============================================================================


class TestPassiveScanWorkflow:
    """Integration tests for passive ASM scanning."""

    def test_full_passive_scan_workflow(
        self,
        temp_db_path: str,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test complete passive scan workflow."""
        now = datetime.now(timezone.utc)

        # 1. Create scan result
        scan_id = generate_scan_id()
        scan_result = ASMScanResult(
            scan_id=scan_id,
            started_at=now,
            target_domains=["example.com"],
            scan_mode=ASMScanMode.PASSIVE,
        )

        # 2. Start scan
        scan_result.start()
        assert scan_result.status == ASMScanStatus.RUNNING

        # 3. Simulate collectors running
        scan_result.add_collector("cert_transparency")
        scan_result.add_collector("dns_enumeration")

        # 4. Complete scan
        scan_result.complete(mock_external_assets, findings_count=3)

        # 5. Verify scan result
        assert scan_result.status == ASMScanStatus.COMPLETED
        assert scan_result.is_complete is True
        assert scan_result.is_success is True
        assert scan_result.assets_discovered == 3
        assert scan_result.duration_seconds >= 0

        # 6. Store scan results
        storage = ASMStorageAdapter(temp_db_path)
        storage.store_scan_result(scan_result)
        storage.store_external_assets(mock_external_assets, scan_id)

        # 7. Retrieve and verify stored data
        retrieved_scan = storage.get_scan_result(scan_id)
        assert retrieved_scan is not None
        assert retrieved_scan.scan_id == scan_id
        assert retrieved_scan.assets_discovered == 3

        retrieved_assets = storage.get_external_assets(scan_id)
        assert len(retrieved_assets) == 3

    def test_scan_workflow_with_collector_errors(
        self,
        temp_db_path: str,
    ) -> None:
        """Test scan workflow handles collector errors gracefully."""
        now = datetime.now(timezone.utc)

        # Create scan
        scan_id = generate_scan_id()
        scan_result = ASMScanResult(
            scan_id=scan_id,
            started_at=now,
            target_domains=["example.com"],
            scan_mode=ASMScanMode.PASSIVE,
        )
        scan_result.start()

        # Simulate some collectors failing
        scan_result.add_collector("cert_transparency")
        scan_result.add_error("dns_enumeration: Connection timeout")
        scan_result.add_error("cloud_ip_ranges: Rate limited")

        # Complete with partial results
        partial_assets = ExternalAssetCollection([
            ExternalAsset(
                id="ext-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now,
                last_seen=now,
            )
        ])
        scan_result.complete(partial_assets, findings_count=1)

        # Scan should still complete successfully
        assert scan_result.status == ASMScanStatus.COMPLETED
        assert scan_result.has_errors is True
        assert len(scan_result.errors) == 2

    def test_scan_failure_handling(self) -> None:
        """Test scan failure is handled correctly."""
        now = datetime.now(timezone.utc)

        scan_result = ASMScanResult(
            scan_id=generate_scan_id(),
            started_at=now,
            target_domains=["example.com"],
        )
        scan_result.start()

        # Simulate fatal failure
        scan_result.fail("Critical error: unable to connect to any collector")

        assert scan_result.status == ASMScanStatus.FAILED
        assert scan_result.is_complete is True
        assert scan_result.is_success is False
        assert "Critical error" in scan_result.errors[0]


# =============================================================================
# Storage Persistence Tests
# =============================================================================


class TestScanStoragePersistence:
    """Integration tests for scan storage persistence."""

    def test_scan_persistence_roundtrip(
        self,
        temp_db_path: str,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test scan data survives storage roundtrip."""
        now = datetime.now(timezone.utc)
        storage = ASMStorageAdapter(temp_db_path)

        # Create and store scan
        scan_id = generate_scan_id()
        scan_result = ASMScanResult(
            scan_id=scan_id,
            started_at=now,
            target_domains=["example.com", "test.com"],
            scan_mode=ASMScanMode.PASSIVE,
        )
        scan_result.start()
        scan_result.add_collector("cert_transparency")
        scan_result.complete(mock_external_assets, findings_count=5)

        storage.store_scan_result(scan_result)
        storage.store_external_assets(mock_external_assets, scan_id)

        # Retrieve and verify
        retrieved = storage.get_scan_result(scan_id)

        assert retrieved.scan_id == scan_id
        assert retrieved.scan_mode == ASMScanMode.PASSIVE
        assert len(retrieved.target_domains) == 2
        assert retrieved.assets_discovered == 3
        assert retrieved.findings_count == 5
        assert "cert_transparency" in retrieved.collectors_run

    def test_asset_certificate_persistence(
        self,
        temp_db_path: str,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test certificate info is persisted correctly."""
        storage = ASMStorageAdapter(temp_db_path)
        now = datetime.now(timezone.utc)

        # Store assets
        scan_result = ASMScanResult(
            scan_id=generate_scan_id(),
            started_at=now,
            target_domains=["example.com"],
        )
        storage.store_scan_result(scan_result)
        storage.store_external_assets(mock_external_assets, scan_result.scan_id)

        # Retrieve and check certificate
        assets = storage.get_external_assets(scan_result.scan_id)
        web_asset = next(a for a in assets if a.domain == "www.example.com")

        assert web_asset.certificate_info is not None
        assert web_asset.certificate_info.subject == "CN=api.example.com"
        assert web_asset.certificate_info.is_expired is False

    def test_multiple_scans_stored(
        self,
        temp_db_path: str,
    ) -> None:
        """Test multiple scans can be stored and queried."""
        storage = ASMStorageAdapter(temp_db_path)
        now = datetime.now(timezone.utc)

        # Create multiple scans
        for i in range(5):
            scan = ASMScanResult(
                scan_id=f"scan-{i:03d}",
                started_at=now - timedelta(hours=i),
                target_domains=["example.com"],
                status=ASMScanStatus.COMPLETED,
            )
            storage.store_scan_result(scan)

        # List scans
        scans = storage.list_scans(limit=10)
        assert len(scans) == 5

        # Latest should be first
        assert scans[0].scan_id == "scan-000"

        # Get latest
        latest = storage.get_latest_scan()
        assert latest.scan_id == "scan-000"


# =============================================================================
# CSPM Correlation Tests
# =============================================================================


class TestCSPMCorrelationWorkflow:
    """Integration tests for CSPM-ASM correlation."""

    def test_correlation_workflow(
        self,
        mock_external_assets: ExternalAssetCollection,
        mock_cspm_assets: AssetCollection,
    ) -> None:
        """Test complete CSPM-ASM correlation workflow."""
        # Run correlation
        correlator = ASMCSPMCorrelator(mock_external_assets, mock_cspm_assets)
        result = correlator.correlate()

        # Check results
        assert result.total_external == 3
        assert result.total_internal == 3

        # www.example.com should match EC2 (by IP)
        # api.example.com should match ALB (by domain)
        assert result.matched_count >= 2

        # db.example.com is shadow IT (not in CSPM)
        assert result.shadow_it_count >= 1

        # Check correlation score
        assert result.correlation_score > 0

    def test_shadow_it_detection(
        self,
        mock_external_assets: ExternalAssetCollection,
        mock_cspm_assets: AssetCollection,
    ) -> None:
        """Test shadow IT detection workflow."""
        shadow_it = detect_shadow_it(mock_external_assets, mock_cspm_assets)

        # db.example.com should be detected as shadow IT
        assert len(shadow_it) >= 1

        # Should be sorted by risk (highest first)
        if len(shadow_it) > 1:
            assert shadow_it[0].risk_score >= shadow_it[1].risk_score

    def test_unified_inventory_creation(
        self,
        mock_external_assets: ExternalAssetCollection,
        mock_cspm_assets: AssetCollection,
    ) -> None:
        """Test unified inventory creation."""
        correlator = ASMCSPMCorrelator(mock_external_assets, mock_cspm_assets)
        correlation = correlator.correlate()

        unified = create_unified_inventory(correlation, include_shadow_it=True)

        # Should include matched assets with ASM correlation data
        matched_assets = [
            a for a in unified
            if "asm_correlation" in a.raw_config
        ]
        assert len(matched_assets) >= 2

        # Check ASM correlation data
        for asset in matched_assets:
            asm_data = asset.raw_config["asm_correlation"]
            assert "external_domain" in asm_data
            assert "external_ip" in asm_data
            assert "match_confidence" in asm_data

        # Should include shadow IT assets
        shadow_assets = [
            a for a in unified
            if a.resource_type == "shadow_it_asset"
        ]
        assert len(shadow_assets) >= 1


# =============================================================================
# Drift Detection Workflow Tests
# =============================================================================


class TestDriftDetectionWorkflow:
    """Integration tests for drift detection."""

    def test_drift_detection_workflow(
        self,
        temp_db_path: str,
    ) -> None:
        """Test complete drift detection workflow."""
        storage = ASMStorageAdapter(temp_db_path)
        now = datetime.now(timezone.utc)

        # Create baseline scan
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=24),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)

        baseline_assets = ExternalAssetCollection([
            ExternalAsset(
                id="ext-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now - timedelta(days=30),
                last_seen=now - timedelta(hours=24),
            ),
        ])
        storage.store_external_assets(baseline_assets, baseline.scan_id)

        # Create current scan with new asset
        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)

        current_assets = ExternalAssetCollection([
            ExternalAsset(
                id="ext-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now - timedelta(days=30),
                last_seen=now,
            ),
            ExternalAsset(
                id="ext-002",
                domain="api.example.com",
                ip_address="5.6.7.8",
                port=443,
                protocol="https",
                first_seen=now,
                last_seen=now,
            ),
        ])
        storage.store_external_assets(current_assets, current.scan_id)

        # Detect drift
        detector = ASMDriftDetector(storage)
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        # Verify drift was detected
        assert report.has_changes() is True
        assert len(report.new_assets) == 1
        assert report.new_assets[0].domain == "api.example.com"

    def test_drift_findings_generation(
        self,
        temp_db_path: str,
    ) -> None:
        """Test drift findings are generated correctly."""
        storage = ASMStorageAdapter(temp_db_path)
        now = datetime.now(timezone.utc)

        # Create baseline with web asset
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=24),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)

        baseline_assets = ExternalAssetCollection([
            ExternalAsset(
                id="ext-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now - timedelta(days=30),
                last_seen=now - timedelta(hours=24),
            ),
        ])
        storage.store_external_assets(baseline_assets, baseline.scan_id)

        # Create current with new critical port
        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)

        current_assets = ExternalAssetCollection([
            ExternalAsset(
                id="ext-001",
                domain="www.example.com",
                ip_address="1.2.3.4",
                port=443,
                protocol="https",
                first_seen=now - timedelta(days=30),
                last_seen=now,
            ),
            ExternalAsset(
                id="ext-rdp-001",
                domain="rdp.example.com",
                ip_address="1.2.3.5",
                port=3389,  # Critical port
                protocol="rdp",
                first_seen=now,
                last_seen=now,
            ),
        ])
        storage.store_external_assets(current_assets, current.scan_id)

        # Detect drift and generate findings
        detector = ASMDriftDetector(storage)
        report = detector.detect_drift(current.scan_id, baseline.scan_id)
        findings = detector.get_drift_findings(report)

        # Should have critical finding for new RDP port
        critical_findings = [f for f in findings if f.get("severity") == "critical"]
        assert len(critical_findings) >= 1


# =============================================================================
# Risk Scoring Workflow Tests
# =============================================================================


class TestRiskScoringWorkflow:
    """Integration tests for risk scoring."""

    def test_risk_scoring_workflow(
        self,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test complete risk scoring workflow."""
        scorer = ASMRiskScorer()

        # Calculate risk for all assets
        assessments = scorer.calculate_risk_batch(mock_external_assets)

        assert len(assessments) == 3

        # Database asset should have highest risk (port 3306)
        db_assessment = next(
            a for a in assessments if a.asset_domain == "db.example.com"
        )
        # Critical service gets service_exposure score of 1.0 * weight 3.0 = 3.0
        # This alone doesn't make it "high risk" (>6.0) but it's the highest among test assets
        assert db_assessment.total_score >= 3.0  # Critical service exposure

        # Web asset should have lower risk
        web_assessment = next(
            a for a in assessments if a.asset_domain == "www.example.com"
        )
        assert web_assessment.total_score < db_assessment.total_score

    def test_attack_surface_risk_calculation(
        self,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test attack surface risk aggregation."""
        risk_metrics = calculate_attack_surface_risk(
            mock_external_assets,
            shadow_it_ids={"ext-db-001"},
        )

        assert risk_metrics["total_assets"] == 3
        assert "average_risk_score" in risk_metrics
        assert "risk_distribution" in risk_metrics
        assert "highest_risk_assets" in risk_metrics

        # Check distribution has all levels
        dist = risk_metrics["risk_distribution"]
        assert all(k in dist for k in ["critical", "high", "medium", "low", "info"])


# =============================================================================
# Output Format Tests
# =============================================================================


class TestScanOutputFormats:
    """Integration tests for scan output formats."""

    def test_json_output(
        self,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test JSON output format."""
        json_str = mock_external_assets.to_json()

        # Should be valid JSON
        data = json.loads(json_str)

        assert isinstance(data, list)
        assert len(data) == 3

        # Check all expected fields
        for asset in data:
            assert "domain" in asset
            assert "ip_address" in asset
            assert "port" in asset

    def test_asset_collection_serialization(
        self,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test asset collection serialization roundtrip."""
        # Serialize
        json_str = mock_external_assets.to_json()

        # Deserialize
        restored = ExternalAssetCollection.from_json(json_str)

        assert len(restored) == len(mock_external_assets)

        # Check domains match
        original_domains = {a.domain for a in mock_external_assets}
        restored_domains = {a.domain for a in restored}
        assert original_domains == restored_domains

    def test_scan_result_serialization(
        self,
        mock_external_assets: ExternalAssetCollection,
    ) -> None:
        """Test scan result serialization."""
        now = datetime.now(timezone.utc)

        scan_result = ASMScanResult(
            scan_id="test-scan-001",
            started_at=now,
            target_domains=["example.com"],
            scan_mode=ASMScanMode.PASSIVE,
        )
        scan_result.start()
        scan_result.add_collector("cert_transparency")
        scan_result.complete(mock_external_assets, findings_count=3)

        # Serialize
        data = scan_result.to_dict()

        # Check all expected fields
        assert data["scan_id"] == "test-scan-001"
        assert data["scan_mode"] == "passive"
        assert data["status"] == "completed"
        assert data["assets_discovered"] == 3
        assert data["findings_count"] == 3
        assert "cert_transparency" in data["collectors_run"]
