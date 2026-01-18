"""
Integration tests for ASM alerting functionality.

Tests the integration between ASM scan results, drift detection,
and the alerting/notification system.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.alerting.router import AlertRouter, RoutingRule, SuppressionRule, RateLimit
from stance.asm.drift import (
    ASMDriftDetector,
    ChangeType,
    CertificateChange,
    DriftReport,
    DriftSeverity,
    DriftSummary,
    PortChange,
)
from stance.asm.models import (
    ASMScanResult,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.notifications import (
    ASMAlertContext,
    ASMNotificationManager,
    ScanSummary,
    create_attack_surface_summary,
    create_certificate_expiry_report,
)
from stance.asm.storage import ASMStorageAdapter
from stance.models.finding import Finding, FindingType, Severity


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_db_path():
    """Create a temporary database path for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield f"{tmpdir}/test_asm.db"


@pytest.fixture
def mock_alert_destination():
    """Create a mock alert destination."""
    destination = MagicMock()
    destination.name = "test_destination"
    destination.send.return_value = True
    destination.test_connection.return_value = True
    return destination


@pytest.fixture
def alert_router(mock_alert_destination):
    """Create an alert router with a mock destination."""
    router = AlertRouter()
    router.add_destination(mock_alert_destination)

    # Add a routing rule that matches all severities
    router.add_routing_rule(RoutingRule(
        name="all_alerts",
        destinations=["test_destination"],
        severities=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO],
        enabled=True,
    ))

    return router


@pytest.fixture
def notification_manager(alert_router):
    """Create an ASM notification manager with a router."""
    return ASMNotificationManager(alert_router=alert_router)


@pytest.fixture
def sample_external_assets():
    """Create sample external assets for testing."""
    now = datetime.now(timezone.utc)

    return ExternalAssetCollection([
        ExternalAsset(
            id="asset-1",
            domain="api.example.com",
            ip_address="192.168.1.100",
            port=443,
            service="https",
            protocol="tcp",
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=now - timedelta(days=30),
            last_seen=now,
            risk_score=3.5,
            certificate_info=CertificateInfo(
                subject="CN=api.example.com",
                issuer="CN=Let's Encrypt",
                not_before=now - timedelta(days=60),
                not_after=now + timedelta(days=30),
                fingerprint_sha256="abc123",
            ),
        ),
        ExternalAsset(
            id="asset-2",
            domain="admin.example.com",
            ip_address="192.168.1.101",
            port=22,
            service="ssh",
            protocol="tcp",
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=now - timedelta(days=15),
            last_seen=now,
            risk_score=8.5,
        ),
        ExternalAsset(
            id="asset-3",
            domain="db.example.com",
            ip_address="192.168.1.102",
            port=3306,
            service="mysql",
            protocol="tcp",
            cloud_provider="gcp",
            cloud_region="us-central1",
            first_seen=now,
            last_seen=now,
            risk_score=9.0,
        ),
    ])


@pytest.fixture
def sample_scan_result(sample_external_assets):
    """Create a sample scan result."""
    now = datetime.now(timezone.utc)

    return ASMScanResult(
        scan_id="scan-001",
        target_domains=["example.com"],
        started_at=now - timedelta(minutes=5),
        completed_at=now,
        status="completed",
        assets=sample_external_assets,
        duration_seconds=300.0,
    )


@pytest.fixture
def expiring_certificate_assets():
    """Create assets with various certificate expiration states."""
    now = datetime.now(timezone.utc)

    return ExternalAssetCollection([
        # Expired certificate
        ExternalAsset(
            id="expired-cert-asset",
            domain="expired.example.com",
            port=443,
            certificate_info=CertificateInfo(
                subject="CN=expired.example.com",
                issuer="CN=Let's Encrypt",
                not_before=now - timedelta(days=365),
                not_after=now - timedelta(days=5),
                fingerprint_sha256="expired123",
            ),
        ),
        # Certificate expiring in 5 days (critical)
        ExternalAsset(
            id="critical-cert-asset",
            domain="critical.example.com",
            port=443,
            certificate_info=CertificateInfo(
                subject="CN=critical.example.com",
                issuer="CN=Let's Encrypt",
                not_before=now - timedelta(days=85),
                not_after=now + timedelta(days=5),
                fingerprint_sha256="critical123",
            ),
        ),
        # Certificate expiring in 10 days (high)
        ExternalAsset(
            id="high-cert-asset",
            domain="high.example.com",
            port=443,
            certificate_info=CertificateInfo(
                subject="CN=high.example.com",
                issuer="CN=Let's Encrypt",
                not_before=now - timedelta(days=80),
                not_after=now + timedelta(days=10),
                fingerprint_sha256="high123",
            ),
        ),
        # Certificate expiring in 20 days (medium)
        ExternalAsset(
            id="medium-cert-asset",
            domain="medium.example.com",
            port=443,
            certificate_info=CertificateInfo(
                subject="CN=medium.example.com",
                issuer="CN=Let's Encrypt",
                not_before=now - timedelta(days=70),
                not_after=now + timedelta(days=20),
                fingerprint_sha256="medium123",
            ),
        ),
        # Certificate valid for 60 days (should not alert)
        ExternalAsset(
            id="valid-cert-asset",
            domain="valid.example.com",
            port=443,
            certificate_info=CertificateInfo(
                subject="CN=valid.example.com",
                issuer="CN=Let's Encrypt",
                not_before=now - timedelta(days=30),
                not_after=now + timedelta(days=60),
                fingerprint_sha256="valid123",
            ),
        ),
    ])


# =============================================================================
# Test Classes
# =============================================================================


class TestASMFindingRouting:
    """Test routing of ASM findings to alert destinations."""

    def test_route_critical_finding(self, alert_router, mock_alert_destination):
        """Test routing a critical ASM finding."""
        finding = Finding(
            id="asm-finding-001",
            asset_id="asm:asset-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            status="open",
            title="Critical port exposed",
            description="Database port 3306 exposed to internet",
            rule_id="asm-exposed-port",
        )

        context = {
            "alert_type": "asm_finding",
            "asm_scan_id": "scan-001",
            "asm_domain": "db.example.com",
            "asm_port": 3306,
        }

        result = alert_router.route(finding, context)

        assert result.finding_id == "asm-finding-001"
        assert len(result.matched_rules) > 0
        assert result.successful_destinations >= 1
        mock_alert_destination.send.assert_called()

    def test_route_with_asm_context(self, alert_router, mock_alert_destination):
        """Test that ASM context is passed to alert destination."""
        finding = Finding(
            id="asm-finding-002",
            asset_id="asm:asset-2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status="open",
            title="SSH exposed",
            description="SSH service exposed",
            rule_id="asm-ssh-exposed",
        )

        asm_context = ASMAlertContext(
            scan_id="scan-001",
            domain="admin.example.com",
            is_shadow_it=False,
            risk_score=8.5,
            port=22,
            service="ssh",
            ip_address="192.168.1.101",
            cloud_provider="aws",
        )

        context = asm_context.to_dict()
        context["alert_type"] = "asm_finding"

        result = alert_router.route(finding, context)

        # Verify the context was passed correctly
        call_args = mock_alert_destination.send.call_args
        assert call_args is not None
        passed_context = call_args[0][1]
        assert passed_context["asm_domain"] == "admin.example.com"
        assert passed_context["asm_port"] == 22
        assert passed_context["asm_risk_score"] == 8.5


class TestScanCompletionNotifications:
    """Test scan completion notifications."""

    def test_notify_scan_complete(
        self, notification_manager, sample_scan_result, mock_alert_destination
    ):
        """Test notification on scan completion."""
        findings = [
            Finding(
                id="f1",
                asset_id="asm:asset-1",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status="open",
                title="High risk finding",
                description="Description",
                rule_id="asm-rule-1",
            ),
        ]

        results = notification_manager.notify_scan_complete(
            result=sample_scan_result,
            findings=findings,
            new_asset_count=2,
            shadow_it_count=1,
        )

        # Should send summary notification + individual high/critical findings
        assert len(results) >= 1
        mock_alert_destination.send.assert_called()

    def test_scan_summary_severity_calculation(self, notification_manager):
        """Test that scan summary severity is calculated correctly."""
        # Create a summary with critical findings
        summary = ScanSummary(
            scan_id="scan-001",
            target_domains=["example.com"],
            total_assets=10,
            new_assets=3,
            critical_findings=2,
            high_findings=5,
            medium_findings=3,
            low_findings=1,
            shadow_it_count=1,
            expiring_certs=2,
            high_risk_ports=3,
            duration_seconds=300.0,
        )

        assert summary.total_findings == 11
        assert summary.requires_immediate_attention is True

        # Verify severity calculation
        severity = notification_manager._determine_scan_severity(summary)
        assert severity == Severity.CRITICAL

    def test_scan_summary_no_immediate_attention(self, notification_manager):
        """Test scan summary without immediate attention items."""
        summary = ScanSummary(
            scan_id="scan-002",
            target_domains=["example.com"],
            total_assets=5,
            new_assets=1,
            critical_findings=0,
            high_findings=0,
            medium_findings=2,
            low_findings=3,
            shadow_it_count=0,
            expiring_certs=1,
            high_risk_ports=0,
            duration_seconds=60.0,
        )

        assert summary.requires_immediate_attention is False

        severity = notification_manager._determine_scan_severity(summary)
        assert severity == Severity.MEDIUM


class TestDriftNotifications:
    """Test drift detection notifications."""

    def test_notify_drift_new_high_risk_asset(
        self, notification_manager, mock_alert_destination
    ):
        """Test notification for new high-risk asset detection."""
        now = datetime.now(timezone.utc)

        high_risk_asset = ExternalAsset(
            id="new-risky-asset",
            domain="unknown.example.com",
            ip_address="10.0.0.1",
            port=3389,  # RDP - critical port
            service="rdp",
            first_seen=now,
            last_seen=now,
            risk_score=8.0,
        )

        drift_report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            new_assets=[high_risk_asset],
            new_ports=[
                PortChange(
                    domain="unknown.example.com",
                    ip_address="10.0.0.1",
                    port=3389,
                    change_type=ChangeType.ADDED,
                    service="rdp",
                )
            ],
            summary=DriftSummary(
                new_assets_count=1,
                new_ports_count=1,
                critical_changes=1,
                total_changes=2,
            ),
        )

        results = notification_manager.notify_drift(drift_report)

        assert len(results) >= 1
        mock_alert_destination.send.assert_called()

    def test_notify_drift_certificate_change(
        self, notification_manager, mock_alert_destination
    ):
        """Test notification for certificate changes."""
        now = datetime.now(timezone.utc)

        drift_report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            certificate_changes=[
                CertificateChange(
                    domain="api.example.com",
                    change_type=ChangeType.REMOVED,
                    old_fingerprint="old123",
                    old_expiry=now + timedelta(days=30),
                    old_issuer="CN=Let's Encrypt",
                )
            ],
            summary=DriftSummary(
                certificate_changes_count=1,
                high_changes=1,
                total_changes=1,
            ),
        )

        results = notification_manager.notify_drift(drift_report)

        # Certificate removal should trigger high-severity alert
        assert len(results) >= 1

    def test_drift_summary_overall_severity(self):
        """Test drift summary overall severity calculation."""
        # Critical severity
        critical_summary = DriftSummary(
            critical_changes=1,
            high_changes=2,
            total_changes=10,
        )
        assert critical_summary.overall_severity == DriftSeverity.CRITICAL
        assert critical_summary.high_risk_changes == 3

        # High severity
        high_summary = DriftSummary(
            critical_changes=0,
            high_changes=3,
            total_changes=5,
        )
        assert high_summary.overall_severity == DriftSeverity.HIGH

        # Medium severity (new assets/ports)
        medium_summary = DriftSummary(
            critical_changes=0,
            high_changes=0,
            new_assets_count=2,
            total_changes=2,
        )
        assert medium_summary.overall_severity == DriftSeverity.MEDIUM

        # Info severity (no changes)
        info_summary = DriftSummary()
        assert info_summary.overall_severity == DriftSeverity.INFO


class TestCertificateExpiryNotifications:
    """Test certificate expiry notifications."""

    def test_notify_expiring_certificates(
        self, notification_manager, expiring_certificate_assets, mock_alert_destination
    ):
        """Test notification for expiring certificates."""
        assets = list(expiring_certificate_assets)

        results = notification_manager.notify_certificate_expiring(
            assets=assets,
            days_threshold=30,
        )

        # Should notify for expired, critical (5 days), high (10 days), medium (20 days)
        # Should NOT notify for valid (60 days)
        assert len(results) == 4
        mock_alert_destination.send.assert_called()

    def test_certificate_expiry_report(self, expiring_certificate_assets):
        """Test certificate expiry report generation."""
        report = create_certificate_expiry_report(
            assets=expiring_certificate_assets,
            days_threshold=30,
        )

        # Should include 4 certificates (expired + 3 expiring within 30 days)
        assert len(report) == 4

        # Should be sorted by days until expiry (soonest first)
        assert report[0]["domain"] == "expired.example.com"
        assert report[0]["status"] == "EXPIRED"

        assert report[1]["domain"] == "critical.example.com"
        assert report[1]["status"] == "CRITICAL"

        assert report[2]["domain"] == "high.example.com"
        assert report[2]["status"] == "WARNING"


class TestShadowITNotifications:
    """Test shadow IT discovery notifications."""

    def test_notify_shadow_it(self, notification_manager, mock_alert_destination):
        """Test notification for shadow IT discoveries."""
        now = datetime.now(timezone.utc)

        shadow_it_assets = [
            ExternalAsset(
                id="shadow-1",
                domain="unauthorized.example.com",
                ip_address="10.0.0.50",
                port=443,
                service="https",
                first_seen=now,
                last_seen=now,
                risk_score=7.5,  # High risk
                cloud_provider="unknown",
            ),
            ExternalAsset(
                id="shadow-2",
                domain="test-server.example.com",
                ip_address="10.0.0.51",
                port=8080,
                service="http",
                first_seen=now,
                last_seen=now,
                risk_score=6.0,  # High risk
                cloud_provider="digitalocean",
            ),
            ExternalAsset(
                id="shadow-3",
                domain="lowrisk.example.com",
                port=443,
                risk_score=3.0,  # Low risk - should not alert
            ),
        ]

        results = notification_manager.notify_shadow_it(
            shadow_it_assets=shadow_it_assets,
            correlation_context={"cspm_check": "no_match"},
        )

        # Should only notify for high-risk shadow IT (risk_score >= 5.0)
        assert len(results) == 2
        mock_alert_destination.send.assert_called()

    def test_shadow_it_severity_levels(self, notification_manager, mock_alert_destination):
        """Test shadow IT severity is based on risk score."""
        now = datetime.now(timezone.utc)

        # Critical risk (score >= 8.0)
        critical_asset = [
            ExternalAsset(
                id="critical-shadow",
                domain="critical.example.com",
                port=3306,
                risk_score=9.0,
                first_seen=now,
                last_seen=now,
            ),
        ]

        results = notification_manager.notify_shadow_it(shadow_it_assets=critical_asset)
        assert len(results) == 1

        # Verify severity in the call
        call_args = mock_alert_destination.send.call_args
        finding = call_args[0][0]
        assert finding.severity == Severity.CRITICAL


class TestAlertDestinationDelivery:
    """Test alert destination delivery (mocked)."""

    def test_successful_delivery(self, alert_router, mock_alert_destination):
        """Test successful alert delivery."""
        mock_alert_destination.send.return_value = True

        finding = Finding(
            id="test-finding",
            asset_id="asm:test",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status="open",
            title="Test finding",
            description="Test",
            rule_id="test-rule",
        )

        result = alert_router.route(finding, {"alert_type": "test"})

        assert result.successful_destinations >= 1
        assert len([r for r in result.results if r.success]) >= 1

    def test_failed_delivery(self, alert_router, mock_alert_destination):
        """Test handling of failed alert delivery."""
        mock_alert_destination.send.side_effect = Exception("Connection failed")

        finding = Finding(
            id="test-finding-2",
            asset_id="asm:test",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status="open",
            title="Test finding",
            description="Test",
            rule_id="test-rule",
        )

        result = alert_router.route(finding, {"alert_type": "test"})

        # Should handle failure gracefully
        failed_results = [r for r in result.results if not r.success and r.error]
        assert len(failed_results) >= 1
        assert "Connection failed" in failed_results[0].error

    def test_deduplication(self, alert_router, mock_alert_destination):
        """Test alert deduplication within time window."""
        finding = Finding(
            id="dedup-finding",
            asset_id="asm:test",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status="open",
            title="Duplicate test",
            description="Test",
            rule_id="test-rule",
        )

        # First send
        result1 = alert_router.route(finding, {"alert_type": "test"})

        # Second send (should be deduplicated)
        result2 = alert_router.route(finding, {"alert_type": "test"})

        # First should succeed, second should be deduplicated
        assert result1.successful_destinations >= 1
        deduplicated = [r for r in result2.results if r.deduplicated]
        assert len(deduplicated) >= 1

    def test_rate_limiting(self, mock_alert_destination):
        """Test rate limiting of alerts."""
        router = AlertRouter()
        router.add_destination(mock_alert_destination)

        # Set strict rate limit
        router.set_rate_limit("test_destination", RateLimit(
            max_alerts=2,
            window_seconds=60,
        ))

        router.add_routing_rule(RoutingRule(
            name="all",
            destinations=["test_destination"],
            enabled=True,
        ))

        # Send multiple alerts
        for i in range(5):
            finding = Finding(
                id=f"rate-limit-{i}",
                asset_id="asm:test",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status="open",
                title=f"Rate limit test {i}",
                description="Test",
                rule_id="test-rule",
            )
            router.route(finding, {"alert_type": "test"})

        # Should have rate limited some alerts
        assert mock_alert_destination.send.call_count <= 3  # Max 2 + some buffer


class TestAlertSuppression:
    """Test alert suppression rules."""

    def test_suppress_by_rule_id(self, mock_alert_destination):
        """Test suppression by rule ID."""
        router = AlertRouter()
        router.add_destination(mock_alert_destination)

        router.add_routing_rule(RoutingRule(
            name="all",
            destinations=["test_destination"],
            enabled=True,
        ))

        # Add suppression rule
        router.add_suppression_rule(SuppressionRule(
            name="suppress_test_rule",
            rule_ids=["suppressed-rule"],
            enabled=True,
        ))

        # This finding should be suppressed
        suppressed_finding = Finding(
            id="suppressed-finding",
            asset_id="asm:test",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status="open",
            title="Suppressed",
            description="Should be suppressed",
            rule_id="suppressed-rule",
        )

        result = router.route(suppressed_finding, {})

        # Should be suppressed
        assert len([r for r in result.results if r.suppressed]) >= 1
        mock_alert_destination.send.assert_not_called()

    def test_suppress_by_asset_pattern(self, mock_alert_destination):
        """Test suppression by asset pattern."""
        router = AlertRouter()
        router.add_destination(mock_alert_destination)

        router.add_routing_rule(RoutingRule(
            name="all",
            destinations=["test_destination"],
            enabled=True,
        ))

        # Add suppression rule for asm:test-* assets
        router.add_suppression_rule(SuppressionRule(
            name="suppress_test_assets",
            asset_patterns=["asm:test-*"],
            enabled=True,
        ))

        finding = Finding(
            id="pattern-suppressed",
            asset_id="asm:test-server-1",  # Matches pattern
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status="open",
            title="Pattern suppressed",
            description="Should be suppressed by pattern",
            rule_id="any-rule",
        )

        result = router.route(finding, {})

        # Should be suppressed
        assert len([r for r in result.results if r.suppressed]) >= 1


class TestAttackSurfaceSummary:
    """Test attack surface summary generation."""

    def test_create_attack_surface_summary(self, sample_external_assets):
        """Test creating an attack surface summary."""
        findings = [
            Finding(
                id="f1",
                asset_id="asm:asset-1",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.CRITICAL,
                status="open",
                title="Critical",
                description="Critical finding",
                rule_id="rule-1",
            ),
            Finding(
                id="f2",
                asset_id="asm:asset-2",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status="open",
                title="High",
                description="High finding",
                rule_id="rule-2",
            ),
        ]

        summary = create_attack_surface_summary(
            assets=sample_external_assets,
            findings=findings,
            shadow_it_count=1,
        )

        assert summary["total_assets"] == 3
        assert summary["shadow_it_count"] == 1
        assert summary["findings"]["total"] == 2
        assert summary["findings"]["by_severity"]["critical"] == 1
        assert summary["findings"]["by_severity"]["high"] == 1

    def test_attack_surface_summary_port_distribution(self, sample_external_assets):
        """Test port distribution in attack surface summary."""
        summary = create_attack_surface_summary(
            assets=sample_external_assets,
            findings=None,
            shadow_it_count=0,
        )

        # Should have high-risk port count
        assert "exposure" in summary
        assert "high_risk_ports" in summary["exposure"]
        # Port 22 (SSH) and 3306 (MySQL) are high-risk
        assert summary["exposure"]["high_risk_ports"] >= 2


class TestASMAlertContext:
    """Test ASM alert context creation and conversion."""

    def test_alert_context_to_dict(self):
        """Test converting alert context to dictionary."""
        now = datetime.now(timezone.utc)

        asset = ExternalAsset(
            id="ctx-asset",
            domain="test.example.com",
            ip_address="10.0.0.1",
            port=443,
        )

        context = ASMAlertContext(
            scan_id="scan-001",
            domain="test.example.com",
            external_asset=asset,
            is_shadow_it=True,
            drift_type="new_asset",
            correlation_status="no_match",
            risk_score=7.5,
            technology_stack=["nginx", "python"],
            certificate_days_until_expiry=15,
            port=443,
            service="https",
            ip_address="10.0.0.1",
            cloud_provider="aws",
        )

        result = context.to_dict()

        assert result["asm_scan_id"] == "scan-001"
        assert result["asm_domain"] == "test.example.com"
        assert result["asm_is_shadow_it"] is True
        assert result["asm_drift_type"] == "new_asset"
        assert result["asm_correlation_status"] == "no_match"
        assert result["asm_risk_score"] == 7.5
        assert result["asm_technology_stack"] == ["nginx", "python"]
        assert result["asm_certificate_days_until_expiry"] == 15
        assert "asm_external_asset" in result

    def test_alert_context_optional_fields(self):
        """Test alert context with minimal fields."""
        context = ASMAlertContext(
            domain="minimal.example.com",
        )

        result = context.to_dict()

        assert result["asm_domain"] == "minimal.example.com"
        # Optional fields should not be present
        assert "asm_drift_type" not in result
        assert "asm_correlation_status" not in result
        assert "asm_certificate_days_until_expiry" not in result


class TestNotificationManagerNoRouter:
    """Test notification manager behavior without a router."""

    def test_notify_without_router(self, sample_scan_result):
        """Test notifications gracefully handle missing router."""
        manager = ASMNotificationManager(alert_router=None)

        # Should not raise, should return empty list
        results = manager.notify_scan_complete(result=sample_scan_result)
        assert results == []

    def test_drift_notify_without_router(self):
        """Test drift notifications without router."""
        manager = ASMNotificationManager(alert_router=None)

        drift_report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
        )

        results = manager.notify_drift(drift_report)
        assert results == []

    def test_cert_notify_without_router(self, expiring_certificate_assets):
        """Test certificate notifications without router."""
        manager = ASMNotificationManager(alert_router=None)

        results = manager.notify_certificate_expiring(
            assets=list(expiring_certificate_assets),
        )
        assert results == []


class TestDriftNotificationSeverityMapping:
    """Test drift notification severity mapping."""

    def test_port_change_severity_mapping(self, notification_manager, mock_alert_destination):
        """Test that port changes map to correct severity."""
        # Critical port (RDP)
        critical_port_change = PortChange(
            domain="test.example.com",
            ip_address="10.0.0.1",
            port=3389,
            change_type=ChangeType.ADDED,
            service="rdp",
        )

        drift_report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            new_ports=[critical_port_change],
            summary=DriftSummary(
                new_ports_count=1,
                critical_changes=1,
                total_changes=1,
            ),
        )

        results = notification_manager.notify_drift(drift_report)

        # Should create alert for critical port
        assert len(results) >= 1

    def test_certificate_change_severity(self, notification_manager, mock_alert_destination):
        """Test certificate change severity mapping."""
        now = datetime.now(timezone.utc)

        # Certificate removal is HIGH severity
        cert_removal = CertificateChange(
            domain="secure.example.com",
            change_type=ChangeType.REMOVED,
            old_fingerprint="removed123",
            old_expiry=now + timedelta(days=30),
        )

        drift_report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            certificate_changes=[cert_removal],
            summary=DriftSummary(
                certificate_changes_count=1,
                high_changes=1,
                total_changes=1,
            ),
        )

        results = notification_manager.notify_drift(drift_report)

        assert len(results) >= 1
