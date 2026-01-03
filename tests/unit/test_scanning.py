"""
Unit tests for the scanning module.

Tests the MultiAccountScanner and related components.
"""

from datetime import datetime, timedelta

import pytest

from stance.config.scan_config import AccountConfig, CloudProvider, ScanConfiguration
from stance.models.asset import AssetCollection
from stance.models.finding import Finding, FindingCollection, FindingStatus, FindingType, Severity
from stance.scanning.multi_account import (
    AccountScanResult,
    AccountStatus,
    MultiAccountScanner,
    OrganizationScan,
    ScanOptions,
    ScanProgress,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_accounts():
    """Create sample account configurations."""
    return [
        AccountConfig(
            account_id="111111111111",
            cloud_provider=CloudProvider.AWS,
            name="AWS Production",
            regions=["us-east-1", "us-west-2"],
            enabled=True,
        ),
        AccountConfig(
            account_id="222222222222",
            cloud_provider=CloudProvider.AWS,
            name="AWS Development",
            regions=["us-east-1"],
            enabled=True,
        ),
        AccountConfig(
            account_id="my-gcp-project",
            cloud_provider=CloudProvider.GCP,
            name="GCP Production",
            enabled=True,
        ),
        AccountConfig(
            account_id="azure-sub-1",
            cloud_provider=CloudProvider.AZURE,
            name="Azure Production",
            enabled=True,
        ),
        AccountConfig(
            account_id="disabled-account",
            cloud_provider=CloudProvider.AWS,
            name="Disabled Account",
            enabled=False,
        ),
    ]


@pytest.fixture
def sample_config(sample_accounts):
    """Create sample scan configuration."""
    return ScanConfiguration(
        name="test-config",
        accounts=sample_accounts,
    )


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    return FindingCollection([
        Finding(
            id="finding-1",
            asset_id="arn:aws:s3:::bucket1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="S3 bucket publicly accessible",
            description="Bucket allows public access",
        ),
        Finding(
            id="finding-2",
            asset_id="arn:aws:iam::111111111111:user/admin",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="IAM user without MFA",
            description="Admin user does not have MFA enabled",
        ),
    ])


def mock_scanner(account: AccountConfig, options: ScanOptions) -> AccountScanResult:
    """Mock scanner that returns sample findings."""
    findings = FindingCollection([
        Finding(
            id=f"finding-{account.account_id}-1",
            asset_id=f"asset-{account.account_id}",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test finding",
            description="Test description",
        ),
    ])

    return AccountScanResult(
        account_id=account.account_id,
        account_name=account.name,
        provider=account.cloud_provider,
        status=AccountStatus.COMPLETED,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        findings_count=len(findings),
        findings=findings,
        assets=AssetCollection([]),
        regions_scanned=account.regions,
        collectors_used=["aws_s3", "aws_iam"],
    )


def mock_failing_scanner(account: AccountConfig, options: ScanOptions) -> AccountScanResult:
    """Mock scanner that always fails."""
    raise Exception("Simulated scan failure")


# =============================================================================
# ScanOptions Tests
# =============================================================================


class TestScanOptions:
    """Tests for ScanOptions class."""

    def test_default_options(self):
        """Test default scan options."""
        options = ScanOptions()
        assert options.parallel_accounts == 3
        assert options.timeout_per_account == 300
        assert options.continue_on_error
        assert options.severity_threshold is None
        assert options.collectors is None
        assert options.regions is None

    def test_custom_options(self):
        """Test custom scan options."""
        options = ScanOptions(
            parallel_accounts=5,
            timeout_per_account=600,
            continue_on_error=False,
            severity_threshold=Severity.HIGH,
            collectors=["aws_s3"],
            skip_accounts=["skip-me"],
        )
        assert options.parallel_accounts == 5
        assert options.severity_threshold == Severity.HIGH
        assert "skip-me" in options.skip_accounts

    def test_options_to_dict(self):
        """Test converting options to dictionary."""
        options = ScanOptions(
            severity_threshold=Severity.CRITICAL,
            skip_accounts=["acc1"],
        )
        data = options.to_dict()
        assert data["severity_threshold"] == "critical"
        assert data["skip_accounts"] == ["acc1"]


# =============================================================================
# AccountScanResult Tests
# =============================================================================


class TestAccountScanResult:
    """Tests for AccountScanResult class."""

    def test_create_result(self):
        """Test creating an account scan result."""
        result = AccountScanResult(
            account_id="123456789012",
            account_name="Production",
            provider=CloudProvider.AWS,
        )
        assert result.status == AccountStatus.PENDING
        assert result.findings_count == 0

    def test_result_duration(self):
        """Test calculating result duration."""
        start = datetime(2024, 1, 15, 10, 0)
        end = datetime(2024, 1, 15, 10, 5)
        result = AccountScanResult(
            account_id="123",
            account_name="Test",
            provider=CloudProvider.AWS,
            started_at=start,
            completed_at=end,
        )
        assert result.duration == timedelta(minutes=5)

    def test_result_is_success(self):
        """Test success status check."""
        result = AccountScanResult(
            account_id="123",
            account_name="Test",
            provider=CloudProvider.AWS,
            status=AccountStatus.COMPLETED,
        )
        assert result.is_success

        result.status = AccountStatus.FAILED
        assert not result.is_success

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = AccountScanResult(
            account_id="123",
            account_name="Test",
            provider=CloudProvider.AWS,
            status=AccountStatus.COMPLETED,
            findings_count=5,
        )
        data = result.to_dict()
        assert data["account_id"] == "123"
        assert data["status"] == "completed"
        assert data["findings_count"] == 5


# =============================================================================
# ScanProgress Tests
# =============================================================================


class TestScanProgress:
    """Tests for ScanProgress class."""

    def test_create_progress(self):
        """Test creating scan progress."""
        progress = ScanProgress(
            scan_id="scan-1",
            total_accounts=5,
        )
        assert progress.total_accounts == 5
        assert progress.completed_accounts == 0
        assert progress.pending_accounts == 5

    def test_progress_percent(self):
        """Test progress percentage calculation."""
        progress = ScanProgress(
            scan_id="scan-1",
            total_accounts=10,
            completed_accounts=3,
            failed_accounts=1,
            skipped_accounts=1,
        )
        assert progress.progress_percent == 50.0
        assert progress.pending_accounts == 5

    def test_progress_is_complete(self):
        """Test completion check."""
        progress = ScanProgress(
            scan_id="scan-1",
            total_accounts=5,
            completed_accounts=5,
        )
        assert progress.is_complete

        progress.current_accounts = ["running"]
        assert not progress.is_complete

    def test_progress_to_dict(self):
        """Test converting progress to dictionary."""
        progress = ScanProgress(
            scan_id="scan-1",
            total_accounts=10,
            completed_accounts=5,
            findings_so_far=25,
        )
        data = progress.to_dict()
        assert data["scan_id"] == "scan-1"
        assert data["progress_percent"] == 50.0
        assert data["findings_so_far"] == 25


# =============================================================================
# OrganizationScan Tests
# =============================================================================


class TestOrganizationScan:
    """Tests for OrganizationScan class."""

    def test_create_scan(self):
        """Test creating an organization scan."""
        scan = OrganizationScan(
            scan_id="org-scan-1",
            config_name="production",
            started_at=datetime(2024, 1, 15, 10, 0),
        )
        assert scan.scan_id == "org-scan-1"
        assert scan.config_name == "production"

    def test_scan_duration(self):
        """Test scan duration calculation."""
        scan = OrganizationScan(
            scan_id="org-scan-1",
            config_name="test",
            started_at=datetime(2024, 1, 15, 10, 0),
            completed_at=datetime(2024, 1, 15, 10, 30),
        )
        assert scan.duration == timedelta(minutes=30)

    def test_scan_success_count(self):
        """Test counting successful scans."""
        scan = OrganizationScan(
            scan_id="org-scan-1",
            config_name="test",
            started_at=datetime.utcnow(),
            account_results=[
                AccountScanResult("acc1", "Acc 1", CloudProvider.AWS, status=AccountStatus.COMPLETED),
                AccountScanResult("acc2", "Acc 2", CloudProvider.AWS, status=AccountStatus.COMPLETED),
                AccountScanResult("acc3", "Acc 3", CloudProvider.AWS, status=AccountStatus.FAILED),
            ],
        )
        assert scan.success_count == 2
        assert scan.failure_count == 1

    def test_scan_total_findings(self):
        """Test total findings count."""
        scan = OrganizationScan(
            scan_id="org-scan-1",
            config_name="test",
            started_at=datetime.utcnow(),
            account_results=[
                AccountScanResult("acc1", "Acc 1", CloudProvider.AWS, findings_count=5),
                AccountScanResult("acc2", "Acc 2", CloudProvider.AWS, findings_count=10),
            ],
        )
        assert scan.total_findings == 15

    def test_scan_findings_by_provider(self):
        """Test findings count by provider."""
        scan = OrganizationScan(
            scan_id="org-scan-1",
            config_name="test",
            started_at=datetime.utcnow(),
            account_results=[
                AccountScanResult("acc1", "Acc 1", CloudProvider.AWS, findings_count=5),
                AccountScanResult("acc2", "Acc 2", CloudProvider.AWS, findings_count=10),
                AccountScanResult("gcp1", "GCP 1", CloudProvider.GCP, findings_count=3),
            ],
        )
        by_provider = scan.get_findings_by_provider()
        assert by_provider["aws"] == 15
        assert by_provider["gcp"] == 3

    def test_scan_get_failed_accounts(self):
        """Test getting failed accounts."""
        scan = OrganizationScan(
            scan_id="org-scan-1",
            config_name="test",
            started_at=datetime.utcnow(),
            account_results=[
                AccountScanResult("acc1", "Acc 1", CloudProvider.AWS, status=AccountStatus.COMPLETED),
                AccountScanResult("acc2", "Acc 2", CloudProvider.AWS, status=AccountStatus.FAILED, error="Test error"),
            ],
        )
        failed = scan.get_failed_accounts()
        assert len(failed) == 1
        assert failed[0].account_id == "acc2"
        assert failed[0].error == "Test error"

    def test_scan_to_dict(self):
        """Test converting scan to dictionary."""
        scan = OrganizationScan(
            scan_id="org-scan-1",
            config_name="test",
            started_at=datetime(2024, 1, 15, 10, 0),
            completed_at=datetime(2024, 1, 15, 10, 30),
            account_results=[
                AccountScanResult("acc1", "Acc 1", CloudProvider.AWS, findings_count=5),
            ],
        )
        data = scan.to_dict()
        assert data["scan_id"] == "org-scan-1"
        assert data["summary"]["total_accounts"] == 1
        assert data["summary"]["total_findings"] == 5


# =============================================================================
# MultiAccountScanner Tests
# =============================================================================


class TestMultiAccountScanner:
    """Tests for MultiAccountScanner class."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = MultiAccountScanner()
        assert not scanner.is_running()
        assert scanner.get_progress() is None

    def test_scanner_with_config(self, sample_config):
        """Test scanner with configuration."""
        scanner = MultiAccountScanner(config=sample_config)
        accounts = scanner.get_accounts_to_scan()
        assert len(accounts) == 4  # Excludes disabled account

    def test_get_accounts_to_scan(self, sample_config):
        """Test getting accounts to scan."""
        scanner = MultiAccountScanner(config=sample_config)

        # Default options - excludes disabled
        accounts = scanner.get_accounts_to_scan()
        assert len(accounts) == 4

        # Include disabled
        options = ScanOptions(include_disabled=True)
        accounts = scanner.get_accounts_to_scan(options)
        assert len(accounts) == 5

    def test_get_accounts_with_skip(self, sample_config):
        """Test skipping specific accounts."""
        scanner = MultiAccountScanner(config=sample_config)
        options = ScanOptions(skip_accounts=["111111111111"])
        accounts = scanner.get_accounts_to_scan(options)
        assert len(accounts) == 3
        assert all(a.account_id != "111111111111" for a in accounts)

    def test_scan_single_account(self, sample_accounts):
        """Test scanning a single account."""
        scanner = MultiAccountScanner()
        scanner.set_account_scanner(mock_scanner)

        result = scanner.scan_single_account(sample_accounts[0])

        assert result.is_success
        assert result.account_id == "111111111111"
        assert result.findings_count == 1
        assert result.duration is not None

    def test_scan_single_account_failure(self, sample_accounts):
        """Test handling single account scan failure."""
        scanner = MultiAccountScanner()
        scanner.set_account_scanner(mock_failing_scanner)

        result = scanner.scan_single_account(sample_accounts[0])

        assert result.status == AccountStatus.FAILED
        assert "Simulated scan failure" in result.error

    def test_scan_all_accounts(self, sample_config):
        """Test scanning all accounts."""
        scanner = MultiAccountScanner(config=sample_config)
        scanner.set_account_scanner(mock_scanner)

        org_scan = scanner.scan()

        assert len(org_scan.account_results) == 4
        assert org_scan.success_count == 4
        assert org_scan.failure_count == 0
        assert org_scan.total_findings == 4  # 1 per account

    def test_scan_with_aggregation(self, sample_config):
        """Test that scan aggregates findings."""
        scanner = MultiAccountScanner(config=sample_config)
        scanner.set_account_scanner(mock_scanner)

        org_scan = scanner.scan()

        assert org_scan.aggregated_findings is not None
        assert org_scan.aggregation_result is not None
        assert org_scan.aggregation_result.total_findings == 4

    def test_scan_parallel_execution(self, sample_config):
        """Test parallel execution."""
        scanner = MultiAccountScanner(config=sample_config)
        scanner.set_account_scanner(mock_scanner)

        options = ScanOptions(parallel_accounts=2)
        org_scan = scanner.scan(options)

        assert len(org_scan.account_results) == 4
        assert org_scan.success_count == 4

    def test_scan_continue_on_error(self, sample_config):
        """Test continue on error option."""
        call_count = [0]

        def sometimes_failing_scanner(account: AccountConfig, options: ScanOptions) -> AccountScanResult:
            call_count[0] += 1
            if call_count[0] == 2:
                raise Exception("Simulated failure")
            return mock_scanner(account, options)

        scanner = MultiAccountScanner(config=sample_config)
        scanner.set_account_scanner(sometimes_failing_scanner)

        options = ScanOptions(continue_on_error=True)
        org_scan = scanner.scan(options)

        # Should have scanned all accounts despite one failure
        assert len(org_scan.account_results) == 4
        assert org_scan.failure_count == 1
        assert org_scan.success_count == 3

    def test_progress_callbacks(self, sample_config):
        """Test progress callbacks."""
        progress_updates = []

        def track_progress(progress: ScanProgress):
            progress_updates.append(progress.to_dict())

        scanner = MultiAccountScanner(config=sample_config)
        scanner.set_account_scanner(mock_scanner)
        scanner.add_progress_callback(track_progress)

        org_scan = scanner.scan()

        # Should have received progress updates
        assert len(progress_updates) > 0
        # Last update should show completion
        assert progress_updates[-1]["is_complete"]

    def test_generate_report(self, sample_config):
        """Test generating report."""
        scanner = MultiAccountScanner(config=sample_config)
        scanner.set_account_scanner(mock_scanner)

        org_scan = scanner.scan()
        report = scanner.generate_report(org_scan)

        assert report["scan_id"] == org_scan.scan_id
        assert report["summary"]["accounts_scanned"] == 4
        assert report["summary"]["accounts_successful"] == 4
        assert report["summary"]["total_findings"] == 4
        assert "top_accounts_by_findings" in report
        assert "findings_by_provider" in report

    def test_no_config_raises_error(self):
        """Test that scanning without config raises error."""
        scanner = MultiAccountScanner()
        with pytest.raises(ValueError, match="No configuration set"):
            scanner.scan()

    def test_set_config(self, sample_config):
        """Test setting configuration after init."""
        scanner = MultiAccountScanner()
        scanner.set_config(sample_config)
        scanner.set_account_scanner(mock_scanner)

        org_scan = scanner.scan()
        assert len(org_scan.account_results) == 4


class TestMultiAccountScannerIntegration:
    """Integration tests for MultiAccountScanner."""

    def test_full_scan_workflow(self, sample_config):
        """Test complete scan workflow."""
        progress_history = []

        def mock_scanner_with_findings(account: AccountConfig, options: ScanOptions) -> AccountScanResult:
            # Create findings based on account
            if account.cloud_provider == CloudProvider.AWS:
                findings = FindingCollection([
                    Finding(
                        id=f"finding-{account.account_id}-s3",
                        asset_id=f"arn:aws:s3:::bucket-{account.account_id}",
                        finding_type=FindingType.MISCONFIGURATION,
                        severity=Severity.HIGH,
                        status=FindingStatus.OPEN,
                        title="S3 bucket issue",
                        description="Test",
                    ),
                    Finding(
                        id=f"finding-{account.account_id}-iam",
                        asset_id=f"arn:aws:iam::{account.account_id}:user/test",
                        finding_type=FindingType.MISCONFIGURATION,
                        severity=Severity.CRITICAL,
                        status=FindingStatus.OPEN,
                        title="IAM issue",
                        description="Test",
                    ),
                ])
            else:
                findings = FindingCollection([
                    Finding(
                        id=f"finding-{account.account_id}-1",
                        asset_id=f"resource-{account.account_id}",
                        finding_type=FindingType.MISCONFIGURATION,
                        severity=Severity.MEDIUM,
                        status=FindingStatus.OPEN,
                        title="General issue",
                        description="Test",
                    ),
                ])

            return AccountScanResult(
                account_id=account.account_id,
                account_name=account.name,
                provider=account.cloud_provider,
                status=AccountStatus.COMPLETED,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                findings_count=len(findings),
                findings=findings,
            )

        scanner = MultiAccountScanner(config=sample_config)
        scanner.set_account_scanner(mock_scanner_with_findings)
        scanner.add_progress_callback(lambda p: progress_history.append(p.to_dict()))

        # Run scan
        org_scan = scanner.scan()

        # Verify results
        assert org_scan.success_count == 4
        assert org_scan.total_findings == 6  # 2 AWS accounts * 2 + 2 other accounts * 1

        # Verify aggregation
        assert org_scan.aggregated_findings is not None
        assert len(org_scan.aggregated_findings) <= org_scan.total_findings

        # Verify report
        report = scanner.generate_report(org_scan)
        assert report["summary"]["scan_success_rate"] == 100.0
        assert "aws" in report["findings_by_provider"]
