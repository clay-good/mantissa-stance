"""
Multi-Account Scanner for Mantissa Stance.

Provides orchestration for scanning multiple cloud accounts across AWS, GCP,
and Azure, with parallel execution, progress tracking, and aggregated results.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

from stance.aggregation.aggregator import (
    AggregationResult,
    CloudAccount,
    FindingsAggregator,
)
from stance.config.scan_config import AccountConfig, CloudProvider, ScanConfiguration
from stance.models.asset import AssetCollection
from stance.models.finding import FindingCollection, Severity

logger = logging.getLogger(__name__)


class AccountStatus(Enum):
    """Status of an account scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanOptions:
    """
    Options for multi-account scanning.

    Attributes:
        parallel_accounts: Number of accounts to scan in parallel
        timeout_per_account: Maximum time per account scan (seconds)
        continue_on_error: Continue scanning other accounts if one fails
        severity_threshold: Minimum severity to include in results
        collectors: List of collectors to run (None = all)
        regions: List of regions to scan (None = all configured)
        skip_accounts: Account IDs to skip
        include_disabled: Include disabled accounts
    """

    parallel_accounts: int = 3
    timeout_per_account: int = 300
    continue_on_error: bool = True
    severity_threshold: Severity | None = None
    collectors: list[str] | None = None
    regions: list[str] | None = None
    skip_accounts: list[str] = field(default_factory=list)
    include_disabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "parallel_accounts": self.parallel_accounts,
            "timeout_per_account": self.timeout_per_account,
            "continue_on_error": self.continue_on_error,
            "severity_threshold": self.severity_threshold.value
            if self.severity_threshold
            else None,
            "collectors": self.collectors,
            "regions": self.regions,
            "skip_accounts": self.skip_accounts,
            "include_disabled": self.include_disabled,
        }


@dataclass
class AccountScanResult:
    """
    Result of scanning a single account.

    Attributes:
        account_id: Account identifier
        account_name: Human-readable account name
        provider: Cloud provider
        status: Scan status
        started_at: When scan started
        completed_at: When scan completed
        findings_count: Number of findings discovered
        assets_count: Number of assets scanned
        findings: Findings from this account
        assets: Assets discovered in this account
        error: Error message if scan failed
        regions_scanned: Regions that were scanned
        collectors_used: Collectors that were run
    """

    account_id: str
    account_name: str
    provider: CloudProvider
    status: AccountStatus = AccountStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
    assets_count: int = 0
    findings: FindingCollection | None = None
    assets: AssetCollection | None = None
    error: str = ""
    regions_scanned: list[str] = field(default_factory=list)
    collectors_used: list[str] = field(default_factory=list)

    @property
    def duration(self) -> timedelta | None:
        """Get scan duration."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def is_success(self) -> bool:
        """Check if scan was successful."""
        return self.status == AccountStatus.COMPLETED

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "account_id": self.account_id,
            "account_name": self.account_name,
            "provider": self.provider.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration.total_seconds() if self.duration else None,
            "findings_count": self.findings_count,
            "assets_count": self.assets_count,
            "error": self.error,
            "regions_scanned": self.regions_scanned,
            "collectors_used": self.collectors_used,
        }


@dataclass
class ScanProgress:
    """
    Real-time progress of a multi-account scan.

    Attributes:
        scan_id: Unique scan identifier
        total_accounts: Total accounts to scan
        completed_accounts: Accounts completed
        failed_accounts: Accounts that failed
        skipped_accounts: Accounts that were skipped
        current_accounts: Accounts currently being scanned
        findings_so_far: Findings discovered so far
        started_at: When scan started
        estimated_completion: Estimated completion time
    """

    scan_id: str
    total_accounts: int = 0
    completed_accounts: int = 0
    failed_accounts: int = 0
    skipped_accounts: int = 0
    current_accounts: list[str] = field(default_factory=list)
    findings_so_far: int = 0
    started_at: datetime = field(default_factory=datetime.utcnow)
    estimated_completion: datetime | None = None

    @property
    def pending_accounts(self) -> int:
        """Get number of pending accounts."""
        return self.total_accounts - (
            self.completed_accounts + self.failed_accounts + self.skipped_accounts
        )

    @property
    def progress_percent(self) -> float:
        """Get progress as percentage."""
        if self.total_accounts == 0:
            return 0.0
        return (
            (self.completed_accounts + self.failed_accounts + self.skipped_accounts)
            / self.total_accounts
            * 100
        )

    @property
    def is_complete(self) -> bool:
        """Check if scan is complete."""
        return self.pending_accounts == 0 and len(self.current_accounts) == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "total_accounts": self.total_accounts,
            "completed_accounts": self.completed_accounts,
            "failed_accounts": self.failed_accounts,
            "skipped_accounts": self.skipped_accounts,
            "pending_accounts": self.pending_accounts,
            "current_accounts": self.current_accounts,
            "findings_so_far": self.findings_so_far,
            "progress_percent": self.progress_percent,
            "started_at": self.started_at.isoformat(),
            "estimated_completion": self.estimated_completion.isoformat()
            if self.estimated_completion
            else None,
            "is_complete": self.is_complete,
        }


@dataclass
class OrganizationScan:
    """
    Complete result of an organization-level scan.

    Attributes:
        scan_id: Unique scan identifier
        config_name: Configuration used for the scan
        started_at: When scan started
        completed_at: When scan completed
        options: Scan options used
        account_results: Results for each account
        aggregated_findings: Deduplicated findings across all accounts
        aggregation_result: Aggregation statistics
        cross_account_findings: Findings appearing in multiple accounts
        summary: Summary statistics
    """

    scan_id: str
    config_name: str
    started_at: datetime
    completed_at: datetime | None = None
    options: ScanOptions = field(default_factory=ScanOptions)
    account_results: list[AccountScanResult] = field(default_factory=list)
    aggregated_findings: FindingCollection | None = None
    aggregation_result: AggregationResult | None = None
    cross_account_findings: FindingCollection | None = None
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> timedelta | None:
        """Get total scan duration."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def success_count(self) -> int:
        """Get number of successful account scans."""
        return sum(1 for r in self.account_results if r.is_success)

    @property
    def failure_count(self) -> int:
        """Get number of failed account scans."""
        return sum(1 for r in self.account_results if r.status == AccountStatus.FAILED)

    @property
    def total_findings(self) -> int:
        """Get total findings count."""
        return sum(r.findings_count for r in self.account_results)

    @property
    def total_assets(self) -> int:
        """Get total assets count."""
        return sum(r.assets_count for r in self.account_results)

    def get_findings_by_severity(self) -> dict[str, int]:
        """Get findings count by severity."""
        if self.aggregation_result:
            return self.aggregation_result.findings_by_severity
        return {}

    def get_findings_by_account(self) -> dict[str, int]:
        """Get findings count by account."""
        return {r.account_id: r.findings_count for r in self.account_results}

    def get_findings_by_provider(self) -> dict[str, int]:
        """Get findings count by provider."""
        by_provider: dict[str, int] = {}
        for result in self.account_results:
            provider = result.provider.value
            by_provider[provider] = by_provider.get(provider, 0) + result.findings_count
        return by_provider

    def get_failed_accounts(self) -> list[AccountScanResult]:
        """Get list of failed account scans."""
        return [r for r in self.account_results if r.status == AccountStatus.FAILED]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "config_name": self.config_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration.total_seconds() if self.duration else None,
            "options": self.options.to_dict(),
            "account_results": [r.to_dict() for r in self.account_results],
            "aggregation_result": self.aggregation_result.to_dict()
            if self.aggregation_result
            else None,
            "cross_account_findings_count": len(self.cross_account_findings)
            if self.cross_account_findings
            else 0,
            "summary": {
                "total_accounts": len(self.account_results),
                "successful_accounts": self.success_count,
                "failed_accounts": self.failure_count,
                "total_findings": self.total_findings,
                "unique_findings": len(self.aggregated_findings)
                if self.aggregated_findings
                else 0,
                "total_assets": self.total_assets,
                "findings_by_severity": self.get_findings_by_severity(),
                "findings_by_provider": self.get_findings_by_provider(),
            },
        }


class MultiAccountScanner:
    """
    Orchestrates scanning across multiple cloud accounts.

    Provides parallel execution, progress tracking, and cross-account
    findings aggregation for organization-level security assessments.
    """

    def __init__(
        self,
        config: ScanConfiguration | None = None,
        account_scanner: Callable[[AccountConfig, ScanOptions], AccountScanResult] | None = None,
    ):
        """
        Initialize the multi-account scanner.

        Args:
            config: Scan configuration with account definitions
            account_scanner: Function to scan a single account
        """
        self._config = config
        self._account_scanner = account_scanner
        self._progress: ScanProgress | None = None
        self._lock = threading.Lock()
        self._progress_callbacks: list[Callable[[ScanProgress], None]] = []
        self._running = False

    def set_config(self, config: ScanConfiguration) -> None:
        """Set the scan configuration."""
        self._config = config

    def set_account_scanner(
        self,
        scanner: Callable[[AccountConfig, ScanOptions], AccountScanResult],
    ) -> None:
        """Set the account scanner function."""
        self._account_scanner = scanner

    def add_progress_callback(
        self,
        callback: Callable[[ScanProgress], None],
    ) -> None:
        """Add a callback for progress updates."""
        self._progress_callbacks.append(callback)

    def get_progress(self) -> ScanProgress | None:
        """Get current scan progress."""
        return self._progress

    def is_running(self) -> bool:
        """Check if a scan is currently running."""
        return self._running

    def get_accounts_to_scan(
        self,
        options: ScanOptions | None = None,
    ) -> list[AccountConfig]:
        """
        Get list of accounts that will be scanned.

        Args:
            options: Scan options for filtering

        Returns:
            List of accounts to scan
        """
        if not self._config:
            return []

        options = options or ScanOptions()
        accounts = []

        for account in self._config.accounts:
            # Skip disabled accounts unless explicitly included
            if not account.enabled and not options.include_disabled:
                continue

            # Skip accounts in skip list
            if account.account_id in options.skip_accounts:
                continue

            accounts.append(account)

        return accounts

    def scan(
        self,
        options: ScanOptions | None = None,
    ) -> OrganizationScan:
        """
        Scan all configured accounts.

        Args:
            options: Scan options

        Returns:
            Complete organization scan result
        """
        if not self._config:
            raise ValueError("No configuration set. Call set_config() first.")

        options = options or ScanOptions()
        scan_id = str(uuid4())
        started_at = datetime.utcnow()

        # Get accounts to scan
        accounts = self.get_accounts_to_scan(options)

        # Initialize progress
        self._progress = ScanProgress(
            scan_id=scan_id,
            total_accounts=len(accounts),
            started_at=started_at,
        )
        self._running = True

        # Notify initial progress
        self._notify_progress()

        # Create organization scan result
        org_scan = OrganizationScan(
            scan_id=scan_id,
            config_name=self._config.name,
            started_at=started_at,
            options=options,
        )

        try:
            # Scan accounts in parallel
            results = self._scan_accounts_parallel(accounts, options)
            org_scan.account_results = results

            # Aggregate findings
            aggregator = FindingsAggregator()
            for result in results:
                if result.is_success and result.findings:
                    cloud_account = CloudAccount(
                        id=result.account_id,
                        provider=result.provider.value,
                        name=result.account_name,
                    )
                    aggregator.add_account(cloud_account)
                    aggregator.add_findings(result.account_id, result.findings)

            # Perform aggregation
            aggregated, agg_result = aggregator.aggregate()
            org_scan.aggregated_findings = aggregated
            org_scan.aggregation_result = agg_result

            # Get cross-account findings
            org_scan.cross_account_findings = aggregator.get_cross_account_findings()

        finally:
            self._running = False
            org_scan.completed_at = datetime.utcnow()

            # Update progress to complete
            if self._progress:
                self._progress.current_accounts = []
                self._notify_progress()

        return org_scan

    def scan_single_account(
        self,
        account: AccountConfig,
        options: ScanOptions | None = None,
    ) -> AccountScanResult:
        """
        Scan a single account.

        Args:
            account: Account to scan
            options: Scan options

        Returns:
            Account scan result
        """
        options = options or ScanOptions()

        result = AccountScanResult(
            account_id=account.account_id,
            account_name=account.name or account.account_id,
            provider=account.cloud_provider,
            started_at=datetime.utcnow(),
        )

        try:
            result.status = AccountStatus.RUNNING

            if self._account_scanner:
                # Use provided scanner
                scanned = self._account_scanner(account, options)
                result.findings = scanned.findings
                result.assets = scanned.assets
                result.findings_count = scanned.findings_count
                result.assets_count = scanned.assets_count
                result.regions_scanned = scanned.regions_scanned
                result.collectors_used = scanned.collectors_used
            else:
                # Default: create empty result (for testing/mocking)
                result.findings = FindingCollection([])
                result.assets = AssetCollection([])

            result.status = AccountStatus.COMPLETED

        except Exception as e:
            result.status = AccountStatus.FAILED
            result.error = str(e)
            logger.error(f"Failed to scan account {account.account_id}: {e}")

        finally:
            result.completed_at = datetime.utcnow()

        return result

    def _scan_accounts_parallel(
        self,
        accounts: list[AccountConfig],
        options: ScanOptions,
    ) -> list[AccountScanResult]:
        """Scan accounts in parallel."""
        results: list[AccountScanResult] = []

        with ThreadPoolExecutor(max_workers=options.parallel_accounts) as executor:
            # Submit all scan jobs
            future_to_account = {
                executor.submit(
                    self._scan_account_with_timeout,
                    account,
                    options,
                ): account
                for account in accounts
            }

            # Collect results as they complete
            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    result = future.result()
                    results.append(result)

                    # Update progress
                    with self._lock:
                        if self._progress:
                            if result.is_success:
                                self._progress.completed_accounts += 1
                            else:
                                self._progress.failed_accounts += 1
                            self._progress.findings_so_far += result.findings_count
                            if account.account_id in self._progress.current_accounts:
                                self._progress.current_accounts.remove(account.account_id)
                            self._update_estimated_completion()

                    self._notify_progress()

                except Exception as e:
                    # Handle unexpected errors
                    result = AccountScanResult(
                        account_id=account.account_id,
                        account_name=account.name or account.account_id,
                        provider=account.cloud_provider,
                        status=AccountStatus.FAILED,
                        error=str(e),
                        started_at=datetime.utcnow(),
                        completed_at=datetime.utcnow(),
                    )
                    results.append(result)

                    with self._lock:
                        if self._progress:
                            self._progress.failed_accounts += 1
                            if account.account_id in self._progress.current_accounts:
                                self._progress.current_accounts.remove(account.account_id)

                    self._notify_progress()

                    if not options.continue_on_error:
                        raise

        return results

    def _scan_account_with_timeout(
        self,
        account: AccountConfig,
        options: ScanOptions,
    ) -> AccountScanResult:
        """Scan an account with timeout handling."""
        # Update progress - mark as current
        with self._lock:
            if self._progress:
                self._progress.current_accounts.append(account.account_id)
        self._notify_progress()

        # Perform scan
        return self.scan_single_account(account, options)

    def _update_estimated_completion(self) -> None:
        """Update estimated completion time based on current progress."""
        if not self._progress:
            return

        completed = (
            self._progress.completed_accounts
            + self._progress.failed_accounts
            + self._progress.skipped_accounts
        )

        if completed == 0:
            return

        elapsed = datetime.utcnow() - self._progress.started_at
        avg_per_account = elapsed / completed
        remaining = self._progress.pending_accounts + len(self._progress.current_accounts)

        self._progress.estimated_completion = datetime.utcnow() + (
            avg_per_account * remaining
        )

    def _notify_progress(self) -> None:
        """Notify progress callbacks."""
        if not self._progress:
            return

        for callback in self._progress_callbacks:
            try:
                callback(self._progress)
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")

    def generate_report(self, org_scan: OrganizationScan) -> dict[str, Any]:
        """
        Generate a detailed report for an organization scan.

        Args:
            org_scan: Completed organization scan

        Returns:
            Report dictionary
        """
        # Find most vulnerable accounts
        sorted_by_findings = sorted(
            org_scan.account_results,
            key=lambda r: r.findings_count,
            reverse=True,
        )

        # Find accounts with critical findings
        critical_accounts = []
        for result in org_scan.account_results:
            if result.findings:
                critical_count = sum(
                    1 for f in result.findings if f.severity == Severity.CRITICAL
                )
                if critical_count > 0:
                    critical_accounts.append({
                        "account_id": result.account_id,
                        "account_name": result.account_name,
                        "provider": result.provider.value,
                        "critical_findings": critical_count,
                    })

        # Calculate compliance metrics
        total_possible = len(org_scan.account_results)
        successful = org_scan.success_count
        compliance_rate = (successful / total_possible * 100) if total_possible > 0 else 0

        return {
            "scan_id": org_scan.scan_id,
            "scan_date": org_scan.started_at.isoformat(),
            "duration_seconds": org_scan.duration.total_seconds() if org_scan.duration else 0,
            "summary": {
                "accounts_scanned": len(org_scan.account_results),
                "accounts_successful": org_scan.success_count,
                "accounts_failed": org_scan.failure_count,
                "scan_success_rate": compliance_rate,
                "total_findings": org_scan.total_findings,
                "unique_findings": len(org_scan.aggregated_findings)
                if org_scan.aggregated_findings
                else 0,
                "cross_account_findings": len(org_scan.cross_account_findings)
                if org_scan.cross_account_findings
                else 0,
                "total_assets": org_scan.total_assets,
            },
            "findings_by_severity": org_scan.get_findings_by_severity(),
            "findings_by_provider": org_scan.get_findings_by_provider(),
            "findings_by_account": org_scan.get_findings_by_account(),
            "top_accounts_by_findings": [
                {
                    "account_id": r.account_id,
                    "account_name": r.account_name,
                    "findings_count": r.findings_count,
                }
                for r in sorted_by_findings[:10]
            ],
            "accounts_with_critical_findings": critical_accounts,
            "failed_accounts": [
                {
                    "account_id": r.account_id,
                    "account_name": r.account_name,
                    "error": r.error,
                }
                for r in org_scan.get_failed_accounts()
            ],
        }
