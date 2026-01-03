"""
Findings aggregator for multi-cloud deployments.

Collects and aggregates findings from multiple cloud accounts and providers
into a unified view for centralized security posture management.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from stance.models.finding import Finding, FindingCollection, Severity, FindingStatus
from stance.models.asset import Asset, AssetCollection

logger = logging.getLogger(__name__)


@dataclass
class CloudAccount:
    """
    Represents a cloud account/project/subscription.

    Attributes:
        id: Account identifier (AWS account ID, GCP project ID, Azure subscription ID)
        provider: Cloud provider (aws, gcp, azure)
        name: Human-readable account name
        region: Primary region (optional)
        metadata: Additional account metadata
    """

    id: str
    provider: str
    name: str
    region: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregationResult:
    """
    Result of an aggregation operation.

    Attributes:
        total_findings: Total number of findings before deduplication
        unique_findings: Number of unique findings after deduplication
        duplicates_removed: Number of duplicates removed
        findings_by_severity: Count of findings by severity
        findings_by_provider: Count of findings by cloud provider
        findings_by_account: Count of findings by account
        aggregated_at: Timestamp of aggregation
        source_accounts: List of accounts included
        metadata: Additional aggregation metadata
    """

    total_findings: int = 0
    unique_findings: int = 0
    duplicates_removed: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_provider: dict[str, int] = field(default_factory=dict)
    findings_by_account: dict[str, int] = field(default_factory=dict)
    aggregated_at: datetime = field(default_factory=datetime.utcnow)
    source_accounts: list[CloudAccount] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_findings": self.total_findings,
            "unique_findings": self.unique_findings,
            "duplicates_removed": self.duplicates_removed,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_provider": self.findings_by_provider,
            "findings_by_account": self.findings_by_account,
            "aggregated_at": self.aggregated_at.isoformat(),
            "source_accounts": [
                {"id": a.id, "provider": a.provider, "name": a.name}
                for a in self.source_accounts
            ],
            "metadata": self.metadata,
        }


@dataclass
class NormalizedFinding:
    """
    A finding normalized to common format for cross-cloud comparison.

    Attributes:
        original: The original Finding object
        normalized_key: Unique key for deduplication
        provider: Cloud provider
        account_id: Cloud account identifier
        canonical_resource_type: Normalized resource type
        canonical_rule_id: Normalized rule identifier
    """

    original: Finding
    normalized_key: str
    provider: str
    account_id: str
    canonical_resource_type: str
    canonical_rule_id: str


class FindingsAggregator:
    """
    Aggregates findings from multiple cloud accounts.

    Collects findings from multiple AWS accounts, GCP projects, and Azure
    subscriptions, normalizes them to a common format, deduplicates across
    accounts, and generates aggregate reports.

    Example:
        >>> aggregator = FindingsAggregator()
        >>> aggregator.add_account(CloudAccount("123456789012", "aws", "Production"))
        >>> aggregator.add_account(CloudAccount("my-project", "gcp", "GCP Prod"))
        >>> aggregator.add_findings("123456789012", findings_aws)
        >>> aggregator.add_findings("my-project", findings_gcp)
        >>> result = aggregator.aggregate()
        >>> print(f"Unique findings: {result.unique_findings}")
    """

    # Resource type mappings across cloud providers
    RESOURCE_TYPE_MAPPINGS = {
        # Storage
        "aws_s3_bucket": "storage_bucket",
        "google_storage_bucket": "storage_bucket",
        "azure_storage_account": "storage_bucket",
        # Compute
        "aws_ec2_instance": "virtual_machine",
        "google_compute_instance": "virtual_machine",
        "azure_virtual_machine": "virtual_machine",
        # IAM
        "aws_iam_user": "iam_user",
        "google_iam_user": "iam_user",
        "azure_ad_user": "iam_user",
        "aws_iam_role": "iam_role",
        "google_service_account": "iam_role",
        "azure_managed_identity": "iam_role",
        # Network
        "aws_security_group": "network_security",
        "google_compute_firewall": "network_security",
        "azure_network_security_group": "network_security",
        # Database
        "aws_rds_instance": "database",
        "google_sql_instance": "database",
        "azure_sql_database": "database",
    }

    # Rule ID mappings for cross-cloud equivalents
    RULE_MAPPINGS = {
        # Encryption rules
        "aws-s3-001": "storage-encryption",  # S3 encryption
        "gcp-storage-001": "storage-encryption",  # GCS encryption
        "azure-storage-001": "storage-encryption",  # Azure Storage encryption
        # Public access rules
        "aws-s3-002": "storage-public-access",
        "gcp-storage-002": "storage-public-access",
        "azure-storage-002": "storage-public-access",
        # IAM rules
        "aws-iam-001": "iam-root-mfa",
        "gcp-iam-001": "iam-admin-mfa",
        "azure-iam-001": "iam-admin-mfa",
    }

    def __init__(
        self,
        dedup_window_hours: int = 24,
        custom_normalizer: Callable[[Finding, str], NormalizedFinding] | None = None,
    ) -> None:
        """
        Initialize the findings aggregator.

        Args:
            dedup_window_hours: Time window for deduplication (findings within
                               this window are considered potential duplicates)
            custom_normalizer: Optional custom function to normalize findings
        """
        self._accounts: dict[str, CloudAccount] = {}
        self._findings: dict[str, list[Finding]] = {}
        self._assets: dict[str, list[Asset]] = {}
        self._dedup_window_hours = dedup_window_hours
        self._custom_normalizer = custom_normalizer

    def add_account(self, account: CloudAccount) -> None:
        """
        Add a cloud account to the aggregation.

        Args:
            account: CloudAccount to add
        """
        self._accounts[account.id] = account
        if account.id not in self._findings:
            self._findings[account.id] = []
        if account.id not in self._assets:
            self._assets[account.id] = []
        logger.info(f"Added account: {account.provider}/{account.name} ({account.id})")

    def add_findings(
        self,
        account_id: str,
        findings: FindingCollection | list[Finding],
    ) -> None:
        """
        Add findings from a cloud account.

        Args:
            account_id: Account identifier
            findings: Findings to add

        Raises:
            ValueError: If account has not been added
        """
        if account_id not in self._accounts:
            raise ValueError(f"Account not registered: {account_id}")

        if isinstance(findings, FindingCollection):
            finding_list = list(findings)
        else:
            finding_list = findings

        self._findings[account_id].extend(finding_list)
        logger.info(f"Added {len(finding_list)} findings for account {account_id}")

    def add_assets(
        self,
        account_id: str,
        assets: AssetCollection | list[Asset],
    ) -> None:
        """
        Add assets from a cloud account for correlation.

        Args:
            account_id: Account identifier
            assets: Assets to add

        Raises:
            ValueError: If account has not been added
        """
        if account_id not in self._accounts:
            raise ValueError(f"Account not registered: {account_id}")

        if isinstance(assets, AssetCollection):
            asset_list = list(assets)
        else:
            asset_list = assets

        self._assets[account_id].extend(asset_list)
        logger.info(f"Added {len(asset_list)} assets for account {account_id}")

    def aggregate(
        self,
        deduplicate: bool = True,
        severity_filter: Severity | None = None,
    ) -> tuple[FindingCollection, AggregationResult]:
        """
        Aggregate findings from all registered accounts.

        Args:
            deduplicate: Whether to remove duplicate findings
            severity_filter: Optional filter to include only specific severity

        Returns:
            Tuple of (aggregated findings, aggregation result)
        """
        all_normalized: list[NormalizedFinding] = []
        total_count = 0

        # Normalize all findings
        for account_id, findings in self._findings.items():
            account = self._accounts[account_id]
            for finding in findings:
                if severity_filter and finding.severity != severity_filter:
                    continue

                normalized = self._normalize_finding(finding, account)
                all_normalized.append(normalized)
                total_count += 1

        # Deduplicate if requested
        if deduplicate:
            unique_findings = self._deduplicate(all_normalized)
        else:
            unique_findings = [n.original for n in all_normalized]

        # Build result
        result = AggregationResult(
            total_findings=total_count,
            unique_findings=len(unique_findings),
            duplicates_removed=total_count - len(unique_findings),
            findings_by_severity=self._count_by_severity(unique_findings),
            findings_by_provider=self._count_by_provider(all_normalized),
            findings_by_account=self._count_by_account(all_normalized),
            source_accounts=list(self._accounts.values()),
        )

        logger.info(
            f"Aggregation complete: {result.unique_findings} unique findings "
            f"from {len(self._accounts)} accounts"
        )

        return FindingCollection(unique_findings), result

    def _normalize_finding(
        self,
        finding: Finding,
        account: CloudAccount,
    ) -> NormalizedFinding:
        """
        Normalize a finding to common format.

        Args:
            finding: Finding to normalize
            account: Account the finding belongs to

        Returns:
            NormalizedFinding with normalized key
        """
        if self._custom_normalizer:
            return self._custom_normalizer(finding, account.id)

        # Determine canonical resource type
        # Extract resource type from asset_id if possible
        resource_type = self._extract_resource_type(finding.asset_id, account.provider)
        canonical_type = self.RESOURCE_TYPE_MAPPINGS.get(resource_type, resource_type)

        # Determine canonical rule ID
        canonical_rule = self.RULE_MAPPINGS.get(
            finding.rule_id or "", finding.rule_id or ""
        )

        # Generate deduplication key
        key = self._generate_dedup_key(
            finding=finding,
            canonical_type=canonical_type,
            canonical_rule=canonical_rule,
        )

        return NormalizedFinding(
            original=finding,
            normalized_key=key,
            provider=account.provider,
            account_id=account.id,
            canonical_resource_type=canonical_type,
            canonical_rule_id=canonical_rule,
        )

    def _extract_resource_type(self, asset_id: str, provider: str) -> str:
        """
        Extract resource type from asset ID.

        Args:
            asset_id: Asset identifier (ARN, resource path, etc.)
            provider: Cloud provider

        Returns:
            Resource type string
        """
        if provider == "aws":
            # AWS ARN format: arn:aws:service:region:account:resource
            if asset_id.startswith("arn:aws:"):
                parts = asset_id.split(":")
                if len(parts) >= 6:
                    service = parts[2]
                    resource_part = parts[5] if len(parts) > 5 else ""
                    if "/" in resource_part:
                        resource_type = resource_part.split("/")[0]
                    else:
                        resource_type = resource_part
                    return f"aws_{service}_{resource_type}".lower()

        elif provider == "gcp":
            # GCP format: //service.googleapis.com/projects/project/...
            if asset_id.startswith("//"):
                parts = asset_id.split("/")
                if len(parts) >= 4:
                    service = parts[2].replace(".googleapis.com", "")
                    return f"google_{service}"

        elif provider == "azure":
            # Azure format: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
            if "/providers/" in asset_id.lower():
                parts = asset_id.lower().split("/providers/")
                if len(parts) > 1:
                    provider_parts = parts[1].split("/")
                    if len(provider_parts) >= 2:
                        return f"azure_{provider_parts[1]}".lower()

        return "unknown"

    def _generate_dedup_key(
        self,
        finding: Finding,
        canonical_type: str,
        canonical_rule: str,
    ) -> str:
        """
        Generate a deduplication key for a finding.

        The key is based on:
        - Canonical resource type
        - Canonical rule ID
        - Severity
        - Title (normalized)

        Args:
            finding: The finding to generate key for
            canonical_type: Normalized resource type
            canonical_rule: Normalized rule ID

        Returns:
            SHA256 hash as deduplication key
        """
        # Normalize title for comparison
        normalized_title = finding.title.lower().strip()

        key_parts = [
            canonical_type,
            canonical_rule,
            finding.severity.value,
            normalized_title,
        ]

        # Add CVE ID for vulnerabilities (exact match required)
        if finding.cve_id:
            key_parts.append(finding.cve_id)

        key_string = "|".join(str(p) for p in key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()[:16]

    def _deduplicate(
        self,
        normalized_findings: list[NormalizedFinding],
    ) -> list[Finding]:
        """
        Remove duplicate findings.

        When duplicates are found, keep the one with:
        1. Most recent last_seen timestamp
        2. Highest severity (if tied)
        3. Most detail (longer description)

        Args:
            normalized_findings: List of normalized findings

        Returns:
            List of unique findings
        """
        seen: dict[str, NormalizedFinding] = {}

        for normalized in normalized_findings:
            key = normalized.normalized_key
            if key not in seen:
                seen[key] = normalized
            else:
                # Compare and keep the "better" finding
                existing = seen[key]
                if self._should_replace(existing.original, normalized.original):
                    seen[key] = normalized

        return [n.original for n in seen.values()]

    def _should_replace(self, existing: Finding, new: Finding) -> bool:
        """
        Determine if new finding should replace existing.

        Args:
            existing: Currently kept finding
            new: New finding to compare

        Returns:
            True if new finding should replace existing
        """
        # Prefer more recent findings
        if existing.last_seen and new.last_seen:
            if new.last_seen > existing.last_seen:
                return True
            elif new.last_seen < existing.last_seen:
                return False

        # Prefer higher severity
        severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        if severity_order.index(new.severity) > severity_order.index(existing.severity):
            return True

        # Prefer more detail
        if len(new.description) > len(existing.description):
            return True

        return False

    def _count_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {}
        for finding in findings:
            sev = finding.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_provider(
        self, normalized: list[NormalizedFinding]
    ) -> dict[str, int]:
        """Count findings by cloud provider."""
        counts: dict[str, int] = {}
        for n in normalized:
            counts[n.provider] = counts.get(n.provider, 0) + 1
        return counts

    def _count_by_account(
        self, normalized: list[NormalizedFinding]
    ) -> dict[str, int]:
        """Count findings by account."""
        counts: dict[str, int] = {}
        for n in normalized:
            counts[n.account_id] = counts.get(n.account_id, 0) + 1
        return counts

    def get_cross_account_findings(
        self,
        min_accounts: int = 2,
    ) -> FindingCollection:
        """
        Get findings that appear in multiple accounts.

        Useful for identifying systemic issues that affect multiple
        accounts and should be prioritized.

        Args:
            min_accounts: Minimum number of accounts a finding must appear in

        Returns:
            FindingCollection of cross-account findings
        """
        key_to_accounts: dict[str, set[str]] = {}
        key_to_finding: dict[str, Finding] = {}

        for account_id, findings in self._findings.items():
            account = self._accounts[account_id]
            for finding in findings:
                normalized = self._normalize_finding(finding, account)
                key = normalized.normalized_key

                if key not in key_to_accounts:
                    key_to_accounts[key] = set()
                    key_to_finding[key] = finding

                key_to_accounts[key].add(account_id)

        cross_account = [
            key_to_finding[key]
            for key, accounts in key_to_accounts.items()
            if len(accounts) >= min_accounts
        ]

        return FindingCollection(cross_account)

    def generate_summary_report(self) -> dict[str, Any]:
        """
        Generate a summary report of aggregated findings.

        Returns:
            Dictionary containing summary statistics
        """
        findings_collection, result = self.aggregate()

        # Get severity distribution
        severity_dist = result.findings_by_severity

        # Get provider distribution
        provider_dist = result.findings_by_provider

        # Get top findings (most common across accounts)
        cross_account = self.get_cross_account_findings(min_accounts=2)

        # Get critical/high findings by provider
        critical_by_provider: dict[str, int] = {}
        for account_id, findings in self._findings.items():
            provider = self._accounts[account_id].provider
            critical_count = sum(
                1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
            )
            critical_by_provider[provider] = (
                critical_by_provider.get(provider, 0) + critical_count
            )

        return {
            "summary": {
                "total_accounts": len(self._accounts),
                "total_findings": result.total_findings,
                "unique_findings": result.unique_findings,
                "duplicates_removed": result.duplicates_removed,
                "cross_account_findings": len(cross_account),
            },
            "by_severity": severity_dist,
            "by_provider": provider_dist,
            "by_account": result.findings_by_account,
            "critical_high_by_provider": critical_by_provider,
            "aggregated_at": result.aggregated_at.isoformat(),
        }

    def clear(self) -> None:
        """Clear all accounts and findings."""
        self._accounts.clear()
        self._findings.clear()
        self._assets.clear()
        logger.info("Aggregator cleared")
