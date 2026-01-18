"""
ASM Drift Detection for Mantissa Stance.

This module provides drift detection capabilities to identify changes
between ASM scans, including new assets, removed assets, configuration
changes, port changes, and certificate rotations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from stance.asm.models import (
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.storage import ASMStorageAdapter

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Type of change detected between scans."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class DriftSeverity(Enum):
    """Severity of a drift detection finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class AssetChange:
    """
    Represents a change detected in an asset's configuration.

    Attributes:
        asset_id: ID of the changed asset
        domain: Domain of the asset
        field_name: Name of the field that changed
        old_value: Previous value
        new_value: New value
        change_type: Type of change (added, removed, modified)
    """

    asset_id: str
    domain: str
    field_name: str
    old_value: Any
    new_value: Any
    change_type: ChangeType

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "asset_id": self.asset_id,
            "domain": self.domain,
            "field_name": self.field_name,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "change_type": self.change_type.value,
        }


@dataclass(frozen=True)
class PortChange:
    """
    Represents a port state change between scans.

    Attributes:
        domain: Domain where port changed
        ip_address: IP address where port changed
        port: Port number
        change_type: Type of change (added = newly open, removed = now closed)
        service: Service detected on port (if known)
        protocol: Protocol (tcp/udp)
    """

    domain: str
    ip_address: str | None
    port: int
    change_type: ChangeType
    service: str | None = None
    protocol: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "domain": self.domain,
            "ip_address": self.ip_address,
            "port": self.port,
            "change_type": self.change_type.value,
            "service": self.service,
            "protocol": self.protocol,
        }


@dataclass(frozen=True)
class CertificateChange:
    """
    Represents a certificate change between scans.

    Attributes:
        domain: Domain where certificate changed
        change_type: Type of change
        old_fingerprint: Previous certificate fingerprint
        new_fingerprint: New certificate fingerprint
        old_expiry: Previous expiration date
        new_expiry: New expiration date
        old_issuer: Previous issuer
        new_issuer: New issuer
    """

    domain: str
    change_type: ChangeType
    old_fingerprint: str | None = None
    new_fingerprint: str | None = None
    old_expiry: datetime | None = None
    new_expiry: datetime | None = None
    old_issuer: str | None = None
    new_issuer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "domain": self.domain,
            "change_type": self.change_type.value,
            "old_fingerprint": self.old_fingerprint,
            "new_fingerprint": self.new_fingerprint,
            "old_expiry": self.old_expiry.isoformat() if self.old_expiry else None,
            "new_expiry": self.new_expiry.isoformat() if self.new_expiry else None,
            "old_issuer": self.old_issuer,
            "new_issuer": self.new_issuer,
        }


@dataclass
class DriftSummary:
    """
    Summary statistics for a drift report.

    Attributes:
        total_changes: Total number of changes detected
        new_assets_count: Number of new assets
        removed_assets_count: Number of removed assets
        modified_assets_count: Number of unique modified assets
        changed_assets_count: Total number of asset changes
        new_ports_count: Number of newly opened ports
        closed_ports_count: Number of closed ports
        certificate_changes_count: Number of certificate changes
        critical_changes: Number of critical severity changes
        high_changes: Number of high severity changes
        overall_severity: Calculated overall severity based on changes (property)
        high_risk_changes: Total critical + high changes (property)
    """

    total_changes: int = 0
    new_assets_count: int = 0
    removed_assets_count: int = 0
    modified_assets_count: int = 0
    changed_assets_count: int = 0
    new_ports_count: int = 0
    closed_ports_count: int = 0
    certificate_changes_count: int = 0
    critical_changes: int = 0
    high_changes: int = 0

    @property
    def overall_severity(self) -> "DriftSeverity":
        """Calculate overall severity based on changes."""
        if self.critical_changes > 0:
            return DriftSeverity.CRITICAL
        if self.high_changes > 0:
            return DriftSeverity.HIGH
        if self.new_assets_count > 0 or self.new_ports_count > 0:
            return DriftSeverity.MEDIUM
        if self.total_changes > 0:
            return DriftSeverity.LOW
        return DriftSeverity.INFO

    @property
    def high_risk_changes(self) -> int:
        """Total high-risk changes (critical + high)."""
        return self.critical_changes + self.high_changes

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_changes": self.total_changes,
            "new_assets_count": self.new_assets_count,
            "removed_assets_count": self.removed_assets_count,
            "modified_assets_count": self.modified_assets_count,
            "changed_assets_count": self.changed_assets_count,
            "new_ports_count": self.new_ports_count,
            "closed_ports_count": self.closed_ports_count,
            "certificate_changes_count": self.certificate_changes_count,
            "critical_changes": self.critical_changes,
            "high_changes": self.high_changes,
            "overall_severity": self.overall_severity.value,
            "high_risk_changes": self.high_risk_changes,
        }


@dataclass
class DriftReport:
    """
    Complete drift detection report between two scans.

    Attributes:
        baseline_scan_id: ID of the baseline scan
        current_scan_id: ID of the current scan
        baseline_scan_time: When baseline scan was run
        current_scan_time: When current scan was run
        new_assets: Assets present in current but not baseline
        removed_assets: Assets present in baseline but not current
        changed_assets: Assets with configuration changes
        new_ports: Newly opened ports
        closed_ports: Ports that are no longer responding
        certificate_changes: Certificate updates detected
        summary: Aggregated statistics
    """

    baseline_scan_id: str
    current_scan_id: str
    baseline_scan_time: datetime | None = None
    current_scan_time: datetime | None = None
    new_assets: list[ExternalAsset] = field(default_factory=list)
    removed_assets: list[ExternalAsset] = field(default_factory=list)
    changed_assets: list[AssetChange] = field(default_factory=list)
    new_ports: list[PortChange] = field(default_factory=list)
    closed_ports: list[PortChange] = field(default_factory=list)
    certificate_changes: list[CertificateChange] = field(default_factory=list)
    summary: DriftSummary = field(default_factory=DriftSummary)

    def has_changes(self) -> bool:
        """Check if any changes were detected."""
        return self.summary.total_changes > 0

    def has_critical_changes(self) -> bool:
        """Check if any critical changes were detected."""
        return self.summary.critical_changes > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "baseline_scan_time": self.baseline_scan_time.isoformat()
            if self.baseline_scan_time
            else None,
            "current_scan_time": self.current_scan_time.isoformat()
            if self.current_scan_time
            else None,
            "new_assets": [a.to_dict() for a in self.new_assets],
            "removed_assets": [a.to_dict() for a in self.removed_assets],
            "changed_assets": [c.to_dict() for c in self.changed_assets],
            "new_ports": [p.to_dict() for p in self.new_ports],
            "closed_ports": [p.to_dict() for p in self.closed_ports],
            "certificate_changes": [c.to_dict() for c in self.certificate_changes],
            "summary": self.summary.to_dict(),
        }


# Port severity mapping for new exposed ports
CRITICAL_PORTS = {3389, 1433, 3306, 5432, 27017, 6379, 9200}  # RDP, MSSQL, MySQL, Postgres, MongoDB, Redis, Elasticsearch
HIGH_RISK_PORTS = {22, 23, 21, 445, 5900, 1521}  # SSH, Telnet, FTP, SMB, VNC, Oracle


class ASMDriftDetector:
    """
    Detects changes between ASM scans.

    Compares external assets across scans to identify new assets,
    removed assets, configuration changes, and certificate rotations.
    """

    def __init__(self, storage: ASMStorageAdapter) -> None:
        """
        Initialize the drift detector.

        Args:
            storage: ASM storage adapter for accessing scan data
        """
        self._storage = storage

    def detect_drift(
        self,
        current_scan_id: str,
        baseline_scan_id: str | None = None,
    ) -> DriftReport:
        """
        Detect drift between two scans.

        Args:
            current_scan_id: ID of the current (newer) scan
            baseline_scan_id: ID of the baseline (older) scan.
                             If None, uses the previous scan.

        Returns:
            DriftReport with all detected changes
        """
        # Get baseline scan if not specified
        if baseline_scan_id is None:
            baseline_scan_id = self._get_previous_scan_id(current_scan_id)
            if baseline_scan_id is None:
                logger.warning("No baseline scan found for drift detection")
                return DriftReport(
                    baseline_scan_id="",
                    current_scan_id=current_scan_id,
                )

        # Get scan metadata
        baseline_scan = self._storage.get_scan_result(baseline_scan_id)
        current_scan = self._storage.get_scan_result(current_scan_id)

        # Get assets from both scans
        baseline_assets = self._storage.get_external_assets(baseline_scan_id)
        current_assets = self._storage.get_external_assets(current_scan_id)

        # Build lookup maps
        baseline_map = self._build_asset_map(baseline_assets)
        current_map = self._build_asset_map(current_assets)

        # Initialize report
        report = DriftReport(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            baseline_scan_time=baseline_scan.started_at if baseline_scan else None,
            current_scan_time=current_scan.started_at if current_scan else None,
        )

        # Detect new assets
        for key, asset in current_map.items():
            if key not in baseline_map:
                report.new_assets.append(asset)
                # Check if new asset exposes critical or high-risk ports
                if asset.port and (asset.port in CRITICAL_PORTS or asset.port in HIGH_RISK_PORTS):
                    report.new_ports.append(
                        PortChange(
                            domain=asset.domain,
                            ip_address=asset.ip_address,
                            port=asset.port,
                            change_type=ChangeType.ADDED,
                            service=asset.service,
                            protocol=asset.protocol,
                        )
                    )

        # Detect removed assets
        for key, asset in baseline_map.items():
            if key not in current_map:
                report.removed_assets.append(asset)
                if asset.port:
                    report.closed_ports.append(
                        PortChange(
                            domain=asset.domain,
                            ip_address=asset.ip_address,
                            port=asset.port,
                            change_type=ChangeType.REMOVED,
                            service=asset.service,
                            protocol=asset.protocol,
                        )
                    )

        # Detect changes in existing assets
        for key, current_asset in current_map.items():
            if key in baseline_map:
                baseline_asset = baseline_map[key]
                changes = self._detect_asset_changes(baseline_asset, current_asset)
                report.changed_assets.extend(changes)

                # Check for certificate changes
                cert_change = self._detect_certificate_change(
                    baseline_asset, current_asset
                )
                if cert_change:
                    report.certificate_changes.append(cert_change)

        # Calculate summary
        report.summary = self._calculate_summary(report)

        logger.info(
            f"Drift detection complete: {report.summary.total_changes} changes "
            f"between {baseline_scan_id} and {current_scan_id}"
        )

        return report

    def _get_previous_scan_id(self, current_scan_id: str) -> str | None:
        """
        Get the scan ID immediately before the given scan.

        Args:
            current_scan_id: Current scan ID

        Returns:
            Previous scan ID, or None if not found
        """
        scans = self._storage.list_scans(limit=100)

        # Find current scan position
        current_index = None
        for i, scan in enumerate(scans):
            if scan.scan_id == current_scan_id:
                current_index = i
                break

        if current_index is None or current_index >= len(scans) - 1:
            return None

        return scans[current_index + 1].scan_id

    def _build_asset_map(
        self,
        assets: ExternalAssetCollection,
    ) -> dict[str, ExternalAsset]:
        """
        Build a lookup map for assets by domain+port.

        Args:
            assets: Collection of assets

        Returns:
            Dictionary mapping domain:port to asset
        """
        asset_map: dict[str, ExternalAsset] = {}
        for asset in assets:
            # Use domain:port as key for comparison
            key = f"{asset.domain.lower()}:{asset.port or 0}"
            asset_map[key] = asset
        return asset_map

    def _detect_asset_changes(
        self,
        baseline: ExternalAsset,
        current: ExternalAsset,
    ) -> list[AssetChange]:
        """
        Detect configuration changes between two versions of an asset.

        Args:
            baseline: Asset from baseline scan
            current: Asset from current scan

        Returns:
            List of detected changes
        """
        changes: list[AssetChange] = []

        # Check IP address change
        if baseline.ip_address != current.ip_address:
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="ip_address",
                    old_value=baseline.ip_address,
                    new_value=current.ip_address,
                    change_type=ChangeType.MODIFIED,
                )
            )

        # Check cloud provider change
        if baseline.cloud_provider != current.cloud_provider:
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="cloud_provider",
                    old_value=baseline.cloud_provider,
                    new_value=current.cloud_provider,
                    change_type=ChangeType.MODIFIED,
                )
            )

        # Check cloud region change
        if baseline.cloud_region != current.cloud_region:
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="cloud_region",
                    old_value=baseline.cloud_region,
                    new_value=current.cloud_region,
                    change_type=ChangeType.MODIFIED,
                )
            )

        # Check service change
        if baseline.service != current.service:
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="service",
                    old_value=baseline.service,
                    new_value=current.service,
                    change_type=ChangeType.MODIFIED,
                )
            )

        # Check protocol change
        if baseline.protocol != current.protocol:
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="protocol",
                    old_value=baseline.protocol,
                    new_value=current.protocol,
                    change_type=ChangeType.MODIFIED,
                )
            )

        # Check technology stack changes
        baseline_tech = set(baseline.technology_stack)
        current_tech = set(current.technology_stack)

        added_tech = current_tech - baseline_tech
        removed_tech = baseline_tech - current_tech

        if added_tech:
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="technology_stack_added",
                    old_value=None,
                    new_value=list(added_tech),
                    change_type=ChangeType.ADDED,
                )
            )

        if removed_tech:
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="technology_stack_removed",
                    old_value=list(removed_tech),
                    new_value=None,
                    change_type=ChangeType.REMOVED,
                )
            )

        # Check risk score change (significant changes only)
        risk_diff = abs(current.risk_score - baseline.risk_score)
        if risk_diff >= 2.0:  # Only flag significant risk changes
            changes.append(
                AssetChange(
                    asset_id=current.id,
                    domain=current.domain,
                    field_name="risk_score",
                    old_value=baseline.risk_score,
                    new_value=current.risk_score,
                    change_type=ChangeType.MODIFIED,
                )
            )

        return changes

    def _detect_certificate_change(
        self,
        baseline: ExternalAsset,
        current: ExternalAsset,
    ) -> CertificateChange | None:
        """
        Detect certificate changes between two versions of an asset.

        Args:
            baseline: Asset from baseline scan
            current: Asset from current scan

        Returns:
            CertificateChange if detected, None otherwise
        """
        baseline_cert = baseline.certificate_info
        current_cert = current.certificate_info

        # Certificate added
        if baseline_cert is None and current_cert is not None:
            return CertificateChange(
                domain=current.domain,
                change_type=ChangeType.ADDED,
                new_fingerprint=current_cert.fingerprint_sha256,
                new_expiry=current_cert.not_after,
                new_issuer=current_cert.issuer,
            )

        # Certificate removed
        if baseline_cert is not None and current_cert is None:
            return CertificateChange(
                domain=current.domain,
                change_type=ChangeType.REMOVED,
                old_fingerprint=baseline_cert.fingerprint_sha256,
                old_expiry=baseline_cert.not_after,
                old_issuer=baseline_cert.issuer,
            )

        # Certificate changed
        if baseline_cert is not None and current_cert is not None:
            # Check if certificate actually changed (by fingerprint)
            if baseline_cert.fingerprint_sha256 != current_cert.fingerprint_sha256:
                return CertificateChange(
                    domain=current.domain,
                    change_type=ChangeType.MODIFIED,
                    old_fingerprint=baseline_cert.fingerprint_sha256,
                    new_fingerprint=current_cert.fingerprint_sha256,
                    old_expiry=baseline_cert.not_after,
                    new_expiry=current_cert.not_after,
                    old_issuer=baseline_cert.issuer,
                    new_issuer=current_cert.issuer,
                )

        return None

    def _calculate_summary(self, report: DriftReport) -> DriftSummary:
        """
        Calculate summary statistics for a drift report.

        Args:
            report: DriftReport to summarize

        Returns:
            DriftSummary with calculated statistics
        """
        # Count unique modified assets
        modified_asset_ids = {c.asset_id for c in report.changed_assets}

        summary = DriftSummary(
            new_assets_count=len(report.new_assets),
            removed_assets_count=len(report.removed_assets),
            modified_assets_count=len(modified_asset_ids),
            changed_assets_count=len(report.changed_assets),
            new_ports_count=len(report.new_ports),
            closed_ports_count=len(report.closed_ports),
            certificate_changes_count=len(report.certificate_changes),
        )

        # Calculate critical/high changes
        critical = 0
        high = 0

        # New critical port exposures are critical
        for port_change in report.new_ports:
            if port_change.port in CRITICAL_PORTS:
                critical += 1
            elif port_change.port in HIGH_RISK_PORTS:
                high += 1

        # New assets with critical ports
        for asset in report.new_assets:
            if asset.port in CRITICAL_PORTS:
                critical += 1
            elif asset.port in HIGH_RISK_PORTS:
                high += 1

        # Certificate removals are high severity
        for cert_change in report.certificate_changes:
            if cert_change.change_type == ChangeType.REMOVED:
                high += 1

        summary.critical_changes = critical
        summary.high_changes = high

        summary.total_changes = (
            summary.new_assets_count
            + summary.removed_assets_count
            + len(report.changed_assets)
            + summary.certificate_changes_count
        )

        return summary

    def get_drift_findings(
        self,
        report: DriftReport,
    ) -> list[dict[str, Any]]:
        """
        Generate finding-style records from drift report.

        Useful for integrating drift detection with alerting systems.

        Args:
            report: DriftReport to convert

        Returns:
            List of finding dictionaries
        """
        findings: list[dict[str, Any]] = []

        # New critical port exposures
        for port_change in report.new_ports:
            if port_change.port in CRITICAL_PORTS:
                findings.append({
                    "type": "drift_new_critical_port",
                    "severity": "critical",
                    "domain": port_change.domain,
                    "port": port_change.port,
                    "service": port_change.service,
                    "title": f"New critical port {port_change.port} exposed on {port_change.domain}",
                    "description": (
                        f"A critical service port ({port_change.port}) was newly detected "
                        f"on {port_change.domain}. This may indicate a new attack vector."
                    ),
                })
            elif port_change.port in HIGH_RISK_PORTS:
                findings.append({
                    "type": "drift_new_high_risk_port",
                    "severity": "high",
                    "domain": port_change.domain,
                    "port": port_change.port,
                    "service": port_change.service,
                    "title": f"New high-risk port {port_change.port} exposed on {port_change.domain}",
                    "description": (
                        f"A high-risk service port ({port_change.port}) was newly detected "
                        f"on {port_change.domain}. Review for security implications."
                    ),
                })

        # New assets with no certificate (HTTP without TLS)
        for asset in report.new_assets:
            if asset.port in {80, 8080} and not asset.certificate_info:
                findings.append({
                    "type": "drift_new_unencrypted_service",
                    "severity": "medium",
                    "domain": asset.domain,
                    "port": asset.port,
                    "title": f"New unencrypted HTTP service on {asset.domain}:{asset.port}",
                    "description": (
                        f"A new HTTP service without TLS was detected on {asset.domain}:{asset.port}. "
                        f"Consider migrating to HTTPS."
                    ),
                })

        # Certificate removals
        for cert_change in report.certificate_changes:
            if cert_change.change_type == ChangeType.REMOVED:
                findings.append({
                    "type": "drift_certificate_removed",
                    "severity": "high",
                    "domain": cert_change.domain,
                    "title": f"TLS certificate removed from {cert_change.domain}",
                    "description": (
                        f"The TLS certificate on {cert_change.domain} was removed since the last scan. "
                        f"This may indicate a misconfiguration or service change."
                    ),
                })

        # IP address changes (potential DNS hijacking or infrastructure change)
        for change in report.changed_assets:
            if change.field_name == "ip_address":
                findings.append({
                    "type": "drift_ip_changed",
                    "severity": "medium",
                    "domain": change.domain,
                    "old_value": change.old_value,
                    "new_value": change.new_value,
                    "title": f"IP address changed for {change.domain}",
                    "description": (
                        f"The IP address for {change.domain} changed from {change.old_value} "
                        f"to {change.new_value}. Verify this is expected infrastructure change."
                    ),
                })

        # Cloud provider changes (potential shadow IT or migration)
        for change in report.changed_assets:
            if change.field_name == "cloud_provider" and change.new_value:
                findings.append({
                    "type": "drift_cloud_provider_changed",
                    "severity": "medium",
                    "domain": change.domain,
                    "old_value": change.old_value,
                    "new_value": change.new_value,
                    "title": f"Cloud provider changed for {change.domain}",
                    "description": (
                        f"The cloud provider for {change.domain} changed from "
                        f"{change.old_value or 'unknown'} to {change.new_value}. "
                        f"Verify this aligns with approved infrastructure."
                    ),
                })

        return findings
