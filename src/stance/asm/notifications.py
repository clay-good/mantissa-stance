"""
ASM Notification Manager for Mantissa Stance.

This module provides ASM-specific notification logic for alerting on:
- Scan completion with findings summary
- Drift detection (new/removed assets, port changes)
- Certificate expiration warnings
- Shadow IT discoveries
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from stance.asm.config import ASMConfiguration
from stance.asm.drift import ChangeType, DriftReport, DriftSeverity
from stance.asm.models import (
    ASMScanResult,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.models.finding import Finding, FindingCollection, FindingType, Severity

logger = logging.getLogger(__name__)


class AlertRouter(Protocol):
    """Protocol for alert routing (matches existing AlertRouter interface)."""

    def route(self, finding: Finding, context: dict[str, Any]) -> Any:
        """Route a finding to configured destinations."""
        ...

    def route_batch(self, findings: list[Finding], context: dict[str, Any]) -> list[Any]:
        """Route multiple findings to configured destinations."""
        ...


@dataclass
class ASMAlertContext:
    """
    Context for ASM alerts.

    Provides additional context for ASM-specific alerts beyond the
    standard Finding model.

    Attributes:
        scan_id: ASM scan identifier
        domain: Primary domain related to the alert
        external_asset: The external asset (if applicable)
        is_shadow_it: Whether this is a shadow IT finding
        drift_type: Type of drift (if drift alert)
        correlation_status: CSPM correlation status
        risk_score: Asset risk score
        technology_stack: Detected technologies
    """

    scan_id: str = ""
    domain: str = ""
    external_asset: ExternalAsset | None = None
    is_shadow_it: bool = False
    drift_type: str = ""
    correlation_status: str = ""
    risk_score: float = 0.0
    technology_stack: list[str] = field(default_factory=list)
    certificate_days_until_expiry: int | None = None
    port: int | None = None
    service: str = ""
    ip_address: str = ""
    cloud_provider: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for alert context."""
        result = {
            "asm_scan_id": self.scan_id,
            "asm_domain": self.domain,
            "asm_is_shadow_it": self.is_shadow_it,
            "asm_risk_score": self.risk_score,
            "asm_technology_stack": self.technology_stack,
            "asm_port": self.port,
            "asm_service": self.service,
            "asm_ip_address": self.ip_address,
            "asm_cloud_provider": self.cloud_provider,
        }

        if self.drift_type:
            result["asm_drift_type"] = self.drift_type

        if self.correlation_status:
            result["asm_correlation_status"] = self.correlation_status

        if self.certificate_days_until_expiry is not None:
            result["asm_certificate_days_until_expiry"] = self.certificate_days_until_expiry

        if self.external_asset:
            result["asm_external_asset"] = self.external_asset.to_dict()

        return result


@dataclass
class ScanSummary:
    """Summary of an ASM scan for notifications."""

    scan_id: str
    target_domains: list[str]
    total_assets: int
    new_assets: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    shadow_it_count: int
    expiring_certs: int
    high_risk_ports: int
    duration_seconds: float

    @property
    def total_findings(self) -> int:
        """Total findings count."""
        return (
            self.critical_findings
            + self.high_findings
            + self.medium_findings
            + self.low_findings
        )

    @property
    def requires_immediate_attention(self) -> bool:
        """Check if scan results require immediate attention."""
        return self.critical_findings > 0 or self.high_risk_ports > 0


class ASMNotificationManager:
    """
    Manages ASM-specific notifications.

    Provides methods to notify on various ASM events:
    - Scan completion
    - Drift detection
    - Certificate expiration
    - Shadow IT discovery
    """

    def __init__(
        self,
        alert_router: AlertRouter | None = None,
        config: ASMConfiguration | None = None,
    ) -> None:
        """
        Initialize the notification manager.

        Args:
            alert_router: Alert router for sending notifications
            config: ASM configuration
        """
        self.alert_router = alert_router
        self.config = config or ASMConfiguration()

    def notify_scan_complete(
        self,
        result: ASMScanResult,
        findings: FindingCollection | None = None,
        new_asset_count: int = 0,
        shadow_it_count: int = 0,
    ) -> list[Any]:
        """
        Send notification for scan completion.

        Args:
            result: Scan result
            findings: Findings from the scan
            new_asset_count: Number of new assets since last scan
            shadow_it_count: Number of shadow IT assets detected

        Returns:
            List of alert routing results
        """
        if not self.alert_router:
            logger.warning("No alert router configured, skipping notification")
            return []

        findings_list = list(findings) if findings else []

        # Create summary
        summary = self._create_scan_summary(
            result, findings_list, new_asset_count, shadow_it_count
        )

        # Create summary finding for notification
        severity = self._determine_scan_severity(summary)
        summary_finding = self._create_scan_summary_finding(summary, severity)

        context = {
            "alert_type": "asm_scan_complete",
            "scan_summary": {
                "scan_id": summary.scan_id,
                "domains": summary.target_domains,
                "total_assets": summary.total_assets,
                "new_assets": summary.new_assets,
                "findings": summary.total_findings,
                "critical": summary.critical_findings,
                "high": summary.high_findings,
                "shadow_it": summary.shadow_it_count,
                "duration": f"{summary.duration_seconds:.1f}s",
            },
        }

        results = [self.alert_router.route(summary_finding, context)]

        # Also route individual critical/high findings
        for finding in findings_list:
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                finding_context = {
                    "alert_type": "asm_finding",
                    "asm_scan_id": result.scan_id,
                }
                results.append(self.alert_router.route(finding, finding_context))

        logger.info(
            f"Sent scan completion notification for {result.scan_id}: "
            f"{len(results)} alerts"
        )

        return results

    def notify_drift(self, drift_report: DriftReport) -> list[Any]:
        """
        Send notifications for drift detection results.

        Args:
            drift_report: Drift report from ASMDriftDetector

        Returns:
            List of alert routing results
        """
        if not self.alert_router:
            logger.warning("No alert router configured, skipping notification")
            return []

        results: list[Any] = []
        summary = drift_report.summary

        # Alert on new high-risk assets
        for asset in drift_report.new_assets:
            if asset.risk_score >= 7.0:
                finding = self._create_drift_finding(
                    asset=asset,
                    drift_type="new_high_risk_asset",
                    title=f"New High-Risk Asset: {asset.domain}",
                    description=(
                        f"A new high-risk external asset was discovered: "
                        f"{asset.domain} ({asset.ip_address}:{asset.port}). "
                        f"Risk score: {asset.risk_score:.1f}/10"
                    ),
                    severity=Severity.HIGH,
                )
                context = ASMAlertContext(
                    domain=asset.domain,
                    external_asset=asset,
                    drift_type="new_asset",
                    risk_score=asset.risk_score,
                    port=asset.port,
                    ip_address=asset.ip_address or "",
                ).to_dict()
                context["alert_type"] = "asm_drift"

                results.append(self.alert_router.route(finding, context))

        # Alert on new exposed ports
        for port_change in drift_report.new_ports:
            # Calculate severity based on port type (critical services like RDP, SSH, DB)
            critical_ports = {3389, 22, 3306, 5432, 27017, 6379, 9200}
            high_ports = {21, 23, 25, 445, 1433, 5900}
            severity = (
                Severity.CRITICAL
                if port_change.port in critical_ports
                else Severity.HIGH
                if port_change.port in high_ports
                else Severity.MEDIUM
            )

            finding = self._create_drift_finding(
                asset=None,
                drift_type="new_exposed_port",
                title=f"New Exposed Port: {port_change.domain}:{port_change.port}",
                description=(
                    f"A new port was detected as exposed on {port_change.domain}: "
                    f"port {port_change.port}/{port_change.protocol or 'tcp'} "
                    f"({port_change.service or 'unknown service'}). "
                    f"This may indicate unauthorized service exposure."
                ),
                severity=severity,
            )

            context = ASMAlertContext(
                domain=port_change.domain,
                drift_type="new_port",
                port=port_change.port,
                service=port_change.service or "",
                ip_address=port_change.ip_address or "",
            ).to_dict()
            context["alert_type"] = "asm_drift"

            results.append(self.alert_router.route(finding, context))

        # Alert on certificate changes
        for cert_change in drift_report.certificate_changes:
            # Determine severity based on change type
            # REMOVED certificates are critical, others are high
            is_critical = cert_change.change_type == ChangeType.REMOVED
            severity = Severity.CRITICAL if is_critical else Severity.HIGH

            # Build description based on available info
            change_desc = f"{cert_change.change_type.value} certificate"
            if cert_change.old_fingerprint and cert_change.new_fingerprint:
                change_desc = f"Certificate rotated (fingerprint changed)"
            elif cert_change.change_type == ChangeType.REMOVED:
                change_desc = f"Certificate removed (was issued by {cert_change.old_issuer or 'unknown'})"
            elif cert_change.change_type == ChangeType.ADDED:
                change_desc = f"New certificate detected (issued by {cert_change.new_issuer or 'unknown'})"

            finding = self._create_drift_finding(
                asset=None,
                drift_type="certificate_change",
                title=f"Certificate Change: {cert_change.domain}",
                description=(
                    f"Certificate change detected for {cert_change.domain}: "
                    f"{change_desc}"
                ),
                severity=severity,
            )

            context = ASMAlertContext(
                domain=cert_change.domain,
                drift_type="certificate_change",
            ).to_dict()
            context["alert_type"] = "asm_drift"

            results.append(self.alert_router.route(finding, context))

        # Send drift summary if significant changes
        if summary.overall_severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH):
            summary_finding = self._create_drift_summary_finding(drift_report)
            context = {
                "alert_type": "asm_drift_summary",
                "drift_summary": {
                    "new_assets": summary.new_assets_count,
                    "removed_assets": summary.removed_assets_count,
                    "changed_assets": summary.changed_assets_count,
                    "new_ports": summary.new_ports_count,
                    "certificate_changes": summary.certificate_changes_count,
                    "overall_severity": summary.overall_severity.value,
                },
            }
            results.append(self.alert_router.route(summary_finding, context))

        logger.info(
            f"Sent drift notifications: {len(results)} alerts "
            f"({summary.new_assets_count} new assets, {summary.new_ports_count} new ports)"
        )

        return results

    def notify_certificate_expiring(
        self,
        assets: list[ExternalAsset],
        days_threshold: int = 30,
    ) -> list[Any]:
        """
        Send notifications for expiring certificates.

        Args:
            assets: Assets with expiring certificates
            days_threshold: Days until expiry threshold

        Returns:
            List of alert routing results
        """
        if not self.alert_router:
            logger.warning("No alert router configured, skipping notification")
            return []

        results: list[Any] = []

        for asset in assets:
            if not asset.certificate_info:
                continue

            days_until_expiry = asset.certificate_info.days_until_expiry

            # Determine severity based on days until expiry
            if days_until_expiry <= 0:
                severity = Severity.CRITICAL
                status = "EXPIRED"
            elif days_until_expiry <= 7:
                severity = Severity.CRITICAL
                status = f"expires in {days_until_expiry} days"
            elif days_until_expiry <= 14:
                severity = Severity.HIGH
                status = f"expires in {days_until_expiry} days"
            elif days_until_expiry <= days_threshold:
                severity = Severity.MEDIUM
                status = f"expires in {days_until_expiry} days"
            else:
                continue  # Not expiring soon

            finding = Finding(
                id=f"asm-cert-expiry-{asset.id}",
                asset_id=f"asm:{asset.id}",
                finding_type=FindingType.MISCONFIGURATION,
                severity=severity,
                status="open",
                title=f"Certificate Expiring: {asset.domain}",
                description=(
                    f"The SSL/TLS certificate for {asset.domain} {status}. "
                    f"Certificate subject: {asset.certificate_info.subject}. "
                    f"Expiry date: {asset.certificate_info.not_after.strftime('%Y-%m-%d')}."
                ),
                rule_id="asm-certificate-expiry",
                remediation_guidance=(
                    "Renew the SSL/TLS certificate before it expires to avoid "
                    "service disruption and security warnings for users."
                ),
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )

            context = ASMAlertContext(
                domain=asset.domain,
                external_asset=asset,
                certificate_days_until_expiry=days_until_expiry,
                ip_address=asset.ip_address or "",
            ).to_dict()
            context["alert_type"] = "asm_certificate_expiry"

            results.append(self.alert_router.route(finding, context))

        logger.info(f"Sent certificate expiry notifications: {len(results)} alerts")

        return results

    def notify_shadow_it(
        self,
        shadow_it_assets: list[ExternalAsset],
        correlation_context: dict[str, Any] | None = None,
    ) -> list[Any]:
        """
        Send notifications for shadow IT discoveries.

        Args:
            shadow_it_assets: List of shadow IT assets
            correlation_context: Context from CSPM correlation

        Returns:
            List of alert routing results
        """
        if not self.alert_router:
            logger.warning("No alert router configured, skipping notification")
            return []

        results: list[Any] = []

        # Only alert on high-risk shadow IT
        high_risk = [a for a in shadow_it_assets if a.risk_score >= 5.0]

        for asset in high_risk:
            severity = (
                Severity.CRITICAL
                if asset.risk_score >= 8.0
                else Severity.HIGH
                if asset.risk_score >= 6.0
                else Severity.MEDIUM
            )

            finding = Finding(
                id=f"asm-shadow-it-{asset.id}",
                asset_id=f"asm:{asset.id}",
                finding_type=FindingType.MISCONFIGURATION,
                severity=severity,
                status="open",
                title=f"Shadow IT Detected: {asset.domain}",
                description=(
                    f"An external asset was discovered that is not present in the "
                    f"internal CSPM inventory: {asset.domain}. "
                    f"IP: {asset.ip_address or 'unknown'}, "
                    f"Port: {asset.port or 'unknown'}, "
                    f"Service: {asset.service or 'unknown'}. "
                    f"Risk score: {asset.risk_score:.1f}/10. "
                    f"Cloud provider: {asset.cloud_provider or 'unknown'}. "
                    f"This may indicate unauthorized infrastructure or a collection gap."
                ),
                rule_id="asm-shadow-it",
                remediation_guidance=(
                    "1. Verify if this asset belongs to your organization. "
                    "2. If legitimate, add it to your CSPM inventory. "
                    "3. If unauthorized, investigate the source and take appropriate action. "
                    "4. Review access controls and security configuration."
                ),
                first_seen=asset.first_seen,
                last_seen=asset.last_seen,
            )

            context = ASMAlertContext(
                domain=asset.domain,
                external_asset=asset,
                is_shadow_it=True,
                risk_score=asset.risk_score,
                port=asset.port,
                service=asset.service or "",
                ip_address=asset.ip_address or "",
                cloud_provider=asset.cloud_provider or "",
                technology_stack=list(asset.technology_stack),
            ).to_dict()
            context["alert_type"] = "asm_shadow_it"

            if correlation_context:
                context["correlation"] = correlation_context

            results.append(self.alert_router.route(finding, context))

        logger.info(
            f"Sent shadow IT notifications: {len(results)} alerts "
            f"(from {len(shadow_it_assets)} total shadow IT assets)"
        )

        return results

    def _create_scan_summary(
        self,
        result: ASMScanResult,
        findings: list[Finding],
        new_asset_count: int,
        shadow_it_count: int,
    ) -> ScanSummary:
        """Create a scan summary from results."""
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity in (Severity.LOW, Severity.INFO))

        # Count expiring certs
        expiring = 0
        high_risk_ports = 0

        for asset in result.assets:
            if asset.certificate_info and asset.certificate_info.is_expiring_soon:
                expiring += 1
            if asset.port in (22, 3389, 3306, 5432, 27017, 6379):
                high_risk_ports += 1

        return ScanSummary(
            scan_id=result.scan_id,
            target_domains=result.target_domains,
            total_assets=len(result.assets),
            new_assets=new_asset_count,
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            shadow_it_count=shadow_it_count,
            expiring_certs=expiring,
            high_risk_ports=high_risk_ports,
            duration_seconds=result.duration_seconds,
        )

    def _determine_scan_severity(self, summary: ScanSummary) -> Severity:
        """Determine severity level for scan summary notification."""
        if summary.critical_findings > 0:
            return Severity.CRITICAL
        if summary.high_findings > 0 or summary.high_risk_ports > 0:
            return Severity.HIGH
        if summary.medium_findings > 0 or summary.shadow_it_count > 0:
            return Severity.MEDIUM
        if summary.low_findings > 0 or summary.expiring_certs > 0:
            return Severity.LOW
        return Severity.INFO

    def _create_scan_summary_finding(
        self, summary: ScanSummary, severity: Severity
    ) -> Finding:
        """Create a summary finding for scan completion."""
        domains_str = ", ".join(summary.target_domains[:3])
        if len(summary.target_domains) > 3:
            domains_str += f" (+{len(summary.target_domains) - 3} more)"

        description = (
            f"ASM scan completed for {domains_str}. "
            f"Discovered {summary.total_assets} external assets "
            f"({summary.new_assets} new). "
        )

        if summary.total_findings > 0:
            description += (
                f"Generated {summary.total_findings} findings: "
                f"{summary.critical_findings} critical, "
                f"{summary.high_findings} high, "
                f"{summary.medium_findings} medium. "
            )

        if summary.shadow_it_count > 0:
            description += f"Detected {summary.shadow_it_count} potential shadow IT assets. "

        if summary.expiring_certs > 0:
            description += f"{summary.expiring_certs} certificates expiring soon. "

        if summary.high_risk_ports > 0:
            description += f"{summary.high_risk_ports} high-risk ports exposed. "

        return Finding(
            id=f"asm-scan-summary-{summary.scan_id}",
            asset_id="asm:scan",
            finding_type=FindingType.MISCONFIGURATION,
            severity=severity,
            status="open",
            title=f"ASM Scan Complete: {domains_str}",
            description=description.strip(),
            rule_id="asm-scan-summary",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

    def _create_drift_finding(
        self,
        asset: ExternalAsset | None,
        drift_type: str,
        title: str,
        description: str,
        severity: Severity,
    ) -> Finding:
        """Create a finding for drift detection alert."""
        asset_id = f"asm:{asset.id}" if asset else "asm:drift"

        return Finding(
            id=f"asm-drift-{drift_type}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            asset_id=asset_id,
            finding_type=FindingType.MISCONFIGURATION,
            severity=severity,
            status="open",
            title=title,
            description=description,
            rule_id=f"asm-drift-{drift_type}",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )

    def _create_drift_summary_finding(self, drift_report: DriftReport) -> Finding:
        """Create a summary finding for drift detection."""
        summary = drift_report.summary

        description = (
            f"Attack surface drift detected between scans. "
            f"New assets: {summary.new_assets_count}, "
            f"Removed assets: {summary.removed_assets_count}, "
            f"Changed assets: {summary.changed_assets_count}. "
            f"New ports: {summary.new_ports_count}, "
            f"Closed ports: {summary.closed_ports_count}. "
            f"Certificate changes: {summary.certificate_changes_count}. "
            f"High-risk changes: {summary.high_risk_changes}."
        )

        severity = (
            Severity.CRITICAL
            if summary.overall_severity == DriftSeverity.CRITICAL
            else Severity.HIGH
            if summary.overall_severity == DriftSeverity.HIGH
            else Severity.MEDIUM
        )

        return Finding(
            id=f"asm-drift-summary-{drift_report.current_scan_id}",
            asset_id="asm:drift",
            finding_type=FindingType.MISCONFIGURATION,
            severity=severity,
            status="open",
            title="Attack Surface Drift Detected",
            description=description,
            rule_id="asm-drift-summary",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )


def create_certificate_expiry_report(
    assets: ExternalAssetCollection,
    days_threshold: int = 30,
) -> list[dict[str, Any]]:
    """
    Create a certificate expiration report.

    Args:
        assets: External assets to check
        days_threshold: Days until expiry to include

    Returns:
        List of certificate expiry entries
    """
    report: list[dict[str, Any]] = []

    for asset in assets:
        if not asset.certificate_info:
            continue

        days = asset.certificate_info.days_until_expiry

        if days <= days_threshold:
            entry = {
                "domain": asset.domain,
                "ip_address": asset.ip_address,
                "days_until_expiry": days,
                "expiry_date": asset.certificate_info.not_after.isoformat(),
                "subject": asset.certificate_info.subject,
                "issuer": asset.certificate_info.issuer,
                "is_expired": asset.certificate_info.is_expired,
                "status": (
                    "EXPIRED"
                    if days <= 0
                    else "CRITICAL"
                    if days <= 7
                    else "WARNING"
                    if days <= 14
                    else "EXPIRING"
                ),
            }
            report.append(entry)

    # Sort by days until expiry (soonest first)
    report.sort(key=lambda x: x["days_until_expiry"])

    return report


def create_attack_surface_summary(
    assets: ExternalAssetCollection,
    findings: FindingCollection | None = None,
    shadow_it_count: int = 0,
) -> dict[str, Any]:
    """
    Create an attack surface summary for reporting.

    Args:
        assets: External assets
        findings: Findings from policy evaluation
        shadow_it_count: Number of shadow IT assets

    Returns:
        Summary dictionary
    """
    findings_list = list(findings) if findings else []

    # Count by severity
    severity_counts = {
        "critical": sum(1 for f in findings_list if f.severity == Severity.CRITICAL),
        "high": sum(1 for f in findings_list if f.severity == Severity.HIGH),
        "medium": sum(1 for f in findings_list if f.severity == Severity.MEDIUM),
        "low": sum(1 for f in findings_list if f.severity in (Severity.LOW, Severity.INFO)),
    }

    # Count expiring certificates
    expiring_7d = 0
    expiring_30d = 0
    expired = 0

    for asset in assets:
        if asset.certificate_info:
            days = asset.certificate_info.days_until_expiry
            if days <= 0:
                expired += 1
            elif days <= 7:
                expiring_7d += 1
            elif days <= 30:
                expiring_30d += 1

    # Port distribution
    port_counts = assets.count_by_port()
    high_risk_ports = {22, 3389, 3306, 5432, 27017, 6379, 9200, 1433}
    exposed_high_risk = sum(
        count for port, count in port_counts.items() if port in high_risk_ports
    )

    # Cloud provider distribution
    cloud_counts = assets.count_by_cloud_provider()

    return {
        "total_assets": len(assets),
        "unique_domains": len(assets.get_unique_domains()),
        "unique_ips": len(assets.get_unique_ips()),
        "shadow_it_count": shadow_it_count,
        "findings": {
            "total": len(findings_list),
            "by_severity": severity_counts,
        },
        "certificates": {
            "expired": expired,
            "expiring_7d": expiring_7d,
            "expiring_30d": expiring_30d,
        },
        "exposure": {
            "high_risk_ports": exposed_high_risk,
            "port_distribution": dict(list(port_counts.items())[:10]),
        },
        "cloud_providers": cloud_counts,
    }
