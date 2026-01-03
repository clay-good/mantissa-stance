"""
CLI command handlers for Exposure Management.

Provides commands for:
- Public asset inventory
- Certificate monitoring
- DNS/subdomain inventory
- Sensitive data exposure detection
"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def cmd_exposure(args: argparse.Namespace) -> int:
    """
    Route Exposure subcommands to appropriate handlers.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "exposure_action", None)

    if action is None:
        print("Usage: stance exposure <command>")
        print("")
        print("Commands:")
        print("  inventory      List publicly accessible assets")
        print("  certificates   Monitor SSL/TLS certificates")
        print("  dns            Analyze DNS records for issues")
        print("  sensitive      Detect sensitive data exposure")
        print("")
        print("Run 'stance exposure <command> --help' for more information")
        return 0

    handlers = {
        "inventory": _cmd_exposure_inventory,
        "certificates": _cmd_exposure_certificates,
        "dns": _cmd_exposure_dns,
        "sensitive": _cmd_exposure_sensitive,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown exposure command: {action}")
    return 1


def _cmd_exposure_inventory(args: argparse.Namespace) -> int:
    """
    List publicly accessible assets.
    """
    from stance.exposure.inventory import PublicAssetInventory

    cloud = getattr(args, "cloud", None)
    output_format = getattr(args, "format", "table")
    region = getattr(args, "region", None)
    resource_type = getattr(args, "type", None)

    try:
        inventory = PublicAssetInventory()

        print("Scanning for publicly accessible assets...")
        result = inventory.discover(
            cloud_provider=cloud,
            region=region,
            resource_type=resource_type,
        )

        # Output results
        if output_format == "json":
            output = {
                "summary": {
                    "total_public_assets": result.summary.total_public_assets if result.summary else 0,
                    "internet_facing": result.summary.internet_facing if result.summary else 0,
                    "with_sensitive_data": result.summary.with_sensitive_data if result.summary else 0,
                },
                "by_cloud": result.summary.by_cloud if result.summary else {},
                "by_type": result.summary.by_type if result.summary else {},
                "assets": [
                    {
                        "resource_id": asset.resource_id,
                        "resource_type": asset.resource_type,
                        "cloud": asset.cloud_provider,
                        "region": asset.region,
                        "exposure_type": asset.exposure_type.value if asset.exposure_type else None,
                        "risk_score": asset.risk_score,
                        "has_sensitive_data": asset.has_sensitive_data,
                    }
                    for asset in result.assets
                ] if result.assets else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print("Public Asset Inventory")
            print("=" * 80)
            if result.summary:
                print(f"Total public assets: {result.summary.total_public_assets}")
                print(f"Internet-facing: {result.summary.internet_facing}")
                print(f"With sensitive data: {result.summary.with_sensitive_data}")
                print("")

                if result.summary.by_cloud:
                    print("By Cloud Provider:")
                    for cloud_name, count in result.summary.by_cloud.items():
                        print(f"  {cloud_name}: {count}")
                    print("")

            if result.assets:
                print("Public Assets:")
                print("-" * 100)
                print(f"{'Resource ID':<40} {'Type':<20} {'Cloud':<8} {'Region':<15} {'Risk'}")
                print("-" * 100)

                for asset in result.assets[:50]:
                    res_id = asset.resource_id[:37] + "..." if len(asset.resource_id) > 40 else asset.resource_id
                    res_type = asset.resource_type[:17] + "..." if len(asset.resource_type) > 20 else asset.resource_type
                    cloud_name = asset.cloud_provider or "N/A"
                    region_name = asset.region[:12] + "..." if asset.region and len(asset.region) > 15 else (asset.region or "N/A")
                    risk = str(asset.risk_score) if asset.risk_score else "N/A"
                    sensitive = " [SENSITIVE]" if asset.has_sensitive_data else ""
                    print(f"{res_id:<40} {res_type:<20} {cloud_name:<8} {region_name:<15} {risk}{sensitive}")

                if len(result.assets) > 50:
                    print(f"... and {len(result.assets) - 50} more assets")
            else:
                print("No publicly accessible assets found.")

        return 0

    except Exception as e:
        logger.error(f"Exposure inventory failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_exposure_certificates(args: argparse.Namespace) -> int:
    """
    Monitor SSL/TLS certificates.
    """
    from stance.exposure.certificates import CertificateMonitor, CertificateConfig

    cloud = getattr(args, "cloud", None)
    output_format = getattr(args, "format", "table")
    expiring_within = getattr(args, "expiring_within", 30)
    domain = getattr(args, "domain", None)

    try:
        config = CertificateConfig(
            warning_days=expiring_within,
            critical_days=7,
        )
        monitor = CertificateMonitor(config)

        print("Analyzing certificates...")
        result = monitor.analyze(
            cloud_provider=cloud,
            domain_filter=domain,
        )

        # Output results
        if output_format == "json":
            output = {
                "summary": {
                    "total_certificates": result.summary.total_certificates if result.summary else 0,
                    "expired": result.summary.expired if result.summary else 0,
                    "expiring_soon": result.summary.expiring_soon if result.summary else 0,
                    "weak_key": result.summary.weak_key if result.summary else 0,
                    "weak_algorithm": result.summary.weak_algorithm if result.summary else 0,
                },
                "certificates": [
                    {
                        "domain": cert.domain,
                        "cloud": cert.cloud_provider,
                        "status": cert.status.value if cert.status else None,
                        "expires_at": cert.expires_at.isoformat() if cert.expires_at else None,
                        "days_until_expiry": cert.days_until_expiry,
                        "key_size": cert.key_size,
                        "algorithm": cert.algorithm,
                        "type": cert.cert_type.value if cert.cert_type else None,
                    }
                    for cert in result.certificates
                ] if result.certificates else [],
                "findings": [
                    {
                        "domain": f.domain,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "severity": f.severity.value if f.severity else None,
                        "message": f.message,
                    }
                    for f in result.findings
                ] if result.findings else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print("Certificate Monitoring")
            print("=" * 80)
            if result.summary:
                print(f"Total certificates: {result.summary.total_certificates}")
                print(f"Expired: {result.summary.expired}")
                print(f"Expiring soon: {result.summary.expiring_soon}")
                print(f"Weak key: {result.summary.weak_key}")
                print(f"Weak algorithm: {result.summary.weak_algorithm}")
            print("")

            if result.findings:
                print("Certificate Findings:")
                print("-" * 100)
                print(f"{'Domain':<40} {'Finding':<25} {'Severity':<10} {'Message'}")
                print("-" * 100)

                for finding in result.findings[:50]:
                    domain_name = finding.domain[:37] + "..." if len(finding.domain) > 40 else finding.domain
                    ftype = finding.finding_type.value if finding.finding_type else "N/A"
                    severity = finding.severity.value if finding.severity else "N/A"
                    message = finding.message[:30] if finding.message else "N/A"
                    print(f"{domain_name:<40} {ftype:<25} {severity:<10} {message}")

                if len(result.findings) > 50:
                    print(f"... and {len(result.findings) - 50} more findings")
                print("")

            if result.certificates:
                print("Certificate Details:")
                print("-" * 100)
                print(f"{'Domain':<35} {'Cloud':<8} {'Status':<12} {'Expires':<12} {'Days':<6} {'Key'}")
                print("-" * 100)

                for cert in result.certificates[:30]:
                    domain_name = cert.domain[:32] + "..." if len(cert.domain) > 35 else cert.domain
                    cloud_name = cert.cloud_provider or "N/A"
                    status = cert.status.value if cert.status else "N/A"
                    expires = cert.expires_at.strftime("%Y-%m-%d") if cert.expires_at else "N/A"
                    days = str(cert.days_until_expiry) if cert.days_until_expiry is not None else "N/A"
                    key = f"{cert.algorithm}/{cert.key_size}" if cert.algorithm else "N/A"
                    print(f"{domain_name:<35} {cloud_name:<8} {status:<12} {expires:<12} {days:<6} {key}")

                if len(result.certificates) > 30:
                    print(f"... and {len(result.certificates) - 30} more certificates")
            else:
                print("No certificates found.")

        return 0

    except Exception as e:
        logger.error(f"Certificate monitoring failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_exposure_dns(args: argparse.Namespace) -> int:
    """
    Analyze DNS records for issues like dangling records.
    """
    from stance.exposure.dns import DNSInventory

    zone = getattr(args, "zone", None)
    cloud = getattr(args, "cloud", None)
    output_format = getattr(args, "format", "table")

    try:
        inventory = DNSInventory()

        print("Analyzing DNS records...")
        result = inventory.analyze(
            zone=zone,
            cloud_provider=cloud,
        )

        # Output results
        if output_format == "json":
            output = {
                "summary": {
                    "total_zones": result.summary.total_zones if result.summary else 0,
                    "total_records": result.summary.total_records if result.summary else 0,
                    "dangling_records": result.summary.dangling_records if result.summary else 0,
                    "takeover_risk": result.summary.takeover_risk if result.summary else 0,
                },
                "zones": [
                    {
                        "name": z.name,
                        "cloud": z.cloud_provider,
                        "record_count": z.record_count,
                    }
                    for z in result.zones
                ] if result.zones else [],
                "findings": [
                    {
                        "record_name": f.record_name,
                        "record_type": f.record_type,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "severity": f.severity.value if f.severity else None,
                        "target": f.target,
                        "takeover_risk": f.takeover_risk,
                        "recommendation": f.recommendation,
                    }
                    for f in result.findings
                ] if result.findings else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print("DNS Inventory Analysis")
            print("=" * 80)
            if result.summary:
                print(f"Total zones: {result.summary.total_zones}")
                print(f"Total records: {result.summary.total_records}")
                print(f"Dangling records: {result.summary.dangling_records}")
                print(f"Takeover risk: {result.summary.takeover_risk}")
            print("")

            if result.findings:
                print("DNS Findings:")
                print("-" * 120)
                print(f"{'Record':<40} {'Type':<8} {'Finding':<25} {'Severity':<10} {'Target':<25} {'Takeover'}")
                print("-" * 120)

                for finding in result.findings[:50]:
                    record = finding.record_name[:37] + "..." if len(finding.record_name) > 40 else finding.record_name
                    rtype = finding.record_type or "N/A"
                    ftype = finding.finding_type.value if finding.finding_type else "N/A"
                    severity = finding.severity.value if finding.severity else "N/A"
                    target = finding.target[:22] + "..." if finding.target and len(finding.target) > 25 else (finding.target or "N/A")
                    takeover = "YES" if finding.takeover_risk else "no"
                    print(f"{record:<40} {rtype:<8} {ftype:<25} {severity:<10} {target:<25} {takeover}")

                if len(result.findings) > 50:
                    print(f"... and {len(result.findings) - 50} more findings")
                print("")

            if result.zones:
                print("DNS Zones:")
                print("-" * 60)
                print(f"{'Zone':<40} {'Cloud':<10} {'Records'}")
                print("-" * 60)

                for zone_info in result.zones[:20]:
                    zone_name = zone_info.name[:37] + "..." if len(zone_info.name) > 40 else zone_info.name
                    cloud_name = zone_info.cloud_provider or "N/A"
                    record_count = str(zone_info.record_count) if zone_info.record_count else "N/A"
                    print(f"{zone_name:<40} {cloud_name:<10} {record_count}")

                if len(result.zones) > 20:
                    print(f"... and {len(result.zones) - 20} more zones")
            else:
                print("No DNS zones found.")

        return 0

    except Exception as e:
        logger.error(f"DNS analysis failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_exposure_sensitive(args: argparse.Namespace) -> int:
    """
    Detect sensitive data exposure in public assets.
    """
    from stance.exposure.sensitive import SensitiveDataExposureAnalyzer

    cloud = getattr(args, "cloud", None)
    output_format = getattr(args, "format", "table")
    classification = getattr(args, "classification", None)

    try:
        analyzer = SensitiveDataExposureAnalyzer()

        print("Analyzing sensitive data exposure...")
        result = analyzer.analyze(
            cloud_provider=cloud,
            classification_filter=classification,
        )

        # Output results
        if output_format == "json":
            output = {
                "summary": {
                    "total_exposures": result.summary.total_exposures if result.summary else 0,
                    "critical_exposures": result.summary.critical_exposures if result.summary else 0,
                    "high_exposures": result.summary.high_exposures if result.summary else 0,
                    "pii_exposures": result.summary.pii_exposures if result.summary else 0,
                    "pci_exposures": result.summary.pci_exposures if result.summary else 0,
                    "phi_exposures": result.summary.phi_exposures if result.summary else 0,
                },
                "findings": [
                    {
                        "resource_id": f.resource_id,
                        "exposure_type": f.exposure_type.value if f.exposure_type else None,
                        "classification": f.classification.value if f.classification else None,
                        "categories": [c.value for c in f.categories] if f.categories else [],
                        "risk_level": f.risk_level.value if f.risk_level else None,
                        "risk_score": f.risk_score,
                        "compliance_impact": f.compliance_impact,
                        "recommendation": f.recommendation,
                    }
                    for f in result.findings
                ] if result.findings else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print("Sensitive Data Exposure Analysis")
            print("=" * 80)
            if result.summary:
                print(f"Total exposures: {result.summary.total_exposures}")
                print(f"Critical: {result.summary.critical_exposures}")
                print(f"High: {result.summary.high_exposures}")
                print(f"PII exposures: {result.summary.pii_exposures}")
                print(f"PCI exposures: {result.summary.pci_exposures}")
                print(f"PHI exposures: {result.summary.phi_exposures}")
            print("")

            if result.findings:
                print("Exposure Findings:")
                print("-" * 120)
                print(f"{'Resource':<35} {'Type':<15} {'Classification':<15} {'Risk':<10} {'Score':<6} {'Compliance'}")
                print("-" * 120)

                for finding in result.findings[:50]:
                    res_id = finding.resource_id[:32] + "..." if len(finding.resource_id) > 35 else finding.resource_id
                    exp_type = finding.exposure_type.value if finding.exposure_type else "N/A"
                    classification = finding.classification.value if finding.classification else "N/A"
                    risk = finding.risk_level.value if finding.risk_level else "N/A"
                    score = str(finding.risk_score) if finding.risk_score else "N/A"
                    compliance = ", ".join(finding.compliance_impact[:2]) if finding.compliance_impact else "N/A"
                    print(f"{res_id:<35} {exp_type:<15} {classification:<15} {risk:<10} {score:<6} {compliance}")

                if len(result.findings) > 50:
                    print(f"... and {len(result.findings) - 50} more findings")
            else:
                print("No sensitive data exposures found.")

        return 0

    except Exception as e:
        logger.error(f"Sensitive data exposure analysis failed: {e}")
        print(f"Error: {e}")
        return 1
