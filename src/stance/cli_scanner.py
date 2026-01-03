"""
CLI commands for Scanner module.

Provides command-line interface for container image scanning:
- Scanner availability and version checking
- Vulnerability scanning with Trivy
- CVE enrichment with EPSS and KEV data
- Vulnerability prioritization
- Scanner configuration and status
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_scanner_parser(subparsers: Any) -> None:
    """Add scanner parser to CLI subparsers."""
    scanner_parser = subparsers.add_parser(
        "scanner",
        help="Container image vulnerability scanning (Trivy, CVE enrichment)",
        description="Scan container images for vulnerabilities and enrich with threat intelligence",
    )

    scanner_subparsers = scanner_parser.add_subparsers(
        dest="scanner_action",
        help="Scanner action to perform",
    )

    # scanners - List available scanners
    scanners_parser = scanner_subparsers.add_parser(
        "scanners",
        help="List available vulnerability scanners",
    )
    scanners_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # check - Check if scanner is available
    check_parser = scanner_subparsers.add_parser(
        "check",
        help="Check if Trivy scanner is available",
    )
    check_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # version - Get scanner version
    version_parser = scanner_subparsers.add_parser(
        "version",
        help="Get Trivy scanner version",
    )
    version_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # scan - Scan a container image
    scan_parser = scanner_subparsers.add_parser(
        "scan",
        help="Scan container image for vulnerabilities",
    )
    scan_parser.add_argument(
        "image",
        help="Container image to scan (e.g., nginx:latest)",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds (default: 300)",
    )
    scan_parser.add_argument(
        "--skip-db-update",
        action="store_true",
        help="Skip vulnerability database update",
    )
    scan_parser.add_argument(
        "--ignore-unfixed",
        action="store_true",
        help="Only show vulnerabilities with available fixes",
    )
    scan_parser.add_argument(
        "--enrich",
        action="store_true",
        help="Enrich with EPSS and KEV data",
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # enrich - Enrich CVE data
    enrich_parser = scanner_subparsers.add_parser(
        "enrich",
        help="Enrich CVE with EPSS and KEV data",
    )
    enrich_parser.add_argument(
        "cve_id",
        help="CVE ID to enrich (e.g., CVE-2021-44228)",
    )
    enrich_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # epss - Get EPSS score for CVE
    epss_parser = scanner_subparsers.add_parser(
        "epss",
        help="Get EPSS score for a CVE",
    )
    epss_parser.add_argument(
        "cve_id",
        help="CVE ID (e.g., CVE-2021-44228)",
    )
    epss_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # kev - Check if CVE is in KEV catalog
    kev_parser = scanner_subparsers.add_parser(
        "kev",
        help="Check if CVE is in CISA KEV catalog",
    )
    kev_parser.add_argument(
        "cve_id",
        help="CVE ID (e.g., CVE-2021-44228)",
    )
    kev_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # severity-levels - List severity levels
    severity_parser = scanner_subparsers.add_parser(
        "severity-levels",
        help="List vulnerability severity levels",
    )
    severity_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # priority-factors - List priority scoring factors
    priority_parser = scanner_subparsers.add_parser(
        "priority-factors",
        help="List vulnerability priority scoring factors",
    )
    priority_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # package-types - List supported package types
    packages_parser = scanner_subparsers.add_parser(
        "package-types",
        help="List supported package types for scanning",
    )
    packages_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show scanning statistics
    stats_parser = scanner_subparsers.add_parser(
        "stats",
        help="Show scanner statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show module status
    status_parser = scanner_subparsers.add_parser(
        "status",
        help="Show scanner module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive summary
    summary_parser = scanner_subparsers.add_parser(
        "summary",
        help="Show scanner module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_scanner(args: argparse.Namespace) -> int:
    """Handle scanner commands."""
    action = getattr(args, "scanner_action", None)

    if action is None:
        print("Error: No scanner action specified")
        print("Use 'stance scanner --help' for available actions")
        return 1

    handlers = {
        "scanners": _handle_scanners,
        "check": _handle_check,
        "version": _handle_version,
        "scan": _handle_scan,
        "enrich": _handle_enrich,
        "epss": _handle_epss,
        "kev": _handle_kev,
        "severity-levels": _handle_severity_levels,
        "priority-factors": _handle_priority_factors,
        "package-types": _handle_package_types,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler is None:
        print(f"Error: Unknown action '{action}'")
        return 1

    return handler(args)


def _handle_scanners(args: argparse.Namespace) -> int:
    """Handle scanners command."""
    from stance.scanner import TrivyScanner

    scanner = TrivyScanner()
    trivy_available = scanner.is_available()
    trivy_version = scanner.get_version() if trivy_available else None

    scanners = [
        {
            "id": "trivy",
            "name": "Trivy",
            "description": "Comprehensive vulnerability scanner by Aqua Security",
            "available": trivy_available,
            "version": trivy_version,
            "install": "brew install trivy",
            "supported_targets": ["container_images", "filesystems", "git_repos"],
        },
        {
            "id": "grype",
            "name": "Grype",
            "description": "Vulnerability scanner by Anchore (not yet implemented)",
            "available": False,
            "version": None,
            "install": "brew install grype",
            "supported_targets": ["container_images", "filesystems"],
        },
    ]

    result = {
        "total": len(scanners),
        "available": sum(1 for s in scanners if s["available"]),
        "scanners": scanners,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Available Scanners")
        print("=" * 70)
        print(f"Total: {result['total']} (Available: {result['available']})")
        print()
        for s in scanners:
            status = "Available" if s["available"] else "Not Available"
            version_str = f" v{s['version']}" if s["version"] else ""
            print(f"{s['name']}{version_str} [{status}]")
            print(f"  {s['description']}")
            if not s["available"]:
                print(f"  Install: {s['install']}")
            print()

    return 0


def _handle_check(args: argparse.Namespace) -> int:
    """Handle check command."""
    from stance.scanner import TrivyScanner

    scanner = TrivyScanner()
    is_available = scanner.is_available()
    version = scanner.get_version() if is_available else None

    result = {
        "scanner": "trivy",
        "available": is_available,
        "version": version,
        "message": "Trivy is installed and available" if is_available else "Trivy is not installed",
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Scanner: Trivy")
        print(f"Available: {'Yes' if result['available'] else 'No'}")
        if version:
            print(f"Version: {version}")
        print(f"Status: {result['message']}")

    return 0 if is_available else 1


def _handle_version(args: argparse.Namespace) -> int:
    """Handle version command."""
    from stance.scanner import TrivyScanner

    scanner = TrivyScanner()
    version = scanner.get_version()

    result = {
        "scanner": "trivy",
        "version": version,
        "available": version is not None,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        if version:
            print(f"Trivy version: {version}")
        else:
            print("Trivy is not installed or version could not be determined")
            return 1

    return 0


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle scan command."""
    from stance.scanner import TrivyScanner, ScannerNotAvailableError

    scanner = TrivyScanner()

    if not scanner.is_available():
        print("Error: Trivy is not installed")
        print("Install with: brew install trivy")
        return 1

    try:
        result = scanner.scan(
            image_reference=args.image,
            timeout_seconds=args.timeout,
            skip_db_update=args.skip_db_update,
            ignore_unfixed=args.ignore_unfixed,
        )
    except ScannerNotAvailableError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Error scanning image: {e}")
        return 1

    # Optionally enrich with EPSS/KEV
    enriched_vulns = None
    if args.enrich and result.vulnerabilities:
        from stance.scanner import CVEEnricher
        enricher = CVEEnricher()
        enriched_vulns = enricher.enrich_scan_result(result)

    if args.format == "json":
        output = result.summary()
        if enriched_vulns:
            output["enriched_vulnerabilities"] = [
                {
                    "vulnerability_id": ev.vulnerability.vulnerability_id,
                    "package_name": ev.vulnerability.package_name,
                    "severity": ev.vulnerability.severity.value,
                    "priority_score": ev.priority_score,
                    "in_kev": ev.kev_entry is not None,
                    "epss_score": ev.epss_score.epss if ev.epss_score else None,
                }
                for ev in enriched_vulns[:20]  # Limit to top 20
            ]
        print(json.dumps(output, indent=2, default=str))
    else:
        summary = result.summary()
        print(f"Image: {summary['image_reference']}")
        print(f"Scanner: {summary['scanner']} {summary['scanner_version'] or ''}")
        print(f"Duration: {summary['scan_duration_seconds']:.2f}s")
        print()
        print("Vulnerability Summary:")
        print("-" * 40)
        print(f"  Total: {summary['total_vulnerabilities']}")
        print(f"  Critical: {summary['critical']}")
        print(f"  High: {summary['high']}")
        print(f"  Medium: {summary['medium']}")
        print(f"  Low: {summary['low']}")
        print(f"  Fixable: {summary['fixable']}")

        if enriched_vulns:
            print()
            print("Top Priority Vulnerabilities:")
            print("-" * 40)
            for ev in enriched_vulns[:10]:
                kev_marker = " [KEV]" if ev.kev_entry else ""
                epss_str = f" EPSS:{ev.epss_score.epss:.1%}" if ev.epss_score else ""
                print(f"  {ev.vulnerability.vulnerability_id} ({ev.vulnerability.severity.value})")
                print(f"    Package: {ev.vulnerability.package_name} {ev.vulnerability.installed_version}")
                print(f"    Priority: {ev.priority_score:.0f}/100{kev_marker}{epss_str}")

    return 0


def _handle_enrich(args: argparse.Namespace) -> int:
    """Handle enrich command."""
    from stance.scanner import CVEEnricher

    cve_id = args.cve_id.upper()
    if not cve_id.startswith("CVE-"):
        print("Error: Invalid CVE ID format. Expected CVE-YYYY-NNNNN")
        return 1

    enricher = CVEEnricher()

    # Get EPSS and KEV data
    epss = enricher._get_epss_score(cve_id)
    kev = enricher._get_kev_entry(cve_id)

    result = {
        "cve_id": cve_id,
        "epss": {
            "score": epss.epss if epss else None,
            "percentile": epss.percentile if epss else None,
            "date": epss.date if epss else None,
        } if epss else None,
        "kev": {
            "in_catalog": kev is not None,
            "vendor": kev.vendor_project if kev else None,
            "product": kev.product if kev else None,
            "date_added": kev.date_added if kev else None,
            "due_date": kev.due_date if kev else None,
            "ransomware_use": kev.known_ransomware_campaign_use if kev else None,
        } if kev else {"in_catalog": False},
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"CVE: {cve_id}")
        print("=" * 50)

        if epss:
            print("\nEPSS Score:")
            print(f"  Score: {epss.epss:.2%}")
            print(f"  Percentile: {epss.percentile:.2%}")
            print(f"  Date: {epss.date}")
        else:
            print("\nEPSS: No data available")

        if kev:
            print("\nCISA KEV Catalog:")
            print(f"  In Catalog: Yes")
            print(f"  Vendor: {kev.vendor_project}")
            print(f"  Product: {kev.product}")
            print(f"  Date Added: {kev.date_added}")
            print(f"  Due Date: {kev.due_date}")
            print(f"  Ransomware Use: {'Yes' if kev.known_ransomware_campaign_use else 'No'}")
        else:
            print("\nCISA KEV: Not in catalog")

    return 0


def _handle_epss(args: argparse.Namespace) -> int:
    """Handle epss command."""
    from stance.scanner import CVEEnricher

    cve_id = args.cve_id.upper()
    if not cve_id.startswith("CVE-"):
        print("Error: Invalid CVE ID format. Expected CVE-YYYY-NNNNN")
        return 1

    enricher = CVEEnricher()
    enricher._batch_fetch_epss([cve_id])
    epss = enricher._get_epss_score(cve_id)

    result = {
        "cve_id": cve_id,
        "found": epss is not None,
        "score": epss.epss if epss else None,
        "percentile": epss.percentile if epss else None,
        "date": epss.date if epss else None,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"CVE: {cve_id}")
        if epss:
            print(f"EPSS Score: {epss.epss:.2%}")
            print(f"Percentile: {epss.percentile:.2%}")
            print(f"Date: {epss.date}")
        else:
            print("EPSS: No data available")

    return 0


def _handle_kev(args: argparse.Namespace) -> int:
    """Handle kev command."""
    from stance.scanner import CVEEnricher

    cve_id = args.cve_id.upper()
    if not cve_id.startswith("CVE-"):
        print("Error: Invalid CVE ID format. Expected CVE-YYYY-NNNNN")
        return 1

    enricher = CVEEnricher()
    kev = enricher._get_kev_entry(cve_id)

    result = {
        "cve_id": cve_id,
        "in_catalog": kev is not None,
    }

    if kev:
        result.update({
            "vendor": kev.vendor_project,
            "product": kev.product,
            "vulnerability_name": kev.vulnerability_name,
            "date_added": kev.date_added,
            "short_description": kev.short_description,
            "required_action": kev.required_action,
            "due_date": kev.due_date,
            "ransomware_use": kev.known_ransomware_campaign_use,
        })

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"CVE: {cve_id}")
        if kev:
            print(f"In KEV Catalog: Yes")
            print(f"Vendor: {kev.vendor_project}")
            print(f"Product: {kev.product}")
            print(f"Name: {kev.vulnerability_name}")
            print(f"Date Added: {kev.date_added}")
            print(f"Due Date: {kev.due_date}")
            print(f"Description: {kev.short_description}")
            print(f"Required Action: {kev.required_action}")
            print(f"Ransomware Use: {'Yes' if kev.known_ransomware_campaign_use else 'No'}")
        else:
            print("In KEV Catalog: No")

    return 0


def _handle_severity_levels(args: argparse.Namespace) -> int:
    """Handle severity-levels command."""
    levels = [
        {
            "level": "CRITICAL",
            "description": "Severe vulnerability requiring immediate attention",
            "cvss_range": "9.0 - 10.0",
            "examples": "Remote code execution, authentication bypass",
        },
        {
            "level": "HIGH",
            "description": "High-impact vulnerability requiring prompt remediation",
            "cvss_range": "7.0 - 8.9",
            "examples": "Privilege escalation, sensitive data exposure",
        },
        {
            "level": "MEDIUM",
            "description": "Moderate vulnerability requiring scheduled remediation",
            "cvss_range": "4.0 - 6.9",
            "examples": "Cross-site scripting, information disclosure",
        },
        {
            "level": "LOW",
            "description": "Low-impact vulnerability for opportunistic fixing",
            "cvss_range": "0.1 - 3.9",
            "examples": "Minor information leaks, DoS with limited impact",
        },
        {
            "level": "UNKNOWN",
            "description": "Severity not determined",
            "cvss_range": "N/A",
            "examples": "Newly published CVEs without scoring",
        },
    ]

    result = {
        "total": len(levels),
        "levels": levels,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Vulnerability Severity Levels")
        print("=" * 70)
        for level in levels:
            print(f"\n{level['level']}")
            print(f"  Description: {level['description']}")
            print(f"  CVSS Range: {level['cvss_range']}")
            print(f"  Examples: {level['examples']}")

    return 0


def _handle_priority_factors(args: argparse.Namespace) -> int:
    """Handle priority-factors command."""
    factors = [
        {
            "factor": "Severity",
            "max_points": 40,
            "description": "Base score from vulnerability severity (CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10)",
        },
        {
            "factor": "CVSS Score",
            "max_points": 20,
            "description": "Contribution from CVSS score (score * 2, capped at 20)",
        },
        {
            "factor": "EPSS Score",
            "max_points": 20,
            "description": "Exploit prediction score (probability * 20)",
        },
        {
            "factor": "KEV Catalog",
            "max_points": 20,
            "description": "In CISA Known Exploited Vulnerabilities catalog",
        },
        {
            "factor": "Ransomware Use",
            "max_points": 10,
            "description": "Known use in ransomware campaigns (requires KEV)",
        },
        {
            "factor": "Fix Available",
            "max_points": 5,
            "description": "Fixed version is available",
        },
    ]

    result = {
        "max_score": 100,
        "factors": factors,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Vulnerability Priority Scoring Factors")
        print("=" * 70)
        print("Maximum Priority Score: 100")
        print()
        print(f"{'Factor':<20} {'Max Points':<12} Description")
        print("-" * 70)
        for f in factors:
            print(f"{f['factor']:<20} {f['max_points']:<12} {f['description']}")

    return 0


def _handle_package_types(args: argparse.Namespace) -> int:
    """Handle package-types command."""
    package_types = [
        {"type": "apk", "ecosystem": "Alpine Linux", "description": "Alpine Package Keeper"},
        {"type": "deb", "ecosystem": "Debian/Ubuntu", "description": "Debian packages"},
        {"type": "rpm", "ecosystem": "RHEL/CentOS/Fedora", "description": "RPM packages"},
        {"type": "gem", "ecosystem": "Ruby", "description": "RubyGems"},
        {"type": "npm", "ecosystem": "Node.js", "description": "NPM packages"},
        {"type": "pip", "ecosystem": "Python", "description": "PyPI packages"},
        {"type": "cargo", "ecosystem": "Rust", "description": "Cargo crates"},
        {"type": "go", "ecosystem": "Go", "description": "Go modules"},
        {"type": "composer", "ecosystem": "PHP", "description": "Composer packages"},
        {"type": "nuget", "ecosystem": "C#/.NET", "description": "NuGet packages"},
        {"type": "maven", "ecosystem": "Java", "description": "Maven artifacts"},
        {"type": "gradle", "ecosystem": "Java", "description": "Gradle dependencies"},
    ]

    result = {
        "total": len(package_types),
        "package_types": package_types,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Supported Package Types")
        print("=" * 70)
        print()
        print(f"{'Type':<12} {'Ecosystem':<20} Description")
        print("-" * 70)
        for pt in package_types:
            print(f"{pt['type']:<12} {pt['ecosystem']:<20} {pt['description']}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    from stance.scanner import TrivyScanner

    scanner = TrivyScanner()
    is_available = scanner.is_available()
    version = scanner.get_version() if is_available else None

    result = {
        "scanner": "trivy",
        "available": is_available,
        "version": version,
        "severity_levels": 5,
        "package_types": 12,
        "enrichment_sources": ["EPSS", "KEV"],
        "priority_factors": 6,
        "supported_targets": [
            "container_images",
            "filesystems",
            "git_repos",
            "kubernetes",
        ],
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Scanner Statistics")
        print("=" * 70)
        print(f"Scanner: {result['scanner']}")
        print(f"Available: {'Yes' if result['available'] else 'No'}")
        if version:
            print(f"Version: {version}")
        print(f"Severity Levels: {result['severity_levels']}")
        print(f"Package Types: {result['package_types']}")
        print(f"Enrichment Sources: {', '.join(result['enrichment_sources'])}")
        print(f"Priority Factors: {result['priority_factors']}")
        print(f"Supported Targets: {', '.join(result['supported_targets'])}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    from stance.scanner import TrivyScanner

    scanner = TrivyScanner()
    is_available = scanner.is_available()
    version = scanner.get_version() if is_available else None

    result = {
        "module": "scanner",
        "status": "operational" if is_available else "degraded",
        "components": {
            "TrivyScanner": "available" if is_available else "not_installed",
            "CVEEnricher": "available",
            "EPSSClient": "available",
            "KEVClient": "available",
        },
        "capabilities": [
            "container_image_scanning",
            "vulnerability_detection",
            "cve_enrichment",
            "epss_scoring",
            "kev_lookup",
            "priority_calculation",
            "batch_scanning",
        ],
        "scanner_version": version,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Scanner Module Status")
        print("=" * 70)
        print(f"Module: {result['module']}")
        print(f"Status: {result['status']}")
        print()
        print("Components:")
        for comp, status in result["components"].items():
            print(f"  {comp}: {status}")
        print()
        print("Capabilities:")
        for cap in result["capabilities"]:
            print(f"  - {cap}")
        if version:
            print(f"\nTrivy Version: {version}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    from stance.scanner import TrivyScanner

    scanner = TrivyScanner()
    is_available = scanner.is_available()
    version = scanner.get_version() if is_available else None

    result = {
        "module": "scanner",
        "version": "1.0.0",
        "description": "Container image vulnerability scanning with CVE enrichment",
        "scanner": {
            "name": "Trivy",
            "available": is_available,
            "version": version,
        },
        "enrichment": {
            "epss": "Exploit Prediction Scoring System from FIRST.org",
            "kev": "CISA Known Exploited Vulnerabilities catalog",
        },
        "features": [
            "Trivy-based container image scanning",
            "Vulnerability detection for 12 package types",
            "EPSS exploit probability scoring",
            "CISA KEV catalog integration",
            "Priority-based vulnerability ranking",
            "Batch image scanning",
            "JSON and SARIF output formats",
            "Fixable vulnerability filtering",
        ],
        "supported_ecosystems": [
            "Alpine (apk)", "Debian/Ubuntu (deb)", "RHEL/CentOS (rpm)",
            "Node.js (npm)", "Python (pip)", "Ruby (gem)",
            "Go (modules)", "Rust (cargo)", "Java (maven/gradle)",
            "PHP (composer)", ".NET (nuget)",
        ],
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Scanner Module Summary")
        print("=" * 70)
        print(f"Module: {result['module']}")
        print(f"Version: {result['version']}")
        print(f"Description: {result['description']}")
        print()
        print("Scanner:")
        print(f"  Name: {result['scanner']['name']}")
        print(f"  Available: {'Yes' if result['scanner']['available'] else 'No'}")
        if version:
            print(f"  Version: {version}")
        print()
        print("Enrichment Sources:")
        for source, desc in result["enrichment"].items():
            print(f"  {source.upper()}: {desc}")
        print()
        print("Features:")
        for feature in result["features"]:
            print(f"  - {feature}")
        print()
        print("Supported Ecosystems:")
        for eco in result["supported_ecosystems"]:
            print(f"  - {eco}")

    return 0
