"""
CLI commands for SBOM (Software Bill of Materials) management.

Provides commands for generating, analyzing, and validating SBOMs,
as well as license compliance and supply chain risk assessment.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


def add_sbom_parser(subparsers: Any) -> None:
    """Add sbom subcommands to the CLI."""
    sbom_parser = subparsers.add_parser(
        "sbom",
        help="SBOM and supply chain security commands",
        description="Generate and analyze Software Bill of Materials for supply chain security.",
    )

    sbom_subparsers = sbom_parser.add_subparsers(
        dest="sbom_command",
        title="sbom commands",
        description="Available SBOM commands",
    )

    # Generate SBOM
    generate_parser = sbom_subparsers.add_parser(
        "generate",
        help="Generate SBOM from dependency files",
        description="Generate a Software Bill of Materials from project dependencies.",
    )
    generate_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to dependency file or directory (default: current directory)",
    )
    generate_parser.add_argument(
        "--format",
        "-f",
        choices=["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag", "stance"],
        default="cyclonedx-json",
        help="Output format (default: cyclonedx-json)",
    )
    generate_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: stdout)",
    )
    generate_parser.add_argument(
        "--name",
        help="Component name for the SBOM",
    )
    generate_parser.add_argument(
        "--version",
        help="Component version for the SBOM",
    )
    generate_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively scan directories for dependency files",
    )

    # Parse dependencies
    parse_parser = sbom_subparsers.add_parser(
        "parse",
        help="Parse dependency files",
        description="Parse dependency files and display dependencies.",
    )
    parse_parser.add_argument(
        "path",
        help="Path to dependency file or directory",
    )
    parse_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively scan directories",
    )
    parse_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Analyze licenses
    license_parser = sbom_subparsers.add_parser(
        "license",
        help="Analyze software licenses",
        description="Analyze licenses in dependencies and check compliance.",
    )
    license_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to dependency file or directory (default: current directory)",
    )
    license_parser.add_argument(
        "--policy",
        choices=["permissive", "copyleft-allowed", "strict"],
        default="permissive",
        help="License policy to enforce (default: permissive)",
    )
    license_parser.add_argument(
        "--allowed",
        nargs="+",
        help="Explicitly allowed license SPDX identifiers",
    )
    license_parser.add_argument(
        "--denied",
        nargs="+",
        help="Explicitly denied license SPDX identifiers",
    )
    license_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Analyze supply chain risks
    risk_parser = sbom_subparsers.add_parser(
        "risk",
        help="Analyze supply chain risks",
        description="Perform comprehensive supply chain risk analysis.",
    )
    risk_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to dependency file or directory (default: current directory)",
    )
    risk_parser.add_argument(
        "--check-typosquat",
        action="store_true",
        default=True,
        help="Check for typosquatting risks (default: enabled)",
    )
    risk_parser.add_argument(
        "--check-deprecated",
        action="store_true",
        default=True,
        help="Check for deprecated packages (default: enabled)",
    )
    risk_parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    risk_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Validate SBOM
    validate_parser = sbom_subparsers.add_parser(
        "validate",
        help="Validate an existing SBOM",
        description="Validate SBOM file format and contents.",
    )
    validate_parser.add_argument(
        "file",
        help="Path to SBOM file",
    )
    validate_parser.add_argument(
        "--format",
        "-f",
        choices=["auto", "cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag"],
        default="auto",
        help="SBOM format (default: auto-detect)",
    )
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # List supported formats
    formats_parser = sbom_subparsers.add_parser(
        "formats",
        help="List supported SBOM formats",
        description="Show information about supported SBOM formats.",
    )
    formats_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # List supported ecosystems
    ecosystems_parser = sbom_subparsers.add_parser(
        "ecosystems",
        help="List supported package ecosystems",
        description="Show information about supported package ecosystems and files.",
    )
    ecosystems_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # List licenses
    licenses_parser = sbom_subparsers.add_parser(
        "licenses",
        help="List known software licenses",
        description="Show information about known software licenses and their properties.",
    )
    licenses_parser.add_argument(
        "--category",
        choices=["permissive", "copyleft", "proprietary", "public-domain", "all"],
        default="all",
        help="Filter by license category (default: all)",
    )
    licenses_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show SBOM info
    info_parser = sbom_subparsers.add_parser(
        "info",
        help="Show SBOM module information",
        description="Show information about the SBOM module capabilities.",
    )
    info_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Show module status
    status_parser = sbom_subparsers.add_parser(
        "status",
        help="Show SBOM module status",
        description="Show status of SBOM module components.",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Diff two SBOMs
    diff_parser = sbom_subparsers.add_parser(
        "diff",
        help="Compare two SBOMs",
        description="Show differences between two SBOM files.",
    )
    diff_parser.add_argument(
        "sbom1",
        help="Path to first SBOM file",
    )
    diff_parser.add_argument(
        "sbom2",
        help="Path to second SBOM file",
    )
    diff_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Convert SBOM format
    convert_parser = sbom_subparsers.add_parser(
        "convert",
        help="Convert SBOM between formats",
        description="Convert SBOM file from one format to another.",
    )
    convert_parser.add_argument(
        "input",
        help="Input SBOM file",
    )
    convert_parser.add_argument(
        "output",
        help="Output SBOM file",
    )
    convert_parser.add_argument(
        "--from-format",
        choices=["auto", "cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag"],
        default="auto",
        help="Input format (default: auto-detect)",
    )
    convert_parser.add_argument(
        "--to-format",
        choices=["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag", "stance"],
        required=True,
        help="Output format",
    )

    # Vulnerability scanning
    vuln_parser = sbom_subparsers.add_parser(
        "vuln",
        help="Scan for vulnerabilities",
        description="Scan dependencies for known vulnerabilities using NVD and OSV databases.",
    )
    vuln_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to dependency file or directory (default: current directory)",
    )
    vuln_parser.add_argument(
        "--sources",
        "-s",
        nargs="+",
        choices=["osv", "nvd", "local"],
        default=["osv"],
        help="Vulnerability sources to query (default: osv)",
    )
    vuln_parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "none"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    vuln_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default=None,
        help="Exit with error if vulnerabilities at or above this severity are found",
    )
    vuln_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        help="Recursively scan directories",
    )
    vuln_parser.add_argument(
        "--offline",
        action="store_true",
        help="Use offline mode (only local cache)",
    )
    vuln_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # List CVEs for a package
    cve_parser = sbom_subparsers.add_parser(
        "cve",
        help="Look up CVEs for a package",
        description="Look up known vulnerabilities for a specific package.",
    )
    cve_parser.add_argument(
        "package",
        help="Package name",
    )
    cve_parser.add_argument(
        "version",
        nargs="?",
        default="*",
        help="Package version (default: all versions)",
    )
    cve_parser.add_argument(
        "--ecosystem",
        "-e",
        choices=["npm", "pypi", "go", "cargo", "maven", "nuget", "rubygems", "composer"],
        default="pypi",
        help="Package ecosystem (default: pypi)",
    )
    cve_parser.add_argument(
        "--sources",
        "-s",
        nargs="+",
        choices=["osv", "nvd", "local"],
        default=["osv"],
        help="Vulnerability sources to query (default: osv)",
    )
    cve_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Vulnerability database management
    vulndb_parser = sbom_subparsers.add_parser(
        "vulndb",
        help="Manage vulnerability database",
        description="Manage local vulnerability database and cache.",
    )
    vulndb_parser.add_argument(
        "action",
        choices=["status", "clear", "import"],
        help="Action to perform",
    )
    vulndb_parser.add_argument(
        "--file",
        help="File to import (for import action)",
    )
    vulndb_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Dependency graph visualization
    graph_parser = sbom_subparsers.add_parser(
        "graph",
        help="Visualize dependency graph",
        description="Generate and visualize dependency graphs from project dependencies.",
    )
    graph_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to dependency file or directory (default: current directory)",
    )
    graph_parser.add_argument(
        "--format",
        "-f",
        choices=["tree", "dot", "mermaid", "json"],
        default="tree",
        help="Output format (default: tree)",
    )
    graph_parser.add_argument(
        "--max-depth",
        type=int,
        default=None,
        help="Maximum depth to display (tree format only)",
    )
    graph_parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: stdout)",
    )
    graph_parser.add_argument(
        "--metrics",
        action="store_true",
        help="Show graph metrics only",
    )
    graph_parser.add_argument(
        "--cycles",
        action="store_true",
        help="Detect and show dependency cycles",
    )

    # SBOM attestation
    attest_parser = sbom_subparsers.add_parser(
        "attest",
        help="Create or verify SBOM attestations",
        description="Create cryptographically signed attestations for SBOMs.",
    )
    attest_parser.add_argument(
        "action",
        choices=["create", "verify", "show"],
        help="Action to perform",
    )
    attest_parser.add_argument(
        "sbom_file",
        nargs="?",
        help="Path to SBOM file",
    )
    attest_parser.add_argument(
        "--key",
        help="Secret key for signing/verification (or use STANCE_ATTEST_KEY env var)",
    )
    attest_parser.add_argument(
        "--signer",
        default="Mantissa Stance",
        help="Signer name (default: Mantissa Stance)",
    )
    attest_parser.add_argument(
        "--expiry-days",
        type=int,
        default=90,
        help="Attestation expiry in days (default: 90)",
    )
    attest_parser.add_argument(
        "--output",
        "-o",
        help="Output file for attestation",
    )
    attest_parser.add_argument(
        "--attestation",
        help="Attestation file to verify (for verify action)",
    )
    attest_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # VEX document management
    vex_parser = sbom_subparsers.add_parser(
        "vex",
        help="Create and manage VEX documents",
        description="Create VEX (Vulnerability Exploitability eXchange) documents.",
    )
    vex_parser.add_argument(
        "action",
        choices=["create", "parse", "show", "export"],
        help="Action to perform",
    )
    vex_parser.add_argument(
        "file",
        nargs="?",
        help="Path to file (SBOM for create, VEX for parse/show/export)",
    )
    vex_parser.add_argument(
        "--format",
        "-f",
        choices=["openvex", "cyclonedx", "csaf", "native"],
        default="openvex",
        help="VEX output format (default: openvex)",
    )
    vex_parser.add_argument(
        "--vuln-file",
        help="Path to vulnerability scan results file",
    )
    vex_parser.add_argument(
        "--output",
        "-o",
        help="Output file path",
    )
    vex_parser.add_argument(
        "--author",
        default="Mantissa Stance",
        help="VEX document author (default: Mantissa Stance)",
    )
    vex_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )


def cmd_sbom(args: argparse.Namespace) -> int:
    """Handle sbom commands."""
    if not hasattr(args, "sbom_command") or args.sbom_command is None:
        print("Usage: stance sbom <command> [options]")
        print("\nAvailable commands:")
        print("  generate   - Generate SBOM from dependency files")
        print("  parse      - Parse dependency files")
        print("  license    - Analyze software licenses")
        print("  risk       - Analyze supply chain risks")
        print("  vuln       - Scan for vulnerabilities (NVD/OSV)")
        print("  cve        - Look up CVEs for a package")
        print("  vulndb     - Manage vulnerability database")
        print("  graph      - Visualize dependency graph")
        print("  attest     - Create or verify SBOM attestations")
        print("  vex        - Create and manage VEX documents")
        print("  validate   - Validate an existing SBOM")
        print("  diff       - Compare two SBOMs")
        print("  convert    - Convert SBOM between formats")
        print("  formats    - List supported SBOM formats")
        print("  ecosystems - List supported package ecosystems")
        print("  licenses   - List known software licenses")
        print("  info       - Show SBOM module information")
        print("  status     - Show SBOM module status")
        print("\nUse 'stance sbom <command> --help' for more information.")
        return 0

    handlers = {
        "generate": _handle_generate,
        "parse": _handle_parse,
        "license": _handle_license,
        "risk": _handle_risk,
        "vuln": _handle_vuln,
        "cve": _handle_cve,
        "vulndb": _handle_vulndb,
        "graph": _handle_graph,
        "attest": _handle_attest,
        "vex": _handle_vex,
        "validate": _handle_validate,
        "formats": _handle_formats,
        "ecosystems": _handle_ecosystems,
        "licenses": _handle_licenses,
        "info": _handle_info,
        "status": _handle_status,
        "diff": _handle_diff,
        "convert": _handle_convert,
    }

    handler = handlers.get(args.sbom_command)
    if handler:
        return handler(args)

    print(f"Unknown sbom command: {args.sbom_command}")
    return 1


def _handle_generate(args: argparse.Namespace) -> int:
    """Handle generate command."""
    from stance.sbom import SBOMGenerator, SBOMFormat

    format_map = {
        "cyclonedx-json": SBOMFormat.CYCLONEDX_JSON,
        "cyclonedx-xml": SBOMFormat.CYCLONEDX_XML,
        "spdx-json": SBOMFormat.SPDX_JSON,
        "spdx-tag": SBOMFormat.SPDX_TAG_VALUE,
        "stance": SBOMFormat.STANCE,
    }

    generator = SBOMGenerator()
    path = Path(args.path)

    try:
        if path.is_file():
            sbom = generator.generate_from_file(
                str(path),
                component_name=args.name,
                component_version=args.version,
            )
        else:
            sbom = generator.generate_from_directory(
                str(path),
                component_name=args.name or path.name,
                component_version=args.version,
                recursive=args.recursive,
            )

        sbom_format = format_map[args.format]
        output = generator.export(sbom, sbom_format)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"SBOM written to {args.output}")
            print(f"Format: {args.format}")
            print(f"Components: {len(sbom.components)}")
        else:
            print(output)

        return 0

    except Exception as e:
        print(f"Error generating SBOM: {e}")
        return 1


def _handle_parse(args: argparse.Namespace) -> int:
    """Handle parse command."""
    from stance.sbom import DependencyParser

    parser = DependencyParser()
    path = Path(args.path)

    try:
        if path.is_file():
            dep_file = parser.parse_file(str(path))
            dep_files = [dep_file] if dep_file else []
        else:
            dep_files = parser.parse_directory(str(path), recursive=args.recursive)

        if args.json:
            output = {
                "files": [
                    {
                        "path": df.path,
                        "ecosystem": df.ecosystem.value,
                        "dependencies": [
                            {
                                "name": d.name,
                                "version": d.version or "any",
                                "scope": d.scope.value,
                                "ecosystem": d.ecosystem.value,
                            }
                            for d in df.dependencies
                        ],
                    }
                    for df in dep_files
                ],
                "total_files": len(dep_files),
                "total_dependencies": sum(len(df.dependencies) for df in dep_files),
            }
            print(json.dumps(output, indent=2))
        else:
            total_deps = 0
            for df in dep_files:
                print(f"\n{df.path} ({df.ecosystem.value}):")
                print("-" * 50)
                for dep in df.dependencies:
                    version = dep.version or "any"
                    scope = f" [{dep.scope.value}]" if dep.scope.value != "runtime" else ""
                    print(f"  {dep.name}@{version}{scope}")
                    total_deps += 1

            print()
            print(f"Total: {len(dep_files)} file(s), {total_deps} dependencies")

        return 0

    except Exception as e:
        print(f"Error parsing dependencies: {e}")
        return 1


def _handle_license(args: argparse.Namespace) -> int:
    """Handle license command."""
    from stance.sbom import DependencyParser, LicenseAnalyzer, LicenseRisk

    parser = DependencyParser()
    analyzer = LicenseAnalyzer()
    path = Path(args.path)

    try:
        if path.is_file():
            dep_file = parser.parse_file(str(path))
            dependencies = dep_file.dependencies if dep_file else []
        else:
            dep_files = parser.parse_directory(str(path), recursive=True)
            dependencies = []
            for df in dep_files:
                dependencies.extend(df.dependencies)

        # Analyze licenses
        report = analyzer.analyze_dependencies(dependencies)

        # Apply policy
        policy_risks = {
            "permissive": [LicenseRisk.HIGH, LicenseRisk.CRITICAL],
            "copyleft-allowed": [LicenseRisk.CRITICAL],
            "strict": [LicenseRisk.MEDIUM, LicenseRisk.HIGH, LicenseRisk.CRITICAL],
        }
        blocked_risks = policy_risks.get(args.policy, [])

        violations = []
        for result in report.results:
            if result.risk in blocked_risks:
                violations.append(result)
            if args.denied and result.license and result.license.spdx_id in args.denied:
                violations.append(result)

        if args.json:
            output = {
                "policy": args.policy,
                "total_dependencies": len(dependencies),
                "licenses_found": len(report.results),
                "unknown_licenses": report.unknown_count,
                "summary": {
                    "permissive": report.permissive_count,
                    "weak_copyleft": report.weak_copyleft_count,
                    "strong_copyleft": report.strong_copyleft_count,
                    "proprietary": report.proprietary_count,
                    "unknown": report.unknown_count,
                },
                "risk_summary": {
                    risk.value: count
                    for risk, count in report.risk_counts.items()
                },
                "violations": [
                    {
                        "package": v.package_name,
                        "license": v.license.spdx_id if v.license else "unknown",
                        "risk": v.risk.value,
                    }
                    for v in violations
                ],
                "compliant": len(violations) == 0,
            }
            print(json.dumps(output, indent=2))
        else:
            print("License Analysis Report")
            print("=" * 50)
            print(f"Policy: {args.policy}")
            print(f"Dependencies analyzed: {len(dependencies)}")
            print()
            print("License Summary:")
            print(f"  Permissive:     {report.permissive_count}")
            print(f"  Weak Copyleft:  {report.weak_copyleft_count}")
            print(f"  Strong Copyleft: {report.strong_copyleft_count}")
            print(f"  Proprietary:    {report.proprietary_count}")
            print(f"  Unknown:        {report.unknown_count}")
            print()
            print("Risk Summary:")
            for risk, count in sorted(report.risk_counts.items(), key=lambda x: x[0].value):
                print(f"  {risk.value.upper()}: {count}")

            if violations:
                print()
                print("Policy Violations:")
                for v in violations:
                    lic = v.license.spdx_id if v.license else "unknown"
                    print(f"  - {v.package_name}: {lic} ({v.risk.value})")
                print()
                print(f"FAILED: {len(violations)} violation(s) found")
                return 1
            else:
                print()
                print("PASSED: All licenses comply with policy")

        return 0

    except Exception as e:
        print(f"Error analyzing licenses: {e}")
        return 1


def _handle_risk(args: argparse.Namespace) -> int:
    """Handle risk command."""
    from stance.sbom import DependencyParser, SupplyChainAnalyzer, RiskLevel

    severity_order = ["critical", "high", "medium", "low", "info"]
    min_severity_idx = severity_order.index(args.min_severity)

    parser = DependencyParser()
    analyzer = SupplyChainAnalyzer()
    path = Path(args.path)

    try:
        if path.is_file():
            dep_file = parser.parse_file(str(path))
            dependencies = dep_file.dependencies if dep_file else []
        else:
            dep_files = parser.parse_directory(str(path), recursive=True)
            dependencies = []
            for df in dep_files:
                dependencies.extend(df.dependencies)

        # Analyze risks
        risk_report = analyzer.analyze(dependencies)

        # Filter by severity
        level_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "info": RiskLevel.INFO,
        }
        min_level = level_map[args.min_severity]

        filtered_risks = []
        for dep_risk in risk_report.dependency_risks:
            for risk in dep_risk.risks:
                risk_idx = severity_order.index(risk.level.value.lower())
                if risk_idx <= min_severity_idx:
                    filtered_risks.append((dep_risk.dependency.name, risk))

        if args.json:
            output = {
                "total_dependencies": len(dependencies),
                "overall_risk": risk_report.overall_risk.value,
                "risk_score": risk_report.risk_score,
                "summary": {
                    "critical": risk_report.critical_count,
                    "high": risk_report.high_count,
                    "medium": risk_report.medium_count,
                    "low": risk_report.low_count,
                },
                "risks": [
                    {
                        "package": pkg,
                        "type": risk.risk_type,
                        "level": risk.level.value,
                        "description": risk.description,
                    }
                    for pkg, risk in filtered_risks
                ],
            }
            print(json.dumps(output, indent=2))
        else:
            print("Supply Chain Risk Analysis")
            print("=" * 50)
            print(f"Dependencies analyzed: {len(dependencies)}")
            print(f"Overall Risk Level: {risk_report.overall_risk.value.upper()}")
            print(f"Risk Score: {risk_report.risk_score:.1f}/100")
            print()
            print("Risk Summary:")
            print(f"  Critical: {risk_report.critical_count}")
            print(f"  High:     {risk_report.high_count}")
            print(f"  Medium:   {risk_report.medium_count}")
            print(f"  Low:      {risk_report.low_count}")

            if filtered_risks:
                print()
                print(f"Risks (>= {args.min_severity}):")
                for pkg, risk in filtered_risks:
                    print(f"  [{risk.level.value.upper()}] {pkg}: {risk.description}")

            if risk_report.critical_count > 0 or risk_report.high_count > 0:
                print()
                print("WARNING: High-severity supply chain risks detected!")
                return 1

        return 0

    except Exception as e:
        print(f"Error analyzing risks: {e}")
        return 1


def _handle_validate(args: argparse.Namespace) -> int:
    """Handle validate command."""
    path = Path(args.file)

    if not path.exists():
        print(f"Error: File not found: {args.file}")
        return 1

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        errors = []
        warnings = []
        sbom_format = args.format

        # Auto-detect format
        if sbom_format == "auto":
            if path.suffix == ".xml":
                sbom_format = "cyclonedx-xml"
            elif content.strip().startswith("{"):
                try:
                    data = json.loads(content)
                    if "bomFormat" in data:
                        sbom_format = "cyclonedx-json"
                    elif "spdxVersion" in data:
                        sbom_format = "spdx-json"
                    else:
                        sbom_format = "unknown"
                except json.JSONDecodeError:
                    errors.append("Invalid JSON content")
            elif content.strip().startswith("SPDXVersion:"):
                sbom_format = "spdx-tag"
            else:
                sbom_format = "unknown"

        # Validate based on format
        if sbom_format == "cyclonedx-json":
            data = json.loads(content)
            if "bomFormat" not in data:
                errors.append("Missing 'bomFormat' field")
            elif data["bomFormat"] != "CycloneDX":
                errors.append(f"Invalid bomFormat: {data['bomFormat']}")
            if "specVersion" not in data:
                warnings.append("Missing 'specVersion' field")
            if "components" not in data:
                warnings.append("No components in SBOM")
            elif not isinstance(data["components"], list):
                errors.append("'components' must be an array")

        elif sbom_format == "spdx-json":
            data = json.loads(content)
            if "spdxVersion" not in data:
                errors.append("Missing 'spdxVersion' field")
            if "SPDXID" not in data:
                errors.append("Missing 'SPDXID' field")
            if "packages" not in data:
                warnings.append("No packages in SBOM")

        elif sbom_format == "spdx-tag":
            if "SPDXVersion:" not in content:
                errors.append("Missing SPDXVersion tag")
            if "SPDXID:" not in content:
                errors.append("Missing SPDXID tag")

        elif sbom_format == "unknown":
            errors.append("Could not determine SBOM format")

        is_valid = len(errors) == 0

        if args.json:
            output = {
                "valid": is_valid,
                "format": sbom_format,
                "errors": errors,
                "warnings": warnings,
            }
            print(json.dumps(output, indent=2))
        else:
            if is_valid:
                print(f"VALID: {path}")
                print(f"Format: {sbom_format}")
                if warnings:
                    print("\nWarnings:")
                    for w in warnings:
                        print(f"  - {w}")
            else:
                print(f"INVALID: {path}")
                print(f"Format: {sbom_format}")
                print("\nErrors:")
                for e in errors:
                    print(f"  - {e}")
                if warnings:
                    print("\nWarnings:")
                    for w in warnings:
                        print(f"  - {w}")

        return 0 if is_valid else 1

    except Exception as e:
        if args.json:
            print(json.dumps({"valid": False, "error": str(e)}))
        else:
            print(f"Error validating SBOM: {e}")
        return 1


def _handle_formats(args: argparse.Namespace) -> int:
    """Handle formats command."""
    formats = [
        {
            "name": "CycloneDX JSON",
            "id": "cyclonedx-json",
            "spec_version": "1.5",
            "description": "OWASP CycloneDX JSON format",
            "file_extensions": [".json"],
            "standards": ["OWASP", "NTIA"],
        },
        {
            "name": "CycloneDX XML",
            "id": "cyclonedx-xml",
            "spec_version": "1.5",
            "description": "OWASP CycloneDX XML format",
            "file_extensions": [".xml"],
            "standards": ["OWASP", "NTIA"],
        },
        {
            "name": "SPDX JSON",
            "id": "spdx-json",
            "spec_version": "2.3",
            "description": "Linux Foundation SPDX JSON format",
            "file_extensions": [".json", ".spdx.json"],
            "standards": ["Linux Foundation", "ISO/IEC 5962:2021"],
        },
        {
            "name": "SPDX Tag-Value",
            "id": "spdx-tag",
            "spec_version": "2.3",
            "description": "Linux Foundation SPDX tag-value format",
            "file_extensions": [".spdx", ".spdx.tv"],
            "standards": ["Linux Foundation", "ISO/IEC 5962:2021"],
        },
        {
            "name": "Stance Native",
            "id": "stance",
            "spec_version": "1.0",
            "description": "Mantissa Stance native SBOM format",
            "file_extensions": [".json", ".stance.json"],
            "standards": ["Proprietary"],
        },
    ]

    if args.json:
        print(json.dumps({"formats": formats, "total": len(formats)}, indent=2))
    else:
        print("Supported SBOM Formats")
        print("=" * 50)
        print()
        for fmt in formats:
            print(f"{fmt['name']} ({fmt['id']}):")
            print(f"  Spec Version: {fmt['spec_version']}")
            print(f"  Description: {fmt['description']}")
            print(f"  Extensions: {', '.join(fmt['file_extensions'])}")
            print(f"  Standards: {', '.join(fmt['standards'])}")
            print()
        print(f"Total: {len(formats)} format(s)")

    return 0


def _handle_ecosystems(args: argparse.Namespace) -> int:
    """Handle ecosystems command."""
    ecosystems = [
        {
            "name": "NPM",
            "id": "npm",
            "language": "JavaScript/TypeScript",
            "files": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
            "registry": "https://registry.npmjs.org",
        },
        {
            "name": "PyPI",
            "id": "pypi",
            "language": "Python",
            "files": ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock", "setup.py"],
            "registry": "https://pypi.org",
        },
        {
            "name": "Go Modules",
            "id": "go",
            "language": "Go",
            "files": ["go.mod", "go.sum"],
            "registry": "https://proxy.golang.org",
        },
        {
            "name": "Cargo",
            "id": "cargo",
            "language": "Rust",
            "files": ["Cargo.toml", "Cargo.lock"],
            "registry": "https://crates.io",
        },
        {
            "name": "RubyGems",
            "id": "rubygems",
            "language": "Ruby",
            "files": ["Gemfile", "Gemfile.lock", "*.gemspec"],
            "registry": "https://rubygems.org",
        },
        {
            "name": "Composer",
            "id": "composer",
            "language": "PHP",
            "files": ["composer.json", "composer.lock"],
            "registry": "https://packagist.org",
        },
        {
            "name": "Maven",
            "id": "maven",
            "language": "Java",
            "files": ["pom.xml"],
            "registry": "https://repo.maven.apache.org",
        },
        {
            "name": "NuGet",
            "id": "nuget",
            "language": "C#/.NET",
            "files": ["*.csproj", "packages.config", "paket.dependencies"],
            "registry": "https://www.nuget.org",
        },
    ]

    if args.json:
        print(json.dumps({"ecosystems": ecosystems, "total": len(ecosystems)}, indent=2))
    else:
        print("Supported Package Ecosystems")
        print("=" * 50)
        print()
        for eco in ecosystems:
            print(f"{eco['name']} ({eco['id']}):")
            print(f"  Language: {eco['language']}")
            print(f"  Files: {', '.join(eco['files'])}")
            print(f"  Registry: {eco['registry']}")
            print()
        print(f"Total: {len(ecosystems)} ecosystem(s)")

    return 0


def _handle_licenses(args: argparse.Namespace) -> int:
    """Handle licenses command."""
    from stance.sbom import LicenseAnalyzer

    analyzer = LicenseAnalyzer()
    licenses = []

    for spdx_id, lic in analyzer.license_db.items():
        lic_info = {
            "spdx_id": spdx_id,
            "name": lic.name,
            "category": lic.category.value,
            "risk": lic.risk.value,
            "osi_approved": lic.osi_approved,
            "copyleft": lic.copyleft,
            "patent_grant": lic.patent_grant,
        }

        if args.category == "all" or lic.category.value == args.category:
            licenses.append(lic_info)

    # Sort by category then name
    licenses.sort(key=lambda x: (x["category"], x["spdx_id"]))

    if args.json:
        print(json.dumps({"licenses": licenses, "total": len(licenses)}, indent=2))
    else:
        print("Known Software Licenses")
        print("=" * 50)
        print()

        current_category = None
        for lic in licenses:
            if lic["category"] != current_category:
                current_category = lic["category"]
                print(f"\n{current_category.upper()}:")
                print("-" * 40)

            osi = "OSI" if lic["osi_approved"] else "   "
            copyleft = "copyleft" if lic["copyleft"] else "        "
            patent = "patent" if lic["patent_grant"] else "      "
            print(f"  {lic['spdx_id']:<15} [{lic['risk']:<8}] {osi} {copyleft} {patent}")

        print()
        print(f"Total: {len(licenses)} license(s)")
        print()
        print("Legend: OSI=OSI Approved, copyleft=Has copyleft clause, patent=Patent grant")

    return 0


def _handle_info(args: argparse.Namespace) -> int:
    """Handle info command."""
    info = {
        "module": "stance.sbom",
        "description": "Software Bill of Materials for supply chain security",
        "capabilities": [
            "Dependency file parsing (npm, pip, go, cargo, ruby, php)",
            "SBOM generation (CycloneDX, SPDX, Stance native)",
            "License identification and risk assessment",
            "License compatibility checking",
            "Supply chain risk analysis",
            "Typosquatting detection",
            "Deprecated package detection",
            "Vulnerability integration",
        ],
        "components": {
            "DependencyParser": "Parses dependency files from multiple ecosystems",
            "SBOMGenerator": "Generates SBOM in various formats",
            "LicenseAnalyzer": "Analyzes and validates software licenses",
            "SupplyChainAnalyzer": "Comprehensive supply chain risk assessment",
        },
        "supported_formats": [
            "CycloneDX JSON (1.5)",
            "CycloneDX XML (1.5)",
            "SPDX JSON (2.3)",
            "SPDX Tag-Value (2.3)",
            "Stance Native (1.0)",
        ],
        "supported_ecosystems": [
            "NPM (JavaScript/TypeScript)",
            "PyPI (Python)",
            "Go Modules",
            "Cargo (Rust)",
            "RubyGems (Ruby)",
            "Composer (PHP)",
        ],
    }

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print("SBOM Module Information")
        print("=" * 50)
        print()
        print(f"Module: {info['module']}")
        print(f"Description: {info['description']}")
        print()
        print("Capabilities:")
        for cap in info["capabilities"]:
            print(f"  - {cap}")
        print()
        print("Components:")
        for name, desc in info["components"].items():
            print(f"  {name}: {desc}")
        print()
        print("Supported SBOM Formats:")
        for fmt in info["supported_formats"]:
            print(f"  - {fmt}")
        print()
        print("Supported Ecosystems:")
        for eco in info["supported_ecosystems"]:
            print(f"  - {eco}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    try:
        from stance.sbom import (
            DependencyParser,
            SBOMGenerator,
            LicenseAnalyzer,
            SupplyChainAnalyzer,
            Dependency,
            SBOM,
            License,
            SupplyChainRisk,
        )

        components_available = {
            "DependencyParser": DependencyParser is not None,
            "SBOMGenerator": SBOMGenerator is not None,
            "LicenseAnalyzer": LicenseAnalyzer is not None,
            "SupplyChainAnalyzer": SupplyChainAnalyzer is not None,
        }

        dataclasses_available = {
            "Dependency": Dependency is not None,
            "SBOM": SBOM is not None,
            "License": License is not None,
            "SupplyChainRisk": SupplyChainRisk is not None,
        }

        all_ok = all(components_available.values()) and all(dataclasses_available.values())

    except ImportError as e:
        if args.json:
            print(json.dumps({"status": "error", "error": str(e)}))
        else:
            print(f"Error loading SBOM module: {e}")
        return 1

    status = {
        "status": "ok" if all_ok else "degraded",
        "module": "sbom",
        "components": components_available,
        "dataclasses": dataclasses_available,
        "capabilities": [
            "dependency_parsing",
            "sbom_generation",
            "license_analysis",
            "supply_chain_risk",
        ],
    }

    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print("SBOM Module Status")
        print("=" * 50)
        print()
        print(f"Status: {status['status'].upper()}")
        print(f"Module: {status['module']}")
        print()
        print("Components:")
        for name, available in status["components"].items():
            status_str = "Available" if available else "Not Available"
            print(f"  {name}: {status_str}")
        print()
        print("Data Classes:")
        for name, available in status["dataclasses"].items():
            status_str = "Available" if available else "Not Available"
            print(f"  {name}: {status_str}")
        print()
        print("Capabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")

    return 0


def _handle_diff(args: argparse.Namespace) -> int:
    """Handle diff command."""
    path1 = Path(args.sbom1)
    path2 = Path(args.sbom2)

    if not path1.exists():
        print(f"Error: File not found: {args.sbom1}")
        return 1
    if not path2.exists():
        print(f"Error: File not found: {args.sbom2}")
        return 1

    try:
        with open(path1, "r", encoding="utf-8") as f:
            sbom1 = json.load(f)
        with open(path2, "r", encoding="utf-8") as f:
            sbom2 = json.load(f)

        # Extract components
        def get_components(sbom: dict) -> dict:
            components = {}
            # CycloneDX
            if "components" in sbom:
                for c in sbom["components"]:
                    name = c.get("name", "")
                    version = c.get("version", "")
                    components[name] = version
            # SPDX
            elif "packages" in sbom:
                for p in sbom["packages"]:
                    name = p.get("name", "")
                    version = p.get("versionInfo", "")
                    components[name] = version
            return components

        comp1 = get_components(sbom1)
        comp2 = get_components(sbom2)

        added = set(comp2.keys()) - set(comp1.keys())
        removed = set(comp1.keys()) - set(comp2.keys())
        common = set(comp1.keys()) & set(comp2.keys())

        changed = []
        for name in common:
            if comp1[name] != comp2[name]:
                changed.append({
                    "name": name,
                    "old_version": comp1[name],
                    "new_version": comp2[name],
                })

        if args.json:
            output = {
                "sbom1": str(path1),
                "sbom2": str(path2),
                "added": [{"name": n, "version": comp2[n]} for n in sorted(added)],
                "removed": [{"name": n, "version": comp1[n]} for n in sorted(removed)],
                "changed": sorted(changed, key=lambda x: x["name"]),
                "summary": {
                    "added": len(added),
                    "removed": len(removed),
                    "changed": len(changed),
                    "unchanged": len(common) - len(changed),
                },
            }
            print(json.dumps(output, indent=2))
        else:
            print("SBOM Comparison")
            print("=" * 50)
            print(f"File 1: {path1}")
            print(f"File 2: {path2}")
            print()

            if added:
                print(f"Added ({len(added)}):")
                for name in sorted(added):
                    print(f"  + {name}@{comp2[name]}")
                print()

            if removed:
                print(f"Removed ({len(removed)}):")
                for name in sorted(removed):
                    print(f"  - {name}@{comp1[name]}")
                print()

            if changed:
                print(f"Changed ({len(changed)}):")
                for c in sorted(changed, key=lambda x: x["name"]):
                    print(f"  ~ {c['name']}: {c['old_version']} -> {c['new_version']}")
                print()

            print("Summary:")
            print(f"  Added: {len(added)}")
            print(f"  Removed: {len(removed)}")
            print(f"  Changed: {len(changed)}")
            print(f"  Unchanged: {len(common) - len(changed)}")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error comparing SBOMs: {e}")
        return 1


def _handle_convert(args: argparse.Namespace) -> int:
    """Handle convert command."""
    from stance.sbom import SBOMGenerator, SBOMFormat, DependencyParser

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Error: Input file not found: {args.input}")
        return 1

    format_map = {
        "cyclonedx-json": SBOMFormat.CYCLONEDX_JSON,
        "cyclonedx-xml": SBOMFormat.CYCLONEDX_XML,
        "spdx-json": SBOMFormat.SPDX_JSON,
        "spdx-tag": SBOMFormat.SPDX_TAG_VALUE,
        "stance": SBOMFormat.STANCE,
    }

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Parse input SBOM
        input_format = args.from_format
        if input_format == "auto":
            if input_path.suffix == ".xml":
                input_format = "cyclonedx-xml"
            elif content.strip().startswith("{"):
                data = json.loads(content)
                if "bomFormat" in data:
                    input_format = "cyclonedx-json"
                elif "spdxVersion" in data:
                    input_format = "spdx-json"
            elif content.strip().startswith("SPDXVersion:"):
                input_format = "spdx-tag"

        if input_format == "auto":
            print("Error: Could not auto-detect input format. Please specify --from-format.")
            return 1

        # Extract components from input
        components = []
        if input_format in ("cyclonedx-json", "spdx-json"):
            data = json.loads(content)
            if input_format == "cyclonedx-json":
                for c in data.get("components", []):
                    components.append({
                        "name": c.get("name", ""),
                        "version": c.get("version", ""),
                        "type": c.get("type", "library"),
                        "purl": c.get("purl", ""),
                        "licenses": c.get("licenses", []),
                    })
            elif input_format == "spdx-json":
                for p in data.get("packages", []):
                    components.append({
                        "name": p.get("name", ""),
                        "version": p.get("versionInfo", ""),
                        "type": "library",
                        "purl": "",
                        "licenses": [],
                    })

        # Generate output SBOM
        generator = SBOMGenerator()
        from stance.sbom import SBOMComponent, SBOM
        import uuid
        from datetime import datetime

        sbom_components = []
        for c in components:
            sbom_components.append(SBOMComponent(
                name=c["name"],
                version=c["version"],
                component_type=c["type"],
                purl=c["purl"] or None,
            ))

        sbom = SBOM(
            format=format_map[args.to_format],
            serial_number=str(uuid.uuid4()),
            version=1,
            created=datetime.utcnow(),
            components=sbom_components,
        )

        output = generator.export(sbom, format_map[args.to_format])

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(output)

        print(f"Converted {input_path} to {output_path}")
        print(f"Input format: {input_format}")
        print(f"Output format: {args.to_format}")
        print(f"Components: {len(components)}")

        return 0

    except Exception as e:
        print(f"Error converting SBOM: {e}")
        return 1


def _handle_vuln(args: argparse.Namespace) -> int:
    """Handle vuln command - scan for vulnerabilities."""
    from stance.sbom import (
        DependencyParser,
        VulnerabilityScanner,
        VulnerabilityDatabase,
        VulnerabilitySource,
        VulnerabilitySeverity,
    )

    # Parse sources
    source_map = {
        "osv": VulnerabilitySource.OSV,
        "nvd": VulnerabilitySource.NVD,
        "local": VulnerabilitySource.LOCAL,
    }
    sources = [source_map[s] for s in args.sources]

    # Severity ordering for filtering
    severity_order = ["critical", "high", "medium", "low", "none"]
    min_severity_idx = severity_order.index(args.min_severity)

    parser = DependencyParser()
    db = VulnerabilityDatabase(offline_mode=args.offline)
    scanner = VulnerabilityScanner(database=db, sources=sources)
    path = Path(args.path)

    try:
        if path.is_file():
            result = scanner.scan_file(str(path))
        else:
            result = scanner.scan_directory(str(path), recursive=args.recursive)

        # Filter by severity
        filtered_matches = []
        for match in result.matches:
            severity_idx = severity_order.index(match.severity.value)
            if severity_idx <= min_severity_idx:
                filtered_matches.append(match)

        if args.json:
            output = {
                "summary": {
                    "total_dependencies": result.total_dependencies,
                    "vulnerable_dependencies": result.vulnerable_dependencies,
                    "total_vulnerabilities": result.total_vulnerabilities,
                    "highest_severity": result.highest_severity.value,
                },
                "severity_breakdown": {
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                    "low": result.low_count,
                },
                "vulnerabilities": [
                    {
                        "id": m.vulnerability.id,
                        "package": m.dependency.name,
                        "version": m.dependency.version,
                        "ecosystem": m.dependency.ecosystem.value,
                        "severity": m.severity.value,
                        "cvss_score": m.vulnerability.cvss_score,
                        "summary": m.vulnerability.summary,
                        "fixed_versions": m.vulnerability.fixed_versions,
                        "references": [r.url for r in m.vulnerability.references[:3]],
                    }
                    for m in filtered_matches
                ],
                "metadata": {
                    "scan_duration_ms": result.scan_duration_ms,
                    "sources": [s.value for s in sources],
                    "path": str(path),
                },
            }
            print(json.dumps(output, indent=2))
        else:
            print("Vulnerability Scan Results")
            print("=" * 50)
            print(f"Path: {path}")
            print(f"Sources: {', '.join(args.sources)}")
            print()
            print(f"Dependencies Scanned: {result.total_dependencies}")
            print(f"Vulnerable Dependencies: {result.vulnerable_dependencies}")
            print(f"Total Vulnerabilities: {result.total_vulnerabilities}")
            print()
            print("Severity Breakdown:")
            print(f"  Critical: {result.critical_count}")
            print(f"  High:     {result.high_count}")
            print(f"  Medium:   {result.medium_count}")
            print(f"  Low:      {result.low_count}")

            if filtered_matches:
                print()
                print(f"Vulnerabilities (>= {args.min_severity}):")
                for match in filtered_matches:
                    vuln = match.vulnerability
                    dep = match.dependency
                    severity = vuln.severity.value.upper()
                    print(f"\n  [{severity}] {vuln.id}")
                    print(f"    Package: {dep.name}@{dep.version}")
                    if vuln.cvss_score:
                        print(f"    CVSS: {vuln.cvss_score}")
                    if vuln.summary:
                        summary = vuln.summary[:80] + "..." if len(vuln.summary) > 80 else vuln.summary
                        print(f"    Summary: {summary}")
                    if vuln.fixed_versions:
                        print(f"    Fixed in: {', '.join(vuln.fixed_versions[:3])}")

            print()
            print(f"Scan Duration: {result.scan_duration_ms}ms")

        # Check fail-on threshold
        if args.fail_on:
            fail_idx = severity_order.index(args.fail_on)
            for sev, count in [
                ("critical", result.critical_count),
                ("high", result.high_count),
                ("medium", result.medium_count),
                ("low", result.low_count),
            ]:
                if severity_order.index(sev) <= fail_idx and count > 0:
                    if not args.json:
                        print()
                        print(f"FAILED: Found {count} {sev} vulnerability(ies)")
                    return 1

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error scanning for vulnerabilities: {e}")
        return 1


def _handle_cve(args: argparse.Namespace) -> int:
    """Handle cve command - look up CVEs for a package."""
    from stance.sbom import (
        VulnerabilityDatabase,
        VulnerabilitySource,
        PackageEcosystem,
    )

    # Parse ecosystem
    ecosystem_map = {
        "npm": PackageEcosystem.NPM,
        "pypi": PackageEcosystem.PYPI,
        "go": PackageEcosystem.GO,
        "cargo": PackageEcosystem.CARGO,
        "maven": PackageEcosystem.MAVEN,
        "nuget": PackageEcosystem.NUGET,
        "rubygems": PackageEcosystem.RUBYGEMS,
        "composer": PackageEcosystem.COMPOSER,
    }
    ecosystem = ecosystem_map[args.ecosystem]

    # Parse sources
    source_map = {
        "osv": VulnerabilitySource.OSV,
        "nvd": VulnerabilitySource.NVD,
        "local": VulnerabilitySource.LOCAL,
    }
    sources = [source_map[s] for s in args.sources]

    db = VulnerabilityDatabase()

    try:
        vulns = db.lookup(
            package=args.package,
            version=args.version if args.version != "*" else "0.0.0",
            ecosystem=ecosystem,
            sources=sources,
        )

        if args.json:
            output = {
                "package": args.package,
                "version": args.version,
                "ecosystem": args.ecosystem,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "aliases": v.aliases,
                        "severity": v.severity.value,
                        "cvss_score": v.cvss_score,
                        "summary": v.summary,
                        "description": v.description[:500] if v.description else None,
                        "fixed_versions": v.fixed_versions,
                        "published": v.published.isoformat() if v.published else None,
                        "cwes": v.cwes,
                        "references": [r.url for r in v.references[:5]],
                    }
                    for v in vulns
                ],
                "total": len(vulns),
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"CVE Lookup: {args.package}")
            print("=" * 50)
            print(f"Version: {args.version}")
            print(f"Ecosystem: {args.ecosystem}")
            print(f"Sources: {', '.join(args.sources)}")
            print()

            if not vulns:
                print("No vulnerabilities found.")
            else:
                print(f"Found {len(vulns)} vulnerability(ies):")
                for vuln in vulns:
                    print()
                    print(f"  {vuln.id}")
                    print(f"    Severity: {vuln.severity.value.upper()}")
                    if vuln.cvss_score:
                        print(f"    CVSS: {vuln.cvss_score}")
                    if vuln.aliases:
                        print(f"    Aliases: {', '.join(vuln.aliases[:3])}")
                    if vuln.summary:
                        summary = vuln.summary[:100] + "..." if len(vuln.summary) > 100 else vuln.summary
                        print(f"    Summary: {summary}")
                    if vuln.fixed_versions:
                        print(f"    Fixed: {', '.join(vuln.fixed_versions[:3])}")
                    if vuln.cwes:
                        print(f"    CWEs: {', '.join(vuln.cwes[:3])}")
                    if vuln.references:
                        print(f"    Reference: {vuln.references[0].url}")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error looking up CVEs: {e}")
        return 1


def _handle_vulndb(args: argparse.Namespace) -> int:
    """Handle vulndb command - manage vulnerability database."""
    from stance.sbom import VulnerabilityDatabase
    import shutil

    db = VulnerabilityDatabase()
    cache_dir = db._cache_dir

    try:
        if args.action == "status":
            # Count cached vulnerabilities
            cache_files = list(cache_dir.glob("*.json")) if cache_dir.exists() else []

            status = {
                "cache_dir": str(cache_dir),
                "cache_exists": cache_dir.exists(),
                "cached_vulnerabilities": len(cache_files),
                "cache_size_bytes": sum(f.stat().st_size for f in cache_files) if cache_files else 0,
            }

            if args.json:
                print(json.dumps(status, indent=2))
            else:
                print("Vulnerability Database Status")
                print("=" * 50)
                print(f"Cache Directory: {status['cache_dir']}")
                print(f"Cache Exists: {status['cache_exists']}")
                print(f"Cached Vulnerabilities: {status['cached_vulnerabilities']}")
                size_kb = status['cache_size_bytes'] / 1024
                print(f"Cache Size: {size_kb:.1f} KB")

        elif args.action == "clear":
            if cache_dir.exists():
                shutil.rmtree(cache_dir)
                cache_dir.mkdir(parents=True, exist_ok=True)
                if args.json:
                    print(json.dumps({"status": "cleared", "cache_dir": str(cache_dir)}))
                else:
                    print(f"Cleared vulnerability cache at {cache_dir}")
            else:
                if args.json:
                    print(json.dumps({"status": "empty", "message": "Cache was already empty"}))
                else:
                    print("Cache was already empty")

        elif args.action == "import":
            if not args.file:
                if args.json:
                    print(json.dumps({"error": "No file specified for import"}))
                else:
                    print("Error: --file is required for import action")
                return 1

            import_path = Path(args.file)
            if not import_path.exists():
                if args.json:
                    print(json.dumps({"error": f"File not found: {args.file}"}))
                else:
                    print(f"Error: File not found: {args.file}")
                return 1

            count = db.load_local_database(import_path)

            if args.json:
                print(json.dumps({
                    "status": "imported",
                    "file": str(import_path),
                    "vulnerabilities_loaded": count,
                }))
            else:
                print(f"Imported {count} vulnerabilities from {import_path}")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error managing vulnerability database: {e}")
        return 1


def _handle_graph(args: argparse.Namespace) -> int:
    """Handle graph command."""
    from stance.sbom import DependencyParser, DependencyGraphBuilder

    parser = DependencyParser()
    path = Path(args.path)

    try:
        # Parse dependencies
        if path.is_file():
            dep_file = parser.parse_file(str(path))
            if not dep_file:
                print(f"Error: Could not parse {path}")
                return 1
            dep_files = [dep_file]
        else:
            dep_files = parser.parse_directory(str(path), recursive=True)

        if not dep_files:
            print(f"Error: No dependency files found in {path}")
            return 1

        # Build graph
        builder = DependencyGraphBuilder()

        if len(dep_files) == 1:
            graph = builder.build_from_file(dep_files[0])
        else:
            graph = builder.build_from_files(dep_files)

        # Handle special output modes
        if args.cycles:
            cycles = graph.detect_cycles()
            if args.format == "json" or hasattr(args, "json") and args.json:
                print(json.dumps({
                    "cycles_detected": len(cycles) > 0,
                    "cycle_count": len(cycles),
                    "cycles": [c.to_dict() for c in cycles],
                }))
            else:
                if cycles:
                    print(f"Detected {len(cycles)} dependency cycle(s):\n")
                    for i, cycle in enumerate(cycles, 1):
                        print(f"  Cycle {i}: {' -> '.join(cycle.nodes + [cycle.nodes[0]])}")
                else:
                    print("No dependency cycles detected.")
            return 0

        if args.metrics:
            metrics = graph.compute_metrics()
            if args.format == "json":
                print(json.dumps(metrics.to_dict(), indent=2))
            else:
                print("Dependency Graph Metrics")
                print("=" * 50)
                print(f"Total nodes:      {metrics.total_nodes}")
                print(f"Direct deps:      {metrics.direct_dependencies}")
                print(f"Transitive deps:  {metrics.transitive_dependencies}")
                print(f"Total edges:      {metrics.total_edges}")
                print(f"Max depth:        {metrics.max_depth}")
                print(f"Average depth:    {metrics.avg_depth:.2f}")
                print(f"Has cycles:       {metrics.has_cycles}")
                if metrics.hub_nodes:
                    print(f"Hub nodes:        {', '.join(metrics.hub_nodes[:5])}")
                print(f"Unique licenses:  {metrics.unique_licenses}")
                print(f"Ecosystems:       {', '.join(metrics.ecosystems)}")
            return 0

        # Generate visualization
        if args.format == "tree":
            output = graph.to_tree_string(max_depth=args.max_depth)
        elif args.format == "dot":
            output = graph.to_dot()
        elif args.format == "mermaid":
            output = graph.to_mermaid()
        elif args.format == "json":
            output = graph.to_json()
        else:
            output = graph.to_tree_string()

        # Output
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Graph written to {args.output}")
            print(f"Format: {args.format}")
            print(f"Nodes: {len(graph.nodes)}")
        else:
            print(output)

        return 0

    except Exception as e:
        print(f"Error generating dependency graph: {e}")
        return 1


def _handle_attest(args: argparse.Namespace) -> int:
    """Handle attest command."""
    from stance.sbom.attestation import (
        AttestationBuilder,
        AttestationSigner,
        AttestationVerifier,
        SignatureAlgorithm,
    )

    action = args.action

    # Get secret key from args or environment
    secret_key = args.key or os.environ.get("STANCE_ATTEST_KEY")

    try:
        if action == "create":
            if not args.sbom_file:
                print("Error: SBOM file path required for create action")
                return 1

            sbom_path = Path(args.sbom_file)
            if not sbom_path.exists():
                print(f"Error: SBOM file not found: {sbom_path}")
                return 1

            # Load SBOM
            sbom_content = sbom_path.read_text(encoding="utf-8")
            try:
                sbom_data = json.loads(sbom_content)
            except json.JSONDecodeError:
                print("Error: SBOM file must be valid JSON")
                return 1

            # Build attestation
            builder = AttestationBuilder()
            builder.add_subject(sbom_path.name, sbom_content, "application/json")
            builder.set_sbom_predicate(sbom_data)
            builder.set_signer(
                signer_id=f"signer:{args.signer.lower().replace(' ', '-')}",
                name=args.signer,
            )
            builder.set_expiry(args.expiry_days)

            attestation = builder.build()

            # Sign if key provided
            if secret_key:
                signer = AttestationSigner(secret_key)
                attestation = signer.sign(attestation)
                signed_status = "signed"
            else:
                signed_status = "unsigned (no key provided)"

            # Output
            if args.json:
                output = json.dumps(attestation.to_dict(), indent=2)
            else:
                output = json.dumps(attestation.to_envelope(), indent=2)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"Attestation created: {args.output}")
                print(f"Status: {signed_status}")
                print(f"Expires: {attestation.expires_at.isoformat() if attestation.expires_at else 'never'}")
            else:
                print(output)

            return 0

        elif action == "verify":
            attestation_file = args.attestation or args.sbom_file
            if not attestation_file:
                print("Error: Attestation file required for verify action")
                return 1

            if not secret_key:
                print("Error: Secret key required for verification (--key or STANCE_ATTEST_KEY)")
                return 1

            att_path = Path(attestation_file)
            if not att_path.exists():
                print(f"Error: Attestation file not found: {att_path}")
                return 1

            # Load attestation
            att_content = att_path.read_text(encoding="utf-8")
            att_data = json.loads(att_content)

            # Reconstruct attestation from stored data
            from stance.sbom.attestation import (
                Attestation,
                Signature,
                AttestationType,
            )

            attestation = Attestation(
                id=att_data.get("id", ""),
                type=AttestationType.IN_TOTO,
            )

            if "signature" in att_data and att_data["signature"]:
                sig_data = att_data["signature"]
                attestation.signature = Signature(
                    algorithm=SignatureAlgorithm(sig_data.get("algorithm", "hmac-sha256")),
                    value=sig_data.get("value", ""),
                    key_id=sig_data.get("key_id"),
                )

            # Verify
            verifier = AttestationVerifier(secret_key)
            result = verifier.verify(attestation)

            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                if result.is_valid:
                    print("✓ Attestation verified successfully")
                else:
                    print(f"✗ Verification failed: {result.message}")
                print(f"Status: {result.status.value}")

            return 0 if result.is_valid else 1

        elif action == "show":
            if not args.sbom_file:
                print("Error: Attestation file required for show action")
                return 1

            att_path = Path(args.sbom_file)
            if not att_path.exists():
                print(f"Error: File not found: {att_path}")
                return 1

            att_content = att_path.read_text(encoding="utf-8")
            att_data = json.loads(att_content)

            if args.json:
                print(json.dumps(att_data, indent=2))
            else:
                print("Attestation Details")
                print("=" * 50)
                print(f"ID: {att_data.get('id', 'N/A')}")
                print(f"Type: {att_data.get('type', 'N/A')}")
                print(f"Signed: {att_data.get('is_signed', False)}")
                if att_data.get("signer"):
                    print(f"Signer: {att_data['signer'].get('name', 'N/A')}")
                print(f"Created: {att_data.get('created_at', 'N/A')}")
                print(f"Expires: {att_data.get('expires_at', 'never')}")
                if att_data.get("subjects"):
                    print(f"Subjects: {len(att_data['subjects'])}")

            return 0

    except Exception as e:
        if hasattr(args, "json") and args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1

    return 0


def _handle_vex(args: argparse.Namespace) -> int:
    """Handle vex command."""
    from stance.sbom.vex import (
        VEXDocument,
        VEXGenerator,
        VEXParser,
        VEXStatus,
    )

    action = args.action

    try:
        if action == "create":
            # Create VEX document from vulnerability scan or SBOM
            generator = VEXGenerator(author=args.author)
            doc = VEXDocument(author=args.author)

            if args.vuln_file:
                # Load vulnerability scan results
                vuln_path = Path(args.vuln_file)
                if not vuln_path.exists():
                    print(f"Error: Vulnerability file not found: {vuln_path}")
                    return 1

                vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))

                # Create VEX statements from vulnerability matches
                from stance.sbom.vex import VEXVulnerability, VEXProduct, VEXStatement

                for match in vuln_data.get("matches", []):
                    vuln = VEXVulnerability(
                        id=match.get("vulnerability_id", match.get("id", "unknown")),
                        description=match.get("description"),
                    )

                    product = VEXProduct(
                        name=match.get("dependency_name", match.get("package", "unknown")),
                        version=match.get("dependency_version", match.get("version")),
                    )

                    statement = VEXStatement(
                        vulnerability=vuln,
                        products=[product],
                        status=VEXStatus.UNDER_INVESTIGATION,
                    )
                    doc.add_statement(statement)

            # Output
            output = doc.to_json(format=args.format)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"VEX document created: {args.output}")
                print(f"Format: {args.format}")
                print(f"Statements: {len(doc.statements)}")
            else:
                print(output)

            return 0

        elif action == "parse":
            if not args.file:
                print("Error: VEX file required for parse action")
                return 1

            vex_path = Path(args.file)
            if not vex_path.exists():
                print(f"Error: VEX file not found: {vex_path}")
                return 1

            vex_content = vex_path.read_text(encoding="utf-8")
            parser = VEXParser()
            doc = parser.parse_json(vex_content, format=args.format)

            if args.json:
                print(json.dumps(doc.to_dict(), indent=2))
            else:
                print("VEX Document")
                print("=" * 50)
                print(f"ID: {doc.id}")
                print(f"Author: {doc.author}")
                print(f"Statements: {len(doc.statements)}")
                print(f"\nSummary:")
                for status, count in doc.summary.items():
                    if count > 0:
                        print(f"  {status}: {count}")

            return 0

        elif action == "show":
            if not args.file:
                print("Error: VEX file required for show action")
                return 1

            vex_path = Path(args.file)
            if not vex_path.exists():
                print(f"Error: VEX file not found: {vex_path}")
                return 1

            vex_content = vex_path.read_text(encoding="utf-8")
            parser = VEXParser()
            doc = parser.parse_json(vex_content, format=args.format)

            if args.json:
                print(json.dumps(doc.to_dict(), indent=2))
            else:
                print("VEX Document Details")
                print("=" * 50)
                print(f"ID: {doc.id}")
                print(f"Author: {doc.author}")
                print(f"Created: {doc.timestamp.isoformat()}")
                print(f"\nStatements ({len(doc.statements)}):")
                for stmt in doc.statements[:10]:  # Show first 10
                    print(f"\n  Vulnerability: {stmt.vulnerability.id}")
                    print(f"  Status: {stmt.status.value}")
                    print(f"  Products: {', '.join(p.name for p in stmt.products)}")
                    if stmt.justification:
                        print(f"  Justification: {stmt.justification.value}")

                if len(doc.statements) > 10:
                    print(f"\n  ... and {len(doc.statements) - 10} more statements")

            return 0

        elif action == "export":
            if not args.file:
                print("Error: VEX file required for export action")
                return 1

            vex_path = Path(args.file)
            if not vex_path.exists():
                print(f"Error: VEX file not found: {vex_path}")
                return 1

            vex_content = vex_path.read_text(encoding="utf-8")
            parser = VEXParser()
            doc = parser.parse_json(vex_content)

            # Export to requested format
            output = doc.to_json(format=args.format)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(output)
                print(f"VEX exported to: {args.output}")
                print(f"Format: {args.format}")
            else:
                print(output)

            return 0

    except Exception as e:
        if hasattr(args, "json") and args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1

    return 0
