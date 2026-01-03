"""
CLI commands for API Security Testing.

Provides command-line interface for API security analysis including
discovery, authentication testing, and security assessments.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from stance.api_security import (
    APIDiscoverer,
    APISecurityAnalyzer,
    AuthenticationTester,
    APIInventory,
    APISecurityReport,
)


def add_api_security_parser(subparsers: Any) -> None:
    """Add api-security subcommand parser."""
    api_parser = subparsers.add_parser(
        "api-security",
        help="API security testing and analysis",
        description="Analyze and test API security configurations.",
    )

    api_subparsers = api_parser.add_subparsers(
        dest="api_security_command",
        title="API Security commands",
    )

    # Discover command
    discover_parser = api_subparsers.add_parser(
        "discover",
        help="Discover API endpoints",
        description="Discover API endpoints from cloud assets or specifications.",
    )
    discover_parser.add_argument(
        "--from-scan",
        action="store_true",
        help="Discover from latest scan results",
    )
    discover_parser.add_argument(
        "--openapi",
        metavar="FILE",
        help="Discover from OpenAPI specification file",
    )
    discover_parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp", "all"],
        default="all",
        help="Filter by cloud provider",
    )
    discover_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Analyze command
    analyze_parser = api_subparsers.add_parser(
        "analyze",
        help="Analyze API security",
        description="Analyze API endpoints for security issues.",
    )
    analyze_parser.add_argument(
        "--from-scan",
        action="store_true",
        help="Analyze APIs from latest scan results",
    )
    analyze_parser.add_argument(
        "--openapi",
        metavar="FILE",
        help="Analyze from OpenAPI specification file",
    )
    analyze_parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    analyze_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Exit with error if findings at or above this severity",
    )
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Test auth command
    test_auth_parser = api_subparsers.add_parser(
        "test-auth",
        help="Test API authentication",
        description="Test API authentication configurations.",
    )
    test_auth_parser.add_argument(
        "--from-scan",
        action="store_true",
        help="Test APIs from latest scan results",
    )
    test_auth_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # List command
    list_parser = api_subparsers.add_parser(
        "list",
        help="List discovered APIs",
        description="List discovered API endpoints.",
    )
    list_parser.add_argument(
        "--provider",
        choices=["aws", "azure", "gcp", "all"],
        default="all",
        help="Filter by cloud provider",
    )
    list_parser.add_argument(
        "--public-only",
        action="store_true",
        help="Show only public APIs",
    )
    list_parser.add_argument(
        "--unauthenticated-only",
        action="store_true",
        help="Show only unauthenticated APIs",
    )
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Status command
    status_parser = api_subparsers.add_parser(
        "status",
        help="Show API security status",
        description="Show API security module status.",
    )
    status_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    # Info command
    info_parser = api_subparsers.add_parser(
        "info",
        help="Show module information",
        description="Show API security module information.",
    )
    info_parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )


def cmd_api_security(args: argparse.Namespace) -> int:
    """Handle api-security commands."""
    if not hasattr(args, "api_security_command") or args.api_security_command is None:
        print("Usage: stance api-security <command> [options]")
        print("\nAvailable commands:")
        print("  discover  - Discover API endpoints")
        print("  analyze   - Analyze API security")
        print("  test-auth - Test authentication configurations")
        print("  list      - List discovered APIs")
        print("  status    - Show API security status")
        print("  info      - Show module information")
        print("\nUse 'stance api-security <command> --help' for more information.")
        return 0

    handlers = {
        "discover": _handle_discover,
        "analyze": _handle_analyze,
        "test-auth": _handle_test_auth,
        "list": _handle_list,
        "status": _handle_status,
        "info": _handle_info,
    }

    handler = handlers.get(args.api_security_command)
    if handler:
        return handler(args)
    else:
        print(f"Unknown command: {args.api_security_command}")
        return 1


def _get_api_gateway_assets() -> list[Any]:
    """Get API Gateway assets from storage."""
    from stance.storage import get_storage

    try:
        storage = get_storage("local")
        assets = storage.get_latest_assets()

        # Filter to API Gateway assets
        api_types = [
            "aws_apigateway_rest_api",
            "aws_apigateway_http_api",
            "azure_apim_api",
            "azure_api_management",
            "gcp_apigateway_api",
            "gcp_api_gateway",
        ]

        return [a for a in assets if a.resource_type in api_types]
    except Exception:
        return []


def _handle_discover(args: argparse.Namespace) -> int:
    """Handle discover command."""
    discoverer = APIDiscoverer()
    inventory = APIInventory()

    try:
        # Discover from scan results
        if args.from_scan:
            assets = _get_api_gateway_assets()

            if args.provider != "all":
                assets = [a for a in assets if a.cloud_provider == args.provider]

            if assets:
                inventory = discoverer.discover_from_assets(assets)

        # Discover from OpenAPI spec
        if args.openapi:
            openapi_path = Path(args.openapi)
            if not openapi_path.exists():
                print(f"Error: OpenAPI file not found: {args.openapi}")
                return 1

            with open(openapi_path) as f:
                if openapi_path.suffix in (".yaml", ".yml"):
                    try:
                        import yaml
                        spec = yaml.safe_load(f)
                    except ImportError:
                        print("Error: PyYAML required for YAML files")
                        return 1
                else:
                    spec = json.load(f)

            openapi_inventory = discoverer.discover_from_openapi(spec, str(openapi_path))
            inventory = discoverer.merge_inventories(inventory, openapi_inventory)

        # Default: discover from scan
        if not args.from_scan and not args.openapi:
            assets = _get_api_gateway_assets()
            if assets:
                inventory = discoverer.discover_from_assets(assets)

        if args.json:
            print(json.dumps(inventory.to_dict(), indent=2))
        else:
            print("API Discovery Results")
            print("=" * 50)
            print(f"Total Endpoints: {inventory.total_endpoints}")
            print(f"Public Endpoints: {inventory.public_endpoints}")
            print(f"Authenticated: {inventory.authenticated_endpoints}")
            print(f"Unauthenticated: {inventory.unauthenticated_endpoints}")
            print()
            print("By Provider:")
            for provider, count in inventory.by_provider.items():
                print(f"  {provider}: {count}")
            print()
            print("By Protocol:")
            for protocol, count in inventory.by_protocol.items():
                print(f"  {protocol}: {count}")

            if inventory.endpoints:
                print()
                print("Endpoints:")
                for endpoint in inventory.endpoints[:10]:
                    auth_status = "auth" if endpoint.authentication_required else "NO AUTH"
                    public_status = "PUBLIC" if endpoint.is_public else "private"
                    print(f"  [{endpoint.cloud_provider}] {endpoint.name}")
                    print(f"    Type: {endpoint.protocol.value} | {auth_status} | {public_status}")
                    if endpoint.url:
                        print(f"    URL: {endpoint.url}")

                if len(inventory.endpoints) > 10:
                    print(f"  ... and {len(inventory.endpoints) - 10} more")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error discovering APIs: {e}")
        return 1


def _handle_analyze(args: argparse.Namespace) -> int:
    """Handle analyze command."""
    discoverer = APIDiscoverer()
    analyzer = APISecurityAnalyzer()
    inventory = APIInventory()

    try:
        # Get inventory
        if args.from_scan:
            assets = _get_api_gateway_assets()
            if assets:
                inventory = discoverer.discover_from_assets(assets)
        elif args.openapi:
            openapi_path = Path(args.openapi)
            if not openapi_path.exists():
                print(f"Error: OpenAPI file not found: {args.openapi}")
                return 1

            with open(openapi_path) as f:
                if openapi_path.suffix in (".yaml", ".yml"):
                    try:
                        import yaml
                        spec = yaml.safe_load(f)
                    except ImportError:
                        print("Error: PyYAML required for YAML files")
                        return 1
                else:
                    spec = json.load(f)

            inventory = discoverer.discover_from_openapi(spec, str(openapi_path))
        else:
            assets = _get_api_gateway_assets()
            if assets:
                inventory = discoverer.discover_from_assets(assets)

        # Analyze
        report = analyzer.analyze(inventory)

        # Filter by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        min_severity_idx = severity_order.index(args.min_severity)
        filtered_findings = [
            f for f in report.findings
            if severity_order.index(f.severity.value) <= min_severity_idx
        ]

        if args.json:
            output = report.to_dict()
            output["findings"] = [f.to_dict() for f in filtered_findings]
            print(json.dumps(output, indent=2))
        else:
            print("API Security Analysis Report")
            print("=" * 50)
            print(f"Endpoints Analyzed: {report.total_endpoints}")
            print(f"Endpoints with Findings: {report.endpoints_with_findings}")
            print(f"Total Findings: {report.total_findings}")
            print()
            print("Severity Breakdown:")
            print(f"  Critical: {report.critical_count}")
            print(f"  High: {report.high_count}")
            print(f"  Medium: {report.medium_count}")
            print(f"  Low: {report.low_count}")
            print(f"  Info: {report.info_count}")

            if report.by_category:
                print()
                print("By Category:")
                for category, count in sorted(report.by_category.items()):
                    print(f"  {category}: {count}")

            if filtered_findings:
                print()
                print(f"Findings (>= {args.min_severity}):")
                for finding in filtered_findings[:20]:
                    sev = finding.severity.value.upper()
                    print(f"\n  [{sev}] {finding.title}")
                    print(f"    API: {finding.api_endpoint_name}")
                    print(f"    Category: {finding.category.value}")
                    if finding.recommendation:
                        rec = finding.recommendation[:80]
                        print(f"    Fix: {rec}...")

                if len(filtered_findings) > 20:
                    print(f"\n  ... and {len(filtered_findings) - 20} more findings")

            print()
            print(f"Analysis Duration: {report.analysis_duration_ms}ms")

        # Check fail-on threshold
        if args.fail_on:
            fail_idx = severity_order.index(args.fail_on)
            for sev, count in [
                ("critical", report.critical_count),
                ("high", report.high_count),
                ("medium", report.medium_count),
                ("low", report.low_count),
            ]:
                if severity_order.index(sev) <= fail_idx and count > 0:
                    if not args.json:
                        print()
                        print(f"FAILED: Found {count} {sev} finding(s)")
                    return 1

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error analyzing APIs: {e}")
        return 1


def _handle_test_auth(args: argparse.Namespace) -> int:
    """Handle test-auth command."""
    discoverer = APIDiscoverer()
    tester = AuthenticationTester()

    try:
        # Get inventory
        assets = _get_api_gateway_assets()
        if not assets:
            if args.json:
                print(json.dumps({"error": "No API assets found. Run a scan first."}))
            else:
                print("No API assets found. Run a scan first.")
            return 1

        inventory = discoverer.discover_from_assets(assets)

        # Test each endpoint
        all_results = []
        passed_total = 0
        failed_total = 0
        warning_total = 0

        for endpoint in inventory.endpoints:
            report = tester.test_endpoint(endpoint)
            all_results.append(report)
            passed_total += report.passed_count
            failed_total += report.failed_count
            warning_total += report.warning_count

        if args.json:
            output = {
                "summary": {
                    "endpoints_tested": len(inventory.endpoints),
                    "total_passed": passed_total,
                    "total_failed": failed_total,
                    "total_warnings": warning_total,
                },
                "reports": [r.to_dict() for r in all_results],
            }
            print(json.dumps(output, indent=2))
        else:
            print("API Authentication Test Results")
            print("=" * 50)
            print(f"Endpoints Tested: {len(inventory.endpoints)}")
            print()
            print("Summary:")
            print(f"  Passed: {passed_total}")
            print(f"  Failed: {failed_total}")
            print(f"  Warnings: {warning_total}")

            # Show failed tests
            failed_reports = [r for r in all_results if r.failed_count > 0]
            if failed_reports:
                print()
                print("Failed Authentication Tests:")
                for report in failed_reports[:10]:
                    print(f"\n  {report.endpoint_name}")
                    print(f"    Auth Type: {report.authentication_type}")
                    for result in report.results:
                        if result.status.value == "failed":
                            print(f"    [FAIL] {result.test_name}: {result.message}")

            # Show warnings
            warning_reports = [r for r in all_results if r.warning_count > 0]
            if warning_reports:
                print()
                print("Authentication Warnings:")
                for report in warning_reports[:5]:
                    print(f"\n  {report.endpoint_name}")
                    for result in report.results:
                        if result.status.value == "warning":
                            print(f"    [WARN] {result.test_name}: {result.message}")

        return 0 if failed_total == 0 else 1

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error testing authentication: {e}")
        return 1


def _handle_list(args: argparse.Namespace) -> int:
    """Handle list command."""
    discoverer = APIDiscoverer()

    try:
        assets = _get_api_gateway_assets()

        if args.provider != "all":
            assets = [a for a in assets if a.cloud_provider == args.provider]

        if not assets:
            if args.json:
                print(json.dumps({"endpoints": [], "total": 0}))
            else:
                print("No API endpoints found.")
            return 0

        inventory = discoverer.discover_from_assets(assets)
        endpoints = inventory.endpoints

        # Apply filters
        if args.public_only:
            endpoints = [e for e in endpoints if e.is_public]
        if args.unauthenticated_only:
            endpoints = [e for e in endpoints if not e.authentication_required]

        if args.json:
            output = {
                "endpoints": [e.to_dict() for e in endpoints],
                "total": len(endpoints),
            }
            print(json.dumps(output, indent=2))
        else:
            print(f"API Endpoints ({len(endpoints)} found)")
            print("=" * 50)

            for endpoint in endpoints:
                auth_icon = "[AUTH]" if endpoint.authentication_required else "[NO AUTH]"
                public_icon = "[PUBLIC]" if endpoint.is_public else "[PRIVATE]"
                waf_icon = "[WAF]" if endpoint.has_waf else ""

                print(f"\n{endpoint.name}")
                print(f"  Provider: {endpoint.cloud_provider} | Region: {endpoint.region}")
                print(f"  Protocol: {endpoint.protocol.value}")
                print(f"  Status: {public_icon} {auth_icon} {waf_icon}")
                if endpoint.url:
                    print(f"  URL: {endpoint.url}")
                if endpoint.authentication_type.value != "unknown":
                    print(f"  Auth Type: {endpoint.authentication_type.value}")

        return 0

    except Exception as e:
        if args.json:
            print(json.dumps({"error": str(e)}))
        else:
            print(f"Error listing APIs: {e}")
        return 1


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    try:
        from stance.api_security import (
            APIDiscoverer,
            APISecurityAnalyzer,
            AuthenticationTester,
        )

        # Get API counts
        assets = _get_api_gateway_assets()
        discoverer = APIDiscoverer()
        inventory = discoverer.discover_from_assets(assets) if assets else APIInventory()

        status = {
            "status": "ok",
            "module": "api_security",
            "components": {
                "APIDiscoverer": True,
                "APISecurityAnalyzer": True,
                "AuthenticationTester": True,
            },
            "inventory": {
                "total_endpoints": inventory.total_endpoints,
                "public_endpoints": inventory.public_endpoints,
                "authenticated_endpoints": inventory.authenticated_endpoints,
                "by_provider": inventory.by_provider,
            },
            "policies": {
                "aws_apigateway": 12,  # Number of API Gateway policies
            },
        }

        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print("API Security Module Status")
            print("=" * 50)
            print(f"Status: {status['status']}")
            print()
            print("Components:")
            for component, available in status["components"].items():
                icon = "[OK]" if available else "[X]"
                print(f"  {icon} {component}")
            print()
            print("Current Inventory:")
            print(f"  Total Endpoints: {inventory.total_endpoints}")
            print(f"  Public Endpoints: {inventory.public_endpoints}")
            print(f"  Authenticated: {inventory.authenticated_endpoints}")
            print()
            print("Security Policies: 12 API Gateway policies")

        return 0

    except ImportError as e:
        if args.json:
            print(json.dumps({"status": "error", "error": str(e)}))
        else:
            print(f"Error: {e}")
        return 1


def _handle_info(args: argparse.Namespace) -> int:
    """Handle info command."""
    info = {
        "module": "stance.api_security",
        "description": "API Security Testing module for multi-cloud environments",
        "capabilities": [
            "API endpoint discovery from cloud assets",
            "OpenAPI specification analysis",
            "Authentication configuration testing",
            "Security issue detection (OWASP API Top 10)",
            "CORS policy analysis",
            "Rate limiting verification",
            "WAF protection checks",
            "Access logging validation",
        ],
        "components": {
            "APIDiscoverer": "Discovers API endpoints from assets and specs",
            "APISecurityAnalyzer": "Analyzes APIs for security issues",
            "AuthenticationTester": "Tests authentication configurations",
        },
        "supported_providers": ["AWS", "Azure", "GCP"],
        "supported_api_types": {
            "aws": ["API Gateway REST API", "API Gateway HTTP API", "WebSocket API"],
            "azure": ["API Management"],
            "gcp": ["API Gateway"],
        },
        "security_checks": [
            "No authentication",
            "Weak authentication",
            "CORS misconfiguration",
            "Missing rate limiting",
            "Public exposure without protection",
            "Missing WAF",
            "Missing logging",
            "Missing documentation",
            "Weak TLS configuration",
            "API key exposure",
        ],
    }

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print("API Security Testing Module")
        print("=" * 50)
        print(f"Module: {info['module']}")
        print(f"Description: {info['description']}")
        print()
        print("Capabilities:")
        for cap in info["capabilities"]:
            print(f"  - {cap}")
        print()
        print("Components:")
        for component, desc in info["components"].items():
            print(f"  {component}: {desc}")
        print()
        print("Supported Providers:", ", ".join(info["supported_providers"]))
        print()
        print("Security Checks:")
        for check in info["security_checks"]:
            print(f"  - {check}")

    return 0
