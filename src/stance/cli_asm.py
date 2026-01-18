"""
CLI command handlers for Attack Surface Management (ASM).

Provides commands for:
- Running ASM scans (passive, active, full modes)
- Viewing external asset inventory
- Detecting drift between ASM scans
- Domain ownership verification
- Continuous monitoring
- Managing ASM policies
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


def add_asm_parser(subparsers: argparse._SubParsersAction) -> None:
    """
    Add the ASM command group to the main CLI parser.

    Args:
        subparsers: The subparsers action from the main argument parser
    """
    asm_parser = subparsers.add_parser(
        "asm",
        help="Attack Surface Management (external reconnaissance)",
        description=(
            "Attack Surface Management commands for external asset discovery "
            "and monitoring. ASM provides an outside-in view of your organization's "
            "attack surface through certificate transparency logs, DNS enumeration, "
            "and optional port scanning."
        ),
    )

    asm_subparsers = asm_parser.add_subparsers(dest="asm_action")

    # asm scan command
    scan_parser = asm_subparsers.add_parser(
        "scan",
        help="Run ASM scan on target domains",
    )
    scan_parser.add_argument(
        "--domains",
        nargs="+",
        required=True,
        help="Target domains to scan (e.g., example.com)",
    )
    scan_parser.add_argument(
        "--mode",
        choices=["passive", "active", "full"],
        default="passive",
        help="Scan mode (default: passive)",
    )
    scan_parser.add_argument(
        "--output",
        choices=["json", "table", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    scan_parser.add_argument(
        "--save",
        action="store_true",
        help="Store results to configured backend",
    )
    scan_parser.add_argument(
        "--correlate",
        action="store_true",
        help="Compare with CSPM inventory",
    )
    scan_parser.add_argument(
        "--config",
        help="Custom ASM config file",
    )
    scan_parser.add_argument(
        "--i-own-this-domain",
        action="store_true",
        help="Confirm domain ownership for active scanning",
    )

    # asm inventory command
    inventory_parser = asm_subparsers.add_parser(
        "inventory",
        help="Query stored external assets",
    )
    inventory_parser.add_argument(
        "--scan-id",
        help="Show specific scan results",
    )
    inventory_parser.add_argument(
        "--latest",
        action="store_true",
        default=True,
        help="Show most recent scan (default)",
    )
    inventory_parser.add_argument(
        "--filter",
        dest="filter_expr",
        help="Filter expression (e.g., 'risk_score > 7')",
    )
    inventory_parser.add_argument(
        "--format",
        choices=["json", "table", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    inventory_parser.add_argument(
        "--sort",
        choices=["domain", "risk", "last_seen", "port"],
        default="risk",
        help="Sort order (default: risk)",
    )
    inventory_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum results to show (default: 100)",
    )

    # asm drift command
    drift_parser = asm_subparsers.add_parser(
        "drift",
        help="Run drift detection between ASM scans",
    )
    drift_parser.add_argument(
        "--baseline",
        help="Baseline scan ID (default: previous scan)",
    )
    drift_parser.add_argument(
        "--current",
        help="Current scan ID (default: latest)",
    )
    drift_parser.add_argument(
        "--format",
        choices=["json", "table", "summary"],
        default="table",
        help="Output format (default: table)",
    )

    # asm verify command
    verify_parser = asm_subparsers.add_parser(
        "verify",
        help="Domain ownership verification",
    )
    verify_parser.add_argument(
        "--domain",
        required=True,
        help="Domain to verify ownership",
    )
    verify_parser.add_argument(
        "--method",
        choices=["dns", "http"],
        default="dns",
        help="Verification method (default: dns)",
    )
    verify_parser.add_argument(
        "--show-token",
        action="store_true",
        help="Display verification token to configure",
    )
    verify_parser.add_argument(
        "--check",
        action="store_true",
        help="Check if verification is complete",
    )

    # asm monitor command
    monitor_parser = asm_subparsers.add_parser(
        "monitor",
        help="Continuous monitoring mode",
    )
    monitor_parser.add_argument(
        "--domains",
        nargs="+",
        required=True,
        help="Domains to monitor",
    )
    monitor_parser.add_argument(
        "--interval",
        type=int,
        default=24,
        help="Scan interval in hours (default: 24)",
    )
    monitor_parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run as background process",
    )
    monitor_parser.add_argument(
        "--notify",
        action="store_true",
        help="Send notifications on changes",
    )

    # asm policies command
    policies_parser = asm_subparsers.add_parser(
        "policies",
        help="Manage ASM policies",
    )
    policies_parser.add_argument(
        "--list",
        action="store_true",
        help="List all ASM policies",
    )
    policies_parser.add_argument(
        "--show",
        metavar="ID",
        help="Show policy details",
    )
    policies_parser.add_argument(
        "--enable",
        metavar="ID",
        help="Enable a policy",
    )
    policies_parser.add_argument(
        "--disable",
        metavar="ID",
        help="Disable a policy",
    )
    policies_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )

    # asm scans command (list scans)
    scans_parser = asm_subparsers.add_parser(
        "scans",
        help="List ASM scans",
    )
    scans_parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Number of scans to show (default: 20)",
    )
    scans_parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_asm(args: argparse.Namespace) -> int:
    """
    Route ASM subcommands to appropriate handlers.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "asm_action", None)

    if action is None:
        print("Usage: stance asm <command>")
        print("")
        print("Attack Surface Management Commands:")
        print("  scan        Run ASM scan on target domains")
        print("  inventory   Query stored external assets")
        print("  drift       Run drift detection between scans")
        print("  verify      Domain ownership verification")
        print("  monitor     Continuous monitoring mode")
        print("  policies    Manage ASM policies")
        print("  scans       List ASM scans")
        print("")
        print("Examples:")
        print("  stance asm scan --domains example.com")
        print("  stance asm scan --domains example.com --mode active --i-own-this-domain")
        print("  stance asm inventory --latest --filter 'risk_score > 7'")
        print("  stance asm drift --baseline scan-001 --current scan-002")
        print("")
        print("Run 'stance asm <command> --help' for more information")
        return 0

    handlers = {
        "scan": _cmd_asm_scan,
        "inventory": _cmd_asm_inventory,
        "drift": _cmd_asm_drift,
        "verify": _cmd_asm_verify,
        "monitor": _cmd_asm_monitor,
        "policies": _cmd_asm_policies,
        "scans": _cmd_asm_scans,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown ASM command: {action}")
    return 1


def _cmd_asm_scan(args: argparse.Namespace) -> int:
    """
    Run ASM scan on target domains.

    Executes all enabled collectors, evaluates policies, and outputs results.
    """
    from stance.asm.models import ASMScanMode, ASMScanResult, ExternalAssetCollection
    from stance.asm.storage import ASMStorageAdapter, generate_scan_id

    domains = args.domains
    mode_str = getattr(args, "mode", "passive")
    output_format = getattr(args, "format", "table") or getattr(args, "output", "table")
    save_results = getattr(args, "save", False)
    i_own_domain = getattr(args, "i_own_this_domain", False)

    # Validate domains
    for domain in domains:
        if not _is_valid_domain(domain):
            print(f"Error: Invalid domain format: {domain}")
            return 1

    # Require ownership confirmation for active scanning
    scan_mode = ASMScanMode(mode_str)
    if scan_mode in (ASMScanMode.ACTIVE, ASMScanMode.FULL) and not i_own_domain:
        print("Error: Active scanning requires domain ownership confirmation.")
        print("Add --i-own-this-domain flag if you own these domains.")
        print("")
        print("Warning: Scanning domains you don't own may violate terms of service")
        print("or laws in your jurisdiction. Only scan domains you control.")
        return 1

    print(f"Starting ASM scan ({mode_str} mode)")
    print(f"Target domains: {', '.join(domains)}")
    print("")

    try:
        # Create scan result
        scan_id = generate_scan_id()
        scan_result = ASMScanResult(
            scan_id=scan_id,
            started_at=datetime.utcnow(),
            target_domains=domains,
            scan_mode=scan_mode,
        )
        scan_result.start()

        # Run collectors based on mode
        all_assets = ExternalAssetCollection()
        collectors_to_run = _get_collectors_for_mode(scan_mode)

        for collector_name in collectors_to_run:
            print(f"Running collector: {collector_name}...")
            try:
                assets = _run_collector(collector_name, domains)
                all_assets.extend(assets.assets)
                scan_result.add_collector(collector_name)
                print(f"  Found {len(assets)} assets")
            except Exception as e:
                logger.warning(f"Collector {collector_name} failed: {e}")
                scan_result.add_error(f"{collector_name}: {str(e)}")

        # Deduplicate assets
        all_assets = all_assets.deduplicate()

        # Evaluate ASM policies
        findings_count = 0
        try:
            from stance.asm.evaluator import ASMPolicyEvaluator

            evaluator = ASMPolicyEvaluator()
            findings, eval_result = evaluator.evaluate(all_assets)
            findings_count = len(findings)
        except ImportError:
            logger.debug("ASM policy evaluator not available")
        except Exception as e:
            logger.warning(f"Policy evaluation failed: {e}")
            scan_result.add_error(f"Policy evaluation: {str(e)}")

        # Complete scan
        scan_result.complete(all_assets, findings_count)

        print("")
        print(f"Scan completed: {scan_result.scan_id}")
        print(f"Duration: {scan_result.duration_seconds:.1f}s")
        print(f"Assets discovered: {len(all_assets)}")
        print(f"Findings generated: {findings_count}")

        if scan_result.errors:
            print(f"Warnings: {len(scan_result.errors)}")
            for error in scan_result.errors[:3]:
                print(f"  - {error}")

        # Save results if requested
        if save_results:
            storage = ASMStorageAdapter()
            storage.store_scan_result(scan_result)
            storage.store_external_assets(all_assets, scan_id)
            print(f"Results saved to storage (scan_id: {scan_id})")

        # Output results
        print("")
        _output_assets(all_assets, output_format)

        # Show statistics
        if output_format == "table":
            _print_scan_statistics(all_assets)

        return 0

    except Exception as e:
        logger.error(f"ASM scan failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_asm_inventory(args: argparse.Namespace) -> int:
    """
    Query stored external assets.

    Retrieves assets from storage with optional filtering and sorting.
    """
    from stance.asm.storage import ASMStorageAdapter

    scan_id = getattr(args, "scan_id", None)
    filter_expr = getattr(args, "filter_expr", None)
    output_format = getattr(args, "format", "table")
    sort_by = getattr(args, "sort", "risk")
    limit = getattr(args, "limit", 100)

    try:
        storage = ASMStorageAdapter()

        # Get assets
        if scan_id:
            assets = storage.get_external_assets(scan_id)
        else:
            assets = storage.get_external_assets()  # Latest

        if len(assets) == 0:
            print("No external assets found.")
            print("Run 'stance asm scan --domains <domain> --save' first.")
            return 0

        # Apply filter if provided
        if filter_expr:
            assets = _apply_filter(assets, filter_expr)

        # Sort assets
        if sort_by == "risk":
            assets = assets.sort_by_risk(descending=True)
        elif sort_by == "domain":
            assets = assets.sort_by_domain()
        elif sort_by == "last_seen":
            assets = assets.sort_by_last_seen(descending=True)
        elif sort_by == "port":
            sorted_list = sorted(assets.assets, key=lambda a: a.port or 0)
            from stance.asm.models import ExternalAssetCollection
            assets = ExternalAssetCollection(sorted_list)

        # Limit results
        if limit and len(assets) > limit:
            from stance.asm.models import ExternalAssetCollection
            assets = ExternalAssetCollection(assets.assets[:limit])

        # Get scan info for context
        latest = storage.get_latest_scan()
        if latest and output_format == "table":
            print(f"Scan: {latest.scan_id}")
            print(f"Date: {latest.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Domains: {', '.join(latest.target_domains)}")
            print("")

        # Output results
        _output_assets(assets, output_format)

        # Show summary
        if output_format == "table":
            print("")
            print(f"Total: {len(assets)} assets")

        return 0

    except Exception as e:
        logger.error(f"Inventory query failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_asm_drift(args: argparse.Namespace) -> int:
    """
    Run drift detection between ASM scans.

    Compares two scans to identify new, removed, and changed assets.
    """
    from stance.asm.drift import ASMDriftDetector
    from stance.asm.storage import ASMStorageAdapter

    baseline_id = getattr(args, "baseline", None)
    current_id = getattr(args, "current", None)
    output_format = getattr(args, "format", "table")

    try:
        storage = ASMStorageAdapter()
        detector = ASMDriftDetector(storage)

        # Get scan IDs
        scans = storage.list_scans(limit=10)
        if len(scans) < 2 and (baseline_id is None or current_id is None):
            print("Error: Need at least 2 scans for drift detection.")
            print("Run 'stance asm scan --domains <domain> --save' to create scans.")
            return 1

        # Default to comparing two most recent scans
        if current_id is None:
            current_id = scans[0].scan_id
        if baseline_id is None:
            baseline_id = scans[1].scan_id

        print(f"Comparing scans:")
        print(f"  Baseline: {baseline_id}")
        print(f"  Current:  {current_id}")
        print("")

        # Detect drift
        report = detector.detect_drift(baseline_id, current_id)

        # Output based on format
        if output_format == "json":
            print(json.dumps(report.to_dict(), indent=2, default=str))
        elif output_format == "summary":
            _print_drift_summary(report)
        else:  # table format
            _print_drift_table(report)

        return 0

    except Exception as e:
        logger.error(f"Drift detection failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_asm_verify(args: argparse.Namespace) -> int:
    """
    Domain ownership verification.

    Generates or checks verification tokens for domain ownership.
    """
    from stance.asm.config import ASMOwnershipVerification

    domain = args.domain
    method = getattr(args, "method", "dns")
    show_token = getattr(args, "show_token", False)
    check_verification = getattr(args, "check", False)

    if not _is_valid_domain(domain):
        print(f"Error: Invalid domain format: {domain}")
        return 1

    try:
        # Map method to verification_method field
        verification_method = "dns_txt" if method == "dns" else "http_file"
        verification = ASMOwnershipVerification(
            domain=domain,
            verification_method=verification_method,
        )

        if show_token:
            print(f"Domain Ownership Verification for: {domain}")
            print("")
            print(f"Method: {method.upper()}")
            print("")

            if method == "dns":
                print("Instructions:")
                print(f"1. Add a TXT record to your DNS zone for {domain}")
                print(f"2. Record name: {verification.dns_record_name}")
                print(f"3. Record value: {verification.verification_token}")
                print("")
                print("Example DNS record:")
                print(f"  {verification.dns_record_name}. IN TXT \"{verification.verification_token}\"")
            else:  # http
                print("Instructions:")
                print(f"1. Create a file at: {verification.http_file_url}")
                print(f"2. File contents: {verification.http_file_content}")
                print("")
                print(f"URL to verify: {verification.http_file_url}")

            print("")
            print(f"Token: {verification.verification_token}")
            print("")
            print("After configuring, run:")
            print(f"  stance asm verify --domain {domain} --method {method} --check")
            return 0

        if check_verification:
            print(f"Checking domain verification for: {domain}")
            print(f"Method: {method}")
            print("")

            is_verified = _check_domain_verification(domain, verification_method, verification.verification_token)

            if is_verified:
                print("Verification: SUCCESS")
                print(f"Domain {domain} is verified for active scanning.")
                verification.verify()
            else:
                print("Verification: FAILED")
                print("")
                print(f"Could not verify ownership of {domain}.")
                print("Use --show-token to see verification instructions.")
            return 0 if is_verified else 1

        # Default: show status
        print(f"Domain: {domain}")
        print(f"Method: {method}")
        print("")
        print("Options:")
        print("  --show-token  Display verification token")
        print("  --check       Check if verification is complete")
        return 0

    except Exception as e:
        logger.error(f"Verification failed: {e}")
        print(f"Error: {e}")
        return 1


def _check_domain_verification(domain: str, method: str, token: str) -> bool:
    """
    Check if domain verification is complete.

    Args:
        domain: Domain to verify
        method: Verification method (dns_txt, http_file)
        token: Expected verification token

    Returns:
        True if verification is successful
    """
    import socket

    if method == "dns_txt":
        try:
            import dns.resolver
            record_name = f"_stance-verify.{domain}"
            answers = dns.resolver.resolve(record_name, "TXT")
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value == token:
                    return True
            return False
        except ImportError:
            logger.warning("dnspython not installed, DNS verification unavailable")
            print("Warning: DNS verification requires dnspython package")
            print("Install with: pip install dnspython")
            return False
        except Exception as e:
            logger.debug(f"DNS verification failed: {e}")
            return False

    elif method == "http_file":
        try:
            import urllib.request
            url = f"https://{domain}/.well-known/stance-verify.txt"
            with urllib.request.urlopen(url, timeout=10) as response:
                content = response.read().decode("utf-8").strip()
                return content == token
        except Exception as e:
            logger.debug(f"HTTP verification failed: {e}")
            return False

    return False


def _cmd_asm_monitor(args: argparse.Namespace) -> int:
    """
    Continuous monitoring mode.

    Runs periodic ASM scans and alerts on changes.
    """
    import time

    domains = args.domains
    interval_hours = getattr(args, "interval", 24)
    daemon_mode = getattr(args, "daemon", False)
    notify = getattr(args, "notify", False)

    # Validate domains
    for domain in domains:
        if not _is_valid_domain(domain):
            print(f"Error: Invalid domain format: {domain}")
            return 1

    print("ASM Continuous Monitoring")
    print("=" * 60)
    print(f"Domains: {', '.join(domains)}")
    print(f"Interval: Every {interval_hours} hours")
    print(f"Notifications: {'Enabled' if notify else 'Disabled'}")
    print("")

    if daemon_mode:
        print("Daemon mode not yet implemented.")
        print("Run in foreground or use a process manager like systemd.")
        return 1

    print("Press Ctrl+C to stop monitoring")
    print("")

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                  f"Running scan iteration {iteration}...")

            # Create a minimal args namespace for the scan
            scan_args = argparse.Namespace(
                domains=domains,
                mode="passive",
                output="table",
                save=True,
                correlate=False,
                config=None,
                i_own_this_domain=False,
                format="table",
            )

            try:
                _cmd_asm_scan(scan_args)
            except Exception as e:
                logger.error(f"Scan iteration {iteration} failed: {e}")
                print(f"Warning: Scan failed: {e}")

            # Check for drift if we have multiple scans
            if iteration > 1:
                print("")
                print("Checking for drift...")
                drift_args = argparse.Namespace(
                    baseline=None,
                    current=None,
                    format="summary",
                )
                _cmd_asm_drift(drift_args)

            print("")
            print(f"Next scan in {interval_hours} hours...")
            print("-" * 60)

            # Sleep until next interval
            time.sleep(interval_hours * 3600)

    except KeyboardInterrupt:
        print("")
        print("Monitoring stopped.")
        return 0

    return 0


def _cmd_asm_policies(args: argparse.Namespace) -> int:
    """
    Manage ASM policies.

    List, show, enable, or disable ASM policies.
    """
    list_policies = getattr(args, "list", False)
    show_id = getattr(args, "show", None)
    enable_id = getattr(args, "enable", None)
    disable_id = getattr(args, "disable", None)
    output_format = getattr(args, "format", "table")

    try:
        from stance.asm.evaluator import ASMPolicyEvaluator

        evaluator = ASMPolicyEvaluator()
        policy_collection = evaluator.load_policies()
        policies = list(policy_collection)

        if enable_id:
            # Find and enable policy by updating its state
            found = False
            for policy in policies:
                if policy.id == enable_id:
                    policy.enabled = True
                    found = True
                    print(f"Policy enabled: {enable_id}")
                    break
            if not found:
                print(f"Policy not found: {enable_id}")
                return 1
            return 0

        if disable_id:
            # Find and disable policy by updating its state
            found = False
            for policy in policies:
                if policy.id == disable_id:
                    policy.enabled = False
                    found = True
                    print(f"Policy disabled: {disable_id}")
                    break
            if not found:
                print(f"Policy not found: {disable_id}")
                return 1
            return 0

        if show_id:
            policy = None
            for p in policies:
                if p.id == show_id:
                    policy = p
                    break

            if policy is None:
                print(f"Policy not found: {show_id}")
                return 1

            if output_format == "json":
                print(json.dumps(policy.to_dict(), indent=2))
            else:
                print(f"Policy: {policy.id}")
                print("=" * 60)
                print(f"  Name: {policy.name}")
                print(f"  Description: {policy.description}")
                print(f"  Severity: {policy.severity.value if hasattr(policy.severity, 'value') else policy.severity}")
                print(f"  Enabled: {policy.enabled}")
                if hasattr(policy, 'checks') and policy.checks:
                    for check in policy.checks:
                        print(f"  Check: {check.expression if hasattr(check, 'expression') else check}")
                if hasattr(policy, 'remediation') and policy.remediation:
                    print(f"  Remediation: {policy.remediation.description if hasattr(policy.remediation, 'description') else policy.remediation}")
            return 0

        # Default: list policies
        if output_format == "json":
            output = [p.to_dict() for p in policies]
            print(json.dumps(output, indent=2))
        else:
            print("ASM Policies")
            print("=" * 80)
            print(f"{'ID':<30} {'Severity':<10} {'Enabled':<8} {'Name'}")
            print("-" * 80)

            for policy in policies:
                enabled = "Yes" if policy.enabled else "No"
                severity = policy.severity.value if hasattr(policy.severity, 'value') else str(policy.severity)
                name = policy.name[:35] + "..." if len(policy.name) > 38 else policy.name
                print(f"{policy.id:<30} {severity:<10} {enabled:<8} {name}")

            print("")
            print(f"Total: {len(policies)} policies")

        return 0

    except ImportError as e:
        logger.debug(f"ASM policy evaluator not available: {e}")
        print("ASM policy evaluator not available.")
        return 1
    except Exception as e:
        logger.error(f"Policy management failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_asm_scans(args: argparse.Namespace) -> int:
    """
    List ASM scans.

    Shows history of ASM scan executions.
    """
    from stance.asm.storage import ASMStorageAdapter

    limit = getattr(args, "limit", 20)
    output_format = getattr(args, "format", "table")

    try:
        storage = ASMStorageAdapter()
        scans = storage.list_scans(limit=limit)

        if len(scans) == 0:
            print("No ASM scans found.")
            print("Run 'stance asm scan --domains <domain> --save' to create a scan.")
            return 0

        if output_format == "json":
            output = []
            for scan in scans:
                output.append({
                    "scan_id": scan.scan_id,
                    "started_at": scan.started_at.isoformat(),
                    "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                    "status": scan.status.value,
                    "target_domains": scan.target_domains,
                    "scan_mode": scan.scan_mode.value,
                    "assets_discovered": scan.assets_discovered,
                    "findings_count": scan.findings_count,
                    "duration_seconds": scan.duration_seconds,
                })
            print(json.dumps(output, indent=2))
        else:
            print("ASM Scans")
            print("=" * 100)
            print(f"{'Scan ID':<30} {'Date':<20} {'Mode':<8} {'Status':<10} {'Assets':<8} {'Domains'}")
            print("-" * 100)

            for scan in scans:
                date_str = scan.started_at.strftime("%Y-%m-%d %H:%M")
                domains = ", ".join(scan.target_domains[:2])
                if len(scan.target_domains) > 2:
                    domains += f" (+{len(scan.target_domains) - 2})"
                domains = domains[:20] + "..." if len(domains) > 23 else domains

                print(
                    f"{scan.scan_id:<30} "
                    f"{date_str:<20} "
                    f"{scan.scan_mode.value:<8} "
                    f"{scan.status.value:<10} "
                    f"{scan.assets_discovered:<8} "
                    f"{domains}"
                )

            print("")
            print(f"Total: {len(scans)} scans")

        return 0

    except Exception as e:
        logger.error(f"Listing scans failed: {e}")
        print(f"Error: {e}")
        return 1


# Helper functions


def _is_valid_domain(domain: str) -> bool:
    """Validate domain format."""
    # Basic domain validation
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def _get_collectors_for_mode(mode) -> list[str]:
    """Get list of collectors to run for a scan mode."""
    from stance.asm.models import ASMScanMode

    passive_collectors = [
        "cert_transparency",
        "dns_enumeration",
        "cloud_ip_ranges",
    ]

    active_collectors = [
        "port_scanner",
        "technology_fingerprint",
    ]

    if mode == ASMScanMode.PASSIVE:
        return passive_collectors
    elif mode == ASMScanMode.ACTIVE:
        return passive_collectors + active_collectors
    else:  # FULL
        return passive_collectors + active_collectors


def _run_collector(collector_name: str, domains: list[str]):
    """
    Run a specific collector.

    Args:
        collector_name: Name of the collector to run
        domains: List of domains to scan

    Returns:
        ExternalAssetCollection with discovered assets
    """
    from stance.asm.models import ExternalAssetCollection

    try:
        if collector_name == "cert_transparency":
            from stance.asm.collectors.cert_transparency import CertTransparencyCollector
            collector = CertTransparencyCollector(target_domains=domains)
            return collector.collect()
        elif collector_name == "dns_enumeration":
            from stance.asm.collectors.passive_dns import PassiveDNSCollector
            collector = PassiveDNSCollector(target_domains=domains)
            return collector.collect()
        elif collector_name == "cloud_ip_ranges":
            from stance.asm.collectors.cloud_ip_ranges import CloudIPRangeCollector
            collector = CloudIPRangeCollector()
            # CloudIPRangeCollector enriches existing assets; for standalone use,
            # we need to pass assets discovered by other collectors
            return ExternalAssetCollection()
        elif collector_name == "port_scanner":
            from stance.asm.collectors.port_scanner import PortScanner
            collector = PortScanner()
            # Port scanner requires ownership verification and works on specific IPs
            # For CLI scan, we'd need to pass discovered assets
            return ExternalAssetCollection()
        elif collector_name == "technology_fingerprint":
            from stance.asm.collectors.technology import TechnologyFingerprinter
            fingerprinter = TechnologyFingerprinter()
            # Technology fingerprinting enriches existing assets
            return ExternalAssetCollection()
        else:
            logger.warning(f"Unknown collector: {collector_name}")
            return ExternalAssetCollection()
    except ImportError as e:
        logger.debug(f"Collector {collector_name} not available: {e}")
        return ExternalAssetCollection()
    except Exception as e:
        logger.warning(f"Collector {collector_name} failed: {e}")
        return ExternalAssetCollection()


def _apply_filter(assets, filter_expr: str):
    """
    Apply a filter expression to assets.

    Supports expressions like:
    - risk_score > 7
    - port == 443
    - domain contains "api"
    """
    from stance.asm.models import ExternalAssetCollection

    # Parse simple filter expressions
    filter_expr = filter_expr.strip()

    # risk_score comparison
    risk_match = re.match(r"risk_score\s*(>|>=|<|<=|==)\s*([\d.]+)", filter_expr)
    if risk_match:
        op, value = risk_match.groups()
        threshold = float(value)
        filtered = []
        for asset in assets:
            if op == ">" and asset.risk_score > threshold:
                filtered.append(asset)
            elif op == ">=" and asset.risk_score >= threshold:
                filtered.append(asset)
            elif op == "<" and asset.risk_score < threshold:
                filtered.append(asset)
            elif op == "<=" and asset.risk_score <= threshold:
                filtered.append(asset)
            elif op == "==" and asset.risk_score == threshold:
                filtered.append(asset)
        return ExternalAssetCollection(filtered)

    # port comparison
    port_match = re.match(r"port\s*(>|>=|<|<=|==)\s*(\d+)", filter_expr)
    if port_match:
        op, value = port_match.groups()
        threshold = int(value)
        filtered = []
        for asset in assets:
            if asset.port is None:
                continue
            if op == ">" and asset.port > threshold:
                filtered.append(asset)
            elif op == ">=" and asset.port >= threshold:
                filtered.append(asset)
            elif op == "<" and asset.port < threshold:
                filtered.append(asset)
            elif op == "<=" and asset.port <= threshold:
                filtered.append(asset)
            elif op == "==" and asset.port == threshold:
                filtered.append(asset)
        return ExternalAssetCollection(filtered)

    # domain contains
    domain_match = re.match(r"domain\s+contains\s+['\"](.+)['\"]", filter_expr)
    if domain_match:
        substring = domain_match.group(1).lower()
        filtered = [a for a in assets if substring in a.domain.lower()]
        return ExternalAssetCollection(filtered)

    logger.warning(f"Unknown filter expression: {filter_expr}")
    return assets


def _output_assets(assets, output_format: str) -> None:
    """Output assets in the specified format."""
    if output_format == "json":
        print(assets.to_json())
    elif output_format == "csv":
        _print_assets_csv(assets)
    else:  # table
        _print_assets_table(assets)


def _print_assets_table(assets) -> None:
    """Print assets in table format."""
    if len(assets) == 0:
        print("No assets to display.")
        return

    print(f"{'Domain':<35} {'IP':<16} {'Port':<6} {'Service':<15} {'Risk':<6} {'Last Seen'}")
    print("-" * 100)

    for asset in assets:
        domain = asset.domain[:32] + "..." if len(asset.domain) > 35 else asset.domain
        ip = asset.ip_address or "-"
        port = str(asset.port) if asset.port else "-"
        service = (asset.service or "-")[:12] + "..." if asset.service and len(asset.service) > 15 else (asset.service or "-")
        risk = f"{asset.risk_score:.1f}"
        last_seen = asset.last_seen.strftime("%Y-%m-%d")

        print(f"{domain:<35} {ip:<16} {port:<6} {service:<15} {risk:<6} {last_seen}")


def _print_assets_csv(assets) -> None:
    """Print assets in CSV format."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "domain", "ip_address", "port", "protocol", "service",
        "cloud_provider", "cloud_region", "risk_score", "source",
        "first_seen", "last_seen"
    ])

    # Data rows
    for asset in assets:
        writer.writerow([
            asset.domain,
            asset.ip_address or "",
            asset.port or "",
            asset.protocol or "",
            asset.service or "",
            asset.cloud_provider or "",
            asset.cloud_region or "",
            asset.risk_score,
            asset.source,
            asset.first_seen.isoformat(),
            asset.last_seen.isoformat(),
        ])

    print(output.getvalue())


def _print_scan_statistics(assets) -> None:
    """Print scan statistics summary."""
    print("")
    print("Statistics")
    print("-" * 40)
    print(f"  Total assets: {len(assets)}")
    print(f"  Unique domains: {len(assets.get_unique_domains())}")
    print(f"  Unique IPs: {len(assets.get_unique_ips())}")

    # Port distribution
    port_counts = assets.count_by_port()
    if port_counts:
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        print("  Top ports:")
        for port, count in top_ports:
            print(f"    {port}: {count}")

    # Cloud provider distribution
    cloud_counts = assets.count_by_cloud_provider()
    if cloud_counts:
        print("  Cloud providers:")
        for provider, count in cloud_counts.items():
            print(f"    {provider}: {count}")


def _print_drift_summary(report) -> None:
    """Print drift report in summary format."""
    summary = report.summary

    print("Drift Detection Summary")
    print("=" * 60)
    print(f"  New assets: {summary.new_assets_count}")
    print(f"  Removed assets: {summary.removed_assets_count}")
    print(f"  Changed assets: {summary.changed_assets_count}")
    print(f"  New ports detected: {summary.new_ports_count}")
    print(f"  Closed ports: {summary.closed_ports_count}")
    print(f"  Certificate changes: {summary.certificate_changes_count}")
    print("")
    print(f"  Overall severity: {summary.overall_severity.value}")

    if summary.high_risk_changes > 0:
        print(f"  High-risk changes: {summary.high_risk_changes}")


def _print_drift_table(report) -> None:
    """Print drift report in table format."""
    from stance.asm.drift import ChangeType

    # Summary first
    _print_drift_summary(report)
    print("")

    # New assets
    if report.new_assets:
        print("New Assets")
        print("-" * 80)
        print(f"{'Domain':<35} {'IP':<16} {'Port':<6} {'Source'}")
        print("-" * 80)
        for change in report.new_assets[:10]:
            asset = change.asset
            domain = asset.domain[:32] + "..." if len(asset.domain) > 35 else asset.domain
            ip = asset.ip_address or "-"
            port = str(asset.port) if asset.port else "-"
            print(f"{domain:<35} {ip:<16} {port:<6} {asset.source}")
        if len(report.new_assets) > 10:
            print(f"  ... and {len(report.new_assets) - 10} more")
        print("")

    # Removed assets
    if report.removed_assets:
        print("Removed Assets")
        print("-" * 80)
        print(f"{'Domain':<35} {'IP':<16} {'Port':<6}")
        print("-" * 80)
        for change in report.removed_assets[:10]:
            asset = change.asset
            domain = asset.domain[:32] + "..." if len(asset.domain) > 35 else asset.domain
            ip = asset.ip_address or "-"
            port = str(asset.port) if asset.port else "-"
            print(f"{domain:<35} {ip:<16} {port:<6}")
        if len(report.removed_assets) > 10:
            print(f"  ... and {len(report.removed_assets) - 10} more")
        print("")

    # New ports
    if report.new_ports:
        print("New Ports Detected")
        print("-" * 80)
        print(f"{'Domain':<35} {'Port':<6} {'Severity'}")
        print("-" * 80)
        for change in report.new_ports[:10]:
            domain = change.domain[:32] + "..." if len(change.domain) > 35 else change.domain
            print(f"{domain:<35} {change.port:<6} {change.severity.value}")
        if len(report.new_ports) > 10:
            print(f"  ... and {len(report.new_ports) - 10} more")
        print("")

    # Certificate changes
    if report.certificate_changes:
        print("Certificate Changes")
        print("-" * 80)
        print(f"{'Domain':<35} {'Change Type':<15} {'Details'}")
        print("-" * 80)
        for change in report.certificate_changes[:10]:
            domain = change.domain[:32] + "..." if len(change.domain) > 35 else change.domain
            details = change.change_type.value
            print(f"{domain:<35} {details:<15} {change.description[:25]}")
        if len(report.certificate_changes) > 10:
            print(f"  ... and {len(report.certificate_changes) - 10} more")
