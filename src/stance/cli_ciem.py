"""
CLI commands for Cloud Infrastructure Entitlement Management (CIEM).

Provides command-line interface for:
- Effective permissions calculation
- Overprivileged identity detection
- Cross-account trust analysis
- Privilege escalation path detection
"""

import argparse
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def add_ciem_parser(subparsers: Any) -> None:
    """Add CIEM command parser."""
    ciem_parser = subparsers.add_parser(
        "ciem",
        help="CIEM - Cloud Infrastructure Entitlement Management",
    )

    ciem_subparsers = ciem_parser.add_subparsers(dest="ciem_action")

    # ciem permissions
    permissions_parser = ciem_subparsers.add_parser(
        "permissions",
        help="Calculate effective permissions for identities",
    )
    permissions_parser.add_argument(
        "--identity",
        "-i",
        help="Specific identity to analyze (ARN, email, or name)",
    )
    permissions_parser.add_argument(
        "--provider",
        "-p",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Cloud provider (default: aws)",
    )
    permissions_parser.add_argument(
        "--admin-only",
        action="store_true",
        help="Show only identities with admin access",
    )
    permissions_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # ciem overprivileged
    overpriv_parser = ciem_subparsers.add_parser(
        "overprivileged",
        help="Find overprivileged identities",
    )
    overpriv_parser.add_argument(
        "--provider",
        "-p",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Cloud provider (default: aws)",
    )
    overpriv_parser.add_argument(
        "--min-unused",
        type=float,
        default=20.0,
        help="Minimum unused permission percentage (default: 20)",
    )
    overpriv_parser.add_argument(
        "--lookback-days",
        type=int,
        default=90,
        help="Days of usage data to analyze (default: 90)",
    )
    overpriv_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # ciem trust
    trust_parser = ciem_subparsers.add_parser(
        "trust",
        help="Analyze cross-account trust relationships",
    )
    trust_parser.add_argument(
        "--provider",
        "-p",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Cloud provider (default: aws)",
    )
    trust_parser.add_argument(
        "--external-only",
        action="store_true",
        help="Show only external/cross-account trusts",
    )
    trust_parser.add_argument(
        "--high-risk",
        action="store_true",
        help="Show only high-risk trusts",
    )
    trust_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # ciem privesc
    privesc_parser = ciem_subparsers.add_parser(
        "privesc",
        help="Detect privilege escalation paths",
    )
    privesc_parser.add_argument(
        "--provider",
        "-p",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Cloud provider (default: aws)",
    )
    privesc_parser.add_argument(
        "--identity",
        "-i",
        help="Specific identity to analyze",
    )
    privesc_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # ciem summary
    summary_parser = ciem_subparsers.add_parser(
        "summary",
        help="Show CIEM summary across all identities",
    )
    summary_parser.add_argument(
        "--provider",
        "-p",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Cloud provider (default: aws)",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_ciem(args: argparse.Namespace) -> int:
    """Handle CIEM commands."""
    action = getattr(args, "ciem_action", None)

    if action == "permissions":
        return _ciem_permissions(args)
    elif action == "overprivileged":
        return _ciem_overprivileged(args)
    elif action == "trust":
        return _ciem_trust(args)
    elif action == "privesc":
        return _ciem_privesc(args)
    elif action == "summary":
        return _ciem_summary(args)
    else:
        print("Usage: stance ciem <command>")
        print("")
        print("Commands:")
        print("  permissions    Calculate effective permissions for identities")
        print("  overprivileged Find overprivileged identities (unused permissions)")
        print("  trust          Analyze cross-account trust relationships")
        print("  privesc        Detect privilege escalation paths")
        print("  summary        Show CIEM summary")
        return 1


def _ciem_permissions(args: argparse.Namespace) -> int:
    """Calculate effective permissions."""
    provider = args.provider
    identity_filter = getattr(args, "identity", None)
    admin_only = getattr(args, "admin_only", False)
    output_format = getattr(args, "format", "table")

    try:
        from stance.ciem import EffectivePermissionsCalculator
        from stance.storage import get_storage

        storage = get_storage()
        assets = storage.get_assets()

        # Filter to identities
        identity_types = [
            f"{provider}_iam_user",
            f"{provider}_iam_role",
            f"{provider}_service_account",
        ]
        identities = [a for a in assets if a.resource_type in identity_types]

        # Filter to policies
        policy_types = [f"{provider}_iam_policy"]
        policies = [a for a in assets if a.resource_type in policy_types]

        if identity_filter:
            identities = [
                i for i in identities
                if identity_filter.lower() in i.id.lower()
                or identity_filter.lower() in i.name.lower()
            ]

        calculator = EffectivePermissionsCalculator(provider=provider)
        results = calculator.calculate_all(identities, policies)

        if admin_only:
            results = [r for r in results if r.is_admin]

        if output_format == "json":
            print(json.dumps({
                "identities": [r.to_dict() for r in results]
            }, indent=2))
        else:
            print("\nEffective Permissions Analysis")
            print("=" * 90)
            print(f"{'Identity':<40} {'Type':<15} {'Services':<10} {'Admin':<8} {'Risk':<10}")
            print("-" * 90)
            for r in results[:50]:
                admin_str = "YES" if r.is_admin else "no"
                print(
                    f"{r.identity_name[:39]:<40} "
                    f"{r.identity_type:<15} "
                    f"{r.permission_set.service_count:<10} "
                    f"{admin_str:<8} "
                    f"{r.risk_score:.1f}"
                )
            if len(results) > 50:
                print(f"\n... and {len(results) - 50} more identities")

            print(f"\nTotal: {len(results)} identities")
            print(f"Admin access: {sum(1 for r in results if r.is_admin)}")

        return 0

    except Exception as e:
        logger.error(f"Error calculating permissions: {e}")
        print(f"Error: {e}")
        return 1


def _ciem_overprivileged(args: argparse.Namespace) -> int:
    """Find overprivileged identities."""
    provider = args.provider
    min_unused = getattr(args, "min_unused", 20.0)
    lookback_days = getattr(args, "lookback_days", 90)
    output_format = getattr(args, "format", "table")

    try:
        from stance.ciem import EffectivePermissionsCalculator, OverprivilegedDetector
        from stance.storage import get_storage

        storage = get_storage()
        assets = storage.get_assets()

        # Get identities and policies
        identity_types = [
            f"{provider}_iam_user",
            f"{provider}_iam_role",
            f"{provider}_service_account",
        ]
        identities = [a for a in assets if a.resource_type in identity_types]
        policies = [a for a in assets if a.resource_type == f"{provider}_iam_policy"]

        # Calculate effective permissions
        calculator = EffectivePermissionsCalculator(provider=provider)
        effective_access = calculator.calculate_all(identities, policies)

        # Detect overprivileged
        detector = OverprivilegedDetector(
            lookback_days=lookback_days,
            min_unused_percentage=min_unused,
        )

        # Note: In production, usage_data would come from CloudTrail/audit logs
        findings = detector.detect_all(effective_access, usage_data={})

        if output_format == "json":
            print(json.dumps({
                "overprivileged": [f.to_dict() for f in findings]
            }, indent=2))
        else:
            print("\nOverprivileged Identities")
            print("=" * 100)
            if findings:
                print(f"{'Identity':<35} {'Type':<12} {'Unused %':<10} {'Unused':<10} {'Severity':<10}")
                print("-" * 100)
                for f in findings[:30]:
                    print(
                        f"{f.identity_name[:34]:<35} "
                        f"{f.identity_type:<12} "
                        f"{f.unused_percentage:.1f}%{'':<5} "
                        f"{len(f.unused_permissions):<10} "
                        f"{f.severity.value:<10}"
                    )
                if len(findings) > 30:
                    print(f"\n... and {len(findings) - 30} more identities")
            else:
                print("No overprivileged identities found.")

            print(f"\nTotal overprivileged: {len(findings)}")

        return 0

    except Exception as e:
        logger.error(f"Error detecting overprivileged: {e}")
        print(f"Error: {e}")
        return 1


def _ciem_trust(args: argparse.Namespace) -> int:
    """Analyze trust relationships."""
    provider = args.provider
    external_only = getattr(args, "external_only", False)
    high_risk = getattr(args, "high_risk", False)
    output_format = getattr(args, "format", "table")

    try:
        from stance.ciem import TrustAnalyzer, TrustRisk
        from stance.storage import get_storage

        storage = get_storage()
        assets = storage.get_assets()

        # Get roles
        role_types = [f"{provider}_iam_role"]
        roles = [a for a in assets if a.resource_type in role_types]

        analyzer = TrustAnalyzer()
        trusts = analyzer.analyze_all(roles)

        if external_only:
            trusts = [t for t in trusts if t.is_cross_account]

        if high_risk:
            trusts = [t for t in trusts if t.risk in [TrustRisk.HIGH, TrustRisk.CRITICAL]]

        if output_format == "json":
            print(json.dumps({
                "trust_relationships": [t.to_dict() for t in trusts]
            }, indent=2))
        else:
            print("\nCross-Account Trust Relationships")
            print("=" * 110)
            if trusts:
                print(f"{'Role':<30} {'Trusts':<35} {'Type':<20} {'Risk':<10}")
                print("-" * 110)
                for t in trusts[:40]:
                    print(
                        f"{t.source_name[:29]:<30} "
                        f"{t.target_principal[:34]:<35} "
                        f"{t.trust_type.value:<20} "
                        f"{t.risk.value:<10}"
                    )
                if len(trusts) > 40:
                    print(f"\n... and {len(trusts) - 40} more trust relationships")
            else:
                print("No trust relationships found.")

            # Summary
            critical = sum(1 for t in trusts if t.risk == TrustRisk.CRITICAL)
            high = sum(1 for t in trusts if t.risk == TrustRisk.HIGH)
            print(f"\nTotal: {len(trusts)} | Critical: {critical} | High: {high}")

        return 0

    except Exception as e:
        logger.error(f"Error analyzing trust: {e}")
        print(f"Error: {e}")
        return 1


def _ciem_privesc(args: argparse.Namespace) -> int:
    """Detect privilege escalation paths."""
    provider = args.provider
    identity_filter = getattr(args, "identity", None)
    output_format = getattr(args, "format", "table")

    try:
        from stance.ciem import PrivilegeEscalationAnalyzer, EffectivePermissionsCalculator
        from stance.storage import get_storage

        storage = get_storage()
        assets = storage.get_assets()

        # Get identities
        identity_types = [
            f"{provider}_iam_user",
            f"{provider}_iam_role",
            f"{provider}_service_account",
        ]
        identities = [a for a in assets if a.resource_type in identity_types]
        policies = [a for a in assets if a.resource_type == f"{provider}_iam_policy"]
        roles = [a for a in assets if a.resource_type == f"{provider}_iam_role"]

        if identity_filter:
            identities = [
                i for i in identities
                if identity_filter.lower() in i.id.lower()
                or identity_filter.lower() in i.name.lower()
            ]

        # Calculate permissions for each identity
        calc = EffectivePermissionsCalculator(provider=provider)
        permissions_map = {}
        for identity in identities:
            attached_policies = identity.properties.get("attached_policies", [])
            attached = [p for p in policies if p.properties.get("arn") in attached_policies]
            access = calc.calculate_effective_permissions(identity, attached)
            permissions_map[identity.id] = [
                f"{p.service}:{p.action}"
                for p in access.permission_set.permissions
                if p.effect.value == "allow"
            ]

        # Detect escalation paths
        analyzer = PrivilegeEscalationAnalyzer(provider=provider)
        paths = analyzer.analyze_all(identities, permissions_map, roles)

        if output_format == "json":
            print(json.dumps({
                "escalation_paths": [p.to_dict() for p in paths]
            }, indent=2))
        else:
            print("\nPrivilege Escalation Paths")
            print("=" * 100)
            if paths:
                print(f"{'Identity':<30} {'Technique':<25} {'Final Access':<30} {'Severity':<10}")
                print("-" * 100)
                for p in paths[:30]:
                    print(
                        f"{p.identity_name[:29]:<30} "
                        f"{p.escalation_type.value:<25} "
                        f"{p.final_access[:29]:<30} "
                        f"{p.severity.value:<10}"
                    )
                if len(paths) > 30:
                    print(f"\n... and {len(paths) - 30} more paths")
            else:
                print("No privilege escalation paths found.")

            critical = sum(1 for p in paths if p.severity.value == "critical")
            high = sum(1 for p in paths if p.severity.value == "high")
            print(f"\nTotal: {len(paths)} | Critical: {critical} | High: {high}")

        return 0

    except Exception as e:
        logger.error(f"Error detecting privesc: {e}")
        print(f"Error: {e}")
        return 1


def _ciem_summary(args: argparse.Namespace) -> int:
    """Show CIEM summary."""
    provider = args.provider
    output_format = getattr(args, "format", "table")

    try:
        from stance.ciem import (
            EffectivePermissionsCalculator,
            OverprivilegedDetector,
            TrustAnalyzer,
            TrustRisk,
        )
        from stance.storage import get_storage

        storage = get_storage()
        assets = storage.get_assets()

        # Get identities
        identity_types = [
            f"{provider}_iam_user",
            f"{provider}_iam_role",
            f"{provider}_service_account",
        ]
        identities = [a for a in assets if a.resource_type in identity_types]
        policies = [a for a in assets if a.resource_type == f"{provider}_iam_policy"]
        roles = [a for a in assets if a.resource_type == f"{provider}_iam_role"]

        # Calculate permissions
        calc = EffectivePermissionsCalculator(provider=provider)
        effective_access = calc.calculate_all(identities, policies)

        admin_count = sum(1 for a in effective_access if a.is_admin)
        high_risk = sum(1 for a in effective_access if a.risk_score >= 70)

        # Detect overprivileged
        detector = OverprivilegedDetector()
        overprivileged = detector.detect_all(effective_access, usage_data={})

        # Analyze trust
        analyzer = TrustAnalyzer()
        trusts = analyzer.analyze_all(roles)
        risky_trusts = sum(
            1 for t in trusts
            if t.risk in [TrustRisk.HIGH, TrustRisk.CRITICAL]
        )

        summary = {
            "provider": provider,
            "total_identities": len(identities),
            "users": sum(1 for i in identities if "user" in i.resource_type),
            "roles": sum(1 for i in identities if "role" in i.resource_type),
            "service_accounts": sum(1 for i in identities if "service_account" in i.resource_type),
            "admin_access": admin_count,
            "high_risk_identities": high_risk,
            "overprivileged": len(overprivileged),
            "trust_relationships": len(trusts),
            "risky_trusts": risky_trusts,
        }

        if output_format == "json":
            print(json.dumps(summary, indent=2))
        else:
            print("\nCIEM Summary")
            print("=" * 50)
            print(f"Provider: {provider.upper()}")
            print("")
            print("Identities:")
            print(f"  Total:            {summary['total_identities']}")
            print(f"  Users:            {summary['users']}")
            print(f"  Roles:            {summary['roles']}")
            print(f"  Service Accounts: {summary['service_accounts']}")
            print("")
            print("Risk Assessment:")
            print(f"  Admin Access:     {summary['admin_access']}")
            print(f"  High Risk:        {summary['high_risk_identities']}")
            print(f"  Overprivileged:   {summary['overprivileged']}")
            print("")
            print("Trust Relationships:")
            print(f"  Total:            {summary['trust_relationships']}")
            print(f"  Risky:            {summary['risky_trusts']}")

        return 0

    except Exception as e:
        logger.error(f"Error generating summary: {e}")
        print(f"Error: {e}")
        return 1
