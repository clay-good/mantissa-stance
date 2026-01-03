"""
CLI command handlers for Identity Security.

Provides commands for:
- Analyzing data access mappings
- Detecting principal exposure to sensitive data
- Finding over-privileged access
"""

from __future__ import annotations

import argparse
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def cmd_identity(args: argparse.Namespace) -> int:
    """
    Route Identity subcommands to appropriate handlers.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "identity_action", None)

    if action is None:
        print("Usage: stance identity <command>")
        print("")
        print("Commands:")
        print("  who-can-access     Show who can access a resource")
        print("  exposure           Analyze principal exposure to sensitive data")
        print("  overprivileged     Find over-privileged principals")
        print("")
        print("Run 'stance identity <command> --help' for more information")
        return 0

    handlers = {
        "who-can-access": _cmd_identity_who_can_access,
        "exposure": _cmd_identity_exposure,
        "overprivileged": _cmd_identity_overprivileged,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown identity command: {action}")
    return 1


def _cmd_identity_who_can_access(args: argparse.Namespace) -> int:
    """
    Show which principals can access a given resource.
    """
    from stance.identity import (
        AWSDataAccessMapper,
        GCPDataAccessMapper,
        AzureDataAccessMapper,
        IdentityConfig,
    )

    resource = args.resource
    cloud = args.cloud
    output_format = getattr(args, "format", "table")

    try:
        # Create config
        config = IdentityConfig(
            include_users=getattr(args, "include_users", True),
            include_roles=getattr(args, "include_roles", True),
            include_groups=getattr(args, "include_groups", True),
            include_service_accounts=getattr(args, "include_service_accounts", True),
        )

        # Select mapper based on cloud provider
        if cloud == "aws":
            mapper = AWSDataAccessMapper(config)
        elif cloud == "gcp":
            mapper = GCPDataAccessMapper(config)
        elif cloud == "azure":
            mapper = AzureDataAccessMapper(config)
        else:
            print(f"Error: Unknown cloud provider: {cloud}")
            return 1

        print(f"Analyzing who can access {resource}...")
        result = mapper.who_can_access(resource)

        # Output results
        if output_format == "json":
            output = {
                "resource": result.resource_id,
                "cloud": result.cloud_provider,
                "principals": [
                    {
                        "principal_id": access.principal.id if access.principal else None,
                        "principal_type": access.principal.type.value if access.principal and access.principal.type else None,
                        "principal_name": access.principal.name if access.principal else None,
                        "permission_level": access.permission_level.value if access.permission_level else None,
                        "source": access.source,
                    }
                    for access in result.access_list
                ] if result.access_list else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Resource: {result.resource_id}")
            print(f"Cloud: {result.cloud_provider}")
            print("")

            if result.access_list:
                print("Principals with Access:")
                print("-" * 100)
                print(f"{'Principal':<40} {'Type':<18} {'Permission':<12} {'Source'}")
                print("-" * 100)

                for access in result.access_list[:50]:
                    principal = access.principal
                    name = principal.name if principal else "Unknown"
                    name = name[:37] + "..." if len(name) > 40 else name
                    ptype = principal.type.value if principal and principal.type else "N/A"
                    perm = access.permission_level.value if access.permission_level else "N/A"
                    source = access.source[:30] if access.source else "N/A"
                    print(f"{name:<40} {ptype:<18} {perm:<12} {source}")

                if len(result.access_list) > 50:
                    print(f"... and {len(result.access_list) - 50} more principals")
                print("")
                print(f"Total: {len(result.access_list)} principals can access this resource")
            else:
                print("No principals found with access to this resource.")

        return 0

    except Exception as e:
        logger.error(f"Identity analysis failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_identity_exposure(args: argparse.Namespace) -> int:
    """
    Analyze what sensitive data a principal can access.
    """
    from stance.identity.exposure import PrincipalExposureAnalyzer

    principal = args.principal
    output_format = getattr(args, "format", "table")
    classification_filter = getattr(args, "classification", None)

    try:
        analyzer = PrincipalExposureAnalyzer()

        print(f"Analyzing sensitive data exposure for {principal}...")
        result = analyzer.analyze_principal_exposure(principal)

        # Output results
        if output_format == "json":
            output = {
                "principal": result.principal_id,
                "summary": {
                    "total_resources": result.summary.total_resources if result.summary else 0,
                    "sensitive_resources": result.summary.sensitive_resources if result.summary else 0,
                    "critical_exposures": result.summary.critical_exposures if result.summary else 0,
                    "high_exposures": result.summary.high_exposures if result.summary else 0,
                },
                "risk_score": result.risk_score,
                "exposures": [
                    {
                        "resource_id": exp.resource.resource_id if exp.resource else None,
                        "classification": exp.resource.classification.value if exp.resource and exp.resource.classification else None,
                        "categories": [c.value for c in exp.resource.categories] if exp.resource and exp.resource.categories else [],
                        "severity": exp.severity.value if exp.severity else None,
                        "permission_level": exp.permission_level.value if exp.permission_level else None,
                    }
                    for exp in result.exposures
                ] if result.exposures else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Principal: {result.principal_id}")
            if result.summary:
                print(f"Total resources accessible: {result.summary.total_resources}")
                print(f"Sensitive resources: {result.summary.sensitive_resources}")
                print(f"Critical exposures: {result.summary.critical_exposures}")
                print(f"High exposures: {result.summary.high_exposures}")
            print(f"Risk Score: {result.risk_score}/100")
            print("")

            exposures = result.exposures or []
            if classification_filter:
                exposures = [e for e in exposures if e.resource and e.resource.classification and e.resource.classification.value == classification_filter]

            if exposures:
                print("Sensitive Data Exposures:")
                print("-" * 100)
                print(f"{'Resource':<40} {'Classification':<15} {'Severity':<10} {'Permission':<10} {'Categories'}")
                print("-" * 100)

                for exp in exposures[:50]:
                    resource = exp.resource
                    res_id = resource.resource_id[:37] + "..." if resource and len(resource.resource_id) > 40 else (resource.resource_id if resource else "N/A")
                    classification = resource.classification.value if resource and resource.classification else "N/A"
                    severity = exp.severity.value if exp.severity else "N/A"
                    perm = exp.permission_level.value if exp.permission_level else "N/A"
                    cats = ", ".join(c.value for c in resource.categories[:2]) if resource and resource.categories else "N/A"
                    print(f"{res_id:<40} {classification:<15} {severity:<10} {perm:<10} {cats}")

                if len(exposures) > 50:
                    print(f"... and {len(exposures) - 50} more exposures")
            else:
                print("No sensitive data exposures found for this principal.")

        return 0

    except Exception as e:
        logger.error(f"Identity exposure analysis failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_identity_overprivileged(args: argparse.Namespace) -> int:
    """
    Find over-privileged principals.
    """
    from stance.identity.overprivileged import OverPrivilegedAnalyzer

    cloud = args.cloud
    output_format = getattr(args, "format", "table")
    days = getattr(args, "days", 90)

    try:
        analyzer = OverPrivilegedAnalyzer(
            cloud_provider=cloud,
            lookback_days=days,
        )

        print(f"Analyzing over-privileged access for {cloud}...")
        result = analyzer.analyze()

        # Output results
        if output_format == "json":
            output = {
                "cloud": result.cloud_provider,
                "analysis_period_days": result.analysis_period_days,
                "summary": {
                    "total_principals": result.summary.total_principals if result.summary else 0,
                    "over_privileged_count": result.summary.over_privileged_count if result.summary else 0,
                    "unused_admin_count": result.summary.unused_admin_count if result.summary else 0,
                    "stale_elevated_count": result.summary.stale_elevated_count if result.summary else 0,
                },
                "findings": [
                    {
                        "principal": f.principal,
                        "principal_type": f.principal_type.value if f.principal_type else None,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "granted_permission": f.granted_permission.value if f.granted_permission else None,
                        "observed_permission": f.observed_permission.value if f.observed_permission else None,
                        "days_inactive": f.days_inactive,
                        "risk_score": f.risk_score,
                        "recommendation": f.recommendation,
                    }
                    for f in result.findings
                ] if result.findings else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Cloud: {result.cloud_provider}")
            print(f"Analysis period: {result.analysis_period_days} days")
            if result.summary:
                print(f"Total principals analyzed: {result.summary.total_principals}")
                print(f"Over-privileged: {result.summary.over_privileged_count}")
                print(f"Unused admin access: {result.summary.unused_admin_count}")
                print(f"Stale elevated access: {result.summary.stale_elevated_count}")
            print("")

            if result.findings:
                print("Over-Privileged Access Findings:")
                print("-" * 120)
                print(f"{'Principal':<35} {'Type':<15} {'Finding':<22} {'Granted':<10} {'Used':<10} {'Days':<6} {'Risk'}")
                print("-" * 120)

                for finding in result.findings[:50]:
                    principal = finding.principal[:32] + "..." if len(finding.principal) > 35 else finding.principal
                    ptype = finding.principal_type.value if finding.principal_type else "N/A"
                    ftype = finding.finding_type.value if finding.finding_type else "N/A"
                    granted = finding.granted_permission.value if finding.granted_permission else "N/A"
                    observed = finding.observed_permission.value if finding.observed_permission else "N/A"
                    days_inactive = str(finding.days_inactive) if finding.days_inactive else "N/A"
                    risk = str(finding.risk_score) if finding.risk_score else "N/A"
                    print(f"{principal:<35} {ptype:<15} {ftype:<22} {granted:<10} {observed:<10} {days_inactive:<6} {risk}")

                if len(result.findings) > 50:
                    print(f"... and {len(result.findings) - 50} more findings")
            else:
                print("No over-privileged access detected.")

        return 0

    except Exception as e:
        logger.error(f"Over-privileged analysis failed: {e}")
        print(f"Error: {e}")
        return 1
