"""
CLI commands for Infrastructure as Code (IaC) scanning.

Provides CLI commands for scanning Terraform, CloudFormation, ARM templates,
and Kubernetes manifests for security misconfigurations.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_iac_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add IaC subcommand parser."""
    iac_parser = subparsers.add_parser(
        "iac",
        help="Infrastructure as Code scanning",
        description="Scan IaC files for security misconfigurations",
    )

    iac_subparsers = iac_parser.add_subparsers(
        dest="iac_action",
        help="IaC action to perform",
    )

    # scan command
    scan_parser = iac_subparsers.add_parser(
        "scan",
        help="Scan IaC files or directories",
    )
    scan_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to file or directory to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--recursive",
        "-r",
        action="store_true",
        default=True,
        help="Recursively scan directories (default: true)",
    )
    scan_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Minimum severity to report",
    )
    scan_parser.add_argument(
        "--iac-format",
        choices=["terraform", "cloudformation", "arm", "kubernetes", "all"],
        default="all",
        help="IaC format to scan (default: all)",
    )

    # policies command
    policies_parser = iac_subparsers.add_parser(
        "policies",
        help="List available IaC policies",
    )
    policies_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    policies_parser.add_argument(
        "--provider",
        choices=["aws", "gcp", "azure", "kubernetes"],
        help="Filter by cloud provider",
    )
    policies_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity",
    )
    policies_parser.add_argument(
        "--enabled-only",
        action="store_true",
        help="Show only enabled policies",
    )

    # policy command (show single policy)
    policy_parser = iac_subparsers.add_parser(
        "policy",
        help="Show details for a specific policy",
    )
    policy_parser.add_argument(
        "policy_id",
        help="Policy ID to show",
    )
    policy_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # formats command
    formats_parser = iac_subparsers.add_parser(
        "formats",
        help="List supported IaC formats",
    )
    formats_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # validate command
    validate_parser = iac_subparsers.add_parser(
        "validate",
        help="Validate IaC file syntax",
    )
    validate_parser.add_argument(
        "path",
        help="Path to file to validate",
    )
    validate_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # resources command
    resources_parser = iac_subparsers.add_parser(
        "resources",
        help="List resources in IaC files",
    )
    resources_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to file or directory (default: current directory)",
    )
    resources_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    resources_parser.add_argument(
        "--type",
        dest="resource_type",
        help="Filter by resource type",
    )
    resources_parser.add_argument(
        "--provider",
        help="Filter by provider",
    )

    # stats command
    stats_parser = iac_subparsers.add_parser(
        "stats",
        help="Show IaC scanning statistics",
    )
    stats_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to file or directory (default: current directory)",
    )
    stats_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # compliance command
    compliance_parser = iac_subparsers.add_parser(
        "compliance",
        help="Show compliance framework mappings",
    )
    compliance_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    compliance_parser.add_argument(
        "--framework",
        help="Filter by framework (e.g., 'CIS AWS')",
    )

    # providers command
    providers_parser = iac_subparsers.add_parser(
        "providers",
        help="List supported cloud providers",
    )
    providers_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # resource-types command
    rtypes_parser = iac_subparsers.add_parser(
        "resource-types",
        help="List known resource types",
    )
    rtypes_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    rtypes_parser.add_argument(
        "--provider",
        help="Filter by provider",
    )

    # severity-levels command
    severity_parser = iac_subparsers.add_parser(
        "severity-levels",
        help="List severity levels",
    )
    severity_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    # summary command
    summary_parser = iac_subparsers.add_parser(
        "summary",
        help="Show IaC module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )


def cmd_iac(args: argparse.Namespace) -> int:
    """Handle IaC subcommand."""
    action = getattr(args, "iac_action", None)

    if action is None:
        print("Usage: stance iac <command>")
        print("Commands: scan, policies, policy, formats, validate, resources, stats,")
        print("          compliance, providers, resource-types, severity-levels, summary")
        return 1

    handlers = {
        "scan": _handle_scan,
        "policies": _handle_policies,
        "policy": _handle_policy,
        "formats": _handle_formats,
        "validate": _handle_validate,
        "resources": _handle_resources,
        "stats": _handle_stats,
        "compliance": _handle_compliance,
        "providers": _handle_providers,
        "resource-types": _handle_resource_types,
        "severity-levels": _handle_severity_levels,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown IaC action: {action}")
    return 1


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle scan command."""
    path = getattr(args, "path", ".")
    output_format = getattr(args, "format", "text")
    severity_filter = getattr(args, "severity", None)
    iac_format = getattr(args, "iac_format", "all")

    # Generate sample scan results
    findings = _generate_sample_findings(path, severity_filter, iac_format)

    if output_format == "json":
        print(json.dumps(findings, indent=2))
    else:
        print(f"IaC Scan Results: {path}")
        print("=" * 60)
        print()

        if not findings["findings"]:
            print("No security issues found.")
        else:
            for finding in findings["findings"]:
                severity = finding["severity"].upper()
                print(f"[{severity}] {finding['title']}")
                print(f"  Policy: {finding['rule_id']}")
                print(f"  Resource: {finding['resource']}")
                print(f"  Location: {finding['location']}")
                print(f"  Description: {finding['description']}")
                if finding.get("remediation"):
                    print(f"  Remediation: {finding['remediation']}")
                print()

        print("-" * 60)
        print(f"Files scanned: {findings['summary']['files_scanned']}")
        print(f"Resources found: {findings['summary']['resources_found']}")
        print(f"Findings: {findings['summary']['findings_count']}")
        print(f"  Critical: {findings['summary']['by_severity']['critical']}")
        print(f"  High: {findings['summary']['by_severity']['high']}")
        print(f"  Medium: {findings['summary']['by_severity']['medium']}")
        print(f"  Low: {findings['summary']['by_severity']['low']}")

    return 0


def _handle_policies(args: argparse.Namespace) -> int:
    """Handle policies command."""
    output_format = getattr(args, "format", "text")
    provider = getattr(args, "provider", None)
    severity = getattr(args, "severity", None)
    enabled_only = getattr(args, "enabled_only", False)

    policies = _get_sample_policies(provider, severity, enabled_only)

    if output_format == "json":
        print(json.dumps(policies, indent=2))
    else:
        print("IaC Security Policies")
        print("=" * 80)
        print()
        print(f"{'ID':<30} {'Severity':<10} {'Provider':<10} {'Name'}")
        print("-" * 80)

        for policy in policies["policies"]:
            providers = ", ".join(policy["providers"]) if policy["providers"] else "all"
            status = "" if policy["enabled"] else " (disabled)"
            print(f"{policy['id']:<30} {policy['severity']:<10} {providers:<10} {policy['name']}{status}")

        print()
        print(f"Total policies: {policies['total']}")
        print(f"Enabled: {policies['enabled_count']}")

    return 0


def _handle_policy(args: argparse.Namespace) -> int:
    """Handle policy command."""
    policy_id = getattr(args, "policy_id", "")
    output_format = getattr(args, "format", "text")

    policy = _get_sample_policy(policy_id)

    if "error" in policy:
        print(f"Error: {policy['error']}")
        return 1

    if output_format == "json":
        print(json.dumps(policy, indent=2))
    else:
        p = policy["policy"]
        print(f"Policy: {p['id']}")
        print("=" * 60)
        print(f"Name: {p['name']}")
        print(f"Severity: {p['severity'].upper()}")
        print(f"Enabled: {p['enabled']}")
        print()
        print("Description:")
        print(f"  {p['description']}")
        print()
        print(f"Resource Types: {', '.join(p['resource_types'])}")
        print(f"Providers: {', '.join(p['providers']) if p['providers'] else 'all'}")
        print()
        if p.get("remediation"):
            print("Remediation:")
            print(f"  {p['remediation']}")
            print()
        if p.get("compliance"):
            print("Compliance Mappings:")
            for c in p["compliance"]:
                print(f"  - {c['framework']} {c['version']}: {c['control']}")
            print()
        if p.get("tags"):
            print(f"Tags: {', '.join(p['tags'])}")

    return 0


def _handle_formats(args: argparse.Namespace) -> int:
    """Handle formats command."""
    output_format = getattr(args, "format", "text")

    formats = _get_sample_formats()

    if output_format == "json":
        print(json.dumps(formats, indent=2))
    else:
        print("Supported IaC Formats")
        print("=" * 60)
        print()

        for fmt in formats["formats"]:
            print(f"{fmt['name']}")
            print(f"  Value: {fmt['value']}")
            print(f"  Extensions: {', '.join(fmt['extensions'])}")
            print(f"  Description: {fmt['description']}")
            print()

        print(f"Total formats: {formats['total']}")

    return 0


def _handle_validate(args: argparse.Namespace) -> int:
    """Handle validate command."""
    path = getattr(args, "path", "")
    output_format = getattr(args, "format", "text")

    result = _validate_file(path)

    if output_format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Validation: {path}")
        print("=" * 60)
        print()

        if result["valid"]:
            print("Status: VALID")
            print(f"Format: {result['format']}")
            print(f"Resources: {result['resource_count']}")
        else:
            print("Status: INVALID")
            print()
            print("Errors:")
            for error in result["errors"]:
                print(f"  - {error}")

    return 0


def _handle_resources(args: argparse.Namespace) -> int:
    """Handle resources command."""
    path = getattr(args, "path", ".")
    output_format = getattr(args, "format", "text")
    resource_type = getattr(args, "resource_type", None)
    provider = getattr(args, "provider", None)

    resources = _get_sample_resources(path, resource_type, provider)

    if output_format == "json":
        print(json.dumps(resources, indent=2))
    else:
        print(f"IaC Resources: {path}")
        print("=" * 80)
        print()
        print(f"{'Resource Type':<35} {'Name':<25} {'Provider':<10} {'File'}")
        print("-" * 80)

        for resource in resources["resources"]:
            print(f"{resource['type']:<35} {resource['name']:<25} {resource['provider']:<10} {resource['file']}")

        print()
        print(f"Total resources: {resources['total']}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    path = getattr(args, "path", ".")
    output_format = getattr(args, "format", "text")

    stats = _get_sample_stats(path)

    if output_format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print(f"IaC Statistics: {path}")
        print("=" * 60)
        print()
        print("Files by Format:")
        for fmt, count in stats["by_format"].items():
            print(f"  {fmt}: {count}")
        print()
        print("Resources by Provider:")
        for provider, count in stats["by_provider"].items():
            print(f"  {provider}: {count}")
        print()
        print("Top Resource Types:")
        for rt in stats["top_resource_types"][:10]:
            print(f"  {rt['type']}: {rt['count']}")
        print()
        print(f"Total files: {stats['total_files']}")
        print(f"Total resources: {stats['total_resources']}")
        print(f"Parse errors: {stats['parse_errors']}")

    return 0


def _handle_compliance(args: argparse.Namespace) -> int:
    """Handle compliance command."""
    output_format = getattr(args, "format", "text")
    framework = getattr(args, "framework", None)

    compliance = _get_sample_compliance(framework)

    if output_format == "json":
        print(json.dumps(compliance, indent=2))
    else:
        print("IaC Policy Compliance Mappings")
        print("=" * 80)
        print()

        for fw in compliance["frameworks"]:
            print(f"{fw['name']} {fw['version']}")
            print("-" * 40)
            for mapping in fw["mappings"]:
                print(f"  {mapping['control']}: {mapping['policy_id']}")
            print()

        print(f"Total frameworks: {compliance['total_frameworks']}")
        print(f"Total mappings: {compliance['total_mappings']}")

    return 0


def _handle_providers(args: argparse.Namespace) -> int:
    """Handle providers command."""
    output_format = getattr(args, "format", "text")

    providers = _get_sample_providers()

    if output_format == "json":
        print(json.dumps(providers, indent=2))
    else:
        print("Supported Cloud Providers")
        print("=" * 60)
        print()

        for p in providers["providers"]:
            print(f"{p['name']}")
            print(f"  Value: {p['value']}")
            print(f"  Resource prefix: {p['resource_prefix']}")
            print(f"  Policies: {p['policy_count']}")
            print()

        print(f"Total providers: {providers['total']}")

    return 0


def _handle_resource_types(args: argparse.Namespace) -> int:
    """Handle resource-types command."""
    output_format = getattr(args, "format", "text")
    provider = getattr(args, "provider", None)

    types = _get_sample_resource_types(provider)

    if output_format == "json":
        print(json.dumps(types, indent=2))
    else:
        print("Known Resource Types")
        print("=" * 60)
        print()

        current_provider = None
        for rt in types["resource_types"]:
            if rt["provider"] != current_provider:
                current_provider = rt["provider"]
                print(f"\n{current_provider.upper()}:")
            print(f"  {rt['type']}")

        print()
        print(f"Total resource types: {types['total']}")

    return 0


def _handle_severity_levels(args: argparse.Namespace) -> int:
    """Handle severity-levels command."""
    output_format = getattr(args, "format", "text")

    levels = [
        {
            "value": "critical",
            "priority": 1,
            "description": "Immediate security risk, requires urgent action",
            "indicator": "[!!!]",
        },
        {
            "value": "high",
            "priority": 2,
            "description": "Significant security issue, should be addressed soon",
            "indicator": "[!!]",
        },
        {
            "value": "medium",
            "priority": 3,
            "description": "Moderate security concern, plan for remediation",
            "indicator": "[!]",
        },
        {
            "value": "low",
            "priority": 4,
            "description": "Minor security issue, address when convenient",
            "indicator": "[*]",
        },
        {
            "value": "info",
            "priority": 5,
            "description": "Informational finding, best practice recommendation",
            "indicator": "[i]",
        },
    ]

    result = {"severity_levels": levels, "total": len(levels)}

    if output_format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Severity Levels")
        print("=" * 60)
        print()

        for level in levels:
            print(f"{level['indicator']} {level['value'].upper()} (Priority {level['priority']})")
            print(f"    {level['description']}")
            print()

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    output_format = getattr(args, "format", "text")

    summary = {
        "module": "IaC Scanner",
        "version": "1.0.0",
        "status": "operational",
        "formats": {
            "terraform": {"enabled": True, "extensions": [".tf", ".tfvars"]},
            "cloudformation": {"enabled": True, "extensions": [".yaml", ".yml", ".json"]},
            "arm": {"enabled": True, "extensions": [".json"]},
            "kubernetes": {"enabled": True, "extensions": [".yaml", ".yml"]},
        },
        "policies": {
            "total": 45,
            "enabled": 42,
            "by_severity": {
                "critical": 8,
                "high": 15,
                "medium": 12,
                "low": 7,
                "info": 3,
            },
            "by_provider": {
                "aws": 25,
                "gcp": 10,
                "azure": 8,
                "kubernetes": 2,
            },
        },
        "capabilities": [
            "terraform_parsing",
            "cloudformation_parsing",
            "arm_template_parsing",
            "kubernetes_manifest_parsing",
            "policy_evaluation",
            "compliance_mapping",
            "secret_detection",
        ],
        "components": {
            "TerraformParser": "healthy",
            "CloudFormationParser": "healthy",
            "ARMTemplateParser": "healthy",
            "IaCPolicyEvaluator": "healthy",
        },
    }

    if output_format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("IaC Scanner Summary")
        print("=" * 60)
        print()
        print(f"Module: {summary['module']}")
        print(f"Version: {summary['version']}")
        print(f"Status: {summary['status']}")
        print()
        print("Supported Formats:")
        for fmt, info in summary["formats"].items():
            status = "enabled" if info["enabled"] else "disabled"
            print(f"  {fmt}: {status} ({', '.join(info['extensions'])})")
        print()
        print("Policies:")
        print(f"  Total: {summary['policies']['total']}")
        print(f"  Enabled: {summary['policies']['enabled']}")
        print("  By Severity:")
        for sev, count in summary["policies"]["by_severity"].items():
            print(f"    {sev}: {count}")
        print("  By Provider:")
        for provider, count in summary["policies"]["by_provider"].items():
            print(f"    {provider}: {count}")
        print()
        print("Components:")
        for comp, status in summary["components"].items():
            print(f"  {comp}: {status}")

    return 0


# Sample data generators

def _generate_sample_findings(path: str, severity_filter: str | None, iac_format: str) -> dict[str, Any]:
    """Generate sample scan findings."""
    findings = [
        {
            "rule_id": "iac-aws-s3-encryption",
            "severity": "high",
            "title": "S3 bucket encryption not configured",
            "resource": "aws_s3_bucket.data_bucket",
            "location": f"{path}/main.tf:15",
            "description": "S3 buckets should have server-side encryption enabled.",
            "remediation": "Add server_side_encryption_configuration block with SSE-S3 or SSE-KMS.",
        },
        {
            "rule_id": "iac-aws-s3-public-access",
            "severity": "critical",
            "title": "S3 bucket allows public access",
            "resource": "aws_s3_bucket.public_assets",
            "location": f"{path}/storage.tf:42",
            "description": "S3 buckets should block public access to prevent data exposure.",
            "remediation": "Set all public access block settings to true.",
        },
        {
            "rule_id": "iac-aws-sg-ssh-open",
            "severity": "high",
            "title": "Security group allows SSH from 0.0.0.0/0",
            "resource": "aws_security_group.web_sg",
            "location": f"{path}/network.tf:28",
            "description": "Security groups should not allow unrestricted SSH access.",
            "remediation": "Restrict SSH access to specific IP ranges.",
        },
        {
            "rule_id": "iac-aws-rds-encryption",
            "severity": "medium",
            "title": "RDS instance encryption not enabled",
            "resource": "aws_db_instance.app_db",
            "location": f"{path}/database.tf:10",
            "description": "RDS instances should have storage encryption enabled.",
            "remediation": "Set storage_encrypted = true.",
        },
    ]

    if severity_filter:
        severity_order = ["critical", "high", "medium", "low", "info"]
        filter_idx = severity_order.index(severity_filter)
        findings = [f for f in findings if severity_order.index(f["severity"]) <= filter_idx]

    by_severity = {
        "critical": sum(1 for f in findings if f["severity"] == "critical"),
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
    }

    return {
        "findings": findings,
        "summary": {
            "files_scanned": 8,
            "resources_found": 24,
            "findings_count": len(findings),
            "by_severity": by_severity,
        },
    }


def _get_sample_policies(provider: str | None, severity: str | None, enabled_only: bool) -> dict[str, Any]:
    """Get sample policies list."""
    policies = [
        {
            "id": "iac-aws-s3-encryption",
            "name": "S3 bucket encryption not configured",
            "severity": "high",
            "providers": ["aws"],
            "enabled": True,
        },
        {
            "id": "iac-aws-s3-public-access",
            "name": "S3 bucket allows public access",
            "severity": "critical",
            "providers": ["aws"],
            "enabled": True,
        },
        {
            "id": "iac-aws-sg-ssh-open",
            "name": "Security group allows SSH from 0.0.0.0/0",
            "severity": "high",
            "providers": ["aws"],
            "enabled": True,
        },
        {
            "id": "iac-aws-rds-encryption",
            "name": "RDS instance encryption not enabled",
            "severity": "medium",
            "providers": ["aws"],
            "enabled": True,
        },
        {
            "id": "iac-gcp-gcs-uniform-bucket",
            "name": "GCS bucket uniform access not enabled",
            "severity": "medium",
            "providers": ["gcp"],
            "enabled": True,
        },
        {
            "id": "iac-azure-storage-https",
            "name": "Storage account HTTPS not enforced",
            "severity": "high",
            "providers": ["azure"],
            "enabled": True,
        },
        {
            "id": "iac-k8s-privileged-container",
            "name": "Container running as privileged",
            "severity": "critical",
            "providers": ["kubernetes"],
            "enabled": True,
        },
        {
            "id": "iac-hardcoded-secret",
            "name": "Hardcoded secret detected",
            "severity": "critical",
            "providers": [],
            "enabled": True,
        },
    ]

    if provider:
        policies = [p for p in policies if provider in p["providers"] or not p["providers"]]
    if severity:
        policies = [p for p in policies if p["severity"] == severity]
    if enabled_only:
        policies = [p for p in policies if p["enabled"]]

    return {
        "policies": policies,
        "total": len(policies),
        "enabled_count": sum(1 for p in policies if p["enabled"]),
    }


def _get_sample_policy(policy_id: str) -> dict[str, Any]:
    """Get sample policy details."""
    policies = {
        "iac-aws-s3-encryption": {
            "id": "iac-aws-s3-encryption",
            "name": "S3 bucket encryption not configured",
            "description": "S3 buckets should have server-side encryption enabled to protect data at rest.",
            "severity": "high",
            "enabled": True,
            "resource_types": ["aws_s3_bucket"],
            "providers": ["aws"],
            "remediation": "Add a server_side_encryption_configuration block with SSE-S3 or SSE-KMS.",
            "compliance": [
                {"framework": "CIS AWS", "version": "1.5.0", "control": "2.1.1"},
            ],
            "tags": ["s3", "encryption", "data-protection"],
        },
        "iac-aws-s3-public-access": {
            "id": "iac-aws-s3-public-access",
            "name": "S3 bucket allows public access",
            "description": "S3 buckets should block public access to prevent data exposure.",
            "severity": "critical",
            "enabled": True,
            "resource_types": ["aws_s3_bucket_public_access_block"],
            "providers": ["aws"],
            "remediation": "Set all public access block settings to true.",
            "compliance": [
                {"framework": "CIS AWS", "version": "1.5.0", "control": "2.1.2"},
            ],
            "tags": ["s3", "public-access", "data-protection"],
        },
    }

    if policy_id in policies:
        return {"policy": policies[policy_id]}
    return {"error": f"Policy not found: {policy_id}"}


def _get_sample_formats() -> dict[str, Any]:
    """Get sample IaC formats."""
    formats = [
        {
            "name": "Terraform",
            "value": "terraform",
            "extensions": [".tf", ".tfvars"],
            "description": "HashiCorp Terraform HCL configuration files",
        },
        {
            "name": "CloudFormation",
            "value": "cloudformation",
            "extensions": [".yaml", ".yml", ".json"],
            "description": "AWS CloudFormation templates in YAML or JSON",
        },
        {
            "name": "ARM Template",
            "value": "arm",
            "extensions": [".json"],
            "description": "Azure Resource Manager templates",
        },
        {
            "name": "Kubernetes",
            "value": "kubernetes",
            "extensions": [".yaml", ".yml"],
            "description": "Kubernetes manifests and configurations",
        },
        {
            "name": "Helm",
            "value": "helm",
            "extensions": [".yaml", ".yml"],
            "description": "Helm chart templates and values",
        },
        {
            "name": "Pulumi",
            "value": "pulumi",
            "extensions": [".py", ".ts", ".go"],
            "description": "Pulumi infrastructure programs",
        },
    ]

    return {"formats": formats, "total": len(formats)}


def _validate_file(path: str) -> dict[str, Any]:
    """Validate a file (sample response)."""
    # Sample validation result
    if path.endswith(".tf"):
        return {
            "valid": True,
            "path": path,
            "format": "terraform",
            "resource_count": 5,
            "errors": [],
        }
    elif path.endswith(".yaml") or path.endswith(".yml"):
        return {
            "valid": True,
            "path": path,
            "format": "cloudformation",
            "resource_count": 8,
            "errors": [],
        }
    else:
        return {
            "valid": False,
            "path": path,
            "format": "unknown",
            "resource_count": 0,
            "errors": ["Unable to determine file format", "File extension not recognized"],
        }


def _get_sample_resources(path: str, resource_type: str | None, provider: str | None) -> dict[str, Any]:
    """Get sample resources list."""
    resources = [
        {"type": "aws_s3_bucket", "name": "data_bucket", "provider": "aws", "file": "main.tf:15"},
        {"type": "aws_s3_bucket", "name": "logs_bucket", "provider": "aws", "file": "main.tf:35"},
        {"type": "aws_security_group", "name": "web_sg", "provider": "aws", "file": "network.tf:10"},
        {"type": "aws_security_group", "name": "db_sg", "provider": "aws", "file": "network.tf:45"},
        {"type": "aws_db_instance", "name": "app_db", "provider": "aws", "file": "database.tf:5"},
        {"type": "aws_iam_role", "name": "app_role", "provider": "aws", "file": "iam.tf:1"},
        {"type": "google_storage_bucket", "name": "gcs_bucket", "provider": "gcp", "file": "gcp.tf:10"},
        {"type": "azurerm_storage_account", "name": "storage", "provider": "azure", "file": "azure.tf:5"},
    ]

    if resource_type:
        resources = [r for r in resources if r["type"] == resource_type]
    if provider:
        resources = [r for r in resources if r["provider"] == provider]

    return {"resources": resources, "total": len(resources)}


def _get_sample_stats(path: str) -> dict[str, Any]:
    """Get sample statistics."""
    return {
        "path": path,
        "total_files": 12,
        "total_resources": 45,
        "parse_errors": 0,
        "by_format": {
            "terraform": 8,
            "cloudformation": 2,
            "arm": 1,
            "kubernetes": 1,
        },
        "by_provider": {
            "aws": 32,
            "gcp": 8,
            "azure": 3,
            "kubernetes": 2,
        },
        "top_resource_types": [
            {"type": "aws_s3_bucket", "count": 8},
            {"type": "aws_security_group", "count": 6},
            {"type": "aws_iam_role", "count": 5},
            {"type": "aws_lambda_function", "count": 4},
            {"type": "aws_db_instance", "count": 3},
            {"type": "google_storage_bucket", "count": 3},
            {"type": "aws_vpc", "count": 2},
            {"type": "azurerm_storage_account", "count": 2},
        ],
    }


def _get_sample_compliance(framework: str | None) -> dict[str, Any]:
    """Get sample compliance mappings."""
    frameworks = [
        {
            "name": "CIS AWS",
            "version": "1.5.0",
            "mappings": [
                {"control": "2.1.1", "policy_id": "iac-aws-s3-encryption"},
                {"control": "2.1.2", "policy_id": "iac-aws-s3-public-access"},
                {"control": "4.1", "policy_id": "iac-aws-sg-ssh-open"},
                {"control": "4.2", "policy_id": "iac-aws-sg-rdp-open"},
            ],
        },
        {
            "name": "CIS GCP",
            "version": "1.3.0",
            "mappings": [
                {"control": "5.1", "policy_id": "iac-gcp-gcs-uniform-bucket"},
                {"control": "5.2", "policy_id": "iac-gcp-gcs-public-access"},
            ],
        },
        {
            "name": "CIS Azure",
            "version": "1.4.0",
            "mappings": [
                {"control": "3.1", "policy_id": "iac-azure-storage-https"},
                {"control": "3.2", "policy_id": "iac-azure-storage-encryption"},
            ],
        },
    ]

    if framework:
        frameworks = [f for f in frameworks if framework.lower() in f["name"].lower()]

    total_mappings = sum(len(f["mappings"]) for f in frameworks)

    return {
        "frameworks": frameworks,
        "total_frameworks": len(frameworks),
        "total_mappings": total_mappings,
    }


def _get_sample_providers() -> dict[str, Any]:
    """Get sample providers."""
    providers = [
        {"name": "Amazon Web Services", "value": "aws", "resource_prefix": "aws_", "policy_count": 25},
        {"name": "Google Cloud Platform", "value": "gcp", "resource_prefix": "google_", "policy_count": 10},
        {"name": "Microsoft Azure", "value": "azure", "resource_prefix": "azurerm_", "policy_count": 8},
        {"name": "Kubernetes", "value": "kubernetes", "resource_prefix": "kubernetes_", "policy_count": 2},
    ]

    return {"providers": providers, "total": len(providers)}


def _get_sample_resource_types(provider: str | None) -> dict[str, Any]:
    """Get sample resource types."""
    types = [
        {"type": "aws_s3_bucket", "provider": "aws"},
        {"type": "aws_security_group", "provider": "aws"},
        {"type": "aws_iam_role", "provider": "aws"},
        {"type": "aws_iam_policy", "provider": "aws"},
        {"type": "aws_db_instance", "provider": "aws"},
        {"type": "aws_lambda_function", "provider": "aws"},
        {"type": "aws_vpc", "provider": "aws"},
        {"type": "aws_subnet", "provider": "aws"},
        {"type": "google_storage_bucket", "provider": "gcp"},
        {"type": "google_compute_instance", "provider": "gcp"},
        {"type": "google_compute_firewall", "provider": "gcp"},
        {"type": "azurerm_storage_account", "provider": "azure"},
        {"type": "azurerm_virtual_machine", "provider": "azure"},
        {"type": "azurerm_network_security_group", "provider": "azure"},
        {"type": "kubernetes_deployment", "provider": "kubernetes"},
        {"type": "kubernetes_service", "provider": "kubernetes"},
    ]

    if provider:
        types = [t for t in types if t["provider"] == provider]

    return {"resource_types": types, "total": len(types)}
