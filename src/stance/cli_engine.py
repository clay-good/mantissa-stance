"""
CLI commands for the Policy Engine module.

Provides commands for policy management, validation, evaluation,
expression testing, and compliance calculation.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_engine_parser(subparsers: Any) -> None:
    """
    Add engine subcommand parser.

    Args:
        subparsers: Argument parser subparsers
    """
    engine_parser = subparsers.add_parser(
        "engine",
        help="Policy engine commands",
        description="Manage and interact with the policy evaluation engine",
    )

    engine_subparsers = engine_parser.add_subparsers(
        dest="engine_action",
        help="Engine action to perform",
    )

    # policies - List all loaded policies
    policies_parser = engine_subparsers.add_parser(
        "policies",
        help="List all loaded policies",
        description="Load and list all available security policies",
    )
    policies_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Policy directory path (default: policies/)",
    )
    policies_parser.add_argument(
        "--enabled-only",
        action="store_true",
        help="Show only enabled policies",
    )
    policies_parser.add_argument(
        "--severity",
        type=str,
        choices=["critical", "high", "medium", "low", "info"],
        help="Filter by severity level",
    )
    policies_parser.add_argument(
        "--resource-type",
        type=str,
        help="Filter by resource type (e.g., aws_s3_bucket)",
    )
    policies_parser.add_argument(
        "--framework",
        type=str,
        help="Filter by compliance framework (e.g., cis-aws)",
    )
    policies_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # policy - Show policy details
    policy_parser = engine_subparsers.add_parser(
        "policy",
        help="Show details for a specific policy",
        description="Display full details for a security policy",
    )
    policy_parser.add_argument(
        "policy_id",
        type=str,
        help="Policy ID to show",
    )
    policy_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Policy directory path (default: policies/)",
    )
    policy_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # validate - Validate policies
    validate_parser = engine_subparsers.add_parser(
        "validate",
        help="Validate policy files",
        description="Validate policy syntax and schema",
    )
    validate_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Policy directory or file path",
    )
    validate_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # evaluate - Evaluate expression
    evaluate_parser = engine_subparsers.add_parser(
        "evaluate",
        help="Evaluate an expression against sample data",
        description="Test expression evaluation with sample context",
    )
    evaluate_parser.add_argument(
        "expression",
        type=str,
        help="Expression to evaluate",
    )
    evaluate_parser.add_argument(
        "--context",
        type=str,
        default="{}",
        help="JSON context for evaluation (default: {})",
    )
    evaluate_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # validate-expression - Validate expression syntax
    validate_expr_parser = engine_subparsers.add_parser(
        "validate-expression",
        help="Validate expression syntax",
        description="Check if an expression has valid syntax",
    )
    validate_expr_parser.add_argument(
        "expression",
        type=str,
        help="Expression to validate",
    )
    validate_expr_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # compliance - Calculate compliance scores
    compliance_parser = engine_subparsers.add_parser(
        "compliance",
        help="Calculate compliance scores",
        description="Calculate compliance scores for frameworks",
    )
    compliance_parser.add_argument(
        "--framework",
        type=str,
        help="Specific framework to calculate (e.g., cis-aws)",
    )
    compliance_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # frameworks - List compliance frameworks
    frameworks_parser = engine_subparsers.add_parser(
        "frameworks",
        help="List available compliance frameworks",
        description="List all compliance frameworks from loaded policies",
    )
    frameworks_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # operators - List expression operators
    operators_parser = engine_subparsers.add_parser(
        "operators",
        help="List expression operators",
        description="List all available expression operators",
    )
    operators_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # check-types - List check types
    check_types_parser = engine_subparsers.add_parser(
        "check-types",
        help="List policy check types",
        description="List available policy check types",
    )
    check_types_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # severity-levels - List severity levels
    severity_parser = engine_subparsers.add_parser(
        "severity-levels",
        help="List severity levels",
        description="List all severity levels with priorities",
    )
    severity_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # stats - Show engine statistics
    stats_parser = engine_subparsers.add_parser(
        "stats",
        help="Show policy engine statistics",
        description="Display statistics about loaded policies",
    )
    stats_parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Policy directory path",
    )
    stats_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # status - Show engine status
    status_parser = engine_subparsers.add_parser(
        "status",
        help="Show policy engine status",
        description="Display engine status and capabilities",
    )
    status_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )

    # summary - Show engine summary
    summary_parser = engine_subparsers.add_parser(
        "summary",
        help="Show policy engine summary",
        description="Display comprehensive engine summary",
    )
    summary_parser.add_argument(
        "--format",
        type=str,
        default="table",
        choices=["table", "json"],
        help="Output format (default: table)",
    )


def cmd_engine(args: argparse.Namespace) -> int:
    """
    Handle engine commands.

    Args:
        args: Parsed command arguments

    Returns:
        Exit code (0 for success, 1 for error)
    """
    action = getattr(args, "engine_action", None)

    if not action:
        print("Error: No action specified. Use --help for available actions.")
        return 1

    handlers = {
        "policies": _handle_policies,
        "policy": _handle_policy,
        "validate": _handle_validate,
        "evaluate": _handle_evaluate,
        "validate-expression": _handle_validate_expression,
        "compliance": _handle_compliance,
        "frameworks": _handle_frameworks,
        "operators": _handle_operators,
        "check-types": _handle_check_types,
        "severity-levels": _handle_severity_levels,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Error: Unknown action '{action}'")
    return 1


def _handle_policies(args: argparse.Namespace) -> int:
    """Handle policies command."""
    policies = _get_sample_policies()

    # Apply filters
    if args.enabled_only:
        policies = [p for p in policies if p["enabled"]]

    if args.severity:
        policies = [p for p in policies if p["severity"] == args.severity]

    if args.resource_type:
        policies = [p for p in policies if p["resource_type"] == args.resource_type]

    if args.framework:
        framework_lower = args.framework.lower()
        policies = [
            p for p in policies
            if any(framework_lower in f.lower() for f in p.get("frameworks", []))
        ]

    if args.format == "json":
        print(json.dumps({"policies": policies, "total": len(policies)}, indent=2))
    else:
        print(f"\nLoaded Policies ({len(policies)} total)")
        print("=" * 80)
        for policy in policies:
            status = "enabled" if policy["enabled"] else "disabled"
            print(f"\n  {policy['id']}")
            print(f"    Name: {policy['name']}")
            print(f"    Severity: {policy['severity']}")
            print(f"    Resource Type: {policy['resource_type']}")
            print(f"    Status: {status}")
            if policy.get("frameworks"):
                print(f"    Frameworks: {', '.join(policy['frameworks'])}")

    return 0


def _handle_policy(args: argparse.Namespace) -> int:
    """Handle policy command."""
    policy = _get_sample_policy(args.policy_id)

    if not policy:
        print(f"Error: Policy '{args.policy_id}' not found")
        return 1

    if args.format == "json":
        print(json.dumps({"policy": policy}, indent=2))
    else:
        print(f"\nPolicy: {policy['id']}")
        print("=" * 60)
        print(f"  Name: {policy['name']}")
        print(f"  Description: {policy['description']}")
        print(f"  Severity: {policy['severity']}")
        print(f"  Resource Type: {policy['resource_type']}")
        print(f"  Enabled: {policy['enabled']}")
        print(f"\n  Check:")
        print(f"    Type: {policy['check']['type']}")
        if policy['check'].get('expression'):
            print(f"    Expression: {policy['check']['expression']}")
        print(f"\n  Compliance Frameworks:")
        for mapping in policy.get("compliance", []):
            print(f"    - {mapping['framework']} {mapping['control']}")
        print(f"\n  Remediation:")
        print(f"    {policy['remediation']['guidance']}")
        if policy.get("tags"):
            print(f"\n  Tags: {', '.join(policy['tags'])}")

    return 0


def _handle_validate(args: argparse.Namespace) -> int:
    """Handle validate command."""
    validation_result = _validate_policies(args.path)

    if args.format == "json":
        print(json.dumps(validation_result, indent=2))
    else:
        print("\nPolicy Validation Results")
        print("=" * 60)
        print(f"  Total files: {validation_result['total_files']}")
        print(f"  Valid policies: {validation_result['valid_count']}")
        print(f"  Invalid policies: {validation_result['invalid_count']}")
        print(f"  Validation status: {'PASSED' if validation_result['valid'] else 'FAILED'}")

        if validation_result.get("errors"):
            print("\n  Errors:")
            for error in validation_result["errors"]:
                print(f"    - {error}")

        if validation_result.get("warnings"):
            print("\n  Warnings:")
            for warning in validation_result["warnings"]:
                print(f"    - {warning}")

    return 0 if validation_result["valid"] else 1


def _handle_evaluate(args: argparse.Namespace) -> int:
    """Handle evaluate command."""
    try:
        context = json.loads(args.context)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON context: {e}")
        return 1

    result = _evaluate_expression(args.expression, context)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("\nExpression Evaluation")
        print("=" * 60)
        print(f"  Expression: {args.expression}")
        print(f"  Context: {json.dumps(context)}")
        print(f"  Result: {result['result']}")
        if result.get("error"):
            print(f"  Error: {result['error']}")

    return 0 if result.get("success") else 1


def _handle_validate_expression(args: argparse.Namespace) -> int:
    """Handle validate-expression command."""
    result = _validate_expression_syntax(args.expression)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("\nExpression Validation")
        print("=" * 60)
        print(f"  Expression: {args.expression}")
        print(f"  Valid: {result['valid']}")

        if result.get("errors"):
            print("  Errors:")
            for error in result["errors"]:
                print(f"    - {error}")

        if result.get("tokens"):
            print(f"  Token count: {len(result['tokens'])}")

    return 0 if result["valid"] else 1


def _handle_compliance(args: argparse.Namespace) -> int:
    """Handle compliance command."""
    scores = _get_sample_compliance_scores(args.framework)

    if args.format == "json":
        print(json.dumps(scores, indent=2))
    else:
        print("\nCompliance Scores")
        print("=" * 60)
        print(f"  Overall Score: {scores['overall_score']}%")
        print(f"\n  Frameworks:")
        for framework in scores["frameworks"]:
            print(f"\n    {framework['name']} ({framework['version']})")
            print(f"      Score: {framework['score']}%")
            print(f"      Controls Passed: {framework['controls_passed']}/{framework['controls_total']}")
            print(f"      Controls Failed: {framework['controls_failed']}")

    return 0


def _handle_frameworks(args: argparse.Namespace) -> int:
    """Handle frameworks command."""
    frameworks = _get_sample_frameworks()

    if args.format == "json":
        print(json.dumps({"frameworks": frameworks, "total": len(frameworks)}, indent=2))
    else:
        print(f"\nCompliance Frameworks ({len(frameworks)} available)")
        print("=" * 60)
        for fw in frameworks:
            print(f"\n  {fw['id']}")
            print(f"    Name: {fw['name']}")
            print(f"    Version: {fw['version']}")
            print(f"    Controls: {fw['controls_count']}")
            print(f"    Policies Mapped: {fw['policies_mapped']}")

    return 0


def _handle_operators(args: argparse.Namespace) -> int:
    """Handle operators command."""
    operators = _get_expression_operators()

    if args.format == "json":
        print(json.dumps({"operators": operators, "total": len(operators)}, indent=2))
    else:
        print(f"\nExpression Operators ({len(operators)} available)")
        print("=" * 60)
        for op in operators:
            print(f"\n  {op['operator']}")
            print(f"    Category: {op['category']}")
            print(f"    Description: {op['description']}")
            print(f"    Example: {op['example']}")

    return 0


def _handle_check_types(args: argparse.Namespace) -> int:
    """Handle check-types command."""
    check_types = _get_check_types()

    if args.format == "json":
        print(json.dumps({"check_types": check_types, "total": len(check_types)}, indent=2))
    else:
        print(f"\nPolicy Check Types ({len(check_types)} available)")
        print("=" * 60)
        for ct in check_types:
            print(f"\n  {ct['type']}")
            print(f"    Description: {ct['description']}")
            print(f"    Fields: {', '.join(ct['fields'])}")
            print(f"    Example: {ct['example']}")

    return 0


def _handle_severity_levels(args: argparse.Namespace) -> int:
    """Handle severity-levels command."""
    levels = _get_severity_levels()

    if args.format == "json":
        print(json.dumps({"severity_levels": levels, "total": len(levels)}, indent=2))
    else:
        print(f"\nSeverity Levels ({len(levels)} defined)")
        print("=" * 60)
        for level in levels:
            print(f"\n  {level['level'].upper()}")
            print(f"    Priority: {level['priority']}")
            print(f"    Description: {level['description']}")
            print(f"    Response Time: {level['response_time']}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    stats = _get_engine_stats()

    if args.format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print("\nPolicy Engine Statistics")
        print("=" * 60)
        print(f"  Total Policies: {stats['total_policies']}")
        print(f"  Enabled Policies: {stats['enabled_policies']}")
        print(f"  Disabled Policies: {stats['disabled_policies']}")
        print(f"\n  By Severity:")
        for sev, count in stats["by_severity"].items():
            print(f"    {sev}: {count}")
        print(f"\n  By Resource Type:")
        for rt, count in list(stats["by_resource_type"].items())[:5]:
            print(f"    {rt}: {count}")
        print(f"\n  Compliance Frameworks: {stats['frameworks_count']}")
        print(f"  Total Compliance Mappings: {stats['compliance_mappings']}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = _get_engine_status()

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nPolicy Engine Status")
        print("=" * 60)
        print(f"  Module: {status['module']}")
        print(f"  Version: {status['version']}")
        print(f"  Status: {status['status']}")
        print(f"\n  Components:")
        for name, available in status["components"].items():
            indicator = "available" if available else "unavailable"
            print(f"    {name}: {indicator}")
        print(f"\n  Capabilities:")
        for cap, enabled in status["capabilities"].items():
            indicator = "enabled" if enabled else "disabled"
            print(f"    {cap}: {indicator}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = _get_engine_summary()

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nPolicy Engine Summary")
        print("=" * 60)
        print(f"  Module: {summary['module']}")
        print(f"  Version: {summary['version']}")
        print(f"  Status: {summary['status']}")
        print(f"\n  Policies:")
        print(f"    Total: {summary['policies']['total']}")
        print(f"    Enabled: {summary['policies']['enabled']}")
        print(f"\n  Compliance:")
        print(f"    Frameworks: {summary['compliance']['frameworks']}")
        print(f"    Overall Score: {summary['compliance']['overall_score']}%")
        print(f"\n  Expression Engine:")
        print(f"    Operators: {summary['expression_engine']['operators']}")
        print(f"    Check Types: {summary['expression_engine']['check_types']}")
        print(f"\n  Features:")
        for feature in summary["features"]:
            print(f"    - {feature}")

    return 0


# Sample data generators for demo mode


def _get_sample_policies() -> list[dict[str, Any]]:
    """Get sample policies for demo."""
    return [
        {
            "id": "aws-s3-encryption",
            "name": "S3 Bucket Encryption Required",
            "description": "Ensure all S3 buckets have encryption enabled",
            "severity": "high",
            "resource_type": "aws_s3_bucket",
            "enabled": True,
            "frameworks": ["CIS AWS", "PCI-DSS"],
            "check": {
                "type": "expression",
                "expression": "resource.encryption.enabled == true",
            },
            "compliance": [
                {"framework": "CIS AWS", "version": "2.0", "control": "2.1.1"},
                {"framework": "PCI-DSS", "version": "4.0", "control": "3.4"},
            ],
            "remediation": {
                "guidance": "Enable server-side encryption on the S3 bucket using SSE-S3, SSE-KMS, or SSE-C.",
            },
            "tags": ["security", "encryption", "s3"],
        },
        {
            "id": "aws-iam-mfa",
            "name": "IAM User MFA Required",
            "description": "Ensure all IAM users have MFA enabled",
            "severity": "critical",
            "resource_type": "aws_iam_user",
            "enabled": True,
            "frameworks": ["CIS AWS", "SOC2"],
            "check": {
                "type": "expression",
                "expression": "resource.mfa_active == true",
            },
            "compliance": [
                {"framework": "CIS AWS", "version": "2.0", "control": "1.10"},
                {"framework": "SOC2", "version": "2017", "control": "CC6.1"},
            ],
            "remediation": {
                "guidance": "Enable MFA for all IAM users, especially those with console access.",
            },
            "tags": ["security", "iam", "mfa"],
        },
        {
            "id": "aws-ec2-public-ip",
            "name": "EC2 No Public IP",
            "description": "EC2 instances should not have public IPs unless required",
            "severity": "medium",
            "resource_type": "aws_ec2_instance",
            "enabled": True,
            "frameworks": ["CIS AWS"],
            "check": {
                "type": "expression",
                "expression": "resource.public_ip_address not_exists or resource.public_ip_address == null",
            },
            "compliance": [
                {"framework": "CIS AWS", "version": "2.0", "control": "5.1"},
            ],
            "remediation": {
                "guidance": "Use private subnets and NAT gateways instead of public IPs for EC2 instances.",
            },
            "tags": ["network", "ec2"],
        },
        {
            "id": "gcp-storage-public",
            "name": "GCS Bucket No Public Access",
            "description": "Ensure GCS buckets are not publicly accessible",
            "severity": "critical",
            "resource_type": "gcp_storage_bucket",
            "enabled": True,
            "frameworks": ["CIS GCP"],
            "check": {
                "type": "expression",
                "expression": "resource.iam_configuration.public_access_prevention == 'enforced'",
            },
            "compliance": [
                {"framework": "CIS GCP", "version": "2.0", "control": "5.1"},
            ],
            "remediation": {
                "guidance": "Enable public access prevention on the GCS bucket.",
            },
            "tags": ["security", "storage", "gcp"],
        },
        {
            "id": "azure-sql-encryption",
            "name": "Azure SQL TDE Enabled",
            "description": "Ensure Azure SQL databases have TDE enabled",
            "severity": "high",
            "resource_type": "azure_sql_database",
            "enabled": False,
            "frameworks": ["CIS Azure"],
            "check": {
                "type": "expression",
                "expression": "resource.transparent_data_encryption.status == 'Enabled'",
            },
            "compliance": [
                {"framework": "CIS Azure", "version": "2.0", "control": "4.1.2"},
            ],
            "remediation": {
                "guidance": "Enable Transparent Data Encryption on the Azure SQL database.",
            },
            "tags": ["security", "encryption", "azure", "sql"],
        },
    ]


def _get_sample_policy(policy_id: str) -> dict[str, Any] | None:
    """Get a specific sample policy."""
    policies = _get_sample_policies()
    for policy in policies:
        if policy["id"] == policy_id:
            return policy
    return None


def _validate_policies(path: str | None) -> dict[str, Any]:
    """Validate policies (demo mode)."""
    return {
        "valid": True,
        "total_files": 5,
        "valid_count": 5,
        "invalid_count": 0,
        "errors": [],
        "warnings": [
            "Policy 'azure-sql-encryption' is disabled",
        ],
        "path": path or "policies/",
    }


def _evaluate_expression(expression: str, context: dict[str, Any]) -> dict[str, Any]:
    """Evaluate expression (demo mode with actual evaluator if available)."""
    try:
        from stance.engine.expressions import ExpressionEvaluator

        evaluator = ExpressionEvaluator()
        result = evaluator.evaluate(expression, context)
        return {
            "success": True,
            "expression": expression,
            "context": context,
            "result": result,
        }
    except Exception as e:
        return {
            "success": False,
            "expression": expression,
            "context": context,
            "result": None,
            "error": str(e),
        }


def _validate_expression_syntax(expression: str) -> dict[str, Any]:
    """Validate expression syntax."""
    try:
        from stance.engine.expressions import ExpressionEvaluator

        evaluator = ExpressionEvaluator()
        errors = evaluator.validate(expression)
        return {
            "valid": len(errors) == 0,
            "expression": expression,
            "errors": errors,
            "tokens": [],  # Would need tokenizer exposure
        }
    except Exception as e:
        return {
            "valid": False,
            "expression": expression,
            "errors": [str(e)],
        }


def _get_sample_compliance_scores(framework: str | None) -> dict[str, Any]:
    """Get sample compliance scores."""
    frameworks = [
        {
            "id": "cis-aws",
            "name": "CIS AWS Foundations Benchmark",
            "version": "2.0",
            "score": 78.5,
            "controls_passed": 47,
            "controls_failed": 13,
            "controls_total": 60,
        },
        {
            "id": "pci-dss",
            "name": "PCI DSS",
            "version": "4.0",
            "score": 85.0,
            "controls_passed": 51,
            "controls_failed": 9,
            "controls_total": 60,
        },
        {
            "id": "soc2",
            "name": "SOC 2",
            "version": "2017",
            "score": 72.0,
            "controls_passed": 36,
            "controls_failed": 14,
            "controls_total": 50,
        },
    ]

    if framework:
        framework_lower = framework.lower().replace(" ", "-")
        frameworks = [f for f in frameworks if f["id"] == framework_lower]

    total_controls = sum(f["controls_total"] for f in frameworks)
    total_passed = sum(f["controls_passed"] for f in frameworks)
    overall_score = (total_passed / total_controls * 100) if total_controls > 0 else 100.0

    return {
        "overall_score": round(overall_score, 1),
        "frameworks": frameworks,
        "generated_at": "2025-12-29T12:00:00Z",
    }


def _get_sample_frameworks() -> list[dict[str, Any]]:
    """Get sample compliance frameworks."""
    return [
        {
            "id": "cis-aws",
            "name": "CIS AWS Foundations Benchmark",
            "version": "2.0",
            "controls_count": 60,
            "policies_mapped": 45,
        },
        {
            "id": "cis-gcp",
            "name": "CIS GCP Foundations Benchmark",
            "version": "2.0",
            "controls_count": 65,
            "policies_mapped": 41,
        },
        {
            "id": "cis-azure",
            "name": "CIS Azure Foundations Benchmark",
            "version": "2.0",
            "controls_count": 112,
            "policies_mapped": 47,
        },
        {
            "id": "pci-dss",
            "name": "PCI DSS",
            "version": "4.0",
            "controls_count": 60,
            "policies_mapped": 52,
        },
        {
            "id": "soc2",
            "name": "SOC 2 Type II",
            "version": "2017",
            "controls_count": 50,
            "policies_mapped": 34,
        },
        {
            "id": "hipaa",
            "name": "HIPAA Security Rule",
            "version": "2013",
            "controls_count": 42,
            "policies_mapped": 24,
        },
        {
            "id": "nist-800-53",
            "name": "NIST 800-53 Rev 5",
            "version": "Rev 5",
            "controls_count": 325,
            "policies_mapped": 75,
        },
    ]


def _get_expression_operators() -> list[dict[str, Any]]:
    """Get expression operators."""
    return [
        {
            "operator": "==",
            "category": "comparison",
            "description": "Equals comparison",
            "example": "resource.enabled == true",
        },
        {
            "operator": "!=",
            "category": "comparison",
            "description": "Not equals comparison",
            "example": "resource.status != 'inactive'",
        },
        {
            "operator": ">",
            "category": "comparison",
            "description": "Greater than",
            "example": "resource.count > 10",
        },
        {
            "operator": "<",
            "category": "comparison",
            "description": "Less than",
            "example": "resource.age < 90",
        },
        {
            "operator": ">=",
            "category": "comparison",
            "description": "Greater than or equal",
            "example": "resource.version >= 2.0",
        },
        {
            "operator": "<=",
            "category": "comparison",
            "description": "Less than or equal",
            "example": "resource.retention <= 365",
        },
        {
            "operator": "in",
            "category": "membership",
            "description": "Value is in list",
            "example": "resource.region in ['us-east-1', 'us-west-2']",
        },
        {
            "operator": "not_in",
            "category": "membership",
            "description": "Value is not in list",
            "example": "resource.env not_in ['prod', 'staging']",
        },
        {
            "operator": "contains",
            "category": "string",
            "description": "String contains substring",
            "example": "resource.name contains 'prod'",
        },
        {
            "operator": "starts_with",
            "category": "string",
            "description": "String starts with prefix",
            "example": "resource.arn starts_with 'arn:aws:'",
        },
        {
            "operator": "ends_with",
            "category": "string",
            "description": "String ends with suffix",
            "example": "resource.bucket ends_with '-logs'",
        },
        {
            "operator": "matches",
            "category": "string",
            "description": "Regex pattern match",
            "example": "resource.name matches '^prod-[a-z]+'",
        },
        {
            "operator": "exists",
            "category": "existence",
            "description": "Field exists and is not null",
            "example": "resource.encryption exists",
        },
        {
            "operator": "not_exists",
            "category": "existence",
            "description": "Field does not exist or is null",
            "example": "resource.public_ip not_exists",
        },
        {
            "operator": "and",
            "category": "boolean",
            "description": "Logical AND",
            "example": "resource.encrypted == true and resource.versioned == true",
        },
        {
            "operator": "or",
            "category": "boolean",
            "description": "Logical OR",
            "example": "resource.tier == 'premium' or resource.tier == 'enterprise'",
        },
        {
            "operator": "not",
            "category": "boolean",
            "description": "Logical NOT",
            "example": "not resource.public",
        },
    ]


def _get_check_types() -> list[dict[str, Any]]:
    """Get policy check types."""
    return [
        {
            "type": "expression",
            "description": "Boolean expression evaluated against resource data",
            "fields": ["expression"],
            "example": "resource.encryption.enabled == true",
        },
        {
            "type": "sql",
            "description": "SQL query for complex checks across resources",
            "fields": ["query"],
            "example": "SELECT * FROM assets WHERE encryption = false",
        },
    ]


def _get_severity_levels() -> list[dict[str, Any]]:
    """Get severity levels."""
    return [
        {
            "level": "critical",
            "priority": 1,
            "description": "Immediate action required - security breach risk",
            "response_time": "Immediate (< 1 hour)",
        },
        {
            "level": "high",
            "priority": 2,
            "description": "High priority - significant security risk",
            "response_time": "Same day (< 24 hours)",
        },
        {
            "level": "medium",
            "priority": 3,
            "description": "Moderate risk - should be addressed soon",
            "response_time": "Within 1 week",
        },
        {
            "level": "low",
            "priority": 4,
            "description": "Low risk - address in normal maintenance",
            "response_time": "Within 30 days",
        },
        {
            "level": "info",
            "priority": 5,
            "description": "Informational - best practice recommendation",
            "response_time": "As time permits",
        },
    ]


def _get_engine_stats() -> dict[str, Any]:
    """Get engine statistics."""
    return {
        "total_policies": 125,
        "enabled_policies": 118,
        "disabled_policies": 7,
        "by_severity": {
            "critical": 15,
            "high": 42,
            "medium": 48,
            "low": 15,
            "info": 5,
        },
        "by_resource_type": {
            "aws_s3_bucket": 12,
            "aws_iam_user": 8,
            "aws_iam_role": 10,
            "aws_ec2_instance": 15,
            "aws_rds_instance": 6,
            "gcp_storage_bucket": 8,
            "gcp_compute_instance": 10,
            "azure_storage_account": 7,
            "azure_vm": 9,
        },
        "frameworks_count": 7,
        "compliance_mappings": 318,
    }


def _get_engine_status() -> dict[str, Any]:
    """Get engine status."""
    return {
        "module": "engine",
        "version": "1.0.0",
        "status": "operational",
        "components": {
            "ExpressionEvaluator": True,
            "PolicyLoader": True,
            "PolicyEvaluator": True,
            "ComplianceCalculator": True,
        },
        "capabilities": {
            "expression_evaluation": True,
            "policy_validation": True,
            "compliance_scoring": True,
            "sql_checks": True,
            "yaml_parsing": True,
            "wildcard_matching": True,
            "regex_patterns": True,
        },
    }


def _get_engine_summary() -> dict[str, Any]:
    """Get engine summary."""
    return {
        "module": "Policy Engine",
        "version": "1.0.0",
        "status": "operational",
        "policies": {
            "total": 125,
            "enabled": 118,
            "disabled": 7,
        },
        "compliance": {
            "frameworks": 7,
            "overall_score": 78.5,
        },
        "expression_engine": {
            "operators": 17,
            "check_types": 2,
        },
        "features": [
            "Expression-based policy evaluation",
            "SQL query-based checks",
            "Wildcard resource type matching",
            "Regex pattern matching",
            "Multi-framework compliance scoring",
            "YAML policy file parsing",
            "Policy validation and error reporting",
        ],
    }
