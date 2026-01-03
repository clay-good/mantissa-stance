"""
CLI command handlers for Mantissa Stance.

Implements each CLI subcommand with proper error handling
and output formatting.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def cmd_scan(args: argparse.Namespace) -> int:
    """
    Execute posture scan.

    Steps:
        1. Initialize storage backend
        2. Create boto3 session
        3. Run collectors
        4. Store assets
        5. Load and evaluate policies
        6. Run secrets detection (if enabled)
        7. Store findings
        8. Print summary

    Returns:
        Exit code (0 success, 1 error)
    """
    from stance.storage import get_storage, generate_snapshot_id
    from stance.collectors import run_collection, list_collector_names
    from stance.engine import PolicyLoader, PolicyEvaluator
    from stance.models.finding import FindingCollection
    from stance.progress import create_progress_tracker, ProgressPhase

    # Determine if we should show progress
    show_progress = not args.quiet and args.output != "quiet" and args.output != "json"

    # Create progress tracker
    progress_callback = getattr(args, "progress_callback", None)
    tracker = create_progress_tracker(
        quiet=not show_progress,
        callback=progress_callback,
    )

    # Build step list based on configuration
    secrets_only = getattr(args, "secrets_only", False)
    enable_secrets = getattr(args, "secrets", False) or secrets_only

    steps = ["Collection"]
    if not secrets_only:
        steps.append("Policy Evaluation")
    if enable_secrets:
        steps.append("Secrets Detection")
    steps.append("Storage")

    try:
        # Start progress tracking
        tracker.start(steps)
        tracker.set_phase(ProgressPhase.INITIALIZING)

        # Initialize storage
        storage = get_storage(args.storage)

        # Parse collectors to run
        collectors_to_run = None
        if args.collectors:
            collectors_to_run = [c.strip() for c in args.collectors.split(",")]
            # Validate collector names
            valid_collectors = list_collector_names()
            for c in collectors_to_run:
                if c not in valid_collectors:
                    tracker.fail(f"Unknown collector '{c}'")
                    print(f"Error: Unknown collector '{c}'")
                    print(f"Valid collectors: {', '.join(valid_collectors)}")
                    return 1

        # Step 1: Collection
        step_index = 0
        tracker.set_phase(ProgressPhase.COLLECTING)
        tracker.start_step(step_index, status="Collecting assets from AWS")

        assets, security_findings, results = run_collection(
            region=args.region,
            collectors=collectors_to_run,
        )

        tracker.update_step(status=f"Collected {len(assets)} assets")

        # Log warnings
        for result in results:
            if result.errors:
                for error in result.errors:
                    logger.warning(error)

        tracker.complete_step(step_index)
        step_index += 1

        # Step 2: Store assets (part of storage phase but interleaved)
        snapshot_id = generate_snapshot_id()
        storage.store_assets(assets, snapshot_id)

        # Step 3: Policy evaluation (unless secrets-only)
        if not secrets_only:
            tracker.set_phase(ProgressPhase.EVALUATING)
            tracker.start_step(step_index, status="Loading policies")

            # Load policies
            loader = PolicyLoader()
            policies = loader.load_all()
            policy_count = len(policies) if hasattr(policies, "__len__") else 0

            tracker.update_step(
                total=policy_count,
                status=f"Evaluating {policy_count} policies"
            )

            # Evaluate policies
            evaluator = PolicyEvaluator()
            findings, eval_result = evaluator.evaluate_all(policies, assets)

            # Merge security findings from collectors
            findings = findings.merge(security_findings)

            tracker.update_step(
                completed=policy_count,
                status=f"Evaluated {policy_count} policies, found {len(findings)} findings"
            )
            tracker.complete_step(step_index)
            step_index += 1
        else:
            # No policy evaluation in secrets-only mode
            findings = FindingCollection([])
            eval_result = None

        # Step 4: Secrets detection (if enabled)
        secrets_count = 0
        if enable_secrets:
            tracker.start_step(step_index, status="Scanning for secrets")

            from stance.detection import SecretsDetector, scan_assets_for_secrets

            detector = SecretsDetector()
            asset_count = len(assets)
            tracker.update_step(total=asset_count)

            secrets_results, secrets_findings = scan_assets_for_secrets(
                list(assets), detector
            )

            # Merge secrets findings
            if secrets_findings:
                secrets_count = len(secrets_findings)
                findings = findings.merge(FindingCollection(secrets_findings))

            tracker.update_step(
                completed=asset_count,
                status=f"Found {secrets_count} secrets"
            )
            tracker.complete_step(step_index)
            step_index += 1

        # Step 5: Storage
        tracker.set_phase(ProgressPhase.STORING)
        tracker.start_step(step_index, status="Storing findings")

        storage.store_findings(findings, snapshot_id)

        tracker.update_step(status=f"Stored {len(findings)} findings")
        tracker.complete_step(step_index)

        # Complete the scan
        tracker.complete()

        # Print summary
        if args.output == "json":
            summary = {
                "snapshot_id": snapshot_id,
                "assets_collected": len(assets),
                "policies_evaluated": eval_result.policies_evaluated if eval_result else 0,
                "findings_generated": len(findings),
                "findings_by_severity": findings.count_by_severity_dict(),
                "secrets_detected": secrets_count if enable_secrets else None,
                "duration_seconds": eval_result.duration_seconds if eval_result else 0,
            }
            print(json.dumps(summary, indent=2))
        elif args.output != "quiet" and not show_progress:
            # Only print summary if progress wasn't shown (quiet or non-table output)
            print()
            print("Scan complete.")
            print(f"  Snapshot ID: {snapshot_id}")
            print(f"  Assets discovered: {len(assets)}")
            if eval_result:
                print(f"  Policies evaluated: {eval_result.policies_evaluated}")
            if enable_secrets:
                print(f"  Secrets detected: {secrets_count}")
            print(f"  Findings generated: {len(findings)}")

            severity_counts = findings.count_by_severity_dict()
            if severity_counts:
                print("  Findings by severity:")
                for severity, count in severity_counts.items():
                    if count > 0:
                        print(f"    {severity}: {count}")

        return 0

    except Exception as e:
        tracker.fail(str(e))
        logger.exception("Scan failed")
        print(f"Error: {e}")
        return 1


def cmd_query(args: argparse.Namespace) -> int:
    """
    Execute natural language or SQL query.

    Steps:
        1. Get LLM provider (if not --no-llm)
        2. Generate SQL from question
        3. Validate query
        4. Execute against storage
        5. Format and print results

    Returns:
        Exit code
    """
    from stance.storage import get_storage

    try:
        storage = get_storage("local")

        if args.no_llm:
            # User provided SQL directly
            sql = args.question

            # Basic validation
            normalized = " ".join(sql.split()).upper()
            if not normalized.startswith("SELECT"):
                print("Error: Query must be a SELECT statement")
                return 1
        else:
            # Use LLM to generate SQL
            from stance.llm import get_llm_provider, QueryGenerator

            try:
                provider = get_llm_provider(args.llm_provider)
            except Exception as e:
                print(f"Error initializing LLM provider: {e}")
                return 1

            generator = QueryGenerator(provider)
            result = generator.generate_query(args.question)

            if not result.is_valid:
                print("Error: Generated query is invalid")
                for error in result.validation_errors:
                    print(f"  - {error}")
                return 1

            sql = result.sql

            if not args.quiet:
                print(f"Generated SQL: {sql}")
                print()

        # Add LIMIT if not present
        if "LIMIT" not in sql.upper():
            sql = f"{sql.rstrip(';')} LIMIT {args.limit}"

        # Execute query
        # Determine which table to query based on SQL
        sql_upper = sql.upper()
        if "FROM ASSETS" in sql_upper or "FROM ASSET" in sql_upper:
            results = storage.query_assets(sql)
        elif "FROM FINDINGS" in sql_upper or "FROM FINDING" in sql_upper:
            results = storage.query_findings(sql)
        else:
            # Default to findings
            results = storage.query_findings(sql)

        # Format output
        if not results:
            print("No results found.")
            return 0

        output = format_output(results, args.format)
        print(output)

        return 0

    except Exception as e:
        logger.exception("Query failed")
        print(f"Error: {e}")
        return 1


def cmd_report(args: argparse.Namespace) -> int:
    """
    Generate compliance report.

    Steps:
        1. Load latest findings and assets
        2. Load policies
        3. Calculate compliance scores
        4. Generate report in requested format
        5. Write to file or stdout

    Returns:
        Exit code
    """
    from stance.storage import get_storage
    from stance.engine import PolicyLoader, ComplianceCalculator

    try:
        storage = get_storage("local")

        # Load data
        snapshot_id = storage.get_latest_snapshot_id()
        if not snapshot_id:
            print("Error: No scan data found. Run 'stance scan' first.")
            return 1

        assets = storage.get_assets(snapshot_id)
        findings = storage.get_findings(snapshot_id)

        # Load policies
        loader = PolicyLoader()
        policies = loader.load_all()

        # Calculate compliance
        calculator = ComplianceCalculator()
        report = calculator.calculate_scores(policies, findings, assets, snapshot_id)

        # Filter by framework if specified
        if args.framework and args.framework != "all":
            report.frameworks = [
                f for f in report.frameworks
                if f.framework_id.lower() == args.framework.lower()
            ]

        # Generate output
        if args.format == "json":
            output = report.to_json()
        elif args.format == "csv":
            output = format_compliance_csv(report)
        else:  # html
            output = format_compliance_html(report)

        # Write output
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Report written to: {args.output}")
        else:
            print(output)

        return 0

    except Exception as e:
        logger.exception("Report generation failed")
        print(f"Error: {e}")
        return 1


def cmd_policies(args: argparse.Namespace) -> int:
    """
    Manage policies: list, validate, generate, or get suggestions.

    Routes to appropriate handler based on subcommand:
    - list: List policies with optional filters
    - validate: Validate policy files
    - generate: Generate policy from natural language (AI)
    - suggest: Get policy suggestions for a resource type (AI)

    Returns:
        Exit code
    """
    # Check for subcommand
    policies_action = getattr(args, "policies_action", None)

    if policies_action == "generate":
        return cmd_policies_generate(args)
    elif policies_action == "suggest":
        return cmd_policies_suggest(args)
    elif policies_action == "validate":
        return cmd_policies_validate(args)
    elif policies_action == "list":
        return cmd_policies_list(args)
    else:
        # Backwards compatibility: check for positional action
        action = getattr(args, "action", None)
        if action == "validate":
            return cmd_policies_validate(args)
        else:
            # Default to list
            return cmd_policies_list(args)


def cmd_policies_list(args: argparse.Namespace) -> int:
    """
    List policies with optional filters.

    Returns:
        Exit code
    """
    from stance.engine import PolicyLoader
    from stance.models import Severity

    try:
        loader = PolicyLoader()
        policies = loader.load_all()

        # Apply filters
        severity = getattr(args, "severity", None)
        if severity:
            severity_enum = Severity.from_string(severity)
            policies = policies.filter_by_severity(severity_enum)

        framework = getattr(args, "framework", None)
        if framework:
            policies = policies.filter_by_framework(framework)

        if not policies:
            print("No policies found matching criteria.")
            return 0

        # Format output
        data = []
        for policy in policies:
            data.append({
                "id": policy.id,
                "name": policy.name,
                "severity": policy.severity.value,
                "resource_type": policy.resource_type,
                "enabled": policy.enabled,
            })

        output = format_output(data, "table")
        print(output)

        return 0

    except Exception as e:
        logger.exception("Policy list command failed")
        print(f"Error: {e}")
        return 1


def cmd_policies_validate(args: argparse.Namespace) -> int:
    """
    Validate policy files.

    Returns:
        Exit code
    """
    from stance.engine import PolicyLoader

    try:
        loader = PolicyLoader()
        policy_files = loader.discover_policies()
        errors_found = False

        for path in policy_files:
            try:
                policy = loader.load_policy(path)
                validation_errors = loader.validate_policy(policy)

                if validation_errors:
                    errors_found = True
                    print(f"{path}:")
                    for error in validation_errors:
                        print(f"  - {error}")
                else:
                    print(f"{path}: OK")

            except Exception as e:
                errors_found = True
                print(f"{path}: ERROR - {e}")

        return 1 if errors_found else 0

    except Exception as e:
        logger.exception("Policy validate command failed")
        print(f"Error: {e}")
        return 1


def cmd_policies_generate(args: argparse.Namespace) -> int:
    """
    Generate a security policy from natural language description using AI.

    Returns:
        Exit code
    """
    from stance.llm.policy_generator import PolicyGenerator, save_policy
    from stance.llm import get_llm_provider

    try:
        # Initialize LLM provider
        try:
            llm_provider = get_llm_provider(args.llm_provider)
        except Exception as e:
            print(f"Error initializing LLM provider '{args.llm_provider}': {e}")
            print("Ensure you have set the appropriate API key environment variable:")
            print("  - ANTHROPIC_API_KEY for anthropic")
            print("  - OPENAI_API_KEY for openai")
            print("  - GOOGLE_API_KEY for gemini")
            return 1

        # Create generator
        generator = PolicyGenerator(
            llm_provider=llm_provider,
            cloud_provider=args.cloud,
        )

        print(f"Generating policy for: {args.description}")
        print("(This may take a few seconds...)")
        print()

        # Generate policy
        result = generator.generate_policy(
            description=args.description,
            severity=getattr(args, "severity", None),
            resource_type=getattr(args, "resource_type", None),
            compliance_framework=getattr(args, "framework", None),
        )

        if not result.is_valid:
            print("Error: Generated policy is invalid")
            if result.error:
                print(f"  {result.error}")
            for error in result.validation_errors:
                print(f"  - {error}")
            print()
            print("Generated content (for debugging):")
            print("-" * 40)
            print(result.yaml_content or "(empty)")
            return 1

        # Output the policy
        output_format = getattr(args, "format", "yaml")
        output_path = getattr(args, "output", None)

        if output_format == "json":
            output = json.dumps({
                "policy_id": result.policy_id,
                "policy_name": result.policy_name,
                "resource_type": result.resource_type,
                "severity": result.severity,
                "yaml_content": result.yaml_content,
                "is_valid": result.is_valid,
            }, indent=2)
        else:
            output = result.yaml_content

        if output_path:
            if save_policy(result, output_path):
                print(f"Policy saved to: {output_path}")
                print()
                print("Policy summary:")
                print(f"  ID: {result.policy_id}")
                print(f"  Name: {result.policy_name}")
                print(f"  Resource Type: {result.resource_type}")
                print(f"  Severity: {result.severity}")
            else:
                print(f"Error: Failed to save policy to {output_path}")
                return 1
        else:
            print("Generated Policy:")
            print("=" * 50)
            print(output)
            print("=" * 50)
            print()
            print("To save this policy, use: --output path/to/policy.yaml")

        return 0

    except Exception as e:
        logger.exception("Policy generate command failed")
        print(f"Error: {e}")
        return 1


def cmd_policies_suggest(args: argparse.Namespace) -> int:
    """
    Get AI-powered policy suggestions for a resource type.

    Returns:
        Exit code
    """
    from stance.llm.policy_generator import PolicyGenerator
    from stance.llm import get_llm_provider

    try:
        # Initialize LLM provider
        try:
            llm_provider = get_llm_provider(args.llm_provider)
        except Exception as e:
            print(f"Error initializing LLM provider '{args.llm_provider}': {e}")
            return 1

        # Create generator
        generator = PolicyGenerator(llm_provider=llm_provider)

        print(f"Getting policy suggestions for: {args.resource_type}")
        print()

        # Get suggestions
        suggestions = generator.suggest_policy_ideas(
            resource_type=args.resource_type,
            count=args.count,
        )

        if not suggestions:
            print("No suggestions generated.")
            return 0

        print("Policy Suggestions:")
        print("-" * 50)
        for i, suggestion in enumerate(suggestions, 1):
            print(f"{i}. {suggestion}")
        print("-" * 50)
        print()
        print("To generate a policy, use:")
        print(f'  stance policies generate "{suggestions[0]}" --cloud aws')

        return 0

    except Exception as e:
        logger.exception("Policy suggest command failed")
        print(f"Error: {e}")
        return 1


def cmd_findings(args: argparse.Namespace) -> int:
    """
    View findings with filters or get AI-powered explanations.

    Routes to appropriate handler based on subcommand:
    - list: View findings with filters (default)
    - explain: Get AI-powered explanation for a finding

    Returns:
        Exit code
    """
    # Check for subcommand
    findings_action = getattr(args, "findings_action", None)

    if findings_action == "explain":
        return cmd_findings_explain(args)
    else:
        # Default to list behavior (both explicit 'list' and no subcommand)
        return cmd_findings_list(args)


def cmd_findings_list(args: argparse.Namespace) -> int:
    """
    List findings with filters.

    Returns:
        Exit code
    """
    from stance.storage import get_storage
    from stance.models import Severity, FindingStatus

    try:
        storage = get_storage("local")

        # Get latest snapshot
        snapshot_id = storage.get_latest_snapshot_id()
        if not snapshot_id:
            print("No scan data found. Run 'stance scan' first.")
            return 0

        # Get findings with filters
        severity = None
        status = None

        if getattr(args, "severity", None):
            severity = Severity.from_string(args.severity)

        if getattr(args, "status", None):
            status = FindingStatus.from_string(args.status)

        findings = storage.get_findings(snapshot_id, severity=severity, status=status)

        # Apply additional filters
        if getattr(args, "asset_id", None):
            findings = findings.filter_by_asset(args.asset_id)

        if not findings:
            print("No findings found matching criteria.")
            return 0

        # Format output
        data = []
        for finding in findings:
            data.append({
                "id": finding.id[:16] + "..." if len(finding.id) > 16 else finding.id,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "title": finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                "asset_id": finding.asset_id[:40] + "..." if len(finding.asset_id) > 40 else finding.asset_id,
            })

        output = format_output(data, getattr(args, "format", "table"))
        print(output)

        print(f"\nTotal: {len(findings)} findings")

        return 0

    except Exception as e:
        logger.exception("Findings list command failed")
        print(f"Error: {e}")
        return 1


def cmd_findings_explain(args: argparse.Namespace) -> int:
    """
    Get AI-powered explanation for a security finding.

    Uses LLM to generate detailed, actionable explanations including:
    - Risk analysis
    - Business impact assessment
    - Step-by-step remediation guidance
    - Technical details

    Returns:
        Exit code
    """
    from stance.storage import get_storage
    from stance.llm.explainer import FindingExplainer
    from stance.llm import get_llm_provider

    try:
        storage = get_storage("local")

        # Get latest snapshot
        snapshot_id = storage.get_latest_snapshot_id()
        if not snapshot_id:
            print("No scan data found. Run 'stance scan' first.")
            return 1

        # Get all findings and search for the specified one
        findings = storage.get_findings(snapshot_id)
        finding = None

        # Search by ID (exact match or prefix)
        for f in findings:
            if f.id == args.finding_id or f.id.startswith(args.finding_id):
                finding = f
                break

        if not finding:
            print(f"Finding '{args.finding_id}' not found.")
            print("Use 'stance findings list' to see available findings.")
            return 1

        # Initialize LLM provider
        try:
            llm_provider = get_llm_provider(args.llm_provider)
        except Exception as e:
            print(f"Error initializing LLM provider '{args.llm_provider}': {e}")
            print("Ensure you have set the appropriate API key environment variable:")
            print("  - ANTHROPIC_API_KEY for anthropic")
            print("  - OPENAI_API_KEY for openai")
            print("  - GOOGLE_API_KEY for gemini")
            return 1

        # Create explainer and generate explanation
        explainer = FindingExplainer(llm_provider=llm_provider)

        print(f"Generating explanation for finding: {finding.id}")
        print("(This may take a few seconds...)")
        print()

        include_remediation = not getattr(args, "no_remediation", False)
        explanation = explainer.explain_finding(
            finding,
            include_remediation=include_remediation,
        )

        if not explanation.is_valid:
            print(f"Error generating explanation: {explanation.error}")
            return 1

        # Output the explanation
        output_format = getattr(args, "format", "text")
        if output_format == "json":
            output = json.dumps({
                "finding_id": explanation.finding_id,
                "summary": explanation.summary,
                "risk_explanation": explanation.risk_explanation,
                "business_impact": explanation.business_impact,
                "remediation_steps": explanation.remediation_steps,
                "technical_details": explanation.technical_details,
                "references": explanation.references,
            }, indent=2)
            print(output)
        else:
            # Text format
            _print_explanation_text(finding, explanation)

        return 0

    except Exception as e:
        logger.exception("Findings explain command failed")
        print(f"Error: {e}")
        return 1


def _print_explanation_text(finding, explanation) -> None:
    """Print explanation in human-readable text format."""
    print("=" * 70)
    print(f"FINDING: {finding.title}")
    print("=" * 70)
    print()
    print(f"ID: {finding.id}")
    print(f"Severity: {finding.severity.value.upper()}")
    print(f"Type: {finding.finding_type.value}")
    print()

    if explanation.summary:
        print("SUMMARY")
        print("-" * 40)
        print(explanation.summary)
        print()

    if explanation.risk_explanation:
        print("RISK ANALYSIS")
        print("-" * 40)
        print(explanation.risk_explanation)
        print()

    if explanation.business_impact:
        print("BUSINESS IMPACT")
        print("-" * 40)
        print(explanation.business_impact)
        print()

    if explanation.remediation_steps:
        print("REMEDIATION STEPS")
        print("-" * 40)
        for i, step in enumerate(explanation.remediation_steps, 1):
            print(f"  {i}. {step}")
        print()

    if explanation.technical_details:
        print("TECHNICAL DETAILS")
        print("-" * 40)
        print(explanation.technical_details)
        print()

    if explanation.references:
        print("REFERENCES")
        print("-" * 40)
        for ref in explanation.references:
            print(f"  - {ref}")
        print()

    print("=" * 70)
    print("Generated by Mantissa Stance AI Explainer")
    print("=" * 70)


def cmd_assets(args: argparse.Namespace) -> int:
    """
    View discovered assets.

    Returns:
        Exit code
    """
    from stance.storage import get_storage

    try:
        storage = get_storage("local")

        # Get latest snapshot
        snapshot_id = storage.get_latest_snapshot_id()
        if not snapshot_id:
            print("No scan data found. Run 'stance scan' first.")
            return 0

        assets = storage.get_assets(snapshot_id)

        # Apply filters
        if args.type:
            assets = assets.filter_by_type(args.type)

        if args.region:
            assets = assets.filter_by_region(args.region)

        if args.exposure:
            if args.exposure == "internet_facing":
                assets = assets.filter_internet_facing()
            else:
                # Filter by specific exposure
                filtered = [a for a in assets if a.network_exposure == args.exposure]
                from stance.models import AssetCollection
                assets = AssetCollection(filtered)

        if not assets:
            print("No assets found matching criteria.")
            return 0

        # Format output
        data = []
        for asset in assets:
            data.append({
                "id": asset.id[:50] + "..." if len(asset.id) > 50 else asset.id,
                "type": asset.resource_type,
                "name": asset.name[:30] + "..." if len(asset.name) > 30 else asset.name,
                "region": asset.region,
                "exposure": asset.network_exposure,
            })

        output = format_output(data, args.format)
        print(output)

        print(f"\nTotal: {len(assets)} assets")

        return 0

    except Exception as e:
        logger.exception("Assets command failed")
        print(f"Error: {e}")
        return 1


def cmd_dashboard(args: argparse.Namespace) -> int:
    """
    Start web dashboard.

    Returns:
        Exit code
    """
    import webbrowser

    try:
        # Import here to avoid circular imports
        from stance.web import serve_dashboard

        url = f"http://{args.host}:{args.port}"

        print("Mantissa Stance Dashboard")
        print(f"  URL: {url}")
        print("  Press Ctrl+C to stop")
        print()

        # Open browser if requested
        should_open = args.open and not args.no_open
        if should_open:
            webbrowser.open(url)

        # Start server (blocks until interrupted)
        serve_dashboard(
            host=args.host,
            port=args.port,
            open_browser=False,  # We handle it above
        )

        return 0

    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        return 0
    except ImportError:
        print("Error: Web dashboard module not available.")
        print("The dashboard requires the web module to be installed.")
        return 1
    except Exception as e:
        logger.exception("Dashboard failed")
        print(f"Error: {e}")
        return 1


# Output formatting functions


def format_output(data: list[dict[str, Any]], format_type: str) -> str:
    """
    Format data for output.

    Args:
        data: List of dictionaries to format
        format_type: Output format (table, json, csv)

    Returns:
        Formatted string
    """
    if not data:
        return ""

    if format_type == "json":
        return json.dumps(data, indent=2, default=str)

    elif format_type == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        return output.getvalue()

    else:  # table
        return format_table(data)


def format_table(data: list[dict[str, Any]]) -> str:
    """
    Format data as ASCII table.

    Args:
        data: List of dictionaries

    Returns:
        Formatted table string
    """
    if not data:
        return ""

    # Get column headers
    headers = list(data[0].keys())

    # Calculate column widths
    widths = {h: len(str(h)) for h in headers}
    for row in data:
        for h in headers:
            value = str(row.get(h, ""))
            widths[h] = max(widths[h], len(value))

    # Build table
    lines = []

    # Header
    header_line = " | ".join(str(h).ljust(widths[h]) for h in headers)
    lines.append(header_line)

    # Separator
    separator = "-+-".join("-" * widths[h] for h in headers)
    lines.append(separator)

    # Data rows
    for row in data:
        row_line = " | ".join(
            str(row.get(h, "")).ljust(widths[h]) for h in headers
        )
        lines.append(row_line)

    return "\n".join(lines)


def format_compliance_html(report: Any) -> str:
    """
    Format compliance report as HTML.

    Args:
        report: ComplianceReport object

    Returns:
        HTML string
    """
    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "<meta charset=\"utf-8\">",
        "<title>Compliance Report - Mantissa Stance</title>",
        "<style>",
        "body { font-family: system-ui, -apple-system, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }",
        "h1 { color: #1a1a1a; }",
        "h2 { color: #333; margin-top: 30px; }",
        ".score { font-size: 48px; font-weight: bold; }",
        ".score.good { color: #22c55e; }",
        ".score.warning { color: #f59e0b; }",
        ".score.bad { color: #ef4444; }",
        "table { border-collapse: collapse; width: 100%; margin-top: 20px; }",
        "th, td { text-align: left; padding: 12px; border-bottom: 1px solid #e0e0e0; }",
        "th { background: #f5f5f5; }",
        ".pass { color: #22c55e; }",
        ".fail { color: #ef4444; }",
        ".meta { color: #666; font-size: 14px; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>Compliance Report</h1>",
        f"<p class=\"meta\">Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>",
        f"<p class=\"meta\">Snapshot: {report.snapshot_id}</p>",
    ]

    # Overall score
    score_class = "good" if report.overall_score >= 80 else ("warning" if report.overall_score >= 60 else "bad")
    html_parts.append(f"<p class=\"score {score_class}\">{report.overall_score:.1f}%</p>")
    html_parts.append("<p>Overall Compliance Score</p>")

    # Framework sections
    for framework in report.frameworks:
        html_parts.append(f"<h2>{framework.framework_name}</h2>")
        if framework.version:
            html_parts.append(f"<p class=\"meta\">Version: {framework.version}</p>")

        html_parts.append(f"<p>Score: <strong>{framework.score_percentage:.1f}%</strong></p>")
        html_parts.append(f"<p>Controls: {framework.controls_passed} passed / {framework.controls_failed} failed / {framework.controls_total} total</p>")

        if framework.control_statuses:
            html_parts.append("<table>")
            html_parts.append("<tr><th>Control</th><th>Name</th><th>Status</th><th>Resources</th></tr>")

            for control in framework.control_statuses:
                status_class = "pass" if control.status == "pass" else "fail"
                html_parts.append(
                    f"<tr>"
                    f"<td>{control.control_id}</td>"
                    f"<td>{control.control_name}</td>"
                    f"<td class=\"{status_class}\">{control.status.upper()}</td>"
                    f"<td>{control.resources_compliant}/{control.resources_evaluated}</td>"
                    f"</tr>"
                )

            html_parts.append("</table>")

    html_parts.extend([
        "</body>",
        "</html>",
    ])

    return "\n".join(html_parts)


def cmd_notify(args: argparse.Namespace) -> int:
    """
    Send notifications for findings.

    Supports sending to various destinations:
    - Slack (webhook)
    - PagerDuty (events API)
    - Email (SMTP)
    - Microsoft Teams (webhook)
    - Jira (REST API)
    - Generic webhook

    Returns:
        Exit code
    """
    from stance.storage import get_storage
    from stance.models import Severity
    from stance.alerting import (
        create_destination,
        get_template_for_finding,
        SlackDestination,
        PagerDutyDestination,
        EmailDestination,
        TeamsDestination,
        WebhookDestination,
    )

    try:
        # Handle test action
        if args.action == "test":
            return _send_test_notification(args)

        # Get storage and load findings
        storage = get_storage("local")
        snapshot_id = storage.get_latest_snapshot_id()

        if not snapshot_id:
            print("Error: No scan data found. Run 'stance scan' first.")
            return 1

        findings = storage.get_findings(snapshot_id)

        # Filter findings
        if args.finding_id:
            # Get specific finding
            finding = next(
                (f for f in findings if f.id == args.finding_id),
                None
            )
            if not finding:
                print(f"Error: Finding '{args.finding_id}' not found.")
                return 1
            findings_to_notify = [finding]
        elif args.severity:
            # Filter by severity
            severity = Severity.from_string(args.severity)
            findings_to_notify = [f for f in findings if f.severity == severity]
            if not findings_to_notify:
                print(f"No findings with severity '{args.severity}' found.")
                return 0
        else:
            print("Error: Must specify either --finding-id or --severity")
            return 1

        # Create destination
        destination = _create_destination_from_args(args)
        if not destination:
            return 1

        # Send notifications
        sent_count = 0
        error_count = 0

        for finding in findings_to_notify:
            template = get_template_for_finding(finding)

            if args.dry_run:
                # Preview mode
                print(f"\n--- Finding: {finding.id} ---")
                print(f"Severity: {finding.severity.value}")
                print(f"Title: {finding.title}")
                print(f"Would send to: {args.destination}")
                print(f"Template: {template.__class__.__name__}")
                sent_count += 1
            else:
                try:
                    result = destination.send(finding, template)
                    if result.success:
                        sent_count += 1
                        if not args.quiet:
                            print(f"Sent notification for: {finding.id}")
                    else:
                        error_count += 1
                        print(f"Failed to send notification for {finding.id}: {result.error}")
                except Exception as e:
                    error_count += 1
                    print(f"Error sending notification for {finding.id}: {e}")

        # Summary
        print()
        if args.dry_run:
            print(f"Dry run: {sent_count} notifications would be sent")
        else:
            print(f"Sent: {sent_count} notifications")
            if error_count:
                print(f"Failed: {error_count} notifications")

        return 0 if error_count == 0 else 1

    except Exception as e:
        logger.exception("Notify command failed")
        print(f"Error: {e}")
        return 1


def _send_test_notification(args: argparse.Namespace) -> int:
    """Send a test notification to verify configuration."""
    from stance.models import Finding, FindingType, Severity, FindingStatus
    from stance.alerting import get_template_for_finding

    # Create a test finding
    test_finding = Finding(
        id="test-finding-001",
        asset_id="test-asset-001",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        title="[TEST] Mantissa Stance Test Notification",
        description="This is a test notification from Mantissa Stance. If you receive this message, your alerting configuration is working correctly.",
        rule_id="test-rule",
        remediation_guidance="No action required - this is a test notification.",
    )

    # Create destination
    destination = _create_destination_from_args(args)
    if not destination:
        return 1

    template = get_template_for_finding(test_finding)

    if args.dry_run:
        print("Test notification preview:")
        print(f"  Destination: {args.destination}")
        print(f"  Title: {test_finding.title}")
        print(f"  Severity: {test_finding.severity.value}")
        return 0

    try:
        result = destination.send(test_finding, template)
        if result.success:
            print("Test notification sent successfully.")
            return 0
        else:
            print(f"Failed to send test notification: {result.error}")
            return 1
    except Exception as e:
        print(f"Error sending test notification: {e}")
        return 1


def _create_destination_from_args(args: argparse.Namespace):
    """Create a destination instance from CLI arguments."""
    import os
    from stance.alerting import (
        create_destination,
        SlackDestination,
        PagerDutyDestination,
        EmailDestination,
        TeamsDestination,
        WebhookDestination,
    )

    dest_type = args.destination.lower()

    try:
        if dest_type == "slack":
            webhook_url = args.webhook_url or os.getenv("SLACK_WEBHOOK_URL")
            if not webhook_url:
                print("Error: Slack requires --webhook-url or SLACK_WEBHOOK_URL environment variable")
                return None
            return SlackDestination(webhook_url=webhook_url)

        elif dest_type == "pagerduty":
            routing_key = os.getenv("PAGERDUTY_ROUTING_KEY")
            if not routing_key:
                print("Error: PagerDuty requires PAGERDUTY_ROUTING_KEY environment variable")
                return None
            return PagerDutyDestination(routing_key=routing_key)

        elif dest_type == "email":
            smtp_host = os.getenv("SMTP_HOST")
            smtp_from = os.getenv("SMTP_FROM")
            smtp_to = os.getenv("SMTP_TO")
            if not all([smtp_host, smtp_from, smtp_to]):
                print("Error: Email requires SMTP_HOST, SMTP_FROM, and SMTP_TO environment variables")
                return None
            return EmailDestination(
                smtp_host=smtp_host,
                smtp_port=int(os.getenv("SMTP_PORT", "587")),
                from_address=smtp_from,
                to_addresses=smtp_to.split(","),
                username=os.getenv("SMTP_USERNAME"),
                password=os.getenv("SMTP_PASSWORD"),
            )

        elif dest_type == "teams":
            webhook_url = args.webhook_url or os.getenv("TEAMS_WEBHOOK_URL")
            if not webhook_url:
                print("Error: Teams requires --webhook-url or TEAMS_WEBHOOK_URL environment variable")
                return None
            return TeamsDestination(webhook_url=webhook_url)

        elif dest_type == "webhook":
            webhook_url = args.webhook_url or os.getenv("WEBHOOK_URL")
            if not webhook_url:
                print("Error: Webhook requires --webhook-url or WEBHOOK_URL environment variable")
                return None
            return WebhookDestination(
                webhook_url=webhook_url,
                headers={"Content-Type": "application/json"},
            )

        else:
            print(f"Error: Unknown destination type '{dest_type}'")
            print("Valid destinations: slack, pagerduty, email, teams, webhook")
            return None

    except Exception as e:
        print(f"Error creating destination: {e}")
        return None


def format_compliance_csv(report: Any) -> str:
    """
    Format compliance report as CSV.

    Args:
        report: ComplianceReport object

    Returns:
        CSV string
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "framework",
        "version",
        "control_id",
        "control_name",
        "status",
        "resources_evaluated",
        "resources_compliant",
        "resources_non_compliant",
    ])

    # Data
    for framework in report.frameworks:
        for control in framework.control_statuses:
            writer.writerow([
                framework.framework_id,
                framework.version,
                control.control_id,
                control.control_name,
                control.status,
                control.resources_evaluated,
                control.resources_compliant,
                control.resources_non_compliant,
            ])

    return output.getvalue()


# =============================================================================
# Image Scanning Commands
# =============================================================================

def cmd_image_scan(args: argparse.Namespace) -> int:
    """Execute container image vulnerability scanning.

    Args:
        args: Command line arguments

    Returns:
        Exit code (0 for success, 1 for vulnerabilities found matching fail-on)
    """
    from stance.scanner import TrivyScanner, ScannerNotAvailableError, ScannerTimeoutError

    # Initialize scanner
    scanner = TrivyScanner()

    # Check if Trivy is available
    if not scanner.is_available():
        print("Error: Trivy scanner is not available.", file=sys.stderr)
        print("Please install Trivy: https://aquasecurity.github.io/trivy/", file=sys.stderr)
        return 1

    version = scanner.get_version()
    if version:
        print(f"Using Trivy version: {version}")

    # Parse severity filter
    severity_filter = None
    if args.severity:
        from stance.scanner import VulnerabilitySeverity
        severity_filter = set()
        for sev in args.severity.upper().split(","):
            sev = sev.strip()
            if sev in VulnerabilitySeverity.__members__:
                severity_filter.add(VulnerabilitySeverity[sev])

    # Scan images
    results = []
    for image in args.images:
        print(f"Scanning image: {image}...")
        try:
            result = scanner.scan(
                image_ref=image,
                timeout=args.timeout,
                skip_db_update=args.skip_db_update,
                ignore_unfixed=args.ignore_unfixed,
                severity_filter=severity_filter,
            )
            results.append(result)
        except ScannerTimeoutError:
            print(f"  Timeout scanning {image}", file=sys.stderr)
        except Exception as e:
            print(f"  Error scanning {image}: {e}", file=sys.stderr)

    if not results:
        print("No images were successfully scanned.")
        return 1

    # Output results
    if args.format == "json":
        print(_output_scan_json(results))
    elif args.format == "sarif":
        print(_output_scan_sarif(results))
    else:
        _output_scan_table(results)

    # Check fail-on threshold
    if args.fail_on:
        from stance.scanner import VulnerabilitySeverity
        fail_severity = VulnerabilitySeverity[args.fail_on.upper()]
        severity_order = [
            VulnerabilitySeverity.UNKNOWN,
            VulnerabilitySeverity.LOW,
            VulnerabilitySeverity.MEDIUM,
            VulnerabilitySeverity.HIGH,
            VulnerabilitySeverity.CRITICAL,
        ]
        fail_index = severity_order.index(fail_severity)

        for result in results:
            for vuln in result.vulnerabilities:
                vuln_index = severity_order.index(vuln.severity)
                if vuln_index >= fail_index:
                    print(f"\nFailing due to {vuln.severity.value} vulnerability: {vuln.vulnerability_id}")
                    return 1

    return 0


def _output_scan_table(results: list) -> None:
    """Output scan results as a formatted table."""
    for result in results:
        print(f"\n{'='*60}")
        print(f"Image: {result.image_ref}")
        print(f"Scanned: {result.scanned_at.isoformat()}")
        print(f"{'='*60}")

        if not result.vulnerabilities:
            print("No vulnerabilities found.")
            continue

        print(f"\nFound {result.total_count} vulnerabilities:")
        print(f"  Critical: {result.critical_count}")
        print(f"  High: {result.high_count}")
        print(f"  Medium: {result.medium_count}")
        print(f"  Low: {result.low_count}")
        print(f"  Fixable: {result.fixable_count}")

        # Group by severity
        from stance.scanner import VulnerabilitySeverity
        by_severity = {}
        for vuln in result.vulnerabilities:
            if vuln.severity not in by_severity:
                by_severity[vuln.severity] = []
            by_severity[vuln.severity].append(vuln)

        for severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH,
                        VulnerabilitySeverity.MEDIUM, VulnerabilitySeverity.LOW]:
            if severity not in by_severity:
                continue

            print(f"\n{severity.value.upper()} ({len(by_severity[severity])}):")
            for vuln in by_severity[severity][:10]:  # Limit to 10 per severity
                fix_info = f" (fix: {vuln.fixed_version})" if vuln.fixed_version else ""
                print(f"  {vuln.vulnerability_id}: {vuln.package_name}@{vuln.installed_version}{fix_info}")

            if len(by_severity[severity]) > 10:
                print(f"  ... and {len(by_severity[severity]) - 10} more")


def _output_scan_json(results: list) -> str:
    """Output scan results as JSON."""
    output = []
    for result in results:
        output.append({
            "image_ref": result.image_ref,
            "scanned_at": result.scanned_at.isoformat(),
            "scanner": result.scanner,
            "scanner_version": result.scanner_version,
            "summary": {
                "total": result.total_count,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "fixable": result.fixable_count,
            },
            "vulnerabilities": [
                {
                    "id": v.vulnerability_id,
                    "package": v.package_name,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "title": v.title,
                    "description": v.description,
                    "references": v.references,
                }
                for v in result.vulnerabilities
            ],
        })
    return json.dumps(output, indent=2)


def _output_scan_sarif(results: list) -> str:
    """Output scan results in SARIF format for CI/CD integration."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }

    for result in results:
        rules = []
        results_list = []

        for i, vuln in enumerate(result.vulnerabilities):
            rule_id = vuln.vulnerability_id

            # Add rule
            rules.append({
                "id": rule_id,
                "name": vuln.title or rule_id,
                "shortDescription": {"text": f"{vuln.package_name} vulnerability"},
                "fullDescription": {"text": vuln.description or f"Vulnerability in {vuln.package_name}"},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(vuln.severity.value),
                },
                "helpUri": vuln.references[0] if vuln.references else None,
            })

            # Add result
            results_list.append({
                "ruleId": rule_id,
                "ruleIndex": i,
                "level": _severity_to_sarif_level(vuln.severity.value),
                "message": {
                    "text": f"{vuln.package_name}@{vuln.installed_version} has {vuln.severity.value} vulnerability {rule_id}"
                           + (f". Fixed in {vuln.fixed_version}" if vuln.fixed_version else ""),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.image_ref,
                        },
                    },
                }],
            })

        sarif["runs"].append({
            "tool": {
                "driver": {
                    "name": result.scanner,
                    "version": result.scanner_version,
                    "informationUri": "https://aquasecurity.github.io/trivy/",
                    "rules": rules,
                },
            },
            "results": results_list,
        })

    return json.dumps(sarif, indent=2)


def _severity_to_sarif_level(severity: str) -> str:
    """Convert vulnerability severity to SARIF level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "unknown": "note",
    }
    return mapping.get(severity.lower(), "note")


def cmd_iac_scan(args: argparse.Namespace) -> int:
    """Execute Infrastructure as Code scanning.

    Scans Terraform, CloudFormation, and ARM templates for security issues.

    Args:
        args: Command line arguments

    Returns:
        Exit code (0 for success, 1 for issues found matching fail-on)
    """
    import os
    from pathlib import Path
    from stance.iac import (
        IaCScanner,
        TerraformParser,
        CloudFormationParser,
        ARMTemplateParser,
        IaCPolicyLoader,
        IaCPolicyEvaluator,
        get_default_iac_policies,
    )

    # Collect files to scan
    files_to_scan: list[Path] = []
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_file():
            files_to_scan.append(path)
        elif path.is_dir():
            if args.recursive:
                # Recursively find IaC files
                for ext in ["*.tf", "*.json", "*.yaml", "*.yml", "*.template"]:
                    files_to_scan.extend(path.rglob(ext))
            else:
                for ext in ["*.tf", "*.json", "*.yaml", "*.yml", "*.template"]:
                    files_to_scan.extend(path.glob(ext))
        else:
            print(f"Warning: Path not found: {path}", file=sys.stderr)

    if not files_to_scan:
        print("No IaC files found to scan.")
        return 0

    print(f"Scanning {len(files_to_scan)} files...")

    # Initialize scanner with parsers
    scanner = IaCScanner()
    scanner.register_parser(TerraformParser())
    scanner.register_parser(CloudFormationParser())
    scanner.register_parser(ARMTemplateParser())

    # Load policies
    policies = get_default_iac_policies()

    # Load additional policies from directory if specified
    if args.policy_dir:
        policy_dir = Path(args.policy_dir)
        if policy_dir.is_dir():
            loader = IaCPolicyLoader()
            additional_policies = loader.load_all(policy_dir)
            for policy in additional_policies:
                policies.add_policy(policy)
            print(f"Loaded {len(additional_policies)} additional policies from {args.policy_dir}")

    # Create evaluator
    evaluator = IaCPolicyEvaluator(policies)
    scanner.set_policy_evaluator(evaluator)

    # Scan files
    all_findings = []
    files_scanned = 0
    files_with_issues = 0

    for file_path in files_to_scan:
        try:
            findings = scanner.scan_file(file_path)
            if findings:
                files_with_issues += 1
                all_findings.extend(findings)
            files_scanned += 1
        except Exception as e:
            print(f"  Error scanning {file_path}: {e}", file=sys.stderr)

    # Filter by severity if specified
    if args.severity:
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_index = severity_order.index(args.severity.lower())
        filtered_findings = []
        for f in all_findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            if severity_order.index(sev.lower()) >= min_index:
                filtered_findings.append(f)
        all_findings = filtered_findings

    # Output results
    if args.format == "json":
        output = _output_iac_json(all_findings, files_scanned, files_with_issues)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
    elif args.format == "sarif":
        output = _output_iac_sarif(all_findings, files_scanned)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
    else:
        _output_iac_table(all_findings, files_scanned, files_with_issues)

    # Check fail-on threshold
    if args.fail_on and all_findings:
        severity_order = ["info", "low", "medium", "high", "critical"]
        fail_index = severity_order.index(args.fail_on.lower())

        for finding in all_findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            finding_index = severity_order.index(sev.lower())
            if finding_index >= fail_index:
                print(f"\nFailing due to {sev} issue: {finding.rule_id}")
                return 1

    return 0


def _output_iac_table(findings: list, files_scanned: int, files_with_issues: int) -> None:
    """Output IaC scan results as a formatted table."""
    print(f"\n{'='*60}")
    print(f"IaC Scan Results")
    print(f"{'='*60}")
    print(f"Files scanned: {files_scanned}")
    print(f"Files with issues: {files_with_issues}")
    print(f"Total issues found: {len(findings)}")

    if not findings:
        print("\nNo security issues found.")
        return

    # Count by severity
    severity_counts = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        sev = sev.upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\nIssues by severity:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in severity_counts:
            print(f"  {sev}: {severity_counts[sev]}")

    # Group by file
    by_file = {}
    for f in findings:
        file_path = str(f.resource.location.file_path) if f.resource and f.resource.location else "unknown"
        if file_path not in by_file:
            by_file[file_path] = []
        by_file[file_path].append(f)

    print("\nFindings by file:")
    for file_path, file_findings in sorted(by_file.items()):
        print(f"\n  {file_path} ({len(file_findings)} issues):")
        for finding in file_findings[:10]:  # Limit to 10 per file
            loc = finding.resource.location if finding.resource else None
            line_info = f":{loc.line_start}" if loc and loc.line_start else ""
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            print(f"    [{sev.upper()}] {finding.rule_id}{line_info}: {finding.title}")

        if len(file_findings) > 10:
            print(f"    ... and {len(file_findings) - 10} more")


def _output_iac_json(findings: list, files_scanned: int, files_with_issues: int) -> str:
    """Output IaC scan results as JSON."""
    output = {
        "summary": {
            "files_scanned": files_scanned,
            "files_with_issues": files_with_issues,
            "total_issues": len(findings),
            "by_severity": {},
        },
        "findings": [],
    }

    # Count by severity
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        sev = sev.upper()
        output["summary"]["by_severity"][sev] = output["summary"]["by_severity"].get(sev, 0) + 1

    # Add findings
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        finding_dict = {
            "rule_id": f.rule_id,
            "severity": sev,
            "title": f.title,
            "description": f.description,
            "resource_type": f.resource.resource_type if f.resource else None,
            "resource_name": f.resource.name if f.resource else None,
        }
        if f.resource and f.resource.location:
            finding_dict["location"] = {
                "file": str(f.resource.location.file_path),
                "start_line": f.resource.location.line_start,
                "end_line": f.resource.location.line_end,
            }
        if f.remediation:
            finding_dict["remediation"] = f.remediation
        output["findings"].append(finding_dict)

    return json.dumps(output, indent=2)


def _output_iac_sarif(findings: list, files_scanned: int) -> str:
    """Output IaC scan results in SARIF format."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Mantissa Stance IaC Scanner",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/clay-good/mantissa-stance",
                    "rules": [],
                },
            },
            "results": [],
        }],
    }

    rules_added = set()
    rules = []
    results = []

    for i, finding in enumerate(findings):
        rule_id = finding.rule_id
        sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)

        # Add rule if not already added
        if rule_id not in rules_added:
            rules.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.title[:100] if finding.title else rule_id},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(sev),
                },
            })
            rules_added.add(rule_id)

        # Add result
        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(sev),
            "message": {"text": finding.description or finding.title},
        }

        if finding.resource and finding.resource.location:
            loc = finding.resource.location
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": str(loc.file_path),
                    },
                    "region": {
                        "startLine": loc.line_start or 1,
                        "endLine": loc.line_end or loc.line_start or 1,
                    },
                },
            }]

        results.append(result)

    sarif["runs"][0]["tool"]["driver"]["rules"] = rules
    sarif["runs"][0]["results"] = results

    return json.dumps(sarif, indent=2)


def cmd_secrets_scan(args: argparse.Namespace) -> int:
    """Execute secrets detection scanning.

    Scans files and configurations for hardcoded secrets, API keys,
    passwords, and other sensitive data.

    Args:
        args: Command line arguments

    Returns:
        Exit code (0 for success, 1 if secrets found and --fail-on-secrets)
    """
    import os
    import fnmatch
    from pathlib import Path
    from stance.detection.secrets import SecretsDetector, SecretMatch

    # Build exclude patterns
    exclude_patterns = []
    if args.exclude:
        exclude_patterns = [p.strip() for p in args.exclude.split(",")]

    # Default exclusions for common non-source files
    default_exclusions = [
        "*.lock", "*.min.js", "*.min.css", "*.map",
        "node_modules/*", ".git/*", "__pycache__/*",
        "*.pyc", "*.pyo", "*.so", "*.dylib",
        "*.exe", "*.dll", "*.bin",
    ]
    exclude_patterns.extend(default_exclusions)

    # Collect files to scan
    files_to_scan: list[Path] = []
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_file():
            files_to_scan.append(path)
        elif path.is_dir():
            if args.recursive:
                for file_path in path.rglob("*"):
                    if file_path.is_file():
                        files_to_scan.append(file_path)
            else:
                for file_path in path.glob("*"):
                    if file_path.is_file():
                        files_to_scan.append(file_path)
        else:
            print(f"Warning: Path not found: {path}", file=sys.stderr)

    # Filter out excluded files
    def should_exclude(file_path: Path) -> bool:
        path_str = str(file_path)
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                return True
        return False

    files_to_scan = [f for f in files_to_scan if not should_exclude(f)]

    if not files_to_scan:
        print("No files found to scan.")
        return 0

    print(f"Scanning {len(files_to_scan)} files for secrets...")

    # Initialize detector
    detector = SecretsDetector(min_entropy=args.min_entropy)

    # Scan files
    all_matches: list[tuple[Path, SecretMatch]] = []
    files_scanned = 0
    files_with_secrets = 0

    for file_path in files_to_scan:
        try:
            content = file_path.read_text(errors="ignore")
            matches = detector.detect_in_text(content, str(file_path))

            if matches:
                files_with_secrets += 1
                for match in matches:
                    all_matches.append((file_path, match))

            files_scanned += 1
        except Exception as e:
            # Skip files that can't be read (binary, permission denied, etc.)
            pass

    # Output results
    if args.format == "json":
        output = _output_secrets_json(all_matches, files_scanned, files_with_secrets)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
    else:
        _output_secrets_table(all_matches, files_scanned, files_with_secrets)

    # Check fail-on-secrets flag
    if args.fail_on_secrets and all_matches:
        print(f"\nFailing due to {len(all_matches)} secrets found.")
        return 1

    return 0


def _output_secrets_table(matches: list, files_scanned: int, files_with_secrets: int) -> None:
    """Output secrets scan results as a formatted table."""
    print(f"\n{'='*60}")
    print(f"Secrets Scan Results")
    print(f"{'='*60}")
    print(f"Files scanned: {files_scanned}")
    print(f"Files with secrets: {files_with_secrets}")
    print(f"Total secrets found: {len(matches)}")

    if not matches:
        print("\nNo secrets found.")
        return

    # Count by type
    type_counts = {}
    for _, match in matches:
        type_counts[match.secret_type] = type_counts.get(match.secret_type, 0) + 1

    print("\nSecrets by type:")
    for secret_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  {secret_type}: {count}")

    # Group by file
    by_file = {}
    for file_path, match in matches:
        key = str(file_path)
        if key not in by_file:
            by_file[key] = []
        by_file[key].append(match)

    print("\nFindings by file:")
    for file_path, file_matches in sorted(by_file.items()):
        print(f"\n  {file_path} ({len(file_matches)} secrets):")
        for match in file_matches[:5]:  # Limit to 5 per file
            # Redact the matched value
            redacted = _redact_secret(match.matched_value)
            confidence = f"[{match.confidence}]" if match.confidence else ""
            entropy_info = f" (entropy: {match.entropy:.2f})" if match.entropy else ""
            print(f"    {match.secret_type} {confidence}: {redacted}{entropy_info}")

        if len(file_matches) > 5:
            print(f"    ... and {len(file_matches) - 5} more")


def _output_secrets_json(matches: list, files_scanned: int, files_with_secrets: int) -> str:
    """Output secrets scan results as JSON."""
    output = {
        "summary": {
            "files_scanned": files_scanned,
            "files_with_secrets": files_with_secrets,
            "total_secrets": len(matches),
            "by_type": {},
        },
        "findings": [],
    }

    # Count by type
    for _, match in matches:
        output["summary"]["by_type"][match.secret_type] = \
            output["summary"]["by_type"].get(match.secret_type, 0) + 1

    # Add findings (with redacted values)
    for file_path, match in matches:
        output["findings"].append({
            "file": str(file_path),
            "secret_type": match.secret_type,
            "field_path": match.field_path,
            "matched_value_redacted": _redact_secret(match.matched_value),
            "confidence": match.confidence,
            "entropy": match.entropy,
            "line_number": match.line_number,
        })

    return json.dumps(output, indent=2)


def _redact_secret(value: str, visible_chars: int = 4) -> str:
    """Redact a secret value for safe display."""
    if len(value) <= visible_chars * 2:
        return "*" * len(value)
    return f"{value[:visible_chars]}{'*' * min(len(value) - visible_chars * 2, 20)}{value[-visible_chars:]}"


# =============================================================================
# Documentation Generation Command
# =============================================================================


def cmd_docs_generate(args: argparse.Namespace) -> int:
    """
    Generate API and CLI documentation.

    Generates documentation from source code docstrings and CLI parser.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code (0 success, 1 error)
    """
    from stance.docs import DocumentationGenerator

    source_dir = getattr(args, "source_dir", "src/stance")
    output_dir = getattr(args, "output_dir", "docs/generated")
    policies_dir = getattr(args, "policies_dir", "policies")
    doc_type = getattr(args, "type", "all")

    print(f"Generating documentation...")
    print(f"  Source: {source_dir}")
    print(f"  Output: {output_dir}")

    try:
        generator = DocumentationGenerator(
            source_dir=source_dir,
            output_dir=output_dir,
            policies_dir=policies_dir if policies_dir else None,
        )

        if doc_type == "all":
            results = generator.generate_all()
            total = sum(len(v) for v in results.values())
            print(f"\nGenerated {total} documentation files:")
            for dtype, files in results.items():
                if files:
                    print(f"  {dtype}: {len(files)} files")
        elif doc_type == "api":
            files = generator.generate_api()
            print(f"\nGenerated {len(files)} API documentation files")
        elif doc_type == "cli":
            filepath = generator.generate_cli()
            print(f"\nGenerated CLI documentation: {filepath}")
        elif doc_type == "policies":
            files = generator.generate_policies()
            print(f"\nGenerated {len(files)} policy documentation files")
        else:
            print(f"Unknown documentation type: {doc_type}", file=sys.stderr)
            return 1

        print(f"\nDocumentation written to: {output_dir}")
        return 0

    except Exception as e:
        print(f"Error generating documentation: {e}", file=sys.stderr)
        return 1
