"""
CLI command handlers for DSPM (Data Security Posture Management).

Provides commands for:
- Scanning cloud storage for sensitive data
- Analyzing data access patterns
- Cost analysis for data storage
- Extended source scanning (databases, SaaS)
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def cmd_dspm(args: argparse.Namespace) -> int:
    """
    Route DSPM subcommands to appropriate handlers.

    Returns:
        Exit code (0 success, 1 error)
    """
    action = getattr(args, "dspm_action", None)

    if action is None:
        print("Usage: stance dspm <command>")
        print("")
        print("Commands:")
        print("  scan       Scan storage for sensitive data")
        print("  access     Analyze data access patterns")
        print("  cost       Analyze storage costs and cold data")
        print("  classify   Classify sample data")
        print("")
        print("Run 'stance dspm <command> --help' for more information")
        return 0

    handlers = {
        "scan": _cmd_dspm_scan,
        "access": _cmd_dspm_access,
        "cost": _cmd_dspm_cost,
        "classify": _cmd_dspm_classify,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown DSPM command: {action}")
    return 1


def _cmd_dspm_scan(args: argparse.Namespace) -> int:
    """
    Scan cloud storage for sensitive data.

    Supports:
    - AWS S3 buckets
    - GCP Cloud Storage buckets
    - Azure Blob Storage containers
    """
    from stance.dspm.scanners import (
        S3DataScanner,
        GCSDataScanner,
        AzureBlobDataScanner,
        ScanConfig,
    )

    target = args.target
    cloud = args.cloud
    output_format = getattr(args, "format", "table")
    sample_size = getattr(args, "sample_size", 100)
    max_file_size = getattr(args, "max_file_size", 10 * 1024 * 1024)  # 10MB

    try:
        # Create scan config
        config = ScanConfig(
            sample_size=sample_size,
            max_file_size=max_file_size,
            include_patterns=args.include.split(",") if args.include else None,
            exclude_patterns=args.exclude.split(",") if args.exclude else None,
        )

        # Select scanner based on cloud provider
        if cloud == "aws":
            scanner = S3DataScanner(config)
        elif cloud == "gcp":
            scanner = GCSDataScanner(config)
        elif cloud == "azure":
            scanner = AzureBlobDataScanner(config)
        else:
            print(f"Error: Unknown cloud provider: {cloud}")
            return 1

        print(f"Scanning {target} for sensitive data...")
        result = scanner.scan(target)

        # Output results
        if output_format == "json":
            output = {
                "target": result.target,
                "cloud": result.cloud_provider,
                "started_at": result.started_at.isoformat() if result.started_at else None,
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "summary": {
                    "total_objects": result.summary.total_objects if result.summary else 0,
                    "objects_scanned": result.summary.objects_scanned if result.summary else 0,
                    "findings_count": result.summary.findings_count if result.summary else 0,
                },
                "findings": [
                    {
                        "object_key": f.object_key,
                        "classification": f.classification.name if f.classification else None,
                        "categories": [c.value for c in f.categories] if f.categories else [],
                        "severity": f.severity.value if f.severity else None,
                        "patterns_matched": f.patterns_matched,
                    }
                    for f in result.findings
                ],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Target: {result.target}")
            print(f"Cloud: {result.cloud_provider}")
            if result.summary:
                print(f"Objects scanned: {result.summary.objects_scanned}/{result.summary.total_objects}")
                print(f"Findings: {result.summary.findings_count}")
            print("")

            if result.findings:
                print("Sensitive Data Findings:")
                print("-" * 80)
                print(f"{'Object':<40} {'Classification':<15} {'Severity':<10} {'Patterns'}")
                print("-" * 80)

                for finding in result.findings[:50]:  # Limit output
                    obj_key = finding.object_key[:37] + "..." if len(finding.object_key) > 40 else finding.object_key
                    classification = finding.classification.name if finding.classification else "N/A"
                    severity = finding.severity.value if finding.severity else "N/A"
                    patterns = ", ".join(finding.patterns_matched[:3]) if finding.patterns_matched else "N/A"
                    print(f"{obj_key:<40} {classification:<15} {severity:<10} {patterns}")

                if len(result.findings) > 50:
                    print(f"... and {len(result.findings) - 50} more findings")
            else:
                print("No sensitive data findings detected.")

        return 0

    except Exception as e:
        logger.error(f"DSPM scan failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_dspm_access(args: argparse.Namespace) -> int:
    """
    Analyze data access patterns for stale permissions.
    """
    from stance.dspm.access import (
        CloudTrailAccessAnalyzer,
        GCPAuditLogAnalyzer,
        AzureActivityLogAnalyzer,
        AccessReviewConfig,
    )

    target = args.target
    cloud = args.cloud
    output_format = getattr(args, "format", "table")
    stale_days = getattr(args, "stale_days", 90)
    lookback_days = getattr(args, "lookback_days", 180)

    try:
        # Create config
        config = AccessReviewConfig(
            stale_days=stale_days,
            lookback_days=lookback_days,
        )

        # Select analyzer based on cloud provider
        if cloud == "aws":
            analyzer = CloudTrailAccessAnalyzer(config)
        elif cloud == "gcp":
            analyzer = GCPAuditLogAnalyzer(config)
        elif cloud == "azure":
            analyzer = AzureActivityLogAnalyzer(config)
        else:
            print(f"Error: Unknown cloud provider: {cloud}")
            return 1

        print(f"Analyzing access patterns for {target}...")
        result = analyzer.analyze(target)

        # Output results
        if output_format == "json":
            output = {
                "target": result.target,
                "cloud": result.cloud_provider,
                "analysis_period_days": result.analysis_period_days,
                "summary": {
                    "total_principals": result.summary.total_principals if result.summary else 0,
                    "stale_access_count": result.summary.stale_access_count if result.summary else 0,
                    "over_privileged_count": result.summary.over_privileged_count if result.summary else 0,
                },
                "findings": [
                    {
                        "principal": f.principal,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "days_since_access": f.days_since_access,
                        "recommendation": f.recommendation,
                    }
                    for f in result.findings
                ],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Target: {result.target}")
            print(f"Cloud: {result.cloud_provider}")
            print(f"Analysis period: {result.analysis_period_days} days")
            if result.summary:
                print(f"Total principals analyzed: {result.summary.total_principals}")
                print(f"Stale access findings: {result.summary.stale_access_count}")
                print(f"Over-privileged findings: {result.summary.over_privileged_count}")
            print("")

            if result.findings:
                print("Access Review Findings:")
                print("-" * 100)
                print(f"{'Principal':<40} {'Type':<20} {'Days Inactive':<15} {'Recommendation'}")
                print("-" * 100)

                for finding in result.findings[:50]:
                    principal = finding.principal[:37] + "..." if len(finding.principal) > 40 else finding.principal
                    finding_type = finding.finding_type.value if finding.finding_type else "N/A"
                    days = str(finding.days_since_access) if finding.days_since_access else "N/A"
                    rec = finding.recommendation[:40] if finding.recommendation else "N/A"
                    print(f"{principal:<40} {finding_type:<20} {days:<15} {rec}")

                if len(result.findings) > 50:
                    print(f"... and {len(result.findings) - 50} more findings")
            else:
                print("No stale or over-privileged access detected.")

        return 0

    except Exception as e:
        logger.error(f"DSPM access analysis failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_dspm_cost(args: argparse.Namespace) -> int:
    """
    Analyze storage costs and identify cold data.
    """
    from stance.dspm.cost import (
        S3CostAnalyzer,
        GCSCostAnalyzer,
        AzureCostAnalyzer,
        CostAnalysisConfig,
    )

    target = args.target
    cloud = args.cloud
    output_format = getattr(args, "format", "table")
    cold_data_days = getattr(args, "cold_days", 90)
    archive_days = getattr(args, "archive_days", 180)
    delete_days = getattr(args, "delete_days", 365)

    try:
        # Create config
        config = CostAnalysisConfig(
            cold_data_days=cold_data_days,
            archive_candidate_days=archive_days,
            delete_candidate_days=delete_days,
        )

        # Select analyzer based on cloud provider
        if cloud == "aws":
            analyzer = S3CostAnalyzer(config)
        elif cloud == "gcp":
            analyzer = GCSCostAnalyzer(config)
        elif cloud == "azure":
            analyzer = AzureCostAnalyzer(config)
        else:
            print(f"Error: Unknown cloud provider: {cloud}")
            return 1

        print(f"Analyzing storage costs for {target}...")
        result = analyzer.analyze(target)

        # Output results
        if output_format == "json":
            output = {
                "target": result.target,
                "cloud": result.cloud_provider,
                "metrics": {
                    "total_size_bytes": result.metrics.total_size_bytes if result.metrics else 0,
                    "object_count": result.metrics.object_count if result.metrics else 0,
                    "estimated_monthly_cost": result.metrics.estimated_monthly_cost if result.metrics else 0,
                },
                "potential_savings": result.potential_monthly_savings,
                "findings": [
                    {
                        "object_key": f.object_key,
                        "finding_type": f.finding_type.value if f.finding_type else None,
                        "days_since_access": f.days_since_access,
                        "size_bytes": f.size_bytes,
                        "current_tier": f.current_tier.value if f.current_tier else None,
                        "recommended_tier": f.recommended_tier.value if f.recommended_tier else None,
                    }
                    for f in result.findings
                ],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print(f"Target: {result.target}")
            print(f"Cloud: {result.cloud_provider}")
            if result.metrics:
                size_gb = result.metrics.total_size_bytes / (1024 ** 3)
                print(f"Total size: {size_gb:.2f} GB")
                print(f"Object count: {result.metrics.object_count}")
                print(f"Est. monthly cost: ${result.metrics.estimated_monthly_cost:.2f}")
            print(f"Potential monthly savings: ${result.potential_monthly_savings:.2f}")
            print("")

            if result.findings:
                print("Cost Optimization Findings:")
                print("-" * 100)
                print(f"{'Object':<35} {'Type':<18} {'Days':<8} {'Size':<12} {'Current':<12} {'Recommended'}")
                print("-" * 100)

                for finding in result.findings[:50]:
                    obj_key = finding.object_key[:32] + "..." if len(finding.object_key) > 35 else finding.object_key
                    finding_type = finding.finding_type.value if finding.finding_type else "N/A"
                    days = str(finding.days_since_access) if finding.days_since_access else "N/A"
                    size_mb = finding.size_bytes / (1024 ** 2) if finding.size_bytes else 0
                    size_str = f"{size_mb:.1f} MB"
                    current = finding.current_tier.value if finding.current_tier else "N/A"
                    recommended = finding.recommended_tier.value if finding.recommended_tier else "N/A"
                    print(f"{obj_key:<35} {finding_type:<18} {days:<8} {size_str:<12} {current:<12} {recommended}")

                if len(result.findings) > 50:
                    print(f"... and {len(result.findings) - 50} more findings")
            else:
                print("No cost optimization opportunities found.")

        return 0

    except Exception as e:
        logger.error(f"DSPM cost analysis failed: {e}")
        print(f"Error: {e}")
        return 1


def _cmd_dspm_classify(args: argparse.Namespace) -> int:
    """
    Classify sample text data for sensitive content.
    """
    from stance.dspm.classifier import DataClassifier
    from stance.dspm.detector import SensitiveDataDetector

    text = args.text
    file_path = getattr(args, "file", None)
    output_format = getattr(args, "format", "table")

    try:
        # Get text from file if specified
        if file_path:
            with open(file_path, "r") as f:
                text = f.read()

        if not text:
            print("Error: No text provided. Use --text or --file")
            return 1

        # Initialize classifier and detector
        classifier = DataClassifier()
        detector = SensitiveDataDetector()

        # Detect sensitive patterns
        detection_result = detector.detect(text)

        # Classify the data
        classification = classifier.classify(text)

        # Output results
        if output_format == "json":
            output = {
                "classification": {
                    "level": classification.level.value if classification.level else None,
                    "categories": [c.value for c in classification.categories] if classification.categories else [],
                    "confidence": classification.confidence,
                },
                "patterns_detected": [
                    {
                        "pattern": match.pattern.name if match.pattern else None,
                        "value": match.value[:50] + "..." if len(match.value) > 50 else match.value,
                        "category": match.pattern.category.value if match.pattern and match.pattern.category else None,
                    }
                    for match in detection_result.matches
                ] if detection_result.matches else [],
            }
            print(json.dumps(output, indent=2))
        else:
            # Table format
            print("")
            print("Data Classification Results")
            print("=" * 60)
            print(f"Classification Level: {classification.level.value if classification.level else 'UNKNOWN'}")
            print(f"Confidence: {classification.confidence:.0%}")
            if classification.categories:
                print(f"Categories: {', '.join(c.value for c in classification.categories)}")
            print("")

            if detection_result.matches:
                print("Sensitive Patterns Detected:")
                print("-" * 60)
                for match in detection_result.matches[:20]:
                    pattern_name = match.pattern.name if match.pattern else "Unknown"
                    category = match.pattern.category.value if match.pattern and match.pattern.category else "N/A"
                    value = match.value[:40] + "..." if len(match.value) > 40 else match.value
                    print(f"  {pattern_name}: {value} [{category}]")

                if len(detection_result.matches) > 20:
                    print(f"  ... and {len(detection_result.matches) - 20} more matches")
            else:
                print("No sensitive patterns detected.")

        return 0

    except Exception as e:
        logger.error(f"DSPM classification failed: {e}")
        print(f"Error: {e}")
        return 1
