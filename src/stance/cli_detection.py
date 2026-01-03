"""
CLI commands for Detection module.

Provides command-line interface for secrets detection:
- Scan text/files for secrets
- List supported secret patterns
- Check entropy of strings
- Validate sensitive field names
- Show detection statistics
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_detection_parser(subparsers: Any) -> None:
    """Add detection parser to CLI subparsers."""
    detection_parser = subparsers.add_parser(
        "detection",
        help="Secrets detection (scan for credentials, API keys, tokens)",
        description="Detect secrets and sensitive data in configurations and text",
    )

    detection_subparsers = detection_parser.add_subparsers(
        dest="detection_action",
        help="Detection action to perform",
    )

    # scan - Scan text for secrets
    scan_parser = detection_subparsers.add_parser(
        "scan",
        help="Scan text for secrets and credentials",
    )
    scan_parser.add_argument(
        "text",
        help="Text to scan for secrets",
    )
    scan_parser.add_argument(
        "--min-entropy",
        type=float,
        default=3.5,
        help="Minimum entropy for high-entropy detection (default: 3.5)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # scan-file - Scan a file for secrets
    scan_file_parser = detection_subparsers.add_parser(
        "scan-file",
        help="Scan a file for secrets and credentials",
    )
    scan_file_parser.add_argument(
        "file_path",
        help="Path to file to scan",
    )
    scan_file_parser.add_argument(
        "--min-entropy",
        type=float,
        default=3.5,
        help="Minimum entropy for high-entropy detection (default: 3.5)",
    )
    scan_file_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # patterns - List supported secret patterns
    patterns_parser = detection_subparsers.add_parser(
        "patterns",
        help="List supported secret patterns",
    )
    patterns_parser.add_argument(
        "--category",
        choices=["aws", "gcp", "azure", "generic", "database", "cicd", "all"],
        default="all",
        help="Filter by category (default: all)",
    )
    patterns_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # pattern - Show details for a specific pattern
    pattern_parser = detection_subparsers.add_parser(
        "pattern",
        help="Show details for a specific secret pattern",
    )
    pattern_parser.add_argument(
        "pattern_name",
        help="Pattern name (e.g., aws_access_key_id)",
    )
    pattern_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # entropy - Calculate entropy of a string
    entropy_parser = detection_subparsers.add_parser(
        "entropy",
        help="Calculate Shannon entropy of a string",
    )
    entropy_parser.add_argument(
        "text",
        help="Text to calculate entropy for",
    )
    entropy_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # sensitive-fields - List sensitive field names
    sensitive_parser = detection_subparsers.add_parser(
        "sensitive-fields",
        help="List sensitive field names that trigger additional scanning",
    )
    sensitive_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # check-field - Check if a field name is sensitive
    check_field_parser = detection_subparsers.add_parser(
        "check-field",
        help="Check if a field name is considered sensitive",
    )
    check_field_parser.add_argument(
        "field_name",
        help="Field name to check",
    )
    check_field_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # categories - List secret categories
    categories_parser = detection_subparsers.add_parser(
        "categories",
        help="List secret categories",
    )
    categories_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # severity-levels - List severity levels
    severity_parser = detection_subparsers.add_parser(
        "severity-levels",
        help="List severity levels for detected secrets",
    )
    severity_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show detection statistics
    stats_parser = detection_subparsers.add_parser(
        "stats",
        help="Show detection module statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show module status
    status_parser = detection_subparsers.add_parser(
        "status",
        help="Show detection module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive summary
    summary_parser = detection_subparsers.add_parser(
        "summary",
        help="Show detection module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_detection(args: argparse.Namespace) -> int:
    """Handle detection commands."""
    action = getattr(args, "detection_action", None)

    if action is None:
        print("Error: No detection action specified")
        print("Use 'stance detection --help' for available actions")
        return 1

    handlers = {
        "scan": _handle_scan,
        "scan-file": _handle_scan_file,
        "patterns": _handle_patterns,
        "pattern": _handle_pattern,
        "entropy": _handle_entropy,
        "sensitive-fields": _handle_sensitive_fields,
        "check-field": _handle_check_field,
        "categories": _handle_categories,
        "severity-levels": _handle_severity_levels,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler is None:
        print(f"Error: Unknown action '{action}'")
        return 1

    return handler(args)


def _handle_scan(args: argparse.Namespace) -> int:
    """Handle scan command."""
    from stance.detection import SecretsDetector

    detector = SecretsDetector(min_entropy=args.min_entropy)
    matches = detector.detect_in_text(args.text, source="cli_input")

    result = {
        "text_length": len(args.text),
        "secrets_found": len(matches),
        "matches": [
            {
                "secret_type": m.secret_type,
                "field_path": m.field_path,
                "matched_value": _redact_value(m.matched_value),
                "confidence": m.confidence,
                "entropy": m.entropy,
            }
            for m in matches
        ],
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Text Length: {result['text_length']} characters")
        print(f"Secrets Found: {result['secrets_found']}")
        print()
        if matches:
            print("Detected Secrets:")
            print("-" * 70)
            for match in result["matches"]:
                print(f"  Type: {match['secret_type']}")
                print(f"  Value: {match['matched_value']}")
                print(f"  Confidence: {match['confidence']}")
                if match["entropy"]:
                    print(f"  Entropy: {match['entropy']:.2f}")
                print()
        else:
            print("No secrets detected.")

    return 0


def _handle_scan_file(args: argparse.Namespace) -> int:
    """Handle scan-file command."""
    from stance.detection import SecretsDetector
    import os

    if not os.path.exists(args.file_path):
        print(f"Error: File not found: {args.file_path}")
        return 1

    try:
        with open(args.file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return 1

    detector = SecretsDetector(min_entropy=args.min_entropy)
    matches = detector.detect_in_text(content, source=args.file_path)

    result = {
        "file_path": args.file_path,
        "file_size": len(content),
        "secrets_found": len(matches),
        "matches": [
            {
                "secret_type": m.secret_type,
                "field_path": m.field_path,
                "matched_value": _redact_value(m.matched_value),
                "confidence": m.confidence,
                "entropy": m.entropy,
                "line_number": m.line_number,
            }
            for m in matches
        ],
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"File: {result['file_path']}")
        print(f"Size: {result['file_size']} bytes")
        print(f"Secrets Found: {result['secrets_found']}")
        print()
        if matches:
            print("Detected Secrets:")
            print("-" * 70)
            for match in result["matches"]:
                print(f"  Type: {match['secret_type']}")
                print(f"  Value: {match['matched_value']}")
                print(f"  Confidence: {match['confidence']}")
                if match["entropy"]:
                    print(f"  Entropy: {match['entropy']:.2f}")
                print()
        else:
            print("No secrets detected.")

    return 0


def _handle_patterns(args: argparse.Namespace) -> int:
    """Handle patterns command."""
    patterns = _get_patterns_by_category(args.category)

    result = {
        "category": args.category,
        "total": len(patterns),
        "patterns": patterns,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Secret Patterns ({args.category})")
        print("=" * 70)
        print(f"Total: {result['total']}")
        print()
        print(f"{'Name':<30} {'Severity':<10} {'Description'}")
        print("-" * 70)
        for p in patterns:
            print(f"{p['name']:<30} {p['severity']:<10} {p['description']}")

    return 0


def _handle_pattern(args: argparse.Namespace) -> int:
    """Handle pattern command."""
    from stance.detection import SECRET_PATTERNS

    if args.pattern_name not in SECRET_PATTERNS:
        print(f"Error: Unknown pattern '{args.pattern_name}'")
        print("Use 'stance detection patterns' to see available patterns")
        return 1

    pattern_info = SECRET_PATTERNS[args.pattern_name]
    result = {
        "name": args.pattern_name,
        "pattern": pattern_info["pattern"],
        "severity": str(pattern_info["severity"].value),
        "description": pattern_info["description"],
        "category": _get_pattern_category(args.pattern_name),
        "entropy_threshold": pattern_info.get("entropy_threshold"),
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Pattern: {result['name']}")
        print("=" * 70)
        print(f"Description: {result['description']}")
        print(f"Severity: {result['severity']}")
        print(f"Category: {result['category']}")
        print(f"Regex: {result['pattern']}")
        if result["entropy_threshold"]:
            print(f"Entropy Threshold: {result['entropy_threshold']}")

    return 0


def _handle_entropy(args: argparse.Namespace) -> int:
    """Handle entropy command."""
    from stance.detection import SecretsDetector

    detector = SecretsDetector()
    entropy = detector._calculate_entropy(args.text)

    result = {
        "text": args.text[:50] + "..." if len(args.text) > 50 else args.text,
        "text_length": len(args.text),
        "entropy": round(entropy, 4),
        "interpretation": _interpret_entropy(entropy),
        "is_high_entropy": entropy >= 3.5,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Text: {result['text']}")
        print(f"Length: {result['text_length']} characters")
        print(f"Entropy: {result['entropy']}")
        print(f"Interpretation: {result['interpretation']}")
        print(f"High Entropy (>=3.5): {'Yes' if result['is_high_entropy'] else 'No'}")

    return 0


def _handle_sensitive_fields(args: argparse.Namespace) -> int:
    """Handle sensitive-fields command."""
    from stance.detection import SENSITIVE_FIELD_NAMES

    result = {
        "total": len(SENSITIVE_FIELD_NAMES),
        "fields": SENSITIVE_FIELD_NAMES,
        "categories": {
            "password": [f for f in SENSITIVE_FIELD_NAMES if "pass" in f or "pwd" in f],
            "api_key": [f for f in SENSITIVE_FIELD_NAMES if "key" in f or "api" in f],
            "token": [f for f in SENSITIVE_FIELD_NAMES if "token" in f],
            "credential": [f for f in SENSITIVE_FIELD_NAMES if "cred" in f],
            "connection": [f for f in SENSITIVE_FIELD_NAMES if "connection" in f or "url" in f],
            "other": [f for f in SENSITIVE_FIELD_NAMES if not any(
                k in f for k in ["pass", "pwd", "key", "api", "token", "cred", "connection", "url"]
            )],
        },
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Sensitive Field Names")
        print("=" * 70)
        print(f"Total: {result['total']}")
        print()
        print("Fields that trigger additional entropy scanning:")
        print("-" * 70)
        for i, field in enumerate(result["fields"], 1):
            print(f"  {i:2}. {field}")

    return 0


def _handle_check_field(args: argparse.Namespace) -> int:
    """Handle check-field command."""
    from stance.detection import SecretsDetector, SENSITIVE_FIELD_NAMES

    detector = SecretsDetector()
    is_sensitive = detector._is_sensitive_field_name(args.field_name)

    matched_patterns = [
        pattern for pattern in SENSITIVE_FIELD_NAMES
        if pattern in args.field_name.lower()
    ]

    result = {
        "field_name": args.field_name,
        "is_sensitive": is_sensitive,
        "matched_patterns": matched_patterns,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Field Name: {result['field_name']}")
        print(f"Is Sensitive: {'Yes' if result['is_sensitive'] else 'No'}")
        if matched_patterns:
            print(f"Matched Patterns: {', '.join(matched_patterns)}")

    return 0


def _handle_categories(args: argparse.Namespace) -> int:
    """Handle categories command."""
    categories = _get_all_categories()

    result = {
        "total": len(categories),
        "categories": categories,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Secret Categories")
        print("=" * 70)
        print()
        print(f"{'Category':<15} {'Patterns':<10} {'Description'}")
        print("-" * 70)
        for cat in categories:
            print(f"{cat['id']:<15} {cat['pattern_count']:<10} {cat['description']}")

    return 0


def _handle_severity_levels(args: argparse.Namespace) -> int:
    """Handle severity-levels command."""
    levels = [
        {
            "level": "critical",
            "description": "Immediate action required - exposed credentials that could lead to full compromise",
            "examples": "AWS Access Keys, Private Keys, Stripe Live Keys",
        },
        {
            "level": "high",
            "description": "High priority - secrets that could lead to significant access",
            "examples": "API Keys, Session Tokens, Database Passwords",
        },
        {
            "level": "medium",
            "description": "Medium priority - tokens with limited scope or impact",
            "examples": "JWT Tokens, Slack Tokens, OAuth Tokens",
        },
        {
            "level": "low",
            "description": "Low priority - potentially sensitive but limited risk",
            "examples": "High-entropy strings in sensitive fields",
        },
    ]

    result = {
        "total": len(levels),
        "levels": levels,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Severity Levels")
        print("=" * 70)
        print()
        for level in levels:
            print(f"{level['level'].upper()}")
            print(f"  {level['description']}")
            print(f"  Examples: {level['examples']}")
            print()

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    from stance.detection import SECRET_PATTERNS, SENSITIVE_FIELD_NAMES

    by_severity = {}
    by_category = {}

    for name, info in SECRET_PATTERNS.items():
        severity = str(info["severity"].value)
        by_severity[severity] = by_severity.get(severity, 0) + 1

        category = _get_pattern_category(name)
        by_category[category] = by_category.get(category, 0) + 1

    result = {
        "total_patterns": len(SECRET_PATTERNS),
        "total_sensitive_fields": len(SENSITIVE_FIELD_NAMES),
        "by_severity": by_severity,
        "by_category": by_category,
        "detection_methods": ["pattern_matching", "entropy_analysis", "context_analysis"],
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Detection Statistics")
        print("=" * 70)
        print(f"Total Patterns: {result['total_patterns']}")
        print(f"Sensitive Field Names: {result['total_sensitive_fields']}")
        print()
        print("By Severity:")
        for sev, count in sorted(by_severity.items()):
            print(f"  {sev}: {count}")
        print()
        print("By Category:")
        for cat, count in sorted(by_category.items()):
            print(f"  {cat}: {count}")
        print()
        print("Detection Methods:")
        for method in result["detection_methods"]:
            print(f"  - {method}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    from stance.detection import SECRET_PATTERNS, SENSITIVE_FIELD_NAMES

    result = {
        "module": "detection",
        "status": "operational",
        "components": {
            "SecretsDetector": "available",
            "PatternMatcher": "available",
            "EntropyAnalyzer": "available",
            "ContextAnalyzer": "available",
        },
        "capabilities": [
            "pattern_based_detection",
            "entropy_analysis",
            "context_analysis",
            "finding_generation",
            "value_redaction",
        ],
        "pattern_count": len(SECRET_PATTERNS),
        "sensitive_fields_count": len(SENSITIVE_FIELD_NAMES),
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Detection Module Status")
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
        print()
        print(f"Pattern Count: {result['pattern_count']}")
        print(f"Sensitive Fields: {result['sensitive_fields_count']}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    from stance.detection import SECRET_PATTERNS, SENSITIVE_FIELD_NAMES

    by_severity = {}
    by_category = {}

    for name, info in SECRET_PATTERNS.items():
        severity = str(info["severity"].value)
        by_severity[severity] = by_severity.get(severity, 0) + 1

        category = _get_pattern_category(name)
        by_category[category] = by_category.get(category, 0) + 1

    result = {
        "module": "detection",
        "version": "1.0.0",
        "description": "Secrets detection for cloud configurations",
        "patterns_total": len(SECRET_PATTERNS),
        "sensitive_fields_total": len(SENSITIVE_FIELD_NAMES),
        "by_severity": by_severity,
        "by_category": by_category,
        "supported_clouds": ["aws", "gcp", "azure"],
        "detection_methods": {
            "pattern_matching": "Regex-based detection of known secret formats",
            "entropy_analysis": "Shannon entropy calculation for high-randomness strings",
            "context_analysis": "Field name analysis for sensitive indicators",
        },
        "features": [
            "26 built-in secret patterns",
            "28 sensitive field name patterns",
            "Multi-cloud support (AWS, GCP, Azure)",
            "Database connection string detection",
            "CI/CD token detection (GitHub, GitLab, NPM)",
            "Automatic value redaction",
            "Finding generation for detected secrets",
        ],
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Detection Module Summary")
        print("=" * 70)
        print(f"Module: {result['module']}")
        print(f"Version: {result['version']}")
        print(f"Description: {result['description']}")
        print()
        print("Overview:")
        print(f"  Total Patterns: {result['patterns_total']}")
        print(f"  Sensitive Fields: {result['sensitive_fields_total']}")
        print(f"  Supported Clouds: {', '.join(result['supported_clouds'])}")
        print()
        print("By Severity:")
        for sev, count in sorted(by_severity.items()):
            print(f"  {sev}: {count}")
        print()
        print("By Category:")
        for cat, count in sorted(by_category.items()):
            print(f"  {cat}: {count}")
        print()
        print("Detection Methods:")
        for method, desc in result["detection_methods"].items():
            print(f"  {method}: {desc}")
        print()
        print("Features:")
        for feature in result["features"]:
            print(f"  - {feature}")

    return 0


# Helper functions

def _redact_value(value: str, visible_chars: int = 4) -> str:
    """Redact a secret value for safe display."""
    if len(value) <= visible_chars * 2:
        return "*" * len(value)
    return f"{value[:visible_chars]}{'*' * (len(value) - visible_chars * 2)}{value[-visible_chars:]}"


def _get_pattern_category(pattern_name: str) -> str:
    """Get the category for a pattern name."""
    if pattern_name.startswith("aws_"):
        return "aws"
    elif pattern_name.startswith("gcp_"):
        return "gcp"
    elif pattern_name.startswith("azure_"):
        return "azure"
    elif pattern_name.startswith("generic_") or pattern_name in [
        "bearer_token", "jwt_token", "basic_auth", "private_key", "ssh_private_key"
    ]:
        return "generic"
    elif pattern_name in [
        "mysql_connection", "postgres_connection", "mongodb_connection", "redis_connection"
    ]:
        return "database"
    elif pattern_name in [
        "github_token", "gitlab_token", "npm_token", "slack_token",
        "slack_webhook", "sendgrid_api_key", "twilio_api_key", "stripe_api_key"
    ]:
        return "cicd"
    else:
        return "other"


def _get_patterns_by_category(category: str) -> list[dict]:
    """Get patterns filtered by category."""
    from stance.detection import SECRET_PATTERNS

    patterns = []
    for name, info in SECRET_PATTERNS.items():
        pattern_cat = _get_pattern_category(name)
        if category == "all" or pattern_cat == category:
            patterns.append({
                "name": name,
                "severity": str(info["severity"].value),
                "description": info["description"],
                "category": pattern_cat,
            })

    return sorted(patterns, key=lambda p: (p["category"], p["name"]))


def _get_all_categories() -> list[dict]:
    """Get all categories with counts."""
    from stance.detection import SECRET_PATTERNS

    category_info = {
        "aws": {"description": "AWS cloud credentials and secrets", "count": 0},
        "gcp": {"description": "GCP cloud credentials and secrets", "count": 0},
        "azure": {"description": "Azure cloud credentials and secrets", "count": 0},
        "generic": {"description": "Generic secrets (API keys, tokens, passwords)", "count": 0},
        "database": {"description": "Database connection strings with passwords", "count": 0},
        "cicd": {"description": "CI/CD and third-party service tokens", "count": 0},
    }

    for name in SECRET_PATTERNS.keys():
        cat = _get_pattern_category(name)
        if cat in category_info:
            category_info[cat]["count"] += 1

    return [
        {
            "id": cat_id,
            "description": info["description"],
            "pattern_count": info["count"],
        }
        for cat_id, info in category_info.items()
    ]


def _interpret_entropy(entropy: float) -> str:
    """Interpret an entropy value."""
    if entropy < 2.0:
        return "Very low - likely not a secret"
    elif entropy < 3.0:
        return "Low - probably not a secret"
    elif entropy < 3.5:
        return "Moderate - could be a weak secret"
    elif entropy < 4.5:
        return "High - likely a secret"
    else:
        return "Very high - almost certainly a secret"
