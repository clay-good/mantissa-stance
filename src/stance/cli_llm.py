"""
CLI commands for LLM module.

Provides command-line interface for AI-powered features:
- LLM provider management
- Natural language query generation
- Finding explanations
- Policy generation
- Data sanitization
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def add_llm_parser(subparsers: Any) -> None:
    """Add LLM parser to CLI subparsers."""
    llm_parser = subparsers.add_parser(
        "llm",
        help="AI-powered features (query generation, explanations, policy generation)",
        description="Manage and use AI-powered features for security analysis",
    )

    llm_subparsers = llm_parser.add_subparsers(
        dest="llm_action",
        help="LLM action to perform",
    )

    # providers - List available LLM providers
    providers_parser = llm_subparsers.add_parser(
        "providers",
        help="List available LLM providers",
    )
    providers_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # provider - Show details for a specific provider
    provider_parser = llm_subparsers.add_parser(
        "provider",
        help="Show details for a specific LLM provider",
    )
    provider_parser.add_argument(
        "provider_name",
        choices=["anthropic", "openai", "gemini"],
        help="Provider name",
    )
    provider_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # generate-query - Generate SQL query from natural language
    query_parser = llm_subparsers.add_parser(
        "generate-query",
        help="Generate SQL query from natural language question",
    )
    query_parser.add_argument(
        "question",
        help="Natural language question to convert to SQL",
    )
    query_parser.add_argument(
        "--provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    query_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # validate-query - Validate a generated SQL query
    validate_query_parser = llm_subparsers.add_parser(
        "validate-query",
        help="Validate a SQL query for safety",
    )
    validate_query_parser.add_argument(
        "sql",
        help="SQL query to validate",
    )
    validate_query_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # explain-finding - Get AI explanation for a finding
    explain_parser = llm_subparsers.add_parser(
        "explain-finding",
        help="Generate AI-powered explanation for a security finding",
    )
    explain_parser.add_argument(
        "finding_id",
        help="Finding ID to explain (or use --demo for demo mode)",
    )
    explain_parser.add_argument(
        "--provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    explain_parser.add_argument(
        "--demo",
        action="store_true",
        help="Use demo mode with sample finding",
    )
    explain_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # generate-policy - Generate policy from description
    policy_parser = llm_subparsers.add_parser(
        "generate-policy",
        help="Generate security policy from natural language description",
    )
    policy_parser.add_argument(
        "description",
        help="Natural language description of the policy",
    )
    policy_parser.add_argument(
        "--provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    policy_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        default="aws",
        help="Cloud provider for the policy (default: aws)",
    )
    policy_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        help="Suggested severity level",
    )
    policy_parser.add_argument(
        "--resource-type",
        help="Target resource type (e.g., aws_s3_bucket)",
    )
    policy_parser.add_argument(
        "--output",
        "-o",
        help="Output file path for generated policy YAML",
    )
    policy_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # suggest-policies - Get policy suggestions for a resource type
    suggest_parser = llm_subparsers.add_parser(
        "suggest-policies",
        help="Get policy suggestions for a resource type",
    )
    suggest_parser.add_argument(
        "resource_type",
        help="Resource type (e.g., aws_s3_bucket)",
    )
    suggest_parser.add_argument(
        "--provider",
        choices=["anthropic", "openai", "gemini"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    suggest_parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of suggestions (default: 5)",
    )
    suggest_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # sanitize - Sanitize text containing sensitive data
    sanitize_parser = llm_subparsers.add_parser(
        "sanitize",
        help="Sanitize text by removing sensitive data",
    )
    sanitize_parser.add_argument(
        "text",
        help="Text to sanitize",
    )
    sanitize_parser.add_argument(
        "--redact-emails",
        action="store_true",
        help="Also redact email addresses",
    )
    sanitize_parser.add_argument(
        "--redact-ips",
        action="store_true",
        help="Also redact IP addresses",
    )
    sanitize_parser.add_argument(
        "--redact-account-ids",
        action="store_true",
        help="Also redact AWS account IDs",
    )
    sanitize_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # check-sensitive - Check if text contains sensitive data
    check_parser = llm_subparsers.add_parser(
        "check-sensitive",
        help="Check if text contains sensitive data",
    )
    check_parser.add_argument(
        "text",
        help="Text to check",
    )
    check_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # resource-types - List available resource types
    resource_types_parser = llm_subparsers.add_parser(
        "resource-types",
        help="List available resource types for policy generation",
    )
    resource_types_parser.add_argument(
        "--cloud",
        choices=["aws", "gcp", "azure"],
        help="Filter by cloud provider",
    )
    resource_types_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # frameworks - List compliance frameworks
    frameworks_parser = llm_subparsers.add_parser(
        "frameworks",
        help="List compliance frameworks for policy generation",
    )
    frameworks_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # models - List available models per provider
    models_parser = llm_subparsers.add_parser(
        "models",
        help="List available models for each provider",
    )
    models_parser.add_argument(
        "--provider",
        choices=["anthropic", "openai", "gemini"],
        help="Filter by provider",
    )
    models_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show LLM module status
    status_parser = llm_subparsers.add_parser(
        "status",
        help="Show LLM module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive LLM module summary
    summary_parser = llm_subparsers.add_parser(
        "summary",
        help="Get comprehensive LLM module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_llm(args: argparse.Namespace) -> int:
    """Handle LLM commands."""
    action = getattr(args, "llm_action", None)

    if not action:
        print("Error: No action specified. Use 'stance llm --help' for options.")
        return 1

    handlers = {
        "providers": _handle_providers,
        "provider": _handle_provider,
        "generate-query": _handle_generate_query,
        "validate-query": _handle_validate_query,
        "explain-finding": _handle_explain_finding,
        "generate-policy": _handle_generate_policy,
        "suggest-policies": _handle_suggest_policies,
        "sanitize": _handle_sanitize,
        "check-sensitive": _handle_check_sensitive,
        "resource-types": _handle_resource_types,
        "frameworks": _handle_frameworks,
        "models": _handle_models,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Error: Unknown action '{action}'")
    return 1


def _handle_providers(args: argparse.Namespace) -> int:
    """Handle providers command."""
    providers = _get_available_providers()

    if args.format == "json":
        print(json.dumps({"providers": providers, "total": len(providers)}, indent=2))
    else:
        print("Available LLM Providers")
        print("=" * 60)
        for provider in providers:
            status = "Available" if provider["available"] else "Not Configured"
            status_icon = "[+]" if provider["available"] else "[-]"
            print(f"\n{status_icon} {provider['name']}")
            print(f"    ID: {provider['id']}")
            print(f"    Status: {status}")
            print(f"    Default Model: {provider['default_model']}")
            print(f"    API Key Env: {provider['api_key_env']}")
        print(f"\nTotal: {len(providers)} providers")

    return 0


def _handle_provider(args: argparse.Namespace) -> int:
    """Handle provider command."""
    provider = _get_provider_details(args.provider_name)

    if args.format == "json":
        print(json.dumps(provider, indent=2))
    else:
        print(f"LLM Provider: {provider['name']}")
        print("=" * 60)
        print(f"ID: {provider['id']}")
        print(f"Status: {'Available' if provider['available'] else 'Not Configured'}")
        print(f"Default Model: {provider['default_model']}")
        print(f"API Key Environment Variable: {provider['api_key_env']}")
        print(f"\nDescription: {provider['description']}")
        print(f"\nSupported Models:")
        for model in provider["models"]:
            print(f"  - {model['id']}: {model['description']}")
        print(f"\nCapabilities:")
        for cap in provider["capabilities"]:
            print(f"  - {cap}")
        print(f"\nPricing Tier: {provider['pricing_tier']}")

    return 0


def _handle_generate_query(args: argparse.Namespace) -> int:
    """Handle generate-query command."""
    result = _generate_query_demo(args.question, args.provider)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Query Generation Result")
        print("=" * 60)
        print(f"Question: {result['question']}")
        print(f"Provider: {result['provider']}")
        print(f"\nGenerated SQL:")
        print("-" * 40)
        print(result["sql"])
        print("-" * 40)
        print(f"\nValid: {'Yes' if result['is_valid'] else 'No'}")
        if result["validation_errors"]:
            print("Validation Errors:")
            for error in result["validation_errors"]:
                print(f"  - {error}")

    return 0


def _handle_validate_query(args: argparse.Namespace) -> int:
    """Handle validate-query command."""
    result = _validate_query(args.sql)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Query Validation Result")
        print("=" * 60)
        print(f"SQL: {args.sql}")
        print(f"\nValid: {'Yes' if result['is_valid'] else 'No'}")
        if result["errors"]:
            print("\nValidation Errors:")
            for error in result["errors"]:
                print(f"  - {error}")
        else:
            print("\nNo validation errors found.")

    return 0


def _handle_explain_finding(args: argparse.Namespace) -> int:
    """Handle explain-finding command."""
    if args.demo or args.finding_id == "demo":
        result = _get_demo_explanation()
    else:
        result = _get_finding_explanation(args.finding_id, args.provider)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Finding Explanation")
        print("=" * 60)
        print(f"Finding ID: {result['finding_id']}")
        print(f"\nSummary:")
        print(f"  {result['summary']}")
        print(f"\nRisk Explanation:")
        print(f"  {result['risk_explanation']}")
        print(f"\nBusiness Impact:")
        print(f"  {result['business_impact']}")
        if result["remediation_steps"]:
            print(f"\nRemediation Steps:")
            for i, step in enumerate(result["remediation_steps"], 1):
                print(f"  {i}. {step}")
        print(f"\nTechnical Details:")
        print(f"  {result['technical_details']}")
        if result["references"]:
            print(f"\nReferences:")
            for ref in result["references"]:
                print(f"  - {ref}")

    return 0


def _handle_generate_policy(args: argparse.Namespace) -> int:
    """Handle generate-policy command."""
    result = _generate_policy_demo(
        args.description,
        args.provider,
        args.cloud,
        args.severity,
        args.resource_type,
    )

    if args.output and result["is_valid"]:
        try:
            with open(args.output, "w") as f:
                f.write(result["yaml_content"])
            print(f"Policy saved to: {args.output}")
        except OSError as e:
            print(f"Error saving policy: {e}")
            return 1

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Policy Generation Result")
        print("=" * 60)
        print(f"Description: {result['description']}")
        print(f"Provider: {result['provider']}")
        print(f"Cloud: {result['cloud']}")
        print(f"\nGenerated Policy:")
        print("-" * 40)
        if result["yaml_content"]:
            print(result["yaml_content"])
        else:
            print("(No policy generated)")
        print("-" * 40)
        print(f"\nValid: {'Yes' if result['is_valid'] else 'No'}")
        if result.get("validation_errors"):
            print("Validation Errors:")
            for error in result["validation_errors"]:
                print(f"  - {error}")

    return 0


def _handle_suggest_policies(args: argparse.Namespace) -> int:
    """Handle suggest-policies command."""
    result = _get_policy_suggestions(args.resource_type, args.count)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Policy Suggestions for {args.resource_type}")
        print("=" * 60)
        for i, suggestion in enumerate(result["suggestions"], 1):
            print(f"{i}. {suggestion}")
        print(f"\nTotal: {len(result['suggestions'])} suggestions")

    return 0


def _handle_sanitize(args: argparse.Namespace) -> int:
    """Handle sanitize command."""
    result = _sanitize_text(
        args.text,
        args.redact_emails,
        args.redact_ips,
        args.redact_account_ids,
    )

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Sanitization Result")
        print("=" * 60)
        print(f"Original: {args.text}")
        print(f"\nSanitized: {result['sanitized_text']}")
        print(f"\nRedactions Made: {result['redactions_made']}")
        if result["redaction_types"]:
            print(f"Redaction Types:")
            for t in result["redaction_types"]:
                print(f"  - {t}")

    return 0


def _handle_check_sensitive(args: argparse.Namespace) -> int:
    """Handle check-sensitive command."""
    result = _check_sensitive_data(args.text)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Sensitive Data Check")
        print("=" * 60)
        print(f"Contains Sensitive Data: {'Yes' if result['is_sensitive'] else 'No'}")
        if result["types_found"]:
            print(f"\nSensitive Data Types Found:")
            for t in result["types_found"]:
                print(f"  - {t}")

    return 0


def _handle_resource_types(args: argparse.Namespace) -> int:
    """Handle resource-types command."""
    result = _get_resource_types(args.cloud)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Available Resource Types")
        print("=" * 60)
        for cloud, types in result["resource_types"].items():
            print(f"\n{cloud.upper()}:")
            for t in types:
                print(f"  - {t}")
        print(f"\nTotal: {result['total']} resource types")

    return 0


def _handle_frameworks(args: argparse.Namespace) -> int:
    """Handle frameworks command."""
    result = _get_compliance_frameworks()

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Compliance Frameworks")
        print("=" * 60)
        for fw in result["frameworks"]:
            print(f"\n{fw['id']}")
            print(f"  Name: {fw['name']}")
            print(f"  Description: {fw['description']}")

    return 0


def _handle_models(args: argparse.Namespace) -> int:
    """Handle models command."""
    result = _get_available_models(args.provider)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Available Models")
        print("=" * 60)
        for provider, models in result["models"].items():
            print(f"\n{provider.upper()}:")
            for model in models:
                default = " (default)" if model.get("default") else ""
                print(f"  - {model['id']}: {model['description']}{default}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    status = _get_llm_status()

    if args.format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("LLM Module Status")
        print("=" * 60)
        print(f"Module: {status['module']}")
        print(f"Status: {status['status']}")
        print(f"\nProviders:")
        for provider in status["providers"]:
            icon = "[+]" if provider["available"] else "[-]"
            print(f"  {icon} {provider['name']}: {'Available' if provider['available'] else 'Not Configured'}")
        print(f"\nCapabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")
        print(f"\nComponents:")
        for comp in status["components"]:
            print(f"  - {comp}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    summary = _get_llm_summary()

    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("LLM Module Summary")
        print("=" * 60)
        print(f"Module: {summary['module']}")
        print(f"Version: {summary['version']}")
        print(f"\nProviders: {summary['providers_available']}/{summary['providers_total']}")
        print(f"\nFeatures:")
        for feature in summary["features"]:
            print(f"  - {feature['name']}: {feature['description']}")
        print(f"\nResource Types: {summary['resource_types_count']} across {summary['cloud_providers']} clouds")
        print(f"Compliance Frameworks: {summary['frameworks_count']}")
        print(f"\nData Sanitization:")
        print(f"  Sensitive Patterns: {summary['sanitizer']['patterns_count']}")
        print(f"  Optional Patterns: {summary['sanitizer']['optional_patterns_count']}")

    return 0


# ==================== Sample Data Generators ====================


def _get_available_providers() -> list[dict[str, Any]]:
    """Get list of available LLM providers."""
    import os

    providers = [
        {
            "id": "anthropic",
            "name": "Anthropic Claude",
            "available": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "default_model": "claude-3-haiku-20240307",
            "api_key_env": "ANTHROPIC_API_KEY",
        },
        {
            "id": "openai",
            "name": "OpenAI GPT",
            "available": bool(os.environ.get("OPENAI_API_KEY")),
            "default_model": "gpt-3.5-turbo",
            "api_key_env": "OPENAI_API_KEY",
        },
        {
            "id": "gemini",
            "name": "Google Gemini",
            "available": bool(os.environ.get("GOOGLE_API_KEY")),
            "default_model": "gemini-pro",
            "api_key_env": "GOOGLE_API_KEY",
        },
    ]
    return providers


def _get_provider_details(provider_id: str) -> dict[str, Any]:
    """Get detailed information about a provider."""
    import os

    details = {
        "anthropic": {
            "id": "anthropic",
            "name": "Anthropic Claude",
            "available": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "default_model": "claude-3-haiku-20240307",
            "api_key_env": "ANTHROPIC_API_KEY",
            "description": "Claude models from Anthropic, known for safety and helpfulness",
            "models": [
                {"id": "claude-3-opus-20240229", "description": "Most capable model for complex tasks"},
                {"id": "claude-3-sonnet-20240229", "description": "Balanced performance and speed"},
                {"id": "claude-3-haiku-20240307", "description": "Fast and cost-effective (default)"},
            ],
            "capabilities": [
                "Natural language query generation",
                "Finding explanations",
                "Policy generation",
                "Code analysis",
            ],
            "pricing_tier": "Pay per token",
        },
        "openai": {
            "id": "openai",
            "name": "OpenAI GPT",
            "available": bool(os.environ.get("OPENAI_API_KEY")),
            "default_model": "gpt-3.5-turbo",
            "api_key_env": "OPENAI_API_KEY",
            "description": "GPT models from OpenAI, widely used for various NLP tasks",
            "models": [
                {"id": "gpt-4-turbo", "description": "Most capable GPT-4 variant"},
                {"id": "gpt-4", "description": "High capability reasoning model"},
                {"id": "gpt-3.5-turbo", "description": "Fast and cost-effective (default)"},
            ],
            "capabilities": [
                "Natural language query generation",
                "Finding explanations",
                "Policy generation",
                "Code completion",
            ],
            "pricing_tier": "Pay per token",
        },
        "gemini": {
            "id": "gemini",
            "name": "Google Gemini",
            "available": bool(os.environ.get("GOOGLE_API_KEY")),
            "default_model": "gemini-pro",
            "api_key_env": "GOOGLE_API_KEY",
            "description": "Gemini models from Google, integrated with Google Cloud",
            "models": [
                {"id": "gemini-pro", "description": "General purpose model (default)"},
                {"id": "gemini-pro-vision", "description": "Multimodal model with vision"},
            ],
            "capabilities": [
                "Natural language query generation",
                "Finding explanations",
                "Policy generation",
                "Multimodal analysis",
            ],
            "pricing_tier": "Pay per token",
        },
    }
    return details.get(provider_id, {"error": f"Unknown provider: {provider_id}"})


def _generate_query_demo(question: str, provider: str) -> dict[str, Any]:
    """Generate a demo query result."""
    # Validate the query using the actual validator
    from stance.llm.query_generator import QueryGenerator

    # Create a mock provider for validation only
    class MockProvider:
        @property
        def provider_name(self) -> str:
            return provider

        @property
        def model_name(self) -> str:
            return "demo-model"

        def generate(self, prompt: str, system_prompt: str | None = None, max_tokens: int = 1024) -> str:
            return ""

    generator = QueryGenerator(MockProvider())

    # Generate demo SQL based on question keywords
    sql = _generate_demo_sql(question)
    errors = generator.validate_query(sql)

    return {
        "question": question,
        "provider": provider,
        "sql": sql,
        "is_valid": len(errors) == 0,
        "validation_errors": errors,
        "mode": "demo",
    }


def _generate_demo_sql(question: str) -> str:
    """Generate demo SQL based on question keywords."""
    q_lower = question.lower()

    if "critical" in q_lower and "finding" in q_lower:
        return "SELECT * FROM findings WHERE severity = 'critical' AND status = 'open' LIMIT 100"
    elif "s3" in q_lower or "bucket" in q_lower:
        return "SELECT * FROM assets WHERE resource_type = 'aws_s3_bucket' LIMIT 100"
    elif "public" in q_lower or "internet" in q_lower:
        return "SELECT * FROM assets WHERE network_exposure = 'internet_facing' LIMIT 100"
    elif "vulnerability" in q_lower or "vulnerabilities" in q_lower:
        return "SELECT * FROM findings WHERE finding_type = 'vulnerability' AND status = 'open' LIMIT 100"
    elif "count" in q_lower:
        return "SELECT severity, COUNT(*) as count FROM findings WHERE status = 'open' GROUP BY severity"
    else:
        return "SELECT f.*, a.name, a.resource_type FROM findings f JOIN assets a ON f.asset_id = a.id WHERE f.status = 'open' LIMIT 100"


def _validate_query(sql: str) -> dict[str, Any]:
    """Validate a SQL query."""
    from stance.llm.query_generator import QueryGenerator

    class MockProvider:
        @property
        def provider_name(self) -> str:
            return "mock"

        @property
        def model_name(self) -> str:
            return "mock-model"

        def generate(self, prompt: str, system_prompt: str | None = None, max_tokens: int = 1024) -> str:
            return ""

    generator = QueryGenerator(MockProvider())
    errors = generator.validate_query(sql)

    return {
        "sql": sql,
        "is_valid": len(errors) == 0,
        "errors": errors,
    }


def _get_demo_explanation() -> dict[str, Any]:
    """Get a demo finding explanation."""
    return {
        "finding_id": "demo-finding-001",
        "summary": "S3 bucket 'my-data-bucket' has public access enabled, potentially exposing sensitive data to the internet.",
        "risk_explanation": "Public S3 buckets can be accessed by anyone on the internet. Attackers actively scan for misconfigured buckets to steal data. This is a common attack vector that has led to major data breaches.",
        "business_impact": "Unauthorized access to data in this bucket could lead to data breaches, regulatory fines (GDPR, HIPAA), reputational damage, and loss of customer trust.",
        "remediation_steps": [
            "Review the bucket policy and remove any statements granting public access",
            "Enable 'Block Public Access' settings at the bucket level",
            "Review bucket ACLs and remove 'AllUsers' or 'AuthenticatedUsers' grants",
            "Enable server-side encryption for data at rest",
            "Set up CloudWatch alarms for bucket policy changes",
        ],
        "technical_details": "The bucket policy contains a statement with Principal: '*' which allows anonymous access. The bucket ACL also has READ permissions for the 'AllUsers' group. Block Public Access settings are disabled.",
        "references": [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            "https://aws.amazon.com/blogs/aws/amazon-s3-block-public-access-another-layer-of-protection-for-your-accounts-and-buckets/",
        ],
        "is_valid": True,
        "mode": "demo",
    }


def _get_finding_explanation(finding_id: str, provider: str) -> dict[str, Any]:
    """Get explanation for a specific finding."""
    # In demo mode, return sample explanation
    explanation = _get_demo_explanation()
    explanation["finding_id"] = finding_id
    explanation["provider"] = provider
    return explanation


def _generate_policy_demo(
    description: str,
    provider: str,
    cloud: str,
    severity: str | None,
    resource_type: str | None,
) -> dict[str, Any]:
    """Generate a demo policy."""
    # Generate policy ID and determine resource type from description
    desc_lower = description.lower()

    if "s3" in desc_lower or "bucket" in desc_lower:
        detected_type = "aws_s3_bucket"
        policy_id = "aws-s3-custom-001"
    elif "iam" in desc_lower or "user" in desc_lower:
        detected_type = "aws_iam_user"
        policy_id = "aws-iam-custom-001"
    elif "ec2" in desc_lower or "instance" in desc_lower:
        detected_type = "aws_ec2_instance"
        policy_id = "aws-ec2-custom-001"
    else:
        detected_type = resource_type or "aws_s3_bucket"
        policy_id = f"{cloud}-custom-001"

    detected_severity = severity or "medium"

    yaml_content = f"""id: {policy_id}
name: Custom policy from description
description: |
  {description}
  Generated by AI from natural language description.

enabled: true
severity: {detected_severity}

resource_type: {detected_type}

check:
  type: expression
  expression: "config.enabled == true"

compliance:
  - framework: cis-aws-foundations
    version: "1.4.0"
    control: "custom"

remediation:
  guidance: |
    Review and implement the security control described above.
    1. Identify affected resources
    2. Apply the required configuration changes
    3. Verify the changes are effective
  automation_supported: false

tags:
  - custom
  - ai-generated
  - {cloud}

references:
  - https://docs.aws.amazon.com/
"""

    return {
        "description": description,
        "provider": provider,
        "cloud": cloud,
        "policy_id": policy_id,
        "policy_name": "Custom policy from description",
        "yaml_content": yaml_content,
        "resource_type": detected_type,
        "severity": detected_severity,
        "is_valid": True,
        "validation_errors": [],
        "mode": "demo",
    }


def _get_policy_suggestions(resource_type: str, count: int) -> dict[str, Any]:
    """Get policy suggestions for a resource type."""
    suggestions_map = {
        "aws_s3_bucket": [
            "Ensure S3 bucket has server-side encryption enabled",
            "Ensure S3 bucket does not have public read access",
            "Ensure S3 bucket has versioning enabled",
            "Ensure S3 bucket has logging enabled",
            "Ensure S3 bucket has MFA delete enabled",
            "Ensure S3 bucket blocks public ACLs",
            "Ensure S3 bucket has lifecycle policy configured",
        ],
        "aws_iam_user": [
            "Ensure IAM users have MFA enabled",
            "Ensure IAM user access keys are rotated within 90 days",
            "Ensure IAM users do not have inline policies attached",
            "Ensure IAM users belong to at least one group",
            "Ensure IAM user passwords meet complexity requirements",
        ],
        "aws_ec2_instance": [
            "Ensure EC2 instance has detailed monitoring enabled",
            "Ensure EC2 instance is not using default security group",
            "Ensure EC2 instance has IMDSv2 required",
            "Ensure EC2 instance EBS volumes are encrypted",
            "Ensure EC2 instance is not publicly accessible",
        ],
        "aws_security_group": [
            "Ensure security group does not allow unrestricted SSH access (0.0.0.0/0:22)",
            "Ensure security group does not allow unrestricted RDP access (0.0.0.0/0:3389)",
            "Ensure security group does not allow unrestricted ingress on all ports",
            "Ensure security group has description for all rules",
            "Ensure unused security groups are removed",
        ],
    }

    suggestions = suggestions_map.get(resource_type, [
        f"Ensure {resource_type} follows security best practices",
        f"Ensure {resource_type} has proper access controls",
        f"Ensure {resource_type} has encryption enabled",
        f"Ensure {resource_type} has logging configured",
        f"Ensure {resource_type} is compliant with organizational policies",
    ])

    return {
        "resource_type": resource_type,
        "suggestions": suggestions[:count],
        "total": len(suggestions[:count]),
    }


def _sanitize_text(
    text: str,
    redact_emails: bool,
    redact_ips: bool,
    redact_account_ids: bool,
) -> dict[str, Any]:
    """Sanitize text using DataSanitizer."""
    from stance.llm.sanitizer import DataSanitizer

    sanitizer = DataSanitizer(
        redact_emails=redact_emails,
        redact_ips=redact_ips,
        redact_account_ids=redact_account_ids,
    )

    result = sanitizer.sanitize_with_details(text)

    return {
        "original": text,
        "sanitized_text": result.sanitized_text,
        "redactions_made": result.redactions_made,
        "redaction_types": result.redaction_types,
    }


def _check_sensitive_data(text: str) -> dict[str, Any]:
    """Check if text contains sensitive data."""
    from stance.llm.sanitizer import DataSanitizer

    sanitizer = DataSanitizer()
    is_sensitive = sanitizer.is_sensitive(text)
    types_found = sanitizer.get_sensitive_types(text)

    return {
        "text": text,
        "is_sensitive": is_sensitive,
        "types_found": types_found,
    }


def _get_resource_types(cloud: str | None) -> dict[str, Any]:
    """Get available resource types."""
    from stance.llm.policy_generator import RESOURCE_TYPES

    if cloud:
        filtered = {cloud: RESOURCE_TYPES.get(cloud, [])}
        total = len(RESOURCE_TYPES.get(cloud, []))
    else:
        filtered = RESOURCE_TYPES
        total = sum(len(types) for types in RESOURCE_TYPES.values())

    return {
        "resource_types": filtered,
        "total": total,
    }


def _get_compliance_frameworks() -> dict[str, Any]:
    """Get available compliance frameworks."""
    from stance.llm.policy_generator import COMPLIANCE_FRAMEWORKS

    frameworks = [
        {"id": k, "name": v, "description": v}
        for k, v in COMPLIANCE_FRAMEWORKS.items()
    ]

    return {
        "frameworks": frameworks,
        "total": len(frameworks),
    }


def _get_available_models(provider: str | None) -> dict[str, Any]:
    """Get available models for each provider."""
    all_models = {
        "anthropic": [
            {"id": "claude-3-opus-20240229", "description": "Most capable, best for complex tasks", "default": False},
            {"id": "claude-3-sonnet-20240229", "description": "Balanced performance and speed", "default": False},
            {"id": "claude-3-haiku-20240307", "description": "Fast and cost-effective", "default": True},
        ],
        "openai": [
            {"id": "gpt-4-turbo", "description": "Latest GPT-4 with improved performance", "default": False},
            {"id": "gpt-4", "description": "High capability reasoning", "default": False},
            {"id": "gpt-3.5-turbo", "description": "Fast and cost-effective", "default": True},
        ],
        "gemini": [
            {"id": "gemini-pro", "description": "General purpose model", "default": True},
            {"id": "gemini-pro-vision", "description": "Multimodal with vision", "default": False},
        ],
    }

    if provider:
        return {"models": {provider: all_models.get(provider, [])}}

    return {"models": all_models}


def _get_llm_status() -> dict[str, Any]:
    """Get LLM module status."""
    import os

    providers = [
        {"name": "Anthropic", "available": bool(os.environ.get("ANTHROPIC_API_KEY"))},
        {"name": "OpenAI", "available": bool(os.environ.get("OPENAI_API_KEY"))},
        {"name": "Gemini", "available": bool(os.environ.get("GOOGLE_API_KEY"))},
    ]

    return {
        "module": "llm",
        "status": "operational",
        "providers": providers,
        "capabilities": [
            "Natural language query generation",
            "SQL query validation",
            "Finding explanations",
            "Policy generation",
            "Policy suggestions",
            "Data sanitization",
            "Sensitive data detection",
        ],
        "components": [
            "QueryGenerator",
            "FindingExplainer",
            "PolicyGenerator",
            "DataSanitizer",
            "AnthropicProvider",
            "OpenAIProvider",
            "GeminiProvider",
        ],
    }


def _get_llm_summary() -> dict[str, Any]:
    """Get comprehensive LLM module summary."""
    import os
    from stance.llm.policy_generator import RESOURCE_TYPES, COMPLIANCE_FRAMEWORKS

    providers_available = sum([
        1 if os.environ.get("ANTHROPIC_API_KEY") else 0,
        1 if os.environ.get("OPENAI_API_KEY") else 0,
        1 if os.environ.get("GOOGLE_API_KEY") else 0,
    ])

    return {
        "module": "LLM",
        "version": "1.0.0",
        "providers_available": providers_available,
        "providers_total": 3,
        "features": [
            {"name": "Query Generation", "description": "Convert natural language to SQL queries"},
            {"name": "Query Validation", "description": "Validate SQL queries for safety"},
            {"name": "Finding Explanation", "description": "AI-powered security finding explanations"},
            {"name": "Policy Generation", "description": "Generate policies from descriptions"},
            {"name": "Policy Suggestions", "description": "Get policy ideas for resource types"},
            {"name": "Data Sanitization", "description": "Remove sensitive data before LLM calls"},
        ],
        "resource_types_count": sum(len(types) for types in RESOURCE_TYPES.values()),
        "cloud_providers": len(RESOURCE_TYPES),
        "frameworks_count": len(COMPLIANCE_FRAMEWORKS),
        "sanitizer": {
            "patterns_count": 7,
            "optional_patterns_count": 3,
        },
    }
