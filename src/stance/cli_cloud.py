"""
CLI commands for Cloud module.

Provides command-line interface for cloud provider management:
- List supported cloud providers
- Get provider details and SDK requirements
- Validate cloud credentials
- Get account/project information
- List available regions
"""

from __future__ import annotations

import argparse
import json
from typing import Any


def add_cloud_parser(subparsers: Any) -> None:
    """Add cloud parser to CLI subparsers."""
    cloud_parser = subparsers.add_parser(
        "cloud",
        help="Cloud provider management",
        description="Manage and inspect cloud provider configurations",
    )

    cloud_subparsers = cloud_parser.add_subparsers(
        dest="cloud_action",
        help="Cloud action to perform",
    )

    # list - List available providers
    list_parser = cloud_subparsers.add_parser(
        "list",
        help="List supported cloud providers",
    )
    list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # info - Get provider details
    info_parser = cloud_subparsers.add_parser(
        "info",
        help="Get details for a specific provider",
    )
    info_parser.add_argument(
        "provider_name",
        choices=["aws", "gcp", "azure"],
        help="Cloud provider name",
    )
    info_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # validate - Validate credentials
    validate_parser = cloud_subparsers.add_parser(
        "validate",
        help="Validate cloud credentials",
    )
    validate_parser.add_argument(
        "provider_name",
        choices=["aws", "gcp", "azure"],
        help="Cloud provider name",
    )
    validate_parser.add_argument(
        "--region",
        help="Region to use for validation",
    )
    validate_parser.add_argument(
        "--profile",
        help="AWS profile name (AWS only)",
    )
    validate_parser.add_argument(
        "--project",
        help="GCP project ID (GCP only)",
    )
    validate_parser.add_argument(
        "--subscription",
        help="Azure subscription ID (Azure only)",
    )
    validate_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # account - Get account info
    account_parser = cloud_subparsers.add_parser(
        "account",
        help="Get cloud account/project information",
    )
    account_parser.add_argument(
        "provider_name",
        choices=["aws", "gcp", "azure"],
        help="Cloud provider name",
    )
    account_parser.add_argument(
        "--region",
        help="Region to use",
    )
    account_parser.add_argument(
        "--profile",
        help="AWS profile name (AWS only)",
    )
    account_parser.add_argument(
        "--project",
        help="GCP project ID (GCP only)",
    )
    account_parser.add_argument(
        "--subscription",
        help="Azure subscription ID (Azure only)",
    )
    account_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # regions - List regions
    regions_parser = cloud_subparsers.add_parser(
        "regions",
        help="List available regions for a provider",
    )
    regions_parser.add_argument(
        "provider_name",
        choices=["aws", "gcp", "azure"],
        help="Cloud provider name",
    )
    regions_parser.add_argument(
        "--region",
        help="Default region to use for API calls",
    )
    regions_parser.add_argument(
        "--profile",
        help="AWS profile name (AWS only)",
    )
    regions_parser.add_argument(
        "--project",
        help="GCP project ID (GCP only)",
    )
    regions_parser.add_argument(
        "--subscription",
        help="Azure subscription ID (Azure only)",
    )
    regions_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # availability - Check SDK availability
    availability_parser = cloud_subparsers.add_parser(
        "availability",
        help="Check cloud SDK availability",
    )
    availability_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # packages - Show required packages
    packages_parser = cloud_subparsers.add_parser(
        "packages",
        help="Show required packages for each provider",
    )
    packages_parser.add_argument(
        "--provider",
        choices=["aws", "gcp", "azure"],
        help="Filter by provider",
    )
    packages_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # credentials - Show credential options
    credentials_parser = cloud_subparsers.add_parser(
        "credentials",
        help="Show credential configuration options",
    )
    credentials_parser.add_argument(
        "--provider",
        choices=["aws", "gcp", "azure"],
        help="Filter by provider",
    )
    credentials_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # exceptions - Show exception types
    exceptions_parser = cloud_subparsers.add_parser(
        "exceptions",
        help="Show cloud provider exception types",
    )
    exceptions_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show module status
    status_parser = cloud_subparsers.add_parser(
        "status",
        help="Show cloud module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive summary
    summary_parser = cloud_subparsers.add_parser(
        "summary",
        help="Get comprehensive cloud module summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_cloud(args: argparse.Namespace) -> int:
    """Handle cloud commands."""
    action = getattr(args, "cloud_action", None)

    if not action:
        print("Usage: stance cloud <action>")
        print("\nAvailable actions:")
        print("  list          List supported cloud providers")
        print("  info          Get details for a specific provider")
        print("  validate      Validate cloud credentials")
        print("  account       Get account/project information")
        print("  regions       List available regions")
        print("  availability  Check cloud SDK availability")
        print("  packages      Show required packages")
        print("  credentials   Show credential configuration options")
        print("  exceptions    Show exception types")
        print("  status        Show cloud module status")
        print("  summary       Get comprehensive summary")
        return 1

    handlers = {
        "list": _handle_list,
        "info": _handle_info,
        "validate": _handle_validate,
        "account": _handle_account,
        "regions": _handle_regions,
        "availability": _handle_availability,
        "packages": _handle_packages,
        "credentials": _handle_credentials,
        "exceptions": _handle_exceptions,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown cloud action: {action}")
    return 1


def _get_provider_metadata() -> list[dict[str, Any]]:
    """Get metadata for all cloud providers."""
    from stance.cloud import PROVIDERS, is_provider_available

    providers = []

    for name, provider_class in PROVIDERS.items():
        providers.append({
            "name": name,
            "display_name": provider_class(None).display_name if is_provider_available(name) else _get_display_name(name),
            "available": is_provider_available(name),
            "packages": provider_class.get_required_packages(),
            "description": _get_provider_description(name),
        })

    return providers


def _get_display_name(provider: str) -> str:
    """Get display name for provider."""
    names = {
        "aws": "Amazon Web Services",
        "gcp": "Google Cloud Platform",
        "azure": "Microsoft Azure",
    }
    return names.get(provider, provider.upper())


def _get_provider_description(provider: str) -> str:
    """Get description for provider."""
    descriptions = {
        "aws": "AWS cloud services including IAM, S3, EC2, RDS, Lambda, and more",
        "gcp": "Google Cloud services including IAM, Cloud Storage, Compute Engine, and more",
        "azure": "Microsoft Azure services including IAM, Blob Storage, VMs, and more",
    }
    return descriptions.get(provider, "Cloud provider")


def _handle_list(args: argparse.Namespace) -> int:
    """Handle list command."""
    output_format = getattr(args, "format", "table")

    providers = _get_provider_metadata()

    if output_format == "json":
        print(json.dumps(providers, indent=2))
    else:
        print("\nSupported Cloud Providers")
        print("=" * 80)
        print(f"{'Provider':<12} {'Name':<30} {'Available':<12} {'Packages':<20}")
        print("-" * 80)

        for p in providers:
            available = "Yes" if p["available"] else "No"
            packages = ", ".join(p["packages"]) if p["packages"] else "N/A"
            print(f"{p['name']:<12} {p['display_name']:<30} {available:<12} {packages:<20}")

    return 0


def _handle_info(args: argparse.Namespace) -> int:
    """Handle info command."""
    output_format = getattr(args, "format", "table")
    provider_name = args.provider_name

    from stance.cloud import PROVIDERS, is_provider_available

    if provider_name not in PROVIDERS:
        print(f"Unknown provider: {provider_name}")
        return 1

    provider_class = PROVIDERS[provider_name]
    available = is_provider_available(provider_name)

    info = {
        "name": provider_name,
        "display_name": _get_display_name(provider_name),
        "available": available,
        "packages": provider_class.get_required_packages(),
        "description": _get_provider_description(provider_name),
        "credential_fields": _get_credential_fields(provider_name),
        "default_region": _get_default_region(provider_name),
        "storage_types": _get_storage_types(provider_name),
    }

    if output_format == "json":
        print(json.dumps(info, indent=2))
    else:
        print(f"\nCloud Provider: {info['display_name']}")
        print("=" * 60)
        print(f"Provider ID:    {info['name']}")
        print(f"Available:      {'Yes' if info['available'] else 'No'}")
        print(f"Description:    {info['description']}")
        print(f"Default Region: {info['default_region']}")

        print("\nRequired Packages:")
        for pkg in info["packages"]:
            print(f"  - {pkg}")

        print("\nCredential Fields:")
        for field in info["credential_fields"]:
            print(f"  - {field}")

        print("\nStorage Types:")
        for st in info["storage_types"]:
            print(f"  - {st}")

        if not info["available"]:
            print(f"\nTo enable {info['display_name']}:")
            print(f"  pip install {' '.join(info['packages'])}")

    return 0


def _get_credential_fields(provider: str) -> list[str]:
    """Get credential fields for provider."""
    fields = {
        "aws": [
            "aws_access_key_id",
            "aws_secret_access_key",
            "aws_session_token",
            "aws_profile",
            "aws_role_arn",
        ],
        "gcp": [
            "gcp_project_id",
            "gcp_service_account_key",
            "gcp_service_account_file",
        ],
        "azure": [
            "azure_subscription_id",
            "azure_tenant_id",
            "azure_client_id",
            "azure_client_secret",
        ],
    }
    return fields.get(provider, [])


def _get_default_region(provider: str) -> str:
    """Get default region for provider."""
    regions = {
        "aws": "us-east-1",
        "gcp": "us-central1",
        "azure": "eastus",
    }
    return regions.get(provider, "unknown")


def _get_storage_types(provider: str) -> list[str]:
    """Get storage types for provider."""
    storage_types = {
        "aws": ["s3", "local"],
        "gcp": ["gcs", "local"],
        "azure": ["blob", "local"],
    }
    return storage_types.get(provider, ["local"])


def _handle_validate(args: argparse.Namespace) -> int:
    """Handle validate command."""
    output_format = getattr(args, "format", "table")
    provider_name = args.provider_name

    from stance.cloud import is_provider_available, get_cloud_provider

    if not is_provider_available(provider_name):
        result = {
            "provider": provider_name,
            "valid": False,
            "error": f"SDK not available. Install required packages.",
        }
        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"\nCredential Validation: {provider_name.upper()}")
            print("=" * 50)
            print(f"Status: FAILED")
            print(f"Error:  {result['error']}")
        return 1

    # Build kwargs for provider
    kwargs = {}
    if getattr(args, "region", None):
        kwargs["region"] = args.region
    if getattr(args, "profile", None):
        kwargs["profile"] = args.profile
    if getattr(args, "project", None):
        kwargs["project_id"] = args.project
    if getattr(args, "subscription", None):
        kwargs["subscription_id"] = args.subscription

    try:
        provider = get_cloud_provider(provider_name, **kwargs)
        valid = provider.validate_credentials()

        result = {
            "provider": provider_name,
            "valid": valid,
            "account_id": provider._account_id if hasattr(provider, "_account_id") else None,
        }

        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"\nCredential Validation: {provider_name.upper()}")
            print("=" * 50)
            print(f"Status: {'VALID' if valid else 'INVALID'}")
            if result.get("account_id"):
                print(f"Account: {result['account_id']}")

        return 0 if valid else 1

    except Exception as e:
        result = {
            "provider": provider_name,
            "valid": False,
            "error": str(e),
        }
        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"\nCredential Validation: {provider_name.upper()}")
            print("=" * 50)
            print(f"Status: FAILED")
            print(f"Error:  {result['error']}")
        return 1


def _handle_account(args: argparse.Namespace) -> int:
    """Handle account command."""
    output_format = getattr(args, "format", "table")
    provider_name = args.provider_name

    from stance.cloud import is_provider_available, get_cloud_provider

    if not is_provider_available(provider_name):
        print(f"SDK not available for {provider_name}. Install required packages.")
        return 1

    # Build kwargs for provider
    kwargs = {}
    if getattr(args, "region", None):
        kwargs["region"] = args.region
    if getattr(args, "profile", None):
        kwargs["profile"] = args.profile
    if getattr(args, "project", None):
        kwargs["project_id"] = args.project
    if getattr(args, "subscription", None):
        kwargs["subscription_id"] = args.subscription

    try:
        provider = get_cloud_provider(provider_name, **kwargs)
        account = provider.get_account()

        result = {
            "provider": account.provider,
            "account_id": account.account_id,
            "display_name": account.display_name,
            "region_count": len(account.regions),
            "metadata": account.metadata,
        }

        if output_format == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"\nCloud Account: {provider_name.upper()}")
            print("=" * 60)
            print(f"Account ID:    {result['account_id']}")
            print(f"Display Name:  {result['display_name'] or 'N/A'}")
            print(f"Regions:       {result['region_count']} available")
            if result["metadata"]:
                print("\nMetadata:")
                for key, value in result["metadata"].items():
                    print(f"  {key}: {value}")

        return 0

    except Exception as e:
        print(f"Failed to get account info: {e}")
        return 1


def _handle_regions(args: argparse.Namespace) -> int:
    """Handle regions command."""
    output_format = getattr(args, "format", "table")
    provider_name = args.provider_name

    from stance.cloud import is_provider_available, get_cloud_provider

    if not is_provider_available(provider_name):
        print(f"SDK not available for {provider_name}. Install required packages.")
        return 1

    # Build kwargs for provider
    kwargs = {}
    if getattr(args, "region", None):
        kwargs["region"] = args.region
    if getattr(args, "profile", None):
        kwargs["profile"] = args.profile
    if getattr(args, "project", None):
        kwargs["project_id"] = args.project
    if getattr(args, "subscription", None):
        kwargs["subscription_id"] = args.subscription

    try:
        provider = get_cloud_provider(provider_name, **kwargs)
        regions = provider.list_regions()

        region_list = [
            {
                "region_id": r.region_id,
                "display_name": r.display_name,
                "is_default": r.is_default,
            }
            for r in regions
        ]

        if output_format == "json":
            print(json.dumps(region_list, indent=2))
        else:
            default_count = len([r for r in regions if r.is_default])
            print(f"\n{provider_name.upper()} Regions ({len(regions)} total)")
            print("=" * 60)
            print(f"{'Region ID':<25} {'Display Name':<25} {'Default':<10}")
            print("-" * 60)

            for r in regions:
                default = "*" if r.is_default else ""
                print(f"{r.region_id:<25} {r.display_name:<25} {default:<10}")

        return 0

    except Exception as e:
        print(f"Failed to list regions: {e}")
        return 1


def _handle_availability(args: argparse.Namespace) -> int:
    """Handle availability command."""
    output_format = getattr(args, "format", "table")

    from stance.cloud import PROVIDERS, is_provider_available

    availability = []
    for name, provider_class in PROVIDERS.items():
        available = is_provider_available(name)
        packages = provider_class.get_required_packages()
        availability.append({
            "provider": name,
            "available": available,
            "packages": packages,
            "install": f"pip install {' '.join(packages)}" if packages else "N/A",
        })

    if output_format == "json":
        print(json.dumps(availability, indent=2))
    else:
        print("\nCloud SDK Availability")
        print("=" * 80)

        for a in availability:
            status = "[+]" if a["available"] else "[-]"
            print(f"\n{status} {a['provider'].upper()}")
            print(f"    Status: {'Available' if a['available'] else 'Not Available'}")
            print(f"    Packages: {', '.join(a['packages'])}")
            if not a["available"]:
                print(f"    Install: {a['install']}")

    return 0


def _handle_packages(args: argparse.Namespace) -> int:
    """Handle packages command."""
    output_format = getattr(args, "format", "table")
    provider_filter = getattr(args, "provider", None)

    from stance.cloud import PROVIDERS

    packages_list = []
    for name, provider_class in PROVIDERS.items():
        if provider_filter and name != provider_filter:
            continue
        packages = provider_class.get_required_packages()
        packages_list.append({
            "provider": name,
            "packages": packages,
            "install_command": f"pip install {' '.join(packages)}",
        })

    if output_format == "json":
        print(json.dumps(packages_list, indent=2))
    else:
        print("\nRequired Packages by Provider")
        print("=" * 80)

        for p in packages_list:
            print(f"\n{p['provider'].upper()}:")
            print(f"  Packages: {', '.join(p['packages'])}")
            print(f"  Install:  {p['install_command']}")

    return 0


def _handle_credentials(args: argparse.Namespace) -> int:
    """Handle credentials command."""
    output_format = getattr(args, "format", "table")
    provider_filter = getattr(args, "provider", None)

    credentials_info = [
        {
            "provider": "aws",
            "fields": _get_credential_fields("aws"),
            "env_vars": [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_PROFILE",
                "AWS_ROLE_ARN",
            ],
            "auth_methods": [
                "Environment variables",
                "AWS profile (~/.aws/credentials)",
                "IAM role (EC2/ECS/Lambda)",
                "Explicit credentials",
                "Role assumption",
            ],
        },
        {
            "provider": "gcp",
            "fields": _get_credential_fields("gcp"),
            "env_vars": [
                "GOOGLE_APPLICATION_CREDENTIALS",
                "GOOGLE_CLOUD_PROJECT",
            ],
            "auth_methods": [
                "Service account key file",
                "Application default credentials",
                "Workload identity (GKE)",
                "Explicit credentials",
            ],
        },
        {
            "provider": "azure",
            "fields": _get_credential_fields("azure"),
            "env_vars": [
                "AZURE_SUBSCRIPTION_ID",
                "AZURE_TENANT_ID",
                "AZURE_CLIENT_ID",
                "AZURE_CLIENT_SECRET",
            ],
            "auth_methods": [
                "Service principal",
                "Managed identity",
                "Azure CLI",
                "Explicit credentials",
            ],
        },
    ]

    if provider_filter:
        credentials_info = [c for c in credentials_info if c["provider"] == provider_filter]

    if output_format == "json":
        print(json.dumps(credentials_info, indent=2))
    else:
        print("\nCredential Configuration Options")
        print("=" * 80)

        for c in credentials_info:
            print(f"\n{c['provider'].upper()}")
            print("-" * 40)

            print("  Fields:")
            for f in c["fields"]:
                print(f"    - {f}")

            print("  Environment Variables:")
            for e in c["env_vars"]:
                print(f"    - {e}")

            print("  Authentication Methods:")
            for m in c["auth_methods"]:
                print(f"    - {m}")

    return 0


def _handle_exceptions(args: argparse.Namespace) -> int:
    """Handle exceptions command."""
    output_format = getattr(args, "format", "table")

    exceptions = [
        {
            "name": "CloudProviderError",
            "description": "Base exception for cloud provider errors",
            "parent": "Exception",
        },
        {
            "name": "AuthenticationError",
            "description": "Raised when authentication fails",
            "parent": "CloudProviderError",
        },
        {
            "name": "ConfigurationError",
            "description": "Raised when configuration is invalid",
            "parent": "CloudProviderError",
        },
        {
            "name": "ResourceNotFoundError",
            "description": "Raised when a resource is not found",
            "parent": "CloudProviderError",
        },
        {
            "name": "PermissionDeniedError",
            "description": "Raised when permission is denied",
            "parent": "CloudProviderError",
        },
    ]

    if output_format == "json":
        print(json.dumps(exceptions, indent=2))
    else:
        print("\nCloud Provider Exception Types")
        print("=" * 80)
        print(f"{'Exception':<25} {'Parent':<25} {'Description':<30}")
        print("-" * 80)

        for e in exceptions:
            print(f"{e['name']:<25} {e['parent']:<25} {e['description']:<30}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    from stance.cloud import PROVIDERS, is_provider_available

    output_format = getattr(args, "format", "table")

    status = {
        "module": "cloud",
        "components": {
            "CloudProvider": True,
            "CloudCredentials": True,
            "CloudRegion": True,
            "CloudAccount": True,
            "PROVIDERS": True,
        },
        "providers": {
            name: is_provider_available(name) for name in PROVIDERS.keys()
        },
        "capabilities": [
            "multi_provider_support",
            "credential_validation",
            "region_discovery",
            "account_info",
            "collector_integration",
            "storage_backend_integration",
            "role_assumption",
            "session_management",
        ],
    }

    if output_format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nCloud Module Status")
        print("=" * 50)
        print(f"Module: {status['module']}")

        print("\nComponents:")
        for component, available in status["components"].items():
            indicator = "[+]" if available else "[-]"
            print(f"  {indicator} {component}")

        print("\nProviders:")
        for provider, available in status["providers"].items():
            indicator = "[+]" if available else "[-]"
            print(f"  {indicator} {provider}")

        print("\nCapabilities:")
        for cap in status["capabilities"]:
            print(f"  - {cap}")

    return 0


def _handle_summary(args: argparse.Namespace) -> int:
    """Handle summary command."""
    from stance.cloud import PROVIDERS, is_provider_available

    output_format = getattr(args, "format", "table")

    providers = _get_provider_metadata()
    available_count = len([p for p in providers if p["available"]])

    summary = {
        "overview": {
            "description": "Cloud provider abstraction layer for multi-cloud security posture management",
            "total_providers": len(providers),
            "available_providers": available_count,
            "providers": {
                p["name"]: {
                    "display_name": p["display_name"],
                    "available": p["available"],
                    "packages": p["packages"],
                }
                for p in providers
            },
        },
        "features": [
            "Unified interface for AWS, GCP, and Azure",
            "Automatic credential discovery and validation",
            "Region enumeration for all providers",
            "Account/project/subscription information",
            "Collector integration for security scanning",
            "Storage backend integration (S3, GCS, Blob)",
            "IAM role assumption support (AWS)",
            "Service account support (GCP)",
            "Service principal support (Azure)",
        ],
        "architecture": {
            "base_class": "CloudProvider",
            "credentials_class": "CloudCredentials",
            "region_class": "CloudRegion",
            "account_class": "CloudAccount",
            "factory_function": "get_cloud_provider",
        },
        "exception_hierarchy": [
            "CloudProviderError (base)",
            "  -> AuthenticationError",
            "  -> ConfigurationError",
            "  -> ResourceNotFoundError",
            "  -> PermissionDeniedError",
        ],
    }

    if output_format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nCloud Module Summary")
        print("=" * 70)

        print(f"\n{summary['overview']['description']}")
        print(f"Total Providers: {summary['overview']['total_providers']}")
        print(f"Available: {summary['overview']['available_providers']}")

        print("\nProviders:")
        for name, info in summary["overview"]["providers"].items():
            status = "[+]" if info["available"] else "[-]"
            print(f"  {status} {name.upper()}: {info['display_name']}")

        print("\nFeatures:")
        for feature in summary["features"]:
            print(f"  - {feature}")

        print("\nArchitecture:")
        for key, value in summary["architecture"].items():
            print(f"  {key}: {value}")

        print("\nException Hierarchy:")
        for exc in summary["exception_hierarchy"]:
            print(f"  {exc}")

    return 0
