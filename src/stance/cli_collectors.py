"""
CLI commands for Collectors module.

Provides command-line interface for collector management:
- List available collectors by provider
- Get collector details and configuration
- Show collector capabilities and resource types
- View collector registry information
"""

from __future__ import annotations

import argparse
import json
from typing import Any


def add_collectors_parser(subparsers: Any) -> None:
    """Add collectors parser to CLI subparsers."""
    collectors_parser = subparsers.add_parser(
        "collectors",
        help="Cloud resource collector management",
        description="Manage and inspect cloud resource collectors",
    )

    collectors_subparsers = collectors_parser.add_subparsers(
        dest="collectors_action",
        help="Collectors action to perform",
    )

    # list - List all collectors
    list_parser = collectors_subparsers.add_parser(
        "list",
        help="List available collectors",
    )
    list_parser.add_argument(
        "--provider",
        choices=["aws", "gcp", "azure", "kubernetes"],
        help="Filter by cloud provider",
    )
    list_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # info - Get collector details
    info_parser = collectors_subparsers.add_parser(
        "info",
        help="Get details for a specific collector",
    )
    info_parser.add_argument(
        "collector_name",
        help="Collector name (e.g., aws_iam, gcp_storage)",
    )
    info_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # providers - List cloud providers
    providers_parser = collectors_subparsers.add_parser(
        "providers",
        help="List supported cloud providers",
    )
    providers_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # resources - List resource types
    resources_parser = collectors_subparsers.add_parser(
        "resources",
        help="List resource types collected",
    )
    resources_parser.add_argument(
        "--provider",
        choices=["aws", "gcp", "azure", "kubernetes"],
        help="Filter by cloud provider",
    )
    resources_parser.add_argument(
        "--collector",
        help="Filter by collector name",
    )
    resources_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # registry - Show collector registry
    registry_parser = collectors_subparsers.add_parser(
        "registry",
        help="Show collector registry",
    )
    registry_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # availability - Check collector availability
    availability_parser = collectors_subparsers.add_parser(
        "availability",
        help="Check collector availability by provider",
    )
    availability_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # categories - List collector categories
    categories_parser = collectors_subparsers.add_parser(
        "categories",
        help="List collector categories",
    )
    categories_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # count - Get collector counts
    count_parser = collectors_subparsers.add_parser(
        "count",
        help="Get collector counts by provider",
    )
    count_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # stats - Show collector statistics
    stats_parser = collectors_subparsers.add_parser(
        "stats",
        help="Show collector statistics",
    )
    stats_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # status - Show module status
    status_parser = collectors_subparsers.add_parser(
        "status",
        help="Show collectors module status",
    )
    status_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    # summary - Get comprehensive summary
    summary_parser = collectors_subparsers.add_parser(
        "summary",
        help="Get comprehensive collectors summary",
    )
    summary_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )


def cmd_collectors(args: argparse.Namespace) -> int:
    """Handle collectors commands."""
    action = getattr(args, "collectors_action", None)

    if not action:
        print("Usage: stance collectors <action>")
        print("\nAvailable actions:")
        print("  list          List available collectors")
        print("  info          Get details for a specific collector")
        print("  providers     List supported cloud providers")
        print("  resources     List resource types collected")
        print("  registry      Show collector registry")
        print("  availability  Check collector availability")
        print("  categories    List collector categories")
        print("  count         Get collector counts by provider")
        print("  stats         Show collector statistics")
        print("  status        Show collectors module status")
        print("  summary       Get comprehensive summary")
        return 1

    handlers = {
        "list": _handle_list,
        "info": _handle_info,
        "providers": _handle_providers,
        "resources": _handle_resources,
        "registry": _handle_registry,
        "availability": _handle_availability,
        "categories": _handle_categories,
        "count": _handle_count,
        "stats": _handle_stats,
        "status": _handle_status,
        "summary": _handle_summary,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown collectors action: {action}")
    return 1


def _get_collector_metadata() -> dict[str, list[dict[str, Any]]]:
    """Get metadata for all collectors."""
    from stance.collectors import (
        COLLECTOR_REGISTRY,
        GCP_COLLECTORS_AVAILABLE,
        AZURE_COLLECTORS_AVAILABLE,
        K8S_COLLECTORS_AVAILABLE,
    )

    metadata: dict[str, list[dict[str, Any]]] = {
        "aws": [],
        "gcp": [],
        "azure": [],
        "kubernetes": [],
    }

    # AWS collectors (always available)
    aws_collectors = [
        {"name": "aws_iam", "description": "IAM users, roles, policies, groups", "category": "identity"},
        {"name": "aws_s3", "description": "S3 bucket configurations", "category": "storage"},
        {"name": "aws_ec2", "description": "EC2 instances, security groups, VPCs", "category": "compute"},
        {"name": "aws_security", "description": "SecurityHub and Inspector findings", "category": "security"},
        {"name": "aws_rds", "description": "RDS instances, clusters, parameter groups", "category": "database"},
        {"name": "aws_lambda", "description": "Lambda functions, layers, event sources", "category": "serverless"},
        {"name": "aws_dynamodb", "description": "DynamoDB tables, backups, configurations", "category": "database"},
        {"name": "aws_apigateway", "description": "API Gateway REST, HTTP, WebSocket APIs", "category": "networking"},
        {"name": "aws_ecr", "description": "ECR repositories, images, scan findings", "category": "container"},
        {"name": "aws_eks", "description": "EKS clusters, node groups, Fargate profiles", "category": "kubernetes"},
    ]
    metadata["aws"] = aws_collectors

    # GCP collectors
    if GCP_COLLECTORS_AVAILABLE:
        gcp_collectors = [
            {"name": "gcp_iam", "description": "Service accounts, IAM policies", "category": "identity"},
            {"name": "gcp_storage", "description": "Cloud Storage buckets", "category": "storage"},
            {"name": "gcp_compute", "description": "Compute Engine instances, firewalls", "category": "compute"},
            {"name": "gcp_security", "description": "Security Command Center findings", "category": "security"},
            {"name": "gcp_sql", "description": "Cloud SQL instances and configurations", "category": "database"},
            {"name": "gcp_functions", "description": "Cloud Functions (1st and 2nd gen)", "category": "serverless"},
            {"name": "gcp_bigquery", "description": "BigQuery datasets and tables", "category": "database"},
            {"name": "gcp_cloudrun", "description": "Cloud Run services and revisions", "category": "serverless"},
            {"name": "gcp_artifactregistry", "description": "Artifact Registry repositories and images", "category": "container"},
            {"name": "gcp_gke", "description": "GKE clusters and node pools", "category": "kubernetes"},
        ]
        metadata["gcp"] = gcp_collectors

    # Azure collectors
    if AZURE_COLLECTORS_AVAILABLE:
        azure_collectors = [
            {"name": "azure_iam", "description": "Role assignments, role definitions", "category": "identity"},
            {"name": "azure_storage", "description": "Storage accounts, blob containers", "category": "storage"},
            {"name": "azure_compute", "description": "VMs, NSGs, VNets", "category": "compute"},
            {"name": "azure_security", "description": "Defender for Cloud findings", "category": "security"},
            {"name": "azure_sql", "description": "SQL servers, databases, security config", "category": "database"},
            {"name": "azure_functions", "description": "Function Apps and configurations", "category": "serverless"},
            {"name": "azure_cosmosdb", "description": "Cosmos DB accounts and configurations", "category": "database"},
            {"name": "azure_logicapps", "description": "Logic Apps (Workflows) and configurations", "category": "serverless"},
            {"name": "azure_containerregistry", "description": "ACR registries, images, security config", "category": "container"},
            {"name": "azure_aks", "description": "AKS clusters and node pools", "category": "kubernetes"},
        ]
        metadata["azure"] = azure_collectors

    # Kubernetes collectors
    if K8S_COLLECTORS_AVAILABLE:
        k8s_collectors = [
            {"name": "k8s_config", "description": "Pods, deployments, services, daemonsets", "category": "workload"},
            {"name": "k8s_rbac", "description": "Roles, cluster roles, role bindings", "category": "identity"},
            {"name": "k8s_network", "description": "Network policies, ingress, secrets", "category": "networking"},
        ]
        metadata["kubernetes"] = k8s_collectors

    return metadata


def _handle_list(args: argparse.Namespace) -> int:
    """Handle list command."""
    output_format = getattr(args, "format", "table")
    provider_filter = getattr(args, "provider", None)

    metadata = _get_collector_metadata()

    # Apply filter
    if provider_filter:
        collectors = metadata.get(provider_filter, [])
    else:
        collectors = []
        for provider, provider_collectors in metadata.items():
            for c in provider_collectors:
                c["provider"] = provider
                collectors.append(c)

    if output_format == "json":
        print(json.dumps(collectors, indent=2))
    else:
        if not collectors:
            print("No collectors found")
            return 0

        if provider_filter:
            print(f"\nCollectors for {provider_filter.upper()} ({len(collectors)} collectors)")
        else:
            print(f"\nAll Collectors ({len(collectors)} total)")
        print("=" * 90)
        print(f"{'Name':<25} {'Provider':<12} {'Category':<12} {'Description':<38}")
        print("-" * 90)

        for c in collectors:
            provider = c.get("provider", provider_filter or "")
            print(f"{c['name']:<25} {provider:<12} {c['category']:<12} {c['description']:<38}")

    return 0


def _handle_info(args: argparse.Namespace) -> int:
    """Handle info command."""
    output_format = getattr(args, "format", "table")
    collector_name = args.collector_name

    metadata = _get_collector_metadata()

    # Find collector
    collector_info = None
    provider_name = None
    for provider, collectors in metadata.items():
        for c in collectors:
            if c["name"] == collector_name:
                collector_info = c
                provider_name = provider
                break
        if collector_info:
            break

    if not collector_info:
        print(f"Collector not found: {collector_name}")
        return 1

    # Get resource types from collector class
    resource_types = _get_resource_types(collector_name)

    info = {
        "name": collector_info["name"],
        "provider": provider_name,
        "category": collector_info["category"],
        "description": collector_info["description"],
        "resource_types": resource_types,
        "available": True,
    }

    if output_format == "json":
        print(json.dumps(info, indent=2))
    else:
        print(f"\nCollector: {info['name']}")
        print("=" * 60)
        print(f"Provider:      {info['provider']}")
        print(f"Category:      {info['category']}")
        print(f"Description:   {info['description']}")
        print(f"Available:     {'Yes' if info['available'] else 'No'}")
        if resource_types:
            print(f"Resource Types:")
            for rt in resource_types:
                print(f"  - {rt}")

    return 0


def _get_resource_types(collector_name: str) -> list[str]:
    """Get resource types for a collector."""
    from stance.collectors import COLLECTOR_REGISTRY

    for provider_collectors in COLLECTOR_REGISTRY.values():
        if collector_name in provider_collectors:
            collector_class = provider_collectors[collector_name]
            return getattr(collector_class, "resource_types", [])
    return []


def _handle_providers(args: argparse.Namespace) -> int:
    """Handle providers command."""
    from stance.collectors import (
        GCP_COLLECTORS_AVAILABLE,
        AZURE_COLLECTORS_AVAILABLE,
        K8S_COLLECTORS_AVAILABLE,
        list_supported_providers,
    )

    output_format = getattr(args, "format", "table")

    providers = [
        {
            "provider": "aws",
            "name": "Amazon Web Services",
            "available": True,
            "collectors": 10,
            "sdk": "boto3",
        },
        {
            "provider": "gcp",
            "name": "Google Cloud Platform",
            "available": GCP_COLLECTORS_AVAILABLE,
            "collectors": 10 if GCP_COLLECTORS_AVAILABLE else 0,
            "sdk": "google-cloud-*",
        },
        {
            "provider": "azure",
            "name": "Microsoft Azure",
            "available": AZURE_COLLECTORS_AVAILABLE,
            "collectors": 10 if AZURE_COLLECTORS_AVAILABLE else 0,
            "sdk": "azure-*",
        },
        {
            "provider": "kubernetes",
            "name": "Kubernetes",
            "available": K8S_COLLECTORS_AVAILABLE,
            "collectors": 3 if K8S_COLLECTORS_AVAILABLE else 0,
            "sdk": "kubernetes",
        },
    ]

    if output_format == "json":
        print(json.dumps(providers, indent=2))
    else:
        active = len([p for p in providers if p["available"]])
        print(f"\nCloud Providers ({active} available)")
        print("=" * 80)
        print(f"{'Provider':<12} {'Name':<25} {'Available':<10} {'Collectors':<12} {'SDK':<15}")
        print("-" * 80)

        for p in providers:
            available = "Yes" if p["available"] else "No"
            print(f"{p['provider']:<12} {p['name']:<25} {available:<10} {p['collectors']:<12} {p['sdk']:<15}")

    return 0


def _handle_resources(args: argparse.Namespace) -> int:
    """Handle resources command."""
    from stance.collectors import COLLECTOR_REGISTRY

    output_format = getattr(args, "format", "table")
    provider_filter = getattr(args, "provider", None)
    collector_filter = getattr(args, "collector", None)

    resources = []

    for provider, collectors in COLLECTOR_REGISTRY.items():
        if provider_filter and provider != provider_filter:
            continue

        for collector_name, collector_class in collectors.items():
            if collector_filter and collector_name != collector_filter:
                continue

            resource_types = getattr(collector_class, "resource_types", [])
            for rt in resource_types:
                resources.append({
                    "provider": provider,
                    "collector": collector_name,
                    "resource_type": rt,
                })

    if output_format == "json":
        print(json.dumps(resources, indent=2))
    else:
        if not resources:
            print("No resource types found")
            return 0

        print(f"\nResource Types ({len(resources)} total)")
        print("=" * 80)
        print(f"{'Provider':<12} {'Collector':<25} {'Resource Type':<40}")
        print("-" * 80)

        for r in resources:
            print(f"{r['provider']:<12} {r['collector']:<25} {r['resource_type']:<40}")

    return 0


def _handle_registry(args: argparse.Namespace) -> int:
    """Handle registry command."""
    from stance.collectors import COLLECTOR_REGISTRY

    output_format = getattr(args, "format", "table")

    registry_data = {}
    for provider, collectors in COLLECTOR_REGISTRY.items():
        registry_data[provider] = list(collectors.keys())

    if output_format == "json":
        print(json.dumps(registry_data, indent=2))
    else:
        total = sum(len(c) for c in registry_data.values())
        print(f"\nCollector Registry ({total} total)")
        print("=" * 60)

        for provider, collectors in registry_data.items():
            if collectors:
                print(f"\n{provider.upper()} ({len(collectors)} collectors):")
                for c in collectors:
                    print(f"  - {c}")

    return 0


def _handle_availability(args: argparse.Namespace) -> int:
    """Handle availability command."""
    from stance.collectors import (
        GCP_COLLECTORS_AVAILABLE,
        AZURE_COLLECTORS_AVAILABLE,
        K8S_COLLECTORS_AVAILABLE,
    )

    output_format = getattr(args, "format", "table")

    availability = [
        {
            "provider": "aws",
            "available": True,
            "reason": "boto3 always available",
            "install": "pip install boto3",
        },
        {
            "provider": "gcp",
            "available": GCP_COLLECTORS_AVAILABLE,
            "reason": "google-cloud SDK installed" if GCP_COLLECTORS_AVAILABLE else "google-cloud SDK not installed",
            "install": "pip install google-cloud-resource-manager google-cloud-storage google-cloud-compute",
        },
        {
            "provider": "azure",
            "available": AZURE_COLLECTORS_AVAILABLE,
            "reason": "azure SDK installed" if AZURE_COLLECTORS_AVAILABLE else "azure SDK not installed",
            "install": "pip install azure-identity azure-mgmt-resource azure-mgmt-storage",
        },
        {
            "provider": "kubernetes",
            "available": K8S_COLLECTORS_AVAILABLE,
            "reason": "kubernetes SDK installed" if K8S_COLLECTORS_AVAILABLE else "kubernetes SDK not installed",
            "install": "pip install kubernetes",
        },
    ]

    if output_format == "json":
        print(json.dumps(availability, indent=2))
    else:
        print("\nCollector Availability")
        print("=" * 80)

        for a in availability:
            status = "[+]" if a["available"] else "[-]"
            print(f"\n{status} {a['provider'].upper()}")
            print(f"    Status: {'Available' if a['available'] else 'Not Available'}")
            print(f"    Reason: {a['reason']}")
            if not a["available"]:
                print(f"    Install: {a['install']}")

    return 0


def _handle_categories(args: argparse.Namespace) -> int:
    """Handle categories command."""
    output_format = getattr(args, "format", "table")

    categories = [
        {
            "category": "identity",
            "description": "Identity and access management (IAM, RBAC)",
            "examples": ["aws_iam", "gcp_iam", "azure_iam", "k8s_rbac"],
        },
        {
            "category": "storage",
            "description": "Object and block storage services",
            "examples": ["aws_s3", "gcp_storage", "azure_storage"],
        },
        {
            "category": "compute",
            "description": "Virtual machines and compute instances",
            "examples": ["aws_ec2", "gcp_compute", "azure_compute"],
        },
        {
            "category": "security",
            "description": "Security findings and compliance",
            "examples": ["aws_security", "gcp_security", "azure_security"],
        },
        {
            "category": "database",
            "description": "Database services (SQL and NoSQL)",
            "examples": ["aws_rds", "aws_dynamodb", "gcp_sql", "azure_sql"],
        },
        {
            "category": "serverless",
            "description": "Serverless functions and workflows",
            "examples": ["aws_lambda", "gcp_functions", "azure_functions"],
        },
        {
            "category": "container",
            "description": "Container registries and images",
            "examples": ["aws_ecr", "gcp_artifactregistry", "azure_containerregistry"],
        },
        {
            "category": "kubernetes",
            "description": "Managed Kubernetes services",
            "examples": ["aws_eks", "gcp_gke", "azure_aks"],
        },
        {
            "category": "networking",
            "description": "Networking and API services",
            "examples": ["aws_apigateway", "k8s_network"],
        },
        {
            "category": "workload",
            "description": "Kubernetes workloads (pods, deployments)",
            "examples": ["k8s_config"],
        },
    ]

    if output_format == "json":
        print(json.dumps(categories, indent=2))
    else:
        print(f"\nCollector Categories ({len(categories)} categories)")
        print("=" * 80)

        for cat in categories:
            print(f"\n{cat['category'].upper()}")
            print(f"  Description: {cat['description']}")
            print(f"  Examples: {', '.join(cat['examples'])}")

    return 0


def _handle_count(args: argparse.Namespace) -> int:
    """Handle count command."""
    from stance.collectors import COLLECTOR_REGISTRY

    output_format = getattr(args, "format", "table")

    counts = []
    total = 0
    for provider, collectors in COLLECTOR_REGISTRY.items():
        count = len(collectors)
        total += count
        counts.append({
            "provider": provider,
            "count": count,
            "available": count > 0,
        })

    if output_format == "json":
        result = {"counts": counts, "total": total}
        print(json.dumps(result, indent=2))
    else:
        print(f"\nCollector Counts (Total: {total})")
        print("=" * 40)
        print(f"{'Provider':<15} {'Count':<10} {'Available':<10}")
        print("-" * 40)

        for c in counts:
            available = "Yes" if c["available"] else "No"
            print(f"{c['provider']:<15} {c['count']:<10} {available:<10}")

        print("-" * 40)
        print(f"{'Total':<15} {total:<10}")

    return 0


def _handle_stats(args: argparse.Namespace) -> int:
    """Handle stats command."""
    from stance.collectors import (
        COLLECTOR_REGISTRY,
        GCP_COLLECTORS_AVAILABLE,
        AZURE_COLLECTORS_AVAILABLE,
        K8S_COLLECTORS_AVAILABLE,
    )

    output_format = getattr(args, "format", "table")

    # Calculate statistics
    total_collectors = sum(len(c) for c in COLLECTOR_REGISTRY.values())
    available_providers = sum([
        1,  # AWS always available
        1 if GCP_COLLECTORS_AVAILABLE else 0,
        1 if AZURE_COLLECTORS_AVAILABLE else 0,
        1 if K8S_COLLECTORS_AVAILABLE else 0,
    ])

    metadata = _get_collector_metadata()
    categories = set()
    for provider_collectors in metadata.values():
        for c in provider_collectors:
            categories.add(c.get("category", "unknown"))

    # Count resource types
    resource_type_count = 0
    for provider_collectors in COLLECTOR_REGISTRY.values():
        for collector_class in provider_collectors.values():
            resource_type_count += len(getattr(collector_class, "resource_types", []))

    stats = {
        "total_collectors": total_collectors,
        "available_providers": available_providers,
        "total_providers": 4,
        "categories": len(categories),
        "resource_types": resource_type_count,
        "by_provider": {
            "aws": len(COLLECTOR_REGISTRY.get("aws", {})),
            "gcp": len(COLLECTOR_REGISTRY.get("gcp", {})),
            "azure": len(COLLECTOR_REGISTRY.get("azure", {})),
            "kubernetes": len(COLLECTOR_REGISTRY.get("kubernetes", {})),
        },
        "sdk_availability": {
            "boto3": True,
            "google-cloud": GCP_COLLECTORS_AVAILABLE,
            "azure": AZURE_COLLECTORS_AVAILABLE,
            "kubernetes": K8S_COLLECTORS_AVAILABLE,
        },
    }

    if output_format == "json":
        print(json.dumps(stats, indent=2))
    else:
        print("\nCollector Statistics")
        print("=" * 50)
        print(f"Total Collectors:      {stats['total_collectors']}")
        print(f"Available Providers:   {stats['available_providers']}/{stats['total_providers']}")
        print(f"Categories:            {stats['categories']}")
        print(f"Resource Types:        {stats['resource_types']}")

        print("\nBy Provider:")
        for provider, count in stats["by_provider"].items():
            print(f"  {provider:<12} {count} collectors")

        print("\nSDK Availability:")
        for sdk, available in stats["sdk_availability"].items():
            status = "[+]" if available else "[-]"
            print(f"  {status} {sdk}")

    return 0


def _handle_status(args: argparse.Namespace) -> int:
    """Handle status command."""
    from stance.collectors import (
        GCP_COLLECTORS_AVAILABLE,
        AZURE_COLLECTORS_AVAILABLE,
        K8S_COLLECTORS_AVAILABLE,
    )

    output_format = getattr(args, "format", "table")

    status = {
        "module": "collectors",
        "components": {
            "BaseCollector": True,
            "CollectorResult": True,
            "CollectorRunner": True,
            "COLLECTOR_REGISTRY": True,
        },
        "providers": {
            "aws": True,
            "gcp": GCP_COLLECTORS_AVAILABLE,
            "azure": AZURE_COLLECTORS_AVAILABLE,
            "kubernetes": K8S_COLLECTORS_AVAILABLE,
        },
        "capabilities": [
            "multi_provider_support",
            "pagination_handling",
            "error_handling",
            "asset_collection",
            "finding_collection",
            "parallel_execution",
        ],
    }

    if output_format == "json":
        print(json.dumps(status, indent=2))
    else:
        print("\nCollectors Module Status")
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
    from stance.collectors import (
        COLLECTOR_REGISTRY,
        GCP_COLLECTORS_AVAILABLE,
        AZURE_COLLECTORS_AVAILABLE,
        K8S_COLLECTORS_AVAILABLE,
    )

    output_format = getattr(args, "format", "table")

    total_collectors = sum(len(c) for c in COLLECTOR_REGISTRY.values())
    metadata = _get_collector_metadata()

    # Get categories
    category_counts: dict[str, int] = {}
    for provider_collectors in metadata.values():
        for c in provider_collectors:
            cat = c.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

    summary = {
        "overview": {
            "description": "Cloud resource collectors for multi-provider security assessment",
            "total_collectors": total_collectors,
            "providers": {
                "aws": {"available": True, "collectors": len(COLLECTOR_REGISTRY.get("aws", {}))},
                "gcp": {"available": GCP_COLLECTORS_AVAILABLE, "collectors": len(COLLECTOR_REGISTRY.get("gcp", {}))},
                "azure": {"available": AZURE_COLLECTORS_AVAILABLE, "collectors": len(COLLECTOR_REGISTRY.get("azure", {}))},
                "kubernetes": {"available": K8S_COLLECTORS_AVAILABLE, "collectors": len(COLLECTOR_REGISTRY.get("kubernetes", {}))},
            },
        },
        "categories": category_counts,
        "features": [
            "Multi-cloud resource collection (AWS, GCP, Azure)",
            "Kubernetes cluster scanning",
            "IAM and identity analysis",
            "Storage security assessment",
            "Compute and VM configuration",
            "Database security posture",
            "Serverless function analysis",
            "Container registry scanning",
            "Managed Kubernetes (EKS, GKE, AKS)",
            "Security findings aggregation",
        ],
        "architecture": {
            "base_class": "BaseCollector",
            "result_class": "CollectorResult",
            "runner_class": "CollectorRunner",
            "registry": "COLLECTOR_REGISTRY",
        },
    }

    if output_format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print("\nCollectors Module Summary")
        print("=" * 70)

        print(f"\n{summary['overview']['description']}")
        print(f"Total Collectors: {summary['overview']['total_collectors']}")

        print("\nProviders:")
        for provider, info in summary["overview"]["providers"].items():
            status = "[+]" if info["available"] else "[-]"
            print(f"  {status} {provider.upper()}: {info['collectors']} collectors")

        print("\nCategories:")
        for cat, count in sorted(summary["categories"].items()):
            print(f"  {cat:<15} {count} collectors")

        print("\nFeatures:")
        for feature in summary["features"]:
            print(f"  - {feature}")

        print("\nArchitecture:")
        for key, value in summary["architecture"].items():
            print(f"  {key}: {value}")

    return 0
