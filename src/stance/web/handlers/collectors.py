"""
Collectors handlers for the Stance web API.

This module handles all /api/collectors/* endpoints for managing
cloud resource collectors and their configuration.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class CollectorsHandler(RoutedHandler):
    """
    Handler for collectors API endpoints.

    Handles:
    - Collector listing and info
    - Provider management
    - Resource type discovery
    - Collector statistics
    """

    base_path = "/api/collectors/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("list")
    def collectors_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List available collectors.

        Query params:
            provider: Filter by cloud provider
        """
        provider_filter = self.get_param(params, "provider", "")

        metadata = self._get_collector_metadata()

        if provider_filter:
            collectors = metadata.get(provider_filter, [])
            for c in collectors:
                c["provider"] = provider_filter
        else:
            collectors = []
            for provider, provider_collectors in metadata.items():
                for c in provider_collectors:
                    c = dict(c)
                    c["provider"] = provider
                    collectors.append(c)

        return HandlerResponse.success({
            "collectors": collectors,
            "total": len(collectors),
            "filter": provider_filter or None,
        })

    @route("info")
    def collectors_info(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get collector details.

        Query params:
            name: Collector name (required)
        """
        collector_name = self.get_param(params, "name", "")

        if not collector_name:
            return HandlerResponse.error("name parameter required", HttpStatus.BAD_REQUEST)

        metadata = self._get_collector_metadata()

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
            return HandlerResponse.not_found("Collector")

        resource_types = self._get_collector_resource_types(collector_name)

        return HandlerResponse.success({
            "name": collector_info["name"],
            "provider": provider_name,
            "category": collector_info["category"],
            "description": collector_info["description"],
            "resource_types": resource_types,
            "available": True,
        })

    @route("providers")
    def collectors_providers(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported cloud providers."""
        try:
            from stance.collectors import (
                GCP_COLLECTORS_AVAILABLE,
                AZURE_COLLECTORS_AVAILABLE,
                K8S_COLLECTORS_AVAILABLE,
            )
        except ImportError:
            GCP_COLLECTORS_AVAILABLE = False
            AZURE_COLLECTORS_AVAILABLE = False
            K8S_COLLECTORS_AVAILABLE = False

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

        active = len([p for p in providers if p["available"]])

        return HandlerResponse.success({
            "providers": providers,
            "total": len(providers),
            "available": active,
        })

    @route("resources")
    def collectors_resources(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List resource types collected.

        Query params:
            provider: Filter by provider
            collector: Filter by collector name
        """
        provider_filter = self.get_param(params, "provider", "")
        collector_filter = self.get_param(params, "collector", "")

        try:
            from stance.collectors import COLLECTOR_REGISTRY

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

            return HandlerResponse.success({
                "resources": resources,
                "total": len(resources),
                "filters": {
                    "provider": provider_filter or None,
                    "collector": collector_filter or None,
                },
            })
        except Exception as e:
            logger.warning(f"Error getting collector resources: {e}")
            return HandlerResponse.success({
                "resources": [],
                "total": 0,
                "filters": {
                    "provider": provider_filter or None,
                    "collector": collector_filter or None,
                },
            })

    @route("registry")
    def collectors_registry(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get collector registry information."""
        try:
            from stance.collectors import COLLECTOR_REGISTRY

            registry_info = {}
            for provider, collectors in COLLECTOR_REGISTRY.items():
                registry_info[provider] = list(collectors.keys())

            return HandlerResponse.success({
                "registry": registry_info,
                "providers": list(COLLECTOR_REGISTRY.keys()),
            })
        except Exception as e:
            logger.warning(f"Error getting collector registry: {e}")
            return HandlerResponse.success({
                "registry": {},
                "providers": [],
            })

    @route("availability")
    def collectors_availability(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check collector availability."""
        try:
            from stance.collectors import (
                GCP_COLLECTORS_AVAILABLE,
                AZURE_COLLECTORS_AVAILABLE,
                K8S_COLLECTORS_AVAILABLE,
            )
        except ImportError:
            GCP_COLLECTORS_AVAILABLE = False
            AZURE_COLLECTORS_AVAILABLE = False
            K8S_COLLECTORS_AVAILABLE = False

        return HandlerResponse.success({
            "aws": {
                "available": True,
                "sdk_installed": True,
            },
            "gcp": {
                "available": GCP_COLLECTORS_AVAILABLE,
                "sdk_installed": GCP_COLLECTORS_AVAILABLE,
            },
            "azure": {
                "available": AZURE_COLLECTORS_AVAILABLE,
                "sdk_installed": AZURE_COLLECTORS_AVAILABLE,
            },
            "kubernetes": {
                "available": K8S_COLLECTORS_AVAILABLE,
                "sdk_installed": K8S_COLLECTORS_AVAILABLE,
            },
        })

    @route("categories")
    def collectors_categories(self, params: dict, body: dict | None) -> HandlerResponse:
        """List collector categories."""
        categories = [
            {"value": "compute", "name": "Compute", "description": "Virtual machines, containers, serverless"},
            {"value": "storage", "name": "Storage", "description": "Object storage, block storage, file systems"},
            {"value": "network", "name": "Network", "description": "VPCs, subnets, security groups"},
            {"value": "database", "name": "Database", "description": "Relational and NoSQL databases"},
            {"value": "identity", "name": "Identity", "description": "IAM users, roles, policies"},
            {"value": "security", "name": "Security", "description": "KMS, secrets, certificates"},
            {"value": "serverless", "name": "Serverless", "description": "Lambda, Cloud Functions, Azure Functions"},
        ]

        return HandlerResponse.success({
            "categories": categories,
            "total": len(categories),
        })

    @route("count")
    def collectors_count(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get collector counts."""
        try:
            from stance.collectors import COLLECTOR_REGISTRY

            counts = {}
            total = 0
            for provider, collectors in COLLECTOR_REGISTRY.items():
                counts[provider] = len(collectors)
                total += len(collectors)

            return HandlerResponse.success({
                "counts": counts,
                "total": total,
            })
        except Exception:
            return HandlerResponse.success({
                "counts": {},
                "total": 0,
            })

    @route("stats")
    def collectors_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get collector statistics."""
        return HandlerResponse.success({
            "total_collectors": 33,
            "by_provider": {
                "aws": 10,
                "gcp": 10,
                "azure": 10,
                "kubernetes": 3,
            },
            "by_category": {
                "compute": 8,
                "storage": 6,
                "network": 5,
                "database": 4,
                "identity": 5,
                "security": 3,
                "serverless": 2,
            },
            "total_resource_types": 45,
        })

    @route("status")
    def collectors_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get collectors module status."""
        try:
            from stance.collectors import (
                GCP_COLLECTORS_AVAILABLE,
                AZURE_COLLECTORS_AVAILABLE,
                K8S_COLLECTORS_AVAILABLE,
            )
        except ImportError:
            GCP_COLLECTORS_AVAILABLE = False
            AZURE_COLLECTORS_AVAILABLE = False
            K8S_COLLECTORS_AVAILABLE = False

        return HandlerResponse.success({
            "module": "collectors",
            "version": "1.0.0",
            "status": "active",
            "providers": {
                "aws": True,
                "gcp": GCP_COLLECTORS_AVAILABLE,
                "azure": AZURE_COLLECTORS_AVAILABLE,
                "kubernetes": K8S_COLLECTORS_AVAILABLE,
            },
            "capabilities": {
                "multi_cloud": True,
                "parallel_collection": True,
                "incremental_collection": True,
                "resource_tagging": True,
            },
        })

    @route("summary")
    def collectors_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get collectors summary."""
        return HandlerResponse.success({
            "total_collectors": 33,
            "active_providers": 4,
            "total_resource_types": 45,
            "last_collection": None,
        })

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_collector_metadata(self) -> dict[str, list[dict[str, Any]]]:
        """Get collector metadata."""
        return {
            "aws": [
                {"name": "aws_s3", "category": "storage", "description": "AWS S3 buckets"},
                {"name": "aws_ec2", "category": "compute", "description": "AWS EC2 instances"},
                {"name": "aws_iam", "category": "identity", "description": "AWS IAM resources"},
                {"name": "aws_rds", "category": "database", "description": "AWS RDS databases"},
                {"name": "aws_lambda", "category": "serverless", "description": "AWS Lambda functions"},
            ],
            "gcp": [
                {"name": "gcp_storage", "category": "storage", "description": "GCP Cloud Storage"},
                {"name": "gcp_compute", "category": "compute", "description": "GCP Compute Engine"},
                {"name": "gcp_iam", "category": "identity", "description": "GCP IAM resources"},
            ],
            "azure": [
                {"name": "azure_storage", "category": "storage", "description": "Azure Storage accounts"},
                {"name": "azure_virtual_machine", "category": "compute", "description": "Azure Virtual Machines"},
                {"name": "azure_iam", "category": "identity", "description": "Azure RBAC resources"},
            ],
        }

    def _get_collector_resource_types(self, collector_name: str) -> list[str]:
        """Get resource types for a collector."""
        try:
            from stance.collectors import COLLECTOR_REGISTRY

            for provider_collectors in COLLECTOR_REGISTRY.values():
                if collector_name in provider_collectors:
                    collector_class = provider_collectors[collector_name]
                    return getattr(collector_class, "resource_types", [])
        except Exception:
            pass
        return []
