"""
Asset management handlers for the Stance web API.

This module handles all /api/assets/* endpoints for asset operations
including listing, filtering, details, grouping, inventory, types,
enrichment, and risk scoring functionality.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class AssetHandler(RoutedHandler):
    """
    Handler for asset management API endpoints.

    Handles:
    - Asset listing and filtering
    - Asset details with related findings
    - Asset grouping by cloud, region, type
    - Asset inventory and types metadata
    - Asset enrichment with context
    - Asset risk scoring
    """

    base_path = "/api/assets/"

    # =========================================================================
    # Asset Listing GET endpoints
    # =========================================================================

    @route("list")
    def assets_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List assets with pagination and filtering."""
        try:
            limit = self.get_param_int(params, "limit", 50)
            offset = self.get_param_int(params, "offset", 0)
            resource_type = self.get_param(params, "type", "")
            region = self.get_param(params, "region", "")
            exposure = self.get_param(params, "exposure", "")
            cloud = self.get_param(params, "cloud", "")

            # Demo assets data
            assets = [
                {
                    "id": "arn:aws:s3:::production-data",
                    "resource_type": "aws_s3_bucket",
                    "name": "production-data",
                    "region": "us-east-1",
                    "network_exposure": "private",
                    "account_id": "123456789012",
                    "cloud_provider": "aws",
                },
                {
                    "id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                    "resource_type": "aws_ec2_instance",
                    "name": "web-server-01",
                    "region": "us-west-2",
                    "network_exposure": "public",
                    "account_id": "123456789012",
                    "cloud_provider": "aws",
                },
                {
                    "id": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
                    "resource_type": "aws_rds_instance",
                    "name": "prod-db",
                    "region": "us-east-1",
                    "network_exposure": "private",
                    "account_id": "123456789012",
                    "cloud_provider": "aws",
                },
                {
                    "id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics",
                    "resource_type": "gcp_storage_bucket",
                    "name": "analytics",
                    "region": "us-central1",
                    "network_exposure": "private",
                    "account_id": "my-gcp-project",
                    "cloud_provider": "gcp",
                },
                {
                    "id": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-prod",
                    "resource_type": "azure_vm",
                    "name": "vm-prod",
                    "region": "eastus",
                    "network_exposure": "public",
                    "account_id": "sub-123",
                    "cloud_provider": "azure",
                },
            ]

            # Apply filters
            if resource_type:
                assets = [a for a in assets if a["resource_type"] == resource_type]
            if region:
                assets = [a for a in assets if a["region"] == region]
            if exposure:
                if exposure == "internet_facing":
                    assets = [a for a in assets if a["network_exposure"] == "public"]
                else:
                    assets = [a for a in assets if a["network_exposure"] == exposure]
            if cloud:
                assets = [a for a in assets if a["cloud_provider"].lower() == cloud.lower()]

            total = len(assets)
            assets = assets[offset:offset + limit]

            return HandlerResponse.success({
                "items": assets,
                "total": total,
                "limit": limit,
                "offset": offset,
            })
        except Exception as e:
            logger.exception("Failed to list assets")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def assets_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detailed information for a specific asset."""
        try:
            asset_id = self.get_param(params, "asset_id", "")

            if not asset_id:
                return HandlerResponse.error("asset_id parameter required", HttpStatus.BAD_REQUEST)

            # Demo asset details with findings
            result = {
                "asset": {
                    "id": asset_id,
                    "name": "production-data",
                    "resource_type": "aws_s3_bucket",
                    "cloud_provider": "aws",
                    "account_id": "123456789012",
                    "region": "us-east-1",
                    "network_exposure": "private",
                    "tags": {"Environment": "production", "Team": "platform"},
                    "created_at": "2024-01-15T10:00:00Z",
                    "last_seen": "2024-12-30T10:00:00Z",
                },
                "findings": [
                    {
                        "id": "finding-001",
                        "title": "S3 bucket without encryption",
                        "severity": "HIGH",
                        "status": "OPEN",
                        "finding_type": "MISCONFIGURATION",
                        "rule_id": "aws-s3-001",
                    },
                    {
                        "id": "finding-002",
                        "title": "S3 bucket logging disabled",
                        "severity": "MEDIUM",
                        "status": "OPEN",
                        "finding_type": "MISCONFIGURATION",
                        "rule_id": "aws-s3-002",
                    },
                ],
                "finding_count": 2,
                "findings_by_severity": {
                    "critical": 0,
                    "high": 1,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get asset details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Asset Search and Filter endpoints
    # =========================================================================

    @route("search")
    def assets_search(self, params: dict, body: dict | None) -> HandlerResponse:
        """Search assets by query string."""
        try:
            query = self.get_param(params, "q", "")
            limit = self.get_param_int(params, "limit", 50)
            offset = self.get_param_int(params, "offset", 0)

            if not query:
                return HandlerResponse.error("q (query) parameter required", HttpStatus.BAD_REQUEST)

            # Demo search results
            results = [
                {
                    "id": "arn:aws:s3:::production-data",
                    "name": "production-data",
                    "resource_type": "aws_s3_bucket",
                    "region": "us-east-1",
                    "network_exposure": "private",
                    "match_score": 0.95,
                    "match_field": "name",
                },
                {
                    "id": "arn:aws:ec2:us-west-2:123456789012:instance/i-prod-server",
                    "name": "prod-server",
                    "resource_type": "aws_ec2_instance",
                    "region": "us-west-2",
                    "network_exposure": "public",
                    "match_score": 0.85,
                    "match_field": "name",
                },
            ]

            return HandlerResponse.success({
                "query": query,
                "items": results[offset:offset + limit],
                "total": len(results),
                "limit": limit,
                "offset": offset,
            })
        except Exception as e:
            logger.exception("Failed to search assets")
            return HandlerResponse.server_error(str(e))

    @route("filter")
    def assets_filter(self, params: dict, body: dict | None) -> HandlerResponse:
        """Filter assets with advanced criteria."""
        try:
            # Get filter parameters
            cloud_providers = self.get_param(params, "clouds", "")
            regions = self.get_param(params, "regions", "")
            types = self.get_param(params, "types", "")
            exposure = self.get_param(params, "exposure", "")
            has_findings = self.get_param(params, "has_findings", "")
            severity_min = self.get_param(params, "severity_min", "")

            filters_applied = []
            if cloud_providers:
                filters_applied.append(f"clouds={cloud_providers}")
            if regions:
                filters_applied.append(f"regions={regions}")
            if types:
                filters_applied.append(f"types={types}")
            if exposure:
                filters_applied.append(f"exposure={exposure}")
            if has_findings:
                filters_applied.append(f"has_findings={has_findings}")
            if severity_min:
                filters_applied.append(f"severity_min={severity_min}")

            # Demo filtered results
            results = [
                {
                    "id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                    "name": "web-server-01",
                    "resource_type": "aws_ec2_instance",
                    "region": "us-west-2",
                    "network_exposure": "public",
                    "cloud_provider": "aws",
                    "finding_count": 3,
                    "highest_severity": "CRITICAL",
                },
            ]

            return HandlerResponse.success({
                "items": results,
                "total": len(results),
                "filters_applied": filters_applied,
            })
        except Exception as e:
            logger.exception("Failed to filter assets")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Asset Grouping and Aggregation endpoints
    # =========================================================================

    @route("by-cloud")
    def assets_by_cloud(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get assets grouped by cloud provider."""
        try:
            include_counts = self.get_param(params, "include_counts", "true").lower() == "true"

            result = {
                "groups": [
                    {
                        "cloud_provider": "aws",
                        "asset_count": 45,
                        "finding_count": 120 if include_counts else None,
                        "critical_findings": 5 if include_counts else None,
                    },
                    {
                        "cloud_provider": "gcp",
                        "asset_count": 20,
                        "finding_count": 35 if include_counts else None,
                        "critical_findings": 2 if include_counts else None,
                    },
                    {
                        "cloud_provider": "azure",
                        "asset_count": 15,
                        "finding_count": 28 if include_counts else None,
                        "critical_findings": 1 if include_counts else None,
                    },
                ],
                "total_assets": 80,
            }

            # Remove None values if counts not requested
            if not include_counts:
                for group in result["groups"]:
                    group.pop("finding_count", None)
                    group.pop("critical_findings", None)

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to group assets by cloud")
            return HandlerResponse.server_error(str(e))

    @route("by-region")
    def assets_by_region(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get assets grouped by region."""
        try:
            cloud = self.get_param(params, "cloud", "")

            groups = [
                {
                    "region": "us-east-1",
                    "cloud_provider": "aws",
                    "asset_count": 25,
                    "finding_count": 65,
                },
                {
                    "region": "us-west-2",
                    "cloud_provider": "aws",
                    "asset_count": 20,
                    "finding_count": 55,
                },
                {
                    "region": "us-central1",
                    "cloud_provider": "gcp",
                    "asset_count": 15,
                    "finding_count": 25,
                },
                {
                    "region": "eastus",
                    "cloud_provider": "azure",
                    "asset_count": 10,
                    "finding_count": 18,
                },
                {
                    "region": "eu-west-1",
                    "cloud_provider": "aws",
                    "asset_count": 10,
                    "finding_count": 20,
                },
            ]

            if cloud:
                groups = [g for g in groups if g["cloud_provider"].lower() == cloud.lower()]

            return HandlerResponse.success({
                "groups": groups,
                "total_regions": len(groups),
            })
        except Exception as e:
            logger.exception("Failed to group assets by region")
            return HandlerResponse.server_error(str(e))

    @route("by-type")
    def assets_by_type(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get assets grouped by resource type."""
        try:
            cloud = self.get_param(params, "cloud", "")

            groups = [
                {
                    "resource_type": "aws_s3_bucket",
                    "cloud_provider": "aws",
                    "asset_count": 15,
                    "finding_count": 30,
                },
                {
                    "resource_type": "aws_ec2_instance",
                    "cloud_provider": "aws",
                    "asset_count": 20,
                    "finding_count": 45,
                },
                {
                    "resource_type": "aws_rds_instance",
                    "cloud_provider": "aws",
                    "asset_count": 10,
                    "finding_count": 25,
                },
                {
                    "resource_type": "gcp_storage_bucket",
                    "cloud_provider": "gcp",
                    "asset_count": 12,
                    "finding_count": 20,
                },
                {
                    "resource_type": "azure_vm",
                    "cloud_provider": "azure",
                    "asset_count": 8,
                    "finding_count": 15,
                },
            ]

            if cloud:
                groups = [g for g in groups if g["cloud_provider"].lower() == cloud.lower()]

            return HandlerResponse.success({
                "groups": groups,
                "total_types": len(groups),
            })
        except Exception as e:
            logger.exception("Failed to group assets by type")
            return HandlerResponse.server_error(str(e))

    @route("by-exposure")
    def assets_by_exposure(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get assets grouped by network exposure."""
        try:
            cloud = self.get_param(params, "cloud", "")

            groups = [
                {
                    "exposure": "public",
                    "asset_count": 25,
                    "finding_count": 80,
                    "critical_findings": 8,
                },
                {
                    "exposure": "private",
                    "asset_count": 45,
                    "finding_count": 60,
                    "critical_findings": 2,
                },
                {
                    "exposure": "internal",
                    "asset_count": 10,
                    "finding_count": 15,
                    "critical_findings": 0,
                },
            ]

            return HandlerResponse.success({
                "groups": groups,
                "total_assets": sum(g["asset_count"] for g in groups),
                "internet_facing_percentage": 31.25,
            })
        except Exception as e:
            logger.exception("Failed to group assets by exposure")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Asset Inventory and Metadata endpoints
    # =========================================================================

    @route("inventory")
    def assets_inventory(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get full asset inventory summary."""
        try:
            result = {
                "summary": {
                    "total_assets": 80,
                    "total_findings": 183,
                    "assets_with_findings": 65,
                    "assets_without_findings": 15,
                    "critical_assets": 12,
                    "internet_facing_assets": 25,
                },
                "by_cloud": {
                    "aws": {"assets": 45, "findings": 120},
                    "gcp": {"assets": 20, "findings": 35},
                    "azure": {"assets": 15, "findings": 28},
                },
                "by_severity": {
                    "critical": 12,
                    "high": 35,
                    "medium": 85,
                    "low": 51,
                },
                "top_resource_types": [
                    {"type": "aws_ec2_instance", "count": 20},
                    {"type": "aws_s3_bucket", "count": 15},
                    {"type": "gcp_storage_bucket", "count": 12},
                    {"type": "aws_rds_instance", "count": 10},
                    {"type": "azure_vm", "count": 8},
                ],
                "last_scan": "2024-12-30T10:00:00Z",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get asset inventory")
            return HandlerResponse.server_error(str(e))

    @route("types")
    def assets_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available asset types."""
        try:
            cloud = self.get_param(params, "cloud", "")

            types = [
                {"type": "aws_s3_bucket", "cloud": "aws", "display_name": "S3 Bucket"},
                {"type": "aws_ec2_instance", "cloud": "aws", "display_name": "EC2 Instance"},
                {"type": "aws_rds_instance", "cloud": "aws", "display_name": "RDS Instance"},
                {"type": "aws_lambda_function", "cloud": "aws", "display_name": "Lambda Function"},
                {"type": "aws_iam_role", "cloud": "aws", "display_name": "IAM Role"},
                {"type": "aws_iam_user", "cloud": "aws", "display_name": "IAM User"},
                {"type": "aws_security_group", "cloud": "aws", "display_name": "Security Group"},
                {"type": "gcp_storage_bucket", "cloud": "gcp", "display_name": "Cloud Storage Bucket"},
                {"type": "gcp_compute_instance", "cloud": "gcp", "display_name": "Compute Engine Instance"},
                {"type": "gcp_sql_instance", "cloud": "gcp", "display_name": "Cloud SQL Instance"},
                {"type": "azure_vm", "cloud": "azure", "display_name": "Virtual Machine"},
                {"type": "azure_storage_account", "cloud": "azure", "display_name": "Storage Account"},
                {"type": "azure_sql_database", "cloud": "azure", "display_name": "SQL Database"},
            ]

            if cloud:
                types = [t for t in types if t["cloud"].lower() == cloud.lower()]

            return HandlerResponse.success({
                "types": types,
                "total": len(types),
            })
        except Exception as e:
            logger.exception("Failed to get asset types")
            return HandlerResponse.server_error(str(e))

    @route("regions")
    def assets_regions(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available regions for assets."""
        try:
            cloud = self.get_param(params, "cloud", "")

            regions = [
                {"region": "us-east-1", "cloud": "aws", "display_name": "US East (N. Virginia)"},
                {"region": "us-west-2", "cloud": "aws", "display_name": "US West (Oregon)"},
                {"region": "eu-west-1", "cloud": "aws", "display_name": "EU (Ireland)"},
                {"region": "ap-southeast-1", "cloud": "aws", "display_name": "Asia Pacific (Singapore)"},
                {"region": "us-central1", "cloud": "gcp", "display_name": "Iowa"},
                {"region": "us-east4", "cloud": "gcp", "display_name": "Northern Virginia"},
                {"region": "europe-west1", "cloud": "gcp", "display_name": "Belgium"},
                {"region": "eastus", "cloud": "azure", "display_name": "East US"},
                {"region": "westus2", "cloud": "azure", "display_name": "West US 2"},
                {"region": "westeurope", "cloud": "azure", "display_name": "West Europe"},
            ]

            if cloud:
                regions = [r for r in regions if r["cloud"].lower() == cloud.lower()]

            return HandlerResponse.success({
                "regions": regions,
                "total": len(regions),
            })
        except Exception as e:
            logger.exception("Failed to get asset regions")
            return HandlerResponse.server_error(str(e))

    @route("clouds")
    def assets_clouds(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available cloud providers."""
        try:
            result = {
                "clouds": [
                    {
                        "id": "aws",
                        "name": "Amazon Web Services",
                        "asset_count": 45,
                        "enabled": True,
                    },
                    {
                        "id": "gcp",
                        "name": "Google Cloud Platform",
                        "asset_count": 20,
                        "enabled": True,
                    },
                    {
                        "id": "azure",
                        "name": "Microsoft Azure",
                        "asset_count": 15,
                        "enabled": True,
                    },
                ],
                "total": 3,
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get cloud providers")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Asset Enrichment endpoints
    # =========================================================================

    @route("enrich", methods=["POST"])
    def assets_enrich(self, params: dict, body: dict | None) -> HandlerResponse:
        """Enrich assets with additional context."""
        try:
            body = body or {}
            asset_id = body.get("asset_id") or self.get_param(params, "asset_id", "")
            enrichment_types = body.get("types") or self.get_param(params, "types", "ip,geo,cloud,context")
            cloud_filter = body.get("cloud") or self.get_param(params, "cloud", "")
            limit = self.get_param_int(params, "limit", 50)

            types_list = [t.strip().lower() for t in enrichment_types.split(",")]

            # Demo enrichment result
            result = {
                "total_assets": 5 if not asset_id else 1,
                "assets_enriched": 5 if not asset_id else 1,
                "enrichment_types": types_list,
                "assets": [
                    {
                        "id": asset_id if asset_id else "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                        "name": "web-server-01",
                        "enrichments": {
                            "ip": {
                                "public_ip": "54.123.45.67",
                                "private_ip": "10.0.1.25",
                                "ip_version": "ipv4",
                            } if "ip" in types_list else None,
                            "geo": {
                                "country": "United States",
                                "city": "Ashburn",
                                "latitude": 39.0437,
                                "longitude": -77.4875,
                            } if "geo" in types_list else None,
                            "cloud": {
                                "provider": "aws",
                                "service": "ec2",
                                "resource_category": "compute",
                            } if "cloud" in types_list else None,
                            "context": {
                                "business_criticality": "high",
                                "data_classification": "confidential",
                                "owner_team": "platform",
                            } if "context" in types_list else None,
                        },
                        "enrichment_timestamp": "2024-12-30T10:00:00Z",
                    },
                ],
                "statistics": {
                    "ip_enriched": 5 if "ip" in types_list else 0,
                    "geo_enriched": 4 if "geo" in types_list else 0,
                    "cloud_enriched": 5 if "cloud" in types_list else 0,
                    "context_enriched": 3 if "context" in types_list else 0,
                },
            }

            # Clean up None enrichments
            for asset in result["assets"]:
                asset["enrichments"] = {k: v for k, v in asset["enrichments"].items() if v is not None}

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to enrich assets")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Asset Risk endpoints
    # =========================================================================

    @route("risk")
    def assets_risk(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get asset risk scores."""
        try:
            asset_id = self.get_param(params, "asset_id", "")
            limit = self.get_param_int(params, "limit", 50)
            sort_by = self.get_param(params, "sort_by", "risk_score")
            order = self.get_param(params, "order", "desc")

            # Demo risk scores
            risk_data = [
                {
                    "asset_id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                    "name": "web-server-01",
                    "risk_score": 85,
                    "risk_level": "CRITICAL",
                    "factors": {
                        "exposure": 25,
                        "vulnerabilities": 30,
                        "misconfigurations": 20,
                        "data_sensitivity": 10,
                    },
                },
                {
                    "asset_id": "arn:aws:s3:::production-data",
                    "name": "production-data",
                    "risk_score": 72,
                    "risk_level": "HIGH",
                    "factors": {
                        "exposure": 15,
                        "vulnerabilities": 0,
                        "misconfigurations": 35,
                        "data_sensitivity": 22,
                    },
                },
                {
                    "asset_id": "arn:aws:rds:us-east-1:123456789012:db:prod-db",
                    "name": "prod-db",
                    "risk_score": 45,
                    "risk_level": "MEDIUM",
                    "factors": {
                        "exposure": 0,
                        "vulnerabilities": 15,
                        "misconfigurations": 20,
                        "data_sensitivity": 10,
                    },
                },
            ]

            if asset_id:
                risk_data = [r for r in risk_data if r["asset_id"] == asset_id or asset_id in r["asset_id"]]

            # Sort
            reverse = order.lower() == "desc"
            if sort_by in ["risk_score", "name"]:
                risk_data.sort(key=lambda x: x.get(sort_by, 0), reverse=reverse)

            return HandlerResponse.success({
                "items": risk_data[:limit],
                "total": len(risk_data),
            })
        except Exception as e:
            logger.exception("Failed to get asset risk scores")
            return HandlerResponse.server_error(str(e))

    @route("risk-summary")
    def assets_risk_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get asset risk summary."""
        try:
            result = {
                "summary": {
                    "total_assets": 80,
                    "average_risk_score": 42.5,
                    "median_risk_score": 38,
                    "highest_risk_score": 92,
                },
                "by_risk_level": {
                    "critical": 5,
                    "high": 12,
                    "medium": 28,
                    "low": 35,
                },
                "top_risk_factors": [
                    {"factor": "misconfigurations", "contribution": 35},
                    {"factor": "vulnerabilities", "contribution": 30},
                    {"factor": "exposure", "contribution": 20},
                    {"factor": "data_sensitivity", "contribution": 15},
                ],
                "trend": {
                    "direction": "improving",
                    "change_7d": -5.2,
                    "change_30d": -12.8,
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get risk summary")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Asset Statistics endpoints
    # =========================================================================

    @route("stats")
    def assets_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get asset statistics."""
        try:
            cloud = self.get_param(params, "cloud", "")

            result = {
                "total_assets": 80,
                "by_cloud": {
                    "aws": 45,
                    "gcp": 20,
                    "azure": 15,
                },
                "by_exposure": {
                    "public": 25,
                    "private": 45,
                    "internal": 10,
                },
                "by_finding_status": {
                    "with_critical": 12,
                    "with_high": 25,
                    "with_findings": 65,
                    "clean": 15,
                },
                "new_assets_7d": 5,
                "removed_assets_7d": 2,
                "last_updated": "2024-12-30T10:00:00Z",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get asset stats")
            return HandlerResponse.server_error(str(e))

    @route("trends")
    def assets_trends(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get asset trend data over time."""
        try:
            period = self.get_param(params, "period", "30d")
            metric = self.get_param(params, "metric", "count")

            result = {
                "period": period,
                "metric": metric,
                "data_points": [
                    {"date": "2024-12-01", "value": 72},
                    {"date": "2024-12-07", "value": 74},
                    {"date": "2024-12-14", "value": 76},
                    {"date": "2024-12-21", "value": 78},
                    {"date": "2024-12-28", "value": 80},
                ],
                "change": {
                    "absolute": 8,
                    "percentage": 11.1,
                    "direction": "increasing",
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get asset trends")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Asset Sample Data endpoints
    # =========================================================================

    @route("sample")
    def assets_sample(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get sample assets for demo/testing."""
        try:
            result = {
                "assets": [
                    {
                        "id": "arn:aws:s3:::production-data",
                        "cloud_provider": "aws",
                        "account_id": "123456789012",
                        "region": "us-east-1",
                        "resource_type": "aws_s3_bucket",
                        "name": "production-data",
                        "tags": '{"Environment": "production"}',
                        "network_exposure": "private",
                    },
                    {
                        "id": "arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0",
                        "cloud_provider": "aws",
                        "account_id": "123456789012",
                        "region": "us-west-2",
                        "resource_type": "aws_ec2_instance",
                        "name": "web-server-01",
                        "tags": '{"Environment": "production", "Role": "web"}',
                        "network_exposure": "public",
                    },
                    {
                        "id": "//storage.googleapis.com/projects/my-gcp-project/buckets/analytics",
                        "cloud_provider": "gcp",
                        "account_id": "my-gcp-project",
                        "region": "us-central1",
                        "resource_type": "gcp_storage_bucket",
                        "name": "analytics",
                        "tags": '{"team": "analytics"}',
                        "network_exposure": "private",
                    },
                ],
                "total": 3,
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get sample assets")
            return HandlerResponse.server_error(str(e))
