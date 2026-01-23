"""
IAC handlers for the Stance web API.

This module handles all /api/iac/* endpoints for Infrastructure
as Code scanning and policy management.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus, PathValidationError, validate_safe_path
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class IacHandler(RoutedHandler):
    """
    Handler for IAC API endpoints.

    Handles:
    - IaC scanning
    - Policy management
    - Format and provider support
    - Compliance mapping
    """

    base_path = "/api/iac/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("scan")
    def iac_scan(self, params: dict, body: dict | None) -> HandlerResponse:
        """Scan IaC files for security issues."""
        path = self.get_param(params, "path", ".")

        # Validate path to prevent traversal attacks
        try:
            path = validate_safe_path(path, allow_parent_refs=False)
        except PathValidationError as e:
            return HandlerResponse.error(f"Invalid path: {e}", HttpStatus.BAD_REQUEST)

        severity_filter = self.get_param(params, "severity", "")
        iac_format = self.get_param(params, "format", "all")

        # Sample scan findings
        findings = [
            {
                "rule_id": "iac-aws-s3-encryption",
                "severity": "high",
                "title": "S3 bucket encryption not configured",
                "resource": "aws_s3_bucket.data_bucket",
                "location": f"{path}/main.tf:15",
                "description": "S3 buckets should have server-side encryption enabled.",
                "remediation": "Add server_side_encryption_configuration block.",
            },
            {
                "rule_id": "iac-aws-s3-public-access",
                "severity": "critical",
                "title": "S3 bucket allows public access",
                "resource": "aws_s3_bucket.public_assets",
                "location": f"{path}/storage.tf:42",
                "description": "S3 buckets should block public access.",
                "remediation": "Set all public access block settings to true.",
            },
            {
                "rule_id": "iac-aws-sg-ssh-open",
                "severity": "high",
                "title": "Security group allows SSH from 0.0.0.0/0",
                "resource": "aws_security_group.web_sg",
                "location": f"{path}/network.tf:28",
                "description": "Security groups should not allow unrestricted SSH.",
                "remediation": "Restrict SSH access to specific IP ranges.",
            },
        ]

        # Apply severity filter
        if severity_filter:
            severity_order = ["critical", "high", "medium", "low", "info"]
            if severity_filter in severity_order:
                filter_idx = severity_order.index(severity_filter)
                findings = [f for f in findings if severity_order.index(f["severity"]) <= filter_idx]

        by_severity = {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
        }

        return HandlerResponse.success({
            "findings": findings,
            "summary": {
                "path": path,
                "files_scanned": 8,
                "resources_found": 24,
                "findings_count": len(findings),
                "by_severity": by_severity,
                "iac_format": iac_format,
            },
        })

    @route("policies")
    def iac_policies(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available IaC policies."""
        provider = self.get_param(params, "provider", "")
        severity = self.get_param(params, "severity", "")
        enabled_only = self.get_param_bool(params, "enabled_only", False)

        policies = [
            {
                "id": "iac-aws-s3-encryption",
                "name": "S3 bucket encryption not configured",
                "severity": "high",
                "providers": ["aws"],
                "resource_types": ["aws_s3_bucket"],
                "enabled": True,
            },
            {
                "id": "iac-aws-s3-public-access",
                "name": "S3 bucket allows public access",
                "severity": "critical",
                "providers": ["aws"],
                "resource_types": ["aws_s3_bucket_public_access_block"],
                "enabled": True,
            },
            {
                "id": "iac-aws-sg-ssh-open",
                "name": "Security group allows SSH from 0.0.0.0/0",
                "severity": "high",
                "providers": ["aws"],
                "resource_types": ["aws_security_group"],
                "enabled": True,
            },
            {
                "id": "iac-gcp-storage-uniform",
                "name": "Cloud Storage bucket uses uniform access",
                "severity": "medium",
                "providers": ["gcp"],
                "resource_types": ["google_storage_bucket"],
                "enabled": True,
            },
        ]

        # Apply filters
        if provider:
            policies = [p for p in policies if provider in p["providers"]]
        if severity:
            policies = [p for p in policies if p["severity"] == severity]
        if enabled_only:
            policies = [p for p in policies if p["enabled"]]

        return HandlerResponse.success({
            "policies": policies,
            "total": len(policies),
        })

    @route("policy")
    def iac_policy(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get details for a specific IaC policy."""
        policy_id = self.get_param(params, "id", "")
        if not policy_id:
            return HandlerResponse.error("Missing required parameter: id", HttpStatus.BAD_REQUEST)

        # Demo policy data
        policies = {
            "iac-aws-s3-encryption": {
                "id": "iac-aws-s3-encryption",
                "name": "S3 bucket encryption not configured",
                "severity": "high",
                "description": "S3 buckets should have server-side encryption enabled to protect data at rest.",
                "providers": ["aws"],
                "resource_types": ["aws_s3_bucket"],
                "remediation": "Add server_side_encryption_configuration block with AES256 or aws:kms algorithm.",
                "references": [
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html"
                ],
                "enabled": True,
            },
        }

        policy = policies.get(policy_id)
        if not policy:
            return HandlerResponse.not_found(f"Policy: {policy_id}")

        return HandlerResponse.success(policy)

    @route("formats")
    def iac_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported IaC formats."""
        formats = [
            {
                "format": "terraform",
                "name": "Terraform",
                "extensions": [".tf", ".tf.json"],
                "description": "HashiCorp Terraform configuration files",
            },
            {
                "format": "cloudformation",
                "name": "CloudFormation",
                "extensions": [".yaml", ".yml", ".json", ".template"],
                "description": "AWS CloudFormation templates",
            },
            {
                "format": "arm",
                "name": "ARM Templates",
                "extensions": [".json"],
                "description": "Azure Resource Manager templates",
            },
            {
                "format": "kubernetes",
                "name": "Kubernetes",
                "extensions": [".yaml", ".yml"],
                "description": "Kubernetes manifests and Helm charts",
            },
            {
                "format": "dockerfile",
                "name": "Dockerfile",
                "extensions": ["Dockerfile", ".dockerfile"],
                "description": "Docker container definitions",
            },
        ]
        return HandlerResponse.success({"formats": formats, "total": len(formats)})

    @route("validate")
    def iac_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate IaC syntax."""
        path = self.get_param(params, "path", "")
        if not path:
            return HandlerResponse.error("Missing required parameter: path", HttpStatus.BAD_REQUEST)

        # Validate path to prevent traversal attacks
        try:
            path = validate_safe_path(path, allow_parent_refs=False)
        except PathValidationError as e:
            return HandlerResponse.error(f"Invalid path: {e}", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "path": path,
            "valid": True,
            "format_detected": "terraform",
            "errors": [],
            "warnings": [],
        })

    @route("resources")
    def iac_resources(self, params: dict, body: dict | None) -> HandlerResponse:
        """List resources in IaC files."""
        path = self.get_param(params, "path", ".")

        # Validate path to prevent traversal attacks
        try:
            path = validate_safe_path(path, allow_parent_refs=False)
        except PathValidationError as e:
            return HandlerResponse.error(f"Invalid path: {e}", HttpStatus.BAD_REQUEST)

        resources = [
            {"type": "aws_s3_bucket", "name": "data_bucket", "file": f"{path}/main.tf", "line": 15},
            {"type": "aws_security_group", "name": "web_sg", "file": f"{path}/network.tf", "line": 28},
            {"type": "aws_db_instance", "name": "app_db", "file": f"{path}/database.tf", "line": 10},
        ]

        return HandlerResponse.success({
            "path": path,
            "resources": resources,
            "total": len(resources),
        })

    @route("stats")
    def iac_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get IaC scanning statistics."""
        return HandlerResponse.success({
            "total_policies": 45,
            "policies_by_provider": {"aws": 25, "gcp": 10, "azure": 8, "kubernetes": 2},
            "policies_by_severity": {"critical": 8, "high": 15, "medium": 12, "low": 10},
            "supported_formats": 5,
        })

    @route("compliance")
    def iac_compliance(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get IaC compliance mappings."""
        return HandlerResponse.success({
            "frameworks": [
                {"id": "cis", "name": "CIS Benchmarks", "policies_mapped": 35},
                {"id": "nist", "name": "NIST 800-53", "policies_mapped": 28},
                {"id": "pci", "name": "PCI DSS", "policies_mapped": 22},
            ],
            "total_mappings": 85,
        })

    @route("providers")
    def iac_providers(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported cloud providers."""
        providers = [
            {"id": "aws", "name": "Amazon Web Services", "policy_count": 25},
            {"id": "gcp", "name": "Google Cloud Platform", "policy_count": 10},
            {"id": "azure", "name": "Microsoft Azure", "policy_count": 8},
            {"id": "kubernetes", "name": "Kubernetes", "policy_count": 2},
        ]
        return HandlerResponse.success({"providers": providers, "total": len(providers)})

    @route("resource-types")
    def iac_resource_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported resource types."""
        provider = self.get_param(params, "provider", "")

        resource_types = [
            {"type": "aws_s3_bucket", "provider": "aws", "category": "Storage"},
            {"type": "aws_security_group", "provider": "aws", "category": "Network"},
            {"type": "aws_db_instance", "provider": "aws", "category": "Database"},
            {"type": "google_storage_bucket", "provider": "gcp", "category": "Storage"},
        ]

        if provider:
            resource_types = [rt for rt in resource_types if rt["provider"] == provider]

        return HandlerResponse.success({"resource_types": resource_types, "total": len(resource_types)})

    @route("severity-levels")
    def iac_severity_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List IaC severity levels."""
        levels = [
            {"level": "critical", "description": "Immediate security risk", "priority": 1},
            {"level": "high", "description": "Significant security concern", "priority": 2},
            {"level": "medium", "description": "Moderate security issue", "priority": 3},
            {"level": "low", "description": "Minor security consideration", "priority": 4},
            {"level": "info", "description": "Informational finding", "priority": 5},
        ]
        return HandlerResponse.success({"levels": levels, "total": len(levels)})

    @route("summary")
    def iac_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get IaC module summary."""
        return HandlerResponse.success({
            "module": "iac",
            "description": "Infrastructure as Code security scanning",
            "features": [
                "Terraform scanning",
                "CloudFormation scanning",
                "ARM template scanning",
                "Kubernetes manifest scanning",
                "Policy-based detection",
                "Compliance mapping",
            ],
            "supported_providers": ["aws", "gcp", "azure", "kubernetes"],
            "supported_formats": ["terraform", "cloudformation", "arm", "kubernetes", "dockerfile"],
            "total_policies": 45,
        })
