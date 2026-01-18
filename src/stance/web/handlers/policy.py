"""
Policy management handlers for the Stance web API.

This module handles all /api/policy/* endpoints for policy operations
including listing, filtering, details, validation, creation, and
management of security policies.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class PolicyHandler(RoutedHandler):
    """
    Handler for policy management API endpoints.

    Handles:
    - Policy listing and filtering
    - Policy details and validation
    - Policy creation and management
    - Policy suggestions and generation
    - Policy categories and severity levels
    - Policy enable/disable operations
    """

    base_path = "/api/policy/"

    # =========================================================================
    # Policy Listing GET endpoints
    # =========================================================================

    @route("list")
    def policy_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all policies with optional filtering."""
        try:
            provider = self.get_param(params, "provider", "")
            severity = self.get_param(params, "severity", "")
            enabled_only = self.get_param(params, "enabled_only", "").lower() == "true"
            resource_type = self.get_param(params, "resource_type", "")
            framework = self.get_param(params, "framework", "")
            limit = self.get_param_int(params, "limit", 50)
            offset = self.get_param_int(params, "offset", 0)

            # Demo policies data
            policies = [
                {
                    "id": "aws-s3-encryption",
                    "name": "S3 Bucket Encryption Required",
                    "description": "Ensure all S3 buckets have encryption enabled",
                    "severity": "high",
                    "provider": "aws",
                    "resource_type": "aws_s3_bucket",
                    "enabled": True,
                    "frameworks": ["CIS AWS", "PCI-DSS"],
                    "category": "encryption",
                    "tags": ["security", "encryption", "s3"],
                },
                {
                    "id": "aws-s3-public-access",
                    "name": "S3 Bucket Public Access Blocked",
                    "description": "Ensure S3 buckets block public access",
                    "severity": "critical",
                    "provider": "aws",
                    "resource_type": "aws_s3_bucket",
                    "enabled": True,
                    "frameworks": ["CIS AWS", "PCI-DSS", "SOC2"],
                    "category": "access-control",
                    "tags": ["security", "public-access", "s3"],
                },
                {
                    "id": "aws-iam-mfa",
                    "name": "IAM User MFA Required",
                    "description": "Ensure all IAM users have MFA enabled",
                    "severity": "critical",
                    "provider": "aws",
                    "resource_type": "aws_iam_user",
                    "enabled": True,
                    "frameworks": ["CIS AWS", "SOC2"],
                    "category": "authentication",
                    "tags": ["security", "iam", "mfa"],
                },
                {
                    "id": "aws-ec2-public-ip",
                    "name": "EC2 No Public IP",
                    "description": "EC2 instances should not have public IPs unless required",
                    "severity": "medium",
                    "provider": "aws",
                    "resource_type": "aws_ec2_instance",
                    "enabled": True,
                    "frameworks": ["CIS AWS"],
                    "category": "network",
                    "tags": ["network", "ec2"],
                },
                {
                    "id": "aws-sg-ssh-open",
                    "name": "Security Group SSH Restricted",
                    "description": "Security groups should not allow SSH from 0.0.0.0/0",
                    "severity": "high",
                    "provider": "aws",
                    "resource_type": "aws_security_group",
                    "enabled": True,
                    "frameworks": ["CIS AWS", "PCI-DSS"],
                    "category": "network",
                    "tags": ["network", "security-group", "ssh"],
                },
                {
                    "id": "gcp-storage-public",
                    "name": "GCS Bucket No Public Access",
                    "description": "Ensure GCS buckets are not publicly accessible",
                    "severity": "critical",
                    "provider": "gcp",
                    "resource_type": "gcp_storage_bucket",
                    "enabled": True,
                    "frameworks": ["CIS GCP"],
                    "category": "access-control",
                    "tags": ["security", "storage", "gcp"],
                },
                {
                    "id": "azure-storage-https",
                    "name": "Storage Account HTTPS Only",
                    "description": "Ensure storage accounts enforce HTTPS",
                    "severity": "high",
                    "provider": "azure",
                    "resource_type": "azure_storage_account",
                    "enabled": True,
                    "frameworks": ["CIS Azure"],
                    "category": "encryption",
                    "tags": ["security", "storage", "azure", "https"],
                },
                {
                    "id": "azure-sql-encryption",
                    "name": "Azure SQL TDE Enabled",
                    "description": "Ensure Azure SQL databases have TDE enabled",
                    "severity": "high",
                    "provider": "azure",
                    "resource_type": "azure_sql_database",
                    "enabled": False,
                    "frameworks": ["CIS Azure"],
                    "category": "encryption",
                    "tags": ["security", "encryption", "azure", "sql"],
                },
                {
                    "id": "k8s-privileged-container",
                    "name": "No Privileged Containers",
                    "description": "Containers should not run as privileged",
                    "severity": "critical",
                    "provider": "kubernetes",
                    "resource_type": "kubernetes_deployment",
                    "enabled": True,
                    "frameworks": ["CIS Kubernetes"],
                    "category": "container-security",
                    "tags": ["security", "kubernetes", "container"],
                },
            ]

            # Apply filters
            if provider:
                policies = [p for p in policies if p["provider"] == provider]
            if severity:
                policies = [p for p in policies if p["severity"] == severity.lower()]
            if enabled_only:
                policies = [p for p in policies if p["enabled"]]
            if resource_type:
                policies = [p for p in policies if p["resource_type"] == resource_type]
            if framework:
                policies = [p for p in policies if any(framework.lower() in f.lower() for f in p["frameworks"])]

            total = len(policies)
            policies = policies[offset:offset + limit]

            return HandlerResponse.success({
                "policies": policies,
                "total": total,
                "enabled_count": sum(1 for p in policies if p["enabled"]),
                "limit": limit,
                "offset": offset,
            })
        except Exception as e:
            logger.exception("Failed to list policies")
            return HandlerResponse.server_error(str(e))

    @route("show")
    def policy_show(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get detailed information for a specific policy."""
        try:
            policy_id = self.get_param(params, "policy_id", "")

            if not policy_id:
                return HandlerResponse.error("policy_id parameter required", HttpStatus.BAD_REQUEST)

            # Demo policy details
            result = {
                "id": policy_id,
                "name": "S3 Bucket Encryption Required",
                "description": "Ensure all S3 buckets have server-side encryption enabled to protect data at rest.",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_s3_bucket",
                "enabled": True,
                "frameworks": ["CIS AWS", "PCI-DSS"],
                "category": "encryption",
                "tags": ["security", "encryption", "s3"],
                "check": {
                    "type": "expression",
                    "expression": "resource.encryption.enabled == true",
                },
                "compliance": [
                    {"framework": "CIS AWS", "version": "2.0", "control": "2.1.1"},
                    {"framework": "PCI-DSS", "version": "4.0", "control": "3.4"},
                ],
                "remediation": {
                    "guidance": "Enable server-side encryption on the S3 bucket using AWS managed keys (SSE-S3) or customer managed keys (SSE-KMS).",
                    "automation_supported": True,
                    "steps": [
                        "Navigate to S3 console",
                        "Select the bucket",
                        "Go to Properties > Default encryption",
                        "Enable server-side encryption",
                    ],
                },
                "metadata": {
                    "created_at": "2024-01-15T10:00:00Z",
                    "updated_at": "2024-12-01T10:00:00Z",
                    "author": "stance-team",
                    "version": "1.2.0",
                },
                "statistics": {
                    "total_evaluated": 45,
                    "compliant": 40,
                    "non_compliant": 5,
                    "compliance_rate": 88.9,
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get policy details")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Policy Categories and Metadata endpoints
    # =========================================================================

    @route("categories")
    def policy_categories(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available policy categories."""
        try:
            categories = [
                {
                    "id": "encryption",
                    "name": "Encryption",
                    "description": "Policies related to data encryption at rest and in transit",
                    "policy_count": 15,
                },
                {
                    "id": "access-control",
                    "name": "Access Control",
                    "description": "Policies related to access management and authorization",
                    "policy_count": 25,
                },
                {
                    "id": "authentication",
                    "name": "Authentication",
                    "description": "Policies related to identity and authentication",
                    "policy_count": 12,
                },
                {
                    "id": "network",
                    "name": "Network Security",
                    "description": "Policies related to network configuration and security",
                    "policy_count": 20,
                },
                {
                    "id": "logging",
                    "name": "Logging & Monitoring",
                    "description": "Policies related to audit logging and monitoring",
                    "policy_count": 18,
                },
                {
                    "id": "container-security",
                    "name": "Container Security",
                    "description": "Policies related to container and Kubernetes security",
                    "policy_count": 10,
                },
                {
                    "id": "data-protection",
                    "name": "Data Protection",
                    "description": "Policies related to data privacy and protection",
                    "policy_count": 8,
                },
            ]

            return HandlerResponse.success({
                "categories": categories,
                "total": len(categories),
            })
        except Exception as e:
            logger.exception("Failed to get policy categories")
            return HandlerResponse.server_error(str(e))

    @route("severities")
    def policy_severities(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available severity levels."""
        try:
            severities = [
                {
                    "id": "critical",
                    "name": "Critical",
                    "priority": 1,
                    "description": "Immediate security risk requiring urgent action",
                    "color": "#dc2626",
                    "policy_count": 15,
                },
                {
                    "id": "high",
                    "name": "High",
                    "priority": 2,
                    "description": "Significant security risk requiring prompt attention",
                    "color": "#ea580c",
                    "policy_count": 25,
                },
                {
                    "id": "medium",
                    "name": "Medium",
                    "priority": 3,
                    "description": "Moderate security risk to be addressed in due course",
                    "color": "#ca8a04",
                    "policy_count": 30,
                },
                {
                    "id": "low",
                    "name": "Low",
                    "priority": 4,
                    "description": "Minor security consideration or best practice",
                    "color": "#2563eb",
                    "policy_count": 20,
                },
                {
                    "id": "info",
                    "name": "Informational",
                    "priority": 5,
                    "description": "Security recommendation or awareness item",
                    "color": "#6b7280",
                    "policy_count": 10,
                },
            ]

            return HandlerResponse.success({
                "severities": severities,
                "total": len(severities),
            })
        except Exception as e:
            logger.exception("Failed to get severity levels")
            return HandlerResponse.server_error(str(e))

    @route("providers")
    def policy_providers(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available cloud providers for policies."""
        try:
            providers = [
                {
                    "id": "aws",
                    "name": "Amazon Web Services",
                    "resource_prefix": "aws_",
                    "policy_count": 45,
                    "resource_types": 25,
                },
                {
                    "id": "gcp",
                    "name": "Google Cloud Platform",
                    "resource_prefix": "gcp_",
                    "policy_count": 20,
                    "resource_types": 15,
                },
                {
                    "id": "azure",
                    "name": "Microsoft Azure",
                    "resource_prefix": "azure_",
                    "policy_count": 18,
                    "resource_types": 12,
                },
                {
                    "id": "kubernetes",
                    "name": "Kubernetes",
                    "resource_prefix": "kubernetes_",
                    "policy_count": 12,
                    "resource_types": 8,
                },
            ]

            return HandlerResponse.success({
                "providers": providers,
                "total": len(providers),
            })
        except Exception as e:
            logger.exception("Failed to get policy providers")
            return HandlerResponse.server_error(str(e))

    @route("resource-types")
    def policy_resource_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available resource types for policies."""
        try:
            provider = self.get_param(params, "provider", "")

            resource_types = [
                {"type": "aws_s3_bucket", "provider": "aws", "name": "S3 Bucket", "policy_count": 8},
                {"type": "aws_iam_user", "provider": "aws", "name": "IAM User", "policy_count": 6},
                {"type": "aws_iam_role", "provider": "aws", "name": "IAM Role", "policy_count": 5},
                {"type": "aws_ec2_instance", "provider": "aws", "name": "EC2 Instance", "policy_count": 7},
                {"type": "aws_security_group", "provider": "aws", "name": "Security Group", "policy_count": 5},
                {"type": "aws_rds_instance", "provider": "aws", "name": "RDS Instance", "policy_count": 4},
                {"type": "aws_lambda_function", "provider": "aws", "name": "Lambda Function", "policy_count": 3},
                {"type": "gcp_storage_bucket", "provider": "gcp", "name": "Cloud Storage Bucket", "policy_count": 5},
                {"type": "gcp_compute_instance", "provider": "gcp", "name": "Compute Instance", "policy_count": 4},
                {"type": "azure_storage_account", "provider": "azure", "name": "Storage Account", "policy_count": 4},
                {"type": "azure_sql_database", "provider": "azure", "name": "SQL Database", "policy_count": 3},
                {"type": "kubernetes_deployment", "provider": "kubernetes", "name": "Deployment", "policy_count": 5},
                {"type": "kubernetes_pod", "provider": "kubernetes", "name": "Pod", "policy_count": 4},
            ]

            if provider:
                resource_types = [rt for rt in resource_types if rt["provider"] == provider]

            return HandlerResponse.success({
                "resource_types": resource_types,
                "total": len(resource_types),
            })
        except Exception as e:
            logger.exception("Failed to get resource types")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Policy Search and Filter endpoints
    # =========================================================================

    @route("search")
    def policy_search(self, params: dict, body: dict | None) -> HandlerResponse:
        """Search policies by query string."""
        try:
            query = self.get_param(params, "q", "")
            limit = self.get_param_int(params, "limit", 20)

            if not query:
                return HandlerResponse.error("q (query) parameter required", HttpStatus.BAD_REQUEST)

            # Demo search results
            results = [
                {
                    "id": "aws-s3-encryption",
                    "name": "S3 Bucket Encryption Required",
                    "severity": "high",
                    "provider": "aws",
                    "match_score": 0.95,
                    "match_field": "name",
                },
                {
                    "id": "azure-storage-https",
                    "name": "Storage Account HTTPS Only",
                    "severity": "high",
                    "provider": "azure",
                    "match_score": 0.75,
                    "match_field": "description",
                },
            ]

            return HandlerResponse.success({
                "query": query,
                "results": results[:limit],
                "total": len(results),
            })
        except Exception as e:
            logger.exception("Failed to search policies")
            return HandlerResponse.server_error(str(e))

    @route("by-framework")
    def policy_by_framework(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policies grouped by compliance framework."""
        try:
            frameworks = [
                {
                    "framework": "CIS AWS",
                    "version": "2.0",
                    "policy_count": 45,
                    "enabled_count": 42,
                    "top_policies": [
                        {"id": "aws-s3-encryption", "name": "S3 Bucket Encryption Required", "severity": "high"},
                        {"id": "aws-iam-mfa", "name": "IAM User MFA Required", "severity": "critical"},
                    ],
                },
                {
                    "framework": "CIS GCP",
                    "version": "2.0",
                    "policy_count": 20,
                    "enabled_count": 18,
                    "top_policies": [
                        {"id": "gcp-storage-public", "name": "GCS Bucket No Public Access", "severity": "critical"},
                    ],
                },
                {
                    "framework": "CIS Azure",
                    "version": "2.0",
                    "policy_count": 18,
                    "enabled_count": 16,
                    "top_policies": [
                        {"id": "azure-storage-https", "name": "Storage Account HTTPS Only", "severity": "high"},
                    ],
                },
                {
                    "framework": "PCI-DSS",
                    "version": "4.0",
                    "policy_count": 25,
                    "enabled_count": 25,
                    "top_policies": [
                        {"id": "aws-s3-encryption", "name": "S3 Bucket Encryption Required", "severity": "high"},
                    ],
                },
                {
                    "framework": "SOC2",
                    "version": "2017",
                    "policy_count": 15,
                    "enabled_count": 15,
                    "top_policies": [
                        {"id": "aws-iam-mfa", "name": "IAM User MFA Required", "severity": "critical"},
                    ],
                },
            ]

            return HandlerResponse.success({
                "frameworks": frameworks,
                "total_frameworks": len(frameworks),
            })
        except Exception as e:
            logger.exception("Failed to get policies by framework")
            return HandlerResponse.server_error(str(e))

    @route("by-severity")
    def policy_by_severity(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policies grouped by severity."""
        try:
            groups = [
                {
                    "severity": "critical",
                    "policy_count": 15,
                    "enabled_count": 14,
                    "sample_policies": [
                        {"id": "aws-iam-mfa", "name": "IAM User MFA Required"},
                        {"id": "aws-s3-public-access", "name": "S3 Bucket Public Access Blocked"},
                    ],
                },
                {
                    "severity": "high",
                    "policy_count": 25,
                    "enabled_count": 23,
                    "sample_policies": [
                        {"id": "aws-s3-encryption", "name": "S3 Bucket Encryption Required"},
                        {"id": "aws-sg-ssh-open", "name": "Security Group SSH Restricted"},
                    ],
                },
                {
                    "severity": "medium",
                    "policy_count": 30,
                    "enabled_count": 28,
                    "sample_policies": [
                        {"id": "aws-ec2-public-ip", "name": "EC2 No Public IP"},
                    ],
                },
                {
                    "severity": "low",
                    "policy_count": 20,
                    "enabled_count": 18,
                    "sample_policies": [],
                },
            ]

            return HandlerResponse.success({
                "groups": groups,
                "total_policies": sum(g["policy_count"] for g in groups),
            })
        except Exception as e:
            logger.exception("Failed to get policies by severity")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Policy Validation endpoints
    # =========================================================================

    @route("validate", methods=["POST"])
    def policy_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate a policy definition."""
        try:
            body = body or {}
            policy_yaml = body.get("yaml", "")
            policy_json = body.get("json", {})

            if not policy_yaml and not policy_json:
                return HandlerResponse.error("Either yaml or json policy definition required", HttpStatus.BAD_REQUEST)

            # Demo validation result
            result = {
                "valid": True,
                "errors": [],
                "warnings": [
                    "Consider adding more specific remediation steps",
                ],
                "policy_id": policy_json.get("id", "custom-policy"),
                "parsed": {
                    "id": policy_json.get("id", "custom-policy"),
                    "name": policy_json.get("name", "Custom Policy"),
                    "severity": policy_json.get("severity", "medium"),
                    "resource_type": policy_json.get("resource_type", "aws_s3_bucket"),
                },
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to validate policy")
            return HandlerResponse.server_error(str(e))

    @route("test", methods=["POST"])
    def policy_test(self, params: dict, body: dict | None) -> HandlerResponse:
        """Test a policy against sample resources."""
        try:
            body = body or {}
            policy_id = body.get("policy_id", "")
            resource_data = body.get("resource", {})

            if not policy_id:
                return HandlerResponse.error("policy_id required", HttpStatus.BAD_REQUEST)

            # Demo test result
            result = {
                "policy_id": policy_id,
                "resource_type": resource_data.get("type", "aws_s3_bucket"),
                "result": "PASS",
                "details": {
                    "expression": "resource.encryption.enabled == true",
                    "evaluated_value": True,
                    "expected_value": True,
                },
                "execution_time_ms": 5,
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to test policy")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Policy Management endpoints
    # =========================================================================

    @route("enable", methods=["POST"])
    def policy_enable(self, params: dict, body: dict | None) -> HandlerResponse:
        """Enable a policy."""
        try:
            body = body or {}
            policy_id = body.get("policy_id") or self.get_param(params, "policy_id", "")

            if not policy_id:
                return HandlerResponse.error("policy_id required", HttpStatus.BAD_REQUEST)

            return HandlerResponse.success({
                "policy_id": policy_id,
                "enabled": True,
                "message": f"Policy {policy_id} has been enabled",
            })
        except Exception as e:
            logger.exception("Failed to enable policy")
            return HandlerResponse.server_error(str(e))

    @route("disable", methods=["POST"])
    def policy_disable(self, params: dict, body: dict | None) -> HandlerResponse:
        """Disable a policy."""
        try:
            body = body or {}
            policy_id = body.get("policy_id") or self.get_param(params, "policy_id", "")

            if not policy_id:
                return HandlerResponse.error("policy_id required", HttpStatus.BAD_REQUEST)

            return HandlerResponse.success({
                "policy_id": policy_id,
                "enabled": False,
                "message": f"Policy {policy_id} has been disabled",
            })
        except Exception as e:
            logger.exception("Failed to disable policy")
            return HandlerResponse.server_error(str(e))

    @route("create", methods=["POST"])
    def policy_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a new custom policy."""
        try:
            body = body or {}
            policy_id = body.get("id", "")
            name = body.get("name", "")
            severity = body.get("severity", "medium")
            resource_type = body.get("resource_type", "")

            if not policy_id or not name:
                return HandlerResponse.error("id and name are required", HttpStatus.BAD_REQUEST)
            if not resource_type:
                return HandlerResponse.error("resource_type is required", HttpStatus.BAD_REQUEST)

            result = {
                "id": policy_id,
                "name": name,
                "severity": severity,
                "resource_type": resource_type,
                "enabled": True,
                "created_at": "2024-12-30T12:00:00Z",
                "message": f"Policy {policy_id} has been created",
            }

            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create policy")
            return HandlerResponse.server_error(str(e))

    @route("update", methods=["POST"])
    def policy_update(self, params: dict, body: dict | None) -> HandlerResponse:
        """Update an existing policy."""
        try:
            body = body or {}
            policy_id = body.get("policy_id", "")

            if not policy_id:
                return HandlerResponse.error("policy_id required", HttpStatus.BAD_REQUEST)

            result = {
                "policy_id": policy_id,
                "updated": True,
                "updated_at": "2024-12-30T12:00:00Z",
                "message": f"Policy {policy_id} has been updated",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to update policy")
            return HandlerResponse.server_error(str(e))

    @route("delete", methods=["POST"])
    def policy_delete(self, params: dict, body: dict | None) -> HandlerResponse:
        """Delete a custom policy."""
        try:
            body = body or {}
            policy_id = body.get("policy_id") or self.get_param(params, "policy_id", "")

            if not policy_id:
                return HandlerResponse.error("policy_id required", HttpStatus.BAD_REQUEST)

            return HandlerResponse.success({
                "policy_id": policy_id,
                "deleted": True,
                "message": f"Policy {policy_id} has been deleted",
            })
        except Exception as e:
            logger.exception("Failed to delete policy")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Policy Suggestions endpoints
    # =========================================================================

    @route("suggest")
    def policy_suggest(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy suggestions for a resource type."""
        try:
            resource_type = self.get_param(params, "resource_type", "aws_s3_bucket")
            count = self.get_param_int(params, "count", 5)

            suggestions_map = {
                "aws_s3_bucket": [
                    "Ensure S3 bucket has server-side encryption enabled",
                    "Ensure S3 bucket does not have public read access",
                    "Ensure S3 bucket has versioning enabled",
                    "Ensure S3 bucket has logging enabled",
                    "Ensure S3 bucket blocks public ACLs",
                ],
                "aws_iam_user": [
                    "Ensure IAM users have MFA enabled",
                    "Ensure IAM user access keys are rotated within 90 days",
                    "Ensure IAM users do not have inline policies",
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
            }

            suggestions = suggestions_map.get(resource_type, [
                f"Ensure {resource_type} follows security best practices",
                f"Ensure {resource_type} has proper access controls",
                f"Ensure {resource_type} has encryption enabled",
            ])

            return HandlerResponse.success({
                "resource_type": resource_type,
                "suggestions": suggestions[:count],
                "total": len(suggestions[:count]),
            })
        except Exception as e:
            logger.exception("Failed to get policy suggestions")
            return HandlerResponse.server_error(str(e))

    @route("generate", methods=["POST"])
    def policy_generate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate a policy from description."""
        try:
            body = body or {}
            description = body.get("description", "")
            cloud = body.get("cloud", "aws")
            severity = body.get("severity", "medium")
            resource_type = body.get("resource_type", "")

            if not description:
                return HandlerResponse.error("description required", HttpStatus.BAD_REQUEST)

            # Determine resource type from description
            desc_lower = description.lower()
            if "s3" in desc_lower or "bucket" in desc_lower:
                detected_type = resource_type or "aws_s3_bucket"
                policy_id = "aws-s3-custom-001"
            elif "iam" in desc_lower:
                detected_type = resource_type or "aws_iam_user"
                policy_id = "aws-iam-custom-001"
            else:
                detected_type = resource_type or "aws_s3_bucket"
                policy_id = f"{cloud}-custom-001"

            yaml_content = f"""id: {policy_id}
name: Custom policy from description
description: |
  {description}

enabled: true
severity: {severity}

resource_type: {detected_type}

check:
  type: expression
  expression: "config.enabled == true"

remediation:
  guidance: |
    Implement the security control described above.
  automation_supported: false

tags:
  - custom
  - ai-generated
"""

            result = {
                "description": description,
                "cloud": cloud,
                "policy_id": policy_id,
                "yaml_content": yaml_content,
                "resource_type": detected_type,
                "severity": severity,
                "is_valid": True,
                "validation_errors": [],
            }

            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to generate policy")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Policy Statistics endpoints
    # =========================================================================

    @route("stats")
    def policy_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy statistics."""
        try:
            result = {
                "total_policies": 95,
                "enabled_policies": 88,
                "disabled_policies": 7,
                "by_severity": {
                    "critical": 15,
                    "high": 25,
                    "medium": 30,
                    "low": 20,
                    "info": 5,
                },
                "by_provider": {
                    "aws": 45,
                    "gcp": 20,
                    "azure": 18,
                    "kubernetes": 12,
                },
                "by_category": {
                    "encryption": 15,
                    "access-control": 25,
                    "authentication": 12,
                    "network": 20,
                    "logging": 18,
                    "container-security": 5,
                },
                "custom_policies": 5,
                "builtin_policies": 90,
                "last_updated": "2024-12-30T10:00:00Z",
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get policy stats")
            return HandlerResponse.server_error(str(e))

    @route("coverage")
    def policy_coverage(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy coverage analysis."""
        try:
            provider = self.get_param(params, "provider", "")

            result = {
                "total_resource_types": 60,
                "covered_resource_types": 45,
                "coverage_percentage": 75.0,
                "by_provider": [
                    {"provider": "aws", "total_types": 25, "covered": 22, "coverage": 88.0},
                    {"provider": "gcp", "total_types": 15, "covered": 10, "coverage": 66.7},
                    {"provider": "azure", "total_types": 12, "covered": 8, "coverage": 66.7},
                    {"provider": "kubernetes", "total_types": 8, "covered": 5, "coverage": 62.5},
                ],
                "uncovered_types": [
                    {"type": "aws_elasticache_cluster", "provider": "aws"},
                    {"type": "gcp_bigquery_dataset", "provider": "gcp"},
                    {"type": "azure_cosmos_db", "provider": "azure"},
                ],
            }

            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get policy coverage")
            return HandlerResponse.server_error(str(e))
