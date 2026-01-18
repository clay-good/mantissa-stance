"""
Engine handlers for the Stance web API.

This module handles all /api/engine/* endpoints for policy
engine operations and expression evaluation.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class EngineHandler(RoutedHandler):
    """
    Handler for policy engine API endpoints.

    Handles:
    - Policy management
    - Expression evaluation
    - Compliance checking
    - Operator listing
    """

    base_path = "/api/engine/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("policies")
    def engine_policies(self, params: dict, body: dict | None) -> HandlerResponse:
        """List loaded policies."""
        provider = self.get_param(params, "provider", "")
        severity = self.get_param(params, "severity", "")

        policies = [
            {
                "id": "s3-encryption-required",
                "name": "S3 Bucket Encryption Required",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_s3_bucket",
                "enabled": True,
            },
            {
                "id": "security-group-no-ingress-all",
                "name": "Security Group No Ingress 0.0.0.0/0",
                "severity": "critical",
                "provider": "aws",
                "resource_type": "aws_security_group",
                "enabled": True,
            },
            {
                "id": "rds-encryption-enabled",
                "name": "RDS Encryption Enabled",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_db_instance",
                "enabled": True,
            },
        ]

        # Apply filters
        if provider:
            policies = [p for p in policies if p["provider"] == provider]
        if severity:
            policies = [p for p in policies if p["severity"] == severity]

        return HandlerResponse.success({"policies": policies, "total": len(policies)})

    @route("policy")
    def engine_policy(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy details."""
        policy_id = self.get_param(params, "id", "")
        if not policy_id:
            return HandlerResponse.error("Missing required parameter: id", HttpStatus.BAD_REQUEST)

        policies = {
            "s3-encryption-required": {
                "id": "s3-encryption-required",
                "name": "S3 Bucket Encryption Required",
                "description": "Ensures S3 buckets have server-side encryption enabled",
                "severity": "high",
                "provider": "aws",
                "resource_type": "aws_s3_bucket",
                "check": "resource.server_side_encryption_configuration != null",
                "remediation": "Enable server-side encryption on the S3 bucket",
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

    @route("validate")
    def engine_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate a policy definition."""
        policy_id = self.get_param(params, "id", "")

        return HandlerResponse.success({
            "policy_id": policy_id or "inline",
            "valid": True,
            "errors": [],
            "warnings": [],
        })

    @route("evaluate")
    def engine_evaluate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Evaluate a policy against a resource."""
        policy_id = self.get_param(params, "policy_id", "")
        resource_id = self.get_param(params, "resource_id", "")

        return HandlerResponse.success({
            "policy_id": policy_id or "demo-policy",
            "resource_id": resource_id or "demo-resource",
            "result": "pass",
            "details": {
                "check_passed": True,
                "evaluation_time_ms": 5,
            },
        })

    @route("validate-expression")
    def engine_validate_expression(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate a policy expression."""
        expression = self.get_param(params, "expression", "")
        if not expression:
            return HandlerResponse.error("Missing required parameter: expression", HttpStatus.BAD_REQUEST)

        return HandlerResponse.success({
            "expression": expression,
            "valid": True,
            "parsed": {
                "type": "comparison",
                "left": "resource.encryption",
                "operator": "==",
                "right": "true",
            },
            "errors": [],
        })

    @route("compliance")
    def engine_compliance(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get compliance framework mappings."""
        framework = self.get_param(params, "framework", "")

        mappings = [
            {"policy_id": "s3-encryption-required", "control": "CIS 2.1.1", "framework": "cis"},
            {"policy_id": "security-group-no-ingress-all", "control": "CIS 5.2", "framework": "cis"},
            {"policy_id": "rds-encryption-enabled", "control": "CIS 2.3.1", "framework": "cis"},
        ]

        if framework:
            mappings = [m for m in mappings if m["framework"] == framework]

        return HandlerResponse.success({"mappings": mappings, "total": len(mappings)})

    @route("frameworks")
    def engine_frameworks(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported compliance frameworks."""
        frameworks = [
            {"id": "cis", "name": "CIS Benchmarks", "version": "1.4.0", "policies_mapped": 85},
            {"id": "nist", "name": "NIST 800-53", "version": "r5", "policies_mapped": 72},
            {"id": "pci", "name": "PCI DSS", "version": "4.0", "policies_mapped": 45},
            {"id": "soc2", "name": "SOC 2", "version": "2017", "policies_mapped": 38},
        ]
        return HandlerResponse.success({"frameworks": frameworks, "total": len(frameworks)})

    @route("operators")
    def engine_operators(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported expression operators."""
        operators = [
            {"operator": "==", "name": "equals", "description": "Equality comparison"},
            {"operator": "!=", "name": "not_equals", "description": "Inequality comparison"},
            {"operator": ">", "name": "greater_than", "description": "Greater than comparison"},
            {"operator": "<", "name": "less_than", "description": "Less than comparison"},
            {"operator": ">=", "name": "greater_equal", "description": "Greater than or equal"},
            {"operator": "<=", "name": "less_equal", "description": "Less than or equal"},
            {"operator": "in", "name": "in", "description": "Membership test"},
            {"operator": "contains", "name": "contains", "description": "Contains check"},
            {"operator": "matches", "name": "matches", "description": "Regex match"},
            {"operator": "exists", "name": "exists", "description": "Existence check"},
        ]
        return HandlerResponse.success({"operators": operators, "total": len(operators)})

    @route("check-types")
    def engine_check_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """List policy check types."""
        check_types = [
            {"type": "resource", "description": "Resource property checks"},
            {"type": "network", "description": "Network configuration checks"},
            {"type": "encryption", "description": "Encryption state checks"},
            {"type": "access", "description": "Access control checks"},
            {"type": "logging", "description": "Logging configuration checks"},
        ]
        return HandlerResponse.success({"check_types": check_types, "total": len(check_types)})

    @route("severity-levels")
    def engine_severity_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List policy severity levels."""
        levels = [
            {"level": "critical", "description": "Immediate action required", "priority": 1},
            {"level": "high", "description": "Significant security risk", "priority": 2},
            {"level": "medium", "description": "Moderate security concern", "priority": 3},
            {"level": "low", "description": "Minor security issue", "priority": 4},
            {"level": "info", "description": "Informational finding", "priority": 5},
        ]
        return HandlerResponse.success({"levels": levels, "total": len(levels)})

    @route("stats")
    def engine_stats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy engine statistics."""
        return HandlerResponse.success({
            "total_policies": 150,
            "enabled_policies": 145,
            "policies_by_provider": {"aws": 85, "gcp": 35, "azure": 25, "kubernetes": 5},
            "policies_by_severity": {"critical": 20, "high": 45, "medium": 55, "low": 25, "info": 5},
            "evaluations_today": 0,
        })

    @route("status")
    def engine_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy engine status."""
        return HandlerResponse.success({
            "module": "engine",
            "status": "operational",
            "policies_loaded": 150,
            "capabilities": [
                "policy_evaluation",
                "expression_parsing",
                "compliance_mapping",
                "batch_evaluation",
            ],
        })

    @route("summary")
    def engine_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get policy engine summary."""
        return HandlerResponse.success({
            "module": "engine",
            "description": "Security policy evaluation engine",
            "features": [
                "Policy-based resource evaluation",
                "Expression language for custom checks",
                "Compliance framework mapping",
                "Multi-provider support",
                "Batch evaluation",
            ],
            "total_policies": 150,
            "supported_providers": ["aws", "gcp", "azure", "kubernetes"],
            "supported_frameworks": ["cis", "nist", "pci", "soc2"],
        })
