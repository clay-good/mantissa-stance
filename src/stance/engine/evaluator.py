"""
Policy evaluator for Mantissa Stance.

Evaluates security policies against collected assets
and generates findings for non-compliant resources.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from stance.engine.expressions import ExpressionEvaluator, ExpressionError
from stance.models import (
    Asset,
    AssetCollection,
    Policy,
    PolicyCollection,
    Check,
    CheckType,
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
)

logger = logging.getLogger(__name__)


@dataclass
class PolicyEvalResult:
    """Result of evaluating a single policy."""

    policy_id: str
    assets_checked: int
    compliant: int
    non_compliant: int
    errors: list[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """Result of evaluating all policies."""

    policies_evaluated: int
    assets_evaluated: int
    findings_generated: int
    duration_seconds: float
    policy_results: dict[str, PolicyEvalResult] = field(default_factory=dict)


class PolicyEvaluator:
    """
    Evaluates security policies against asset configurations.

    Generates findings for resources that do not comply with
    policy requirements.
    """

    def __init__(self):
        """Initialize the policy evaluator."""
        self.expression_evaluator = ExpressionEvaluator()

    def evaluate_all(
        self, policies: PolicyCollection, assets: AssetCollection
    ) -> tuple[FindingCollection, EvaluationResult]:
        """
        Evaluate all enabled policies against all assets.

        Args:
            policies: Collection of policies to evaluate
            assets: Collection of assets to check

        Returns:
            Tuple of (FindingCollection, EvaluationResult)
        """
        start_time = time.time()
        all_findings: list[Finding] = []
        policy_results: dict[str, PolicyEvalResult] = {}
        evaluated_assets: set[str] = set()

        enabled_policies = policies.filter_enabled()

        for policy in enabled_policies:
            try:
                findings, result = self._evaluate_policy_with_result(policy, assets)
                all_findings.extend(findings)
                policy_results[policy.id] = result

                # Track evaluated assets
                for asset in assets:
                    if self._matches_resource_type(policy, asset):
                        evaluated_assets.add(asset.id)

            except Exception as e:
                logger.error(f"Error evaluating policy {policy.id}: {e}")
                policy_results[policy.id] = PolicyEvalResult(
                    policy_id=policy.id,
                    assets_checked=0,
                    compliant=0,
                    non_compliant=0,
                    errors=[str(e)],
                )

        duration = time.time() - start_time

        evaluation_result = EvaluationResult(
            policies_evaluated=len(enabled_policies),
            assets_evaluated=len(evaluated_assets),
            findings_generated=len(all_findings),
            duration_seconds=duration,
            policy_results=policy_results,
        )

        logger.info(
            f"Evaluation complete: {len(all_findings)} findings from "
            f"{len(enabled_policies)} policies against {len(evaluated_assets)} assets"
        )

        return FindingCollection(all_findings), evaluation_result

    def evaluate_policy(
        self, policy: Policy, assets: AssetCollection
    ) -> list[Finding]:
        """
        Evaluate single policy against matching assets.

        Args:
            policy: Policy to evaluate
            assets: Assets to check

        Returns:
            List of findings for non-compliant resources
        """
        findings, _ = self._evaluate_policy_with_result(policy, assets)
        return findings

    def _evaluate_policy_with_result(
        self, policy: Policy, assets: AssetCollection
    ) -> tuple[list[Finding], PolicyEvalResult]:
        """
        Evaluate policy and return findings with result stats.

        Args:
            policy: Policy to evaluate
            assets: Assets to check

        Returns:
            Tuple of (findings list, PolicyEvalResult)
        """
        findings: list[Finding] = []
        checked = 0
        compliant = 0
        non_compliant = 0
        errors: list[str] = []

        for asset in assets:
            if not self._matches_resource_type(policy, asset):
                continue

            checked += 1

            try:
                finding = self.evaluate_asset(policy, asset)
                if finding:
                    findings.append(finding)
                    non_compliant += 1
                else:
                    compliant += 1
            except Exception as e:
                error_msg = f"Error evaluating asset {asset.id}: {e}"
                logger.warning(error_msg)
                errors.append(error_msg)

        result = PolicyEvalResult(
            policy_id=policy.id,
            assets_checked=checked,
            compliant=compliant,
            non_compliant=non_compliant,
            errors=errors,
        )

        return findings, result

    def evaluate_asset(self, policy: Policy, asset: Asset) -> Finding | None:
        """
        Evaluate single policy against single asset.

        Args:
            policy: Policy to evaluate
            asset: Asset to check

        Returns:
            Finding if non-compliant, None if compliant
        """
        if not self._matches_resource_type(policy, asset):
            return None

        try:
            is_compliant = self._evaluate_check(policy, asset)

            if not is_compliant:
                return self._create_finding(policy, asset)

        except ExpressionError as e:
            logger.warning(
                f"Expression error evaluating policy {policy.id} "
                f"against asset {asset.id}: {e}"
            )
            # Expression errors indicate a problem with the policy, not the asset
            # Return None to avoid false positives
            return None

        return None

    def _matches_resource_type(self, policy: Policy, asset: Asset) -> bool:
        """
        Check if policy applies to asset's resource type.

        Args:
            policy: Policy to check
            asset: Asset to check

        Returns:
            True if policy applies to this asset type
        """
        if not policy.resource_type:
            return False

        # Support wildcard matching
        if policy.resource_type == "*":
            return True

        # Support prefix matching (e.g., "aws_iam_*" matches "aws_iam_user")
        if policy.resource_type.endswith("*"):
            prefix = policy.resource_type[:-1]
            return asset.resource_type.startswith(prefix)

        return asset.resource_type == policy.resource_type

    def _evaluate_check(self, policy: Policy, asset: Asset) -> bool:
        """
        Evaluate the policy check against an asset.

        Args:
            policy: Policy containing check
            asset: Asset to evaluate

        Returns:
            True if asset is compliant, False otherwise
        """
        check = policy.check

        if check.check_type == CheckType.EXPRESSION:
            return self._evaluate_expression(policy, asset)
        elif check.check_type == CheckType.SQL:
            # SQL checks are not evaluated inline
            # They require separate handling via storage queries
            logger.debug(f"SQL check for policy {policy.id} requires query execution")
            return True  # Assume compliant for now

        return True

    def _evaluate_expression(self, policy: Policy, asset: Asset) -> bool:
        """
        Evaluate an expression check against an asset.

        Args:
            policy: Policy with expression check
            asset: Asset to evaluate

        Returns:
            True if expression evaluates to true (compliant)
        """
        expression = policy.check.expression

        if not expression:
            return True

        # Build context with asset data
        context = {
            "resource": asset.raw_config,
            "asset": {
                "id": asset.id,
                "name": asset.name,
                "resource_type": asset.resource_type,
                "region": asset.region,
                "account_id": asset.account_id,
                "network_exposure": asset.network_exposure,
                "tags": asset.tags,
            },
        }

        try:
            return self.expression_evaluator.evaluate(expression, context)
        except ExpressionError:
            raise
        except Exception as e:
            logger.warning(f"Expression evaluation failed: {e}")
            raise ExpressionError(f"Evaluation failed: {e}")

    def _create_finding(self, policy: Policy, asset: Asset) -> Finding:
        """
        Create a finding for a non-compliant resource.

        Args:
            policy: Failed policy
            asset: Non-compliant asset

        Returns:
            Finding object
        """
        now = datetime.now(timezone.utc)
        finding_id = self._generate_finding_id(policy, asset)

        # Get expected and actual values from expression
        expected_value = None
        actual_value = None
        resource_path = None

        if policy.check.expression:
            # Try to extract expected value from expression
            expression = policy.check.expression
            # Simple parsing for common patterns like "resource.field == value"
            if "==" in expression:
                parts = expression.split("==")
                if len(parts) == 2:
                    resource_path = parts[0].strip()
                    expected_value = parts[1].strip().strip("'\"")

                    # Try to get actual value
                    if resource_path.startswith("resource."):
                        path = resource_path[9:]  # Remove "resource."
                        actual_value = self._get_nested_value(asset.raw_config, path)

        # Get compliance frameworks from policy
        compliance_frameworks = [
            f"{m.framework} {m.control}" for m in policy.compliance
        ]

        return Finding(
            id=finding_id,
            asset_id=asset.id,
            finding_type=FindingType.MISCONFIGURATION,
            severity=policy.severity,
            status=FindingStatus.OPEN,
            title=policy.name,
            description=policy.description,
            first_seen=now,
            last_seen=now,
            rule_id=policy.id,
            resource_path=resource_path,
            expected_value=str(expected_value) if expected_value else None,
            actual_value=str(actual_value) if actual_value is not None else None,
            compliance_frameworks=compliance_frameworks,
            remediation_guidance=policy.remediation.guidance,
        )

    def _generate_finding_id(self, policy: Policy, asset: Asset) -> str:
        """
        Generate a deterministic finding ID.

        Same policy + asset combination always produces the same ID,
        allowing tracking across scans.

        Args:
            policy: Policy that generated finding
            asset: Asset that failed check

        Returns:
            Deterministic finding ID
        """
        # Combine policy ID and asset ID for uniqueness
        combined = f"{policy.id}:{asset.id}"

        # Create a hash for a consistent, shorter ID
        hash_digest = hashlib.sha256(combined.encode()).hexdigest()[:16]

        return f"finding-{hash_digest}"

    def _get_nested_value(self, data: dict[str, Any], path: str) -> Any:
        """
        Get a nested value from a dictionary using dot notation.

        Args:
            data: Dictionary to traverse
            path: Dot-separated path

        Returns:
            Value at path or None
        """
        keys = path.split(".")
        value: Any = data

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None

            if value is None:
                return None

        return value
