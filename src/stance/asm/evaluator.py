"""
ASM Policy Evaluator for Mantissa Stance.

This module evaluates ASM-specific policies against external assets
discovered through attack surface reconnaissance.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stance.engine.expressions import ExpressionEvaluator, ExpressionError
from stance.models.finding import (
    Finding,
    FindingCollection,
    FindingStatus,
    FindingType,
    Severity,
)
from stance.models.policy import (
    Check,
    CheckType,
    ComplianceMapping,
    Policy,
    PolicyCollection,
    Remediation,
)
from stance.asm.models import ExternalAsset, ExternalAssetCollection

logger = logging.getLogger(__name__)


# Default ASM policies directory
DEFAULT_ASM_POLICIES_PATH = "policies/asm"


@dataclass
class ASMPolicyEvalResult:
    """Result of evaluating a single ASM policy."""

    policy_id: str
    assets_checked: int
    compliant: int
    non_compliant: int
    errors: list[str] = field(default_factory=list)


@dataclass
class ASMEvaluationResult:
    """Result of evaluating all ASM policies."""

    policies_evaluated: int
    assets_evaluated: int
    findings_generated: int
    duration_seconds: float
    policy_results: dict[str, ASMPolicyEvalResult] = field(default_factory=dict)


class ASMPolicyLoader:
    """
    Loads ASM-specific policies from YAML files.

    Handles parsing of multi-document YAML files where multiple
    policies are separated by --- delimiters.
    """

    def __init__(self, policies_path: str | None = None) -> None:
        """
        Initialize the ASM policy loader.

        Args:
            policies_path: Path to ASM policies directory
        """
        self._policies_path = policies_path or DEFAULT_ASM_POLICIES_PATH

    @property
    def policies_path(self) -> str:
        """Get the policies path."""
        return self._policies_path

    def load_all(self) -> PolicyCollection:
        """
        Load all ASM policies from the policies directory.

        Returns:
            PolicyCollection containing all loaded policies
        """
        policies: list[Policy] = []
        policy_path = Path(self._policies_path)

        if not policy_path.exists():
            logger.warning(f"ASM policies directory not found: {policy_path}")
            return PolicyCollection(policies)

        # Find all YAML files
        yaml_files = list(policy_path.glob("*.yaml")) + list(policy_path.glob("*.yml"))

        for yaml_file in yaml_files:
            try:
                file_policies = self._load_file(yaml_file)
                policies.extend(file_policies)
                logger.debug(
                    f"Loaded {len(file_policies)} policies from {yaml_file.name}"
                )
            except Exception as e:
                logger.error(f"Error loading policies from {yaml_file}: {e}")

        logger.info(f"Loaded {len(policies)} ASM policies from {policy_path}")
        return PolicyCollection(policies)

    def _load_file(self, path: Path) -> list[Policy]:
        """
        Load policies from a single YAML file.

        Handles multi-document YAML files separated by ---.

        Args:
            path: Path to YAML file

        Returns:
            List of Policy objects
        """
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        policies: list[Policy] = []

        # Split multi-document YAML
        documents = content.split("\n---\n")

        for doc in documents:
            doc = doc.strip()
            if not doc or doc.startswith("---"):
                continue

            try:
                policy = self._parse_policy(doc)
                if policy:
                    policies.append(policy)
            except Exception as e:
                logger.warning(f"Error parsing policy in {path}: {e}")

        return policies

    def _parse_policy(self, yaml_content: str) -> Policy | None:
        """
        Parse a single policy from YAML content.

        Args:
            yaml_content: YAML string for one policy

        Returns:
            Policy object or None if parsing fails
        """
        try:
            return Policy.from_yaml(yaml_content)
        except Exception as e:
            logger.debug(f"Failed to parse policy: {e}")
            return None


class ASMPolicyEvaluator:
    """
    Evaluates ASM policies against external assets.

    Adapts the standard PolicyEvaluator for external assets,
    building appropriate expression context from ExternalAsset
    properties.
    """

    def __init__(
        self,
        policies_path: str | None = None,
    ) -> None:
        """
        Initialize the ASM policy evaluator.

        Args:
            policies_path: Path to ASM policies directory
        """
        self._policies_path = policies_path or DEFAULT_ASM_POLICIES_PATH
        self._expression_evaluator = ExpressionEvaluator()
        self._policies: PolicyCollection | None = None

    @property
    def policies_path(self) -> str:
        """Get the policies path."""
        return self._policies_path

    def load_policies(self) -> PolicyCollection:
        """
        Load ASM policies from disk.

        Returns:
            PolicyCollection of loaded policies
        """
        loader = ASMPolicyLoader(self._policies_path)
        self._policies = loader.load_all()
        return self._policies

    def evaluate(
        self,
        assets: ExternalAssetCollection,
        policies: PolicyCollection | None = None,
    ) -> tuple[FindingCollection, ASMEvaluationResult]:
        """
        Evaluate ASM policies against external assets.

        Args:
            assets: Collection of external assets to evaluate
            policies: Optional policy collection (loads from disk if not provided)

        Returns:
            Tuple of (FindingCollection, ASMEvaluationResult)
        """
        start_time = time.time()

        # Load policies if not provided
        if policies is None:
            if self._policies is None:
                self.load_policies()
            policies = self._policies

        if policies is None:
            logger.warning("No ASM policies loaded")
            return FindingCollection(), ASMEvaluationResult(
                policies_evaluated=0,
                assets_evaluated=len(assets),
                findings_generated=0,
                duration_seconds=0.0,
            )

        all_findings: list[Finding] = []
        policy_results: dict[str, ASMPolicyEvalResult] = {}
        evaluated_assets: set[str] = set()

        # Filter to enabled policies
        enabled_policies = policies.filter_enabled()

        for policy in enabled_policies:
            try:
                findings, result = self._evaluate_policy(policy, assets)
                all_findings.extend(findings)
                policy_results[policy.id] = result

                # Track evaluated assets
                for asset in assets:
                    if self._matches_resource_type(policy, asset):
                        evaluated_assets.add(asset.id)

            except Exception as e:
                logger.error(f"Error evaluating ASM policy {policy.id}: {e}")
                policy_results[policy.id] = ASMPolicyEvalResult(
                    policy_id=policy.id,
                    assets_checked=0,
                    compliant=0,
                    non_compliant=0,
                    errors=[str(e)],
                )

        duration = time.time() - start_time

        result = ASMEvaluationResult(
            policies_evaluated=len(enabled_policies),
            assets_evaluated=len(evaluated_assets),
            findings_generated=len(all_findings),
            duration_seconds=duration,
            policy_results=policy_results,
        )

        logger.info(
            f"ASM evaluation complete: {len(all_findings)} findings from "
            f"{len(enabled_policies)} policies against {len(evaluated_assets)} assets "
            f"in {duration:.2f}s"
        )

        return FindingCollection(all_findings), result

    def _evaluate_policy(
        self,
        policy: Policy,
        assets: ExternalAssetCollection,
    ) -> tuple[list[Finding], ASMPolicyEvalResult]:
        """
        Evaluate a single policy against all matching assets.

        Args:
            policy: Policy to evaluate
            assets: Assets to check

        Returns:
            Tuple of (findings list, ASMPolicyEvalResult)
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
                finding = self._evaluate_asset(policy, asset)
                if finding:
                    findings.append(finding)
                    non_compliant += 1
                else:
                    compliant += 1
            except Exception as e:
                error_msg = f"Error evaluating asset {asset.id}: {e}"
                logger.debug(error_msg)
                errors.append(error_msg)

        result = ASMPolicyEvalResult(
            policy_id=policy.id,
            assets_checked=checked,
            compliant=compliant,
            non_compliant=non_compliant,
            errors=errors,
        )

        return findings, result

    def _evaluate_asset(
        self,
        policy: Policy,
        asset: ExternalAsset,
    ) -> Finding | None:
        """
        Evaluate a single policy against a single asset.

        Args:
            policy: Policy to evaluate
            asset: Asset to check

        Returns:
            Finding if non-compliant, None if compliant
        """
        try:
            is_compliant = self._evaluate_check(policy, asset)

            if not is_compliant:
                return self._create_finding(policy, asset)

        except ExpressionError as e:
            logger.debug(
                f"Expression error evaluating policy {policy.id} "
                f"against asset {asset.id}: {e}"
            )
            return None

        return None

    def _matches_resource_type(
        self,
        policy: Policy,
        asset: ExternalAsset,
    ) -> bool:
        """
        Check if policy applies to asset's resource type.

        Args:
            policy: Policy to check
            asset: Asset to check

        Returns:
            True if policy applies to this asset
        """
        if not policy.resource_type:
            return False

        # ASM policies use "external_asset" as resource type
        if policy.resource_type == "external_asset":
            return True

        # Support wildcard
        if policy.resource_type == "*":
            return True

        return False

    def _evaluate_check(
        self,
        policy: Policy,
        asset: ExternalAsset,
    ) -> bool:
        """
        Evaluate the policy check against an asset.

        Args:
            policy: Policy containing check
            asset: Asset to evaluate

        Returns:
            True if asset is compliant, False if non-compliant
        """
        check = policy.check

        if check.check_type == CheckType.EXPRESSION:
            return self._evaluate_expression(policy, asset)

        # SQL checks not currently supported for ASM
        return True

    def _evaluate_expression(
        self,
        policy: Policy,
        asset: ExternalAsset,
    ) -> bool:
        """
        Evaluate an expression check against an external asset.

        Args:
            policy: Policy with expression check
            asset: External asset to evaluate

        Returns:
            True if expression evaluates to true (compliant)
        """
        expression = policy.check.expression

        if not expression:
            return True

        # Build context with external asset data
        context = self._build_expression_context(asset)

        try:
            return self._expression_evaluator.evaluate(expression, context)
        except ExpressionError:
            raise
        except Exception as e:
            logger.debug(f"Expression evaluation failed: {e}")
            raise ExpressionError(f"Evaluation failed: {e}")

    def _build_expression_context(
        self,
        asset: ExternalAsset,
    ) -> dict[str, Any]:
        """
        Build expression evaluation context from external asset.

        Args:
            asset: External asset to build context from

        Returns:
            Context dictionary for expression evaluation
        """
        # Build certificate info dict if present
        cert_info: dict[str, Any] = {}
        if asset.certificate_info:
            cert = asset.certificate_info
            cert_info = {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "not_before": cert.not_before.isoformat() if cert.not_before else None,
                "not_after": cert.not_after.isoformat() if cert.not_after else None,
                "san_domains": list(cert.san_domains),
                "fingerprint_sha256": cert.fingerprint_sha256,
                "is_self_signed": cert.is_self_signed,
                "key_algorithm": cert.key_algorithm,
                "key_size": cert.key_size,
                "signature_algorithm": getattr(cert, "signature_algorithm", "unknown"),
                "is_expired": cert.is_expired,
                "is_expiring_soon": cert.is_expiring_soon,
                "days_until_expiry": cert.days_until_expiry,
                "is_weak_key": cert.is_weak_key,
            }

        # Build resource context
        resource: dict[str, Any] = {
            "id": asset.id,
            "domain": asset.domain,
            "ip_address": asset.ip_address,
            "port": asset.port,
            "protocol": asset.protocol,
            "service": asset.service,
            "technology_stack": list(asset.technology_stack),
            "cloud_provider": asset.cloud_provider,
            "cloud_region": asset.cloud_region,
            "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
            "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
            "risk_score": asset.risk_score,
            "source": asset.source,
            "is_verified": asset.is_verified,
            "certificate_info": cert_info if cert_info else None,
            "raw_data": asset.raw_data,
        }

        # Merge raw_data into resource for easier access
        if asset.raw_data:
            for key, value in asset.raw_data.items():
                if key not in resource:
                    resource[key] = value

        return {
            "resource": resource,
            "asset": resource,  # Alias for compatibility
        }

    def _create_finding(
        self,
        policy: Policy,
        asset: ExternalAsset,
    ) -> Finding:
        """
        Create a finding for a non-compliant external asset.

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
            expression = policy.check.expression.strip()
            # Simple parsing for common patterns
            if "==" in expression:
                parts = expression.split("==")
                if len(parts) == 2:
                    resource_path = parts[0].strip()
                    expected_value = parts[1].strip().strip("'\"")
                    actual_value = self._get_asset_value(asset, resource_path)

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

    def _generate_finding_id(
        self,
        policy: Policy,
        asset: ExternalAsset,
    ) -> str:
        """
        Generate a deterministic finding ID.

        Args:
            policy: Policy that generated finding
            asset: Asset that failed check

        Returns:
            Deterministic finding ID
        """
        combined = f"{policy.id}:{asset.id}"
        hash_digest = hashlib.sha256(combined.encode()).hexdigest()[:16]
        return f"asm-finding-{hash_digest}"

    def _get_asset_value(
        self,
        asset: ExternalAsset,
        path: str,
    ) -> Any:
        """
        Get value from asset using path notation.

        Args:
            asset: External asset
            path: Dot-separated path (e.g., "resource.domain")

        Returns:
            Value at path or None
        """
        context = self._build_expression_context(asset)
        parts = path.split(".")
        value: Any = context

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None

            if value is None:
                return None

        return value


def create_shadow_it_findings(
    external_assets: ExternalAssetCollection,
    internal_assets: Any,  # AssetCollection from CSPM
) -> FindingCollection:
    """
    Create findings for shadow IT - external assets not in CSPM inventory.

    Args:
        external_assets: Assets discovered externally
        internal_assets: Assets from CSPM inventory

    Returns:
        FindingCollection with shadow IT findings
    """
    from stance.asm.findings import create_asm_finding, ASMFindingType

    findings: list[Finding] = []

    # Build set of internal asset identifiers for matching
    internal_domains: set[str] = set()
    internal_ips: set[str] = set()

    if hasattr(internal_assets, "__iter__"):
        for internal in internal_assets:
            # Extract domain from tags or name if available
            if hasattr(internal, "tags") and internal.tags:
                if "domain" in internal.tags:
                    internal_domains.add(internal.tags["domain"].lower())
            if hasattr(internal, "name") and internal.name:
                internal_domains.add(internal.name.lower())
            # Extract public IP if available
            if hasattr(internal, "raw_config") and internal.raw_config:
                public_ip = internal.raw_config.get("public_ip")
                if public_ip:
                    internal_ips.add(public_ip)

    # Check each external asset
    for external in external_assets:
        matched = False

        # Check domain match
        if external.domain and external.domain.lower() in internal_domains:
            matched = True

        # Check IP match
        if external.ip_address and external.ip_address in internal_ips:
            matched = True

        if not matched:
            # Create shadow IT finding
            finding = create_asm_finding(
                asset=external,
                finding_type=ASMFindingType.SHADOW_IT,
                title=f"Shadow IT detected: {external.domain}",
                description=(
                    f"The external asset {external.domain} "
                    f"(IP: {external.ip_address or 'unknown'}) was not found in the "
                    f"CSPM inventory. This may indicate unauthorized infrastructure, "
                    f"a collection gap, or an asset that needs to be added to inventory."
                ),
                additional_data={
                    "cspm_matched": False,
                    "correlation_checked": True,
                },
            )
            findings.append(finding)

    logger.info(f"Shadow IT detection found {len(findings)} unmatched external assets")
    return FindingCollection(findings)
