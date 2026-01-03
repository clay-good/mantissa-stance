"""
Exception matcher for Mantissa Stance.

Matches findings against policy exceptions based on various criteria.
"""

from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING

from stance.exceptions.models import (
    PolicyException,
    ExceptionScope,
    ExceptionMatch,
    ExceptionResult,
)

if TYPE_CHECKING:
    from stance.models import Finding, Asset


class ExceptionMatcher:
    """
    Matches findings against policy exceptions.

    Supports matching by:
    - Finding ID
    - Asset ID
    - Policy/Rule ID
    - Asset + Policy combination
    - Resource type
    - Tags
    - Account ID
    - Custom conditions
    """

    def __init__(self, exceptions: list[PolicyException] | None = None):
        """
        Initialize the matcher.

        Args:
            exceptions: List of exceptions to match against
        """
        self._exceptions = exceptions or []

    @property
    def exceptions(self) -> list[PolicyException]:
        """Get list of exceptions."""
        return self._exceptions

    def add_exception(self, exception: PolicyException) -> None:
        """
        Add an exception to the matcher.

        Args:
            exception: Exception to add
        """
        self._exceptions.append(exception)

    def remove_exception(self, exception_id: str) -> bool:
        """
        Remove an exception by ID.

        Args:
            exception_id: ID of exception to remove

        Returns:
            True if exception was removed
        """
        original_count = len(self._exceptions)
        self._exceptions = [e for e in self._exceptions if e.id != exception_id]
        return len(self._exceptions) < original_count

    def check_finding(
        self,
        finding: "Finding",
        asset: "Asset | None" = None,
    ) -> ExceptionResult:
        """
        Check if a finding matches any exceptions.

        Args:
            finding: Finding to check
            asset: Optional asset for additional matching

        Returns:
            ExceptionResult with match information
        """
        matches: list[ExceptionMatch] = []

        for exception in self._exceptions:
            if not exception.is_active:
                continue

            match = self._match_exception(finding, asset, exception)
            if match:
                matches.append(match)

        # Sort by match score (highest first)
        matches.sort(key=lambda m: m.match_score, reverse=True)

        # Get the highest priority match
        applied = matches[0].exception if matches else None

        return ExceptionResult(
            finding_id=finding.id,
            is_excepted=len(matches) > 0,
            matches=matches,
            applied_exception=applied,
        )

    def _match_exception(
        self,
        finding: "Finding",
        asset: "Asset | None",
        exception: PolicyException,
    ) -> ExceptionMatch | None:
        """
        Check if a finding matches a specific exception.

        Args:
            finding: Finding to check
            asset: Optional asset
            exception: Exception to match

        Returns:
            ExceptionMatch if matched, None otherwise
        """
        scope = exception.scope
        match_reason = ""
        match_score = 100

        # Check by scope
        if scope == ExceptionScope.FINDING:
            if not self._match_finding_id(finding.id, exception.finding_id):
                return None
            match_reason = f"Finding ID match: {exception.finding_id}"
            match_score = 100

        elif scope == ExceptionScope.ASSET:
            if not self._match_asset_id(finding.asset_id, exception.asset_id):
                return None
            match_reason = f"Asset ID match: {exception.asset_id}"
            match_score = 90

        elif scope == ExceptionScope.POLICY:
            if not self._match_policy_id(finding.rule_id, exception.policy_id):
                return None
            match_reason = f"Policy ID match: {exception.policy_id}"
            match_score = 85

        elif scope == ExceptionScope.ASSET_POLICY:
            if not self._match_asset_id(finding.asset_id, exception.asset_id):
                return None
            if not self._match_policy_id(finding.rule_id, exception.policy_id):
                return None
            match_reason = f"Asset + Policy match: {exception.asset_id} + {exception.policy_id}"
            match_score = 95

        elif scope == ExceptionScope.RESOURCE_TYPE:
            if not asset:
                return None
            if not self._match_resource_type(asset.resource_type, exception.resource_type):
                return None
            # Also check policy if specified
            if exception.policy_id:
                if not self._match_policy_id(finding.rule_id, exception.policy_id):
                    return None
            match_reason = f"Resource type match: {exception.resource_type}"
            match_score = 70

        elif scope == ExceptionScope.TAG:
            if not asset:
                return None
            if not self._match_tag(asset, exception.tag_key, exception.tag_value):
                return None
            match_reason = f"Tag match: {exception.tag_key}={exception.tag_value}"
            match_score = 60

        elif scope == ExceptionScope.ACCOUNT:
            if not asset:
                return None
            if not self._match_account(asset, exception.account_id):
                return None
            match_reason = f"Account match: {exception.account_id}"
            match_score = 50

        elif scope == ExceptionScope.GLOBAL:
            # Global exceptions match everything
            match_reason = "Global exception"
            match_score = 30

        else:
            return None

        # Check additional conditions
        if exception.conditions:
            if not self._match_conditions(finding, asset, exception.conditions):
                return None
            match_reason += " (with conditions)"
            match_score = max(match_score - 5, 0)

        return ExceptionMatch(
            exception=exception,
            match_reason=match_reason,
            match_score=match_score,
        )

    def _match_finding_id(
        self,
        finding_id: str,
        pattern: str | None,
    ) -> bool:
        """Match finding ID with pattern support."""
        if not pattern:
            return False
        # Support exact match or prefix match
        if pattern.endswith("*"):
            return finding_id.startswith(pattern[:-1])
        return finding_id == pattern

    def _match_asset_id(
        self,
        asset_id: str,
        pattern: str | None,
    ) -> bool:
        """Match asset ID with pattern support."""
        if not pattern:
            return False
        # Support wildcard patterns
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(asset_id, pattern)
        return asset_id == pattern

    def _match_policy_id(
        self,
        policy_id: str | None,
        pattern: str | None,
    ) -> bool:
        """Match policy ID with pattern support."""
        if not pattern:
            return False
        if not policy_id:
            return False
        # Support wildcard patterns
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(policy_id, pattern)
        return policy_id == pattern

    def _match_resource_type(
        self,
        resource_type: str | None,
        pattern: str | None,
    ) -> bool:
        """Match resource type."""
        if not pattern:
            return False
        if not resource_type:
            return False
        # Support wildcard patterns
        if "*" in pattern or "?" in pattern:
            return fnmatch.fnmatch(resource_type, pattern)
        return resource_type == pattern

    def _match_tag(
        self,
        asset: "Asset",
        tag_key: str | None,
        tag_value: str | None,
    ) -> bool:
        """Match asset tag."""
        if not tag_key:
            return False

        tags = getattr(asset, "tags", {})
        if not isinstance(tags, dict):
            return False

        # Check tag key exists
        if tag_key not in tags:
            return False

        # If no tag value specified, just check key exists
        if tag_value is None:
            return True

        # Check tag value
        actual_value = tags.get(tag_key)
        if tag_value.startswith("*") or tag_value.endswith("*"):
            return fnmatch.fnmatch(str(actual_value or ""), tag_value)
        return str(actual_value) == tag_value

    def _match_account(
        self,
        asset: "Asset",
        account_id: str | None,
    ) -> bool:
        """Match account ID."""
        if not account_id:
            return False

        asset_account = getattr(asset, "account_id", None)
        if not asset_account:
            return False

        return asset_account == account_id

    def _match_conditions(
        self,
        finding: "Finding",
        asset: "Asset | None",
        conditions: dict,
    ) -> bool:
        """
        Match custom conditions.

        Supported conditions:
        - severity: Match finding severity
        - severity_min: Minimum severity (critical > high > medium > low > info)
        - title_contains: Finding title contains text
        - title_regex: Finding title matches regex
        - description_contains: Description contains text
        """
        severity_order = ["info", "low", "medium", "high", "critical"]

        # Severity exact match
        if "severity" in conditions:
            finding_sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            if finding_sev != conditions["severity"]:
                return False

        # Severity minimum
        if "severity_min" in conditions:
            finding_sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
            min_sev = conditions["severity_min"]
            if severity_order.index(finding_sev) > severity_order.index(min_sev):
                return False

        # Title contains
        if "title_contains" in conditions:
            if conditions["title_contains"].lower() not in finding.title.lower():
                return False

        # Title regex
        if "title_regex" in conditions:
            if not re.search(conditions["title_regex"], finding.title):
                return False

        # Description contains
        if "description_contains" in conditions:
            desc = finding.description or ""
            if conditions["description_contains"].lower() not in desc.lower():
                return False

        return True


def match_exception(
    finding: "Finding",
    exceptions: list[PolicyException],
    asset: "Asset | None" = None,
) -> ExceptionResult:
    """
    Check if a finding matches any exceptions.

    Convenience function for one-off matching.

    Args:
        finding: Finding to check
        exceptions: List of exceptions
        asset: Optional asset

    Returns:
        ExceptionResult with match information
    """
    matcher = ExceptionMatcher(exceptions)
    return matcher.check_finding(finding, asset)
