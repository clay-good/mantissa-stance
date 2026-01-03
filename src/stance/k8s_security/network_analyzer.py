"""
Kubernetes Network Policy Analyzer.

Provides deep analysis of Kubernetes network policies for:
- Coverage gaps (namespaces/pods without policies)
- Overly permissive policies
- Network segmentation validation
- Zero-trust network assessment
- Traffic flow analysis
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class PolicyDirection(Enum):
    """Network policy direction."""

    INGRESS = "ingress"
    EGRESS = "egress"
    BOTH = "both"


class PolicyAction(Enum):
    """Network policy action."""

    ALLOW = "allow"
    DENY = "deny"


class CoverageLevel(Enum):
    """Network policy coverage level."""

    FULL = "full"  # All pods covered by explicit policies
    PARTIAL = "partial"  # Some pods covered
    NONE = "none"  # No network policies


class SegmentationLevel(Enum):
    """Network segmentation level."""

    STRONG = "strong"  # Strict isolation between segments
    MODERATE = "moderate"  # Some isolation
    WEAK = "weak"  # Limited isolation
    NONE = "none"  # No segmentation


class GapSeverity(Enum):
    """Severity of policy gaps."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NetworkFlow:
    """Represents a network traffic flow."""

    source_namespace: str
    source_pod_selector: dict[str, str]
    destination_namespace: str
    destination_pod_selector: dict[str, str]
    ports: list[dict[str, Any]] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    direction: PolicyDirection = PolicyDirection.INGRESS
    is_allowed: bool = True
    matched_policy: Optional[str] = None


@dataclass
class NetworkSegment:
    """Represents a network segment (group of related pods)."""

    name: str
    namespace: str
    pod_selector: dict[str, str]
    pod_count: int = 0
    has_ingress_policy: bool = False
    has_egress_policy: bool = False
    ingress_policies: list[str] = field(default_factory=list)
    egress_policies: list[str] = field(default_factory=list)
    allowed_ingress_sources: list[str] = field(default_factory=list)
    allowed_egress_destinations: list[str] = field(default_factory=list)


@dataclass
class PolicyGap:
    """Represents a gap or issue in network policy coverage."""

    gap_id: str
    severity: GapSeverity
    gap_type: str
    namespace: str
    description: str
    affected_pods: list[str] = field(default_factory=list)
    recommendation: str = ""
    policy_suggestion: Optional[dict[str, Any]] = None


@dataclass
class NetworkCoverage:
    """Network policy coverage for a namespace."""

    namespace: str
    total_pods: int = 0
    pods_with_ingress_policy: int = 0
    pods_with_egress_policy: int = 0
    pods_with_both_policies: int = 0
    pods_without_policy: int = 0
    ingress_coverage_percent: float = 0.0
    egress_coverage_percent: float = 0.0
    total_policies: int = 0
    has_default_deny_ingress: bool = False
    has_default_deny_egress: bool = False


@dataclass
class NetworkPolicyAnalysis:
    """Complete network policy analysis result."""

    # Analysis metadata
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    cluster_name: str = "unknown"

    # Coverage analysis
    total_namespaces: int = 0
    namespaces_with_policies: int = 0
    total_pods: int = 0
    pods_with_policies: int = 0
    coverage_by_namespace: dict[str, NetworkCoverage] = field(default_factory=dict)

    # Policy analysis
    total_policies: int = 0
    ingress_policies: int = 0
    egress_policies: int = 0
    default_deny_policies: int = 0
    overly_permissive_policies: int = 0

    # Segmentation
    segments: list[NetworkSegment] = field(default_factory=list)
    segmentation_level: SegmentationLevel = SegmentationLevel.NONE

    # Gaps and issues
    gaps: list[PolicyGap] = field(default_factory=list)
    critical_gaps: int = 0
    high_gaps: int = 0

    # Flows (if analyzed)
    allowed_flows: list[NetworkFlow] = field(default_factory=list)
    denied_flows: list[NetworkFlow] = field(default_factory=list)

    # Errors
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if analysis completed without errors."""
        return len(self.errors) == 0

    @property
    def overall_coverage_level(self) -> CoverageLevel:
        """Get overall coverage level."""
        if self.total_pods == 0:
            return CoverageLevel.NONE
        coverage = self.pods_with_policies / self.total_pods
        if coverage >= 0.9:
            return CoverageLevel.FULL
        elif coverage > 0:
            return CoverageLevel.PARTIAL
        return CoverageLevel.NONE

    def summary(self) -> dict[str, Any]:
        """Get analysis summary."""
        return {
            "cluster": self.cluster_name,
            "total_namespaces": self.total_namespaces,
            "namespaces_with_policies": self.namespaces_with_policies,
            "total_pods": self.total_pods,
            "pods_with_policies": self.pods_with_policies,
            "coverage_level": self.overall_coverage_level.value,
            "segmentation_level": self.segmentation_level.value,
            "total_policies": self.total_policies,
            "default_deny_policies": self.default_deny_policies,
            "overly_permissive_policies": self.overly_permissive_policies,
            "critical_gaps": self.critical_gaps,
            "high_gaps": self.high_gaps,
            "total_gaps": len(self.gaps),
        }


# Common security namespaces that should have policies
SECURITY_CRITICAL_NAMESPACES = {
    "kube-system",
    "kube-public",
    "default",
    "istio-system",
    "cert-manager",
    "ingress-nginx",
    "monitoring",
    "logging",
}


class NetworkPolicyAnalyzer:
    """
    Analyzer for Kubernetes network policies.

    Provides comprehensive analysis of network policy coverage,
    segmentation, and security posture.

    Example:
        analyzer = NetworkPolicyAnalyzer()
        result = analyzer.analyze(policies, pods, namespaces)
        if result.gaps:
            print(f"Found {len(result.gaps)} policy gaps")
    """

    def __init__(self):
        """Initialize NetworkPolicyAnalyzer."""
        self.security_namespaces = SECURITY_CRITICAL_NAMESPACES

    def analyze(
        self,
        network_policies: list[dict[str, Any]],
        pods: list[dict[str, Any]],
        namespaces: list[dict[str, Any]],
    ) -> NetworkPolicyAnalysis:
        """
        Analyze network policies for coverage and security.

        Args:
            network_policies: List of NetworkPolicy resources
            pods: List of Pod resources
            namespaces: List of Namespace resources

        Returns:
            NetworkPolicyAnalysis with findings
        """
        result = NetworkPolicyAnalysis()

        # Index policies by namespace
        policies_by_ns = self._index_policies(network_policies)

        # Index pods by namespace
        pods_by_ns = self._index_pods(pods)

        # Analyze each namespace
        result.total_namespaces = len(namespaces)
        result.total_policies = len(network_policies)

        for ns in namespaces:
            ns_name = ns.get("metadata", {}).get("name", "unknown")
            ns_pods = pods_by_ns.get(ns_name, [])
            ns_policies = policies_by_ns.get(ns_name, [])

            coverage = self._analyze_namespace_coverage(
                ns_name, ns_pods, ns_policies
            )
            result.coverage_by_namespace[ns_name] = coverage

            if coverage.total_policies > 0:
                result.namespaces_with_policies += 1

            result.total_pods += coverage.total_pods
            result.pods_with_policies += coverage.pods_with_ingress_policy

        # Analyze policies globally
        for policy in network_policies:
            policy_type = self._get_policy_type(policy)
            if "Ingress" in policy_type:
                result.ingress_policies += 1
            if "Egress" in policy_type:
                result.egress_policies += 1

            if self._is_default_deny(policy):
                result.default_deny_policies += 1

            if self._is_overly_permissive(policy):
                result.overly_permissive_policies += 1

        # Identify segments
        result.segments = self._identify_segments(network_policies, pods_by_ns)

        # Assess segmentation level
        result.segmentation_level = self._assess_segmentation(
            result.segments, result.coverage_by_namespace
        )

        # Find gaps
        result.gaps = self._find_gaps(
            result.coverage_by_namespace,
            policies_by_ns,
            pods_by_ns,
        )

        result.critical_gaps = sum(1 for g in result.gaps if g.severity == GapSeverity.CRITICAL)
        result.high_gaps = sum(1 for g in result.gaps if g.severity == GapSeverity.HIGH)

        return result

    def analyze_policy(
        self,
        policy: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Analyze a single network policy.

        Args:
            policy: NetworkPolicy resource

        Returns:
            Analysis dict with policy details
        """
        metadata = policy.get("metadata", {})
        spec = policy.get("spec", {})

        policy_types = self._get_policy_type(policy)
        is_default_deny = self._is_default_deny(policy)
        is_overly_permissive = self._is_overly_permissive(policy)

        # Analyze ingress rules
        ingress_rules = spec.get("ingress", [])
        ingress_analysis = self._analyze_ingress_rules(ingress_rules)

        # Analyze egress rules
        egress_rules = spec.get("egress", [])
        egress_analysis = self._analyze_egress_rules(egress_rules)

        return {
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "policy_types": policy_types,
            "pod_selector": spec.get("podSelector", {}),
            "is_default_deny": is_default_deny,
            "is_overly_permissive": is_overly_permissive,
            "ingress_rules_count": len(ingress_rules),
            "egress_rules_count": len(egress_rules),
            "ingress_analysis": ingress_analysis,
            "egress_analysis": egress_analysis,
            "recommendations": self._get_policy_recommendations(
                policy, is_overly_permissive
            ),
        }

    def check_segmentation(
        self,
        network_policies: list[dict[str, Any]],
        pods: list[dict[str, Any]],
        segment_labels: dict[str, list[str]],
    ) -> dict[str, Any]:
        """
        Check network segmentation between defined segments.

        Args:
            network_policies: List of NetworkPolicy resources
            pods: List of Pod resources
            segment_labels: Dict mapping segment names to label selectors

        Returns:
            Segmentation analysis dict
        """
        segments = {}
        cross_segment_flows = []

        # Build segments from label selectors
        for seg_name, labels in segment_labels.items():
            matching_pods = self._find_pods_by_labels(pods, labels)
            segments[seg_name] = {
                "name": seg_name,
                "pod_count": len(matching_pods),
                "pods": [p.get("metadata", {}).get("name") for p in matching_pods],
                "namespaces": list(set(
                    p.get("metadata", {}).get("namespace") for p in matching_pods
                )),
            }

        # Check for cross-segment communication
        for policy in network_policies:
            spec = policy.get("spec", {})
            policy_ns = policy.get("metadata", {}).get("namespace")

            # Check ingress rules
            for rule in spec.get("ingress", []):
                for from_rule in rule.get("from", []):
                    # Check if this allows cross-segment traffic
                    ns_selector = from_rule.get("namespaceSelector", {})
                    pod_selector = from_rule.get("podSelector", {})

                    if not ns_selector and not pod_selector:
                        # Empty selectors = allow all
                        cross_segment_flows.append({
                            "policy": policy.get("metadata", {}).get("name"),
                            "type": "ingress",
                            "allows": "all",
                        })

        return {
            "segments": segments,
            "segment_count": len(segments),
            "cross_segment_flows": cross_segment_flows,
            "is_segmented": len(cross_segment_flows) == 0,
        }

    def generate_default_deny_policy(
        self,
        namespace: str,
        direction: PolicyDirection = PolicyDirection.BOTH,
    ) -> dict[str, Any]:
        """
        Generate a default deny network policy.

        Args:
            namespace: Target namespace
            direction: Policy direction

        Returns:
            NetworkPolicy resource dict
        """
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"default-deny-{direction.value}",
                "namespace": namespace,
            },
            "spec": {
                "podSelector": {},  # Selects all pods
                "policyTypes": [],
            },
        }

        if direction in [PolicyDirection.INGRESS, PolicyDirection.BOTH]:
            policy["spec"]["policyTypes"].append("Ingress")
            policy["spec"]["ingress"] = []

        if direction in [PolicyDirection.EGRESS, PolicyDirection.BOTH]:
            policy["spec"]["policyTypes"].append("Egress")
            policy["spec"]["egress"] = []

        return policy

    def _index_policies(
        self,
        policies: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Index policies by namespace."""
        result: dict[str, list[dict[str, Any]]] = {}
        for policy in policies:
            ns = policy.get("metadata", {}).get("namespace", "default")
            if ns not in result:
                result[ns] = []
            result[ns].append(policy)
        return result

    def _index_pods(
        self,
        pods: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Index pods by namespace."""
        result: dict[str, list[dict[str, Any]]] = {}
        for pod in pods:
            ns = pod.get("metadata", {}).get("namespace", "default")
            if ns not in result:
                result[ns] = []
            result[ns].append(pod)
        return result

    def _analyze_namespace_coverage(
        self,
        namespace: str,
        pods: list[dict[str, Any]],
        policies: list[dict[str, Any]],
    ) -> NetworkCoverage:
        """Analyze network policy coverage for a namespace."""
        coverage = NetworkCoverage(
            namespace=namespace,
            total_pods=len(pods),
            total_policies=len(policies),
        )

        if not pods or not policies:
            coverage.pods_without_policy = len(pods)
            return coverage

        # Check each policy for default deny
        for policy in policies:
            if self._is_default_deny_ingress(policy):
                coverage.has_default_deny_ingress = True
            if self._is_default_deny_egress(policy):
                coverage.has_default_deny_egress = True

        # Check pod coverage
        for pod in pods:
            pod_labels = pod.get("metadata", {}).get("labels", {})
            has_ingress = False
            has_egress = False

            for policy in policies:
                if self._policy_selects_pod(policy, pod_labels):
                    policy_types = self._get_policy_type(policy)
                    if "Ingress" in policy_types:
                        has_ingress = True
                    if "Egress" in policy_types:
                        has_egress = True

            if has_ingress:
                coverage.pods_with_ingress_policy += 1
            if has_egress:
                coverage.pods_with_egress_policy += 1
            if has_ingress and has_egress:
                coverage.pods_with_both_policies += 1
            if not has_ingress and not has_egress:
                coverage.pods_without_policy += 1

        # Calculate percentages
        if coverage.total_pods > 0:
            coverage.ingress_coverage_percent = (
                coverage.pods_with_ingress_policy / coverage.total_pods * 100
            )
            coverage.egress_coverage_percent = (
                coverage.pods_with_egress_policy / coverage.total_pods * 100
            )

        return coverage

    def _get_policy_type(self, policy: dict[str, Any]) -> list[str]:
        """Get policy types (Ingress/Egress)."""
        spec = policy.get("spec", {})
        policy_types = spec.get("policyTypes", [])

        if not policy_types:
            # Infer from rules
            if spec.get("ingress") is not None:
                policy_types.append("Ingress")
            if spec.get("egress") is not None:
                policy_types.append("Egress")

        return policy_types if policy_types else ["Ingress"]

    def _is_default_deny(self, policy: dict[str, Any]) -> bool:
        """Check if policy is a default deny policy."""
        spec = policy.get("spec", {})
        pod_selector = spec.get("podSelector", {})

        # Default deny selects all pods and has empty rules
        if pod_selector.get("matchLabels") or pod_selector.get("matchExpressions"):
            return False

        policy_types = self._get_policy_type(policy)

        # Check for empty ingress/egress rules
        if "Ingress" in policy_types and spec.get("ingress") == []:
            return True
        if "Egress" in policy_types and spec.get("egress") == []:
            return True

        return False

    def _is_default_deny_ingress(self, policy: dict[str, Any]) -> bool:
        """Check if policy is a default deny ingress policy."""
        spec = policy.get("spec", {})
        pod_selector = spec.get("podSelector", {})

        if pod_selector.get("matchLabels") or pod_selector.get("matchExpressions"):
            return False

        policy_types = self._get_policy_type(policy)
        return "Ingress" in policy_types and spec.get("ingress") == []

    def _is_default_deny_egress(self, policy: dict[str, Any]) -> bool:
        """Check if policy is a default deny egress policy."""
        spec = policy.get("spec", {})
        pod_selector = spec.get("podSelector", {})

        if pod_selector.get("matchLabels") or pod_selector.get("matchExpressions"):
            return False

        policy_types = self._get_policy_type(policy)
        return "Egress" in policy_types and spec.get("egress") == []

    def _is_overly_permissive(self, policy: dict[str, Any]) -> bool:
        """Check if policy is overly permissive."""
        spec = policy.get("spec", {})

        # Check ingress rules
        for rule in spec.get("ingress", []):
            from_rules = rule.get("from", [])
            if not from_rules:
                # Empty from = allow from all
                return True
            for from_rule in from_rules:
                # Check for empty selectors (matches all)
                if not from_rule.get("namespaceSelector") and \
                   not from_rule.get("podSelector") and \
                   not from_rule.get("ipBlock"):
                    return True
                # Check for catch-all namespace selector
                ns_selector = from_rule.get("namespaceSelector", {})
                if ns_selector == {}:
                    return True

        # Check egress rules
        for rule in spec.get("egress", []):
            to_rules = rule.get("to", [])
            if not to_rules:
                # Empty to = allow to all
                return True
            for to_rule in to_rules:
                if not to_rule.get("namespaceSelector") and \
                   not to_rule.get("podSelector") and \
                   not to_rule.get("ipBlock"):
                    return True
                ns_selector = to_rule.get("namespaceSelector", {})
                if ns_selector == {}:
                    return True

        return False

    def _policy_selects_pod(
        self,
        policy: dict[str, Any],
        pod_labels: dict[str, str],
    ) -> bool:
        """Check if a policy selects a pod with given labels."""
        spec = policy.get("spec", {})
        pod_selector = spec.get("podSelector", {})

        # Empty selector matches all pods
        if not pod_selector or (not pod_selector.get("matchLabels") and
                                 not pod_selector.get("matchExpressions")):
            return True

        # Check matchLabels
        match_labels = pod_selector.get("matchLabels", {})
        for key, value in match_labels.items():
            if pod_labels.get(key) != value:
                return False

        # Check matchExpressions (simplified)
        match_expressions = pod_selector.get("matchExpressions", [])
        for expr in match_expressions:
            key = expr.get("key")
            operator = expr.get("operator")
            values = expr.get("values", [])

            if operator == "In":
                if pod_labels.get(key) not in values:
                    return False
            elif operator == "NotIn":
                if pod_labels.get(key) in values:
                    return False
            elif operator == "Exists":
                if key not in pod_labels:
                    return False
            elif operator == "DoesNotExist":
                if key in pod_labels:
                    return False

        return True

    def _identify_segments(
        self,
        policies: list[dict[str, Any]],
        pods_by_ns: dict[str, list[dict[str, Any]]],
    ) -> list[NetworkSegment]:
        """Identify network segments from policies."""
        segments = []
        seen_selectors = set()

        for policy in policies:
            metadata = policy.get("metadata", {})
            spec = policy.get("spec", {})
            ns = metadata.get("namespace", "default")
            pod_selector = spec.get("podSelector", {})

            # Create unique key for this selector
            selector_key = f"{ns}:{str(sorted(pod_selector.items()))}"
            if selector_key in seen_selectors:
                continue
            seen_selectors.add(selector_key)

            # Count matching pods
            ns_pods = pods_by_ns.get(ns, [])
            matching_pods = sum(
                1 for pod in ns_pods
                if self._policy_selects_pod(policy, pod.get("metadata", {}).get("labels", {}))
            )

            policy_types = self._get_policy_type(policy)

            segment = NetworkSegment(
                name=metadata.get("name", "unknown"),
                namespace=ns,
                pod_selector=pod_selector,
                pod_count=matching_pods,
                has_ingress_policy="Ingress" in policy_types,
                has_egress_policy="Egress" in policy_types,
            )

            if segment.has_ingress_policy:
                segment.ingress_policies.append(metadata.get("name"))
            if segment.has_egress_policy:
                segment.egress_policies.append(metadata.get("name"))

            segments.append(segment)

        return segments

    def _assess_segmentation(
        self,
        segments: list[NetworkSegment],
        coverage_by_ns: dict[str, NetworkCoverage],
    ) -> SegmentationLevel:
        """Assess overall network segmentation level."""
        if not segments:
            return SegmentationLevel.NONE

        # Check for default deny policies
        has_default_deny = any(
            c.has_default_deny_ingress and c.has_default_deny_egress
            for c in coverage_by_ns.values()
        )

        # Count segments with both ingress and egress
        full_segments = sum(
            1 for s in segments
            if s.has_ingress_policy and s.has_egress_policy
        )

        if has_default_deny and full_segments >= len(segments) * 0.8:
            return SegmentationLevel.STRONG
        elif full_segments >= len(segments) * 0.5:
            return SegmentationLevel.MODERATE
        elif segments:
            return SegmentationLevel.WEAK

        return SegmentationLevel.NONE

    def _find_gaps(
        self,
        coverage_by_ns: dict[str, NetworkCoverage],
        policies_by_ns: dict[str, list[dict[str, Any]]],
        pods_by_ns: dict[str, list[dict[str, Any]]],
    ) -> list[PolicyGap]:
        """Find network policy gaps."""
        gaps = []

        for ns, coverage in coverage_by_ns.items():
            # Check for no policies in security-critical namespaces
            if ns in self.security_namespaces and coverage.total_policies == 0:
                gaps.append(PolicyGap(
                    gap_id=f"NP-GAP-001-{ns}",
                    severity=GapSeverity.CRITICAL,
                    gap_type="no_policy_critical_namespace",
                    namespace=ns,
                    description=f"Security-critical namespace '{ns}' has no network policies",
                    recommendation="Add default-deny network policies to this namespace",
                    policy_suggestion=self.generate_default_deny_policy(ns),
                ))

            # Check for no default deny
            if coverage.total_pods > 0 and not coverage.has_default_deny_ingress:
                gaps.append(PolicyGap(
                    gap_id=f"NP-GAP-002-{ns}",
                    severity=GapSeverity.HIGH if ns in self.security_namespaces else GapSeverity.MEDIUM,
                    gap_type="no_default_deny_ingress",
                    namespace=ns,
                    description=f"Namespace '{ns}' has no default-deny ingress policy",
                    recommendation="Add a default-deny ingress policy",
                    policy_suggestion=self.generate_default_deny_policy(ns, PolicyDirection.INGRESS),
                ))

            if coverage.total_pods > 0 and not coverage.has_default_deny_egress:
                gaps.append(PolicyGap(
                    gap_id=f"NP-GAP-003-{ns}",
                    severity=GapSeverity.MEDIUM,
                    gap_type="no_default_deny_egress",
                    namespace=ns,
                    description=f"Namespace '{ns}' has no default-deny egress policy",
                    recommendation="Add a default-deny egress policy for zero-trust",
                    policy_suggestion=self.generate_default_deny_policy(ns, PolicyDirection.EGRESS),
                ))

            # Check for uncovered pods
            if coverage.pods_without_policy > 0:
                gaps.append(PolicyGap(
                    gap_id=f"NP-GAP-004-{ns}",
                    severity=GapSeverity.MEDIUM,
                    gap_type="uncovered_pods",
                    namespace=ns,
                    description=f"{coverage.pods_without_policy} pods in '{ns}' have no network policy",
                    recommendation="Create network policies for uncovered pods",
                ))

            # Check for overly permissive policies
            ns_policies = policies_by_ns.get(ns, [])
            for policy in ns_policies:
                if self._is_overly_permissive(policy):
                    policy_name = policy.get("metadata", {}).get("name", "unknown")
                    gaps.append(PolicyGap(
                        gap_id=f"NP-GAP-005-{ns}-{policy_name}",
                        severity=GapSeverity.HIGH,
                        gap_type="overly_permissive",
                        namespace=ns,
                        description=f"Network policy '{policy_name}' in '{ns}' is overly permissive",
                        recommendation="Restrict the policy to specific sources/destinations",
                    ))

        return gaps

    def _analyze_ingress_rules(
        self,
        rules: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze ingress rules."""
        return {
            "rule_count": len(rules),
            "allows_all_sources": any(not r.get("from") for r in rules),
            "uses_namespace_selector": any(
                any(f.get("namespaceSelector") for f in r.get("from", []))
                for r in rules
            ),
            "uses_pod_selector": any(
                any(f.get("podSelector") for f in r.get("from", []))
                for r in rules
            ),
            "uses_ip_block": any(
                any(f.get("ipBlock") for f in r.get("from", []))
                for r in rules
            ),
        }

    def _analyze_egress_rules(
        self,
        rules: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze egress rules."""
        return {
            "rule_count": len(rules),
            "allows_all_destinations": any(not r.get("to") for r in rules),
            "uses_namespace_selector": any(
                any(t.get("namespaceSelector") for t in r.get("to", []))
                for r in rules
            ),
            "uses_pod_selector": any(
                any(t.get("podSelector") for t in r.get("to", []))
                for r in rules
            ),
            "uses_ip_block": any(
                any(t.get("ipBlock") for t in r.get("to", []))
                for r in rules
            ),
        }

    def _get_policy_recommendations(
        self,
        policy: dict[str, Any],
        is_overly_permissive: bool,
    ) -> list[str]:
        """Get recommendations for a policy."""
        recommendations = []

        if is_overly_permissive:
            recommendations.append(
                "Restrict policy to specific namespaces and pod selectors"
            )

        spec = policy.get("spec", {})
        policy_types = self._get_policy_type(policy)

        if "Ingress" in policy_types and not spec.get("ingress"):
            recommendations.append(
                "Add explicit ingress rules or use empty array for default deny"
            )

        if "Egress" not in policy_types:
            recommendations.append(
                "Consider adding egress rules for complete traffic control"
            )

        return recommendations

    def _find_pods_by_labels(
        self,
        pods: list[dict[str, Any]],
        label_selector: list[str],
    ) -> list[dict[str, Any]]:
        """Find pods matching label selector."""
        matching = []
        for pod in pods:
            pod_labels = pod.get("metadata", {}).get("labels", {})
            # Simple label matching (key=value pairs)
            matches = True
            for selector in label_selector:
                if "=" in selector:
                    key, value = selector.split("=", 1)
                    if pod_labels.get(key) != value:
                        matches = False
                        break
                elif selector not in pod_labels:
                    matches = False
                    break
            if matches:
                matching.append(pod)
        return matching


def analyze_network_policies(
    network_policies: list[dict[str, Any]],
    pods: list[dict[str, Any]],
    namespaces: list[dict[str, Any]],
) -> NetworkPolicyAnalysis:
    """
    Convenience function to analyze network policies.

    Args:
        network_policies: List of NetworkPolicy resources
        pods: List of Pod resources
        namespaces: List of Namespace resources

    Returns:
        NetworkPolicyAnalysis with findings
    """
    analyzer = NetworkPolicyAnalyzer()
    return analyzer.analyze(network_policies, pods, namespaces)


def check_network_segmentation(
    network_policies: list[dict[str, Any]],
    pods: list[dict[str, Any]],
    segment_labels: dict[str, list[str]],
) -> dict[str, Any]:
    """
    Convenience function to check network segmentation.

    Args:
        network_policies: List of NetworkPolicy resources
        pods: List of Pod resources
        segment_labels: Dict mapping segment names to label selectors

    Returns:
        Segmentation analysis dict
    """
    analyzer = NetworkPolicyAnalyzer()
    return analyzer.check_segmentation(network_policies, pods, segment_labels)
