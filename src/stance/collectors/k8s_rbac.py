"""
Kubernetes RBAC (Role-Based Access Control) collector.

This collector gathers Kubernetes RBAC resources including
roles, cluster roles, role bindings, cluster role bindings,
and service accounts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_INTERNAL

logger = logging.getLogger(__name__)

# Try to import kubernetes client (optional dependency)
try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    client = None  # type: ignore
    config = None  # type: ignore
    ApiException = Exception  # type: ignore


# High-risk permissions that indicate admin-like access
HIGH_RISK_VERBS = {"*", "create", "delete", "deletecollection", "patch", "update"}
HIGH_RISK_RESOURCES = {
    "*",
    "secrets",
    "pods/exec",
    "pods/attach",
    "serviceaccounts",
    "clusterroles",
    "clusterrolebindings",
    "roles",
    "rolebindings",
    "persistentvolumes",
    "nodes",
    "nodes/proxy",
}
ADMIN_CLUSTER_ROLES = {
    "cluster-admin",
    "admin",
    "edit",
    "system:masters",
}


@dataclass
class K8sRBACCollectorResult:
    """Result from running the Kubernetes RBAC collector."""

    collector_name: str
    assets: AssetCollection
    duration_seconds: float
    errors: list[str]

    @property
    def success(self) -> bool:
        """Check if collection completed without errors."""
        return len(self.errors) == 0

    @property
    def asset_count(self) -> int:
        """Get number of assets collected."""
        return len(self.assets)


class K8sRBACCollector:
    """
    Collector for Kubernetes RBAC resources.

    Collects security-relevant configuration for:
    - Roles (namespace-scoped)
    - ClusterRoles (cluster-scoped)
    - RoleBindings (namespace-scoped)
    - ClusterRoleBindings (cluster-scoped)
    - ServiceAccounts

    Resource types collected:
    - k8s_role
    - k8s_cluster_role
    - k8s_role_binding
    - k8s_cluster_role_binding
    - k8s_service_account
    """

    collector_name: str = "k8s_rbac"
    resource_types: list[str] = [
        "k8s_role",
        "k8s_cluster_role",
        "k8s_role_binding",
        "k8s_cluster_role_binding",
        "k8s_service_account",
    ]

    def __init__(
        self,
        kubeconfig: str | None = None,
        context: str | None = None,
        in_cluster: bool = False,
        namespaces: list[str] | None = None,
    ) -> None:
        """
        Initialize the Kubernetes RBAC collector.

        Args:
            kubeconfig: Path to kubeconfig file (default: ~/.kube/config)
            context: Kubernetes context to use (default: current context)
            in_cluster: If True, use in-cluster configuration
            namespaces: List of namespaces to collect from (default: all)
        """
        if not K8S_AVAILABLE:
            raise ImportError(
                "kubernetes client is required. Install with: pip install kubernetes"
            )

        self._kubeconfig = kubeconfig
        self._context = context
        self._in_cluster = in_cluster
        self._namespaces = namespaces
        self._cluster_name: str | None = None
        self._api_client: Any = None
        self._core_v1: Any = None
        self._rbac_v1: Any = None

    def _init_client(self) -> None:
        """Initialize the Kubernetes client."""
        if self._api_client is not None:
            return

        if self._in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config(
                config_file=self._kubeconfig,
                context=self._context,
            )

        self._api_client = client.ApiClient()
        self._core_v1 = client.CoreV1Api(self._api_client)
        self._rbac_v1 = client.RbacAuthorizationV1Api(self._api_client)

        # Try to get cluster name from context
        try:
            contexts, active_context = config.list_kube_config_contexts(
                config_file=self._kubeconfig
            )
            if self._context:
                for ctx in contexts:
                    if ctx["name"] == self._context:
                        self._cluster_name = ctx.get("context", {}).get("cluster", self._context)
                        break
            elif active_context:
                self._cluster_name = active_context.get("context", {}).get(
                    "cluster", active_context.get("name", "unknown")
                )
        except Exception:
            self._cluster_name = "unknown"

    @property
    def cluster_name(self) -> str:
        """Get the cluster name."""
        if self._cluster_name is None:
            self._init_client()
        return self._cluster_name or "unknown"

    def collect(self) -> K8sRBACCollectorResult:
        """
        Collect Kubernetes RBAC configuration.

        Returns:
            K8sRBACCollectorResult with collected assets
        """
        import time

        start_time = time.time()
        assets: list[Asset] = []
        errors: list[str] = []

        try:
            self._init_client()

            # Get namespaces to collect from
            namespaces = self._get_namespaces()

            # Collect cluster-scoped resources
            try:
                for asset in self._collect_cluster_roles():
                    assets.append(asset)
            except ApiException as e:
                errors.append(f"Error collecting cluster roles: {e.reason}")

            try:
                for asset in self._collect_cluster_role_bindings():
                    assets.append(asset)
            except ApiException as e:
                errors.append(f"Error collecting cluster role bindings: {e.reason}")

            # Collect namespace-scoped resources
            for namespace in namespaces:
                try:
                    # Roles
                    for asset in self._collect_roles(namespace):
                        assets.append(asset)

                    # RoleBindings
                    for asset in self._collect_role_bindings(namespace):
                        assets.append(asset)

                    # ServiceAccounts
                    for asset in self._collect_service_accounts(namespace):
                        assets.append(asset)

                except ApiException as e:
                    errors.append(f"Error collecting from namespace {namespace}: {e.reason}")
                except Exception as e:
                    errors.append(f"Error in namespace {namespace}: {str(e)}")

        except Exception as e:
            errors.append(f"Failed to initialize Kubernetes client: {str(e)}")

        duration = time.time() - start_time

        return K8sRBACCollectorResult(
            collector_name=self.collector_name,
            assets=AssetCollection(assets=assets),
            duration_seconds=duration,
            errors=errors,
        )

    def _get_namespaces(self) -> list[str]:
        """Get list of namespaces to collect from."""
        if self._namespaces:
            return self._namespaces

        try:
            ns_list = self._core_v1.list_namespace()
            return [ns.metadata.name for ns in ns_list.items]
        except ApiException as e:
            logger.warning(f"Failed to list namespaces: {e.reason}")
            return ["default"]

    def _collect_cluster_roles(self) -> Iterator[Asset]:
        """Collect ClusterRole resources."""
        try:
            cluster_roles = self._rbac_v1.list_cluster_role()
            for cr in cluster_roles.items:
                yield self._cluster_role_to_asset(cr)
        except ApiException as e:
            logger.warning(f"Failed to list cluster roles: {e.reason}")

    def _cluster_role_to_asset(self, cr: Any) -> Asset:
        """Convert ClusterRole to Asset."""
        metadata = cr.metadata
        rules = cr.rules or []

        # Analyze rules for risk
        risk_analysis = self._analyze_rules(rules)

        raw_config = {
            "name": metadata.name,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "rules": self._extract_rules(rules),
            "aggregation_rule": (
                self._extract_aggregation_rule(cr.aggregation_rule)
                if cr.aggregation_rule
                else None
            ),
            "is_aggregate": cr.aggregation_rule is not None,
            "risk_analysis": risk_analysis,
            "is_admin_role": metadata.name in ADMIN_CLUSTER_ROLES,
            "is_system_role": metadata.name.startswith("system:"),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/clusterrole/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_cluster_role",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_cluster_role_bindings(self) -> Iterator[Asset]:
        """Collect ClusterRoleBinding resources."""
        try:
            bindings = self._rbac_v1.list_cluster_role_binding()
            for crb in bindings.items:
                yield self._cluster_role_binding_to_asset(crb)
        except ApiException as e:
            logger.warning(f"Failed to list cluster role bindings: {e.reason}")

    def _cluster_role_binding_to_asset(self, crb: Any) -> Asset:
        """Convert ClusterRoleBinding to Asset."""
        metadata = crb.metadata
        role_ref = crb.role_ref
        subjects = crb.subjects or []

        # Determine if this binding grants admin access
        is_admin_binding = role_ref.name in ADMIN_CLUSTER_ROLES

        raw_config = {
            "name": metadata.name,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "role_ref": {
                "api_group": role_ref.api_group,
                "kind": role_ref.kind,
                "name": role_ref.name,
            },
            "subjects": self._extract_subjects(subjects),
            "is_admin_binding": is_admin_binding,
            "is_system_binding": metadata.name.startswith("system:"),
            "grants_cluster_admin": role_ref.name == "cluster-admin",
            "subject_count": len(subjects),
            "has_user_subjects": any(s.kind == "User" for s in subjects),
            "has_group_subjects": any(s.kind == "Group" for s in subjects),
            "has_service_account_subjects": any(s.kind == "ServiceAccount" for s in subjects),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/clusterrolebinding/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_cluster_role_binding",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_roles(self, namespace: str) -> Iterator[Asset]:
        """Collect Role resources."""
        try:
            roles = self._rbac_v1.list_namespaced_role(namespace)
            for role in roles.items:
                yield self._role_to_asset(role, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list roles in {namespace}: {e.reason}")

    def _role_to_asset(self, role: Any, namespace: str) -> Asset:
        """Convert Role to Asset."""
        metadata = role.metadata
        rules = role.rules or []

        # Analyze rules for risk
        risk_analysis = self._analyze_rules(rules)

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "rules": self._extract_rules(rules),
            "risk_analysis": risk_analysis,
            "is_system_role": metadata.name.startswith("system:"),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/role/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_role",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_role_bindings(self, namespace: str) -> Iterator[Asset]:
        """Collect RoleBinding resources."""
        try:
            bindings = self._rbac_v1.list_namespaced_role_binding(namespace)
            for rb in bindings.items:
                yield self._role_binding_to_asset(rb, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list role bindings in {namespace}: {e.reason}")

    def _role_binding_to_asset(self, rb: Any, namespace: str) -> Asset:
        """Convert RoleBinding to Asset."""
        metadata = rb.metadata
        role_ref = rb.role_ref
        subjects = rb.subjects or []

        # Determine if this binding grants admin access
        is_admin_binding = role_ref.name in ADMIN_CLUSTER_ROLES

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "role_ref": {
                "api_group": role_ref.api_group,
                "kind": role_ref.kind,
                "name": role_ref.name,
            },
            "subjects": self._extract_subjects(subjects),
            "is_admin_binding": is_admin_binding,
            "is_system_binding": metadata.name.startswith("system:"),
            "references_cluster_role": role_ref.kind == "ClusterRole",
            "subject_count": len(subjects),
            "has_user_subjects": any(s.kind == "User" for s in subjects),
            "has_group_subjects": any(s.kind == "Group" for s in subjects),
            "has_service_account_subjects": any(s.kind == "ServiceAccount" for s in subjects),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/rolebinding/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_role_binding",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_service_accounts(self, namespace: str) -> Iterator[Asset]:
        """Collect ServiceAccount resources."""
        try:
            service_accounts = self._core_v1.list_namespaced_service_account(namespace)
            for sa in service_accounts.items:
                yield self._service_account_to_asset(sa, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list service accounts in {namespace}: {e.reason}")

    def _service_account_to_asset(self, sa: Any, namespace: str) -> Asset:
        """Convert ServiceAccount to Asset."""
        metadata = sa.metadata
        secrets = sa.secrets or []
        image_pull_secrets = sa.image_pull_secrets or []

        # Check if this is the default service account
        is_default = metadata.name == "default"

        # Check for automount token setting
        automount_token = sa.automount_service_account_token
        if automount_token is None:
            automount_token = True  # Default is true if not specified

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "secrets": [{"name": s.name} for s in secrets],
            "image_pull_secrets": [{"name": s.name} for s in image_pull_secrets],
            "automount_service_account_token": automount_token,
            "is_default": is_default,
            "is_system_account": metadata.name.startswith("system:"),
            "secret_count": len(secrets),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/serviceaccount/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_service_account",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    # Helper methods

    def _extract_rules(self, rules: list[Any]) -> list[dict[str, Any]]:
        """Extract RBAC rules configuration."""
        return [
            {
                "api_groups": list(r.api_groups or [""]),
                "resources": list(r.resources or []),
                "resource_names": list(r.resource_names or []),
                "verbs": list(r.verbs or []),
                "non_resource_urls": list(r.non_resource_ur_ls or []),
            }
            for r in rules
        ]

    def _extract_subjects(self, subjects: list[Any]) -> list[dict[str, Any]]:
        """Extract binding subjects."""
        return [
            {
                "kind": s.kind,
                "name": s.name,
                "namespace": s.namespace,
                "api_group": s.api_group,
            }
            for s in subjects
        ]

    def _extract_aggregation_rule(self, agg_rule: Any) -> dict[str, Any]:
        """Extract aggregation rule configuration."""
        selectors = agg_rule.cluster_role_selectors or []
        return {
            "cluster_role_selectors": [
                {
                    "match_labels": dict(s.match_labels or {}),
                    "match_expressions": [
                        {
                            "key": e.key,
                            "operator": e.operator,
                            "values": list(e.values or []),
                        }
                        for e in (s.match_expressions or [])
                    ],
                }
                for s in selectors
            ],
        }

    def _analyze_rules(self, rules: list[Any]) -> dict[str, Any]:
        """Analyze RBAC rules for risk indicators."""
        has_wildcard_resources = False
        has_wildcard_verbs = False
        has_high_risk_resources = False
        has_high_risk_verbs = False
        has_secrets_access = False
        has_pod_exec_access = False
        high_risk_combinations: list[dict[str, Any]] = []
        total_permissions = 0

        for rule in rules:
            resources = set(rule.resources or [])
            verbs = set(rule.verbs or [])

            # Check for wildcards
            if "*" in resources:
                has_wildcard_resources = True
            if "*" in verbs:
                has_wildcard_verbs = True

            # Check for secrets access
            if "secrets" in resources or "*" in resources:
                has_secrets_access = True

            # Check for pod exec access
            if "pods/exec" in resources or "pods/attach" in resources or "*" in resources:
                has_pod_exec_access = True

            # Check for high-risk resources
            risky_resources = resources & HIGH_RISK_RESOURCES
            if risky_resources:
                has_high_risk_resources = True

            # Check for high-risk verbs
            risky_verbs = verbs & HIGH_RISK_VERBS
            if risky_verbs:
                has_high_risk_verbs = True

            # Identify high-risk combinations
            if risky_resources and risky_verbs:
                high_risk_combinations.append({
                    "resources": list(risky_resources),
                    "verbs": list(risky_verbs),
                })

            # Count total permissions
            total_permissions += len(resources) * len(verbs)

        # Calculate risk score (0-100)
        risk_score = 0
        if has_wildcard_resources and has_wildcard_verbs:
            risk_score = 100  # Full wildcard access
        elif has_wildcard_resources or has_wildcard_verbs:
            risk_score = 80  # Partial wildcard access
        elif high_risk_combinations:
            risk_score = 70  # High-risk combinations
        elif has_high_risk_resources:
            risk_score = 50  # Access to sensitive resources
        elif has_high_risk_verbs:
            risk_score = 40  # Destructive verbs
        elif total_permissions > 20:
            risk_score = 30  # Many permissions
        else:
            risk_score = 10  # Limited permissions

        return {
            "risk_score": risk_score,
            "has_wildcard_resources": has_wildcard_resources,
            "has_wildcard_verbs": has_wildcard_verbs,
            "has_high_risk_resources": has_high_risk_resources,
            "has_high_risk_verbs": has_high_risk_verbs,
            "has_secrets_access": has_secrets_access,
            "has_pod_exec_access": has_pod_exec_access,
            "high_risk_combinations": high_risk_combinations,
            "total_permissions": total_permissions,
            "is_overly_permissive": risk_score >= 70,
        }
