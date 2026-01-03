"""
Kubernetes Network and Security Resource Collector for Mantissa Stance.

Collects network-related and secret resources from Kubernetes clusters:
- NetworkPolicies
- Ingress resources
- Secrets (metadata only, not values)
- LimitRanges
- ResourceQuotas
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)

# Try to import kubernetes client
try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException

    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    ApiException = Exception


@dataclass
class K8sNetworkCollectorResult:
    """Result from K8sNetworkCollector."""

    collector_name: str
    assets: AssetCollection
    duration_seconds: float
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Return True if no errors occurred."""
        return len(self.errors) == 0

    @property
    def asset_count(self) -> int:
        """Return number of assets collected."""
        return len(self.assets)


class K8sNetworkCollector:
    """
    Kubernetes Network and Security Resource Collector.

    Collects network-related resources:
    - NetworkPolicies: Network segmentation rules
    - Ingress: External HTTP(S) access
    - Secrets: Secret resources (metadata only)
    - LimitRanges: Resource constraints per namespace
    - ResourceQuotas: Namespace resource quotas
    """

    collector_name: str = "k8s_network"
    resource_types: list[str] = [
        "k8s_network_policy",
        "k8s_ingress",
        "k8s_secret",
        "k8s_limit_range",
        "k8s_resource_quota",
    ]

    def __init__(
        self,
        kubeconfig: str | None = None,
        context: str | None = None,
        in_cluster: bool = False,
        namespaces: list[str] | None = None,
    ) -> None:
        """
        Initialize K8sNetworkCollector.

        Args:
            kubeconfig: Path to kubeconfig file
            context: Kubernetes context to use
            in_cluster: Use in-cluster configuration
            namespaces: List of namespaces to scan (None = all)
        """
        self._kubeconfig = kubeconfig
        self._context = context
        self._in_cluster = in_cluster
        self._namespaces = namespaces
        self._cluster_name = "kubernetes"
        self._core_api: Any = None
        self._networking_api: Any = None

    @property
    def cluster_name(self) -> str:
        """Return cluster name."""
        return self._cluster_name

    def _init_client(self) -> None:
        """Initialize Kubernetes client."""
        if not K8S_AVAILABLE:
            raise ImportError("kubernetes package is required for K8sNetworkCollector")

        if self._in_cluster:
            config.load_incluster_config()
        else:
            config.load_kube_config(
                config_file=self._kubeconfig,
                context=self._context,
            )

        self._core_api = client.CoreV1Api()
        self._networking_api = client.NetworkingV1Api()

        # Try to get cluster name from context
        try:
            _, active_context = config.list_kube_config_contexts(
                config_file=self._kubeconfig
            )
            if active_context:
                self._cluster_name = active_context.get("name", "kubernetes")
        except Exception:
            pass

    def collect(self) -> K8sNetworkCollectorResult:
        """
        Collect network and security resources from Kubernetes.

        Returns:
            K8sNetworkCollectorResult with collected assets
        """
        import time

        start_time = time.time()
        assets: list[Asset] = []
        errors: list[str] = []

        try:
            self._init_client()
        except Exception as e:
            return K8sNetworkCollectorResult(
                collector_name=self.collector_name,
                assets=AssetCollection([]),
                duration_seconds=time.time() - start_time,
                errors=[f"Failed to initialize Kubernetes client: {e}"],
            )

        # Determine namespaces to scan
        namespaces = self._namespaces
        if not namespaces:
            try:
                ns_list = self._core_api.list_namespace()
                namespaces = [ns.metadata.name for ns in ns_list.items]
            except ApiException as e:
                errors.append(f"Failed to list namespaces: {e}")
                namespaces = ["default"]

        # Collect resources from each namespace
        for namespace in namespaces:
            # Collect NetworkPolicies
            try:
                network_policies = self._networking_api.list_namespaced_network_policy(
                    namespace=namespace
                )
                for np in network_policies.items:
                    assets.append(self._network_policy_to_asset(np, namespace))
            except ApiException as e:
                if e.status != 404:
                    errors.append(
                        f"Failed to list NetworkPolicies in {namespace}: {e}"
                    )

            # Collect Ingresses
            try:
                ingresses = self._networking_api.list_namespaced_ingress(
                    namespace=namespace
                )
                for ing in ingresses.items:
                    assets.append(self._ingress_to_asset(ing, namespace))
            except ApiException as e:
                if e.status != 404:
                    errors.append(f"Failed to list Ingresses in {namespace}: {e}")

            # Collect Secrets (metadata only)
            try:
                secrets = self._core_api.list_namespaced_secret(namespace=namespace)
                for secret in secrets.items:
                    assets.append(self._secret_to_asset(secret, namespace))
            except ApiException as e:
                if e.status != 404:
                    errors.append(f"Failed to list Secrets in {namespace}: {e}")

            # Collect LimitRanges
            try:
                limit_ranges = self._core_api.list_namespaced_limit_range(
                    namespace=namespace
                )
                for lr in limit_ranges.items:
                    assets.append(self._limit_range_to_asset(lr, namespace))
            except ApiException as e:
                if e.status != 404:
                    errors.append(f"Failed to list LimitRanges in {namespace}: {e}")

            # Collect ResourceQuotas
            try:
                quotas = self._core_api.list_namespaced_resource_quota(
                    namespace=namespace
                )
                for quota in quotas.items:
                    assets.append(self._resource_quota_to_asset(quota, namespace))
            except ApiException as e:
                if e.status != 404:
                    errors.append(f"Failed to list ResourceQuotas in {namespace}: {e}")

        return K8sNetworkCollectorResult(
            collector_name=self.collector_name,
            assets=AssetCollection(assets),
            duration_seconds=time.time() - start_time,
            errors=errors,
        )

    def _network_policy_to_asset(self, np: Any, namespace: str) -> Asset:
        """Convert NetworkPolicy to Asset."""
        metadata = np.metadata
        spec = np.spec

        # Analyze policy coverage
        pod_selector = self._extract_label_selector(spec.pod_selector) if spec else {}
        has_ingress_rules = bool(spec.ingress) if spec and spec.ingress else False
        has_egress_rules = bool(spec.egress) if spec and spec.egress else False
        policy_types = list(spec.policy_types) if spec and spec.policy_types else []

        # Detect default deny policies
        is_default_deny_ingress = (
            "Ingress" in policy_types
            and not has_ingress_rules
            and not pod_selector.get("match_labels")
        )
        is_default_deny_egress = (
            "Egress" in policy_types
            and not has_egress_rules
            and not pod_selector.get("match_labels")
        )

        # Extract ingress and egress rules
        ingress_rules = self._extract_ingress_rules(spec.ingress if spec else None)
        egress_rules = self._extract_egress_rules(spec.egress if spec else None)

        # Check if policy allows traffic from all sources (overly permissive)
        allows_all_ingress = False
        if has_ingress_rules:
            for rule in ingress_rules:
                from_peers = rule.get("from", [])
                if not from_peers:
                    # No 'from' means allow from all in the selected pods
                    allows_all_ingress = True
                    break
                for peer in from_peers:
                    # Check for empty selectors (match all)
                    if not peer.get("pod_selector") and not peer.get("namespace_selector") and not peer.get("ip_block"):
                        allows_all_ingress = True
                        break

        # Check if ingress rules specify ports
        ingress_rules_have_ports = True
        if has_ingress_rules:
            for rule in ingress_rules:
                if not rule.get("ports"):
                    ingress_rules_have_ports = False
                    break

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "pod_selector": pod_selector,
            "policy_types": policy_types,
            "ingress_rules": ingress_rules,
            "egress_rules": egress_rules,
            "has_ingress_rules": has_ingress_rules,
            "has_egress_rules": has_egress_rules,
            "is_default_deny_ingress": is_default_deny_ingress,
            "is_default_deny_egress": is_default_deny_egress,
            "allows_all_ingress": allows_all_ingress,
            "ingress_rules_have_ports": ingress_rules_have_ports,
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/networkpolicy/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_network_policy",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _ingress_to_asset(self, ing: Any, namespace: str) -> Asset:
        """Convert Ingress to Asset."""
        metadata = ing.metadata
        spec = ing.spec

        # Extract ingress class and TLS configuration
        ingress_class = spec.ingress_class_name if spec else None
        has_tls = bool(spec.tls) if spec and spec.tls else False

        # Extract rules and hosts
        rules = self._extract_ingress_rules_config(spec.rules if spec else None)
        tls_config = self._extract_tls_config(spec.tls if spec else None)
        hosts = list(set(r.get("host", "") for r in rules if r.get("host")))

        # Check for default backend (catch-all)
        has_default_backend = bool(spec.default_backend) if spec else False

        # Computed property for policy checks
        has_hosts = len(hosts) > 0

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "ingress_class": ingress_class,
            "rules": rules,
            "tls": tls_config,
            "has_tls": has_tls,
            "has_default_backend": has_default_backend,
            "hosts": hosts,
            "has_hosts": has_hosts,
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        # Ingress is internet-facing by design
        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/ingress/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_ingress",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNET,
        )

    def _secret_to_asset(self, secret: Any, namespace: str) -> Asset:
        """Convert Secret to Asset (metadata only, no values)."""
        metadata = secret.metadata

        # Get secret type
        secret_type = secret.type or "Opaque"

        # Determine key names (not values)
        data_keys = list(secret.data.keys()) if secret.data else []
        string_data_keys = list(secret.string_data.keys()) if secret.string_data else []

        # Detect service account tokens
        is_service_account_token = secret_type == "kubernetes.io/service-account-token"
        service_account = (
            metadata.annotations.get("kubernetes.io/service-account.name")
            if metadata.annotations
            else None
        )

        # Detect TLS secrets
        is_tls_secret = secret_type == "kubernetes.io/tls"

        # Detect docker config secrets
        is_docker_config = secret_type in [
            "kubernetes.io/dockerconfigjson",
            "kubernetes.io/dockercfg",
        ]

        # Check if secret uses appropriate type for its content
        # Flag as inappropriate if Opaque type contains TLS or docker config data
        all_keys = data_keys + string_data_keys
        has_tls_keys = "tls.crt" in all_keys or "tls.key" in all_keys
        has_docker_keys = ".dockerconfigjson" in all_keys or ".dockercfg" in all_keys
        uses_appropriate_type = not (
            secret_type == "Opaque" and (has_tls_keys or has_docker_keys)
        )

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "type": secret_type,
            "data_keys": data_keys,
            "string_data_keys": string_data_keys,
            "key_count": len(data_keys) + len(string_data_keys),
            "is_service_account_token": is_service_account_token,
            "is_tls_secret": is_tls_secret,
            "is_docker_config": is_docker_config,
            "uses_appropriate_type": uses_appropriate_type,
            "service_account": service_account,
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/secret/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_secret",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _limit_range_to_asset(self, lr: Any, namespace: str) -> Asset:
        """Convert LimitRange to Asset."""
        metadata = lr.metadata
        spec = lr.spec

        limits = []
        if spec and spec.limits:
            for limit in spec.limits:
                limits.append({
                    "type": limit.type,
                    "default": dict(limit.default or {}),
                    "default_request": dict(limit.default_request or {}),
                    "max": dict(limit.max or {}),
                    "min": dict(limit.min or {}),
                    "max_limit_request_ratio": dict(limit.max_limit_request_ratio or {}),
                })

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "limits": limits,
            "limit_count": len(limits),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/limitrange/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_limit_range",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _resource_quota_to_asset(self, quota: Any, namespace: str) -> Asset:
        """Convert ResourceQuota to Asset."""
        metadata = quota.metadata
        spec = quota.spec
        status = quota.status

        # Extract quota specification
        hard_limits = dict(spec.hard) if spec and spec.hard else {}
        scopes = list(spec.scopes) if spec and spec.scopes else []
        scope_selector = (
            self._extract_scope_selector(spec.scope_selector)
            if spec and spec.scope_selector
            else None
        )

        # Extract usage status
        used = dict(status.used) if status and status.used else {}
        hard_status = dict(status.hard) if status and status.hard else {}

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "hard": hard_limits,
            "scopes": scopes,
            "scope_selector": scope_selector,
            "used": used,
            "hard_status": hard_status,
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/resourcequota/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_resource_quota",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _extract_label_selector(self, selector: Any) -> dict[str, Any]:
        """Extract label selector to dict."""
        if not selector:
            return {}

        result: dict[str, Any] = {}
        if selector.match_labels:
            result["match_labels"] = dict(selector.match_labels)
        if selector.match_expressions:
            result["match_expressions"] = [
                {
                    "key": expr.key,
                    "operator": expr.operator,
                    "values": list(expr.values or []),
                }
                for expr in selector.match_expressions
            ]
        return result

    def _extract_ingress_rules(self, rules: Any) -> list[dict[str, Any]]:
        """Extract NetworkPolicy ingress rules."""
        if not rules:
            return []

        result = []
        for rule in rules:
            ingress_rule: dict[str, Any] = {}

            if rule._from:
                ingress_rule["from"] = []
                for peer in rule._from:
                    peer_config: dict[str, Any] = {}
                    if peer.pod_selector:
                        peer_config["pod_selector"] = self._extract_label_selector(
                            peer.pod_selector
                        )
                    if peer.namespace_selector:
                        peer_config["namespace_selector"] = self._extract_label_selector(
                            peer.namespace_selector
                        )
                    if peer.ip_block:
                        peer_config["ip_block"] = {
                            "cidr": peer.ip_block.cidr,
                            "except": list(peer.ip_block._except or []),
                        }
                    ingress_rule["from"].append(peer_config)

            if rule.ports:
                ingress_rule["ports"] = [
                    {
                        "protocol": p.protocol or "TCP",
                        "port": str(p.port) if p.port else None,
                        "end_port": p.end_port,
                    }
                    for p in rule.ports
                ]

            result.append(ingress_rule)

        return result

    def _extract_egress_rules(self, rules: Any) -> list[dict[str, Any]]:
        """Extract NetworkPolicy egress rules."""
        if not rules:
            return []

        result = []
        for rule in rules:
            egress_rule: dict[str, Any] = {}

            if rule.to:
                egress_rule["to"] = []
                for peer in rule.to:
                    peer_config: dict[str, Any] = {}
                    if peer.pod_selector:
                        peer_config["pod_selector"] = self._extract_label_selector(
                            peer.pod_selector
                        )
                    if peer.namespace_selector:
                        peer_config["namespace_selector"] = self._extract_label_selector(
                            peer.namespace_selector
                        )
                    if peer.ip_block:
                        peer_config["ip_block"] = {
                            "cidr": peer.ip_block.cidr,
                            "except": list(peer.ip_block._except or []),
                        }
                    egress_rule["to"].append(peer_config)

            if rule.ports:
                egress_rule["ports"] = [
                    {
                        "protocol": p.protocol or "TCP",
                        "port": str(p.port) if p.port else None,
                        "end_port": p.end_port,
                    }
                    for p in rule.ports
                ]

            result.append(egress_rule)

        return result

    def _extract_ingress_rules_config(self, rules: Any) -> list[dict[str, Any]]:
        """Extract Ingress rules to config."""
        if not rules:
            return []

        result = []
        for rule in rules:
            rule_config: dict[str, Any] = {"host": rule.host}
            if rule.http and rule.http.paths:
                rule_config["paths"] = [
                    {
                        "path": p.path,
                        "path_type": p.path_type,
                        "backend": {
                            "service_name": (
                                p.backend.service.name if p.backend.service else None
                            ),
                            "service_port": (
                                str(p.backend.service.port.number)
                                if p.backend.service and p.backend.service.port
                                else None
                            ),
                        }
                        if p.backend
                        else {},
                    }
                    for p in rule.http.paths
                ]
            result.append(rule_config)
        return result

    def _extract_tls_config(self, tls: Any) -> list[dict[str, Any]]:
        """Extract Ingress TLS configuration."""
        if not tls:
            return []

        return [
            {
                "hosts": list(t.hosts or []),
                "secret_name": t.secret_name,
            }
            for t in tls
        ]

    def _extract_scope_selector(self, selector: Any) -> dict[str, Any] | None:
        """Extract ResourceQuota scope selector."""
        if not selector or not selector.match_expressions:
            return None

        return {
            "match_expressions": [
                {
                    "scope_name": expr.scope_name,
                    "operator": expr.operator,
                    "values": list(expr.values or []),
                }
                for expr in selector.match_expressions
            ]
        }
