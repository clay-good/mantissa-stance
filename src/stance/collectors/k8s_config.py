"""
Kubernetes workload configuration collector.

This collector gathers Kubernetes workload resources including
deployments, pods, services, daemonsets, statefulsets, and more.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_INTERNET, NETWORK_EXPOSURE_INTERNAL

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


@dataclass
class K8sCollectorResult:
    """Result from running a Kubernetes collector."""

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


class K8sConfigCollector:
    """
    Collector for Kubernetes workload configuration resources.

    Collects security-relevant configuration for:
    - Deployments
    - Pods
    - Services
    - DaemonSets
    - StatefulSets
    - ReplicaSets
    - Jobs
    - CronJobs
    - ConfigMaps (metadata only, not data)
    - Namespaces

    Resource types collected:
    - k8s_deployment
    - k8s_pod
    - k8s_service
    - k8s_daemonset
    - k8s_statefulset
    - k8s_replicaset
    - k8s_job
    - k8s_cronjob
    - k8s_configmap
    - k8s_namespace
    """

    collector_name: str = "k8s_config"
    resource_types: list[str] = [
        "k8s_deployment",
        "k8s_pod",
        "k8s_service",
        "k8s_daemonset",
        "k8s_statefulset",
        "k8s_replicaset",
        "k8s_job",
        "k8s_cronjob",
        "k8s_configmap",
        "k8s_namespace",
    ]

    def __init__(
        self,
        kubeconfig: str | None = None,
        context: str | None = None,
        in_cluster: bool = False,
        namespaces: list[str] | None = None,
    ) -> None:
        """
        Initialize the Kubernetes config collector.

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
        self._apps_v1: Any = None
        self._batch_v1: Any = None

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
        self._apps_v1 = client.AppsV1Api(self._api_client)
        self._batch_v1 = client.BatchV1Api(self._api_client)

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

    def collect(self) -> K8sCollectorResult:
        """
        Collect Kubernetes workload configuration.

        Returns:
            K8sCollectorResult with collected assets
        """
        import time

        start_time = time.time()
        assets: list[Asset] = []
        errors: list[str] = []

        try:
            self._init_client()

            # Get namespaces to collect from
            namespaces = self._get_namespaces()

            # Collect namespaces themselves
            for ns_asset in self._collect_namespaces():
                assets.append(ns_asset)

            # Collect workloads from each namespace
            for namespace in namespaces:
                try:
                    # Deployments
                    for asset in self._collect_deployments(namespace):
                        assets.append(asset)

                    # Pods
                    for asset in self._collect_pods(namespace):
                        assets.append(asset)

                    # Services
                    for asset in self._collect_services(namespace):
                        assets.append(asset)

                    # DaemonSets
                    for asset in self._collect_daemonsets(namespace):
                        assets.append(asset)

                    # StatefulSets
                    for asset in self._collect_statefulsets(namespace):
                        assets.append(asset)

                    # ReplicaSets
                    for asset in self._collect_replicasets(namespace):
                        assets.append(asset)

                    # Jobs
                    for asset in self._collect_jobs(namespace):
                        assets.append(asset)

                    # CronJobs
                    for asset in self._collect_cronjobs(namespace):
                        assets.append(asset)

                    # ConfigMaps (metadata only)
                    for asset in self._collect_configmaps(namespace):
                        assets.append(asset)

                except ApiException as e:
                    errors.append(f"Error collecting from namespace {namespace}: {e.reason}")
                except Exception as e:
                    errors.append(f"Error in namespace {namespace}: {str(e)}")

        except Exception as e:
            errors.append(f"Failed to initialize Kubernetes client: {str(e)}")

        duration = time.time() - start_time

        return K8sCollectorResult(
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

    def _collect_namespaces(self) -> Iterator[Asset]:
        """Collect namespace resources."""
        try:
            ns_list = self._core_v1.list_namespace()
            for ns in ns_list.items:
                yield self._namespace_to_asset(ns)
        except ApiException as e:
            logger.warning(f"Failed to list namespaces: {e.reason}")

    def _namespace_to_asset(self, ns: Any) -> Asset:
        """Convert namespace to Asset."""
        metadata = ns.metadata
        status = ns.status

        raw_config = {
            "name": metadata.name,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "status": status.phase if status else "Unknown",
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/namespace/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_namespace",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_deployments(self, namespace: str) -> Iterator[Asset]:
        """Collect Deployment resources."""
        try:
            deployments = self._apps_v1.list_namespaced_deployment(namespace)
            for dep in deployments.items:
                yield self._deployment_to_asset(dep, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list deployments in {namespace}: {e.reason}")

    def _deployment_to_asset(self, dep: Any, namespace: str) -> Asset:
        """Convert Deployment to Asset."""
        metadata = dep.metadata
        spec = dep.spec
        status = dep.status

        # Extract security-relevant configuration
        pod_spec = spec.template.spec
        security_context = self._extract_pod_security_context(pod_spec)
        container_security = self._extract_container_security(pod_spec.containers)

        # Computed properties for policy checks
        strategy_type = spec.strategy.type if spec.strategy else "RollingUpdate"

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "replicas": spec.replicas,
            "available_replicas": status.available_replicas if status else 0,
            "ready_replicas": status.ready_replicas if status else 0,
            "selector": spec.selector.match_labels if spec.selector else {},
            "strategy": strategy_type,
            "strategy_type": strategy_type,
            "pod_security_context": security_context,
            "container_security": container_security,
            "service_account": pod_spec.service_account_name,
            "automount_service_account_token": pod_spec.automount_service_account_token,
            "host_network": pod_spec.host_network or False,
            "host_pid": pod_spec.host_pid or False,
            "host_ipc": pod_spec.host_ipc or False,
            "containers": self._extract_container_info(pod_spec.containers),
            "init_containers": self._extract_container_info(pod_spec.init_containers or []),
            "volumes": self._extract_volume_info(pod_spec.volumes or []),
            "node_selector": dict(pod_spec.node_selector or {}),
            "tolerations": self._extract_tolerations(pod_spec.tolerations or []),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/deployment/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_deployment",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_pods(self, namespace: str) -> Iterator[Asset]:
        """Collect Pod resources."""
        try:
            pods = self._core_v1.list_namespaced_pod(namespace)
            for pod in pods.items:
                yield self._pod_to_asset(pod, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list pods in {namespace}: {e.reason}")

    def _pod_to_asset(self, pod: Any, namespace: str) -> Asset:
        """Convert Pod to Asset."""
        metadata = pod.metadata
        spec = pod.spec
        status = pod.status

        security_context = self._extract_pod_security_context(spec)
        container_security = self._extract_container_security(spec.containers)
        containers_info = self._extract_container_info(spec.containers)
        volumes_info = self._extract_volume_info(spec.volumes or [])

        # Compute security summary flags for easy policy checking
        has_privileged_container = any(
            cs.get("security_context", {}).get("privileged", False)
            for cs in container_security
            if cs.get("security_context")
        )
        has_privilege_escalation = any(
            cs.get("security_context", {}).get("allow_privilege_escalation", True)
            for cs in container_security
            if cs.get("security_context")
        )
        has_read_only_root_fs = all(
            cs.get("security_context", {}).get("read_only_root_filesystem", False)
            for cs in container_security
            if cs.get("security_context")
        ) if container_security else False
        has_capabilities_dropped = all(
            "ALL" in cs.get("security_context", {}).get("capabilities", {}).get("drop", [])
            for cs in container_security
            if cs.get("security_context")
        ) if container_security else False
        has_host_path_volume = any(v.get("type") == "hostPath" for v in volumes_info)
        has_resource_limits = all(
            c.get("resources", {}).get("limits", {}).get("cpu") and
            c.get("resources", {}).get("limits", {}).get("memory")
            for c in containers_info
        ) if containers_info else False
        uses_latest_tag = any(
            c.get("image", "").endswith(":latest") or ":" not in c.get("image", "")
            for c in containers_info
        )
        uses_image_digests = all(
            "@sha256:" in c.get("image", "")
            for c in containers_info
        ) if containers_info else False
        has_liveness_probe = all(c.get("liveness_probe", False) for c in containers_info) if containers_info else False
        has_readiness_probe = all(c.get("readiness_probe", False) for c in containers_info) if containers_info else False

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "phase": status.phase if status else "Unknown",
            "pod_ip": status.pod_ip if status else None,
            "host_ip": status.host_ip if status else None,
            "node_name": spec.node_name,
            "pod_security_context": security_context,
            "container_security": container_security,
            "service_account": spec.service_account_name,
            "automount_service_account_token": spec.automount_service_account_token,
            "host_network": spec.host_network or False,
            "host_pid": spec.host_pid or False,
            "host_ipc": spec.host_ipc or False,
            "containers": containers_info,
            "init_containers": self._extract_container_info(spec.init_containers or []),
            "volumes": volumes_info,
            "owner_references": self._extract_owner_refs(metadata.owner_references or []),
            "restart_policy": spec.restart_policy,
            "priority_class_name": spec.priority_class_name,
            # Security summary flags for policy checking
            "has_privileged_container": has_privileged_container,
            "has_privilege_escalation": has_privilege_escalation,
            "has_read_only_root_fs": has_read_only_root_fs,
            "has_capabilities_dropped": has_capabilities_dropped,
            "has_host_path_volume": has_host_path_volume,
            "has_resource_limits": has_resource_limits,
            "uses_latest_tag": uses_latest_tag,
            "uses_image_digests": uses_image_digests,
            "has_liveness_probe": has_liveness_probe,
            "has_readiness_probe": has_readiness_probe,
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/pod/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_pod",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_services(self, namespace: str) -> Iterator[Asset]:
        """Collect Service resources."""
        try:
            services = self._core_v1.list_namespaced_service(namespace)
            for svc in services.items:
                yield self._service_to_asset(svc, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list services in {namespace}: {e.reason}")

    def _service_to_asset(self, svc: Any, namespace: str) -> Asset:
        """Convert Service to Asset."""
        metadata = svc.metadata
        spec = svc.spec
        status = svc.status

        # Determine network exposure
        network_exposure = NETWORK_EXPOSURE_INTERNAL
        if spec.type == "LoadBalancer":
            network_exposure = NETWORK_EXPOSURE_INTERNET
        elif spec.type == "NodePort":
            # NodePort could be internet-facing depending on node network
            network_exposure = NETWORK_EXPOSURE_INTERNET

        # Get external IPs if any
        external_ips = []
        if spec.external_i_ps:
            external_ips = list(spec.external_i_ps)
        if status and status.load_balancer and status.load_balancer.ingress:
            for ingress in status.load_balancer.ingress:
                if ingress.ip:
                    external_ips.append(ingress.ip)
                if ingress.hostname:
                    external_ips.append(ingress.hostname)

        # Computed properties for policy checks
        has_selector = bool(spec.selector)

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "type": spec.type,
            "cluster_ip": spec.cluster_ip,
            "external_ips": external_ips,
            "ports": self._extract_service_ports(spec.ports or []),
            "selector": dict(spec.selector or {}),
            "has_selector": has_selector,
            "session_affinity": spec.session_affinity,
            "load_balancer_ip": spec.load_balancer_ip,
            "load_balancer_source_ranges": list(spec.load_balancer_source_ranges or []),
            "external_traffic_policy": spec.external_traffic_policy,
            "internal_traffic_policy": spec.internal_traffic_policy,
            "ip_families": list(spec.ip_families or []),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/service/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_service",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=network_exposure,
        )

    def _collect_daemonsets(self, namespace: str) -> Iterator[Asset]:
        """Collect DaemonSet resources."""
        try:
            daemonsets = self._apps_v1.list_namespaced_daemon_set(namespace)
            for ds in daemonsets.items:
                yield self._daemonset_to_asset(ds, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list daemonsets in {namespace}: {e.reason}")

    def _daemonset_to_asset(self, ds: Any, namespace: str) -> Asset:
        """Convert DaemonSet to Asset."""
        metadata = ds.metadata
        spec = ds.spec
        status = ds.status
        pod_spec = spec.template.spec

        security_context = self._extract_pod_security_context(pod_spec)
        container_security = self._extract_container_security(pod_spec.containers)

        # Computed properties for policy checks
        update_strategy_type = spec.update_strategy.type if spec.update_strategy else "RollingUpdate"

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "desired_number_scheduled": status.desired_number_scheduled if status else 0,
            "current_number_scheduled": status.current_number_scheduled if status else 0,
            "number_ready": status.number_ready if status else 0,
            "selector": spec.selector.match_labels if spec.selector else {},
            "update_strategy": update_strategy_type,
            "update_strategy_type": update_strategy_type,
            "pod_security_context": security_context,
            "container_security": container_security,
            "service_account": pod_spec.service_account_name,
            "automount_service_account_token": pod_spec.automount_service_account_token,
            "host_network": pod_spec.host_network or False,
            "host_pid": pod_spec.host_pid or False,
            "host_ipc": pod_spec.host_ipc or False,
            "containers": self._extract_container_info(pod_spec.containers),
            "volumes": self._extract_volume_info(pod_spec.volumes or []),
            "node_selector": dict(pod_spec.node_selector or {}),
            "tolerations": self._extract_tolerations(pod_spec.tolerations or []),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/daemonset/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_daemonset",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_statefulsets(self, namespace: str) -> Iterator[Asset]:
        """Collect StatefulSet resources."""
        try:
            statefulsets = self._apps_v1.list_namespaced_stateful_set(namespace)
            for sts in statefulsets.items:
                yield self._statefulset_to_asset(sts, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list statefulsets in {namespace}: {e.reason}")

    def _statefulset_to_asset(self, sts: Any, namespace: str) -> Asset:
        """Convert StatefulSet to Asset."""
        metadata = sts.metadata
        spec = sts.spec
        status = sts.status
        pod_spec = spec.template.spec

        security_context = self._extract_pod_security_context(pod_spec)
        container_security = self._extract_container_security(pod_spec.containers)

        # Computed properties for policy checks
        volume_claim_templates = self._extract_pvc_templates(spec.volume_claim_templates or [])
        has_volume_claim_templates = len(volume_claim_templates) > 0

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "replicas": spec.replicas,
            "ready_replicas": status.ready_replicas if status else 0,
            "current_replicas": status.current_replicas if status else 0,
            "selector": spec.selector.match_labels if spec.selector else {},
            "service_name": spec.service_name,
            "pod_management_policy": spec.pod_management_policy,
            "update_strategy": spec.update_strategy.type if spec.update_strategy else "RollingUpdate",
            "pod_security_context": security_context,
            "container_security": container_security,
            "service_account": pod_spec.service_account_name,
            "automount_service_account_token": pod_spec.automount_service_account_token,
            "host_network": pod_spec.host_network or False,
            "host_pid": pod_spec.host_pid or False,
            "host_ipc": pod_spec.host_ipc or False,
            "containers": self._extract_container_info(pod_spec.containers),
            "volumes": self._extract_volume_info(pod_spec.volumes or []),
            "volume_claim_templates": volume_claim_templates,
            "has_volume_claim_templates": has_volume_claim_templates,
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/statefulset/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_statefulset",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_replicasets(self, namespace: str) -> Iterator[Asset]:
        """Collect ReplicaSet resources."""
        try:
            replicasets = self._apps_v1.list_namespaced_replica_set(namespace)
            for rs in replicasets.items:
                # Skip ReplicaSets owned by Deployments (they're managed)
                if rs.metadata.owner_references:
                    has_deployment_owner = any(
                        ref.kind == "Deployment" for ref in rs.metadata.owner_references
                    )
                    if has_deployment_owner:
                        continue
                yield self._replicaset_to_asset(rs, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list replicasets in {namespace}: {e.reason}")

    def _replicaset_to_asset(self, rs: Any, namespace: str) -> Asset:
        """Convert ReplicaSet to Asset."""
        metadata = rs.metadata
        spec = rs.spec
        status = rs.status
        pod_spec = spec.template.spec if spec.template else None

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "replicas": spec.replicas,
            "ready_replicas": status.ready_replicas if status else 0,
            "available_replicas": status.available_replicas if status else 0,
            "selector": spec.selector.match_labels if spec.selector else {},
            "owner_references": self._extract_owner_refs(metadata.owner_references or []),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        if pod_spec:
            raw_config["pod_security_context"] = self._extract_pod_security_context(pod_spec)
            raw_config["container_security"] = self._extract_container_security(pod_spec.containers)
            raw_config["containers"] = self._extract_container_info(pod_spec.containers)

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/replicaset/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_replicaset",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_jobs(self, namespace: str) -> Iterator[Asset]:
        """Collect Job resources."""
        try:
            jobs = self._batch_v1.list_namespaced_job(namespace)
            for job in jobs.items:
                yield self._job_to_asset(job, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list jobs in {namespace}: {e.reason}")

    def _job_to_asset(self, job: Any, namespace: str) -> Asset:
        """Convert Job to Asset."""
        metadata = job.metadata
        spec = job.spec
        status = job.status
        pod_spec = spec.template.spec

        security_context = self._extract_pod_security_context(pod_spec)
        container_security = self._extract_container_security(pod_spec.containers)

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "parallelism": spec.parallelism,
            "completions": spec.completions,
            "backoff_limit": spec.backoff_limit,
            "active_deadline_seconds": spec.active_deadline_seconds,
            "ttl_seconds_after_finished": spec.ttl_seconds_after_finished,
            "succeeded": status.succeeded if status else 0,
            "failed": status.failed if status else 0,
            "active": status.active if status else 0,
            "pod_security_context": security_context,
            "container_security": container_security,
            "service_account": pod_spec.service_account_name,
            "automount_service_account_token": pod_spec.automount_service_account_token,
            "containers": self._extract_container_info(pod_spec.containers),
            "restart_policy": pod_spec.restart_policy,
            "owner_references": self._extract_owner_refs(metadata.owner_references or []),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/job/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_job",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_cronjobs(self, namespace: str) -> Iterator[Asset]:
        """Collect CronJob resources."""
        try:
            cronjobs = self._batch_v1.list_namespaced_cron_job(namespace)
            for cj in cronjobs.items:
                yield self._cronjob_to_asset(cj, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list cronjobs in {namespace}: {e.reason}")

    def _cronjob_to_asset(self, cj: Any, namespace: str) -> Asset:
        """Convert CronJob to Asset."""
        metadata = cj.metadata
        spec = cj.spec
        status = cj.status
        job_spec = spec.job_template.spec
        pod_spec = job_spec.template.spec

        security_context = self._extract_pod_security_context(pod_spec)
        container_security = self._extract_container_security(pod_spec.containers)

        # Computed properties for policy checks
        has_history_limits = (
            spec.successful_jobs_history_limit is not None or
            spec.failed_jobs_history_limit is not None
        )

        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "schedule": spec.schedule,
            "timezone": spec.time_zone,
            "concurrency_policy": spec.concurrency_policy,
            "has_history_limits": has_history_limits,
            "suspend": spec.suspend or False,
            "successful_jobs_history_limit": spec.successful_jobs_history_limit,
            "failed_jobs_history_limit": spec.failed_jobs_history_limit,
            "starting_deadline_seconds": spec.starting_deadline_seconds,
            "last_schedule_time": (
                status.last_schedule_time.isoformat()
                if status and status.last_schedule_time
                else None
            ),
            "last_successful_time": (
                status.last_successful_time.isoformat()
                if status and status.last_successful_time
                else None
            ),
            "active_jobs": len(status.active or []) if status else 0,
            "pod_security_context": security_context,
            "container_security": container_security,
            "service_account": pod_spec.service_account_name,
            "containers": self._extract_container_info(pod_spec.containers),
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/cronjob/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_cronjob",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    def _collect_configmaps(self, namespace: str) -> Iterator[Asset]:
        """Collect ConfigMap resources (metadata only)."""
        try:
            configmaps = self._core_v1.list_namespaced_config_map(namespace)
            for cm in configmaps.items:
                yield self._configmap_to_asset(cm, namespace)
        except ApiException as e:
            logger.warning(f"Failed to list configmaps in {namespace}: {e.reason}")

    def _configmap_to_asset(self, cm: Any, namespace: str) -> Asset:
        """Convert ConfigMap to Asset (metadata only, not data)."""
        metadata = cm.metadata

        # Only collect metadata, not actual data (could contain secrets)
        raw_config = {
            "name": metadata.name,
            "namespace": namespace,
            "uid": metadata.uid,
            "labels": dict(metadata.labels or {}),
            "annotations": dict(metadata.annotations or {}),
            "data_keys": list((cm.data or {}).keys()),
            "binary_data_keys": list((cm.binary_data or {}).keys()),
            "immutable": cm.immutable or False,
            "creation_timestamp": (
                metadata.creation_timestamp.isoformat()
                if metadata.creation_timestamp
                else None
            ),
        }

        return Asset(
            id=f"k8s://{self.cluster_name}/{namespace}/configmap/{metadata.name}",
            cloud_provider="kubernetes",
            name=metadata.name,
            resource_type="k8s_configmap",
            region=self.cluster_name,
            account_id=self.cluster_name,
            tags=dict(metadata.labels or {}),
            raw_config=raw_config,
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
        )

    # Helper methods for extracting security-relevant configuration

    def _extract_pod_security_context(self, pod_spec: Any) -> dict[str, Any]:
        """Extract pod-level security context."""
        if not pod_spec.security_context:
            return {}

        sc = pod_spec.security_context
        return {
            "run_as_user": sc.run_as_user,
            "run_as_group": sc.run_as_group,
            "run_as_non_root": sc.run_as_non_root,
            "fs_group": sc.fs_group,
            "supplemental_groups": list(sc.supplemental_groups or []),
            "seccomp_profile": (
                {"type": sc.seccomp_profile.type} if sc.seccomp_profile else None
            ),
            "sysctls": [
                {"name": s.name, "value": s.value} for s in (sc.sysctls or [])
            ],
        }

    def _extract_container_security(self, containers: list[Any]) -> list[dict[str, Any]]:
        """Extract container-level security contexts."""
        results = []
        for c in containers:
            sc = c.security_context
            if not sc:
                results.append({"name": c.name, "security_context": None})
                continue

            results.append({
                "name": c.name,
                "security_context": {
                    "privileged": sc.privileged or False,
                    "allow_privilege_escalation": sc.allow_privilege_escalation,
                    "run_as_user": sc.run_as_user,
                    "run_as_group": sc.run_as_group,
                    "run_as_non_root": sc.run_as_non_root,
                    "read_only_root_filesystem": sc.read_only_root_filesystem or False,
                    "capabilities": {
                        "add": list(sc.capabilities.add or []) if sc.capabilities else [],
                        "drop": list(sc.capabilities.drop or []) if sc.capabilities else [],
                    },
                    "seccomp_profile": (
                        {"type": sc.seccomp_profile.type} if sc.seccomp_profile else None
                    ),
                },
            })
        return results

    def _extract_container_info(self, containers: list[Any]) -> list[dict[str, Any]]:
        """Extract container configuration."""
        results = []
        for c in containers:
            results.append({
                "name": c.name,
                "image": c.image,
                "image_pull_policy": c.image_pull_policy,
                "ports": [
                    {
                        "container_port": p.container_port,
                        "protocol": p.protocol,
                        "host_port": p.host_port,
                    }
                    for p in (c.ports or [])
                ],
                "env_vars": [e.name for e in (c.env or [])],  # Names only, not values
                "env_from": [
                    {
                        "type": "configMapRef" if ef.config_map_ref else "secretRef",
                        "name": (
                            ef.config_map_ref.name
                            if ef.config_map_ref
                            else ef.secret_ref.name if ef.secret_ref else None
                        ),
                    }
                    for ef in (c.env_from or [])
                ],
                "resources": {
                    "requests": dict(c.resources.requests or {}) if c.resources else {},
                    "limits": dict(c.resources.limits or {}) if c.resources else {},
                },
                "volume_mounts": [
                    {
                        "name": vm.name,
                        "mount_path": vm.mount_path,
                        "read_only": vm.read_only or False,
                        "sub_path": vm.sub_path,
                    }
                    for vm in (c.volume_mounts or [])
                ],
                "liveness_probe": bool(c.liveness_probe),
                "readiness_probe": bool(c.readiness_probe),
                "startup_probe": bool(c.startup_probe),
            })
        return results

    def _extract_volume_info(self, volumes: list[Any]) -> list[dict[str, Any]]:
        """Extract volume configuration."""
        results = []
        for v in volumes:
            vol_info: dict[str, Any] = {"name": v.name}

            if v.secret:
                vol_info["type"] = "secret"
                vol_info["secret_name"] = v.secret.secret_name
            elif v.config_map:
                vol_info["type"] = "configMap"
                vol_info["config_map_name"] = v.config_map.name
            elif v.persistent_volume_claim:
                vol_info["type"] = "persistentVolumeClaim"
                vol_info["claim_name"] = v.persistent_volume_claim.claim_name
            elif v.host_path:
                vol_info["type"] = "hostPath"
                vol_info["path"] = v.host_path.path
                vol_info["host_path_type"] = v.host_path.type
            elif v.empty_dir:
                vol_info["type"] = "emptyDir"
                vol_info["medium"] = v.empty_dir.medium
            elif v.projected:
                vol_info["type"] = "projected"
                vol_info["sources"] = len(v.projected.sources or [])
            elif v.downward_api:
                vol_info["type"] = "downwardAPI"
            elif v.csi:
                vol_info["type"] = "csi"
                vol_info["driver"] = v.csi.driver
            else:
                vol_info["type"] = "other"

            results.append(vol_info)
        return results

    def _extract_service_ports(self, ports: list[Any]) -> list[dict[str, Any]]:
        """Extract service port configuration."""
        return [
            {
                "name": p.name,
                "port": p.port,
                "target_port": str(p.target_port) if p.target_port else None,
                "node_port": p.node_port,
                "protocol": p.protocol,
            }
            for p in ports
        ]

    def _extract_tolerations(self, tolerations: list[Any]) -> list[dict[str, Any]]:
        """Extract pod tolerations."""
        return [
            {
                "key": t.key,
                "operator": t.operator,
                "value": t.value,
                "effect": t.effect,
                "toleration_seconds": t.toleration_seconds,
            }
            for t in tolerations
        ]

    def _extract_owner_refs(self, owner_refs: list[Any]) -> list[dict[str, str]]:
        """Extract owner references."""
        return [
            {
                "api_version": ref.api_version,
                "kind": ref.kind,
                "name": ref.name,
                "uid": ref.uid,
            }
            for ref in owner_refs
        ]

    def _extract_pvc_templates(self, templates: list[Any]) -> list[dict[str, Any]]:
        """Extract PVC templates for StatefulSets."""
        results = []
        for t in templates:
            results.append({
                "name": t.metadata.name if t.metadata else "unknown",
                "storage_class": t.spec.storage_class_name if t.spec else None,
                "access_modes": list(t.spec.access_modes or []) if t.spec else [],
                "storage": (
                    t.spec.resources.requests.get("storage")
                    if t.spec and t.spec.resources and t.spec.resources.requests
                    else None
                ),
            })
        return results
