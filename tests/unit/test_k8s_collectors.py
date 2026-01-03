"""
Unit tests for Kubernetes collectors.

Tests cover:
- K8sConfigCollector initialization and collection
- K8sRBACCollector initialization and collection
- Pod security context extraction
- Container security configuration
- RBAC risk analysis
- Service network exposure detection
- Error handling for API exceptions
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from stance.models import (
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)


# Mock the kubernetes module before importing collectors
@pytest.fixture(autouse=True)
def mock_kubernetes():
    """Mock the kubernetes module for all tests."""
    with patch.dict("sys.modules", {
        "kubernetes": MagicMock(),
        "kubernetes.client": MagicMock(),
        "kubernetes.client.rest": MagicMock(),
        "kubernetes.config": MagicMock(),
    }):
        # Set up the K8S_AVAILABLE flag
        import stance.collectors.k8s_config as k8s_config_module
        import stance.collectors.k8s_rbac as k8s_rbac_module
        import stance.collectors.k8s_network as k8s_network_module

        k8s_config_module.K8S_AVAILABLE = True
        k8s_rbac_module.K8S_AVAILABLE = True
        k8s_network_module.K8S_AVAILABLE = True

        yield


class TestK8sConfigCollector:
    """Tests for K8sConfigCollector."""

    def test_k8s_config_collector_init(self, mock_kubernetes):
        """Test K8sConfigCollector can be initialized."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()
        assert collector.collector_name == "k8s_config"
        assert "k8s_deployment" in collector.resource_types
        assert "k8s_pod" in collector.resource_types
        assert "k8s_service" in collector.resource_types
        assert "k8s_daemonset" in collector.resource_types
        assert "k8s_statefulset" in collector.resource_types
        assert "k8s_job" in collector.resource_types
        assert "k8s_cronjob" in collector.resource_types
        assert "k8s_configmap" in collector.resource_types
        assert "k8s_namespace" in collector.resource_types

    def test_k8s_config_collector_with_kubeconfig(self, mock_kubernetes):
        """Test initialization with custom kubeconfig."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector(
            kubeconfig="/path/to/kubeconfig",
            context="test-context",
        )
        assert collector._kubeconfig == "/path/to/kubeconfig"
        assert collector._context == "test-context"

    def test_k8s_config_collector_with_namespaces(self, mock_kubernetes):
        """Test initialization with specific namespaces."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector(namespaces=["default", "kube-system"])
        assert collector._namespaces == ["default", "kube-system"]

    def test_k8s_config_collector_in_cluster(self, mock_kubernetes):
        """Test initialization for in-cluster mode."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector(in_cluster=True)
        assert collector._in_cluster is True

    def test_extract_pod_security_context(self, mock_kubernetes):
        """Test extraction of pod security context."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        # Mock pod spec with security context
        mock_pod_spec = MagicMock()
        mock_sc = MagicMock()
        mock_sc.run_as_user = 1000
        mock_sc.run_as_group = 1000
        mock_sc.run_as_non_root = True
        mock_sc.fs_group = 2000
        mock_sc.supplemental_groups = [3000]
        mock_sc.seccomp_profile = MagicMock(type="RuntimeDefault")
        mock_sc.sysctls = []
        mock_pod_spec.security_context = mock_sc

        result = collector._extract_pod_security_context(mock_pod_spec)

        assert result["run_as_user"] == 1000
        assert result["run_as_group"] == 1000
        assert result["run_as_non_root"] is True
        assert result["fs_group"] == 2000
        assert result["supplemental_groups"] == [3000]
        assert result["seccomp_profile"]["type"] == "RuntimeDefault"

    def test_extract_pod_security_context_empty(self, mock_kubernetes):
        """Test extraction when no security context is set."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        mock_pod_spec = MagicMock()
        mock_pod_spec.security_context = None

        result = collector._extract_pod_security_context(mock_pod_spec)
        assert result == {}

    def test_extract_container_security(self, mock_kubernetes):
        """Test extraction of container security contexts."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        # Mock container with security context
        mock_container = MagicMock()
        mock_container.name = "test-container"
        mock_sc = MagicMock()
        mock_sc.privileged = False
        mock_sc.allow_privilege_escalation = False
        mock_sc.run_as_user = 1000
        mock_sc.run_as_group = 1000
        mock_sc.run_as_non_root = True
        mock_sc.read_only_root_filesystem = True
        mock_caps = MagicMock()
        mock_caps.add = ["NET_BIND_SERVICE"]
        mock_caps.drop = ["ALL"]
        mock_sc.capabilities = mock_caps
        mock_sc.seccomp_profile = None
        mock_container.security_context = mock_sc

        result = collector._extract_container_security([mock_container])

        assert len(result) == 1
        assert result[0]["name"] == "test-container"
        assert result[0]["security_context"]["privileged"] is False
        assert result[0]["security_context"]["allow_privilege_escalation"] is False
        assert result[0]["security_context"]["read_only_root_filesystem"] is True
        assert "ALL" in result[0]["security_context"]["capabilities"]["drop"]
        assert "NET_BIND_SERVICE" in result[0]["security_context"]["capabilities"]["add"]

    def test_extract_container_security_privileged(self, mock_kubernetes):
        """Test detection of privileged containers."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        mock_container = MagicMock()
        mock_container.name = "privileged-container"
        mock_sc = MagicMock()
        mock_sc.privileged = True
        mock_sc.allow_privilege_escalation = True
        mock_sc.run_as_user = None
        mock_sc.run_as_group = None
        mock_sc.run_as_non_root = None
        mock_sc.read_only_root_filesystem = False
        mock_sc.capabilities = None
        mock_sc.seccomp_profile = None
        mock_container.security_context = mock_sc

        result = collector._extract_container_security([mock_container])

        assert result[0]["security_context"]["privileged"] is True
        assert result[0]["security_context"]["allow_privilege_escalation"] is True

    def test_extract_container_info(self, mock_kubernetes):
        """Test extraction of container configuration."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        mock_container = MagicMock()
        mock_container.name = "web-app"
        mock_container.image = "nginx:latest"
        mock_container.image_pull_policy = "Always"

        mock_port = MagicMock()
        mock_port.container_port = 80
        mock_port.protocol = "TCP"
        mock_port.host_port = None
        mock_container.ports = [mock_port]

        mock_env = MagicMock()
        mock_env.name = "LOG_LEVEL"
        mock_container.env = [mock_env]
        mock_container.env_from = []

        mock_resources = MagicMock()
        mock_resources.requests = {"cpu": "100m", "memory": "128Mi"}
        mock_resources.limits = {"cpu": "500m", "memory": "512Mi"}
        mock_container.resources = mock_resources

        mock_container.volume_mounts = []
        mock_container.liveness_probe = MagicMock()
        mock_container.readiness_probe = MagicMock()
        mock_container.startup_probe = None

        result = collector._extract_container_info([mock_container])

        assert len(result) == 1
        assert result[0]["name"] == "web-app"
        assert result[0]["image"] == "nginx:latest"
        assert result[0]["image_pull_policy"] == "Always"
        assert result[0]["ports"][0]["container_port"] == 80
        assert "LOG_LEVEL" in result[0]["env_vars"]
        assert result[0]["resources"]["limits"]["memory"] == "512Mi"
        assert result[0]["liveness_probe"] is True
        assert result[0]["readiness_probe"] is True
        assert result[0]["startup_probe"] is False

    def test_extract_volume_info_hostpath(self, mock_kubernetes):
        """Test extraction of hostPath volumes."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        mock_volume = MagicMock()
        mock_volume.name = "host-vol"
        mock_volume.secret = None
        mock_volume.config_map = None
        mock_volume.persistent_volume_claim = None
        mock_volume.host_path = MagicMock(path="/var/log", type="Directory")
        mock_volume.empty_dir = None
        mock_volume.projected = None
        mock_volume.downward_api = None
        mock_volume.csi = None

        result = collector._extract_volume_info([mock_volume])

        assert len(result) == 1
        assert result[0]["name"] == "host-vol"
        assert result[0]["type"] == "hostPath"
        assert result[0]["path"] == "/var/log"

    def test_extract_volume_info_secret(self, mock_kubernetes):
        """Test extraction of secret volumes."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        mock_volume = MagicMock()
        mock_volume.name = "secret-vol"
        mock_volume.secret = MagicMock(secret_name="my-secret")
        mock_volume.config_map = None
        mock_volume.persistent_volume_claim = None
        mock_volume.host_path = None
        mock_volume.empty_dir = None
        mock_volume.projected = None
        mock_volume.downward_api = None
        mock_volume.csi = None

        result = collector._extract_volume_info([mock_volume])

        assert result[0]["type"] == "secret"
        assert result[0]["secret_name"] == "my-secret"

    def test_service_network_exposure_loadbalancer(self, mock_kubernetes):
        """Test that LoadBalancer services are marked as internet-facing."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()
        collector._cluster_name = "test-cluster"

        mock_svc = MagicMock()
        mock_svc.metadata.name = "web-lb"
        mock_svc.metadata.uid = "svc-123"
        mock_svc.metadata.namespace = "default"
        mock_svc.metadata.labels = {}
        mock_svc.metadata.annotations = {}
        mock_svc.metadata.creation_timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_svc.spec.type = "LoadBalancer"
        mock_svc.spec.cluster_ip = "10.0.0.1"
        mock_svc.spec.external_i_ps = None
        mock_svc.spec.ports = []
        mock_svc.spec.selector = {}
        mock_svc.spec.session_affinity = "None"
        mock_svc.spec.load_balancer_ip = None
        mock_svc.spec.load_balancer_source_ranges = None
        mock_svc.spec.external_traffic_policy = "Cluster"
        mock_svc.spec.internal_traffic_policy = "Cluster"
        mock_svc.spec.ip_families = ["IPv4"]
        mock_svc.status = MagicMock()
        mock_svc.status.load_balancer = None

        asset = collector._service_to_asset(mock_svc, "default")

        assert asset.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_service_network_exposure_nodeport(self, mock_kubernetes):
        """Test that NodePort services are marked as internet-facing."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()
        collector._cluster_name = "test-cluster"

        mock_svc = MagicMock()
        mock_svc.metadata.name = "web-np"
        mock_svc.metadata.uid = "svc-456"
        mock_svc.metadata.namespace = "default"
        mock_svc.metadata.labels = {}
        mock_svc.metadata.annotations = {}
        mock_svc.metadata.creation_timestamp = None
        mock_svc.spec.type = "NodePort"
        mock_svc.spec.cluster_ip = "10.0.0.2"
        mock_svc.spec.external_i_ps = None
        mock_svc.spec.ports = []
        mock_svc.spec.selector = {}
        mock_svc.spec.session_affinity = "None"
        mock_svc.spec.load_balancer_ip = None
        mock_svc.spec.load_balancer_source_ranges = None
        mock_svc.spec.external_traffic_policy = "Cluster"
        mock_svc.spec.internal_traffic_policy = "Cluster"
        mock_svc.spec.ip_families = ["IPv4"]
        mock_svc.status = None

        asset = collector._service_to_asset(mock_svc, "default")

        assert asset.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_service_network_exposure_clusterip(self, mock_kubernetes):
        """Test that ClusterIP services are marked as internal."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()
        collector._cluster_name = "test-cluster"

        mock_svc = MagicMock()
        mock_svc.metadata.name = "internal-svc"
        mock_svc.metadata.uid = "svc-789"
        mock_svc.metadata.namespace = "default"
        mock_svc.metadata.labels = {}
        mock_svc.metadata.annotations = {}
        mock_svc.metadata.creation_timestamp = None
        mock_svc.spec.type = "ClusterIP"
        mock_svc.spec.cluster_ip = "10.0.0.3"
        mock_svc.spec.external_i_ps = None
        mock_svc.spec.ports = []
        mock_svc.spec.selector = {}
        mock_svc.spec.session_affinity = "None"
        mock_svc.spec.load_balancer_ip = None
        mock_svc.spec.load_balancer_source_ranges = None
        mock_svc.spec.external_traffic_policy = None
        mock_svc.spec.internal_traffic_policy = "Cluster"
        mock_svc.spec.ip_families = ["IPv4"]
        mock_svc.status = None

        asset = collector._service_to_asset(mock_svc, "default")

        assert asset.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_extract_service_ports(self, mock_kubernetes):
        """Test extraction of service ports."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        mock_port = MagicMock()
        mock_port.name = "http"
        mock_port.port = 80
        mock_port.target_port = 8080
        mock_port.node_port = 30080
        mock_port.protocol = "TCP"

        result = collector._extract_service_ports([mock_port])

        assert len(result) == 1
        assert result[0]["name"] == "http"
        assert result[0]["port"] == 80
        assert result[0]["target_port"] == "8080"
        assert result[0]["node_port"] == 30080

    def test_extract_tolerations(self, mock_kubernetes):
        """Test extraction of pod tolerations."""
        from stance.collectors.k8s_config import K8sConfigCollector

        collector = K8sConfigCollector()

        mock_toleration = MagicMock()
        mock_toleration.key = "node-role.kubernetes.io/master"
        mock_toleration.operator = "Exists"
        mock_toleration.value = None
        mock_toleration.effect = "NoSchedule"
        mock_toleration.toleration_seconds = None

        result = collector._extract_tolerations([mock_toleration])

        assert len(result) == 1
        assert result[0]["key"] == "node-role.kubernetes.io/master"
        assert result[0]["effect"] == "NoSchedule"


class TestK8sRBACCollector:
    """Tests for K8sRBACCollector."""

    def test_k8s_rbac_collector_init(self, mock_kubernetes):
        """Test K8sRBACCollector can be initialized."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()
        assert collector.collector_name == "k8s_rbac"
        assert "k8s_role" in collector.resource_types
        assert "k8s_cluster_role" in collector.resource_types
        assert "k8s_role_binding" in collector.resource_types
        assert "k8s_cluster_role_binding" in collector.resource_types
        assert "k8s_service_account" in collector.resource_types

    def test_analyze_rules_wildcard_all(self, mock_kubernetes):
        """Test risk analysis with full wildcard access."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()

        mock_rule = MagicMock()
        mock_rule.resources = ["*"]
        mock_rule.verbs = ["*"]
        mock_rule.api_groups = [""]
        mock_rule.resource_names = []
        mock_rule.non_resource_ur_ls = []

        result = collector._analyze_rules([mock_rule])

        assert result["risk_score"] == 100
        assert result["has_wildcard_resources"] is True
        assert result["has_wildcard_verbs"] is True
        assert result["is_overly_permissive"] is True

    def test_analyze_rules_secrets_access(self, mock_kubernetes):
        """Test risk analysis with secrets access."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()

        mock_rule = MagicMock()
        mock_rule.resources = ["secrets"]
        mock_rule.verbs = ["get", "list", "create", "delete"]
        mock_rule.api_groups = [""]
        mock_rule.resource_names = []
        mock_rule.non_resource_ur_ls = []

        result = collector._analyze_rules([mock_rule])

        assert result["has_high_risk_resources"] is True
        assert result["has_high_risk_verbs"] is True
        assert len(result["high_risk_combinations"]) > 0

    def test_analyze_rules_pod_exec(self, mock_kubernetes):
        """Test risk analysis with pods/exec access."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()

        mock_rule = MagicMock()
        mock_rule.resources = ["pods/exec"]
        mock_rule.verbs = ["create"]
        mock_rule.api_groups = [""]
        mock_rule.resource_names = []
        mock_rule.non_resource_ur_ls = []

        result = collector._analyze_rules([mock_rule])

        assert result["has_high_risk_resources"] is True
        assert result["has_high_risk_verbs"] is True

    def test_analyze_rules_limited_permissions(self, mock_kubernetes):
        """Test risk analysis with limited permissions."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()

        mock_rule = MagicMock()
        mock_rule.resources = ["pods", "services"]
        mock_rule.verbs = ["get", "list", "watch"]
        mock_rule.api_groups = [""]
        mock_rule.resource_names = []
        mock_rule.non_resource_ur_ls = []

        result = collector._analyze_rules([mock_rule])

        assert result["risk_score"] == 10  # Limited permissions
        assert result["has_wildcard_resources"] is False
        assert result["has_wildcard_verbs"] is False
        assert result["is_overly_permissive"] is False

    def test_extract_rules(self, mock_kubernetes):
        """Test extraction of RBAC rules."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()

        mock_rule = MagicMock()
        mock_rule.api_groups = ["", "apps"]
        mock_rule.resources = ["pods", "deployments"]
        mock_rule.resource_names = ["specific-pod"]
        mock_rule.verbs = ["get", "list"]
        mock_rule.non_resource_ur_ls = []

        result = collector._extract_rules([mock_rule])

        assert len(result) == 1
        assert "" in result[0]["api_groups"]
        assert "apps" in result[0]["api_groups"]
        assert "pods" in result[0]["resources"]
        assert "deployments" in result[0]["resources"]
        assert "specific-pod" in result[0]["resource_names"]
        assert "get" in result[0]["verbs"]

    def test_extract_subjects(self, mock_kubernetes):
        """Test extraction of binding subjects."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()

        mock_user_subject = MagicMock()
        mock_user_subject.kind = "User"
        mock_user_subject.name = "jane@example.com"
        mock_user_subject.namespace = None
        mock_user_subject.api_group = "rbac.authorization.k8s.io"

        mock_sa_subject = MagicMock()
        mock_sa_subject.kind = "ServiceAccount"
        mock_sa_subject.name = "my-sa"
        mock_sa_subject.namespace = "default"
        mock_sa_subject.api_group = ""

        result = collector._extract_subjects([mock_user_subject, mock_sa_subject])

        assert len(result) == 2
        assert result[0]["kind"] == "User"
        assert result[0]["name"] == "jane@example.com"
        assert result[1]["kind"] == "ServiceAccount"
        assert result[1]["namespace"] == "default"

    def test_cluster_role_admin_detection(self, mock_kubernetes):
        """Test detection of admin cluster roles."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()
        collector._cluster_name = "test-cluster"

        mock_cr = MagicMock()
        mock_cr.metadata.name = "cluster-admin"
        mock_cr.metadata.uid = "cr-123"
        mock_cr.metadata.labels = {}
        mock_cr.metadata.annotations = {}
        mock_cr.metadata.creation_timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_cr.rules = []
        mock_cr.aggregation_rule = None

        asset = collector._cluster_role_to_asset(mock_cr)

        assert asset.raw_config["is_admin_role"] is True

    def test_cluster_role_binding_admin_detection(self, mock_kubernetes):
        """Test detection of bindings granting cluster-admin."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()
        collector._cluster_name = "test-cluster"

        mock_crb = MagicMock()
        mock_crb.metadata.name = "admin-binding"
        mock_crb.metadata.uid = "crb-123"
        mock_crb.metadata.labels = {}
        mock_crb.metadata.annotations = {}
        mock_crb.metadata.creation_timestamp = None
        mock_crb.role_ref.api_group = "rbac.authorization.k8s.io"
        mock_crb.role_ref.kind = "ClusterRole"
        mock_crb.role_ref.name = "cluster-admin"
        mock_crb.subjects = []

        asset = collector._cluster_role_binding_to_asset(mock_crb)

        assert asset.raw_config["is_admin_binding"] is True
        assert asset.raw_config["grants_cluster_admin"] is True

    def test_service_account_default_detection(self, mock_kubernetes):
        """Test detection of default service account."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()
        collector._cluster_name = "test-cluster"

        mock_sa = MagicMock()
        mock_sa.metadata.name = "default"
        mock_sa.metadata.uid = "sa-123"
        mock_sa.metadata.labels = {}
        mock_sa.metadata.annotations = {}
        mock_sa.metadata.creation_timestamp = None
        mock_sa.secrets = []
        mock_sa.image_pull_secrets = []
        mock_sa.automount_service_account_token = None

        asset = collector._service_account_to_asset(mock_sa, "default")

        assert asset.raw_config["is_default"] is True
        # Default automount is true if not specified
        assert asset.raw_config["automount_service_account_token"] is True

    def test_service_account_automount_disabled(self, mock_kubernetes):
        """Test service account with automount disabled."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()
        collector._cluster_name = "test-cluster"

        mock_sa = MagicMock()
        mock_sa.metadata.name = "secure-sa"
        mock_sa.metadata.uid = "sa-456"
        mock_sa.metadata.labels = {}
        mock_sa.metadata.annotations = {}
        mock_sa.metadata.creation_timestamp = None
        mock_sa.secrets = []
        mock_sa.image_pull_secrets = []
        mock_sa.automount_service_account_token = False

        asset = collector._service_account_to_asset(mock_sa, "default")

        assert asset.raw_config["automount_service_account_token"] is False

    def test_role_binding_references_cluster_role(self, mock_kubernetes):
        """Test detection of role binding referencing cluster role."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()
        collector._cluster_name = "test-cluster"

        mock_rb = MagicMock()
        mock_rb.metadata.name = "view-binding"
        mock_rb.metadata.uid = "rb-123"
        mock_rb.metadata.labels = {}
        mock_rb.metadata.annotations = {}
        mock_rb.metadata.creation_timestamp = None
        mock_rb.role_ref.api_group = "rbac.authorization.k8s.io"
        mock_rb.role_ref.kind = "ClusterRole"
        mock_rb.role_ref.name = "view"
        mock_rb.subjects = []

        asset = collector._role_binding_to_asset(mock_rb, "default")

        assert asset.raw_config["references_cluster_role"] is True

    def test_extract_aggregation_rule(self, mock_kubernetes):
        """Test extraction of aggregation rules."""
        from stance.collectors.k8s_rbac import K8sRBACCollector

        collector = K8sRBACCollector()

        mock_selector = MagicMock()
        mock_selector.match_labels = {"rbac.authorization.k8s.io/aggregate-to-view": "true"}
        mock_selector.match_expressions = []

        mock_agg_rule = MagicMock()
        mock_agg_rule.cluster_role_selectors = [mock_selector]

        result = collector._extract_aggregation_rule(mock_agg_rule)

        assert len(result["cluster_role_selectors"]) == 1
        assert "rbac.authorization.k8s.io/aggregate-to-view" in result["cluster_role_selectors"][0]["match_labels"]


class TestK8sCollectorResult:
    """Tests for K8sCollectorResult dataclass."""

    def test_collector_result_success(self, mock_kubernetes):
        """Test result indicates success when no errors."""
        from stance.collectors.k8s_config import K8sCollectorResult

        result = K8sCollectorResult(
            collector_name="k8s_config",
            assets=AssetCollection([]),
            duration_seconds=1.5,
            errors=[],
        )

        assert result.success is True
        assert result.asset_count == 0

    def test_collector_result_failure(self, mock_kubernetes):
        """Test result indicates failure when errors present."""
        from stance.collectors.k8s_config import K8sCollectorResult

        result = K8sCollectorResult(
            collector_name="k8s_config",
            assets=AssetCollection([]),
            duration_seconds=0.5,
            errors=["Failed to connect to cluster"],
        )

        assert result.success is False


class TestK8sRBACCollectorResult:
    """Tests for K8sRBACCollectorResult dataclass."""

    def test_rbac_collector_result_success(self, mock_kubernetes):
        """Test RBAC result indicates success when no errors."""
        from stance.collectors.k8s_rbac import K8sRBACCollectorResult

        result = K8sRBACCollectorResult(
            collector_name="k8s_rbac",
            assets=AssetCollection([]),
            duration_seconds=2.0,
            errors=[],
        )

        assert result.success is True

    def test_rbac_collector_result_with_assets(self, mock_kubernetes):
        """Test RBAC result correctly counts assets."""
        from stance.collectors.k8s_rbac import K8sRBACCollectorResult
        from stance.models import Asset

        mock_asset = Asset(
            id="k8s://test/clusterrole/admin",
            cloud_provider="kubernetes",
            name="admin",
            resource_type="k8s_cluster_role",
            region="test",
            account_id="test",
        )

        result = K8sRBACCollectorResult(
            collector_name="k8s_rbac",
            assets=AssetCollection([mock_asset]),
            duration_seconds=1.0,
            errors=[],
        )

        assert result.asset_count == 1


class TestK8sNetworkCollector:
    """Tests for K8sNetworkCollector."""

    def test_k8s_network_collector_init(self, mock_kubernetes):
        """Test K8sNetworkCollector can be initialized."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        assert collector.collector_name == "k8s_network"
        assert "k8s_network_policy" in collector.resource_types
        assert "k8s_ingress" in collector.resource_types
        assert "k8s_secret" in collector.resource_types
        assert "k8s_limit_range" in collector.resource_types
        assert "k8s_resource_quota" in collector.resource_types

    def test_k8s_network_collector_with_kubeconfig(self, mock_kubernetes):
        """Test initialization with custom kubeconfig."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector(
            kubeconfig="/path/to/kubeconfig",
            context="test-context",
        )
        assert collector._kubeconfig == "/path/to/kubeconfig"
        assert collector._context == "test-context"

    def test_k8s_network_collector_with_namespaces(self, mock_kubernetes):
        """Test initialization with specific namespaces."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector(namespaces=["default", "production"])
        assert collector._namespaces == ["default", "production"]

    def test_network_policy_to_asset(self, mock_kubernetes):
        """Test NetworkPolicy conversion to asset."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_np = MagicMock()
        mock_np.metadata.name = "deny-all"
        mock_np.metadata.uid = "np-123"
        mock_np.metadata.labels = {"app": "web"}
        mock_np.metadata.annotations = {}
        mock_np.metadata.creation_timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_np.spec.pod_selector.match_labels = None
        mock_np.spec.pod_selector.match_expressions = None
        mock_np.spec.policy_types = ["Ingress", "Egress"]
        mock_np.spec.ingress = None
        mock_np.spec.egress = None

        asset = collector._network_policy_to_asset(mock_np, "default")

        assert asset.resource_type == "k8s_network_policy"
        assert asset.name == "deny-all"
        assert asset.cloud_provider == "kubernetes"
        assert asset.network_exposure == NETWORK_EXPOSURE_INTERNAL
        assert asset.raw_config["is_default_deny_ingress"] is True
        assert asset.raw_config["is_default_deny_egress"] is True

    def test_network_policy_with_ingress_rules(self, mock_kubernetes):
        """Test NetworkPolicy with ingress rules."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_np = MagicMock()
        mock_np.metadata.name = "allow-web"
        mock_np.metadata.uid = "np-456"
        mock_np.metadata.labels = {}
        mock_np.metadata.annotations = {}
        mock_np.metadata.creation_timestamp = None
        mock_np.spec.pod_selector.match_labels = {"app": "web"}
        mock_np.spec.pod_selector.match_expressions = None
        mock_np.spec.policy_types = ["Ingress"]

        # Mock ingress rule
        mock_ingress = MagicMock()
        mock_ingress._from = []
        mock_ingress.ports = [MagicMock(protocol="TCP", port=80, end_port=None)]
        mock_np.spec.ingress = [mock_ingress]
        mock_np.spec.egress = None

        asset = collector._network_policy_to_asset(mock_np, "default")

        assert asset.raw_config["has_ingress_rules"] is True
        assert asset.raw_config["is_default_deny_ingress"] is False

    def test_ingress_to_asset(self, mock_kubernetes):
        """Test Ingress conversion to asset."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_ing = MagicMock()
        mock_ing.metadata.name = "web-ingress"
        mock_ing.metadata.uid = "ing-123"
        mock_ing.metadata.labels = {"app": "web"}
        mock_ing.metadata.annotations = {}
        mock_ing.metadata.creation_timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_ing.spec.ingress_class_name = "nginx"
        mock_ing.spec.default_backend = None

        # Mock TLS config
        mock_tls = MagicMock()
        mock_tls.hosts = ["app.example.com"]
        mock_tls.secret_name = "tls-secret"
        mock_ing.spec.tls = [mock_tls]

        # Mock rules
        mock_rule = MagicMock()
        mock_rule.host = "app.example.com"
        mock_path = MagicMock()
        mock_path.path = "/"
        mock_path.path_type = "Prefix"
        mock_path.backend.service.name = "web-svc"
        mock_path.backend.service.port.number = 80
        mock_rule.http.paths = [mock_path]
        mock_ing.spec.rules = [mock_rule]

        asset = collector._ingress_to_asset(mock_ing, "default")

        assert asset.resource_type == "k8s_ingress"
        assert asset.name == "web-ingress"
        assert asset.network_exposure == NETWORK_EXPOSURE_INTERNET
        assert asset.raw_config["has_tls"] is True
        assert "app.example.com" in asset.raw_config["hosts"]

    def test_ingress_without_tls(self, mock_kubernetes):
        """Test Ingress without TLS."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_ing = MagicMock()
        mock_ing.metadata.name = "insecure-ingress"
        mock_ing.metadata.uid = "ing-456"
        mock_ing.metadata.labels = {}
        mock_ing.metadata.annotations = {}
        mock_ing.metadata.creation_timestamp = None
        mock_ing.spec.ingress_class_name = "nginx"
        mock_ing.spec.tls = None
        mock_ing.spec.rules = []
        mock_ing.spec.default_backend = MagicMock()

        asset = collector._ingress_to_asset(mock_ing, "default")

        assert asset.raw_config["has_tls"] is False
        assert asset.raw_config["has_default_backend"] is True

    def test_secret_to_asset(self, mock_kubernetes):
        """Test Secret conversion to asset (metadata only)."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_secret = MagicMock()
        mock_secret.metadata.name = "app-secrets"
        mock_secret.metadata.uid = "secret-123"
        mock_secret.metadata.labels = {}
        mock_secret.metadata.annotations = {}
        mock_secret.metadata.creation_timestamp = None
        mock_secret.type = "Opaque"
        mock_secret.data = {"username": "dXNlcg==", "password": "cGFzcw=="}
        mock_secret.string_data = None

        asset = collector._secret_to_asset(mock_secret, "default")

        assert asset.resource_type == "k8s_secret"
        assert asset.name == "app-secrets"
        # Verify we only store key names, not values
        assert "username" in asset.raw_config["data_keys"]
        assert "password" in asset.raw_config["data_keys"]
        assert asset.raw_config["key_count"] == 2
        assert asset.raw_config["is_service_account_token"] is False

    def test_secret_service_account_token(self, mock_kubernetes):
        """Test detection of service account token secrets."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_secret = MagicMock()
        mock_secret.metadata.name = "default-token-abc"
        mock_secret.metadata.uid = "secret-456"
        mock_secret.metadata.labels = {}
        mock_secret.metadata.annotations = {
            "kubernetes.io/service-account.name": "default"
        }
        mock_secret.metadata.creation_timestamp = None
        mock_secret.type = "kubernetes.io/service-account-token"
        mock_secret.data = {"token": "dG9rZW4="}
        mock_secret.string_data = None

        asset = collector._secret_to_asset(mock_secret, "default")

        assert asset.raw_config["is_service_account_token"] is True
        assert asset.raw_config["service_account"] == "default"

    def test_secret_tls_type(self, mock_kubernetes):
        """Test detection of TLS secrets."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_secret = MagicMock()
        mock_secret.metadata.name = "tls-cert"
        mock_secret.metadata.uid = "secret-789"
        mock_secret.metadata.labels = {}
        mock_secret.metadata.annotations = {}
        mock_secret.metadata.creation_timestamp = None
        mock_secret.type = "kubernetes.io/tls"
        mock_secret.data = {"tls.crt": "Y2VydA==", "tls.key": "a2V5"}
        mock_secret.string_data = None

        asset = collector._secret_to_asset(mock_secret, "default")

        assert asset.raw_config["is_tls_secret"] is True

    def test_limit_range_to_asset(self, mock_kubernetes):
        """Test LimitRange conversion to asset."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_lr = MagicMock()
        mock_lr.metadata.name = "default-limits"
        mock_lr.metadata.uid = "lr-123"
        mock_lr.metadata.labels = {}
        mock_lr.metadata.annotations = {}
        mock_lr.metadata.creation_timestamp = None

        mock_limit = MagicMock()
        mock_limit.type = "Container"
        mock_limit.default = {"cpu": "500m", "memory": "512Mi"}
        mock_limit.default_request = {"cpu": "100m", "memory": "128Mi"}
        mock_limit.max = {"cpu": "2", "memory": "4Gi"}
        mock_limit.min = {"cpu": "50m", "memory": "64Mi"}
        mock_limit.max_limit_request_ratio = None
        mock_lr.spec.limits = [mock_limit]

        asset = collector._limit_range_to_asset(mock_lr, "default")

        assert asset.resource_type == "k8s_limit_range"
        assert asset.name == "default-limits"
        assert asset.raw_config["limit_count"] == 1
        assert asset.raw_config["limits"][0]["type"] == "Container"
        assert asset.raw_config["limits"][0]["default"]["cpu"] == "500m"

    def test_resource_quota_to_asset(self, mock_kubernetes):
        """Test ResourceQuota conversion to asset."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()
        collector._cluster_name = "test-cluster"

        mock_quota = MagicMock()
        mock_quota.metadata.name = "compute-quota"
        mock_quota.metadata.uid = "rq-123"
        mock_quota.metadata.labels = {}
        mock_quota.metadata.annotations = {}
        mock_quota.metadata.creation_timestamp = None
        mock_quota.spec.hard = {
            "pods": "10",
            "requests.cpu": "4",
            "requests.memory": "16Gi",
        }
        mock_quota.spec.scopes = None
        mock_quota.spec.scope_selector = None
        mock_quota.status.used = {
            "pods": "3",
            "requests.cpu": "1",
            "requests.memory": "4Gi",
        }
        mock_quota.status.hard = mock_quota.spec.hard

        asset = collector._resource_quota_to_asset(mock_quota, "default")

        assert asset.resource_type == "k8s_resource_quota"
        assert asset.name == "compute-quota"
        assert asset.raw_config["hard"]["pods"] == "10"
        assert asset.raw_config["used"]["pods"] == "3"

    def test_extract_label_selector(self, mock_kubernetes):
        """Test extraction of label selectors."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()

        mock_selector = MagicMock()
        mock_selector.match_labels = {"app": "web", "tier": "frontend"}
        mock_selector.match_expressions = None

        result = collector._extract_label_selector(mock_selector)

        assert result["match_labels"]["app"] == "web"
        assert result["match_labels"]["tier"] == "frontend"

    def test_extract_ingress_rules(self, mock_kubernetes):
        """Test extraction of NetworkPolicy ingress rules."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()

        mock_rule = MagicMock()
        mock_peer = MagicMock()
        mock_peer.pod_selector = MagicMock()
        mock_peer.pod_selector.match_labels = {"app": "backend"}
        mock_peer.pod_selector.match_expressions = None
        mock_peer.namespace_selector = None
        mock_peer.ip_block = None
        mock_rule._from = [mock_peer]

        mock_port = MagicMock()
        mock_port.protocol = "TCP"
        mock_port.port = 8080
        mock_port.end_port = None
        mock_rule.ports = [mock_port]

        result = collector._extract_ingress_rules([mock_rule])

        assert len(result) == 1
        assert len(result[0]["from"]) == 1
        assert result[0]["ports"][0]["port"] == "8080"

    def test_extract_egress_rules_with_ip_block(self, mock_kubernetes):
        """Test extraction of NetworkPolicy egress rules with IP block."""
        from stance.collectors.k8s_network import K8sNetworkCollector

        collector = K8sNetworkCollector()

        mock_rule = MagicMock()
        mock_peer = MagicMock()
        mock_peer.pod_selector = None
        mock_peer.namespace_selector = None
        mock_peer.ip_block = MagicMock()
        mock_peer.ip_block.cidr = "10.0.0.0/8"
        mock_peer.ip_block._except = ["10.1.0.0/16"]
        mock_rule.to = [mock_peer]
        mock_rule.ports = []

        result = collector._extract_egress_rules([mock_rule])

        assert len(result) == 1
        assert result[0]["to"][0]["ip_block"]["cidr"] == "10.0.0.0/8"
        assert "10.1.0.0/16" in result[0]["to"][0]["ip_block"]["except"]


class TestK8sNetworkCollectorResult:
    """Tests for K8sNetworkCollectorResult dataclass."""

    def test_network_collector_result_success(self, mock_kubernetes):
        """Test network collector result indicates success when no errors."""
        from stance.collectors.k8s_network import K8sNetworkCollectorResult

        result = K8sNetworkCollectorResult(
            collector_name="k8s_network",
            assets=AssetCollection([]),
            duration_seconds=1.5,
            errors=[],
        )

        assert result.success is True
        assert result.asset_count == 0

    def test_network_collector_result_failure(self, mock_kubernetes):
        """Test network collector result indicates failure when errors present."""
        from stance.collectors.k8s_network import K8sNetworkCollectorResult

        result = K8sNetworkCollectorResult(
            collector_name="k8s_network",
            assets=AssetCollection([]),
            duration_seconds=0.5,
            errors=["Failed to list network policies"],
        )

        assert result.success is False

    def test_network_collector_result_with_assets(self, mock_kubernetes):
        """Test network collector result correctly counts assets."""
        from stance.collectors.k8s_network import K8sNetworkCollectorResult
        from stance.models import Asset

        mock_asset = Asset(
            id="k8s://test/default/networkpolicy/deny-all",
            cloud_provider="kubernetes",
            name="deny-all",
            resource_type="k8s_network_policy",
            region="test",
            account_id="test",
        )

        result = K8sNetworkCollectorResult(
            collector_name="k8s_network",
            assets=AssetCollection([mock_asset]),
            duration_seconds=1.0,
            errors=[],
        )

        assert result.asset_count == 1
