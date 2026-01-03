"""
Tests for Kubernetes security policies.

Validates all Kubernetes-related security policies work correctly:
- Pod security policies (privileged containers, host namespaces, etc.)
- RBAC policies (cluster-admin, wildcard permissions, etc.)
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Severity,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_INTERNET,
)
from stance.engine import PolicyLoader, PolicyEvaluator


@pytest.fixture
def pod_policy_loader():
    """Load Kubernetes pod security policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "kubernetes" / "pod-security"
    if not policy_dir.exists():
        pytest.skip("Kubernetes pod-security policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


@pytest.fixture
def rbac_policy_loader():
    """Load Kubernetes RBAC policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "kubernetes" / "rbac"
    if not policy_dir.exists():
        pytest.skip("Kubernetes RBAC policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


@pytest.fixture
def pod_policies(pod_policy_loader):
    """Load all pod security policies."""
    return pod_policy_loader.load_all()


@pytest.fixture
def rbac_policies(rbac_policy_loader):
    """Load all RBAC policies."""
    return rbac_policy_loader.load_all()


class TestPrivilegedContainerPolicy:
    """Tests for privileged-containers.yaml policy."""

    def test_policy_loads(self, pod_policies):
        """Test privileged container policy loads correctly."""
        policy = pod_policies.get_by_id("k8s-pod-001")
        if policy is None:
            pytest.skip("Privileged container policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.CRITICAL
        assert policy.resource_type == "k8s_pod"

    def test_non_privileged_container_passes(self, pod_policies):
        """Test non-privileged container passes validation."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/secure-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="secure-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "has_privileged_container": False,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        priv_findings = [f for f in findings if f.rule_id == "k8s-pod-001"]
        assert len(priv_findings) == 0

    def test_privileged_container_generates_finding(self, pod_policies):
        """Test privileged container generates finding."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/privileged-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="privileged-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "has_privileged_container": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        priv_findings = [f for f in findings if f.rule_id == "k8s-pod-001"]
        assert len(priv_findings) == 1
        assert priv_findings[0].severity == Severity.CRITICAL


class TestHostNetworkPolicy:
    """Tests for host-network.yaml policy."""

    def test_policy_loads(self, pod_policies):
        """Test host network policy loads correctly."""
        policy = pod_policies.get_by_id("k8s-pod-002")
        if policy is None:
            pytest.skip("Host network policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.HIGH

    def test_pod_without_host_network_passes(self, pod_policies):
        """Test pod without host network passes validation."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/normal-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="normal-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "host_network": False,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        host_net_findings = [f for f in findings if f.rule_id == "k8s-pod-002"]
        assert len(host_net_findings) == 0

    def test_pod_with_host_network_generates_finding(self, pod_policies):
        """Test pod with host network generates finding."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/hostnet-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="hostnet-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "host_network": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        host_net_findings = [f for f in findings if f.rule_id == "k8s-pod-002"]
        assert len(host_net_findings) == 1


class TestHostPathVolumePolicy:
    """Tests for host-path-volumes.yaml policy."""

    def test_policy_loads(self, pod_policies):
        """Test host path volume policy loads correctly."""
        policy = pod_policies.get_by_id("k8s-pod-009")
        if policy is None:
            pytest.skip("Host path volume policy not found")

        assert policy.severity == Severity.HIGH

    def test_pod_without_hostpath_passes(self, pod_policies):
        """Test pod without hostPath volumes passes validation."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/normal-vol-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="normal-vol-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "has_host_path_volume": False,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        hostpath_findings = [f for f in findings if f.rule_id == "k8s-pod-009"]
        assert len(hostpath_findings) == 0

    def test_pod_with_hostpath_generates_finding(self, pod_policies):
        """Test pod with hostPath volume generates finding."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/hostpath-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="hostpath-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "has_host_path_volume": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        hostpath_findings = [f for f in findings if f.rule_id == "k8s-pod-009"]
        assert len(hostpath_findings) == 1


class TestResourceLimitsPolicy:
    """Tests for resource-limits.yaml policy."""

    def test_policy_loads(self, pod_policies):
        """Test resource limits policy loads correctly."""
        policy = pod_policies.get_by_id("k8s-pod-010")
        if policy is None:
            pytest.skip("Resource limits policy not found")

        assert policy.severity == Severity.MEDIUM

    def test_container_with_limits_passes(self, pod_policies):
        """Test container with resource limits passes validation."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/limited-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="limited-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "has_resource_limits": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        limit_findings = [f for f in findings if f.rule_id == "k8s-pod-010"]
        assert len(limit_findings) == 0

    def test_container_without_limits_generates_finding(self, pod_policies):
        """Test container without resource limits generates finding."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/unlimited-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="unlimited-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "has_resource_limits": False,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        limit_findings = [f for f in findings if f.rule_id == "k8s-pod-010"]
        assert len(limit_findings) == 1


class TestLatestImageTagPolicy:
    """Tests for latest-image-tag.yaml policy."""

    def test_policy_loads(self, pod_policies):
        """Test latest image tag policy loads correctly."""
        policy = pod_policies.get_by_id("k8s-pod-011")
        if policy is None:
            pytest.skip("Latest image tag policy not found")

        assert policy.severity == Severity.MEDIUM

    def test_versioned_image_passes(self, pod_policies):
        """Test versioned image passes validation."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/versioned-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="versioned-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "uses_latest_tag": False,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        latest_findings = [f for f in findings if f.rule_id == "k8s-pod-011"]
        assert len(latest_findings) == 0

    def test_latest_image_generates_finding(self, pod_policies):
        """Test image with 'latest' tag generates finding."""
        asset = Asset(
            id="k8s://test-cluster/default/pod/latest-pod",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_pod",
            name="latest-pod",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "uses_latest_tag": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(pod_policies, AssetCollection([asset]))

        latest_findings = [f for f in findings if f.rule_id == "k8s-pod-011"]
        assert len(latest_findings) == 1


class TestClusterAdminBindingPolicy:
    """Tests for cluster-admin-binding.yaml policy."""

    def test_policy_loads(self, rbac_policies):
        """Test cluster admin binding policy loads correctly."""
        policy = rbac_policies.get_by_id("k8s-rbac-001")
        if policy is None:
            pytest.skip("Cluster admin binding policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.CRITICAL
        assert policy.resource_type == "k8s_cluster_role_binding"

    def test_non_admin_binding_passes(self, rbac_policies):
        """Test non-admin binding passes validation."""
        asset = Asset(
            id="k8s://test-cluster/clusterrolebinding/view-binding",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_cluster_role_binding",
            name="view-binding",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "grants_cluster_admin": False,
                "role_ref": {"name": "view", "kind": "ClusterRole"},
                "subjects": [{"kind": "User", "name": "reader"}],
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        admin_findings = [f for f in findings if f.rule_id == "k8s-rbac-001"]
        assert len(admin_findings) == 0

    def test_cluster_admin_binding_generates_finding(self, rbac_policies):
        """Test cluster-admin binding generates finding."""
        asset = Asset(
            id="k8s://test-cluster/clusterrolebinding/admin-binding",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_cluster_role_binding",
            name="admin-binding",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "grants_cluster_admin": True,
                "role_ref": {"name": "cluster-admin", "kind": "ClusterRole"},
                "subjects": [{"kind": "User", "name": "admin-user"}],
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        admin_findings = [f for f in findings if f.rule_id == "k8s-rbac-001"]
        assert len(admin_findings) == 1
        assert admin_findings[0].severity == Severity.CRITICAL


class TestWildcardPermissionsPolicy:
    """Tests for wildcard-permissions.yaml policy."""

    def test_policy_loads(self, rbac_policies):
        """Test wildcard permissions policy loads correctly."""
        policy = rbac_policies.get_by_id("k8s-rbac-002")
        if policy is None:
            pytest.skip("Wildcard permissions policy not found")

        assert policy.severity == Severity.HIGH

    def test_specific_permissions_passes(self, rbac_policies):
        """Test specific permissions passes validation."""
        asset = Asset(
            id="k8s://test-cluster/clusterrole/pod-reader",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_cluster_role",
            name="pod-reader",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "rules": [
                    {"resources": ["pods"], "verbs": ["get", "list", "watch"]},
                ],
                "risk_analysis": {
                    "has_wildcard_resources": False,
                    "has_wildcard_verbs": False,
                    "has_secrets_access": False,
                    "has_pod_exec_access": False,
                    "is_overly_permissive": False,
                    "risk_score": 10,
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        wildcard_findings = [f for f in findings if f.rule_id == "k8s-rbac-002"]
        assert len(wildcard_findings) == 0

    def test_wildcard_permissions_generates_finding(self, rbac_policies):
        """Test wildcard permissions generates finding."""
        asset = Asset(
            id="k8s://test-cluster/clusterrole/god-mode",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_cluster_role",
            name="god-mode",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "rules": [
                    {"resources": ["*"], "verbs": ["*"]},
                ],
                "risk_analysis": {
                    "has_wildcard_resources": True,
                    "has_wildcard_verbs": True,
                    "has_secrets_access": True,
                    "has_pod_exec_access": True,
                    "is_overly_permissive": True,
                    "risk_score": 100,
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        wildcard_findings = [f for f in findings if f.rule_id == "k8s-rbac-002"]
        assert len(wildcard_findings) == 1


class TestSecretsAccessPolicy:
    """Tests for secrets-access.yaml policy."""

    def test_policy_loads(self, rbac_policies):
        """Test secrets access policy loads correctly."""
        policy = rbac_policies.get_by_id("k8s-rbac-003")
        if policy is None:
            pytest.skip("Secrets access policy not found")

        assert policy.severity == Severity.HIGH

    def test_no_secrets_access_passes(self, rbac_policies):
        """Test role without secrets access passes validation."""
        asset = Asset(
            id="k8s://test-cluster/clusterrole/pod-manager",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_cluster_role",
            name="pod-manager",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "rules": [
                    {"resources": ["pods"], "verbs": ["get", "list", "create"]},
                ],
                "risk_analysis": {
                    "has_secrets_access": False,
                    "has_pod_exec_access": False,
                    "has_wildcard_resources": False,
                    "has_wildcard_verbs": False,
                    "is_overly_permissive": False,
                    "risk_score": 30,
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        secrets_findings = [f for f in findings if f.rule_id == "k8s-rbac-003"]
        assert len(secrets_findings) == 0

    def test_secrets_access_generates_finding(self, rbac_policies):
        """Test role with secrets access generates finding."""
        asset = Asset(
            id="k8s://test-cluster/clusterrole/secret-reader",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_cluster_role",
            name="secret-reader",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "rules": [
                    {"resources": ["secrets"], "verbs": ["get", "list"]},
                ],
                "risk_analysis": {
                    "has_secrets_access": True,
                    "has_pod_exec_access": False,
                    "has_wildcard_resources": False,
                    "has_wildcard_verbs": False,
                    "is_overly_permissive": False,
                    "risk_score": 50,
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        secrets_findings = [f for f in findings if f.rule_id == "k8s-rbac-003"]
        assert len(secrets_findings) == 1


class TestServiceAccountTokenPolicy:
    """Tests for service-account-tokens.yaml policy."""

    def test_policy_loads(self, rbac_policies):
        """Test service account tokens policy loads correctly."""
        policy = rbac_policies.get_by_id("k8s-rbac-005")
        if policy is None:
            pytest.skip("Service account tokens policy not found")

        assert policy.severity == Severity.MEDIUM

    def test_disabled_automount_passes(self, rbac_policies):
        """Test disabled automount passes validation."""
        asset = Asset(
            id="k8s://test-cluster/default/serviceaccount/secure-sa",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_service_account",
            name="secure-sa",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "automount_service_account_token": False,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        token_findings = [f for f in findings if f.rule_id == "k8s-rbac-005"]
        assert len(token_findings) == 0

    def test_enabled_automount_generates_finding(self, rbac_policies):
        """Test enabled automount generates finding."""
        asset = Asset(
            id="k8s://test-cluster/default/serviceaccount/insecure-sa",
            cloud_provider="kubernetes",
            account_id="test-cluster",
            region="test-cluster",
            resource_type="k8s_service_account",
            name="insecure-sa",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "automount_service_account_token": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(rbac_policies, AssetCollection([asset]))

        token_findings = [f for f in findings if f.rule_id == "k8s-rbac-005"]
        assert len(token_findings) == 1


class TestAllKubernetesPoliciesLoad:
    """Test that all Kubernetes policies load without errors."""

    def test_all_pod_policies_load(self, pod_policies):
        """Test all pod security policies load successfully."""
        assert len(pod_policies) > 0

        # Check expected policies exist
        expected_ids = [
            "k8s-pod-001",  # privileged containers
            "k8s-pod-002",  # host network
            "k8s-pod-003",  # host pid
            "k8s-pod-004",  # host ipc
            "k8s-pod-005",  # run as non-root
            "k8s-pod-006",  # read-only root fs
            "k8s-pod-007",  # privilege escalation
            "k8s-pod-008",  # capabilities drop all
            "k8s-pod-009",  # host path volumes
            "k8s-pod-010",  # resource limits
            "k8s-pod-011",  # latest image tag
            "k8s-pod-012",  # liveness probe
            "k8s-pod-013",  # readiness probe
        ]

        for policy_id in expected_ids:
            policy = pod_policies.get_by_id(policy_id)
            assert policy is not None, f"Policy {policy_id} not found"
            assert policy.enabled is True
            assert policy.resource_type == "k8s_pod"

    def test_all_rbac_policies_load(self, rbac_policies):
        """Test all RBAC policies load successfully."""
        assert len(rbac_policies) > 0

        # Check expected policies exist
        expected_ids = [
            "k8s-rbac-001",  # cluster-admin binding
            "k8s-rbac-002",  # wildcard permissions
            "k8s-rbac-003",  # secrets access
            "k8s-rbac-004",  # pod exec access
            "k8s-rbac-005",  # service account tokens
            "k8s-rbac-006",  # default service account
            "k8s-rbac-007",  # overly permissive role
        ]

        for policy_id in expected_ids:
            policy = rbac_policies.get_by_id(policy_id)
            assert policy is not None, f"Policy {policy_id} not found"
            assert policy.enabled is True
