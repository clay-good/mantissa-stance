"""
Tests for Azure policies.

Validates all Azure-related security policies work correctly.
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
def identity_policy_loader():
    """Load Azure Identity policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "azure" / "identity"
    if not policy_dir.exists():
        pytest.skip("Azure Identity policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


@pytest.fixture
def storage_policy_loader():
    """Load Azure Storage policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "azure" / "storage"
    if not policy_dir.exists():
        pytest.skip("Azure Storage policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


@pytest.fixture
def compute_policy_loader():
    """Load Azure Compute policies."""
    policy_dir = Path(__file__).parent.parent.parent / "policies" / "azure" / "compute"
    if not policy_dir.exists():
        pytest.skip("Azure Compute policies directory not found")
    return PolicyLoader(policy_dirs=[str(policy_dir)])


class TestAzureIdentityPolicies:
    """Tests for Azure Identity policies."""

    def test_privileged_role_review_loads(self, identity_policy_loader):
        """Test privileged role review policy loads."""
        policies = identity_policy_loader.load_all()
        policy = policies.get_by_id("azure-identity-001")
        if policy is None:
            pytest.skip("Azure privileged role review policy not found")

        assert policy.name is not None

    def test_custom_role_wildcard_loads(self, identity_policy_loader):
        """Test custom role wildcard policy loads."""
        policies = identity_policy_loader.load_all()
        policy = policies.get_by_id("azure-identity-002")
        if policy is None:
            pytest.skip("Azure custom role wildcard policy not found")

        assert policy.name is not None

    def test_subscription_scope_limited_loads(self, identity_policy_loader):
        """Test subscription scope limited policy loads."""
        policies = identity_policy_loader.load_all()
        policy = policies.get_by_id("azure-identity-003")
        if policy is None:
            pytest.skip("Azure subscription scope limited policy not found")

        assert policy.name is not None


class TestAzureStoragePolicies:
    """Tests for Azure Storage policies."""

    def test_secure_transfer_required_loads(self, storage_policy_loader):
        """Test secure transfer required policy loads."""
        policies = storage_policy_loader.load_all()
        policy = policies.get_by_id("azure-storage-001")
        if policy is None:
            pytest.skip("Azure secure transfer required policy not found")

        assert policy.name is not None
        assert policy.severity in [Severity.HIGH, Severity.MEDIUM]

    def test_minimum_tls_version_loads(self, storage_policy_loader):
        """Test minimum TLS version policy loads."""
        policies = storage_policy_loader.load_all()
        policy = policies.get_by_id("azure-storage-002")
        if policy is None:
            pytest.skip("Azure minimum TLS version policy not found")

        assert policy.name is not None

    def test_public_access_disabled_loads(self, storage_policy_loader):
        """Test public access disabled policy loads."""
        policies = storage_policy_loader.load_all()
        policy = policies.get_by_id("azure-storage-003")
        if policy is None:
            pytest.skip("Azure public access disabled policy not found")

        assert policy.name is not None
        assert policy.severity in [Severity.CRITICAL, Severity.HIGH]

    def test_secure_storage_account_passes(self, storage_policy_loader):
        """Test secure storage account passes validation."""
        policies = storage_policy_loader.load_all()

        secure_account = Asset(
            id="/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/secure",
            cloud_provider="azure",
            account_id="xxx-subscription",
            region="eastus",
            resource_type="azure_storage_account",
            name="secure-storage",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            raw_config={
                "enable_https_traffic_only": True,
                "minimum_tls_version": "TLS1_2",
                "allow_blob_public_access": False,
                "network_rule_set": {
                    "default_action": "Deny",
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([secure_account]))

        # Secure account should have minimal findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0

    def test_insecure_storage_account_generates_findings(self, storage_policy_loader):
        """Test insecure storage account generates findings."""
        policies = storage_policy_loader.load_all()

        insecure_account = Asset(
            id="/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/insecure",
            cloud_provider="azure",
            account_id="xxx-subscription",
            region="eastus",
            resource_type="azure_storage_account",
            name="insecure-storage",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            raw_config={
                "enable_https_traffic_only": False,
                "minimum_tls_version": "TLS1_0",
                "allow_blob_public_access": True,
                "network_rule_set": {
                    "default_action": "Allow",
                },
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([insecure_account]))

        # Insecure account should generate findings
        assert len(findings) > 0


class TestAzureComputePolicies:
    """Tests for Azure Compute policies."""

    def test_nsg_ssh_restricted_loads(self, compute_policy_loader):
        """Test NSG SSH restricted policy loads."""
        policies = compute_policy_loader.load_all()
        policy = policies.get_by_id("azure-compute-001")
        if policy is None:
            pytest.skip("Azure NSG SSH restricted policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.HIGH

    def test_nsg_rdp_restricted_loads(self, compute_policy_loader):
        """Test NSG RDP restricted policy loads."""
        policies = compute_policy_loader.load_all()
        policy = policies.get_by_id("azure-compute-002")
        if policy is None:
            pytest.skip("Azure NSG RDP restricted policy not found")

        assert policy.name is not None
        assert policy.severity == Severity.HIGH

    def test_vm_managed_identity_loads(self, compute_policy_loader):
        """Test VM managed identity policy loads."""
        policies = compute_policy_loader.load_all()
        policy = policies.get_by_id("azure-compute-003")
        if policy is None:
            pytest.skip("Azure VM managed identity policy not found")

        assert policy.name is not None

    def test_open_nsg_generates_finding(self, compute_policy_loader):
        """Test open NSG generates finding."""
        policies = compute_policy_loader.load_all()

        open_nsg = Asset(
            id="/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/open-nsg",
            cloud_provider="azure",
            account_id="xxx-subscription",
            region="eastus",
            resource_type="azure_network_security_group",
            name="open-nsg",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            raw_config={
                "security_rules": [
                    {
                        "name": "AllowSSH",
                        "direction": "Inbound",
                        "protocol": "TCP",
                        "destination_port_range": "22",
                        "source_address_prefix": "*",
                        "access": "Allow",
                    },
                ],
                "has_open_ssh": True,
            },
        )

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(policies, AssetCollection([open_nsg]))

        ssh_findings = [f for f in findings if f.rule_id == "azure-compute-001"]
        assert len(ssh_findings) == 1


class TestAzurePolicySchema:
    """Test Azure policy schema validation."""

    def test_all_azure_policies_have_azure_resource_types(
        self, identity_policy_loader, storage_policy_loader, compute_policy_loader
    ):
        """Test all Azure policies target Azure resources."""
        all_policies = []
        for loader in [identity_policy_loader, storage_policy_loader, compute_policy_loader]:
            try:
                all_policies.extend(loader.load_all().policies)
            except Exception:
                pass

        for policy in all_policies:
            assert policy.resource_type.startswith("azure_"), \
                f"Policy {policy.id} has non-Azure resource type: {policy.resource_type}"

    def test_azure_policies_have_tags(self, storage_policy_loader):
        """Test Azure policies have tags."""
        policies = storage_policy_loader.load_all()

        for policy in policies:
            assert policy.tags is not None
            assert len(policy.tags) > 0


class TestAzureComplianceMappings:
    """Test Azure policy compliance mappings."""

    def test_azure_policies_map_to_cis(self, storage_policy_loader):
        """Test Azure policies map to CIS benchmarks."""
        policies = storage_policy_loader.load_all()

        has_cis_mapping = False
        for policy in policies:
            if policy.compliance:
                for mapping in policy.compliance:
                    if "cis" in mapping.framework.lower():
                        has_cis_mapping = True
                        break

        # At least some policies should have CIS mappings
        assert has_cis_mapping or len(policies) == 0

    def test_network_policies_have_high_severity(self, compute_policy_loader):
        """Test network-related policies have appropriate severity."""
        policies = compute_policy_loader.load_all()

        for policy in policies:
            if "nsg" in policy.id.lower() or "network" in policy.resource_type.lower():
                # Network security policies should be high severity
                assert policy.severity in [Severity.CRITICAL, Severity.HIGH]
