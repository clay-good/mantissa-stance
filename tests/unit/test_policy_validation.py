"""
Policy Validation Tests (G.3).

Tests that validate all YAML policy files in the policies directory:
- Schema validation
- Expression syntax validation
- Compliance mapping validation
- Policy file consistency
"""

import os
from pathlib import Path

import pytest

from stance.engine import PolicyLoader, ExpressionEvaluator
from stance.models import Severity


# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent.parent
POLICY_DIRS = [
    PROJECT_ROOT / "policies" / "aws",
    PROJECT_ROOT / "policies" / "gcp",
    PROJECT_ROOT / "policies" / "azure",
]


def get_all_policy_files() -> list[Path]:
    """Get all YAML policy files from the policies directory."""
    policy_files = []
    for policy_dir in POLICY_DIRS:
        if policy_dir.exists():
            policy_files.extend(policy_dir.glob("**/*.yaml"))
            policy_files.extend(policy_dir.glob("**/*.yml"))
    return sorted(policy_files)


def get_policy_ids() -> list[str]:
    """Get parametrized test IDs from policy file paths."""
    return [
        str(p.relative_to(PROJECT_ROOT))
        for p in get_all_policy_files()
    ]


class TestPolicyFilesExist:
    """Test that policy files exist and directory structure is correct."""

    def test_policies_directory_exists(self):
        """Test the policies directory exists."""
        policies_dir = PROJECT_ROOT / "policies"
        assert policies_dir.exists(), "policies/ directory should exist"

    def test_aws_policies_exist(self):
        """Test AWS policy files exist."""
        aws_dir = PROJECT_ROOT / "policies" / "aws"
        if aws_dir.exists():
            policy_files = list(aws_dir.glob("**/*.yaml"))
            assert len(policy_files) > 0, "AWS policy files should exist"

    def test_gcp_policies_exist(self):
        """Test GCP policy files exist."""
        gcp_dir = PROJECT_ROOT / "policies" / "gcp"
        if gcp_dir.exists():
            policy_files = list(gcp_dir.glob("**/*.yaml"))
            assert len(policy_files) > 0, "GCP policy files should exist"

    def test_azure_policies_exist(self):
        """Test Azure policy files exist."""
        azure_dir = PROJECT_ROOT / "policies" / "azure"
        if azure_dir.exists():
            policy_files = list(azure_dir.glob("**/*.yaml"))
            assert len(policy_files) > 0, "Azure policy files should exist"

    def test_policy_count_minimum(self):
        """Test minimum number of policies exist."""
        all_policies = get_all_policy_files()
        # According to the plan, we should have at least 8 AWS policies
        # plus GCP and Azure policies
        assert len(all_policies) >= 8, f"Expected at least 8 policies, found {len(all_policies)}"


class TestPolicySchemaValidation:
    """Test that all policies conform to the expected schema."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader with all policy directories."""
        return PolicyLoader(policy_dirs=[str(d) for d in POLICY_DIRS if d.exists()])

    @pytest.fixture(params=get_all_policy_files(), ids=get_policy_ids())
    def policy_file(self, request) -> Path:
        """Parametrized fixture for each policy file."""
        return request.param

    def test_policy_loads_successfully(self, loader, policy_file):
        """Test each policy file loads without errors."""
        try:
            policy = loader.load_policy(str(policy_file))
            assert policy is not None
        except Exception as e:
            pytest.fail(f"Failed to load policy {policy_file}: {e}")

    def test_policy_has_required_fields(self, loader, policy_file):
        """Test each policy has all required fields."""
        policy = loader.load_policy(str(policy_file))

        # Required fields
        assert policy.id, f"Policy {policy_file} missing 'id'"
        assert policy.name, f"Policy {policy_file} missing 'name'"
        assert policy.description, f"Policy {policy_file} missing 'description'"
        assert policy.resource_type, f"Policy {policy_file} missing 'resource_type'"
        assert policy.check is not None, f"Policy {policy_file} missing 'check'"
        assert policy.severity is not None, f"Policy {policy_file} missing 'severity'"

    def test_policy_id_format(self, loader, policy_file):
        """Test policy IDs follow the expected format."""
        policy = loader.load_policy(str(policy_file))

        # ID should be in format: provider-service-XXX
        parts = policy.id.split("-")
        assert len(parts) >= 3, f"Policy ID '{policy.id}' should have at least 3 parts (provider-service-number)"

        # First part should be cloud provider
        valid_providers = ["aws", "gcp", "azure"]
        assert parts[0] in valid_providers, f"Policy ID '{policy.id}' should start with valid provider"

    def test_policy_severity_valid(self, loader, policy_file):
        """Test policy severity is a valid value."""
        policy = loader.load_policy(str(policy_file))

        valid_severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert policy.severity in valid_severities, f"Policy {policy.id} has invalid severity: {policy.severity}"

    def test_policy_resource_type_format(self, loader, policy_file):
        """Test resource type follows expected format."""
        policy = loader.load_policy(str(policy_file))

        # Resource type should be in format: provider_service_resource
        assert "_" in policy.resource_type, f"Resource type '{policy.resource_type}' should use underscore separator"

        # Should start with cloud provider prefix
        valid_prefixes = ["aws_", "gcp_", "azure_"]
        assert any(policy.resource_type.startswith(p) for p in valid_prefixes), \
            f"Resource type '{policy.resource_type}' should start with provider prefix"


class TestExpressionValidation:
    """Test that policy expressions are syntactically valid."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader."""
        return PolicyLoader(policy_dirs=[str(d) for d in POLICY_DIRS if d.exists()])

    @pytest.fixture
    def expression_evaluator(self):
        """Create an ExpressionEvaluator."""
        return ExpressionEvaluator()

    @pytest.fixture(params=get_all_policy_files(), ids=get_policy_ids())
    def policy_file(self, request) -> Path:
        """Parametrized fixture for each policy file."""
        return request.param

    def test_expression_syntax_valid(self, loader, expression_evaluator, policy_file):
        """Test each policy's expression has valid syntax."""
        policy = loader.load_policy(str(policy_file))

        if policy.check.expression:
            errors = expression_evaluator.validate(policy.check.expression)
            assert len(errors) == 0, f"Policy {policy.id} has invalid expression: {errors}"

    def test_expression_references_resource(self, loader, policy_file):
        """Test expression references the 'resource' object."""
        policy = loader.load_policy(str(policy_file))

        if policy.check.expression:
            # Expression should reference resource. for evaluation context
            assert "resource." in policy.check.expression or "resource[" in policy.check.expression, \
                f"Policy {policy.id} expression should reference 'resource.'"


class TestComplianceMappings:
    """Test compliance framework mappings in policies."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader."""
        return PolicyLoader(policy_dirs=[str(d) for d in POLICY_DIRS if d.exists()])

    @pytest.fixture(params=get_all_policy_files(), ids=get_policy_ids())
    def policy_file(self, request) -> Path:
        """Parametrized fixture for each policy file."""
        return request.param

    def test_compliance_mapping_format(self, loader, policy_file):
        """Test compliance mappings have required fields."""
        policy = loader.load_policy(str(policy_file))

        for mapping in policy.compliance:
            assert mapping.framework, f"Policy {policy.id} compliance mapping missing framework"
            assert mapping.control, f"Policy {policy.id} compliance mapping missing control"

    def test_compliance_framework_valid(self, loader, policy_file):
        """Test compliance framework names are valid."""
        policy = loader.load_policy(str(policy_file))

        valid_frameworks = [
            "cis-aws-foundations",
            "cis-gcp-foundations",
            "cis-azure-foundations",
            "pci-dss",
            "aws-foundational-security",
            "gcp-security-best-practices",
            "azure-security-benchmark",
            "hipaa",
            "soc2",
            "nist-800-53",
        ]

        for mapping in policy.compliance:
            # Allow some flexibility for version suffixes
            framework_base = mapping.framework.split("-v")[0]
            assert any(framework_base.startswith(f) or f in framework_base for f in valid_frameworks), \
                f"Policy {policy.id} has unknown compliance framework: {mapping.framework}"


class TestRemediationGuidance:
    """Test remediation guidance in policies."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader."""
        return PolicyLoader(policy_dirs=[str(d) for d in POLICY_DIRS if d.exists()])

    @pytest.fixture(params=get_all_policy_files(), ids=get_policy_ids())
    def policy_file(self, request) -> Path:
        """Parametrized fixture for each policy file."""
        return request.param

    def test_remediation_guidance_exists(self, loader, policy_file):
        """Test each policy has remediation guidance."""
        policy = loader.load_policy(str(policy_file))

        assert policy.remediation is not None, f"Policy {policy.id} missing remediation"
        assert policy.remediation.guidance, f"Policy {policy.id} missing remediation guidance"

    def test_remediation_guidance_meaningful(self, loader, policy_file):
        """Test remediation guidance is not trivially short."""
        policy = loader.load_policy(str(policy_file))

        # Guidance should be at least somewhat detailed
        min_length = 50
        assert len(policy.remediation.guidance) >= min_length, \
            f"Policy {policy.id} remediation guidance too short ({len(policy.remediation.guidance)} chars)"


class TestPolicyConsistency:
    """Test consistency across all policies."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader."""
        return PolicyLoader(policy_dirs=[str(d) for d in POLICY_DIRS if d.exists()])

    def test_no_duplicate_policy_ids(self, loader):
        """Test all policy IDs are unique."""
        policies = loader.load_all()

        ids = [p.id for p in policies]
        duplicates = [id for id in ids if ids.count(id) > 1]

        assert len(duplicates) == 0, f"Duplicate policy IDs found: {set(duplicates)}"

    def test_policy_names_unique(self, loader):
        """Test policy names are reasonably unique."""
        policies = loader.load_all()

        names = [p.name for p in policies]
        # Names don't have to be strictly unique, but warn about exact duplicates
        duplicates = [name for name in names if names.count(name) > 1]

        if duplicates:
            pytest.warns(UserWarning, match="Duplicate policy names")

    def test_severity_distribution_reasonable(self, loader):
        """Test severity distribution is reasonable (not all critical)."""
        policies = loader.load_all()

        severity_counts = {}
        for policy in policies:
            severity = policy.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        total = len(policies)
        if total > 0:
            # Not all policies should be CRITICAL
            critical_ratio = severity_counts.get("critical", 0) / total
            assert critical_ratio < 0.5, f"Too many critical policies: {critical_ratio:.0%}"

    def test_all_enabled_policies_have_tags(self, loader):
        """Test all enabled policies have at least one tag."""
        policies = loader.load_all()

        for policy in policies:
            if policy.enabled:
                assert len(policy.tags) > 0, f"Policy {policy.id} has no tags"


class TestPolicyByCloud:
    """Test policies organized by cloud provider."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader."""
        return PolicyLoader(policy_dirs=[str(d) for d in POLICY_DIRS if d.exists()])

    def test_aws_policies_target_aws_resources(self, loader):
        """Test AWS policies target AWS resources."""
        aws_dir = PROJECT_ROOT / "policies" / "aws"
        if not aws_dir.exists():
            pytest.skip("No AWS policies directory")

        aws_loader = PolicyLoader(policy_dirs=[str(aws_dir)])
        policies = aws_loader.load_all()

        for policy in policies:
            assert policy.resource_type.startswith("aws_"), \
                f"AWS policy {policy.id} targets non-AWS resource: {policy.resource_type}"

    def test_gcp_policies_target_gcp_resources(self, loader):
        """Test GCP policies target GCP resources."""
        gcp_dir = PROJECT_ROOT / "policies" / "gcp"
        if not gcp_dir.exists():
            pytest.skip("No GCP policies directory")

        gcp_loader = PolicyLoader(policy_dirs=[str(gcp_dir)])
        policies = gcp_loader.load_all()

        for policy in policies:
            assert policy.resource_type.startswith("gcp_"), \
                f"GCP policy {policy.id} targets non-GCP resource: {policy.resource_type}"

    def test_azure_policies_target_azure_resources(self, loader):
        """Test Azure policies target Azure resources."""
        azure_dir = PROJECT_ROOT / "policies" / "azure"
        if not azure_dir.exists():
            pytest.skip("No Azure policies directory")

        azure_loader = PolicyLoader(policy_dirs=[str(azure_dir)])
        policies = azure_loader.load_all()

        for policy in policies:
            assert policy.resource_type.startswith("azure_"), \
                f"Azure policy {policy.id} targets non-Azure resource: {policy.resource_type}"


class TestSpecificPolicies:
    """Test specific required policies exist and are correctly configured."""

    @pytest.fixture
    def loader(self):
        """Create a PolicyLoader."""
        return PolicyLoader(policy_dirs=[str(d) for d in POLICY_DIRS if d.exists()])

    def test_root_mfa_policy_exists(self, loader):
        """Test root MFA policy exists (required by roadmap)."""
        policies = loader.load_all()
        policy = policies.get_by_id("aws-iam-001")

        assert policy is not None, "Root MFA policy (aws-iam-001) should exist"
        assert policy.severity == Severity.CRITICAL, "Root MFA should be critical severity"

    def test_s3_encryption_policy_exists(self, loader):
        """Test S3 encryption policy exists (required by roadmap)."""
        policies = loader.load_all()
        policy = policies.get_by_id("aws-s3-001")

        assert policy is not None, "S3 encryption policy (aws-s3-001) should exist"
        assert policy.resource_type == "aws_s3_bucket"

    def test_security_group_ssh_policy_exists(self, loader):
        """Test security group SSH policy exists (required by roadmap)."""
        policies = loader.load_all()

        # Look for a policy about SSH access
        ssh_policies = [p for p in policies if "ssh" in p.id.lower() or "ssh" in p.name.lower()]
        assert len(ssh_policies) > 0, "Should have at least one SSH-related policy"

    def test_imdsv2_policy_exists(self, loader):
        """Test IMDSv2 policy exists (required by roadmap)."""
        policies = loader.load_all()

        # Look for IMDSv2 policy - check ID, name, or tags
        imds_policies = [
            p for p in policies
            if "imds" in p.id.lower()
            or "imds" in p.name.lower()
            or "metadata" in p.name.lower()
            or any("imds" in tag.lower() for tag in p.tags)
        ]
        assert len(imds_policies) > 0, "Should have at least one IMDS/metadata policy"
