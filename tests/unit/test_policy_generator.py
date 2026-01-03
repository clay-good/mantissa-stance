"""
Tests for Mantissa Stance PolicyGenerator.

Tests cover:
- Policy generation from natural language
- Policy validation
- YAML output formatting
- CLI integration for policy generation
- Policy suggestions
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from stance.llm import (
    LLMProvider,
    LLMError,
)
from stance.llm.policy_generator import (
    PolicyGenerator,
    GeneratedPolicy,
    create_policy_generator,
    save_policy,
    RESOURCE_TYPES,
    COMPLIANCE_FRAMEWORKS,
    POLICY_SYSTEM_PROMPT,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_llm() -> MagicMock:
    """Create a mock LLM provider."""
    mock = MagicMock(spec=LLMProvider)
    mock.provider_name = "mock"
    mock.model_name = "mock-model"
    return mock


@pytest.fixture
def generator(mock_llm) -> PolicyGenerator:
    """Create a PolicyGenerator with mock LLM."""
    return PolicyGenerator(llm_provider=mock_llm, cloud_provider="aws")


@pytest.fixture
def valid_policy_yaml() -> str:
    """Return a valid policy YAML string."""
    return """id: aws-s3-010
name: S3 bucket versioning enabled
description: |
  Ensure S3 buckets have versioning enabled to protect
  against accidental deletion and maintain object history.

enabled: true
severity: medium

resource_type: aws_s3_bucket

check:
  type: expression
  expression: "resource.versioning.status == 'Enabled'"

compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "2.1.3"

remediation:
  guidance: |
    1. Open the Amazon S3 console
    2. Select the bucket
    3. Go to Properties tab
    4. Enable Bucket Versioning
  automation_supported: false

tags:
  - s3
  - versioning
  - data-protection

references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html
"""


# ============================================================================
# GeneratedPolicy Tests
# ============================================================================


class TestGeneratedPolicy:
    """Tests for GeneratedPolicy dataclass."""

    def test_generated_policy_creation(self, valid_policy_yaml):
        """Test GeneratedPolicy creation."""
        policy = GeneratedPolicy(
            description="Enable S3 versioning",
            policy_id="aws-s3-010",
            policy_name="S3 bucket versioning enabled",
            yaml_content=valid_policy_yaml,
            resource_type="aws_s3_bucket",
            severity="medium",
            is_valid=True,
        )

        assert policy.description == "Enable S3 versioning"
        assert policy.policy_id == "aws-s3-010"
        assert policy.is_valid is True
        assert len(policy.validation_errors) == 0

    def test_generated_policy_with_errors(self):
        """Test GeneratedPolicy with validation errors."""
        policy = GeneratedPolicy(
            description="Bad policy",
            policy_id="",
            policy_name="",
            yaml_content="invalid yaml",
            resource_type="",
            severity="",
            is_valid=False,
            validation_errors=["Missing required field: id"],
        )

        assert policy.is_valid is False
        assert len(policy.validation_errors) == 1

    def test_generated_policy_with_llm_error(self):
        """Test GeneratedPolicy with LLM error."""
        policy = GeneratedPolicy(
            description="Test policy",
            policy_id="",
            policy_name="",
            yaml_content="",
            resource_type="",
            severity="",
            is_valid=False,
            error="LLM error: API unavailable",
        )

        assert policy.is_valid is False
        assert policy.error is not None


# ============================================================================
# PolicyGenerator Tests
# ============================================================================


class TestPolicyGenerator:
    """Tests for PolicyGenerator."""

    def test_generator_init(self, mock_llm):
        """Test PolicyGenerator initialization."""
        generator = PolicyGenerator(llm_provider=mock_llm)

        assert generator._llm == mock_llm
        assert generator._cloud_provider == "aws"

    def test_generator_custom_cloud(self, mock_llm):
        """Test PolicyGenerator with custom cloud provider."""
        generator = PolicyGenerator(llm_provider=mock_llm, cloud_provider="gcp")

        assert generator._cloud_provider == "gcp"

    def test_generate_policy_success(self, generator, mock_llm, valid_policy_yaml):
        """Test successful policy generation."""
        mock_llm.generate.return_value = valid_policy_yaml

        result = generator.generate_policy("Enable versioning on S3 buckets")

        assert isinstance(result, GeneratedPolicy)
        assert result.is_valid is True
        assert result.policy_id == "aws-s3-010"
        assert result.resource_type == "aws_s3_bucket"
        assert result.severity == "medium"

    def test_generate_policy_cleans_markdown(self, generator, mock_llm, valid_policy_yaml):
        """Test that markdown code blocks are cleaned from output."""
        mock_llm.generate.return_value = f"```yaml\n{valid_policy_yaml}\n```"

        result = generator.generate_policy("Enable versioning")

        assert "```" not in result.yaml_content
        assert result.is_valid is True

    def test_generate_policy_with_llm_error(self, generator, mock_llm):
        """Test policy generation with LLM error."""
        mock_llm.generate.side_effect = LLMError("API error")

        result = generator.generate_policy("Test policy")

        assert result.is_valid is False
        assert "LLM error" in result.error

    def test_generate_policy_with_severity_hint(self, generator, mock_llm, valid_policy_yaml):
        """Test generation with severity hint."""
        mock_llm.generate.return_value = valid_policy_yaml

        result = generator.generate_policy(
            "Enable versioning",
            severity="high",
        )

        # Check that severity was included in prompt
        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]
        assert "high" in prompt.lower()

    def test_generate_policy_with_resource_type(self, generator, mock_llm, valid_policy_yaml):
        """Test generation with specific resource type."""
        mock_llm.generate.return_value = valid_policy_yaml

        result = generator.generate_policy(
            "Enable versioning",
            resource_type="aws_s3_bucket",
        )

        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]
        assert "aws_s3_bucket" in prompt

    def test_generate_policy_with_framework(self, generator, mock_llm, valid_policy_yaml):
        """Test generation with compliance framework."""
        mock_llm.generate.return_value = valid_policy_yaml

        result = generator.generate_policy(
            "Enable versioning",
            compliance_framework="cis-aws-foundations",
        )

        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]
        assert "CIS" in prompt or "cis" in prompt.lower()

    def test_generate_multiple_policies(self, generator, mock_llm, valid_policy_yaml):
        """Test generating multiple policies."""
        mock_llm.generate.return_value = valid_policy_yaml

        descriptions = [
            "Enable S3 versioning",
            "Require S3 encryption",
            "Block public S3 access",
        ]
        results = generator.generate_multiple(descriptions)

        assert len(results) == 3
        assert mock_llm.generate.call_count == 3

    def test_suggest_policy_ideas(self, generator, mock_llm):
        """Test policy suggestion generation."""
        mock_llm.generate.return_value = """Check S3 bucket encryption is enabled
Verify S3 versioning is configured
Ensure public access is blocked
Confirm logging is enabled
Validate lifecycle policies exist"""

        suggestions = generator.suggest_policy_ideas("aws_s3_bucket", count=5)

        assert len(suggestions) == 5
        assert "encryption" in suggestions[0].lower()

    def test_suggest_policy_ideas_with_llm_error(self, generator, mock_llm):
        """Test suggestion generation with LLM error."""
        mock_llm.generate.side_effect = LLMError("API error")

        suggestions = generator.suggest_policy_ideas("aws_s3_bucket")

        assert suggestions == []


class TestPolicyValidation:
    """Tests for policy validation."""

    def test_validate_empty_content(self, generator):
        """Test validation of empty content."""
        result = generator._validate_policy("")

        assert result["is_valid"] is False
        assert "Empty policy content" in result["errors"]

    def test_validate_missing_id(self, generator):
        """Test validation catches missing id."""
        yaml = """name: Test
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "true"
"""
        result = generator._validate_policy(yaml)

        assert result["is_valid"] is False
        assert any("id" in e.lower() for e in result["errors"])

    def test_validate_missing_severity(self, generator):
        """Test validation catches missing severity."""
        yaml = """id: aws-s3-001
name: Test
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "true"
"""
        result = generator._validate_policy(yaml)

        assert result["is_valid"] is False
        assert any("severity" in e.lower() for e in result["errors"])

    def test_validate_invalid_severity(self, generator):
        """Test validation catches invalid severity."""
        yaml = """id: aws-s3-001
name: Test
severity: extreme
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "true"
"""
        result = generator._validate_policy(yaml)

        assert result["is_valid"] is False
        assert any("severity" in e.lower() for e in result["errors"])

    def test_validate_missing_check(self, generator):
        """Test validation catches missing check."""
        yaml = """id: aws-s3-001
name: Test
severity: high
resource_type: aws_s3_bucket
"""
        result = generator._validate_policy(yaml)

        assert result["is_valid"] is False
        assert any("check" in e.lower() for e in result["errors"])

    def test_validate_invalid_resource_type_format(self, generator):
        """Test validation catches invalid resource type format."""
        yaml = """id: aws-s3-001
name: Test
severity: high
resource_type: S3Bucket
check:
  type: expression
  expression: "true"
"""
        result = generator._validate_policy(yaml)

        assert result["is_valid"] is False
        assert any("resource_type" in e.lower() for e in result["errors"])

    def test_validate_invalid_id_format(self, generator):
        """Test validation catches invalid policy ID format."""
        yaml = """id: my-policy
name: Test
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "true"
"""
        result = generator._validate_policy(yaml)

        assert result["is_valid"] is False
        assert any("id" in e.lower() for e in result["errors"])

    def test_validate_expression_missing_operator(self, generator):
        """Test validation catches expression without operator."""
        yaml = """id: aws-s3-001
name: Test
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.versioning"
"""
        result = generator._validate_policy(yaml)

        assert result["is_valid"] is False
        assert any("expression" in e.lower() or "operator" in e.lower() for e in result["errors"])

    def test_validate_valid_policy(self, generator, valid_policy_yaml):
        """Test validation accepts valid policy."""
        result = generator._validate_policy(valid_policy_yaml)

        assert result["is_valid"] is True
        assert result["errors"] == []


class TestFieldExtraction:
    """Tests for field extraction."""

    def test_extract_id(self, generator):
        """Test extracting policy ID."""
        yaml = "id: aws-s3-001\nname: Test"
        result = generator._extract_field(yaml, "id")

        assert result == "aws-s3-001"

    def test_extract_name(self, generator):
        """Test extracting policy name."""
        yaml = "id: aws-s3-001\nname: Test Policy Name"
        result = generator._extract_field(yaml, "name")

        assert result == "Test Policy Name"

    def test_extract_quoted_value(self, generator):
        """Test extracting quoted value."""
        yaml = 'id: "aws-s3-001"'
        result = generator._extract_field(yaml, "id")

        assert result == "aws-s3-001"

    def test_extract_missing_field(self, generator):
        """Test extracting missing field."""
        yaml = "id: aws-s3-001"
        result = generator._extract_field(yaml, "name")

        assert result == ""


class TestCreatePolicyGenerator:
    """Tests for create_policy_generator factory function."""

    def test_create_generator_default(self):
        """Test create_policy_generator with defaults."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            generator = create_policy_generator()

            assert isinstance(generator, PolicyGenerator)
            assert generator._cloud_provider == "aws"

    def test_create_generator_custom_provider(self):
        """Test create_policy_generator with custom provider."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            generator = create_policy_generator(provider="openai")

            assert generator._llm.provider_name == "openai"

    def test_create_generator_custom_cloud(self):
        """Test create_policy_generator with custom cloud."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            generator = create_policy_generator(cloud_provider="gcp")

            assert generator._cloud_provider == "gcp"


class TestSavePolicy:
    """Tests for save_policy function."""

    def test_save_valid_policy(self, valid_policy_yaml):
        """Test saving a valid policy."""
        policy = GeneratedPolicy(
            description="Test",
            policy_id="aws-s3-010",
            policy_name="Test",
            yaml_content=valid_policy_yaml,
            resource_type="aws_s3_bucket",
            severity="medium",
            is_valid=True,
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            path = f.name

        try:
            result = save_policy(policy, path)

            assert result is True

            with open(path, "r") as f:
                content = f.read()
            assert "id: aws-s3-010" in content
        finally:
            os.unlink(path)

    def test_save_invalid_policy(self):
        """Test saving an invalid policy fails."""
        policy = GeneratedPolicy(
            description="Test",
            policy_id="",
            policy_name="",
            yaml_content="invalid",
            resource_type="",
            severity="",
            is_valid=False,
        )

        result = save_policy(policy, "/tmp/test.yaml")

        assert result is False

    def test_save_adds_newline(self, valid_policy_yaml):
        """Test that saved policy ends with newline."""
        yaml_no_newline = valid_policy_yaml.rstrip("\n")
        policy = GeneratedPolicy(
            description="Test",
            policy_id="aws-s3-010",
            policy_name="Test",
            yaml_content=yaml_no_newline,
            resource_type="aws_s3_bucket",
            severity="medium",
            is_valid=True,
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            path = f.name

        try:
            save_policy(policy, path)

            with open(path, "r") as f:
                content = f.read()
            assert content.endswith("\n")
        finally:
            os.unlink(path)


# ============================================================================
# Constants Tests
# ============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_resource_types_aws(self):
        """Test AWS resource types exist."""
        assert "aws" in RESOURCE_TYPES
        assert "aws_s3_bucket" in RESOURCE_TYPES["aws"]
        assert "aws_ec2_instance" in RESOURCE_TYPES["aws"]
        assert "aws_iam_user" in RESOURCE_TYPES["aws"]

    def test_resource_types_gcp(self):
        """Test GCP resource types exist."""
        assert "gcp" in RESOURCE_TYPES
        assert "gcp_storage_bucket" in RESOURCE_TYPES["gcp"]
        assert "gcp_compute_instance" in RESOURCE_TYPES["gcp"]

    def test_resource_types_azure(self):
        """Test Azure resource types exist."""
        assert "azure" in RESOURCE_TYPES
        assert "azure_storage_account" in RESOURCE_TYPES["azure"]
        assert "azure_vm" in RESOURCE_TYPES["azure"]

    def test_compliance_frameworks(self):
        """Test compliance frameworks exist."""
        assert "cis-aws-foundations" in COMPLIANCE_FRAMEWORKS
        assert "pci-dss" in COMPLIANCE_FRAMEWORKS
        assert "soc2" in COMPLIANCE_FRAMEWORKS
        assert "hipaa" in COMPLIANCE_FRAMEWORKS

    def test_system_prompt_content(self):
        """Test system prompt contains required elements."""
        assert "id:" in POLICY_SYSTEM_PROMPT
        assert "severity:" in POLICY_SYSTEM_PROMPT
        assert "resource_type:" in POLICY_SYSTEM_PROMPT
        assert "expression" in POLICY_SYSTEM_PROMPT.lower()


# ============================================================================
# Integration Tests
# ============================================================================


class TestPolicyGeneratorIntegration:
    """Integration tests for PolicyGenerator workflow."""

    def test_full_generation_workflow(self, mock_llm, valid_policy_yaml):
        """Test complete workflow: generate, validate, save."""
        mock_llm.generate.return_value = valid_policy_yaml

        # Create generator
        generator = PolicyGenerator(llm_provider=mock_llm)

        # Generate policy
        result = generator.generate_policy("Enable S3 versioning")

        assert result.is_valid is True

        # Save policy
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            path = f.name

        try:
            saved = save_policy(result, path)
            assert saved is True

            # Verify saved content
            with open(path, "r") as f:
                content = f.read()
            assert "aws-s3-010" in content
            assert "versioning" in content.lower()
        finally:
            os.unlink(path)
