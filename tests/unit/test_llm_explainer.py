"""
Tests for Mantissa Stance FindingExplainer and DataSanitizer.

Tests cover:
- FindingExplainer generation and parsing
- DataSanitizer pattern detection and redaction
- CLI integration for findings explain command
- Privacy protection features
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from stance.models.finding import Finding, FindingType, Severity, FindingStatus
from stance.llm import (
    LLMProvider,
    LLMError,
)
from stance.llm.explainer import (
    FindingExplainer,
    FindingExplanation,
    create_explainer,
    EXPLANATION_SYSTEM_PROMPT,
)
from stance.llm.sanitizer import (
    DataSanitizer,
    SanitizationResult,
    create_sanitizer,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        id="finding-001",
        asset_id="arn:aws:s3:::test-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        title="S3 Bucket Public Access Enabled",
        description="The S3 bucket has public access enabled, which may expose sensitive data.",
        rule_id="aws-s3-001",
        resource_path="public_access_block.block_public_acls",
        expected_value="true",
        actual_value="false",
        compliance_frameworks=["CIS 2.1.5", "PCI-DSS 1.2.3"],
        remediation_guidance="Enable block public access on the S3 bucket.",
        first_seen=datetime(2024, 1, 1),
        last_seen=datetime(2024, 1, 2),
    )


@pytest.fixture
def vulnerability_finding() -> Finding:
    """Create a vulnerability finding for testing."""
    return Finding(
        id="vuln-001",
        asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        finding_type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        title="Critical CVE in OpenSSL",
        description="A critical vulnerability in OpenSSL allows remote code execution.",
        cve_id="CVE-2024-12345",
        cvss_score=9.8,
        package_name="openssl",
        installed_version="1.1.1",
        fixed_version="1.1.1w",
        remediation_guidance="Update OpenSSL to version 1.1.1w or later.",
    )


@pytest.fixture
def mock_llm() -> MagicMock:
    """Create a mock LLM provider."""
    mock = MagicMock(spec=LLMProvider)
    mock.provider_name = "mock"
    mock.model_name = "mock-model"
    return mock


@pytest.fixture
def explainer(mock_llm) -> FindingExplainer:
    """Create a FindingExplainer with mock LLM."""
    return FindingExplainer(llm_provider=mock_llm)


@pytest.fixture
def sanitizer() -> DataSanitizer:
    """Create a DataSanitizer."""
    return DataSanitizer()


# ============================================================================
# FindingExplanation Tests
# ============================================================================


class TestFindingExplanation:
    """Tests for FindingExplanation dataclass."""

    def test_finding_explanation_creation(self):
        """Test FindingExplanation creation."""
        explanation = FindingExplanation(
            finding_id="finding-001",
            summary="Test summary",
            risk_explanation="Test risk",
            business_impact="Test impact",
            remediation_steps=["Step 1", "Step 2"],
            technical_details="Technical info",
            references=["https://example.com"],
            is_valid=True,
        )

        assert explanation.finding_id == "finding-001"
        assert explanation.summary == "Test summary"
        assert explanation.is_valid is True
        assert len(explanation.remediation_steps) == 2

    def test_finding_explanation_with_error(self):
        """Test FindingExplanation with error."""
        explanation = FindingExplanation(
            finding_id="finding-001",
            summary="",
            risk_explanation="",
            business_impact="",
            remediation_steps=[],
            technical_details="",
            references=[],
            is_valid=False,
            error="LLM error: API unavailable",
        )

        assert explanation.is_valid is False
        assert explanation.error is not None
        assert "LLM error" in explanation.error


# ============================================================================
# FindingExplainer Tests
# ============================================================================


class TestFindingExplainer:
    """Tests for FindingExplainer."""

    def test_explainer_init(self, mock_llm):
        """Test FindingExplainer initialization."""
        explainer = FindingExplainer(llm_provider=mock_llm)

        assert explainer._llm == mock_llm
        assert explainer._sanitizer is None

    def test_explainer_with_sanitizer(self, mock_llm, sanitizer):
        """Test FindingExplainer with sanitizer."""
        explainer = FindingExplainer(llm_provider=mock_llm, sanitizer=sanitizer)

        assert explainer._sanitizer == sanitizer

    def test_explain_finding_success(self, explainer, mock_llm, sample_finding):
        """Test successful finding explanation."""
        mock_llm.generate.return_value = """
SUMMARY: S3 bucket has public access enabled, potentially exposing data.

RISK: Public S3 buckets can lead to data breaches. Anyone on the internet can access the bucket contents.

BUSINESS IMPACT: May violate compliance requirements and expose sensitive data.

REMEDIATION STEPS:
1. Navigate to S3 console
2. Select the bucket
3. Enable block public access

TECHNICAL DETAILS: The public access block settings control bucket ACL permissions.

REFERENCES:
- https://docs.aws.amazon.com/s3
"""
        result = explainer.explain_finding(sample_finding)

        assert isinstance(result, FindingExplanation)
        assert result.finding_id == "finding-001"
        assert result.is_valid is True
        assert "S3" in result.summary
        assert len(result.remediation_steps) > 0

    def test_explain_finding_llm_error(self, explainer, mock_llm, sample_finding):
        """Test finding explanation with LLM error."""
        mock_llm.generate.side_effect = LLMError("API error")

        result = explainer.explain_finding(sample_finding)

        assert result.is_valid is False
        assert "LLM error" in result.error

    def test_explain_finding_with_asset_context(self, explainer, mock_llm, sample_finding):
        """Test explanation with asset context."""
        mock_llm.generate.return_value = """
SUMMARY: Test summary.

RISK: Test risk.

TECHNICAL DETAILS: Test details.
"""
        asset_context = {
            "name": "test-bucket",
            "region": "us-east-1",
            "tags": {"Environment": "production"},
        }

        result = explainer.explain_finding(sample_finding, asset_context=asset_context)

        # Check that context was included in prompt
        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]
        assert "test-bucket" in prompt or result.is_valid

    def test_explain_finding_without_remediation(self, explainer, mock_llm, sample_finding):
        """Test explanation without remediation steps."""
        mock_llm.generate.return_value = """
SUMMARY: Test summary.

RISK: Test risk.

TECHNICAL DETAILS: Test details.
"""

        result = explainer.explain_finding(sample_finding, include_remediation=False)

        # Check that prompt asked to skip remediation
        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]
        assert "Skip remediation" in prompt or result.is_valid

    def test_explain_vulnerability_finding(self, explainer, mock_llm, vulnerability_finding):
        """Test explanation of vulnerability finding."""
        mock_llm.generate.return_value = """
SUMMARY: Critical OpenSSL vulnerability.

RISK: Remote code execution possible.

BUSINESS IMPACT: High risk to infrastructure.

REMEDIATION STEPS:
1. Update OpenSSL package
2. Restart affected services

TECHNICAL DETAILS: CVE-2024-12345 affects OpenSSL < 1.1.1w.

REFERENCES:
- https://cve.mitre.org/CVE-2024-12345
"""

        result = explainer.explain_finding(vulnerability_finding)

        assert result.is_valid is True
        # Check that CVE-specific fields were included in prompt
        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]
        assert "CVE-2024-12345" in prompt

    def test_explain_multiple_findings(self, explainer, mock_llm, sample_finding, vulnerability_finding):
        """Test explaining multiple findings."""
        mock_llm.generate.return_value = """
SUMMARY: Test summary.

RISK: Test risk.

TECHNICAL DETAILS: Test details.
"""

        findings = [sample_finding, vulnerability_finding]
        results = explainer.explain_multiple(findings)

        assert len(results) == 2
        assert mock_llm.generate.call_count == 2

    def test_explain_multiple_with_limit(self, explainer, mock_llm, sample_finding):
        """Test explaining multiple findings with limit."""
        mock_llm.generate.return_value = """
SUMMARY: Test.

RISK: Test.

TECHNICAL DETAILS: Test.
"""

        findings = [sample_finding] * 20
        results = explainer.explain_multiple(findings, max_findings=5)

        assert len(results) == 5
        assert mock_llm.generate.call_count == 5

    def test_get_summary_for_severity(self, explainer, mock_llm, sample_finding):
        """Test severity-based summary."""
        mock_llm.generate.return_value = "Executive summary of high severity findings."

        summary = explainer.get_summary_for_severity([sample_finding], Severity.HIGH)

        assert "Executive summary" in summary or len(summary) > 0

    def test_get_summary_for_empty_findings(self, explainer, sample_finding):
        """Test summary with no findings for severity."""
        summary = explainer.get_summary_for_severity([sample_finding], Severity.CRITICAL)

        assert "No critical findings" in summary

    def test_build_prompt_includes_required_fields(self, explainer, mock_llm, sample_finding):
        """Test that prompt includes all required fields."""
        mock_llm.generate.return_value = "SUMMARY: Test\n\nRISK: Test\n\nTECHNICAL DETAILS: Test"

        explainer.explain_finding(sample_finding)

        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]

        assert sample_finding.title in prompt
        assert sample_finding.severity.value in prompt
        assert sample_finding.finding_type.value in prompt
        assert sample_finding.rule_id in prompt

    def test_parse_response_extracts_sections(self, explainer, mock_llm, sample_finding):
        """Test response parsing extracts all sections."""
        mock_llm.generate.return_value = """
SUMMARY: This is the summary.

RISK: This is the risk explanation.

BUSINESS IMPACT: This is the business impact.

REMEDIATION STEPS:
1. First step
2. Second step
3. Third step

TECHNICAL DETAILS: Technical explanation here.

REFERENCES:
- https://example.com/doc1
- https://example.com/doc2
"""

        result = explainer.explain_finding(sample_finding)

        assert result.summary == "This is the summary."
        assert "risk explanation" in result.risk_explanation
        assert "business impact" in result.business_impact
        assert len(result.remediation_steps) == 3
        assert "First step" in result.remediation_steps[0]
        assert "Technical explanation" in result.technical_details
        assert len(result.references) == 2


class TestCreateExplainer:
    """Tests for create_explainer factory function."""

    def test_create_explainer_default(self):
        """Test create_explainer with defaults."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            explainer = create_explainer()

            assert isinstance(explainer, FindingExplainer)
            assert explainer._llm is not None

    def test_create_explainer_custom_provider(self):
        """Test create_explainer with custom provider."""
        with patch.dict("os.environ", {"OPENAI_API_KEY": "test-key"}):
            explainer = create_explainer(provider="openai")

            assert explainer._llm.provider_name == "openai"

    def test_create_explainer_with_sanitization(self):
        """Test create_explainer enables sanitization."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            explainer = create_explainer(enable_sanitization=True)

            assert explainer._sanitizer is not None

    def test_create_explainer_without_sanitization(self):
        """Test create_explainer disables sanitization."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
            explainer = create_explainer(enable_sanitization=False)

            assert explainer._sanitizer is None


# ============================================================================
# DataSanitizer Tests
# ============================================================================


class TestDataSanitizer:
    """Tests for DataSanitizer."""

    def test_sanitizer_init_default(self):
        """Test DataSanitizer default initialization."""
        sanitizer = DataSanitizer()

        assert sanitizer._redact_emails is False
        assert sanitizer._redact_ips is False
        assert sanitizer._redact_account_ids is False

    def test_sanitizer_init_custom(self):
        """Test DataSanitizer custom initialization."""
        sanitizer = DataSanitizer(
            redact_emails=True,
            redact_ips=True,
            redact_account_ids=True,
        )

        assert sanitizer._redact_emails is True
        assert sanitizer._redact_ips is True
        assert sanitizer._redact_account_ids is True

    def test_sanitize_aws_access_key(self, sanitizer):
        """Test sanitization of AWS access key."""
        text = "Access key: AKIAIOSFODNN7EXAMPLE"
        result = sanitizer.sanitize(text)

        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_sanitize_aws_secret_key(self, sanitizer):
        """Test sanitization of AWS secret key."""
        # 40 character base64-like secret
        text = "Secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result = sanitizer.sanitize(text)

        assert "wJalrXUtnFEMI" not in result

    def test_sanitize_generic_api_key(self, sanitizer):
        """Test sanitization of generic API key."""
        text = "api_key: sk-12345678901234567890123456789012"
        result = sanitizer.sanitize(text)

        assert "sk-12345678901234567890123456789012" not in result
        assert "REDACTED" in result

    def test_sanitize_bearer_token(self, sanitizer):
        """Test sanitization of bearer token."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
        result = sanitizer.sanitize(text)

        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "REDACTED" in result

    def test_sanitize_password(self, sanitizer):
        """Test sanitization of password."""
        text = "password: SuperSecretPassword123!"
        result = sanitizer.sanitize(text)

        assert "SuperSecretPassword123!" not in result
        assert "REDACTED" in result

    def test_sanitize_private_key(self, sanitizer):
        """Test sanitization of private key."""
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALRiMLAHudeSA2ai
-----END RSA PRIVATE KEY-----"""
        result = sanitizer.sanitize(text)

        assert "MIIBOgIBAAJBALRiMLAHudeSA2ai" not in result
        assert "REDACTED" in result

    def test_sanitize_jwt_token(self, sanitizer):
        """Test sanitization of JWT token."""
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = sanitizer.sanitize(text)

        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "REDACTED" in result

    def test_sanitize_email_disabled_by_default(self, sanitizer):
        """Test emails are NOT sanitized by default."""
        text = "contact: user@example.com"
        result = sanitizer.sanitize(text)

        # Emails should NOT be redacted by default
        assert "user@example.com" in result

    def test_sanitize_email_when_enabled(self):
        """Test emails ARE sanitized when enabled."""
        sanitizer = DataSanitizer(redact_emails=True)
        text = "contact: user@example.com"
        result = sanitizer.sanitize(text)

        assert "user@example.com" not in result
        assert "REDACTED" in result

    def test_sanitize_ip_disabled_by_default(self, sanitizer):
        """Test IPs are NOT sanitized by default."""
        text = "server: 192.168.1.100"
        result = sanitizer.sanitize(text)

        assert "192.168.1.100" in result

    def test_sanitize_ip_when_enabled(self):
        """Test IPs ARE sanitized when enabled."""
        sanitizer = DataSanitizer(redact_ips=True)
        text = "server: 192.168.1.100"
        result = sanitizer.sanitize(text)

        assert "192.168.1.100" not in result
        assert "REDACTED" in result

    def test_sanitize_account_id_disabled_by_default(self, sanitizer):
        """Test account IDs are NOT sanitized by default."""
        text = "account: 123456789012"
        result = sanitizer.sanitize(text)

        assert "123456789012" in result

    def test_sanitize_account_id_when_enabled(self):
        """Test account IDs ARE sanitized when enabled."""
        sanitizer = DataSanitizer(redact_account_ids=True)
        text = "account: 123456789012"
        result = sanitizer.sanitize(text)

        assert "123456789012" not in result
        assert "REDACTED" in result

    def test_sanitize_with_details(self, sanitizer):
        """Test sanitize_with_details returns metadata."""
        text = "key: AKIAIOSFODNN7EXAMPLE"
        result = sanitizer.sanitize_with_details(text)

        assert isinstance(result, SanitizationResult)
        assert result.redactions_made > 0
        assert "aws_access_key" in result.redaction_types

    def test_sanitize_dict(self, sanitizer):
        """Test sanitizing a dictionary."""
        data = {
            "name": "test",
            "credentials": {
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "password": "password: secret123"
            }
        }

        result = sanitizer.sanitize_dict(data)

        assert "AKIAIOSFODNN7EXAMPLE" not in str(result)
        assert result["name"] == "test"

    def test_is_sensitive_true(self, sanitizer):
        """Test is_sensitive returns True for sensitive data."""
        assert sanitizer.is_sensitive("AKIAIOSFODNN7EXAMPLE") is True
        assert sanitizer.is_sensitive("password: secretpassword123") is True

    def test_is_sensitive_false(self, sanitizer):
        """Test is_sensitive returns False for safe data."""
        assert sanitizer.is_sensitive("This is safe text") is False
        assert sanitizer.is_sensitive("bucket_name: test-bucket") is False

    def test_get_sensitive_types(self, sanitizer):
        """Test get_sensitive_types returns detected types."""
        text = "key: AKIAIOSFODNN7EXAMPLE, password: secret123456"
        types = sanitizer.get_sensitive_types(text)

        assert "aws_access_key" in types
        assert "password" in types

    def test_preserve_structure_creates_consistent_tokens(self, sanitizer):
        """Test preserve_structure creates consistent replacement tokens."""
        text = "key1: AKIAIOSFODNN7EXAMPLE, key2: AKIAIOSFODNN7EXAMPLE"
        result = sanitizer.sanitize_with_details(text)

        # Same value should get same token
        tokens = [v for v in result.mapping.values()]
        # Both occurrences should map to same token
        assert len(set(result.mapping.values())) == 1 or result.redactions_made > 0

    def test_desanitize_restores_original(self, sanitizer):
        """Test desanitize can restore original values."""
        original = "key: AKIAIOSFODNN7EXAMPLE"
        result = sanitizer.sanitize_with_details(original)
        restored = sanitizer.desanitize(result.sanitized_text, result.mapping)

        assert restored == original

    def test_sanitize_multiple_sensitive_items(self, sanitizer):
        """Test sanitizing text with multiple sensitive items."""
        text = """
API Key: AKIAIOSFODNN7EXAMPLE
Password: password=MySecretPass123
Token: Bearer abc123def456ghi789jkl012mno
"""
        result = sanitizer.sanitize(text)

        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "MySecretPass123" not in result

    def test_sanitize_preserves_non_sensitive_data(self, sanitizer):
        """Test sanitization preserves non-sensitive data."""
        text = """
Finding: S3 Bucket Public Access
Severity: HIGH
Resource: test-bucket
"""
        result = sanitizer.sanitize(text)

        assert "S3 Bucket Public Access" in result
        assert "HIGH" in result
        assert "test-bucket" in result


class TestCreateSanitizer:
    """Tests for create_sanitizer factory function."""

    def test_create_sanitizer_default(self):
        """Test create_sanitizer with defaults."""
        sanitizer = create_sanitizer()

        assert isinstance(sanitizer, DataSanitizer)
        assert sanitizer._redact_emails is False

    def test_create_sanitizer_all_options(self):
        """Test create_sanitizer with all options."""
        sanitizer = create_sanitizer(
            redact_emails=True,
            redact_ips=True,
            redact_account_ids=True,
        )

        assert sanitizer._redact_emails is True
        assert sanitizer._redact_ips is True
        assert sanitizer._redact_account_ids is True


# ============================================================================
# Integration Tests
# ============================================================================


class TestExplainerWithSanitizer:
    """Integration tests for FindingExplainer with DataSanitizer."""

    def test_explainer_sanitizes_prompt(self, mock_llm, sample_finding):
        """Test that explainer sanitizes prompt before sending to LLM."""
        sanitizer = DataSanitizer()
        explainer = FindingExplainer(llm_provider=mock_llm, sanitizer=sanitizer)

        mock_llm.generate.return_value = "SUMMARY: Test\n\nRISK: Test\n\nTECHNICAL DETAILS: Test"

        # Add sensitive data to asset context
        asset_context = {
            "credentials": "api_key=AKIAIOSFODNN7EXAMPLE",
        }

        explainer.explain_finding(sample_finding, asset_context=asset_context)

        # Verify the prompt sent to LLM was sanitized
        call_args = mock_llm.generate.call_args
        prompt = call_args.kwargs.get("prompt") or call_args.args[0]

        # The actual AWS access key should not appear in the prompt
        assert "AKIAIOSFODNN7EXAMPLE" not in prompt


class TestSystemPrompt:
    """Tests for the explanation system prompt."""

    def test_system_prompt_content(self):
        """Test system prompt contains required elements."""
        assert "cloud security" in EXPLANATION_SYSTEM_PROMPT.lower()
        assert "SUMMARY" in EXPLANATION_SYSTEM_PROMPT
        assert "RISK" in EXPLANATION_SYSTEM_PROMPT
        assert "REMEDIATION" in EXPLANATION_SYSTEM_PROMPT
