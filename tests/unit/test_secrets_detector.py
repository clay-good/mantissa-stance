"""
Tests for Mantissa Stance SecretsDetector.

Tests cover:
- Pattern-based secret detection
- Entropy analysis
- Context analysis (field names)
- Finding generation
- Multi-cloud secret patterns
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from stance.detection.secrets import (
    SecretsDetector,
    SecretMatch,
    SecretsResult,
    SECRET_PATTERNS,
    SENSITIVE_FIELD_NAMES,
    create_secrets_detector,
    scan_assets_for_secrets,
)
from stance.models.asset import Asset
from stance.models.finding import Severity, FindingType, FindingStatus


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def detector() -> SecretsDetector:
    """Create a SecretsDetector with default settings."""
    return SecretsDetector()


@pytest.fixture
def sample_asset() -> Asset:
    """Create a sample asset for testing."""
    return Asset(
        id="arn:aws:lambda:us-east-1:123456789012:function:my-function",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_lambda_function",
        name="my-function",
        tags={"Environment": "production"},
        network_exposure="internal",
        created_at=datetime.now(),
        last_seen=datetime.now(),
        raw_config={
            "FunctionName": "my-function",
            "Environment": {
                "Variables": {
                    "DATABASE_URL": "postgres://user:password123@host:5432/db",
                    "API_KEY": "sk_live_1234567890abcdefghijklmnop",
                }
            }
        },
    )


@pytest.fixture
def asset_with_secrets() -> Asset:
    """Create an asset with embedded secrets."""
    return Asset(
        id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_ec2_instance",
        name="web-server",
        tags={
            "secret_key": "mysupersecretvalue123456789",
            "Environment": "production",
        },
        network_exposure="internet_facing",
        created_at=datetime.now(),
        last_seen=datetime.now(),
        raw_config={
            "InstanceId": "i-1234567890abcdef0",
            "UserData": "#!/bin/bash\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
    )


# ============================================================================
# SecretMatch Tests
# ============================================================================


class TestSecretMatch:
    """Tests for SecretMatch dataclass."""

    def test_secret_match_creation(self):
        """Test SecretMatch creation."""
        match = SecretMatch(
            secret_type="aws_access_key_id",
            field_path="config.access_key",
            matched_value="AKIAIOSFODNN7EXAMPLE",
            confidence="high",
            entropy=4.2,
        )

        assert match.secret_type == "aws_access_key_id"
        assert match.field_path == "config.access_key"
        assert match.matched_value == "AKIAIOSFODNN7EXAMPLE"
        assert match.confidence == "high"
        assert match.entropy == 4.2

    def test_secret_match_without_entropy(self):
        """Test SecretMatch without entropy value."""
        match = SecretMatch(
            secret_type="generic_api_key",
            field_path="env.API_KEY",
            matched_value="test_key_12345",
            confidence="medium",
        )

        assert match.entropy is None


# ============================================================================
# SecretsResult Tests
# ============================================================================


class TestSecretsResult:
    """Tests for SecretsResult dataclass."""

    def test_secrets_result_creation(self):
        """Test SecretsResult creation."""
        result = SecretsResult(
            asset_id="arn:aws:lambda:us-east-1:123456789012:function:test",
            secrets_found=2,
            matches=[
                SecretMatch(
                    secret_type="aws_access_key_id",
                    field_path="config.key",
                    matched_value="AKIA...",
                    confidence="high",
                ),
            ],
            scan_duration_seconds=0.05,
        )

        assert result.asset_id.startswith("arn:")
        assert result.secrets_found == 2
        assert len(result.matches) == 1

    def test_secrets_result_empty(self):
        """Test SecretsResult with no matches."""
        result = SecretsResult(
            asset_id="test-asset",
            secrets_found=0,
        )

        assert result.secrets_found == 0
        assert result.matches == []


# ============================================================================
# Pattern Detection Tests
# ============================================================================


class TestPatternDetection:
    """Tests for pattern-based secret detection."""

    def test_detect_aws_access_key(self, detector):
        """Test AWS access key detection."""
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        matches = detector.detect_in_text(text)

        assert any(m.secret_type == "aws_access_key_id" for m in matches)

    def test_detect_aws_access_key_variations(self, detector):
        """Test various AWS access key prefixes."""
        keys = [
            "AKIAIOSFODNN7EXAMPLE",  # Standard (20 chars total)
            "ASIAIOSFODNN7EXAMPLE",  # Session token
            "AROAIOSFODNN7EXAMPLE",  # Role
        ]

        for key in keys:
            matches = detector.detect_in_text(f"key={key}")
            assert any(
                m.secret_type == "aws_access_key_id" for m in matches
            ), f"Failed to detect {key[:4]}..."

    def test_detect_gcp_api_key(self, detector):
        """Test GCP API key detection."""
        text = "GCP_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe"
        matches = detector.detect_in_text(text)

        assert any(m.secret_type == "gcp_api_key" for m in matches)

    def test_detect_azure_storage_key(self, detector):
        """Test Azure storage key detection."""
        text = "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdA=="
        matches = detector.detect_in_text(text)

        assert any(m.secret_type == "azure_storage_key" for m in matches)

    def test_detect_jwt_token(self, detector):
        """Test JWT token detection."""
        text = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        matches = detector.detect_in_text(text)

        assert any(m.secret_type == "jwt_token" for m in matches)

    def test_detect_private_key(self, detector):
        """Test private key detection."""
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV
-----END RSA PRIVATE KEY-----"""
        matches = detector.detect_in_text(text)

        assert any(m.secret_type == "private_key" for m in matches)

    def test_detect_github_token(self, detector):
        """Test GitHub token detection."""
        tokens = [
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",  # PAT
            "gho_1234567890abcdefghijklmnopqrstuvwxyz",  # OAuth
            "ghu_1234567890abcdefghijklmnopqrstuvwxyz",  # User-to-server
            "ghs_1234567890abcdefghijklmnopqrstuvwxyz",  # Server-to-server
            "ghr_1234567890abcdefghijklmnopqrstuvwxyz",  # Refresh
        ]

        for token in tokens:
            matches = detector.detect_in_text(f"TOKEN={token}")
            assert any(
                m.secret_type == "github_token" for m in matches
            ), f"Failed to detect {token[:4]}..."

    def test_detect_slack_token(self, detector):
        """Test Slack token detection."""
        text = "SLACK_TOKEN=xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
        matches = detector.detect_in_text(text)

        assert any(m.secret_type == "slack_token" for m in matches)

    def test_detect_stripe_api_key(self, detector):
        """Test Stripe API key detection."""
        keys = [
            "sk_live_1234567890abcdefghijklmnop",  # Live secret
            "sk_test_1234567890abcdefghijklmnop",  # Test secret
            "pk_live_1234567890abcdefghijklmnop",  # Live public
        ]

        for key in keys:
            matches = detector.detect_in_text(f"STRIPE_KEY={key}")
            assert any(
                m.secret_type == "stripe_api_key" for m in matches
            ), f"Failed to detect {key[:7]}..."

    def test_detect_database_connection(self, detector):
        """Test database connection string detection."""
        connections = [
            "postgres://user:password123@localhost:5432/db",
            "mysql://admin:secret@mysql.example.com:3306/mydb",
            "mongodb+srv://user:pass@cluster.mongodb.net/db",
        ]

        for conn in connections:
            matches = detector.detect_in_text(f"DATABASE_URL={conn}")
            assert len(matches) > 0, f"Failed to detect credentials in {conn[:20]}..."

    def test_detect_sendgrid_api_key(self, detector):
        """Test SendGrid API key detection."""
        # SendGrid keys: SG.<22 chars>.<43 chars>
        text = "SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefg"
        matches = detector.detect_in_text(text)

        assert any(m.secret_type == "sendgrid_api_key" for m in matches)

    def test_no_false_positives_normal_text(self, detector):
        """Test that normal text doesn't trigger false positives."""
        text = "This is a normal sentence without any secrets."
        matches = detector.detect_in_text(text)

        assert len(matches) == 0

    def test_detect_bearer_token(self, detector):
        """Test bearer token detection."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
        matches = detector.detect_in_text(text)

        assert any(m.secret_type in ("bearer_token", "jwt_token") for m in matches)


# ============================================================================
# Entropy Analysis Tests
# ============================================================================


class TestEntropyAnalysis:
    """Tests for entropy-based detection."""

    def test_calculate_entropy_high(self, detector):
        """Test entropy calculation for high-entropy string."""
        # Random-looking string should have high entropy
        high_entropy = "aB3$xY9@kL2!mN5#pQ8&"
        entropy = detector._calculate_entropy(high_entropy)

        assert entropy > 4.0

    def test_calculate_entropy_low(self, detector):
        """Test entropy calculation for low-entropy string."""
        # Repetitive string should have low entropy
        low_entropy = "aaaaaaaaaa"
        entropy = detector._calculate_entropy(low_entropy)

        assert entropy < 1.0

    def test_calculate_entropy_empty(self, detector):
        """Test entropy calculation for empty string."""
        entropy = detector._calculate_entropy("")
        assert entropy == 0.0

    def test_entropy_detection_sensitive_field(self, detector):
        """Test entropy detection on sensitive field names."""
        # Use a high-entropy value that doesn't match other patterns
        data = {
            "api_key": "Xq9$mK2#pL5@nR8&vT1!wY4%bH7*dF0+",
        }

        matches = detector.detect_in_dict(data)

        # Should detect via pattern (generic_api_key) or sensitive field name + high entropy
        assert len(matches) > 0, "Should detect secret in api_key field"


# ============================================================================
# Context Analysis Tests
# ============================================================================


class TestContextAnalysis:
    """Tests for context-based detection."""

    def test_is_sensitive_field_name(self, detector):
        """Test sensitive field name detection."""
        sensitive_fields = [
            "password", "api_key", "secret", "token",
            "private_key", "credentials", "connection_string",
        ]

        for field in sensitive_fields:
            assert detector._is_sensitive_field_name(field) is True

    def test_is_not_sensitive_field_name(self, detector):
        """Test non-sensitive field name detection."""
        normal_fields = [
            "name", "id", "region", "type", "status",
        ]

        for field in normal_fields:
            assert detector._is_sensitive_field_name(field) is False

    def test_case_insensitive_field_name(self, detector):
        """Test case-insensitive field name matching."""
        assert detector._is_sensitive_field_name("PASSWORD") is True
        assert detector._is_sensitive_field_name("Api_Key") is True
        assert detector._is_sensitive_field_name("SECRET_TOKEN") is True


# ============================================================================
# Dictionary Scanning Tests
# ============================================================================


class TestDictScanning:
    """Tests for dictionary scanning."""

    def test_scan_dict_flat(self, detector):
        """Test scanning flat dictionary."""
        data = {
            "access_key": "AKIAIOSFODNN7EXAMPLE",
            "name": "test-resource",
        }

        matches = detector.detect_in_dict(data)

        assert any(m.secret_type == "aws_access_key_id" for m in matches)
        # Default source is "config", so path is "config.access_key"
        assert any("access_key" in m.field_path for m in matches)

    def test_scan_dict_nested(self, detector):
        """Test scanning nested dictionary."""
        data = {
            "config": {
                "credentials": {
                    "api_key": "sk_live_1234567890abcdefghijklmnop",
                }
            }
        }

        matches = detector.detect_in_dict(data)

        assert any("config.credentials.api_key" in m.field_path for m in matches)

    def test_scan_dict_with_list(self, detector):
        """Test scanning dictionary with list values."""
        data = {
            "env_vars": [
                {"name": "API_KEY", "value": "sk_live_1234567890abcdefghijklmnop"},
                {"name": "DEBUG", "value": "true"},
            ]
        }

        matches = detector.detect_in_dict(data)

        assert any("env_vars[0]" in m.field_path for m in matches)


# ============================================================================
# Asset Scanning Tests
# ============================================================================


class TestAssetScanning:
    """Tests for asset scanning."""

    def test_detect_in_asset(self, detector, asset_with_secrets):
        """Test detecting secrets in an asset."""
        result = detector.detect_in_asset(asset_with_secrets)

        assert result.asset_id == asset_with_secrets.id
        assert result.secrets_found > 0
        assert len(result.matches) > 0

    def test_detect_in_asset_no_secrets(self, detector):
        """Test scanning asset without secrets."""
        clean_asset = Asset(
            id="arn:aws:s3:::my-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="my-bucket",
            tags={},
            network_exposure="internal",
            created_at=datetime.now(),
            last_seen=datetime.now(),
            raw_config={"BucketName": "my-bucket", "Versioning": "Enabled"},
        )

        result = detector.detect_in_asset(clean_asset)

        assert result.secrets_found == 0

    def test_detect_secrets_in_tags(self, detector, asset_with_secrets):
        """Test detecting secrets in asset tags."""
        result = detector.detect_in_asset(asset_with_secrets)

        # Should find the secret_key tag with high-entropy value
        assert any("tags.secret_key" in m.field_path for m in result.matches)

    def test_scan_duration_tracked(self, detector, sample_asset):
        """Test that scan duration is tracked."""
        result = detector.detect_in_asset(sample_asset)

        assert result.scan_duration_seconds >= 0


# ============================================================================
# Finding Generation Tests
# ============================================================================


class TestFindingGeneration:
    """Tests for finding generation from secrets."""

    def test_generate_findings(self, detector, asset_with_secrets):
        """Test generating findings from detection results."""
        result = detector.detect_in_asset(asset_with_secrets)
        findings = detector.generate_findings(asset_with_secrets, result)

        assert len(findings) == result.secrets_found

        for finding in findings:
            assert finding.finding_type == FindingType.MISCONFIGURATION
            assert finding.status == FindingStatus.OPEN
            assert finding.asset_id == asset_with_secrets.id
            assert "Exposed Secret" in finding.title
            assert finding.rule_id.startswith("secrets-")

    def test_finding_severity_matches_pattern(self, detector, asset_with_secrets):
        """Test that finding severity matches pattern severity."""
        result = detector.detect_in_asset(asset_with_secrets)
        findings = detector.generate_findings(asset_with_secrets, result)

        # AWS access keys should have CRITICAL severity
        aws_key_findings = [f for f in findings if "aws_access_key" in f.rule_id]
        for finding in aws_key_findings:
            assert finding.severity == Severity.CRITICAL

    def test_finding_has_remediation(self, detector, asset_with_secrets):
        """Test that findings include remediation guidance."""
        result = detector.detect_in_asset(asset_with_secrets)
        findings = detector.generate_findings(asset_with_secrets, result)

        for finding in findings:
            assert finding.remediation_guidance is not None
            assert len(finding.remediation_guidance) > 0
            assert "Rotate" in finding.remediation_guidance or "secrets manager" in finding.remediation_guidance

    def test_finding_redacts_secret(self, detector, asset_with_secrets):
        """Test that secret values are redacted in findings."""
        result = detector.detect_in_asset(asset_with_secrets)
        findings = detector.generate_findings(asset_with_secrets, result)

        for finding in findings:
            # The actual_value should be redacted (contain asterisks)
            if finding.actual_value and len(finding.actual_value) > 8:
                assert "*" in finding.actual_value

    def test_finding_id_is_deterministic(self, detector, asset_with_secrets):
        """Test that finding IDs are deterministic."""
        result1 = detector.detect_in_asset(asset_with_secrets)
        result2 = detector.detect_in_asset(asset_with_secrets)

        findings1 = detector.generate_findings(asset_with_secrets, result1)
        findings2 = detector.generate_findings(asset_with_secrets, result2)

        # Same asset + same secrets = same finding IDs
        ids1 = sorted([f.id for f in findings1])
        ids2 = sorted([f.id for f in findings2])

        assert ids1 == ids2


# ============================================================================
# Factory Function Tests
# ============================================================================


class TestCreateSecretsDetector:
    """Tests for create_secrets_detector factory."""

    def test_create_default(self):
        """Test creating detector with defaults."""
        detector = create_secrets_detector()

        assert detector._min_entropy == 3.5
        assert detector._scan_env_vars is True
        assert detector._scan_tags is True
        assert detector._scan_raw_config is True

    def test_create_custom_entropy(self):
        """Test creating detector with custom entropy threshold."""
        detector = create_secrets_detector(min_entropy=4.5)

        assert detector._min_entropy == 4.5

    def test_create_disable_scanning(self):
        """Test creating detector with disabled scanning options."""
        detector = create_secrets_detector(
            scan_environment_vars=False,
            scan_tags=False,
            scan_raw_config=False,
        )

        assert detector._scan_env_vars is False
        assert detector._scan_tags is False
        assert detector._scan_raw_config is False


# ============================================================================
# Batch Scanning Tests
# ============================================================================


class TestBatchScanning:
    """Tests for scan_assets_for_secrets function."""

    def test_scan_multiple_assets(self, asset_with_secrets, sample_asset):
        """Test scanning multiple assets."""
        assets = [asset_with_secrets, sample_asset]

        results, findings = scan_assets_for_secrets(assets)

        assert len(results) == 2
        assert len(findings) > 0

    def test_scan_empty_list(self):
        """Test scanning empty asset list."""
        results, findings = scan_assets_for_secrets([])

        assert results == []
        assert findings == []

    def test_scan_with_custom_detector(self, sample_asset):
        """Test scanning with custom detector."""
        custom_detector = SecretsDetector(min_entropy=5.0)

        results, findings = scan_assets_for_secrets(
            [sample_asset], detector=custom_detector
        )

        assert len(results) == 1


# ============================================================================
# Constants Tests
# ============================================================================


class TestConstants:
    """Tests for module constants."""

    def test_secret_patterns_has_keys(self):
        """Test SECRET_PATTERNS contains expected keys."""
        expected_patterns = [
            "aws_access_key_id",
            "gcp_api_key",
            "azure_storage_key",
            "jwt_token",
            "private_key",
        ]

        for pattern_name in expected_patterns:
            assert pattern_name in SECRET_PATTERNS

    def test_secret_patterns_have_required_fields(self):
        """Test each pattern has required fields."""
        for name, pattern_info in SECRET_PATTERNS.items():
            assert "pattern" in pattern_info, f"Pattern {name} missing 'pattern'"
            assert "severity" in pattern_info, f"Pattern {name} missing 'severity'"
            assert "description" in pattern_info, f"Pattern {name} missing 'description'"

    def test_sensitive_field_names(self):
        """Test SENSITIVE_FIELD_NAMES contains expected values."""
        expected = ["password", "secret", "api_key", "token", "private_key"]

        for field in expected:
            assert field in SENSITIVE_FIELD_NAMES


# ============================================================================
# Redaction Tests
# ============================================================================


class TestRedaction:
    """Tests for value redaction."""

    def test_redact_short_value(self, detector):
        """Test redacting short values."""
        # Values <= 8 chars should be fully redacted
        result = detector._redact_value("short")
        assert result == "*****"

    def test_redact_long_value(self, detector):
        """Test redacting long values."""
        value = "AKIAIOSFODNN7EXAMPLE"
        result = detector._redact_value(value)

        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" * 12 in result

    def test_redact_preserves_length_hint(self, detector):
        """Test that redacted values preserve some length information."""
        value = "verylongsecretvalue123456789"
        result = detector._redact_value(value)

        # Visible chars + asterisks should equal original length
        assert len(result) == len(value)
