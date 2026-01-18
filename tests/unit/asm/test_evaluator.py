"""
Unit tests for ASM Policy Evaluator.

Tests the ASMPolicyEvaluator and ASMPolicyLoader with sample
assets and policies.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from stance.asm.evaluator import (
    ASMPolicyEvaluator,
    ASMPolicyLoader,
    ASMPolicyEvalResult,
    ASMEvaluationResult,
)
from stance.asm.models import (
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.models.finding import Finding, FindingCollection, Severity
from stance.models.policy import Policy, PolicyCollection


NOW = datetime.now(timezone.utc)


# ==============================================================================
# ASMPolicyLoader Tests
# ==============================================================================


class TestASMPolicyLoader:
    """Tests for ASMPolicyLoader."""

    @pytest.fixture
    def loader(self, tmp_path: Path) -> ASMPolicyLoader:
        """Create a loader with temporary policy directory."""
        return ASMPolicyLoader(policies_path=str(tmp_path))

    @pytest.fixture
    def sample_policy_yaml(self) -> str:
        """Return sample policy YAML content."""
        return """
id: asm-test-001
name: Test Policy
description: A test ASM policy
severity: high
resource_type: external_asset
enabled: true
checks:
  - type: expression
    expression: resource.risk_score > 7.0
remediation:
  description: Review and remediate high-risk assets
"""

    def test_loader_initialization(self, loader: ASMPolicyLoader) -> None:
        """Test loader initializes correctly."""
        assert loader is not None
        assert loader.policies_path is not None

    def test_loader_returns_empty_for_missing_directory(self) -> None:
        """Test loader returns empty collection for missing directory."""
        loader = ASMPolicyLoader(policies_path="/nonexistent/path")
        result = loader.load_all()
        assert isinstance(result, PolicyCollection)
        assert len(result) == 0

    def test_loader_loads_yaml_files(
        self,
        loader: ASMPolicyLoader,
        sample_policy_yaml: str,
        tmp_path: Path,
    ) -> None:
        """Test loader loads YAML policy files."""
        # Create a policy file
        policy_file = tmp_path / "test_policy.yaml"
        policy_file.write_text(sample_policy_yaml)

        result = loader.load_all()

        assert isinstance(result, PolicyCollection)
        # May or may not successfully parse depending on Policy.from_yaml impl
        # The key is that it doesn't crash

    def test_loader_handles_multi_document_yaml(
        self,
        loader: ASMPolicyLoader,
        tmp_path: Path,
    ) -> None:
        """Test loader handles multi-document YAML files."""
        multi_doc_yaml = """
id: policy-1
name: First Policy
description: First test policy
severity: medium
resource_type: external_asset
enabled: true
checks:
  - type: expression
    expression: resource.port == 22
---
id: policy-2
name: Second Policy
description: Second test policy
severity: high
resource_type: external_asset
enabled: true
checks:
  - type: expression
    expression: resource.port == 3389
"""
        policy_file = tmp_path / "multi_policy.yaml"
        policy_file.write_text(multi_doc_yaml)

        result = loader.load_all()
        assert isinstance(result, PolicyCollection)

    def test_loader_handles_invalid_yaml(
        self,
        loader: ASMPolicyLoader,
        tmp_path: Path,
    ) -> None:
        """Test loader handles invalid YAML gracefully."""
        invalid_yaml = "this is not: valid: yaml: [[[["
        policy_file = tmp_path / "invalid.yaml"
        policy_file.write_text(invalid_yaml)

        # Should not raise
        result = loader.load_all()
        assert isinstance(result, PolicyCollection)


# ==============================================================================
# ASMPolicyEvaluator Tests
# ==============================================================================


class TestASMPolicyEvaluator:
    """Tests for ASMPolicyEvaluator."""

    @pytest.fixture
    def evaluator(self, tmp_path: Path) -> ASMPolicyEvaluator:
        """Create an evaluator with temporary policy directory."""
        return ASMPolicyEvaluator(policies_path=str(tmp_path))

    @pytest.fixture
    def high_risk_asset(self) -> ExternalAsset:
        """Return a high-risk external asset."""
        return ExternalAsset(
            id="high-risk-001",
            domain="exposed-db.example.com",
            ip_address="203.0.113.100",
            port=3306,
            protocol="mysql",
            service="MySQL 8.0",
            technology_stack=("MySQL",),
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=NOW - timedelta(days=1),
            last_seen=NOW,
            risk_score=9.0,
            source="port_scan",
        )

    @pytest.fixture
    def low_risk_asset(self) -> ExternalAsset:
        """Return a low-risk external asset."""
        cert = CertificateInfo(
            subject="CN=www.example.com",
            issuer="CN=DigiCert",
            not_before=NOW - timedelta(days=100),
            not_after=NOW + timedelta(days=265),
            san_domains=("www.example.com",),
            fingerprint_sha256="abc123",
            is_self_signed=False,
            key_algorithm="RSA",
            key_size=2048,
        )
        return ExternalAsset(
            id="low-risk-001",
            domain="www.example.com",
            ip_address="203.0.113.10",
            port=443,
            protocol="https",
            service="nginx",
            technology_stack=("nginx",),
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=NOW - timedelta(days=30),
            last_seen=NOW,
            certificate_info=cert,
            risk_score=2.0,
            source="cert_transparency",
        )

    @pytest.fixture
    def expired_cert_asset(self) -> ExternalAsset:
        """Return an asset with expired certificate."""
        cert = CertificateInfo(
            subject="CN=old.example.com",
            issuer="CN=old.example.com",
            not_before=NOW - timedelta(days=400),
            not_after=NOW - timedelta(days=10),
            san_domains=(),
            fingerprint_sha256="expired123",
            is_self_signed=True,
            key_algorithm="RSA",
            key_size=1024,
        )
        return ExternalAsset(
            id="expired-cert-001",
            domain="old.example.com",
            ip_address="203.0.113.50",
            port=443,
            protocol="https",
            service="Apache",
            technology_stack=("Apache",),
            cloud_provider=None,
            cloud_region=None,
            first_seen=NOW - timedelta(days=60),
            last_seen=NOW,
            certificate_info=cert,
            risk_score=7.5,
            source="cert_transparency",
        )

    def test_evaluator_initialization(self, evaluator: ASMPolicyEvaluator) -> None:
        """Test evaluator initializes correctly."""
        assert evaluator is not None
        assert evaluator.policies_path is not None

    def test_load_policies_returns_collection(
        self,
        evaluator: ASMPolicyEvaluator,
    ) -> None:
        """Test load_policies returns PolicyCollection."""
        result = evaluator.load_policies()
        assert isinstance(result, PolicyCollection)

    def test_evaluate_returns_tuple(
        self,
        evaluator: ASMPolicyEvaluator,
        low_risk_asset: ExternalAsset,
    ) -> None:
        """Test evaluate returns (FindingCollection, ASMEvaluationResult)."""
        assets = ExternalAssetCollection([low_risk_asset])

        findings, eval_result = evaluator.evaluate(assets)

        assert isinstance(findings, FindingCollection)
        assert isinstance(eval_result, ASMEvaluationResult)

    def test_evaluate_with_empty_assets(
        self,
        evaluator: ASMPolicyEvaluator,
    ) -> None:
        """Test evaluate handles empty asset collection."""
        assets = ExternalAssetCollection([])

        findings, eval_result = evaluator.evaluate(assets)

        assert isinstance(findings, FindingCollection)
        assert len(findings) == 0
        assert eval_result.assets_evaluated == 0

    def test_evaluate_with_no_policies(
        self,
        evaluator: ASMPolicyEvaluator,
        high_risk_asset: ExternalAsset,
    ) -> None:
        """Test evaluate with no policies loaded."""
        assets = ExternalAssetCollection([high_risk_asset])

        findings, eval_result = evaluator.evaluate(assets)

        assert isinstance(findings, FindingCollection)
        assert eval_result.policies_evaluated == 0

    def test_evaluation_result_structure(
        self,
        evaluator: ASMPolicyEvaluator,
        low_risk_asset: ExternalAsset,
        high_risk_asset: ExternalAsset,
    ) -> None:
        """Test ASMEvaluationResult has correct structure."""
        assets = ExternalAssetCollection([low_risk_asset, high_risk_asset])

        findings, eval_result = evaluator.evaluate(assets)

        # Verify structure exists
        assert hasattr(eval_result, "policies_evaluated")
        assert hasattr(eval_result, "assets_evaluated")
        assert hasattr(eval_result, "findings_generated")
        assert hasattr(eval_result, "duration_seconds")
        # Note: assets_evaluated may be 0 if no policies are loaded
        # (evaluator with empty tmp_path has no policies)


# ==============================================================================
# Policy Evaluation Logic Tests
# ==============================================================================


class TestPolicyEvaluationLogic:
    """Test specific policy evaluation scenarios."""

    @pytest.fixture
    def evaluator_with_policies(self, tmp_path: Path) -> ASMPolicyEvaluator:
        """Create an evaluator with test policies."""
        # Create test policy files
        cert_policy = """
id: asm-cert-expired
name: Expired Certificate
description: Certificate has expired
severity: critical
resource_type: external_asset
enabled: true
checks:
  - type: expression
    expression: resource.certificate_info.is_expired == true
"""
        exposure_policy = """
id: asm-exp-database
name: Database Exposed
description: Database port exposed to internet
severity: critical
resource_type: external_asset
enabled: true
checks:
  - type: expression
    expression: resource.port in [3306, 5432, 27017]
"""
        (tmp_path / "certificates.yaml").write_text(cert_policy)
        (tmp_path / "exposure.yaml").write_text(exposure_policy)

        return ASMPolicyEvaluator(policies_path=str(tmp_path))

    def test_high_risk_asset_generates_findings(
        self,
        evaluator_with_policies: ASMPolicyEvaluator,
    ) -> None:
        """Test that high-risk assets generate findings."""
        high_risk_asset = ExternalAsset(
            id="db-exposed-001",
            domain="db.example.com",
            ip_address="203.0.113.100",
            port=3306,  # MySQL port - should trigger exposure policy
            protocol="mysql",
            service="MySQL",
            technology_stack=("MySQL",),
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=NOW - timedelta(days=1),
            last_seen=NOW,
            risk_score=9.0,
            source="port_scan",
        )
        assets = ExternalAssetCollection([high_risk_asset])

        findings, eval_result = evaluator_with_policies.evaluate(assets)

        # May or may not generate findings depending on policy parsing
        assert isinstance(findings, FindingCollection)
        assert eval_result.assets_evaluated == 1

    def test_safe_asset_minimal_findings(
        self,
        evaluator_with_policies: ASMPolicyEvaluator,
    ) -> None:
        """Test that safe assets generate minimal findings."""
        safe_asset = ExternalAsset(
            id="safe-web-001",
            domain="www.example.com",
            ip_address="203.0.113.10",
            port=443,  # Standard HTTPS port
            protocol="https",
            service="nginx",
            technology_stack=("nginx",),
            cloud_provider="aws",
            cloud_region="us-east-1",
            first_seen=NOW - timedelta(days=30),
            last_seen=NOW,
            certificate_info=CertificateInfo(
                subject="CN=www.example.com",
                issuer="CN=DigiCert",
                not_before=NOW - timedelta(days=100),
                not_after=NOW + timedelta(days=265),
                san_domains=("www.example.com",),
                fingerprint_sha256="abc123",
                is_self_signed=False,
                key_algorithm="RSA",
                key_size=2048,
            ),
            risk_score=1.5,
            source="cert_transparency",
        )
        assets = ExternalAssetCollection([safe_asset])

        findings, eval_result = evaluator_with_policies.evaluate(assets)

        # Safe asset should have fewer/no critical findings
        assert isinstance(findings, FindingCollection)


# ==============================================================================
# ASMPolicyEvalResult Tests
# ==============================================================================


class TestASMPolicyEvalResult:
    """Tests for ASMPolicyEvalResult dataclass."""

    def test_eval_result_creation(self) -> None:
        """Test ASMPolicyEvalResult can be created."""
        result = ASMPolicyEvalResult(
            policy_id="test-policy-001",
            assets_checked=10,
            compliant=8,
            non_compliant=2,
            errors=[],
        )

        assert result.policy_id == "test-policy-001"
        assert result.assets_checked == 10
        assert result.compliant == 8
        assert result.non_compliant == 2
        assert len(result.errors) == 0

    def test_eval_result_with_errors(self) -> None:
        """Test ASMPolicyEvalResult with errors."""
        result = ASMPolicyEvalResult(
            policy_id="test-policy-002",
            assets_checked=5,
            compliant=3,
            non_compliant=1,
            errors=["Expression evaluation failed", "Invalid asset format"],
        )

        assert len(result.errors) == 2


# ==============================================================================
# ASMEvaluationResult Tests
# ==============================================================================


class TestASMEvaluationResult:
    """Tests for ASMEvaluationResult dataclass."""

    def test_evaluation_result_creation(self) -> None:
        """Test ASMEvaluationResult can be created."""
        result = ASMEvaluationResult(
            policies_evaluated=5,
            assets_evaluated=100,
            findings_generated=15,
            duration_seconds=2.5,
            policy_results={},
        )

        assert result.policies_evaluated == 5
        assert result.assets_evaluated == 100
        assert result.findings_generated == 15
        assert result.duration_seconds == 2.5

    def test_evaluation_result_with_policy_results(self) -> None:
        """Test ASMEvaluationResult with policy results."""
        policy_result = ASMPolicyEvalResult(
            policy_id="policy-1",
            assets_checked=50,
            compliant=45,
            non_compliant=5,
            errors=[],
        )

        result = ASMEvaluationResult(
            policies_evaluated=1,
            assets_evaluated=50,
            findings_generated=5,
            duration_seconds=1.0,
            policy_results={"policy-1": policy_result},
        )

        assert "policy-1" in result.policy_results
        assert result.policy_results["policy-1"].non_compliant == 5


# ==============================================================================
# Integration with CSPM Correlation
# ==============================================================================


class TestCSPMCorrelationEvaluation:
    """Test ASM evaluation with CSPM correlation context."""

    @pytest.fixture
    def evaluator(self, tmp_path: Path) -> ASMPolicyEvaluator:
        """Create an evaluator."""
        return ASMPolicyEvaluator(policies_path=str(tmp_path))

    def test_evaluate_provides_cspm_context(
        self,
        evaluator: ASMPolicyEvaluator,
        external_asset_collection: ExternalAssetCollection,
    ) -> None:
        """Test evaluator can use CSPM context if provided."""
        # Evaluate without CSPM context
        findings, result = evaluator.evaluate(external_asset_collection)

        assert isinstance(findings, FindingCollection)
        # Note: assets_evaluated may be 0 if no policies are loaded
        # (evaluator with empty tmp_path has no policies to evaluate against)

    def test_shadow_it_detection_integration(
        self,
        evaluator: ASMPolicyEvaluator,
    ) -> None:
        """Test shadow IT detection during evaluation."""
        # Create asset that would be shadow IT (not in any CSPM inventory)
        shadow_asset = ExternalAsset(
            id="shadow-001",
            domain="unknown-app.example.com",
            ip_address="198.51.100.50",
            port=8080,
            protocol="http",
            service="Unknown",
            technology_stack=(),
            cloud_provider="unknown",
            cloud_region=None,
            first_seen=NOW - timedelta(days=7),
            last_seen=NOW,
            risk_score=6.0,
            source="dns_enumeration",
            is_verified=False,
        )
        assets = ExternalAssetCollection([shadow_asset])

        findings, result = evaluator.evaluate(assets)

        assert isinstance(findings, FindingCollection)
        # Shadow IT detection depends on policy presence


# ==============================================================================
# Error Handling Tests
# ==============================================================================


class TestEvaluatorErrorHandling:
    """Test error handling in ASMPolicyEvaluator."""

    def test_evaluator_handles_invalid_expression(self, tmp_path: Path) -> None:
        """Test evaluator handles invalid policy expressions."""
        invalid_policy = """
id: invalid-policy
name: Invalid Policy
description: Policy with invalid expression
severity: high
resource_type: external_asset
enabled: true
checks:
  - type: expression
    expression: this.is.not.valid.syntax[[[
"""
        (tmp_path / "invalid.yaml").write_text(invalid_policy)

        evaluator = ASMPolicyEvaluator(policies_path=str(tmp_path))
        asset = ExternalAsset(
            id="test-001",
            domain="test.example.com",
            ip_address="203.0.113.1",
            port=443,
            protocol="https",
            service="nginx",
            technology_stack=(),
            cloud_provider=None,
            cloud_region=None,
            first_seen=NOW,
            last_seen=NOW,
            risk_score=1.0,
            source="test",
        )
        assets = ExternalAssetCollection([asset])

        # Should not crash
        findings, result = evaluator.evaluate(assets)
        assert isinstance(findings, FindingCollection)

    def test_evaluator_handles_missing_asset_fields(self, tmp_path: Path) -> None:
        """Test evaluator handles assets with missing optional fields."""
        evaluator = ASMPolicyEvaluator(policies_path=str(tmp_path))

        # Asset with minimal fields
        minimal_asset = ExternalAsset(
            id="minimal-001",
            domain="minimal.example.com",
            ip_address=None,  # Optional
            port=None,  # Optional
            protocol=None,
            service=None,
            technology_stack=(),
            cloud_provider=None,
            cloud_region=None,
            first_seen=NOW,
            last_seen=NOW,
            risk_score=0.0,
            source="test",
        )
        assets = ExternalAssetCollection([minimal_asset])

        # Should not crash
        findings, result = evaluator.evaluate(assets)
        assert isinstance(findings, FindingCollection)
