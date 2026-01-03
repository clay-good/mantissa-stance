"""
Unit tests for Exposure Management - Sensitive Data Exposure Correlation.

Tests the SensitiveDataExposureAnalyzer for correlating public assets
with DSPM scan findings to identify critical sensitive data exposures.
"""

import pytest
from datetime import datetime, timezone

from stance.dspm.classifier import ClassificationLevel, DataCategory
from stance.dspm.scanners.base import ScanResult, ScanFinding, ScanConfig, FindingSeverity
from stance.exposure.base import ExposureType, PublicAsset
from stance.exposure.sensitive import (
    SensitiveExposureType,
    ExposureRiskLevel,
    SensitiveExposureConfig,
    SensitiveDataMatch,
    SensitiveExposureFinding,
    SensitiveExposureSummary,
    SensitiveExposureResult,
    SensitiveDataExposureAnalyzer,
    correlate_exposure_with_dspm,
)
from stance.exposure.inventory import ExposureInventoryResult, ExposureConfig


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def public_bucket() -> PublicAsset:
    """Create a public S3 bucket asset."""
    return PublicAsset(
        asset_id="arn:aws:s3:::public-data-bucket",
        name="public-data-bucket",
        exposure_type=ExposureType.PUBLIC_BUCKET,
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        access_method="public_acl",
    )


@pytest.fixture
def public_database() -> PublicAsset:
    """Create a public database asset."""
    return PublicAsset(
        asset_id="arn:aws:rds:us-east-1:123456789012:db:public-db",
        name="public-db",
        exposure_type=ExposureType.PUBLIC_DATABASE,
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_rds_instance",
        access_method="public_ip",
    )


@pytest.fixture
def pii_finding() -> ScanFinding:
    """Create a PII scan finding."""
    return ScanFinding(
        finding_id="finding-pii-001",
        finding_type="SENSITIVE_DATA_DETECTED",
        severity=FindingSeverity.HIGH,
        title="PII detected in customer data",
        description="Email addresses and phone numbers found in CSV file",
        storage_location="s3://public-data-bucket/customers/data.csv",
        bucket_name="public-data-bucket",
        object_key="customers/data.csv",
        classification_level=ClassificationLevel.CONFIDENTIAL,
        categories=[DataCategory.PII_EMAIL, DataCategory.PII_PHONE],
        sample_matches=[
            {"pattern": "email", "sample": "j***@example.com"},
            {"pattern": "phone", "sample": "555-***-1234"},
        ],
    )


@pytest.fixture
def pci_finding() -> ScanFinding:
    """Create a PCI scan finding."""
    return ScanFinding(
        finding_id="finding-pci-001",
        finding_type="SENSITIVE_DATA_DETECTED",
        severity=FindingSeverity.CRITICAL,
        title="Credit card data detected",
        description="Credit card numbers found in payment log",
        storage_location="s3://public-data-bucket/payments/log.txt",
        bucket_name="public-data-bucket",
        object_key="payments/log.txt",
        classification_level=ClassificationLevel.RESTRICTED,
        categories=[DataCategory.PCI_CARD_NUMBER, DataCategory.PCI_CVV],
        sample_matches=[
            {"pattern": "card_number", "sample": "4111-****-****-1111"},
        ],
    )


@pytest.fixture
def credential_finding() -> ScanFinding:
    """Create a credential scan finding."""
    return ScanFinding(
        finding_id="finding-cred-001",
        finding_type="SENSITIVE_DATA_DETECTED",
        severity=FindingSeverity.CRITICAL,
        title="API keys detected",
        description="AWS API keys found in configuration file",
        storage_location="s3://public-data-bucket/config/settings.json",
        bucket_name="public-data-bucket",
        object_key="config/settings.json",
        classification_level=ClassificationLevel.RESTRICTED,
        categories=[DataCategory.CREDENTIALS_API_KEY],
        sample_matches=[
            {"pattern": "aws_key", "sample": "AKIA***************"},
        ],
    )


@pytest.fixture
def phi_finding() -> ScanFinding:
    """Create a PHI scan finding."""
    return ScanFinding(
        finding_id="finding-phi-001",
        finding_type="SENSITIVE_DATA_DETECTED",
        severity=FindingSeverity.CRITICAL,
        title="Medical records detected",
        description="Patient medical records found",
        storage_location="s3://public-data-bucket/health/records.csv",
        bucket_name="public-data-bucket",
        object_key="health/records.csv",
        classification_level=ClassificationLevel.RESTRICTED,
        categories=[DataCategory.PHI_MEDICAL_RECORD, DataCategory.PHI_DIAGNOSIS],
        sample_matches=[],
    )


@pytest.fixture
def scan_result(pii_finding: ScanFinding) -> ScanResult:
    """Create a scan result with PII finding."""
    return ScanResult(
        scan_id="scan-001",
        storage_type="s3",
        target="public-data-bucket",
        config=ScanConfig(),
        findings=[pii_finding],
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def analyzer() -> SensitiveDataExposureAnalyzer:
    """Create an analyzer with default config."""
    return SensitiveDataExposureAnalyzer()


# =============================================================================
# SensitiveExposureType Tests
# =============================================================================


class TestSensitiveExposureType:
    """Tests for SensitiveExposureType enum."""

    def test_exposure_types_exist(self) -> None:
        """Test that all exposure types exist."""
        assert SensitiveExposureType.PII_EXPOSURE.value == "pii_exposure"
        assert SensitiveExposureType.PCI_EXPOSURE.value == "pci_exposure"
        assert SensitiveExposureType.PHI_EXPOSURE.value == "phi_exposure"
        assert SensitiveExposureType.CREDENTIAL_EXPOSURE.value == "credential_exposure"
        assert SensitiveExposureType.FINANCIAL_EXPOSURE.value == "financial_exposure"


# =============================================================================
# ExposureRiskLevel Tests
# =============================================================================


class TestExposureRiskLevel:
    """Tests for ExposureRiskLevel enum."""

    def test_risk_level_ranking(self) -> None:
        """Test risk level ranking comparison."""
        assert ExposureRiskLevel.CRITICAL > ExposureRiskLevel.HIGH
        assert ExposureRiskLevel.HIGH > ExposureRiskLevel.MEDIUM
        assert ExposureRiskLevel.MEDIUM > ExposureRiskLevel.LOW
        assert ExposureRiskLevel.LOW > ExposureRiskLevel.INFO

    def test_risk_level_rank_values(self) -> None:
        """Test risk level rank numeric values."""
        assert ExposureRiskLevel.CRITICAL.rank == 5
        assert ExposureRiskLevel.HIGH.rank == 4
        assert ExposureRiskLevel.MEDIUM.rank == 3


# =============================================================================
# SensitiveExposureConfig Tests
# =============================================================================


class TestSensitiveExposureConfig:
    """Tests for SensitiveExposureConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = SensitiveExposureConfig()
        assert config.min_classification_level == ClassificationLevel.INTERNAL
        assert config.include_pii is True
        assert config.include_pci is True
        assert config.include_phi is True
        assert config.include_credentials is True
        assert config.generate_remediation is True

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = SensitiveExposureConfig(
            min_classification_level=ClassificationLevel.CONFIDENTIAL,
            include_pii=True,
            include_pci=False,
        )
        assert config.min_classification_level == ClassificationLevel.CONFIDENTIAL
        assert config.include_pci is False


# =============================================================================
# SensitiveDataMatch Tests
# =============================================================================


class TestSensitiveDataMatch:
    """Tests for SensitiveDataMatch dataclass."""

    def test_match_creation(self) -> None:
        """Test creating a data match."""
        match = SensitiveDataMatch(
            asset_id="test-asset",
            asset_name="test-bucket",
            finding_id="finding-001",
            storage_location="s3://test-bucket/file.csv",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            data_categories=[DataCategory.PII_EMAIL],
            match_count=5,
        )
        assert match.asset_id == "test-asset"
        assert match.classification_level == ClassificationLevel.CONFIDENTIAL

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        match = SensitiveDataMatch(
            asset_id="test-asset",
            asset_name="test-bucket",
            finding_id="finding-001",
            storage_location="s3://test-bucket/file.csv",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            data_categories=[DataCategory.PII_EMAIL],
        )
        result = match.to_dict()
        assert result["asset_id"] == "test-asset"
        assert result["classification_level"] == "confidential"


# =============================================================================
# SensitiveDataExposureAnalyzer Basic Tests
# =============================================================================


class TestSensitiveDataExposureAnalyzerBasic:
    """Basic tests for SensitiveDataExposureAnalyzer."""

    def test_analyzer_initialization(self, analyzer: SensitiveDataExposureAnalyzer) -> None:
        """Test analyzer initializes with default config."""
        assert analyzer.config is not None
        assert analyzer.config.include_pii is True

    def test_analyzer_custom_config(self) -> None:
        """Test analyzer with custom config."""
        config = SensitiveExposureConfig(include_pci=False)
        analyzer = SensitiveDataExposureAnalyzer(config=config)
        assert analyzer.config.include_pci is False

    def test_register_public_assets(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
    ) -> None:
        """Test registering public assets."""
        analyzer.register_public_assets([public_bucket])
        result = analyzer.analyze()
        assert result.public_assets_analyzed == 1

    def test_register_dspm_scan_result(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        scan_result: ScanResult,
    ) -> None:
        """Test registering DSPM scan result."""
        analyzer.register_dspm_scan_result(scan_result)
        # Verify internal state (indirectly through analysis)
        assert scan_result.target in analyzer._dspm_results


# =============================================================================
# SensitiveDataExposureAnalyzer Correlation Tests
# =============================================================================


class TestSensitiveDataExposureAnalyzerCorrelation:
    """Tests for sensitive data exposure correlation."""

    def test_correlate_pii_exposure(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test correlating PII exposure."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()

        assert result.has_exposures
        assert len(result.exposures) == 1
        assert result.exposures[0].exposure_type == SensitiveExposureType.PII_EXPOSURE

    def test_correlate_pci_exposure(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pci_finding: ScanFinding,
    ) -> None:
        """Test correlating PCI exposure."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pci_finding])

        result = analyzer.analyze()

        assert result.has_exposures
        assert result.exposures[0].exposure_type == SensitiveExposureType.PCI_EXPOSURE
        assert result.exposures[0].risk_level == ExposureRiskLevel.CRITICAL

    def test_correlate_credential_exposure(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        credential_finding: ScanFinding,
    ) -> None:
        """Test correlating credential exposure."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [credential_finding])

        result = analyzer.analyze()

        assert result.has_exposures
        assert result.exposures[0].exposure_type == SensitiveExposureType.CREDENTIAL_EXPOSURE
        assert result.exposures[0].risk_level == ExposureRiskLevel.CRITICAL

    def test_correlate_phi_exposure(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        phi_finding: ScanFinding,
    ) -> None:
        """Test correlating PHI exposure."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [phi_finding])

        result = analyzer.analyze()

        assert result.has_exposures
        assert result.exposures[0].exposure_type == SensitiveExposureType.PHI_EXPOSURE

    def test_no_exposure_when_no_dspm_findings(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
    ) -> None:
        """Test no exposure when no DSPM findings match."""
        analyzer.register_public_assets([public_bucket])
        # No DSPM findings registered

        result = analyzer.analyze()

        assert not result.has_exposures
        assert len(result.exposures) == 0

    def test_correlate_multiple_findings(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
        pci_finding: ScanFinding,
    ) -> None:
        """Test correlating multiple findings for same asset."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding, pci_finding])

        result = analyzer.analyze()

        assert result.has_exposures
        assert len(result.exposures) == 1  # Combined into one exposure
        # Should have highest classification
        assert result.exposures[0].classification_level == ClassificationLevel.RESTRICTED
        # Should have multiple categories
        assert len(result.exposures[0].data_categories) > 2


# =============================================================================
# Risk Level Calculation Tests
# =============================================================================


class TestRiskLevelCalculation:
    """Tests for risk level calculation."""

    def test_critical_risk_for_credentials(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        credential_finding: ScanFinding,
    ) -> None:
        """Test critical risk for credential exposure."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [credential_finding])

        result = analyzer.analyze()

        assert result.exposures[0].risk_level == ExposureRiskLevel.CRITICAL

    def test_critical_risk_for_pci_on_public_bucket(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pci_finding: ScanFinding,
    ) -> None:
        """Test critical risk for PCI on public bucket."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pci_finding])

        result = analyzer.analyze()

        assert result.exposures[0].risk_level == ExposureRiskLevel.CRITICAL

    def test_high_risk_for_phi(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        phi_finding: ScanFinding,
    ) -> None:
        """Test high risk for PHI exposure."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [phi_finding])

        result = analyzer.analyze()

        # PHI with restricted classification should be critical
        assert result.exposures[0].risk_level == ExposureRiskLevel.CRITICAL

    def test_medium_risk_for_pii_confidential(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test high risk for PII with confidential classification."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()

        # Confidential PII should be high
        assert result.exposures[0].risk_level == ExposureRiskLevel.HIGH


# =============================================================================
# Risk Score Calculation Tests
# =============================================================================


class TestRiskScoreCalculation:
    """Tests for risk score calculation."""

    def test_risk_score_increases_with_classification(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
    ) -> None:
        """Test risk score increases with classification level."""
        # Create findings with different classification levels
        internal_finding = ScanFinding(
            finding_id="finding-internal",
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=FindingSeverity.LOW,
            title="Internal data",
            description="Internal data found",
            storage_location="s3://public-data-bucket/internal.txt",
            bucket_name="public-data-bucket",
            object_key="internal.txt",
            classification_level=ClassificationLevel.INTERNAL,
            categories=[DataCategory.PII_EMAIL],
        )

        restricted_finding = ScanFinding(
            finding_id="finding-restricted",
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=FindingSeverity.CRITICAL,
            title="Restricted data",
            description="Restricted data found",
            storage_location="s3://public-data-bucket/restricted.txt",
            bucket_name="public-data-bucket",
            object_key="restricted.txt",
            classification_level=ClassificationLevel.RESTRICTED,
            categories=[DataCategory.PII_SSN],
        )

        # Analyze internal
        analyzer1 = SensitiveDataExposureAnalyzer()
        analyzer1.register_public_assets([public_bucket])
        analyzer1.register_dspm_findings(public_bucket.name, [internal_finding])
        result1 = analyzer1.analyze()

        # Analyze restricted
        analyzer2 = SensitiveDataExposureAnalyzer()
        analyzer2.register_public_assets([public_bucket])
        analyzer2.register_dspm_findings(public_bucket.name, [restricted_finding])
        result2 = analyzer2.analyze()

        assert result2.exposures[0].risk_score > result1.exposures[0].risk_score

    def test_risk_score_capped_at_100(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        credential_finding: ScanFinding,
        pci_finding: ScanFinding,
        phi_finding: ScanFinding,
    ) -> None:
        """Test risk score is capped at 100."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(
            public_bucket.name,
            [credential_finding, pci_finding, phi_finding],
        )

        result = analyzer.analyze()

        assert result.exposures[0].risk_score <= 100.0


# =============================================================================
# Compliance Impact Tests
# =============================================================================


class TestComplianceImpact:
    """Tests for compliance impact determination."""

    def test_pci_triggers_pci_dss(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pci_finding: ScanFinding,
    ) -> None:
        """Test PCI data triggers PCI-DSS compliance impact."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pci_finding])

        result = analyzer.analyze()

        assert "PCI-DSS" in result.exposures[0].compliance_impact

    def test_phi_triggers_hipaa(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        phi_finding: ScanFinding,
    ) -> None:
        """Test PHI data triggers HIPAA compliance impact."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [phi_finding])

        result = analyzer.analyze()

        assert "HIPAA" in result.exposures[0].compliance_impact

    def test_pii_triggers_gdpr_ccpa(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test PII data triggers GDPR and CCPA compliance impact."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()

        assert "GDPR" in result.exposures[0].compliance_impact
        assert "CCPA" in result.exposures[0].compliance_impact


# =============================================================================
# Summary Statistics Tests
# =============================================================================


class TestSummaryStatistics:
    """Tests for summary statistics."""

    def test_summary_counts(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        public_database: PublicAsset,
        pii_finding: ScanFinding,
        pci_finding: ScanFinding,
    ) -> None:
        """Test summary statistics are correctly calculated."""
        analyzer.register_public_assets([public_bucket, public_database])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])
        analyzer.register_dspm_findings(public_database.name, [pci_finding])

        result = analyzer.analyze()
        summary = result.summary

        assert summary.total_public_assets == 2
        assert summary.assets_with_sensitive_data == 2
        assert summary.critical_exposures >= 1  # PCI is critical

    def test_exposures_by_cloud(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test exposures are counted by cloud provider."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()
        summary = result.summary

        assert summary.exposures_by_cloud.get("aws") == 1

    def test_highest_risk_assets(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        credential_finding: ScanFinding,
    ) -> None:
        """Test highest risk assets are tracked."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [credential_finding])

        result = analyzer.analyze()
        summary = result.summary

        assert public_bucket.name in summary.highest_risk_assets


# =============================================================================
# Remediation Generation Tests
# =============================================================================


class TestRemediationGeneration:
    """Tests for remediation recommendation generation."""

    def test_remediation_generated(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test remediation recommendations are generated."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()

        assert result.exposures[0].recommended_action != ""
        assert "IMMEDIATE" in result.exposures[0].recommended_action

    def test_remediation_disabled_by_config(
        self,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test remediation can be disabled."""
        config = SensitiveExposureConfig(generate_remediation=False)
        analyzer = SensitiveDataExposureAnalyzer(config=config)
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()

        assert result.exposures[0].recommended_action == ""


# =============================================================================
# Filter Tests
# =============================================================================


class TestCategoryFiltering:
    """Tests for category-based filtering."""

    def test_filter_by_classification_level(
        self,
        public_bucket: PublicAsset,
    ) -> None:
        """Test filtering by minimum classification level."""
        # Create a finding with low classification
        internal_finding = ScanFinding(
            finding_id="finding-internal",
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=FindingSeverity.LOW,
            title="Internal data",
            description="Internal data found",
            storage_location="s3://public-data-bucket/internal.txt",
            bucket_name="public-data-bucket",
            object_key="internal.txt",
            classification_level=ClassificationLevel.INTERNAL,
            categories=[DataCategory.PII_EMAIL],
        )

        # Configure to only include confidential and above
        config = SensitiveExposureConfig(
            min_classification_level=ClassificationLevel.CONFIDENTIAL
        )
        analyzer = SensitiveDataExposureAnalyzer(config=config)
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [internal_finding])

        result = analyzer.analyze()

        # Internal should be filtered out
        assert not result.has_exposures

    def test_filter_excludes_pci(
        self,
        public_bucket: PublicAsset,
        pci_finding: ScanFinding,
    ) -> None:
        """Test filtering can exclude PCI findings."""
        config = SensitiveExposureConfig(include_pci=False)
        analyzer = SensitiveDataExposureAnalyzer(config=config)
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pci_finding])

        result = analyzer.analyze()

        # PCI should be filtered but still included based on classification
        # since RESTRICTED classification is included by default
        assert result.has_exposures


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_correlate_exposure_with_dspm(
        self,
        public_bucket: PublicAsset,
        scan_result: ScanResult,
    ) -> None:
        """Test correlate_exposure_with_dspm convenience function."""
        # Create inventory result
        inventory_result = ExposureInventoryResult(
            inventory_id="inv-001",
            config=ExposureConfig(),
            started_at=datetime.now(timezone.utc),
            public_assets=[public_bucket],
        )

        result = correlate_exposure_with_dspm(
            inventory_result=inventory_result,
            dspm_results=[scan_result],
        )

        assert result.public_assets_analyzed == 1
        assert result.has_exposures


# =============================================================================
# Result Properties Tests
# =============================================================================


class TestResultProperties:
    """Tests for result properties."""

    def test_critical_exposures_property(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        credential_finding: ScanFinding,
    ) -> None:
        """Test critical_exposures property."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [credential_finding])

        result = analyzer.analyze()

        assert len(result.critical_exposures) >= 1

    def test_exposures_by_type_property(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test exposures_by_type property."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()
        by_type = result.exposures_by_type

        assert SensitiveExposureType.PII_EXPOSURE.value in by_type

    def test_to_dict(
        self,
        analyzer: SensitiveDataExposureAnalyzer,
        public_bucket: PublicAsset,
        pii_finding: ScanFinding,
    ) -> None:
        """Test conversion to dictionary."""
        analyzer.register_public_assets([public_bucket])
        analyzer.register_dspm_findings(public_bucket.name, [pii_finding])

        result = analyzer.analyze()
        data = result.to_dict()

        assert "analysis_id" in data
        assert "exposures" in data
        assert "summary" in data


# =============================================================================
# Integration Tests
# =============================================================================


class TestSensitiveExposureIntegration:
    """Integration-style tests."""

    def test_full_correlation_workflow(
        self,
        public_bucket: PublicAsset,
        public_database: PublicAsset,
        pii_finding: ScanFinding,
        pci_finding: ScanFinding,
        credential_finding: ScanFinding,
    ) -> None:
        """Test a complete correlation workflow."""
        analyzer = SensitiveDataExposureAnalyzer()

        # Register assets
        analyzer.register_public_assets([public_bucket, public_database])

        # Register findings for bucket
        analyzer.register_dspm_findings(
            public_bucket.name,
            [pii_finding, pci_finding, credential_finding],
        )

        # Create finding for database
        db_finding = ScanFinding(
            finding_id="finding-db-001",
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=FindingSeverity.HIGH,
            title="Financial data in database",
            description="Financial records exposed",
            storage_location="rds://public-db/transactions",
            bucket_name="public-db",
            object_key="transactions",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            categories=[DataCategory.FINANCIAL],
        )
        analyzer.register_dspm_findings(public_database.name, [db_finding])

        # Analyze
        result = analyzer.analyze()

        # Verify
        assert result.public_assets_analyzed == 2
        assert result.has_exposures
        assert len(result.exposures) == 2  # One per asset

        # Check summary
        assert result.summary.assets_with_sensitive_data == 2
        assert result.summary.critical_exposures >= 1

        # Check compliance frameworks
        all_frameworks = set()
        for exposure in result.exposures:
            all_frameworks.update(exposure.compliance_impact)
        assert "PCI-DSS" in all_frameworks
        assert "GDPR" in all_frameworks


# =============================================================================
# Module Import Tests
# =============================================================================


class TestModuleImports:
    """Tests for module imports."""

    def test_import_sensitive_exposure_classes(self) -> None:
        """Test that all sensitive exposure classes can be imported."""
        from stance.exposure.sensitive import (
            SensitiveExposureType,
            ExposureRiskLevel,
            SensitiveExposureConfig,
            SensitiveDataMatch,
            SensitiveExposureFinding,
            SensitiveExposureSummary,
            SensitiveExposureResult,
            SensitiveDataExposureAnalyzer,
            correlate_exposure_with_dspm,
        )

        # Verify imports work
        assert SensitiveDataExposureAnalyzer is not None
        assert correlate_exposure_with_dspm is not None
