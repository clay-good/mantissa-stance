"""
Unit tests for Identity Security - Principal Data Exposure module.

Tests exposure analysis, DSPM correlation, and finding generation.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch


class TestExposureSeverity:
    """Tests for ExposureSeverity enum."""

    def test_severity_levels_exist(self):
        """Test all severity levels are defined."""
        from stance.identity.exposure import ExposureSeverity

        assert ExposureSeverity.CRITICAL is not None
        assert ExposureSeverity.HIGH is not None
        assert ExposureSeverity.MEDIUM is not None
        assert ExposureSeverity.LOW is not None
        assert ExposureSeverity.INFO is not None

    def test_severity_from_classification_admin(self):
        """Test severity calculation for ADMIN access."""
        from stance.identity.exposure import ExposureSeverity
        from stance.identity import PermissionLevel
        from stance.dspm.classifier import ClassificationLevel

        # ADMIN + TOP_SECRET = CRITICAL
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.TOP_SECRET, PermissionLevel.ADMIN
        )
        assert severity == ExposureSeverity.CRITICAL

        # ADMIN + RESTRICTED = CRITICAL
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.RESTRICTED, PermissionLevel.ADMIN
        )
        assert severity == ExposureSeverity.CRITICAL

        # ADMIN + CONFIDENTIAL = HIGH
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.CONFIDENTIAL, PermissionLevel.ADMIN
        )
        assert severity == ExposureSeverity.HIGH

    def test_severity_from_classification_write(self):
        """Test severity calculation for WRITE access."""
        from stance.identity.exposure import ExposureSeverity
        from stance.identity import PermissionLevel
        from stance.dspm.classifier import ClassificationLevel

        # WRITE + RESTRICTED = CRITICAL
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.RESTRICTED, PermissionLevel.WRITE
        )
        assert severity == ExposureSeverity.CRITICAL

        # WRITE + CONFIDENTIAL = HIGH
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.CONFIDENTIAL, PermissionLevel.WRITE
        )
        assert severity == ExposureSeverity.HIGH

    def test_severity_from_classification_read(self):
        """Test severity calculation for READ access."""
        from stance.identity.exposure import ExposureSeverity
        from stance.identity import PermissionLevel
        from stance.dspm.classifier import ClassificationLevel

        # READ + RESTRICTED = HIGH
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.RESTRICTED, PermissionLevel.READ
        )
        assert severity == ExposureSeverity.HIGH

        # READ + CONFIDENTIAL = MEDIUM
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.CONFIDENTIAL, PermissionLevel.READ
        )
        assert severity == ExposureSeverity.MEDIUM

        # READ + INTERNAL = LOW
        severity = ExposureSeverity.from_classification_and_permission(
            ClassificationLevel.INTERNAL, PermissionLevel.READ
        )
        assert severity == ExposureSeverity.LOW


class TestResourceClassification:
    """Tests for ResourceClassification dataclass."""

    def test_classification_creation(self):
        """Test creating a resource classification."""
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        classification = ResourceClassification(
            resource_id="my-bucket",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            categories=[DataCategory.PII_EMAIL, DataCategory.PII_PHONE],
            finding_count=5,
        )

        assert classification.resource_id == "my-bucket"
        assert classification.classification_level == ClassificationLevel.CONFIDENTIAL
        assert len(classification.categories) == 2
        assert classification.finding_count == 5

    def test_classification_to_dict(self):
        """Test classification serialization."""
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        classification = ResourceClassification(
            resource_id="bucket",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.RESTRICTED,
            categories=[DataCategory.PCI_CARD_NUMBER],
        )

        data = classification.to_dict()

        assert data["resource_id"] == "bucket"
        assert data["classification_level"] == "restricted"
        assert "pci_card_number" in data["categories"]


class TestExposedResource:
    """Tests for ExposedResource dataclass."""

    def test_exposed_resource_creation(self):
        """Test creating an exposed resource."""
        from stance.identity.exposure import ExposedResource, ResourceClassification
        from stance.identity import PermissionLevel
        from stance.dspm.classifier import ClassificationLevel

        classification = ResourceClassification(
            resource_id="bucket",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.CONFIDENTIAL,
        )

        resource = ExposedResource(
            resource_id="bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.WRITE,
            permission_source="bucket_policy",
            classification=classification,
            risk_score=65,
        )

        assert resource.resource_id == "bucket"
        assert resource.permission_level == PermissionLevel.WRITE
        assert resource.risk_score == 65
        assert resource.classification is not None

    def test_exposed_resource_to_dict(self):
        """Test exposed resource serialization."""
        from stance.identity.exposure import ExposedResource
        from stance.identity import PermissionLevel

        resource = ExposedResource(
            resource_id="bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.READ,
            permission_source="iam_policy",
            risk_score=30,
        )

        data = resource.to_dict()

        assert data["resource_id"] == "bucket"
        assert data["permission_level"] == "read"
        assert data["classification"] is None


class TestExposureFinding:
    """Tests for ExposureFinding dataclass."""

    def test_finding_creation(self):
        """Test creating an exposure finding."""
        from stance.identity.exposure import ExposureFinding, ExposureSeverity
        from stance.identity import FindingType, PrincipalType, PermissionLevel
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        finding = ExposureFinding(
            finding_id="EXP-12345",
            finding_type=FindingType.SENSITIVE_DATA_ACCESS,
            severity=ExposureSeverity.HIGH,
            title="Access to confidential data",
            description="User has access to PII data",
            principal_id="user-123",
            principal_type=PrincipalType.USER,
            resource_id="pii-bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.WRITE,
            classification_level=ClassificationLevel.CONFIDENTIAL,
            categories=[DataCategory.PII_EMAIL],
        )

        assert finding.finding_id == "EXP-12345"
        assert finding.severity == ExposureSeverity.HIGH
        assert DataCategory.PII_EMAIL in finding.categories

    def test_finding_to_dict(self):
        """Test finding serialization."""
        from stance.identity.exposure import ExposureFinding, ExposureSeverity
        from stance.identity import FindingType, PrincipalType, PermissionLevel
        from stance.dspm.classifier import ClassificationLevel

        finding = ExposureFinding(
            finding_id="F-001",
            finding_type=FindingType.SERVICE_ACCOUNT_RISK,
            severity=ExposureSeverity.CRITICAL,
            title="Service account risk",
            description="Service account has admin access",
            principal_id="sa-123",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            resource_id="bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.ADMIN,
            classification_level=ClassificationLevel.RESTRICTED,
        )

        data = finding.to_dict()

        assert data["finding_id"] == "F-001"
        assert data["severity"] == "critical"
        assert data["finding_type"] == "service_account_risk"


class TestExposureSummary:
    """Tests for ExposureSummary dataclass."""

    def test_summary_creation(self):
        """Test creating an exposure summary."""
        from stance.identity.exposure import ExposureSummary
        from stance.identity import Principal, PrincipalType, PermissionLevel
        from stance.dspm.classifier import ClassificationLevel

        principal = Principal(
            id="user-1",
            name="alice@example.com",
            principal_type=PrincipalType.USER,
            cloud_provider="aws",
        )

        summary = ExposureSummary(
            principal=principal,
            total_resources=10,
            classified_resources=8,
            sensitive_resources=3,
            highest_classification=ClassificationLevel.RESTRICTED,
            highest_permission=PermissionLevel.WRITE,
            risk_score=75,
        )

        assert summary.total_resources == 10
        assert summary.sensitive_resources == 3
        assert summary.risk_score == 75

    def test_summary_to_dict(self):
        """Test summary serialization."""
        from stance.identity.exposure import ExposureSummary
        from stance.identity import Principal, PrincipalType

        principal = Principal(
            id="user-1",
            name="alice",
            principal_type=PrincipalType.USER,
            cloud_provider="aws",
        )

        summary = ExposureSummary(
            principal=principal,
            total_resources=5,
        )

        data = summary.to_dict()

        assert data["total_resources"] == 5
        assert data["principal"]["id"] == "user-1"


class TestExposureResult:
    """Tests for ExposureResult dataclass."""

    def test_result_creation(self):
        """Test creating an exposure result."""
        from stance.identity.exposure import ExposureResult

        result = ExposureResult(
            analysis_id="ABC123",
            principal_id="user-1",
        )

        assert result.analysis_id == "ABC123"
        assert result.principal_id == "user-1"
        assert result.exposed_resources == []
        assert result.findings == []

    def test_result_to_dict(self):
        """Test result serialization."""
        from stance.identity.exposure import ExposureResult

        result = ExposureResult(
            analysis_id="XYZ",
            principal_id="sa-1",
        )

        data = result.to_dict()

        assert data["analysis_id"] == "XYZ"
        assert "started_at" in data


class TestPrincipalExposureAnalyzer:
    """Tests for PrincipalExposureAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create an exposure analyzer."""
        from stance.identity.exposure import PrincipalExposureAnalyzer

        return PrincipalExposureAnalyzer()

    @pytest.fixture
    def sample_principal(self):
        """Create a sample principal."""
        from stance.identity import Principal, PrincipalType

        return Principal(
            id="user-123",
            name="alice@example.com",
            principal_type=PrincipalType.USER,
            cloud_provider="aws",
            account_id="123456789012",
        )

    @pytest.fixture
    def sample_classification(self):
        """Create a sample classification."""
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        return ResourceClassification(
            resource_id="sensitive-bucket",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            categories=[DataCategory.PII_EMAIL, DataCategory.PII_PHONE],
            finding_count=3,
        )

    def test_analyzer_creation(self, analyzer):
        """Test analyzer creation."""
        assert analyzer is not None

    def test_register_classification(self, analyzer, sample_classification):
        """Test registering a classification."""
        analyzer.register_classification(
            sample_classification.resource_id,
            sample_classification,
        )

        retrieved = analyzer.get_classification("sensitive-bucket")
        assert retrieved is not None
        assert retrieved.resource_id == "sensitive-bucket"

    def test_register_multiple_classifications(self, analyzer):
        """Test registering multiple classifications."""
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel

        classifications = [
            ResourceClassification(
                resource_id="bucket-1",
                resource_type="s3_bucket",
                classification_level=ClassificationLevel.INTERNAL,
            ),
            ResourceClassification(
                resource_id="bucket-2",
                resource_type="s3_bucket",
                classification_level=ClassificationLevel.CONFIDENTIAL,
            ),
        ]

        analyzer.register_classifications(classifications)

        assert analyzer.get_classification("bucket-1") is not None
        assert analyzer.get_classification("bucket-2") is not None

    def test_clear_classifications(self, analyzer, sample_classification):
        """Test clearing classifications."""
        analyzer.register_classification(
            sample_classification.resource_id,
            sample_classification,
        )
        analyzer.clear_classifications()

        assert analyzer.get_classification("sensitive-bucket") is None

    def test_analyze_principal_exposure_basic(self, analyzer, sample_principal):
        """Test basic exposure analysis."""
        from stance.identity import ResourceAccess, PermissionLevel

        access_list = [
            ResourceAccess(
                resource_id="bucket-1",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.READ,
                permission_source="bucket_policy",
            ),
        ]

        result = analyzer.analyze_principal_exposure(sample_principal, access_list)

        assert result is not None
        assert result.analysis_id is not None
        assert result.principal_id == "user-123"
        assert len(result.exposed_resources) == 1

    def test_analyze_with_classification(
        self, analyzer, sample_principal, sample_classification
    ):
        """Test exposure analysis with DSPM classification."""
        from stance.identity import ResourceAccess, PermissionLevel

        analyzer.register_classification(
            sample_classification.resource_id,
            sample_classification,
        )

        access_list = [
            ResourceAccess(
                resource_id="sensitive-bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
                permission_source="iam_policy",
            ),
        ]

        result = analyzer.analyze_principal_exposure(sample_principal, access_list)

        assert len(result.exposed_resources) == 1
        assert result.exposed_resources[0].classification is not None
        assert result.exposed_resources[0].risk_score > 0
        assert len(result.findings) >= 1

    def test_analyze_generates_findings_for_sensitive_data(
        self, analyzer, sample_principal
    ):
        """Test that findings are generated for sensitive data access."""
        from stance.identity import ResourceAccess, PermissionLevel
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        # Register a classified resource
        classification = ResourceClassification(
            resource_id="pii-bucket",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.RESTRICTED,
            categories=[DataCategory.PII_SSN],
        )
        analyzer.register_classification("pii-bucket", classification)

        access_list = [
            ResourceAccess(
                resource_id="pii-bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.ADMIN,
                permission_source="bucket_policy",
            ),
        ]

        result = analyzer.analyze_principal_exposure(sample_principal, access_list)

        # Should have findings for sensitive data access
        assert len(result.findings) >= 1
        finding_types = [f.finding_type.value for f in result.findings]
        assert "sensitive_data_access" in finding_types or "broad_access" in finding_types

    def test_analyze_service_account_generates_risk_finding(self, analyzer):
        """Test that service accounts generate risk findings."""
        from stance.identity import Principal, PrincipalType, ResourceAccess, PermissionLevel
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel

        service_account = Principal(
            id="sa-123",
            name="data-processor",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            cloud_provider="aws",
        )

        classification = ResourceClassification(
            resource_id="sensitive-bucket",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.RESTRICTED,
        )
        analyzer.register_classification("sensitive-bucket", classification)

        access_list = [
            ResourceAccess(
                resource_id="sensitive-bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.ADMIN,
                permission_source="iam_policy",
            ),
        ]

        result = analyzer.analyze_principal_exposure(service_account, access_list)

        service_account_findings = [
            f for f in result.findings if f.finding_type.value == "service_account_risk"
        ]
        assert len(service_account_findings) >= 1

    def test_analyze_broad_access_generates_finding(self, analyzer, sample_principal):
        """Test that broad access generates findings."""
        from stance.identity import ResourceAccess, PermissionLevel
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel

        # Register 6 classified resources (threshold is 5)
        for i in range(6):
            classification = ResourceClassification(
                resource_id=f"bucket-{i}",
                resource_type="s3_bucket",
                classification_level=ClassificationLevel.CONFIDENTIAL,
            )
            analyzer.register_classification(f"bucket-{i}", classification)

        access_list = [
            ResourceAccess(
                resource_id=f"bucket-{i}",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.READ,
                permission_source="iam_policy",
            )
            for i in range(6)
        ]

        result = analyzer.analyze_principal_exposure(sample_principal, access_list)

        broad_access_findings = [
            f for f in result.findings if f.finding_type.value == "broad_access"
        ]
        assert len(broad_access_findings) >= 1

    def test_summary_calculation(self, analyzer, sample_principal):
        """Test summary statistics calculation."""
        from stance.identity import ResourceAccess, PermissionLevel
        from stance.identity.exposure import ResourceClassification
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        # Register classifications with different levels
        analyzer.register_classification(
            "public-bucket",
            ResourceClassification(
                resource_id="public-bucket",
                resource_type="s3_bucket",
                classification_level=ClassificationLevel.PUBLIC,
            ),
        )
        analyzer.register_classification(
            "internal-bucket",
            ResourceClassification(
                resource_id="internal-bucket",
                resource_type="s3_bucket",
                classification_level=ClassificationLevel.INTERNAL,
                categories=[DataCategory.PII_EMAIL],
            ),
        )
        analyzer.register_classification(
            "restricted-bucket",
            ResourceClassification(
                resource_id="restricted-bucket",
                resource_type="s3_bucket",
                classification_level=ClassificationLevel.RESTRICTED,
                categories=[DataCategory.PCI_CARD_NUMBER],
            ),
        )

        access_list = [
            ResourceAccess(
                resource_id="public-bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.READ,
                permission_source="bucket_policy",
            ),
            ResourceAccess(
                resource_id="internal-bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
                permission_source="iam_policy",
            ),
            ResourceAccess(
                resource_id="restricted-bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.ADMIN,
                permission_source="bucket_policy",
            ),
        ]

        result = analyzer.analyze_principal_exposure(sample_principal, access_list)

        assert result.summary is not None
        assert result.summary.total_resources == 3
        assert result.summary.classified_resources == 3
        assert result.summary.sensitive_resources == 1  # Only RESTRICTED counts
        assert result.summary.highest_classification == ClassificationLevel.RESTRICTED
        assert result.summary.highest_permission == PermissionLevel.ADMIN
        assert result.summary.risk_score > 0

    def test_risk_score_calculation(self, analyzer):
        """Test risk score calculation."""
        from stance.identity.exposure import ResourceClassification
        from stance.identity import PermissionLevel
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        # High risk: ADMIN + RESTRICTED + high-risk category
        classification_high = ResourceClassification(
            resource_id="high-risk",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.RESTRICTED,
            categories=[DataCategory.PCI_CARD_NUMBER],
        )

        score_high = analyzer._calculate_risk_score(
            PermissionLevel.ADMIN, classification_high
        )
        assert score_high >= 70

        # Low risk: READ + INTERNAL
        classification_low = ResourceClassification(
            resource_id="low-risk",
            resource_type="s3_bucket",
            classification_level=ClassificationLevel.INTERNAL,
        )

        score_low = analyzer._calculate_risk_score(
            PermissionLevel.READ, classification_low
        )
        assert score_low < 20

        # No classification
        score_none = analyzer._calculate_risk_score(PermissionLevel.ADMIN, None)
        assert score_none == 0

    def test_min_classification_filter(self):
        """Test minimum classification level filtering."""
        from stance.identity.exposure import PrincipalExposureAnalyzer, ResourceClassification
        from stance.identity import Principal, PrincipalType, ResourceAccess, PermissionLevel
        from stance.dspm.classifier import ClassificationLevel

        # Only report RESTRICTED and above
        analyzer = PrincipalExposureAnalyzer(
            min_classification=ClassificationLevel.RESTRICTED
        )

        principal = Principal(
            id="user-1",
            name="alice",
            principal_type=PrincipalType.USER,
            cloud_provider="aws",
        )

        # Register a CONFIDENTIAL resource (below threshold)
        analyzer.register_classification(
            "conf-bucket",
            ResourceClassification(
                resource_id="conf-bucket",
                resource_type="s3_bucket",
                classification_level=ClassificationLevel.CONFIDENTIAL,
            ),
        )

        access_list = [
            ResourceAccess(
                resource_id="conf-bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.ADMIN,
                permission_source="bucket_policy",
            ),
        ]

        result = analyzer.analyze_principal_exposure(principal, access_list)

        # Should not generate findings for below-threshold classifications
        sensitive_findings = [
            f for f in result.findings if f.finding_type.value == "sensitive_data_access"
        ]
        assert len(sensitive_findings) == 0


class TestCreateClassificationsFromScanResults:
    """Tests for the helper function to create classifications from DSPM results."""

    def test_create_from_scan_results(self):
        """Test creating classifications from scan results."""
        from stance.identity.exposure import create_classifications_from_scan_results

        scan_results = [
            {
                "bucket_name": "bucket-1",
                "resource_type": "s3_bucket",
                "completed_at": "2024-01-15T10:00:00Z",
                "findings": [
                    {
                        "classification_level": "confidential",
                        "categories": ["pii_email", "pii_phone"],
                    },
                    {
                        "classification_level": "restricted",
                        "categories": ["pci_card_number"],
                    },
                ],
            },
        ]

        classifications = create_classifications_from_scan_results(scan_results)

        assert len(classifications) == 1
        classification = classifications[0]
        assert classification.resource_id == "bucket-1"
        # Highest classification should be RESTRICTED
        assert classification.classification_level.value == "restricted"
        assert classification.finding_count == 2
        assert len(classification.categories) == 3

    def test_create_from_empty_results(self):
        """Test creating classifications from empty results."""
        from stance.identity.exposure import create_classifications_from_scan_results

        classifications = create_classifications_from_scan_results([])
        assert classifications == []

    def test_create_handles_missing_fields(self):
        """Test creating classifications handles missing fields."""
        from stance.identity.exposure import create_classifications_from_scan_results

        scan_results = [
            {
                "bucket_name": "bucket-1",
                "resource_type": "gcs_bucket",
                "findings": [],
            },
        ]

        classifications = create_classifications_from_scan_results(scan_results)

        assert len(classifications) == 1
        assert classifications[0].classification_level.value == "public"
        assert classifications[0].finding_count == 0


class TestExposureIntegration:
    """Integration tests for exposure analysis."""

    def test_full_exposure_workflow(self):
        """Test complete exposure analysis workflow."""
        from stance.identity.exposure import (
            PrincipalExposureAnalyzer,
            ResourceClassification,
            create_classifications_from_scan_results,
        )
        from stance.identity import Principal, PrincipalType, ResourceAccess, PermissionLevel
        from stance.dspm.classifier import ClassificationLevel, DataCategory

        # 1. Create analyzer
        analyzer = PrincipalExposureAnalyzer()

        # 2. Simulate DSPM scan results
        scan_results = [
            {
                "bucket_name": "customer-data",
                "resource_type": "s3_bucket",
                "findings": [
                    {
                        "classification_level": "restricted",
                        "categories": ["pii_ssn", "pii_name", "pii_address"],
                    },
                ],
            },
            {
                "bucket_name": "logs",
                "resource_type": "s3_bucket",
                "findings": [
                    {
                        "classification_level": "internal",
                        "categories": [],
                    },
                ],
            },
        ]

        # 3. Register classifications
        classifications = create_classifications_from_scan_results(scan_results)
        analyzer.register_classifications(classifications)

        # 4. Create principal (service account)
        service_account = Principal(
            id="arn:aws:iam::123456789012:role/DataProcessor",
            name="DataProcessor",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            cloud_provider="aws",
            account_id="123456789012",
        )

        # 5. Define access
        access_list = [
            ResourceAccess(
                resource_id="customer-data",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.ADMIN,
                permission_source="iam_policy",
                policy_ids=["DataProcessorPolicy"],
            ),
            ResourceAccess(
                resource_id="logs",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
                permission_source="iam_policy",
            ),
        ]

        # 6. Run analysis
        result = analyzer.analyze_principal_exposure(service_account, access_list)

        # 7. Verify results
        assert result is not None
        assert result.principal_id == service_account.id
        assert len(result.exposed_resources) == 2
        assert result.summary is not None
        assert result.summary.sensitive_resources >= 1
        assert len(result.findings) >= 1

        # Check for service account risk finding
        service_account_findings = [
            f for f in result.findings
            if f.finding_type.value == "service_account_risk"
        ]
        assert len(service_account_findings) >= 1

        # Serialize and verify
        result_dict = result.to_dict()
        assert "analysis_id" in result_dict
        assert "summary" in result_dict
        assert "findings" in result_dict


class TestModuleImports:
    """Tests for module imports."""

    def test_import_exposure_classes(self):
        """Test importing exposure classes."""
        from stance.identity.exposure import (
            ExposureSeverity,
            ResourceClassification,
            ExposedResource,
            ExposureFinding,
            ExposureSummary,
            ExposureResult,
            PrincipalExposureAnalyzer,
            create_classifications_from_scan_results,
        )

        assert ExposureSeverity is not None
        assert ResourceClassification is not None
        assert PrincipalExposureAnalyzer is not None
