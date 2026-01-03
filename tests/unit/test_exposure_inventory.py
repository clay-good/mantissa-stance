"""
Unit tests for Exposure Management - Public Asset Inventory.

Tests the PublicAssetInventory for discovering and analyzing
publicly accessible cloud resources.
"""

import pytest
from datetime import datetime, timezone

from stance.exposure import (
    ExposureType,
    ExposureSeverity,
    ExposureFindingType,
    ExposureConfig,
    PublicAsset,
    ExposureFinding,
    ExposureInventorySummary,
    ExposureInventoryResult,
    BaseExposureAnalyzer,
    DSPMClassification,
    PublicAssetInventory,
    create_inventory_from_assets,
    RESOURCE_TYPE_TO_EXPOSURE,
)
from stance.models.asset import Asset, AssetCollection, NETWORK_EXPOSURE_INTERNET, NETWORK_EXPOSURE_INTERNAL


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def public_s3_bucket() -> Asset:
    """Create a public S3 bucket asset."""
    return Asset(
        id="arn:aws:s3:::public-bucket",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        name="public-bucket",
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        raw_config={
            "acl_allows_public": True,
            "policy_allows_public": False,
            "encryption_enabled": True,
            "versioning_enabled": False,
        },
    )


@pytest.fixture
def private_s3_bucket() -> Asset:
    """Create a private S3 bucket asset."""
    return Asset(
        id="arn:aws:s3:::private-bucket",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        name="private-bucket",
        network_exposure=NETWORK_EXPOSURE_INTERNAL,
        raw_config={
            "acl_allows_public": False,
            "policy_allows_public": False,
        },
    )


@pytest.fixture
def public_ec2_instance() -> Asset:
    """Create a public EC2 instance asset."""
    return Asset(
        id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_ec2_instance",
        name="web-server",
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        raw_config={
            "public_ip_address": "54.123.45.67",
            "public_dns_name": "ec2-54-123-45-67.compute-1.amazonaws.com",
            "dangerous_ingress_rules": [
                {"port": 22, "protocol": "tcp", "source": "0.0.0.0/0"},
            ],
        },
    )


@pytest.fixture
def public_gcs_bucket() -> Asset:
    """Create a public GCS bucket asset."""
    return Asset(
        id="projects/my-project/buckets/public-gcs-bucket",
        cloud_provider="gcp",
        account_id="my-project",
        region="us-central1",
        resource_type="gcp_storage_bucket",
        name="public-gcs-bucket",
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        raw_config={
            "is_public": True,
            "iam_bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
            ],
        },
    )


@pytest.fixture
def public_azure_blob() -> Asset:
    """Create a public Azure blob container asset."""
    return Asset(
        id="/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/storage/blobServices/default/containers/public-container",
        cloud_provider="azure",
        account_id="sub-id",
        region="eastus",
        resource_type="azure_storage_container",
        name="public-container",
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        raw_config={
            "public_access": "container",
            "allow_blob_public_access": True,
        },
    )


@pytest.fixture
def public_rds_database() -> Asset:
    """Create a public RDS database asset."""
    return Asset(
        id="arn:aws:rds:us-east-1:123456789012:db:production-db",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_rds_instance",
        name="production-db",
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        raw_config={
            "publicly_accessible": True,
            "endpoint": "production-db.abc123.us-east-1.rds.amazonaws.com",
        },
    )


@pytest.fixture
def inventory() -> PublicAssetInventory:
    """Create an inventory with default config."""
    return PublicAssetInventory()


# =============================================================================
# ExposureType Tests
# =============================================================================


class TestExposureType:
    """Tests for ExposureType enum."""

    def test_exposure_types_exist(self) -> None:
        """Test that all expected exposure types exist."""
        assert ExposureType.PUBLIC_BUCKET.value == "public_bucket"
        assert ExposureType.PUBLIC_INSTANCE.value == "public_instance"
        assert ExposureType.PUBLIC_DATABASE.value == "public_database"
        assert ExposureType.PUBLIC_FUNCTION.value == "public_function"
        assert ExposureType.PUBLIC_LOAD_BALANCER.value == "public_load_balancer"
        assert ExposureType.PUBLIC_API_GATEWAY.value == "public_api_gateway"


# =============================================================================
# ExposureSeverity Tests
# =============================================================================


class TestExposureSeverity:
    """Tests for ExposureSeverity enum."""

    def test_severity_ranking(self) -> None:
        """Test severity ranking comparison."""
        assert ExposureSeverity.CRITICAL > ExposureSeverity.HIGH
        assert ExposureSeverity.HIGH > ExposureSeverity.MEDIUM
        assert ExposureSeverity.MEDIUM > ExposureSeverity.LOW
        assert ExposureSeverity.LOW > ExposureSeverity.INFO

    def test_severity_rank_values(self) -> None:
        """Test severity rank numeric values."""
        assert ExposureSeverity.CRITICAL.rank == 5
        assert ExposureSeverity.HIGH.rank == 4
        assert ExposureSeverity.MEDIUM.rank == 3
        assert ExposureSeverity.LOW.rank == 2
        assert ExposureSeverity.INFO.rank == 1


# =============================================================================
# ExposureConfig Tests
# =============================================================================


class TestExposureConfig:
    """Tests for ExposureConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = ExposureConfig()
        assert config.include_storage is True
        assert config.include_compute is True
        assert config.include_database is True
        assert config.include_network is True
        assert config.include_kubernetes is True
        assert config.cloud_providers == ["aws", "gcp", "azure"]
        assert config.regions == []

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = ExposureConfig(
            include_storage=True,
            include_compute=False,
            cloud_providers=["aws"],
            regions=["us-east-1"],
        )
        assert config.include_compute is False
        assert config.cloud_providers == ["aws"]
        assert config.regions == ["us-east-1"]


# =============================================================================
# PublicAsset Tests
# =============================================================================


class TestPublicAsset:
    """Tests for PublicAsset dataclass."""

    def test_public_asset_creation(self) -> None:
        """Test creating a public asset."""
        asset = PublicAsset(
            asset_id="test-asset",
            name="test",
            exposure_type=ExposureType.PUBLIC_BUCKET,
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
        )
        assert asset.asset_id == "test-asset"
        assert asset.exposure_type == ExposureType.PUBLIC_BUCKET
        assert asset.has_sensitive_data is False
        assert asset.risk_score == 0.0

    def test_public_asset_with_sensitive_data(self) -> None:
        """Test creating a public asset with sensitive data."""
        asset = PublicAsset(
            asset_id="pii-bucket",
            name="pii-bucket",
            exposure_type=ExposureType.PUBLIC_BUCKET,
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            data_classification="confidential",
            data_categories=["pii_email", "pii_phone"],
            has_sensitive_data=True,
            risk_score=75.0,
        )
        assert asset.has_sensitive_data is True
        assert asset.data_classification == "confidential"
        assert "pii_email" in asset.data_categories

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        asset = PublicAsset(
            asset_id="test-asset",
            name="test",
            exposure_type=ExposureType.PUBLIC_BUCKET,
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            public_ips=["1.2.3.4"],
        )
        result = asset.to_dict()
        assert result["asset_id"] == "test-asset"
        assert result["exposure_type"] == "public_bucket"
        assert result["public_ips"] == ["1.2.3.4"]


# =============================================================================
# PublicAssetInventory Basic Tests
# =============================================================================


class TestPublicAssetInventoryBasic:
    """Basic tests for PublicAssetInventory."""

    def test_inventory_initialization(self, inventory: PublicAssetInventory) -> None:
        """Test inventory initializes with default config."""
        assert inventory.config is not None
        assert inventory.config.include_storage is True

    def test_inventory_with_custom_config(self) -> None:
        """Test inventory with custom config."""
        config = ExposureConfig(include_compute=False)
        inventory = PublicAssetInventory(config=config)
        assert inventory.config.include_compute is False

    def test_inventory_with_assets(self, public_s3_bucket: Asset) -> None:
        """Test inventory initialized with assets."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        assets = list(inventory.discover_public_assets())
        assert len(assets) == 1

    def test_register_assets(
        self,
        inventory: PublicAssetInventory,
        public_s3_bucket: Asset,
    ) -> None:
        """Test registering assets after initialization."""
        inventory.register_assets([public_s3_bucket])
        assets = list(inventory.discover_public_assets())
        assert len(assets) == 1


# =============================================================================
# PublicAssetInventory Discovery Tests
# =============================================================================


class TestPublicAssetInventoryDiscovery:
    """Tests for public asset discovery."""

    def test_discovers_public_s3_bucket(self, public_s3_bucket: Asset) -> None:
        """Test discovering a public S3 bucket."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        assets = list(inventory.discover_public_assets())

        assert len(assets) == 1
        assert assets[0].asset_id == public_s3_bucket.id
        assert assets[0].exposure_type == ExposureType.PUBLIC_BUCKET
        assert assets[0].access_method == "public_acl"

    def test_filters_private_assets(
        self,
        public_s3_bucket: Asset,
        private_s3_bucket: Asset,
    ) -> None:
        """Test that private assets are filtered out."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket, private_s3_bucket])
        assets = list(inventory.discover_public_assets())

        assert len(assets) == 1
        assert assets[0].asset_id == public_s3_bucket.id

    def test_discovers_public_ec2_instance(self, public_ec2_instance: Asset) -> None:
        """Test discovering a public EC2 instance."""
        inventory = PublicAssetInventory(assets=[public_ec2_instance])
        assets = list(inventory.discover_public_assets())

        assert len(assets) == 1
        assert assets[0].exposure_type == ExposureType.PUBLIC_INSTANCE
        assert "54.123.45.67" in assets[0].public_ips

    def test_discovers_public_gcs_bucket(self, public_gcs_bucket: Asset) -> None:
        """Test discovering a public GCS bucket."""
        inventory = PublicAssetInventory(assets=[public_gcs_bucket])
        assets = list(inventory.discover_public_assets())

        assert len(assets) == 1
        assert assets[0].cloud_provider == "gcp"
        assert assets[0].access_method == "public_acl"

    def test_discovers_public_azure_blob(self, public_azure_blob: Asset) -> None:
        """Test discovering a public Azure blob container."""
        inventory = PublicAssetInventory(assets=[public_azure_blob])
        assets = list(inventory.discover_public_assets())

        assert len(assets) == 1
        assert assets[0].cloud_provider == "azure"
        # allow_blob_public_access is checked first
        assert assets[0].access_method == "public_access_enabled"

    def test_filter_by_cloud_provider(
        self,
        public_s3_bucket: Asset,
        public_gcs_bucket: Asset,
    ) -> None:
        """Test filtering by cloud provider."""
        config = ExposureConfig(cloud_providers=["aws"])
        inventory = PublicAssetInventory(
            config=config,
            assets=[public_s3_bucket, public_gcs_bucket],
        )
        assets = list(inventory.discover_public_assets())

        assert len(assets) == 1
        assert assets[0].cloud_provider == "aws"

    def test_filter_by_region(self, public_s3_bucket: Asset) -> None:
        """Test filtering by region."""
        config = ExposureConfig(regions=["us-west-2"])
        inventory = PublicAssetInventory(
            config=config,
            assets=[public_s3_bucket],
        )
        assets = list(inventory.discover_public_assets())

        # us-east-1 should be filtered out
        assert len(assets) == 0

    def test_filter_by_resource_type(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
    ) -> None:
        """Test filtering by resource type."""
        config = ExposureConfig(include_compute=False)
        inventory = PublicAssetInventory(
            config=config,
            assets=[public_s3_bucket, public_ec2_instance],
        )
        assets = list(inventory.discover_public_assets())

        assert len(assets) == 1
        assert assets[0].exposure_type == ExposureType.PUBLIC_BUCKET


# =============================================================================
# DSPM Classification Integration Tests
# =============================================================================


class TestDSPMClassificationIntegration:
    """Tests for DSPM classification integration."""

    def test_register_dspm_classification(
        self,
        inventory: PublicAssetInventory,
        public_s3_bucket: Asset,
    ) -> None:
        """Test registering DSPM classification."""
        inventory.register_assets([public_s3_bucket])
        inventory.register_dspm_classification(
            resource_id=public_s3_bucket.id,
            classification_level="confidential",
            data_categories=["pii_email", "pii_phone"],
        )

        assets = list(inventory.discover_public_assets())
        assert len(assets) == 1
        assert assets[0].data_classification == "confidential"
        assert assets[0].has_sensitive_data is True

    def test_sensitive_data_detection_from_classification(
        self,
        public_s3_bucket: Asset,
    ) -> None:
        """Test that sensitive data is detected from classification level."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        inventory.register_dspm_classification(
            resource_id=public_s3_bucket.id,
            classification_level="restricted",
            data_categories=[],
        )

        assets = list(inventory.discover_public_assets())
        assert assets[0].has_sensitive_data is True

    def test_sensitive_data_detection_from_categories(
        self,
        public_s3_bucket: Asset,
    ) -> None:
        """Test that sensitive data is detected from categories."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        inventory.register_dspm_classification(
            resource_id=public_s3_bucket.id,
            classification_level="internal",
            data_categories=["pii_ssn"],
        )

        assets = list(inventory.discover_public_assets())
        assert assets[0].has_sensitive_data is True


# =============================================================================
# Finding Generation Tests
# =============================================================================


class TestFindingGeneration:
    """Tests for exposure finding generation."""

    def test_sensitive_data_finding(self, public_s3_bucket: Asset) -> None:
        """Test generation of sensitive data finding."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        inventory.register_dspm_classification(
            resource_id=public_s3_bucket.id,
            classification_level="confidential",
            data_categories=["pii_email"],
        )

        result = inventory.run_inventory()

        pii_findings = [
            f for f in result.findings
            if f.finding_type == ExposureFindingType.PUBLIC_PII_EXPOSURE
        ]
        assert len(pii_findings) == 1

    def test_unrestricted_access_finding(self, public_s3_bucket: Asset) -> None:
        """Test generation of unrestricted access finding."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        result = inventory.run_inventory()

        unrestricted_findings = [
            f for f in result.findings
            if f.finding_type == ExposureFindingType.UNRESTRICTED_ACCESS
        ]
        assert len(unrestricted_findings) == 1

    def test_dangerous_ports_finding(self, public_ec2_instance: Asset) -> None:
        """Test generation of dangerous ports finding."""
        inventory = PublicAssetInventory(assets=[public_ec2_instance])
        result = inventory.run_inventory()

        port_findings = [
            f for f in result.findings
            if f.finding_type == ExposureFindingType.DANGEROUS_PORTS_EXPOSED
        ]
        assert len(port_findings) == 1

    def test_unclassified_finding(self, public_s3_bucket: Asset) -> None:
        """Test generation of unclassified data finding."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        result = inventory.run_inventory()

        unclassified_findings = [
            f for f in result.findings
            if f.finding_type == ExposureFindingType.UNCLASSIFIED_PUBLIC
        ]
        assert len(unclassified_findings) == 1


# =============================================================================
# Risk Score Tests
# =============================================================================


class TestRiskScoreCalculation:
    """Tests for risk score calculation."""

    def test_risk_score_increases_with_classification(
        self,
        inventory: PublicAssetInventory,
    ) -> None:
        """Test risk score increases with data classification."""
        # Public classification
        score_public = inventory.calculate_risk_score(
            ExposureType.PUBLIC_BUCKET,
            "public",
            [],
            "policy",
        )

        # Restricted classification
        score_restricted = inventory.calculate_risk_score(
            ExposureType.PUBLIC_BUCKET,
            "restricted",
            [],
            "policy",
        )

        assert score_restricted > score_public

    def test_risk_score_increases_with_sensitive_categories(
        self,
        inventory: PublicAssetInventory,
    ) -> None:
        """Test risk score increases with sensitive data categories."""
        # No categories
        score_no_cat = inventory.calculate_risk_score(
            ExposureType.PUBLIC_BUCKET,
            "internal",
            [],
            "policy",
        )

        # With PII
        score_pii = inventory.calculate_risk_score(
            ExposureType.PUBLIC_BUCKET,
            "internal",
            ["pii_email"],
            "policy",
        )

        assert score_pii > score_no_cat

    def test_risk_score_capped_at_100(
        self,
        inventory: PublicAssetInventory,
    ) -> None:
        """Test risk score is capped at 100."""
        score = inventory.calculate_risk_score(
            ExposureType.PUBLIC_DATABASE,
            "top_secret",
            ["pii_ssn", "pci_card_number", "phi_medical_record"],
            "wildcard_policy",
        )

        assert score <= 100.0


# =============================================================================
# Severity Calculation Tests
# =============================================================================


class TestSeverityCalculation:
    """Tests for severity calculation."""

    def test_critical_severity_for_restricted_pii(
        self,
        inventory: PublicAssetInventory,
    ) -> None:
        """Test critical severity for restricted data with sensitive content."""
        severity = inventory.calculate_severity(
            ExposureType.PUBLIC_BUCKET,
            "restricted",
            True,
        )
        assert severity == ExposureSeverity.CRITICAL

    def test_high_severity_for_public_database(
        self,
        inventory: PublicAssetInventory,
    ) -> None:
        """Test high severity for public database."""
        severity = inventory.calculate_severity(
            ExposureType.PUBLIC_DATABASE,
            None,
            False,
        )
        assert severity == ExposureSeverity.HIGH

    def test_low_severity_for_public_cdn(
        self,
        inventory: PublicAssetInventory,
    ) -> None:
        """Test low severity for public CDN."""
        severity = inventory.calculate_severity(
            ExposureType.PUBLIC_CDN,
            None,
            False,
        )
        assert severity == ExposureSeverity.LOW


# =============================================================================
# Inventory Result Tests
# =============================================================================


class TestInventoryResult:
    """Tests for ExposureInventoryResult."""

    def test_run_inventory(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
    ) -> None:
        """Test running the full inventory."""
        inventory = PublicAssetInventory(
            assets=[public_s3_bucket, public_ec2_instance]
        )
        result = inventory.run_inventory()

        assert result.inventory_id.startswith("exp-")
        assert len(result.public_assets) == 2
        assert result.completed_at is not None

    def test_summary_statistics(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
        public_gcs_bucket: Asset,
    ) -> None:
        """Test summary statistics generation."""
        inventory = PublicAssetInventory(
            assets=[public_s3_bucket, public_ec2_instance, public_gcs_bucket]
        )
        result = inventory.run_inventory()

        summary = result.summary
        assert summary.total_public_assets == 3
        assert summary.assets_by_cloud.get("aws") == 2
        assert summary.assets_by_cloud.get("gcp") == 1
        assert ExposureType.PUBLIC_BUCKET.value in summary.assets_by_type

    def test_findings_by_type_property(self, public_s3_bucket: Asset) -> None:
        """Test findings_by_type property."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        result = inventory.run_inventory()

        by_type = result.findings_by_type
        assert isinstance(by_type, dict)

    def test_findings_by_severity_property(self, public_s3_bucket: Asset) -> None:
        """Test findings_by_severity property."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        result = inventory.run_inventory()

        by_severity = result.findings_by_severity
        assert isinstance(by_severity, dict)

    def test_to_dict(self, public_s3_bucket: Asset) -> None:
        """Test conversion to dictionary."""
        inventory = PublicAssetInventory(assets=[public_s3_bucket])
        result = inventory.run_inventory()

        data = result.to_dict()
        assert "inventory_id" in data
        assert "public_assets" in data
        assert "findings" in data
        assert "summary" in data


# =============================================================================
# Helper Method Tests
# =============================================================================


class TestHelperMethods:
    """Tests for helper methods."""

    def test_get_public_assets_by_type(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
    ) -> None:
        """Test getting public assets by type."""
        inventory = PublicAssetInventory(
            assets=[public_s3_bucket, public_ec2_instance]
        )
        buckets = inventory.get_public_assets_by_type(ExposureType.PUBLIC_BUCKET)

        assert len(buckets) == 1
        assert buckets[0].exposure_type == ExposureType.PUBLIC_BUCKET

    def test_get_public_assets_by_cloud(
        self,
        public_s3_bucket: Asset,
        public_gcs_bucket: Asset,
    ) -> None:
        """Test getting public assets by cloud provider."""
        inventory = PublicAssetInventory(
            assets=[public_s3_bucket, public_gcs_bucket]
        )
        aws_assets = inventory.get_public_assets_by_cloud("aws")

        assert len(aws_assets) == 1
        assert aws_assets[0].cloud_provider == "aws"

    def test_get_sensitive_public_assets(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
    ) -> None:
        """Test getting sensitive public assets."""
        inventory = PublicAssetInventory(
            assets=[public_s3_bucket, public_ec2_instance]
        )
        inventory.register_dspm_classification(
            resource_id=public_s3_bucket.id,
            classification_level="confidential",
            data_categories=["pii_email"],
        )

        sensitive = inventory.get_sensitive_public_assets()
        assert len(sensitive) == 1
        assert sensitive[0].has_sensitive_data is True


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_inventory_from_assets(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
    ) -> None:
        """Test creating inventory from assets using convenience function."""
        result = create_inventory_from_assets(
            assets=[public_s3_bucket, public_ec2_instance]
        )

        assert len(result.public_assets) == 2
        assert result.completed_at is not None

    def test_create_inventory_with_dspm_results(
        self,
        public_s3_bucket: Asset,
    ) -> None:
        """Test creating inventory with DSPM results."""
        dspm_results = {
            public_s3_bucket.id: {
                "classification_level": "confidential",
                "data_categories": ["pii_email"],
            },
        }

        result = create_inventory_from_assets(
            assets=[public_s3_bucket],
            dspm_results=dspm_results,
        )

        assert len(result.public_assets) == 1
        assert result.public_assets[0].has_sensitive_data is True

    def test_create_inventory_with_config(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
    ) -> None:
        """Test creating inventory with custom config."""
        config = ExposureConfig(include_compute=False)

        result = create_inventory_from_assets(
            assets=[public_s3_bucket, public_ec2_instance],
            config=config,
        )

        # Only storage should be included
        assert len(result.public_assets) == 1


# =============================================================================
# Resource Type Mapping Tests
# =============================================================================


class TestResourceTypeMapping:
    """Tests for resource type to exposure type mapping."""

    def test_aws_mappings(self) -> None:
        """Test AWS resource type mappings."""
        assert RESOURCE_TYPE_TO_EXPOSURE["aws_s3_bucket"] == ExposureType.PUBLIC_BUCKET
        assert RESOURCE_TYPE_TO_EXPOSURE["aws_ec2_instance"] == ExposureType.PUBLIC_INSTANCE
        assert RESOURCE_TYPE_TO_EXPOSURE["aws_rds_instance"] == ExposureType.PUBLIC_DATABASE

    def test_gcp_mappings(self) -> None:
        """Test GCP resource type mappings."""
        assert RESOURCE_TYPE_TO_EXPOSURE["gcp_storage_bucket"] == ExposureType.PUBLIC_BUCKET
        assert RESOURCE_TYPE_TO_EXPOSURE["gcp_compute_instance"] == ExposureType.PUBLIC_INSTANCE
        assert RESOURCE_TYPE_TO_EXPOSURE["gcp_sql_instance"] == ExposureType.PUBLIC_DATABASE

    def test_azure_mappings(self) -> None:
        """Test Azure resource type mappings."""
        assert RESOURCE_TYPE_TO_EXPOSURE["azure_storage_container"] == ExposureType.PUBLIC_BUCKET
        assert RESOURCE_TYPE_TO_EXPOSURE["azure_vm"] == ExposureType.PUBLIC_INSTANCE
        assert RESOURCE_TYPE_TO_EXPOSURE["azure_sql_server"] == ExposureType.PUBLIC_DATABASE


# =============================================================================
# Integration Tests
# =============================================================================


class TestExposureIntegration:
    """Integration-style tests for complete workflows."""

    def test_full_exposure_workflow(
        self,
        public_s3_bucket: Asset,
        public_ec2_instance: Asset,
        private_s3_bucket: Asset,
    ) -> None:
        """Test a complete exposure analysis workflow."""
        # Create inventory with mixed assets
        inventory = PublicAssetInventory(
            assets=[public_s3_bucket, public_ec2_instance, private_s3_bucket]
        )

        # Register DSPM classification for the public bucket
        inventory.register_dspm_classification(
            resource_id=public_s3_bucket.id,
            classification_level="confidential",
            data_categories=["pii_email", "pii_phone"],
        )

        # Run inventory
        result = inventory.run_inventory()

        # Verify results
        assert len(result.public_assets) == 2  # private bucket filtered
        assert result.summary.assets_with_sensitive_data == 1
        assert result.has_findings is True

        # Check for PII exposure finding
        pii_findings = [
            f for f in result.findings
            if f.finding_type == ExposureFindingType.PUBLIC_PII_EXPOSURE
        ]
        assert len(pii_findings) == 1

    def test_multi_cloud_exposure_inventory(
        self,
        public_s3_bucket: Asset,
        public_gcs_bucket: Asset,
        public_azure_blob: Asset,
    ) -> None:
        """Test exposure inventory across multiple clouds."""
        result = create_inventory_from_assets(
            assets=[public_s3_bucket, public_gcs_bucket, public_azure_blob]
        )

        # All three should be discovered
        assert len(result.public_assets) == 3

        # Summary should show all three clouds
        assert result.summary.assets_by_cloud.get("aws") == 1
        assert result.summary.assets_by_cloud.get("gcp") == 1
        assert result.summary.assets_by_cloud.get("azure") == 1


# =============================================================================
# Module Import Tests
# =============================================================================


class TestModuleImports:
    """Tests for module imports."""

    def test_import_exposure_classes(self) -> None:
        """Test that all exposure classes can be imported."""
        from stance.exposure import (
            ExposureType,
            ExposureSeverity,
            ExposureFindingType,
            ExposureConfig,
            PublicAsset,
            ExposureFinding,
            ExposureInventorySummary,
            ExposureInventoryResult,
            BaseExposureAnalyzer,
            DSPMClassification,
            PublicAssetInventory,
            create_inventory_from_assets,
        )

        # Just verify imports work
        assert ExposureType is not None
        assert PublicAssetInventory is not None
