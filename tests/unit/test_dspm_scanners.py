"""
Tests for DSPM storage scanners.

Tests cover:
- Base scanner classes and models
- S3DataScanner
- GCSDataScanner
- AzureBlobDataScanner
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

from stance.dspm.scanners.base import (
    BaseDataScanner,
    ScanConfig,
    ScanResult,
    ScanFinding,
    ScanSummary,
    FindingSeverity,
)
from stance.dspm.classifier import ClassificationLevel, DataCategory


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def scan_config():
    """Create a default scan configuration."""
    return ScanConfig(
        sample_size=10,
        max_object_size_bytes=1024 * 1024,  # 1MB
        content_sample_bytes=1024,  # 1KB
    )


@pytest.fixture
def sample_finding():
    """Create a sample finding for testing."""
    return ScanFinding(
        finding_id="test-finding-001",
        finding_type="SENSITIVE_DATA_DETECTED",
        severity=FindingSeverity.HIGH,
        title="Sensitive data detected: pii_ssn",
        description="Detected SSN patterns in object",
        storage_location="s3://test-bucket/data.csv",
        bucket_name="test-bucket",
        object_key="data.csv",
        classification_level=ClassificationLevel.RESTRICTED,
        categories=[DataCategory.PII_SSN],
        sample_matches=[
            {
                "pattern": "ssn-formatted",
                "category": "pii_ssn",
                "redacted_value": "123-**-6789",
                "confidence": 0.95,
            }
        ],
        remediation="Enable encryption for the bucket",
    )


@pytest.fixture
def sample_summary():
    """Create a sample scan summary."""
    return ScanSummary(
        total_objects_scanned=100,
        total_objects_skipped=10,
        total_bytes_scanned=1024 * 1024,
        total_findings=5,
        findings_by_severity={"high": 2, "medium": 3},
        findings_by_category={"pii_ssn": 3, "pii_email": 2},
        scan_duration_seconds=10.5,
    )


# =============================================================================
# Test FindingSeverity
# =============================================================================

class TestFindingSeverity:
    """Tests for FindingSeverity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"

    def test_from_classification_top_secret(self):
        """Test mapping TOP_SECRET to CRITICAL."""
        severity = FindingSeverity.from_classification(ClassificationLevel.TOP_SECRET)
        assert severity == FindingSeverity.CRITICAL

    def test_from_classification_restricted(self):
        """Test mapping RESTRICTED to HIGH."""
        severity = FindingSeverity.from_classification(ClassificationLevel.RESTRICTED)
        assert severity == FindingSeverity.HIGH

    def test_from_classification_confidential(self):
        """Test mapping CONFIDENTIAL to MEDIUM."""
        severity = FindingSeverity.from_classification(ClassificationLevel.CONFIDENTIAL)
        assert severity == FindingSeverity.MEDIUM

    def test_from_classification_internal(self):
        """Test mapping INTERNAL to LOW."""
        severity = FindingSeverity.from_classification(ClassificationLevel.INTERNAL)
        assert severity == FindingSeverity.LOW

    def test_from_classification_public(self):
        """Test mapping PUBLIC to INFO."""
        severity = FindingSeverity.from_classification(ClassificationLevel.PUBLIC)
        assert severity == FindingSeverity.INFO


# =============================================================================
# Test ScanConfig
# =============================================================================

class TestScanConfig:
    """Tests for ScanConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScanConfig()
        assert config.sample_size == 100
        assert config.max_object_size_bytes == 10 * 1024 * 1024
        assert config.file_extensions is None
        assert config.exclude_patterns == []
        assert config.include_metadata is True
        assert config.timeout_seconds == 300
        assert config.content_sample_bytes == 64 * 1024

    def test_custom_values(self):
        """Test custom configuration values."""
        config = ScanConfig(
            sample_size=50,
            max_object_size_bytes=5 * 1024 * 1024,
            file_extensions=[".csv", ".json"],
            exclude_patterns=["*.log", "temp/*"],
        )
        assert config.sample_size == 50
        assert config.max_object_size_bytes == 5 * 1024 * 1024
        assert config.file_extensions == ["csv", "json"]
        assert config.exclude_patterns == ["*.log", "temp/*"]

    def test_file_extension_normalization(self):
        """Test that file extensions are normalized."""
        config = ScanConfig(file_extensions=[".CSV", "JSON", ".txt"])
        assert config.file_extensions == ["csv", "json", "txt"]

    def test_unlimited_sample_size(self):
        """Test unlimited sample size."""
        config = ScanConfig(sample_size=None)
        assert config.sample_size is None


# =============================================================================
# Test ScanFinding
# =============================================================================

class TestScanFinding:
    """Tests for ScanFinding dataclass."""

    def test_finding_creation(self, sample_finding):
        """Test creating a scan finding."""
        assert sample_finding.finding_id == "test-finding-001"
        assert sample_finding.finding_type == "SENSITIVE_DATA_DETECTED"
        assert sample_finding.severity == FindingSeverity.HIGH
        assert sample_finding.bucket_name == "test-bucket"
        assert sample_finding.object_key == "data.csv"
        assert sample_finding.classification_level == ClassificationLevel.RESTRICTED

    def test_finding_categories(self, sample_finding):
        """Test finding categories."""
        assert len(sample_finding.categories) == 1
        assert DataCategory.PII_SSN in sample_finding.categories

    def test_finding_sample_matches(self, sample_finding):
        """Test finding sample matches."""
        assert len(sample_finding.sample_matches) == 1
        assert sample_finding.sample_matches[0]["pattern"] == "ssn-formatted"

    def test_finding_to_dict(self, sample_finding):
        """Test converting finding to dictionary."""
        result = sample_finding.to_dict()

        assert result["finding_id"] == "test-finding-001"
        assert result["severity"] == "high"
        assert result["classification_level"] == "restricted"
        assert result["categories"] == ["pii_ssn"]
        assert "detected_at" in result

    def test_finding_detected_at_default(self):
        """Test that detected_at has a default value."""
        finding = ScanFinding(
            finding_id="test",
            finding_type="TEST",
            severity=FindingSeverity.LOW,
            title="Test",
            description="Test",
            storage_location="s3://test/test",
            bucket_name="test",
            object_key="test",
            classification_level=ClassificationLevel.PUBLIC,
        )
        assert finding.detected_at is not None
        assert isinstance(finding.detected_at, datetime)


# =============================================================================
# Test ScanSummary
# =============================================================================

class TestScanSummary:
    """Tests for ScanSummary dataclass."""

    def test_summary_creation(self, sample_summary):
        """Test creating a scan summary."""
        assert sample_summary.total_objects_scanned == 100
        assert sample_summary.total_objects_skipped == 10
        assert sample_summary.total_bytes_scanned == 1024 * 1024
        assert sample_summary.total_findings == 5

    def test_summary_findings_by_severity(self, sample_summary):
        """Test findings grouped by severity."""
        assert sample_summary.findings_by_severity["high"] == 2
        assert sample_summary.findings_by_severity["medium"] == 3

    def test_summary_findings_by_category(self, sample_summary):
        """Test findings grouped by category."""
        assert sample_summary.findings_by_category["pii_ssn"] == 3
        assert sample_summary.findings_by_category["pii_email"] == 2

    def test_summary_to_dict(self, sample_summary):
        """Test converting summary to dictionary."""
        result = sample_summary.to_dict()

        assert result["total_objects_scanned"] == 100
        assert result["total_findings"] == 5
        assert result["scan_duration_seconds"] == 10.5

    def test_empty_summary(self):
        """Test empty summary defaults."""
        summary = ScanSummary()

        assert summary.total_objects_scanned == 0
        assert summary.total_findings == 0
        assert summary.errors == []


# =============================================================================
# Test ScanResult
# =============================================================================

class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_result_creation(self, scan_config):
        """Test creating a scan result."""
        result = ScanResult(
            scan_id="scan-001",
            storage_type="s3",
            target="my-bucket",
            config=scan_config,
        )

        assert result.scan_id == "scan-001"
        assert result.storage_type == "s3"
        assert result.target == "my-bucket"
        assert result.findings == []
        assert result.completed_at is None

    def test_result_has_findings_false(self, scan_config):
        """Test has_findings when no findings."""
        result = ScanResult(
            scan_id="scan-001",
            storage_type="s3",
            target="my-bucket",
            config=scan_config,
        )

        assert result.has_findings is False

    def test_result_has_findings_true(self, scan_config, sample_finding):
        """Test has_findings when findings exist."""
        result = ScanResult(
            scan_id="scan-001",
            storage_type="s3",
            target="my-bucket",
            config=scan_config,
            findings=[sample_finding],
        )

        assert result.has_findings is True

    def test_result_highest_severity_none(self, scan_config):
        """Test highest_severity when no findings."""
        result = ScanResult(
            scan_id="scan-001",
            storage_type="s3",
            target="my-bucket",
            config=scan_config,
        )

        assert result.highest_severity is None

    def test_result_highest_severity(self, scan_config, sample_finding):
        """Test highest_severity with findings."""
        result = ScanResult(
            scan_id="scan-001",
            storage_type="s3",
            target="my-bucket",
            config=scan_config,
            findings=[sample_finding],
        )

        assert result.highest_severity == FindingSeverity.HIGH

    def test_result_to_dict(self, scan_config, sample_finding, sample_summary):
        """Test converting result to dictionary."""
        result = ScanResult(
            scan_id="scan-001",
            storage_type="s3",
            target="my-bucket",
            config=scan_config,
            findings=[sample_finding],
            summary=sample_summary,
            completed_at=datetime.now(timezone.utc),
        )

        result_dict = result.to_dict()

        assert result_dict["scan_id"] == "scan-001"
        assert result_dict["storage_type"] == "s3"
        assert len(result_dict["findings"]) == 1
        assert result_dict["completed_at"] is not None


# =============================================================================
# Test BaseDataScanner
# =============================================================================

class TestBaseDataScanner:
    """Tests for BaseDataScanner abstract class."""

    def test_should_scan_object_valid(self, scan_config):
        """Test _should_scan_object with valid object."""
        # Create a concrete implementation for testing
        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(scan_config)
        should_scan, reason = scanner._should_scan_object("data.csv", 1024)

        assert should_scan is True
        assert reason == ""

    def test_should_scan_object_too_large(self, scan_config):
        """Test _should_scan_object with object exceeding size limit."""
        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(scan_config)
        should_scan, reason = scanner._should_scan_object(
            "large.csv", 100 * 1024 * 1024
        )

        assert should_scan is False
        assert "exceeds limit" in reason

    def test_should_scan_object_wrong_extension(self):
        """Test _should_scan_object with disallowed extension."""
        config = ScanConfig(file_extensions=[".csv", ".json"])

        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(config)
        should_scan, reason = scanner._should_scan_object("image.png", 1024)

        assert should_scan is False
        assert "not in allowed list" in reason

    def test_should_scan_object_excluded_pattern(self):
        """Test _should_scan_object with excluded pattern."""
        config = ScanConfig(exclude_patterns=["*.log", "temp/*"])

        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(config)

        should_scan, reason = scanner._should_scan_object("app.log", 1024)
        assert should_scan is False
        assert "exclude pattern" in reason

        should_scan, reason = scanner._should_scan_object("temp/data.csv", 1024)
        assert should_scan is False

    def test_generate_finding_id(self, scan_config):
        """Test finding ID generation."""
        class TestScanner(BaseDataScanner):
            storage_type = "test"
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(scan_config)

        id1 = scanner._generate_finding_id("bucket1", "key1")
        id2 = scanner._generate_finding_id("bucket1", "key1")
        id3 = scanner._generate_finding_id("bucket1", "key2")

        # Same inputs should produce same ID
        assert id1 == id2
        # Different inputs should produce different IDs
        assert id1 != id3
        # ID should be 16 characters
        assert len(id1) == 16

    def test_decode_content_utf8(self, scan_config):
        """Test decoding UTF-8 content."""
        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(scan_config)

        content = b"Hello, World!"
        result = scanner._decode_content(content)

        assert result == "Hello, World!"

    def test_decode_content_binary(self, scan_config):
        """Test decoding binary content returns None."""
        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(scan_config)

        # Invalid UTF-8 sequence
        content = bytes([0x80, 0x81, 0x82, 0x83])
        result = scanner._decode_content(content)

        # Should still decode with latin-1 fallback
        assert result is not None


# =============================================================================
# Test S3DataScanner
# =============================================================================

class TestS3DataScanner:
    """Tests for S3DataScanner."""

    @pytest.fixture
    def mock_boto3(self):
        """Mock boto3 for testing."""
        with patch("stance.dspm.scanners.s3.BOTO3_AVAILABLE", True):
            with patch("stance.dspm.scanners.s3.boto3") as mock:
                yield mock

    def test_s3_scanner_creation(self, mock_boto3, scan_config):
        """Test creating S3 scanner."""
        from stance.dspm.scanners.s3 import S3DataScanner

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        scanner = S3DataScanner(config=scan_config)

        assert scanner.storage_type == "s3"
        assert scanner.config == scan_config

    def test_s3_scanner_storage_type(self, mock_boto3):
        """Test S3 scanner storage type."""
        from stance.dspm.scanners.s3 import S3DataScanner

        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        scanner = S3DataScanner()
        assert scanner.storage_type == "s3"

    def test_s3_list_objects(self, mock_boto3):
        """Test listing S3 objects."""
        from stance.dspm.scanners.s3 import S3DataScanner

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        # Mock paginator
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "file1.csv", "Size": 1024},
                    {"Key": "file2.json", "Size": 2048},
                ]
            }
        ]

        scanner = S3DataScanner()
        objects = list(scanner.list_objects("test-bucket"))

        assert len(objects) == 2
        assert objects[0]["Key"] == "file1.csv"
        assert objects[1]["Size"] == 2048

    def test_s3_get_bucket_metadata(self, mock_boto3):
        """Test getting S3 bucket metadata."""
        from stance.dspm.scanners.s3 import S3DataScanner

        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_boto3.Session.return_value = mock_session

        # Mock encryption response
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }

        # Mock public access block
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }

        # Mock versioning
        mock_client.get_bucket_versioning.return_value = {"Status": "Enabled"}

        # Mock logging
        mock_client.get_bucket_logging.return_value = {"LoggingEnabled": {}}

        scanner = S3DataScanner()
        metadata = scanner.get_bucket_metadata("test-bucket")

        assert metadata["encrypted"] is True
        assert metadata["encryption_type"] == "AES256"
        assert metadata["public_access"] is False
        assert metadata["versioning"] is True
        assert metadata["logging"] is True


# =============================================================================
# Test GCSDataScanner
# =============================================================================

class TestGCSDataScanner:
    """Tests for GCSDataScanner."""

    @pytest.fixture
    def mock_gcs(self):
        """Mock google-cloud-storage for testing."""
        with patch("stance.dspm.scanners.gcs.GCS_AVAILABLE", True):
            with patch("stance.dspm.scanners.gcs.storage") as mock:
                yield mock

    def test_gcs_scanner_creation(self, mock_gcs, scan_config):
        """Test creating GCS scanner."""
        from stance.dspm.scanners.gcs import GCSDataScanner

        mock_client = MagicMock()
        mock_gcs.Client.return_value = mock_client

        scanner = GCSDataScanner(config=scan_config, project="test-project")

        assert scanner.storage_type == "gcs"
        assert scanner.config == scan_config

    def test_gcs_scanner_storage_type(self, mock_gcs):
        """Test GCS scanner storage type."""
        from stance.dspm.scanners.gcs import GCSDataScanner

        mock_client = MagicMock()
        mock_gcs.Client.return_value = mock_client

        scanner = GCSDataScanner()
        assert scanner.storage_type == "gcs"

    def test_gcs_list_objects(self, mock_gcs):
        """Test listing GCS objects."""
        from stance.dspm.scanners.gcs import GCSDataScanner

        mock_client = MagicMock()
        mock_bucket = MagicMock()
        mock_gcs.Client.return_value = mock_client
        mock_client.bucket.return_value = mock_bucket

        # Mock blobs
        mock_blob1 = MagicMock()
        mock_blob1.name = "file1.csv"
        mock_blob1.size = 1024
        mock_blob1.updated = None
        mock_blob1.content_type = "text/csv"
        mock_blob1.storage_class = "STANDARD"
        mock_blob1.md5_hash = "abc123"

        mock_blob2 = MagicMock()
        mock_blob2.name = "file2.json"
        mock_blob2.size = 2048
        mock_blob2.updated = None
        mock_blob2.content_type = "application/json"
        mock_blob2.storage_class = "STANDARD"
        mock_blob2.md5_hash = "def456"

        mock_bucket.list_blobs.return_value = [mock_blob1, mock_blob2]

        scanner = GCSDataScanner()
        objects = list(scanner.list_objects("test-bucket"))

        assert len(objects) == 2
        assert objects[0]["name"] == "file1.csv"
        assert objects[1]["size"] == 2048

    def test_gcs_get_bucket_metadata(self, mock_gcs):
        """Test getting GCS bucket metadata."""
        from stance.dspm.scanners.gcs import GCSDataScanner

        mock_client = MagicMock()
        mock_bucket = MagicMock()
        mock_gcs.Client.return_value = mock_client
        mock_client.get_bucket.return_value = mock_bucket

        # Configure mock bucket
        mock_bucket.location = "US"
        mock_bucket.default_kms_key_name = None
        mock_bucket.versioning_enabled = True

        mock_iam_config = MagicMock()
        mock_iam_config.uniform_bucket_level_access_enabled = True
        mock_iam_config.public_access_prevention = "enforced"
        mock_bucket.iam_configuration = mock_iam_config

        scanner = GCSDataScanner()
        metadata = scanner.get_bucket_metadata("test-bucket")

        assert metadata["encrypted"] is True
        assert metadata["location"] == "US"
        assert metadata["uniform_bucket_level_access"] is True
        assert metadata["versioning"] is True


# =============================================================================
# Test AzureBlobDataScanner
# =============================================================================

class TestAzureBlobDataScanner:
    """Tests for AzureBlobDataScanner."""

    @pytest.fixture
    def mock_azure(self):
        """Mock azure-storage-blob for testing."""
        with patch("stance.dspm.scanners.azure_blob.AZURE_AVAILABLE", True):
            with patch("stance.dspm.scanners.azure_blob.BlobServiceClient") as mock:
                yield mock

    def test_azure_scanner_creation(self, mock_azure, scan_config):
        """Test creating Azure Blob scanner."""
        from stance.dspm.scanners.azure_blob import AzureBlobDataScanner

        mock_service = MagicMock()
        mock_azure.from_connection_string.return_value = mock_service

        scanner = AzureBlobDataScanner(
            config=scan_config,
            connection_string="DefaultEndpointsProtocol=https;..."
        )

        assert scanner.storage_type == "azure_blob"
        assert scanner.config == scan_config

    def test_azure_scanner_storage_type(self, mock_azure):
        """Test Azure Blob scanner storage type."""
        from stance.dspm.scanners.azure_blob import AzureBlobDataScanner

        mock_service = MagicMock()
        mock_azure.from_connection_string.return_value = mock_service

        scanner = AzureBlobDataScanner(
            connection_string="DefaultEndpointsProtocol=https;..."
        )
        assert scanner.storage_type == "azure_blob"

    def test_azure_scanner_requires_connection_info(self, mock_azure):
        """Test that Azure scanner requires connection info."""
        from stance.dspm.scanners.azure_blob import AzureBlobDataScanner

        with pytest.raises(ValueError) as exc_info:
            AzureBlobDataScanner()

        assert "connection_string or account_url" in str(exc_info.value)

    def test_azure_list_objects(self, mock_azure):
        """Test listing Azure blobs."""
        from stance.dspm.scanners.azure_blob import AzureBlobDataScanner

        mock_service = MagicMock()
        mock_container = MagicMock()
        mock_azure.from_connection_string.return_value = mock_service
        mock_service.get_container_client.return_value = mock_container

        # Mock blobs
        mock_blob1 = MagicMock()
        mock_blob1.name = "file1.csv"
        mock_blob1.size = 1024
        mock_blob1.last_modified = None
        mock_blob1.content_settings = MagicMock()
        mock_blob1.content_settings.content_type = "text/csv"
        mock_blob1.blob_type = "BlockBlob"
        mock_blob1.etag = "abc123"

        mock_blob2 = MagicMock()
        mock_blob2.name = "file2.json"
        mock_blob2.size = 2048
        mock_blob2.last_modified = None
        mock_blob2.content_settings = MagicMock()
        mock_blob2.content_settings.content_type = "application/json"
        mock_blob2.blob_type = "BlockBlob"
        mock_blob2.etag = "def456"

        mock_container.list_blobs.return_value = [mock_blob1, mock_blob2]

        scanner = AzureBlobDataScanner(
            connection_string="DefaultEndpointsProtocol=https;..."
        )
        objects = list(scanner.list_objects("test-container"))

        assert len(objects) == 2
        assert objects[0]["name"] == "file1.csv"
        assert objects[1]["size"] == 2048

    def test_azure_get_bucket_metadata(self, mock_azure):
        """Test getting Azure container metadata."""
        from stance.dspm.scanners.azure_blob import AzureBlobDataScanner

        mock_service = MagicMock()
        mock_container = MagicMock()
        mock_azure.from_connection_string.return_value = mock_service
        mock_service.get_container_client.return_value = mock_container

        # Mock properties
        mock_container.get_container_properties.return_value = {
            "public_access": None,
            "lease": {"state": "available"},
            "last_modified": datetime.now(timezone.utc),
        }

        scanner = AzureBlobDataScanner(
            connection_string="DefaultEndpointsProtocol=https;..."
        )
        metadata = scanner.get_bucket_metadata("test-container")

        assert metadata["encrypted"] is True
        assert metadata["public_access"] is False


# =============================================================================
# Test Scanner Integration
# =============================================================================

class TestScannerIntegration:
    """Integration tests for scanners."""

    def test_scan_config_applies_to_all_scanners(self, scan_config):
        """Test that scan config is applied consistently."""
        # Create a test scanner implementation
        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(scan_config)

        assert scanner.config.sample_size == 10
        assert scanner.config.max_object_size_bytes == 1024 * 1024

    def test_detector_available_in_scanner(self, scan_config):
        """Test that detector is available in scanner."""
        class TestScanner(BaseDataScanner):
            def scan_bucket(self, bucket_name):
                pass
            def scan_object(self, bucket_name, object_key):
                pass
            def list_objects(self, bucket_name, prefix=""):
                pass
            def get_object_content(self, bucket_name, object_key, max_bytes=None):
                pass
            def get_bucket_metadata(self, bucket_name):
                pass

        scanner = TestScanner(scan_config)

        assert scanner.detector is not None
        # Check detector has patterns
        assert len(scanner.detector.get_patterns()) > 0


# =============================================================================
# Test Factory Functions
# =============================================================================

class TestScannerFactory:
    """Tests for scanner module exports."""

    def test_imports_from_scanners_module(self):
        """Test that all scanners can be imported."""
        from stance.dspm.scanners import (
            BaseDataScanner,
            ScanConfig,
            ScanResult,
            ScanFinding,
            ScanSummary,
            FindingSeverity,
            S3DataScanner,
            GCSDataScanner,
            AzureBlobDataScanner,
        )

        assert BaseDataScanner is not None
        assert ScanConfig is not None
        assert ScanResult is not None
        assert ScanFinding is not None
        assert ScanSummary is not None
        assert FindingSeverity is not None
        assert S3DataScanner is not None
        assert GCSDataScanner is not None
        assert AzureBlobDataScanner is not None

    def test_imports_from_dspm_module(self):
        """Test that scanners can be imported from main DSPM module."""
        from stance.dspm import (
            BaseDataScanner,
            ScanConfig,
            ScanResult,
            ScanFinding,
            S3DataScanner,
            GCSDataScanner,
            AzureBlobDataScanner,
        )

        assert BaseDataScanner is not None
        assert S3DataScanner is not None
        assert GCSDataScanner is not None
        assert AzureBlobDataScanner is not None
