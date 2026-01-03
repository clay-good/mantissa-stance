"""
Unit tests for DSPM extended sources base classes.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from stance.dspm.extended.base import (
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
    BaseExtendedScanner,
)
from stance.dspm.scanners.base import FindingSeverity
from stance.dspm.classifier import ClassificationLevel, DataCategory


class TestExtendedSourceType:
    """Tests for ExtendedSourceType enum."""

    def test_source_types_exist(self):
        """Test all expected source types exist."""
        assert ExtendedSourceType.SNOWFLAKE.value == "snowflake"
        assert ExtendedSourceType.GOOGLE_DRIVE.value == "google_drive"
        assert ExtendedSourceType.RDS.value == "rds"
        assert ExtendedSourceType.CLOUD_SQL.value == "cloud_sql"
        assert ExtendedSourceType.AZURE_SQL.value == "azure_sql"
        assert ExtendedSourceType.BIGQUERY.value == "bigquery"
        assert ExtendedSourceType.REDSHIFT.value == "redshift"


class TestExtendedScanConfig:
    """Tests for ExtendedScanConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = ExtendedScanConfig()

        assert config.sample_size == 100
        assert config.max_tables == 50
        assert config.max_columns_per_table == 100
        assert config.include_schemas is None
        assert "information_schema" in config.exclude_schemas
        assert "pg_catalog" in config.exclude_schemas
        assert config.include_tables is None
        assert config.exclude_tables == []
        assert config.file_extensions is None
        assert config.timeout_seconds == 600
        assert config.sample_rows_per_column == 100

    def test_custom_config(self):
        """Test custom configuration."""
        config = ExtendedScanConfig(
            sample_size=50,
            max_tables=10,
            include_schemas=["public"],
            exclude_tables=["users"],
            file_extensions=["txt", "csv"],
        )

        assert config.sample_size == 50
        assert config.max_tables == 10
        assert config.include_schemas == ["public"]
        assert config.exclude_tables == ["users"]
        assert config.file_extensions == ["txt", "csv"]

    def test_file_extension_normalization(self):
        """Test that file extensions are normalized."""
        config = ExtendedScanConfig(
            file_extensions=[".TXT", "CSV", ".json"]
        )

        assert config.file_extensions == ["txt", "csv", "json"]


class TestExtendedScanFinding:
    """Tests for ExtendedScanFinding."""

    def test_finding_creation(self):
        """Test finding creation with all fields."""
        finding = ExtendedScanFinding(
            finding_id="abc123",
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=FindingSeverity.HIGH,
            title="Sensitive data in column: PII",
            description="Detected SSN patterns",
            source_type=ExtendedSourceType.SNOWFLAKE,
            source_location="snowflake://db.schema.table",
            object_type="column",
            object_name="ssn_column",
            classification_level=ClassificationLevel.RESTRICTED,
            categories=[DataCategory.PII],
        )

        assert finding.finding_id == "abc123"
        assert finding.severity == FindingSeverity.HIGH
        assert finding.source_type == ExtendedSourceType.SNOWFLAKE
        assert finding.classification_level == ClassificationLevel.RESTRICTED
        assert DataCategory.PII in finding.categories

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = ExtendedScanFinding(
            finding_id="abc123",
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=FindingSeverity.HIGH,
            title="Test",
            description="Test description",
            source_type=ExtendedSourceType.RDS,
            source_location="rds://host/db",
            object_type="column",
            object_name="test_col",
            classification_level=ClassificationLevel.CONFIDENTIAL,
            categories=[DataCategory.FINANCIAL],
            metadata={"test": "value"},
        )

        data = finding.to_dict()

        assert data["finding_id"] == "abc123"
        assert data["severity"] == "high"
        assert data["source_type"] == "rds"
        assert data["classification_level"] == "confidential"
        assert "financial" in data["categories"]
        assert data["metadata"]["test"] == "value"
        assert "detected_at" in data

    def test_finding_default_values(self):
        """Test finding default values."""
        finding = ExtendedScanFinding(
            finding_id="test",
            finding_type="TEST",
            severity=FindingSeverity.LOW,
            title="Test",
            description="Test",
            source_type=ExtendedSourceType.GOOGLE_DRIVE,
            source_location="drive://",
            object_type="file",
            object_name="test.txt",
            classification_level=ClassificationLevel.PUBLIC,
        )

        assert finding.categories == []
        assert finding.sample_matches == []
        assert finding.remediation == ""
        assert finding.metadata == {}
        assert isinstance(finding.detected_at, datetime)


class TestExtendedScanSummary:
    """Tests for ExtendedScanSummary."""

    def test_summary_default_values(self):
        """Test summary default values."""
        summary = ExtendedScanSummary()

        assert summary.total_objects_scanned == 0
        assert summary.total_objects_skipped == 0
        assert summary.total_rows_sampled == 0
        assert summary.total_files_scanned == 0
        assert summary.total_findings == 0
        assert summary.findings_by_severity == {}
        assert summary.findings_by_category == {}
        assert summary.scan_duration_seconds == 0.0
        assert summary.errors == []

    def test_summary_to_dict(self):
        """Test summary serialization."""
        summary = ExtendedScanSummary(
            total_objects_scanned=10,
            total_findings=5,
            findings_by_severity={"high": 2, "medium": 3},
            scan_duration_seconds=15.5,
        )

        data = summary.to_dict()

        assert data["total_objects_scanned"] == 10
        assert data["total_findings"] == 5
        assert data["findings_by_severity"]["high"] == 2
        assert data["scan_duration_seconds"] == 15.5


class TestExtendedScanResult:
    """Tests for ExtendedScanResult."""

    def test_result_creation(self):
        """Test result creation."""
        config = ExtendedScanConfig()
        result = ExtendedScanResult(
            scan_id="scan123",
            source_type=ExtendedSourceType.SNOWFLAKE,
            target="MY_DATABASE",
            config=config,
        )

        assert result.scan_id == "scan123"
        assert result.source_type == ExtendedSourceType.SNOWFLAKE
        assert result.target == "MY_DATABASE"
        assert result.findings == []
        assert result.completed_at is None

    def test_result_has_findings(self):
        """Test has_findings property."""
        config = ExtendedScanConfig()
        result = ExtendedScanResult(
            scan_id="test",
            source_type=ExtendedSourceType.RDS,
            target="test",
            config=config,
        )

        assert result.has_findings is False

        result.findings.append(
            ExtendedScanFinding(
                finding_id="f1",
                finding_type="TEST",
                severity=FindingSeverity.HIGH,
                title="Test",
                description="Test",
                source_type=ExtendedSourceType.RDS,
                source_location="rds://",
                object_type="column",
                object_name="test",
                classification_level=ClassificationLevel.RESTRICTED,
            )
        )

        assert result.has_findings is True

    def test_result_highest_severity(self):
        """Test highest_severity property."""
        config = ExtendedScanConfig()
        result = ExtendedScanResult(
            scan_id="test",
            source_type=ExtendedSourceType.RDS,
            target="test",
            config=config,
        )

        # No findings
        assert result.highest_severity is None

        # Add low severity finding
        result.findings.append(
            ExtendedScanFinding(
                finding_id="f1",
                finding_type="TEST",
                severity=FindingSeverity.LOW,
                title="Test",
                description="Test",
                source_type=ExtendedSourceType.RDS,
                source_location="rds://",
                object_type="column",
                object_name="test",
                classification_level=ClassificationLevel.INTERNAL,
            )
        )
        assert result.highest_severity == FindingSeverity.LOW

        # Add high severity finding
        result.findings.append(
            ExtendedScanFinding(
                finding_id="f2",
                finding_type="TEST",
                severity=FindingSeverity.HIGH,
                title="Test",
                description="Test",
                source_type=ExtendedSourceType.RDS,
                source_location="rds://",
                object_type="column",
                object_name="test2",
                classification_level=ClassificationLevel.RESTRICTED,
            )
        )
        assert result.highest_severity == FindingSeverity.HIGH

    def test_result_to_dict(self):
        """Test result serialization."""
        config = ExtendedScanConfig()
        result = ExtendedScanResult(
            scan_id="test",
            source_type=ExtendedSourceType.GOOGLE_DRIVE,
            target="folder123",
            config=config,
        )
        result.completed_at = datetime.now(timezone.utc)

        data = result.to_dict()

        assert data["scan_id"] == "test"
        assert data["source_type"] == "google_drive"
        assert data["target"] == "folder123"
        assert "started_at" in data
        assert "completed_at" in data


class TestBaseExtendedScanner:
    """Tests for BaseExtendedScanner."""

    def test_scanner_initialization(self):
        """Test scanner initialization."""
        # Create a concrete implementation for testing
        class TestScanner(BaseExtendedScanner):
            source_type = ExtendedSourceType.SNOWFLAKE

            def scan(self, target):
                pass

            def test_connection(self):
                return True

            def list_scannable_objects(self, target):
                return []

        scanner = TestScanner()
        assert scanner.config.sample_size == 100
        assert scanner.detector is not None

    def test_scanner_custom_config(self):
        """Test scanner with custom config."""
        class TestScanner(BaseExtendedScanner):
            source_type = ExtendedSourceType.RDS

            def scan(self, target):
                pass

            def test_connection(self):
                return True

            def list_scannable_objects(self, target):
                return []

        config = ExtendedScanConfig(sample_size=50)
        scanner = TestScanner(config)
        assert scanner.config.sample_size == 50

    def test_generate_finding_id(self):
        """Test finding ID generation."""
        class TestScanner(BaseExtendedScanner):
            source_type = ExtendedSourceType.SNOWFLAKE

            def scan(self, target):
                pass

            def test_connection(self):
                return True

            def list_scannable_objects(self, target):
                return []

        scanner = TestScanner()
        id1 = scanner._generate_finding_id("source1", "object1")
        id2 = scanner._generate_finding_id("source1", "object1")
        id3 = scanner._generate_finding_id("source2", "object1")

        # Same inputs should produce same ID
        assert id1 == id2
        # Different inputs should produce different ID
        assert id1 != id3
        # ID should be 16 characters
        assert len(id1) == 16

    def test_get_remediation_guidance(self):
        """Test remediation guidance generation."""
        class TestScanner(BaseExtendedScanner):
            source_type = ExtendedSourceType.RDS

            def scan(self, target):
                pass

            def test_connection(self):
                return True

            def list_scannable_objects(self, target):
                return []

        scanner = TestScanner()

        # High severity column
        guidance = scanner._get_remediation_guidance(
            ClassificationLevel.TOP_SECRET,
            "column",
            {"encrypted": False},
        )
        assert "sensitive data" in guidance.lower()
        assert "encryption" in guidance.lower()

        # File type
        guidance = scanner._get_remediation_guidance(
            ClassificationLevel.RESTRICTED,
            "file",
            {},
        )
        assert "file" in guidance.lower() or "storage" in guidance.lower()

    @patch("stance.dspm.detector.SensitiveDataDetector")
    def test_create_finding_from_detection(self, mock_detector_class):
        """Test creating finding from detection result."""
        class TestScanner(BaseExtendedScanner):
            source_type = ExtendedSourceType.SNOWFLAKE

            def scan(self, target):
                pass

            def test_connection(self):
                return True

            def list_scannable_objects(self, target):
                return []

        scanner = TestScanner()

        # Create mock detection result
        from stance.dspm.detector import DetectionResult, PatternMatch

        mock_match = MagicMock()
        mock_match.pattern_name = "SSN"
        mock_match.category = DataCategory.PII
        mock_match.redacted_value = "XXX-XX-1234"
        mock_match.confidence = 0.95

        mock_result = MagicMock(spec=DetectionResult)
        mock_result.has_sensitive_data = True
        mock_result.highest_classification = ClassificationLevel.RESTRICTED
        mock_result.categories_found = [DataCategory.PII]
        mock_result.match_count = 5
        mock_result.matches = [mock_match]
        mock_result.scan_coverage = 1.0

        finding = scanner._create_finding_from_detection(
            source_location="snowflake://db.schema.table",
            object_type="column",
            object_name="ssn_column",
            detection_result=mock_result,
            metadata={"table": "users"},
        )

        assert finding is not None
        assert finding.severity == FindingSeverity.HIGH
        assert finding.source_type == ExtendedSourceType.SNOWFLAKE
        assert "column" in finding.title.lower()
        assert len(finding.sample_matches) == 1
        assert finding.metadata["table"] == "users"

    def test_create_finding_no_sensitive_data(self):
        """Test that no finding is created when no sensitive data found."""
        class TestScanner(BaseExtendedScanner):
            source_type = ExtendedSourceType.RDS

            def scan(self, target):
                pass

            def test_connection(self):
                return True

            def list_scannable_objects(self, target):
                return []

        scanner = TestScanner()

        mock_result = MagicMock()
        mock_result.has_sensitive_data = False

        finding = scanner._create_finding_from_detection(
            source_location="rds://host/db",
            object_type="column",
            object_name="test_col",
            detection_result=mock_result,
            metadata={},
        )

        assert finding is None
