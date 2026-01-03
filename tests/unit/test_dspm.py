"""
Tests for Mantissa Stance DSPM (Data Security Posture Management).

Tests cover:
- Data classification engine
- Sensitive data detection
- Data flow analysis
- Data residency checking
- Data access analysis
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from stance.dspm import (
    # Classifier
    DataClassifier,
    DataClassification,
    ClassificationLevel,
    DataCategory,
    ClassificationResult,
    ClassificationRule,
    # Detector
    SensitiveDataDetector,
    DetectionResult,
    DataPattern,
    PatternMatch,
    # Analyzer
    DataFlowAnalyzer,
    DataFlow,
    DataResidencyChecker,
    ResidencyViolation,
    DataAccessAnalyzer,
    AccessPattern,
)
from stance.dspm.analyzer import FlowDirection, AccessType
from stance.dspm.detector import PatternType


# =============================================================================
# Classification Tests
# =============================================================================

class TestClassificationLevel:
    """Tests for ClassificationLevel enum."""

    def test_classification_levels_exist(self):
        """Test all classification levels are defined."""
        assert ClassificationLevel.PUBLIC
        assert ClassificationLevel.INTERNAL
        assert ClassificationLevel.CONFIDENTIAL
        assert ClassificationLevel.RESTRICTED
        assert ClassificationLevel.TOP_SECRET

    def test_severity_scores(self):
        """Test severity scores are properly ordered."""
        assert ClassificationLevel.PUBLIC.severity_score == 0
        assert ClassificationLevel.INTERNAL.severity_score == 25
        assert ClassificationLevel.CONFIDENTIAL.severity_score == 50
        assert ClassificationLevel.RESTRICTED.severity_score == 75
        assert ClassificationLevel.TOP_SECRET.severity_score == 100

    def test_severity_order(self):
        """Test severity ordering."""
        levels = [
            ClassificationLevel.PUBLIC,
            ClassificationLevel.INTERNAL,
            ClassificationLevel.CONFIDENTIAL,
            ClassificationLevel.RESTRICTED,
            ClassificationLevel.TOP_SECRET,
        ]
        scores = [l.severity_score for l in levels]
        assert scores == sorted(scores)


class TestDataCategory:
    """Tests for DataCategory enum."""

    def test_pii_categories_exist(self):
        """Test PII categories are defined."""
        assert DataCategory.PII
        assert DataCategory.PII_EMAIL
        assert DataCategory.PII_SSN
        assert DataCategory.PII_PHONE

    def test_pci_categories_exist(self):
        """Test PCI categories are defined."""
        assert DataCategory.PCI
        assert DataCategory.PCI_CARD_NUMBER
        assert DataCategory.PCI_CVV

    def test_phi_categories_exist(self):
        """Test PHI categories are defined."""
        assert DataCategory.PHI
        assert DataCategory.PHI_MEDICAL_RECORD
        assert DataCategory.PHI_DIAGNOSIS

    def test_credential_categories_exist(self):
        """Test credential categories are defined."""
        assert DataCategory.CREDENTIALS
        assert DataCategory.CREDENTIALS_PASSWORD
        assert DataCategory.CREDENTIALS_API_KEY


class TestClassificationRule:
    """Tests for ClassificationRule dataclass."""

    def test_rule_creation(self):
        """Test creating a classification rule."""
        rule = ClassificationRule(
            name="test-rule",
            description="Test rule",
            category=DataCategory.PII_EMAIL,
            level=ClassificationLevel.CONFIDENTIAL,
            patterns=[r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"],
        )

        assert rule.name == "test-rule"
        assert rule.category == DataCategory.PII_EMAIL
        assert rule.level == ClassificationLevel.CONFIDENTIAL
        assert rule.enabled is True

    def test_rule_defaults(self):
        """Test rule default values."""
        rule = ClassificationRule(
            name="test",
            description="Test",
            category=DataCategory.UNKNOWN,
            level=ClassificationLevel.PUBLIC,
        )

        assert rule.patterns == []
        assert rule.field_patterns == []
        assert rule.min_confidence == 0.7
        assert rule.enabled is True


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""

    def test_result_creation(self):
        """Test creating a classification result."""
        result = ClassificationResult(
            level=ClassificationLevel.CONFIDENTIAL,
            categories=[DataCategory.PII_EMAIL],
            confidence=0.95,
            matched_rules=["email-rule"],
        )

        assert result.level == ClassificationLevel.CONFIDENTIAL
        assert DataCategory.PII_EMAIL in result.categories
        assert result.confidence == 0.95

    def test_result_defaults(self):
        """Test result default values."""
        result = ClassificationResult(level=ClassificationLevel.PUBLIC)

        assert result.categories == []
        assert result.confidence == 0.0
        assert result.matched_rules == []


class TestDataClassifier:
    """Tests for DataClassifier class."""

    @pytest.fixture
    def classifier(self):
        """Create classifier instance."""
        return DataClassifier()

    def test_classifier_creation(self, classifier):
        """Test classifier can be created."""
        assert classifier is not None

    def test_classifier_has_default_rules(self, classifier):
        """Test classifier loads default rules."""
        rules = classifier.get_rules()
        assert len(rules) > 0

    def test_classify_ssn(self, classifier):
        """Test SSN classification."""
        # Use valid SSN format (not starting with 000, 666, or 9xx)
        result = classifier.classify(
            content="SSN: 078-05-1120",
            field_name="social_security_number",
        )

        assert result.level.severity_score >= ClassificationLevel.RESTRICTED.severity_score
        assert DataCategory.PII_SSN in result.categories

    def test_classify_email(self, classifier):
        """Test email classification."""
        result = classifier.classify(
            content="Contact: john.doe@example.com",
            field_name="email_address",
        )

        assert DataCategory.PII_EMAIL in result.categories

    def test_classify_phone(self, classifier):
        """Test phone number classification."""
        result = classifier.classify(
            content="Call: 555-123-4567",
            field_name="phone_number",
        )

        assert DataCategory.PII_PHONE in result.categories

    def test_classify_credit_card(self, classifier):
        """Test credit card classification."""
        result = classifier.classify(
            content="Card: 4111111111111111",
            field_name="card_number",
        )

        assert DataCategory.PCI_CARD_NUMBER in result.categories
        assert result.level.severity_score >= ClassificationLevel.RESTRICTED.severity_score

    def test_classify_private_key(self, classifier):
        """Test private key classification."""
        result = classifier.classify(
            content="-----BEGIN RSA PRIVATE KEY-----",
            field_name="private_key",  # Field name helps with classification
        )

        assert DataCategory.CREDENTIALS_PRIVATE_KEY in result.categories
        assert result.level == ClassificationLevel.TOP_SECRET

    def test_classify_public_data(self, classifier):
        """Test public data classification."""
        result = classifier.classify(
            content="Welcome to our website!",
            field_name="greeting",
        )

        assert result.level == ClassificationLevel.PUBLIC

    def test_classify_field_context_boosts(self, classifier):
        """Test field name context improves classification."""
        # With password field name
        result_with_context = classifier.classify(
            content="secret123",
            field_name="password",
        )

        # Without context
        result_without_context = classifier.classify(
            content="secret123",
            field_name="data",
        )

        # Password field should have higher confidence
        assert result_with_context.level.severity_score >= result_without_context.level.severity_score

    def test_add_custom_rule(self, classifier):
        """Test adding a custom rule."""
        custom_rule = ClassificationRule(
            name="custom-id",
            description="Custom ID pattern",
            category=DataCategory.PII,
            level=ClassificationLevel.CONFIDENTIAL,
            patterns=[r"\bCUST-\d{6}\b"],
        )

        classifier.add_rule(custom_rule)
        rules = classifier.get_rules()
        rule_names = [r.name for r in rules]

        assert "custom-id" in rule_names

    def test_remove_rule(self, classifier):
        """Test removing a rule."""
        # First verify rule exists
        rule = classifier.get_rule("pii-email")
        assert rule is not None

        # Remove it
        result = classifier.remove_rule("pii-email")
        assert result is True

        # Verify it's gone
        rule = classifier.get_rule("pii-email")
        assert rule is None

    def test_remove_nonexistent_rule(self, classifier):
        """Test removing non-existent rule returns False."""
        result = classifier.remove_rule("nonexistent-rule")
        assert result is False

    def test_classify_asset(self, classifier):
        """Test asset classification with samples."""
        samples = [
            {"name": "John Doe", "email": "john@example.com", "ssn": "123-45-6789"},
            {"name": "Jane Doe", "email": "jane@example.com", "phone": "555-123-4567"},
        ]

        classification = classifier.classify_asset(
            asset_id="db-001",
            asset_type="rds_database",
            samples=samples,
            metadata={"region": "us-east-1"},
        )

        assert classification.asset_id == "db-001"
        assert classification.asset_type == "rds_database"
        assert classification.classification.level.severity_score > 0
        assert len(classification.classification.categories) > 0

    def test_compliance_framework_detection(self, classifier):
        """Test compliance frameworks are detected based on categories."""
        # PCI data should trigger PCI-DSS
        samples = [{"card_number": "4111111111111111"}]
        classification = classifier.classify_asset(
            asset_id="test",
            asset_type="database",
            samples=samples,
        )

        assert "PCI-DSS" in classification.compliance_frameworks

    def test_recommendations_generated(self, classifier):
        """Test recommendations are generated for sensitive data."""
        result = classifier.classify(
            content="SSN: 123-45-6789",
            field_name="ssn",
        )

        assert len(result.recommendations) > 0


# =============================================================================
# Detection Tests
# =============================================================================

class TestDataPattern:
    """Tests for DataPattern dataclass."""

    def test_pattern_creation(self):
        """Test creating a data pattern."""
        pattern = DataPattern(
            name="test-pattern",
            description="Test pattern",
            pattern_type=PatternType.REGEX,
            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            category=DataCategory.PII_SSN,
        )

        assert pattern.name == "test-pattern"
        assert pattern.pattern_type == PatternType.REGEX
        assert pattern._compiled is not None

    def test_keyword_pattern(self):
        """Test keyword pattern doesn't compile regex."""
        pattern = DataPattern(
            name="keyword",
            description="Keyword pattern",
            pattern_type=PatternType.KEYWORD,
            pattern="confidential",
            category=DataCategory.BUSINESS,
        )

        assert pattern._compiled is None


class TestPatternMatch:
    """Tests for PatternMatch dataclass."""

    def test_match_creation(self):
        """Test creating a pattern match."""
        match = PatternMatch(
            pattern_name="ssn-pattern",
            category=DataCategory.PII_SSN,
            value="123-45-6789",
            location={"line": 1, "column": 10},
            confidence=0.95,
        )

        assert match.pattern_name == "ssn-pattern"
        assert match.category == DataCategory.PII_SSN
        assert match.confidence == 0.95

    def test_value_redaction(self):
        """Test sensitive values are redacted."""
        match = PatternMatch(
            pattern_name="test",
            category=DataCategory.PII_SSN,
            value="123-45-6789",
            location={},
            confidence=0.9,
        )

        assert match.redacted_value != match.value
        assert "****" in match.redacted_value or "*" in match.redacted_value

    def test_short_value_redaction(self):
        """Test short values are fully redacted."""
        match = PatternMatch(
            pattern_name="test",
            category=DataCategory.PCI_CVV,
            value="123",
            location={},
            confidence=0.9,
        )

        assert match.redacted_value == "***"


class TestDetectionResult:
    """Tests for DetectionResult dataclass."""

    def test_result_creation(self):
        """Test creating a detection result."""
        result = DetectionResult(
            asset_id="bucket-001",
            asset_type="s3_bucket",
            total_records_scanned=100,
        )

        assert result.asset_id == "bucket-001"
        assert result.total_records_scanned == 100
        assert result.has_sensitive_data is False

    def test_has_sensitive_data(self):
        """Test has_sensitive_data property."""
        match = PatternMatch(
            pattern_name="test",
            category=DataCategory.PII_EMAIL,
            value="test@example.com",
            location={},
            confidence=0.9,
        )

        result = DetectionResult(
            asset_id="test",
            asset_type="database",
            matches=[match],
        )

        assert result.has_sensitive_data is True
        assert result.match_count == 1

    def test_get_matches_by_category(self):
        """Test filtering matches by category."""
        matches = [
            PatternMatch("p1", DataCategory.PII_EMAIL, "a@b.com", {}, 0.9),
            PatternMatch("p2", DataCategory.PII_SSN, "123-45-6789", {}, 0.9),
            PatternMatch("p3", DataCategory.PII_EMAIL, "c@d.com", {}, 0.9),
        ]

        result = DetectionResult(
            asset_id="test",
            asset_type="database",
            matches=matches,
        )

        email_matches = result.get_matches_by_category(DataCategory.PII_EMAIL)
        assert len(email_matches) == 2


class TestSensitiveDataDetector:
    """Tests for SensitiveDataDetector class."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return SensitiveDataDetector()

    def test_detector_creation(self, detector):
        """Test detector can be created."""
        assert detector is not None

    def test_detector_has_default_patterns(self, detector):
        """Test detector loads default patterns."""
        patterns = detector.get_patterns()
        assert len(patterns) > 0

    def test_scan_ssn(self, detector):
        """Test scanning for SSN."""
        # Use valid SSN format (formatted pattern matches xxx-xx-xxxx)
        matches = detector.scan_content(
            content="My SSN is 078-05-1120",
            field_name="ssn",  # Field name context helps
        )

        assert len(matches) > 0
        ssn_matches = [m for m in matches if m.category == DataCategory.PII_SSN]
        assert len(ssn_matches) > 0

    def test_scan_email(self, detector):
        """Test scanning for email."""
        matches = detector.scan_content(
            content="Contact: john.doe@example.com",
            field_name="contact",
        )

        email_matches = [m for m in matches if m.category == DataCategory.PII_EMAIL]
        assert len(email_matches) > 0

    def test_scan_credit_card_visa(self, detector):
        """Test scanning for Visa card."""
        matches = detector.scan_content(
            content="Card number: 4111111111111111",
            field_name="payment",
        )

        card_matches = [m for m in matches if m.category == DataCategory.PCI_CARD_NUMBER]
        assert len(card_matches) > 0

    def test_scan_credit_card_mastercard(self, detector):
        """Test scanning for Mastercard."""
        matches = detector.scan_content(
            content="Card: 5500000000000004",
            field_name="payment",
        )

        card_matches = [m for m in matches if m.category == DataCategory.PCI_CARD_NUMBER]
        assert len(card_matches) > 0

    def test_scan_private_key(self, detector):
        """Test scanning for private key."""
        content = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA...
        -----END RSA PRIVATE KEY-----
        """
        matches = detector.scan_content(content)

        key_matches = [m for m in matches if m.category == DataCategory.CREDENTIALS_PRIVATE_KEY]
        assert len(key_matches) > 0

    def test_scan_aws_key(self, detector):
        """Test scanning for AWS access key."""
        matches = detector.scan_content(
            content="aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        )

        key_matches = [m for m in matches if m.category == DataCategory.CREDENTIALS_API_KEY]
        assert len(key_matches) > 0

    def test_scan_jwt(self, detector):
        """Test scanning for JWT tokens."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        matches = detector.scan_content(f"Token: {jwt}")

        token_matches = [m for m in matches if m.category == DataCategory.CREDENTIALS_TOKEN]
        assert len(token_matches) > 0

    def test_scan_records(self, detector):
        """Test scanning multiple records."""
        records = [
            {"name": "John", "email": "john@example.com", "ssn": "123-45-6789"},
            {"name": "Jane", "email": "jane@example.com", "phone": "555-123-4567"},
        ]

        result = detector.scan_records(
            records=records,
            asset_id="db-001",
            asset_type="database",
        )

        assert result.asset_id == "db-001"
        assert result.total_records_scanned == 2
        assert result.has_sensitive_data is True

    def test_scan_records_with_sample_size(self, detector):
        """Test scanning with sample size limit."""
        records = [{"id": i, "data": "test"} for i in range(100)]

        result = detector.scan_records(
            records=records,
            asset_id="test",
            asset_type="database",
            sample_size=10,
        )

        assert result.total_records_scanned == 10

    def test_add_custom_pattern(self, detector):
        """Test adding a custom pattern."""
        pattern = DataPattern(
            name="custom-id",
            description="Custom ID",
            pattern_type=PatternType.REGEX,
            pattern=r"\bCUST-\d{6}\b",
            category=DataCategory.PII,
        )

        detector.add_pattern(pattern)

        # Test it works
        matches = detector.scan_content("Customer: CUST-123456")
        custom_matches = [m for m in matches if m.pattern_name == "custom-id"]
        assert len(custom_matches) > 0

    def test_remove_pattern(self, detector):
        """Test removing a pattern."""
        result = detector.remove_pattern("email-address")
        assert result is True

        # Verify emails no longer detected by that pattern
        matches = detector.scan_content("test@example.com")
        email_pattern_matches = [m for m in matches if m.pattern_name == "email-address"]
        assert len(email_pattern_matches) == 0

    def test_luhn_validation(self, detector):
        """Test Luhn algorithm validation."""
        # Valid card number (passes Luhn)
        assert detector._luhn_validate("4111111111111111") is True

        # Invalid card number
        assert detector._luhn_validate("4111111111111112") is False


# =============================================================================
# Analyzer Tests
# =============================================================================

class TestDataFlow:
    """Tests for DataFlow dataclass."""

    def test_flow_creation(self):
        """Test creating a data flow."""
        flow = DataFlow(
            flow_id="flow-001",
            source_asset="s3://source-bucket",
            destination_asset="rds://database",
            direction=FlowDirection.INTERNAL,
        )

        assert flow.flow_id == "flow-001"
        assert flow.direction == FlowDirection.INTERNAL

    def test_is_cross_boundary(self):
        """Test cross-boundary detection."""
        internal_flow = DataFlow(
            flow_id="f1",
            source_asset="a",
            destination_asset="b",
            direction=FlowDirection.INTERNAL,
        )
        assert internal_flow.is_cross_boundary is False

        outbound_flow = DataFlow(
            flow_id="f2",
            source_asset="a",
            destination_asset="b",
            direction=FlowDirection.OUTBOUND,
        )
        assert outbound_flow.is_cross_boundary is True

    def test_requires_encryption(self):
        """Test encryption requirement detection."""
        public_flow = DataFlow(
            flow_id="f1",
            source_asset="a",
            destination_asset="b",
            direction=FlowDirection.INTERNAL,
            classification_level=ClassificationLevel.PUBLIC,
        )
        assert public_flow.requires_encryption is False

        confidential_flow = DataFlow(
            flow_id="f2",
            source_asset="a",
            destination_asset="b",
            direction=FlowDirection.INTERNAL,
            classification_level=ClassificationLevel.CONFIDENTIAL,
        )
        assert confidential_flow.requires_encryption is True


class TestDataFlowAnalyzer:
    """Tests for DataFlowAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return DataFlowAnalyzer()

    def test_analyzer_creation(self, analyzer):
        """Test analyzer can be created."""
        assert analyzer is not None

    def test_add_and_get_flow(self, analyzer):
        """Test adding and retrieving flows."""
        flow = DataFlow(
            flow_id="flow-001",
            source_asset="source",
            destination_asset="dest",
            direction=FlowDirection.INTERNAL,
        )

        analyzer.add_flow(flow)
        retrieved = analyzer.get_flow("flow-001")

        assert retrieved is not None
        assert retrieved.flow_id == "flow-001"

    def test_get_flows_for_asset(self, analyzer):
        """Test getting flows for an asset."""
        flows = [
            DataFlow("f1", "asset-A", "asset-B", FlowDirection.INTERNAL),
            DataFlow("f2", "asset-B", "asset-C", FlowDirection.INTERNAL),
            DataFlow("f3", "asset-D", "asset-A", FlowDirection.INTERNAL),
        ]

        for flow in flows:
            analyzer.add_flow(flow)

        asset_a_flows = analyzer.get_flows_for_asset("asset-A")
        assert len(asset_a_flows) == 2  # f1 and f3

    def test_analyze_unencrypted_flow_risk(self, analyzer):
        """Test unencrypted sensitive flow risk detection."""
        flow = DataFlow(
            flow_id="f1",
            source_asset="a",
            destination_asset="b",
            direction=FlowDirection.INTERNAL,
            classification_level=ClassificationLevel.CONFIDENTIAL,
            encryption_in_transit=False,
        )

        risks = analyzer.analyze_flow_risks(flow)
        unencrypted_risks = [r for r in risks if r["type"] == "unencrypted_sensitive_data"]

        assert len(unencrypted_risks) > 0

    def test_analyze_cross_boundary_risk(self, analyzer):
        """Test cross-boundary sensitive flow risk."""
        flow = DataFlow(
            flow_id="f1",
            source_asset="a",
            destination_asset="b",
            direction=FlowDirection.OUTBOUND,
            classification_level=ClassificationLevel.RESTRICTED,
        )

        risks = analyzer.analyze_flow_risks(flow)
        boundary_risks = [r for r in risks if r["type"] == "cross_boundary_sensitive_data"]

        assert len(boundary_risks) > 0

    def test_analyze_pci_outbound_risk(self, analyzer):
        """Test PCI data outbound risk."""
        flow = DataFlow(
            flow_id="f1",
            source_asset="a",
            destination_asset="b",
            direction=FlowDirection.OUTBOUND,
            data_categories=[DataCategory.PCI_CARD_NUMBER],
        )

        risks = analyzer.analyze_flow_risks(flow)
        pci_risks = [r for r in risks if r["type"] == "pci_data_outbound"]

        assert len(pci_risks) > 0

    def test_get_flow_graph(self, analyzer):
        """Test generating flow graph."""
        flows = [
            DataFlow("f1", "A", "B", FlowDirection.INTERNAL),
            DataFlow("f2", "B", "C", FlowDirection.INTERNAL),
        ]

        for flow in flows:
            analyzer.add_flow(flow)

        graph = analyzer.get_flow_graph()

        assert "A" in graph["nodes"]
        assert "B" in graph["nodes"]
        assert "C" in graph["nodes"]
        assert len(graph["edges"]) == 2


class TestDataResidencyChecker:
    """Tests for DataResidencyChecker class."""

    @pytest.fixture
    def checker(self):
        """Create residency checker instance."""
        return DataResidencyChecker()

    def test_checker_creation(self, checker):
        """Test checker can be created."""
        assert checker is not None

    def test_gdpr_compliant_region(self, checker):
        """Test GDPR-compliant region passes."""
        violations = checker.check_compliance(
            asset_id="db-001",
            actual_region="eu-west-1",
            data_categories=[DataCategory.PII_EMAIL],
        )

        gdpr_violations = [v for v in violations if "GDPR" in v.compliance_frameworks]
        assert len(gdpr_violations) == 0

    def test_gdpr_non_compliant_region(self, checker):
        """Test non-EU region fails GDPR."""
        violations = checker.check_compliance(
            asset_id="db-001",
            actual_region="us-east-1",
            data_categories=[DataCategory.PII_EMAIL],
        )

        gdpr_violations = [v for v in violations if "GDPR" in v.compliance_frameworks]
        assert len(gdpr_violations) > 0

    def test_add_custom_rule(self, checker):
        """Test adding a custom residency rule."""
        checker.add_rule("CUSTOM", ["custom-region-1", "custom-region-2"])

        # This should not cause violations for categories not mapped to CUSTOM
        violations = checker.check_compliance(
            asset_id="test",
            actual_region="us-east-1",
            data_categories=[DataCategory.BUSINESS],
        )

        # No violations because BUSINESS isn't mapped to any framework
        assert len(violations) == 0


class TestDataAccessAnalyzer:
    """Tests for DataAccessAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create access analyzer instance."""
        return DataAccessAnalyzer()

    def test_analyzer_creation(self, analyzer):
        """Test analyzer can be created."""
        assert analyzer is not None

    def test_record_access(self, analyzer):
        """Test recording access patterns."""
        pattern = AccessPattern(
            asset_id="db-001",
            principal_id="user-123",
            principal_type="user",
            access_type=AccessType.READ,
        )

        analyzer.record_access(pattern)
        patterns = analyzer.get_patterns()

        assert len(patterns) == 1
        assert patterns[0].asset_id == "db-001"

    def test_analyze_excessive_access_risk(self, analyzer):
        """Test excessive access risk detection."""
        # Create many principals accessing same asset
        for i in range(60):
            pattern = AccessPattern(
                asset_id="sensitive-db",
                principal_id=f"user-{i}",
                principal_type="user",
                access_type=AccessType.READ,
            )
            analyzer.record_access(pattern)

        risks = analyzer.analyze_access_risks(
            asset_id="sensitive-db",
            classification_level=ClassificationLevel.CONFIDENTIAL,
        )

        excessive_risks = [r for r in risks if r["type"] == "excessive_access"]
        assert len(excessive_risks) > 0

    def test_analyze_anomalous_access_risk(self, analyzer):
        """Test anomalous access risk detection."""
        pattern = AccessPattern(
            asset_id="db-001",
            principal_id="user-123",
            principal_type="user",
            access_type=AccessType.READ,
            is_anomalous=True,
        )
        analyzer.record_access(pattern)

        risks = analyzer.analyze_access_risks(
            asset_id="db-001",
            classification_level=ClassificationLevel.CONFIDENTIAL,
        )

        anomaly_risks = [r for r in risks if r["type"] == "anomalous_access"]
        assert len(anomaly_risks) > 0

    def test_get_access_summary(self, analyzer):
        """Test getting access summary."""
        patterns = [
            AccessPattern("db-001", "user-1", "user", AccessType.READ),
            AccessPattern("db-001", "user-2", "user", AccessType.WRITE),
            AccessPattern("db-001", "user-1", "user", AccessType.READ),
        ]

        for p in patterns:
            analyzer.record_access(p)

        summary = analyzer.get_access_summary("db-001")

        assert summary["total_access_events"] == 3
        assert summary["unique_principals"] == 2
        assert "read" in summary["access_types"]
        assert "write" in summary["access_types"]

    def test_detect_anomaly_new_principal(self, analyzer):
        """Test anomaly detection for new principal."""
        # First establish baseline
        baseline_pattern = AccessPattern(
            asset_id="db-001",
            principal_id="user-1",
            principal_type="user",
            access_type=AccessType.READ,
            last_access=datetime.now(timezone.utc),
        )
        analyzer.record_access(baseline_pattern)

        # New principal should be anomalous
        new_pattern = AccessPattern(
            asset_id="db-001",
            principal_id="new-user",
            principal_type="user",
            access_type=AccessType.READ,
            last_access=datetime.now(timezone.utc),
        )

        is_anomalous = analyzer.detect_anomalies(new_pattern)
        assert is_anomalous is True

    def test_detect_anomaly_new_access_type(self, analyzer):
        """Test anomaly detection for new access type."""
        # Establish baseline with READ access
        baseline = AccessPattern(
            asset_id="db-001",
            principal_id="user-1",
            principal_type="user",
            access_type=AccessType.READ,
        )
        analyzer.record_access(baseline)

        # Same user with ADMIN access should be anomalous
        admin_pattern = AccessPattern(
            asset_id="db-001",
            principal_id="user-1",
            principal_type="user",
            access_type=AccessType.ADMIN,
        )

        is_anomalous = analyzer.detect_anomalies(admin_pattern)
        assert is_anomalous is True

    def test_clear_patterns(self, analyzer):
        """Test clearing patterns."""
        pattern = AccessPattern("db", "user", "user", AccessType.READ)
        analyzer.record_access(pattern)

        analyzer.clear_patterns()
        patterns = analyzer.get_patterns()

        assert len(patterns) == 0


# =============================================================================
# Integration Tests
# =============================================================================

class TestDSPMIntegration:
    """Integration tests for DSPM components."""

    def test_classify_and_detect(self):
        """Test classifying and detecting sensitive data."""
        classifier = DataClassifier()
        detector = SensitiveDataDetector()

        # Sample data with valid SSN format and email
        content = "Customer SSN: 078-05-1120, Email: john@example.com"

        # Detect sensitive data
        matches = detector.scan_content(content, field_name="customer_info")
        assert len(matches) > 0

        # Classify the data with field context
        result = classifier.classify(content=content, field_name="customer_ssn")
        assert result.level.severity_score > 0

    def test_flow_analysis_with_classification(self):
        """Test flow analysis with classification context."""
        classifier = DataClassifier()
        flow_analyzer = DataFlowAnalyzer()

        # Create classified flow
        flow = DataFlow(
            flow_id="f1",
            source_asset="source-db",
            destination_asset="analytics-db",
            direction=FlowDirection.INTERNAL,
            data_categories=[DataCategory.PII_SSN, DataCategory.PII_EMAIL],
            classification_level=ClassificationLevel.RESTRICTED,
            encryption_in_transit=False,
        )

        flow_analyzer.add_flow(flow)
        risks = flow_analyzer.analyze_flow_risks(flow)

        # Should identify unencrypted sensitive data risk
        assert len(risks) > 0

    def test_residency_with_classification(self):
        """Test residency checking with classified data."""
        classifier = DataClassifier()
        residency_checker = DataResidencyChecker()

        # Classify some PII data
        result = classifier.classify(
            content="john@example.com",
            field_name="email",
        )

        # Check residency
        violations = residency_checker.check_compliance(
            asset_id="db-001",
            actual_region="us-east-1",
            data_categories=result.categories,
        )

        # Should have GDPR violation for PII in US
        gdpr_violations = [v for v in violations if "GDPR" in v.compliance_frameworks]
        assert len(gdpr_violations) > 0
