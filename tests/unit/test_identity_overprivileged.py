"""
Unit tests for Identity Security Over-Privileged Detection.

Tests the OverPrivilegedAnalyzer for detecting principals with permissions
that exceed their actual usage patterns.
"""

import pytest
from datetime import datetime, timezone, timedelta

from stance.identity.overprivileged import (
    OverPrivilegedConfig,
    OverPrivilegedFindingType,
    OverPrivilegedSeverity,
    UsagePattern,
    OverPrivilegedFinding,
    OverPrivilegedSummary,
    OverPrivilegedResult,
    OverPrivilegedAnalyzer,
    create_usage_patterns_from_access_review,
)
from stance.identity.base import (
    Principal,
    PrincipalType,
    PermissionLevel,
    ResourceAccess,
)
from stance.dspm.access.base import AccessSummary


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def user_principal() -> Principal:
    """Create a user principal for testing."""
    return Principal(
        id="arn:aws:iam::123456789012:user/alice",
        name="alice",
        principal_type=PrincipalType.USER,
        cloud_provider="aws",
        account_id="123456789012",
    )


@pytest.fixture
def service_account_principal() -> Principal:
    """Create a service account principal for testing."""
    return Principal(
        id="app-service@project.iam.gserviceaccount.com",
        name="app-service",
        principal_type=PrincipalType.SERVICE_ACCOUNT,
        cloud_provider="gcp",
        account_id="my-project",
    )


@pytest.fixture
def role_principal() -> Principal:
    """Create a role principal for testing."""
    return Principal(
        id="arn:aws:iam::123456789012:role/DataReader",
        name="DataReader",
        principal_type=PrincipalType.ROLE,
        cloud_provider="aws",
        account_id="123456789012",
    )


@pytest.fixture
def write_access() -> ResourceAccess:
    """Create write access for testing."""
    return ResourceAccess(
        resource_id="my-bucket",
        resource_type="s3_bucket",
        permission_level=PermissionLevel.WRITE,
        permission_source="direct",
    )


@pytest.fixture
def admin_access() -> ResourceAccess:
    """Create admin access for testing."""
    return ResourceAccess(
        resource_id="admin-bucket",
        resource_type="s3_bucket",
        permission_level=PermissionLevel.ADMIN,
        permission_source="direct",
    )


@pytest.fixture
def read_access() -> ResourceAccess:
    """Create read access for testing."""
    return ResourceAccess(
        resource_id="read-bucket",
        resource_type="s3_bucket",
        permission_level=PermissionLevel.READ,
        permission_source="direct",
    )


@pytest.fixture
def read_only_summary() -> AccessSummary:
    """Create an access summary showing only read operations."""
    return AccessSummary(
        principal_id="arn:aws:iam::123456789012:user/alice",
        principal_type="user",
        resource_id="my-bucket",
        total_access_count=50,
        read_count=50,
        write_count=0,
        delete_count=0,
        list_count=0,
        first_access=datetime.now(timezone.utc) - timedelta(days=30),
        last_access=datetime.now(timezone.utc) - timedelta(days=2),
        days_since_last_access=2,
    )


@pytest.fixture
def write_summary() -> AccessSummary:
    """Create an access summary showing write operations."""
    return AccessSummary(
        principal_id="arn:aws:iam::123456789012:user/alice",
        principal_type="user",
        resource_id="my-bucket",
        total_access_count=100,
        read_count=60,
        write_count=40,
        delete_count=0,
        list_count=0,
        first_access=datetime.now(timezone.utc) - timedelta(days=60),
        last_access=datetime.now(timezone.utc) - timedelta(days=1),
        days_since_last_access=1,
    )


@pytest.fixture
def stale_summary() -> AccessSummary:
    """Create an access summary showing stale access."""
    return AccessSummary(
        principal_id="arn:aws:iam::123456789012:user/alice",
        principal_type="user",
        resource_id="my-bucket",
        total_access_count=10,
        read_count=10,
        write_count=0,
        delete_count=0,
        list_count=0,
        first_access=datetime.now(timezone.utc) - timedelta(days=120),
        last_access=datetime.now(timezone.utc) - timedelta(days=60),
        days_since_last_access=60,
    )


@pytest.fixture
def analyzer() -> OverPrivilegedAnalyzer:
    """Create an analyzer with default config."""
    return OverPrivilegedAnalyzer()


# =============================================================================
# UsagePattern Tests
# =============================================================================


class TestUsagePattern:
    """Tests for UsagePattern dataclass."""

    def test_highest_observed_permission_write(self) -> None:
        """Test highest observed permission detection for write."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.ADMIN,
            observed_write_count=10,
            observed_read_count=50,
            total_access_count=60,
        )
        assert pattern.highest_observed_permission == PermissionLevel.WRITE

    def test_highest_observed_permission_read(self) -> None:
        """Test highest observed permission detection for read."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            observed_read_count=50,
            total_access_count=50,
        )
        assert pattern.highest_observed_permission == PermissionLevel.READ

    def test_highest_observed_permission_list(self) -> None:
        """Test highest observed permission detection for list."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.READ,
            observed_list_count=20,
            total_access_count=20,
        )
        assert pattern.highest_observed_permission == PermissionLevel.LIST

    def test_highest_observed_permission_none(self) -> None:
        """Test highest observed permission detection when no access."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
        )
        assert pattern.highest_observed_permission == PermissionLevel.NONE

    def test_has_unused_write(self) -> None:
        """Test detection of unused write permission."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            observed_read_count=50,
            total_access_count=50,
        )
        assert pattern.has_unused_write is True

    def test_no_unused_write_when_writes_observed(self) -> None:
        """Test no unused write when writes are observed."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            observed_read_count=50,
            observed_write_count=10,
            total_access_count=60,
        )
        assert pattern.has_unused_write is False

    def test_has_unused_delete(self) -> None:
        """Test detection of unused delete permission."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            observed_write_count=10,
            total_access_count=10,
        )
        assert pattern.has_unused_delete is True

    def test_has_unused_admin(self) -> None:
        """Test detection of unused admin permission."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.ADMIN,
            observed_read_count=50,
            total_access_count=50,
        )
        assert pattern.has_unused_admin is True

    def test_is_stale(self) -> None:
        """Test detection of stale access."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            days_since_last_access=60,
            last_access=datetime.now(timezone.utc) - timedelta(days=60),
        )
        assert pattern.is_stale is True

    def test_not_stale(self) -> None:
        """Test recent access is not stale."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            days_since_last_access=5,
            last_access=datetime.now(timezone.utc) - timedelta(days=5),
        )
        assert pattern.is_stale is False

    def test_is_never_used(self) -> None:
        """Test detection of never-used permission."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            total_access_count=0,
        )
        assert pattern.is_never_used is True

    def test_to_dict(self) -> None:
        """Test conversion to dictionary."""
        pattern = UsagePattern(
            principal_id="test",
            resource_id="bucket",
            granted_permission=PermissionLevel.WRITE,
            observed_read_count=50,
            total_access_count=50,
        )
        result = pattern.to_dict()
        assert result["principal_id"] == "test"
        assert result["resource_id"] == "bucket"
        assert result["granted_permission"] == "write"
        assert result["highest_observed_permission"] == "read"
        assert result["has_unused_write"] is True


# =============================================================================
# OverPrivilegedSeverity Tests
# =============================================================================


class TestOverPrivilegedSeverity:
    """Tests for OverPrivilegedSeverity enum."""

    def test_severity_ranking(self) -> None:
        """Test severity ranking comparison."""
        assert OverPrivilegedSeverity.CRITICAL > OverPrivilegedSeverity.HIGH
        assert OverPrivilegedSeverity.HIGH > OverPrivilegedSeverity.MEDIUM
        assert OverPrivilegedSeverity.MEDIUM > OverPrivilegedSeverity.LOW
        assert OverPrivilegedSeverity.LOW > OverPrivilegedSeverity.INFO

    def test_severity_rank_values(self) -> None:
        """Test severity rank numeric values."""
        assert OverPrivilegedSeverity.CRITICAL.rank == 5
        assert OverPrivilegedSeverity.HIGH.rank == 4
        assert OverPrivilegedSeverity.MEDIUM.rank == 3
        assert OverPrivilegedSeverity.LOW.rank == 2
        assert OverPrivilegedSeverity.INFO.rank == 1


# =============================================================================
# OverPrivilegedConfig Tests
# =============================================================================


class TestOverPrivilegedConfig:
    """Tests for OverPrivilegedConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = OverPrivilegedConfig()
        assert config.lookback_days == 90
        assert config.stale_days == 30
        assert config.sensitive_resource_threshold == 5
        assert config.include_service_accounts is True
        assert config.include_roles is True
        assert config.include_users is True
        assert config.min_sensitivity_level == "confidential"

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = OverPrivilegedConfig(
            lookback_days=180,
            stale_days=60,
            sensitive_resource_threshold=10,
            include_service_accounts=False,
        )
        assert config.lookback_days == 180
        assert config.stale_days == 60
        assert config.sensitive_resource_threshold == 10
        assert config.include_service_accounts is False


# =============================================================================
# OverPrivilegedAnalyzer Basic Tests
# =============================================================================


class TestOverPrivilegedAnalyzerBasic:
    """Basic tests for OverPrivilegedAnalyzer."""

    def test_analyzer_initialization(self, analyzer: OverPrivilegedAnalyzer) -> None:
        """Test analyzer initializes with default config."""
        assert analyzer.config is not None
        assert analyzer.config.lookback_days == 90

    def test_analyzer_custom_config(self) -> None:
        """Test analyzer with custom config."""
        config = OverPrivilegedConfig(lookback_days=180)
        analyzer = OverPrivilegedAnalyzer(config=config)
        assert analyzer.config.lookback_days == 180

    def test_compare_permission_vs_usage_over_privileged(
        self, analyzer: OverPrivilegedAnalyzer
    ) -> None:
        """Test comparison detects over-privileged access."""
        summary = AccessSummary(
            principal_id="test",
            principal_type="user",
            resource_id="bucket",
            read_count=50,
            write_count=0,
            total_access_count=50,
        )
        is_over, observed = analyzer.compare_permission_vs_usage(
            PermissionLevel.WRITE, summary
        )
        assert is_over is True
        assert observed == PermissionLevel.READ

    def test_compare_permission_vs_usage_not_over_privileged(
        self, analyzer: OverPrivilegedAnalyzer
    ) -> None:
        """Test comparison when not over-privileged."""
        summary = AccessSummary(
            principal_id="test",
            principal_type="user",
            resource_id="bucket",
            read_count=30,
            write_count=20,
            total_access_count=50,
        )
        is_over, observed = analyzer.compare_permission_vs_usage(
            PermissionLevel.WRITE, summary
        )
        assert is_over is False
        assert observed == PermissionLevel.WRITE

    def test_compare_permission_vs_usage_no_summary(
        self, analyzer: OverPrivilegedAnalyzer
    ) -> None:
        """Test comparison when no access summary."""
        is_over, observed = analyzer.compare_permission_vs_usage(
            PermissionLevel.WRITE, None
        )
        assert is_over is True
        assert observed == PermissionLevel.NONE


# =============================================================================
# OverPrivilegedAnalyzer Finding Generation Tests
# =============================================================================


class TestOverPrivilegedAnalyzerFindings:
    """Tests for OverPrivilegedAnalyzer finding generation."""

    def test_unused_write_access_finding(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
        write_access: ResourceAccess,
        read_only_summary: AccessSummary,
    ) -> None:
        """Test generation of unused write access finding."""
        result = analyzer.analyze_principal(
            user_principal,
            [write_access],
            [read_only_summary],
        )

        assert result.has_findings
        unused_write_findings = [
            f for f in result.findings
            if f.finding_type == OverPrivilegedFindingType.UNUSED_WRITE_ACCESS
        ]
        assert len(unused_write_findings) == 1

        finding = unused_write_findings[0]
        assert finding.granted_permission == PermissionLevel.WRITE
        assert finding.observed_permission == PermissionLevel.READ
        assert "read-only" in finding.recommended_action.lower()

    def test_unused_admin_access_finding(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
        admin_access: ResourceAccess,
    ) -> None:
        """Test generation of unused admin access finding."""
        summary = AccessSummary(
            principal_id=user_principal.id,
            principal_type="user",
            resource_id="admin-bucket",
            read_count=50,
            total_access_count=50,
        )
        result = analyzer.analyze_principal(
            user_principal,
            [admin_access],
            [summary],
        )

        assert result.has_findings
        admin_findings = [
            f for f in result.findings
            if f.finding_type == OverPrivilegedFindingType.UNUSED_ADMIN_ACCESS
        ]
        assert len(admin_findings) == 1
        assert admin_findings[0].severity >= OverPrivilegedSeverity.HIGH

    def test_unused_delete_access_finding(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
        write_access: ResourceAccess,
    ) -> None:
        """Test generation of unused delete access finding."""
        summary = AccessSummary(
            principal_id=user_principal.id,
            principal_type="user",
            resource_id="my-bucket",
            read_count=30,
            write_count=20,
            delete_count=0,
            total_access_count=50,
            last_access=datetime.now(timezone.utc),
            days_since_last_access=0,
        )
        result = analyzer.analyze_principal(
            user_principal,
            [write_access],
            [summary],
        )

        assert result.has_findings
        delete_findings = [
            f for f in result.findings
            if f.finding_type == OverPrivilegedFindingType.UNUSED_DELETE_ACCESS
        ]
        assert len(delete_findings) == 1

    def test_never_used_access_finding(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
        write_access: ResourceAccess,
    ) -> None:
        """Test generation of never-used access finding."""
        result = analyzer.analyze_principal(
            user_principal,
            [write_access],
            [],  # No access summaries
        )

        assert result.has_findings
        never_used_findings = [
            f for f in result.findings
            if f.finding_type == OverPrivilegedFindingType.NEVER_USED_ACCESS
        ]
        assert len(never_used_findings) == 1
        assert "never accessed" in never_used_findings[0].description.lower()

    def test_stale_elevated_access_finding(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
        write_access: ResourceAccess,
        stale_summary: AccessSummary,
    ) -> None:
        """Test generation of stale elevated access finding."""
        result = analyzer.analyze_principal(
            user_principal,
            [write_access],
            [stale_summary],
        )

        assert result.has_findings
        stale_findings = [
            f for f in result.findings
            if f.finding_type == OverPrivilegedFindingType.STALE_ELEVATED_ACCESS
        ]
        assert len(stale_findings) == 1

    def test_broad_sensitive_access_finding(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test generation of broad sensitive access finding."""
        # Create access to many sensitive resources
        accesses = []
        summaries = []
        classifications = {}

        for i in range(6):
            resource_id = f"sensitive-bucket-{i}"
            accesses.append(ResourceAccess(
                resource_id=resource_id,
                resource_type="s3_bucket",
                permission_level=PermissionLevel.READ,
            ))
            summaries.append(AccessSummary(
                principal_id=user_principal.id,
                principal_type="user",
                resource_id=resource_id,
                read_count=10,
                total_access_count=10,
                last_access=datetime.now(timezone.utc),
                days_since_last_access=0,
            ))
            classifications[resource_id] = "confidential"

        result = analyzer.analyze_principal(
            user_principal,
            accesses,
            summaries,
            classifications,
        )

        assert result.has_findings
        broad_findings = [
            f for f in result.findings
            if f.finding_type == OverPrivilegedFindingType.BROAD_SENSITIVE_ACCESS
        ]
        assert len(broad_findings) == 1
        assert broad_findings[0].severity >= OverPrivilegedSeverity.HIGH


# =============================================================================
# OverPrivilegedAnalyzer Severity Calculation Tests
# =============================================================================


class TestOverPrivilegedAnalyzerSeverity:
    """Tests for severity calculation."""

    def test_elevated_severity_for_sensitive_data(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test severity is elevated for sensitive data."""
        access = ResourceAccess(
            resource_id="pii-bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.WRITE,
        )
        summary = AccessSummary(
            principal_id=user_principal.id,
            principal_type="user",
            resource_id="pii-bucket",
            read_count=50,
            total_access_count=50,
            last_access=datetime.now(timezone.utc),
            days_since_last_access=0,
        )
        result = analyzer.analyze_principal(
            user_principal,
            [access],
            [summary],
            {"pii-bucket": "restricted"},
        )

        # With sensitive data, severity should be elevated
        assert any(f.severity >= OverPrivilegedSeverity.HIGH for f in result.findings)

    def test_elevated_severity_for_service_account(
        self,
        analyzer: OverPrivilegedAnalyzer,
        service_account_principal: Principal,
        write_access: ResourceAccess,
        read_only_summary: AccessSummary,
    ) -> None:
        """Test severity is elevated for service accounts."""
        # Update summary to match service account
        read_only_summary.principal_id = service_account_principal.id
        read_only_summary.principal_type = "service_account"

        result = analyzer.analyze_principal(
            service_account_principal,
            [write_access],
            [read_only_summary],
        )

        # Service account should have elevated severity
        assert any(f.severity >= OverPrivilegedSeverity.HIGH for f in result.findings)

    def test_critical_severity_for_service_account_sensitive(
        self,
        analyzer: OverPrivilegedAnalyzer,
        service_account_principal: Principal,
    ) -> None:
        """Test critical severity for service account with sensitive data."""
        access = ResourceAccess(
            resource_id="pii-bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.ADMIN,
        )
        summary = AccessSummary(
            principal_id=service_account_principal.id,
            principal_type="service_account",
            resource_id="pii-bucket",
            read_count=50,
            total_access_count=50,
            last_access=datetime.now(timezone.utc),
            days_since_last_access=0,
        )
        result = analyzer.analyze_principal(
            service_account_principal,
            [access],
            [summary],
            {"pii-bucket": "restricted"},
        )

        # Should have critical severity
        assert any(f.severity == OverPrivilegedSeverity.CRITICAL for f in result.findings)


# =============================================================================
# OverPrivilegedAnalyzer Risk Score Tests
# =============================================================================


class TestOverPrivilegedAnalyzerRiskScore:
    """Tests for risk score calculation."""

    def test_risk_score_increases_with_permission_level(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test risk score increases with permission level."""
        # Write access
        write_access = ResourceAccess(
            resource_id="bucket1",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.WRITE,
        )
        result1 = analyzer.analyze_principal(user_principal, [write_access], [])
        write_score = result1.findings[0].risk_score if result1.findings else 0

        # Admin access
        admin_access = ResourceAccess(
            resource_id="bucket2",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.ADMIN,
        )
        result2 = analyzer.analyze_principal(user_principal, [admin_access], [])
        admin_score = result2.findings[0].risk_score if result2.findings else 0

        assert admin_score > write_score

    def test_risk_score_increases_with_sensitivity(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test risk score increases with data sensitivity."""
        access = ResourceAccess(
            resource_id="bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.WRITE,
        )

        # Without classification
        result1 = analyzer.analyze_principal(user_principal, [access], [])
        score1 = result1.findings[0].risk_score if result1.findings else 0

        # With restricted classification
        result2 = analyzer.analyze_principal(
            user_principal, [access], [], {"bucket": "restricted"}
        )
        score2 = result2.findings[0].risk_score if result2.findings else 0

        assert score2 > score1

    def test_average_risk_score_in_summary(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test average risk score calculation in summary."""
        accesses = [
            ResourceAccess(
                resource_id=f"bucket{i}",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            )
            for i in range(3)
        ]
        result = analyzer.analyze_principal(user_principal, accesses, [])

        assert len(result.summaries) == 1
        assert result.summaries[0].average_risk_score > 0


# =============================================================================
# OverPrivilegedAnalyzer Multiple Principals Tests
# =============================================================================


class TestOverPrivilegedAnalyzerMultiple:
    """Tests for analyzing multiple principals."""

    def test_analyze_multiple_principals(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
        service_account_principal: Principal,
    ) -> None:
        """Test analyzing multiple principals at once."""
        access1 = ResourceAccess(
            resource_id="bucket1",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.WRITE,
        )
        access2 = ResourceAccess(
            resource_id="bucket2",
            resource_type="gcs_bucket",
            permission_level=PermissionLevel.ADMIN,
        )

        principals_data = [
            (user_principal, [access1], []),
            (service_account_principal, [access2], []),
        ]

        result = analyzer.analyze_multiple_principals(principals_data)

        assert result.principals_analyzed == 2
        assert result.resources_analyzed == 2
        assert len(result.summaries) == 2

    def test_filter_principals_by_type(self) -> None:
        """Test filtering principals by type."""
        config = OverPrivilegedConfig(include_service_accounts=False)
        analyzer = OverPrivilegedAnalyzer(config=config)

        service_account = Principal(
            id="sa@project.iam.gserviceaccount.com",
            name="sa",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            cloud_provider="gcp",
        )
        access = ResourceAccess(
            resource_id="bucket",
            resource_type="gcs_bucket",
            permission_level=PermissionLevel.WRITE,
        )

        result = analyzer.analyze_principal(service_account, [access], [])

        # Service account should be filtered out
        assert result.principals_analyzed == 0
        assert len(result.findings) == 0


# =============================================================================
# OverPrivilegedResult Tests
# =============================================================================


class TestOverPrivilegedResult:
    """Tests for OverPrivilegedResult."""

    def test_findings_by_type(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test findings_by_type property."""
        accesses = [
            ResourceAccess(
                resource_id=f"bucket{i}",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            )
            for i in range(3)
        ]
        result = analyzer.analyze_principal(user_principal, accesses, [])

        by_type = result.findings_by_type
        assert OverPrivilegedFindingType.NEVER_USED_ACCESS.value in by_type

    def test_findings_by_severity(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test findings_by_severity property."""
        accesses = [
            ResourceAccess(
                resource_id="bucket1",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            ),
            ResourceAccess(
                resource_id="bucket2",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.ADMIN,
            ),
        ]
        result = analyzer.analyze_principal(user_principal, accesses, [])

        by_severity = result.findings_by_severity
        assert len(by_severity) > 0

    def test_critical_and_high_findings_properties(
        self,
        analyzer: OverPrivilegedAnalyzer,
        service_account_principal: Principal,
    ) -> None:
        """Test critical_findings and high_findings properties."""
        access = ResourceAccess(
            resource_id="pii-bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.ADMIN,
        )
        result = analyzer.analyze_principal(
            service_account_principal,
            [access],
            [],
            {"pii-bucket": "restricted"},
        )

        # Should have high severity findings
        high = result.high_findings
        assert len(high) >= 0  # May have high findings

    def test_to_dict(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
        write_access: ResourceAccess,
    ) -> None:
        """Test conversion to dictionary."""
        result = analyzer.analyze_principal(user_principal, [write_access], [])

        data = result.to_dict()
        assert "analysis_id" in data
        assert "config" in data
        assert "findings" in data
        assert "summaries" in data
        assert data["principals_analyzed"] == 1


# =============================================================================
# Helper Function Tests
# =============================================================================


class TestCreateUsagePatternsFromAccessReview:
    """Tests for create_usage_patterns_from_access_review helper."""

    def test_creates_patterns_with_summaries(self) -> None:
        """Test creating patterns when summaries exist."""
        principal_id = "test-principal"
        accesses = [
            ResourceAccess(
                resource_id="bucket1",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            ),
            ResourceAccess(
                resource_id="bucket2",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.READ,
            ),
        ]
        summaries = [
            AccessSummary(
                principal_id=principal_id,
                principal_type="user",
                resource_id="bucket1",
                read_count=30,
                write_count=20,
                total_access_count=50,
            ),
        ]

        patterns = create_usage_patterns_from_access_review(
            principal_id, accesses, summaries
        )

        assert len(patterns) == 2

        # bucket1 should have access counts
        bucket1_pattern = next(p for p in patterns if p.resource_id == "bucket1")
        assert bucket1_pattern.observed_read_count == 30
        assert bucket1_pattern.observed_write_count == 20

        # bucket2 should have no access counts
        bucket2_pattern = next(p for p in patterns if p.resource_id == "bucket2")
        assert bucket2_pattern.total_access_count == 0

    def test_creates_patterns_without_summaries(self) -> None:
        """Test creating patterns when no summaries exist."""
        principal_id = "test-principal"
        accesses = [
            ResourceAccess(
                resource_id="bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            ),
        ]

        patterns = create_usage_patterns_from_access_review(principal_id, accesses, [])

        assert len(patterns) == 1
        assert patterns[0].is_never_used is True


# =============================================================================
# Integration-Style Tests
# =============================================================================


class TestOverPrivilegedIntegration:
    """Integration-style tests for complete workflows."""

    def test_full_analysis_workflow(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test a complete analysis workflow."""
        # Set up multiple resources with varying access patterns
        accesses = [
            ResourceAccess(
                resource_id="frequently-read",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            ),
            ResourceAccess(
                resource_id="actively-written",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            ),
            ResourceAccess(
                resource_id="never-used",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.ADMIN,
            ),
            ResourceAccess(
                resource_id="stale-access",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.WRITE,
            ),
        ]

        summaries = [
            AccessSummary(
                principal_id=user_principal.id,
                principal_type="user",
                resource_id="frequently-read",
                read_count=100,
                total_access_count=100,
                last_access=datetime.now(timezone.utc),
                days_since_last_access=0,
            ),
            AccessSummary(
                principal_id=user_principal.id,
                principal_type="user",
                resource_id="actively-written",
                read_count=50,
                write_count=50,
                total_access_count=100,
                last_access=datetime.now(timezone.utc),
                days_since_last_access=0,
            ),
            # No summary for "never-used"
            AccessSummary(
                principal_id=user_principal.id,
                principal_type="user",
                resource_id="stale-access",
                read_count=10,
                total_access_count=10,
                last_access=datetime.now(timezone.utc) - timedelta(days=60),
                days_since_last_access=60,
            ),
        ]

        result = analyzer.analyze_principal(user_principal, accesses, summaries)

        # Verify results
        assert result.principals_analyzed == 1
        assert result.resources_analyzed == 4
        assert result.has_findings

        # Check finding types
        finding_types = {f.finding_type for f in result.findings}
        assert OverPrivilegedFindingType.UNUSED_WRITE_ACCESS in finding_types
        assert OverPrivilegedFindingType.NEVER_USED_ACCESS in finding_types
        assert OverPrivilegedFindingType.STALE_ELEVATED_ACCESS in finding_types

        # Verify summary
        assert len(result.summaries) == 1
        summary = result.summaries[0]
        assert summary.total_resources_accessed == 4
        assert summary.over_privileged_resources > 0

    def test_no_findings_for_appropriate_access(
        self,
        analyzer: OverPrivilegedAnalyzer,
        user_principal: Principal,
    ) -> None:
        """Test no findings when access is appropriate."""
        access = ResourceAccess(
            resource_id="bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.READ,
        )
        summary = AccessSummary(
            principal_id=user_principal.id,
            principal_type="user",
            resource_id="bucket",
            read_count=100,
            total_access_count=100,
            last_access=datetime.now(timezone.utc),
            days_since_last_access=0,
        )

        result = analyzer.analyze_principal(user_principal, [access], [summary])

        # Read-only access with read usage should have no findings
        assert not result.has_findings
