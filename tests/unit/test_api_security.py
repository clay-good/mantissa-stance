"""
Unit tests for API Security Testing module.

Tests cover:
- API security data classes (models)
- API endpoint discovery
- API security analyzer
- Authentication tester
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from stance.models import Asset


# =============================================================================
# Model Tests
# =============================================================================


class TestAPIProtocol:
    """Tests for APIProtocol enum."""

    def test_protocol_values(self):
        """Test that all protocol values are defined."""
        from stance.api_security.models import APIProtocol

        assert APIProtocol.REST.value == "rest"
        assert APIProtocol.GRAPHQL.value == "graphql"
        assert APIProtocol.WEBSOCKET.value == "websocket"
        assert APIProtocol.GRPC.value == "grpc"
        assert APIProtocol.SOAP.value == "soap"
        assert APIProtocol.UNKNOWN.value == "unknown"


class TestAuthenticationType:
    """Tests for AuthenticationType enum."""

    def test_authentication_type_values(self):
        """Test that all authentication types are defined."""
        from stance.api_security.models import AuthenticationType

        assert AuthenticationType.NONE.value == "none"
        assert AuthenticationType.API_KEY.value == "api_key"
        assert AuthenticationType.BASIC.value == "basic"
        assert AuthenticationType.BEARER.value == "bearer"
        assert AuthenticationType.JWT.value == "jwt"
        assert AuthenticationType.OAUTH2.value == "oauth2"
        assert AuthenticationType.IAM.value == "iam"
        assert AuthenticationType.COGNITO.value == "cognito"
        assert AuthenticationType.LAMBDA.value == "lambda"
        assert AuthenticationType.MTLS.value == "mtls"
        assert AuthenticationType.CUSTOM.value == "custom"
        assert AuthenticationType.UNKNOWN.value == "unknown"


class TestAPISecuritySeverity:
    """Tests for APISecuritySeverity enum."""

    def test_severity_values(self):
        """Test that all severity values are defined."""
        from stance.api_security.models import APISecuritySeverity

        assert APISecuritySeverity.CRITICAL.value == "critical"
        assert APISecuritySeverity.HIGH.value == "high"
        assert APISecuritySeverity.MEDIUM.value == "medium"
        assert APISecuritySeverity.LOW.value == "low"
        assert APISecuritySeverity.INFO.value == "info"


class TestAPISecurityCategory:
    """Tests for APISecurityCategory enum."""

    def test_category_values(self):
        """Test that all category values are defined."""
        from stance.api_security.models import APISecurityCategory

        assert APISecurityCategory.AUTHENTICATION.value == "authentication"
        assert APISecurityCategory.AUTHORIZATION.value == "authorization"
        assert APISecurityCategory.INPUT_VALIDATION.value == "input_validation"
        assert APISecurityCategory.RATE_LIMITING.value == "rate_limiting"
        assert APISecurityCategory.ENCRYPTION.value == "encryption"
        assert APISecurityCategory.CORS.value == "cors"
        assert APISecurityCategory.LOGGING.value == "logging"
        assert APISecurityCategory.DOCUMENTATION.value == "documentation"
        assert APISecurityCategory.EXPOSURE.value == "exposure"
        assert APISecurityCategory.CONFIGURATION.value == "configuration"


class TestAPIEndpoint:
    """Tests for APIEndpoint dataclass."""

    def test_basic_endpoint(self):
        """Test basic endpoint creation."""
        from stance.api_security.models import APIEndpoint, APIProtocol

        endpoint = APIEndpoint(
            id="api-123",
            name="Test API",
            url="https://api.example.com",
        )

        assert endpoint.id == "api-123"
        assert endpoint.name == "Test API"
        assert endpoint.url == "https://api.example.com"
        assert endpoint.protocol == APIProtocol.REST

    def test_endpoint_defaults(self):
        """Test endpoint default values."""
        from stance.api_security.models import (
            APIEndpoint,
            APIProtocol,
            AuthenticationType,
        )

        endpoint = APIEndpoint(id="api-1", name="Test")

        assert endpoint.protocol == APIProtocol.REST
        assert endpoint.authentication_type == AuthenticationType.UNKNOWN
        assert endpoint.authentication_required is True
        assert endpoint.is_public is False
        assert endpoint.has_waf is False
        assert endpoint.has_rate_limiting is False
        assert endpoint.cors_enabled is False
        assert endpoint.tls_enabled is True
        assert endpoint.access_logging_enabled is False

    def test_endpoint_to_dict(self):
        """Test endpoint serialization."""
        from stance.api_security.models import (
            APIEndpoint,
            APIProtocol,
            AuthenticationType,
        )

        endpoint = APIEndpoint(
            id="api-123",
            name="Test API",
            url="https://api.example.com",
            protocol=APIProtocol.REST,
            authentication_type=AuthenticationType.JWT,
            is_public=True,
            has_rate_limiting=True,
            rate_limit=1000,
        )

        result = endpoint.to_dict()

        assert result["id"] == "api-123"
        assert result["name"] == "Test API"
        assert result["protocol"] == "rest"
        assert result["authentication"]["type"] == "jwt"
        assert result["security"]["is_public"] is True
        assert result["security"]["has_rate_limiting"] is True
        assert result["security"]["rate_limit"] == 1000


class TestAPISecurityFinding:
    """Tests for APISecurityFinding dataclass."""

    def test_basic_finding(self):
        """Test basic finding creation."""
        from stance.api_security.models import (
            APISecurityFinding,
            APISecuritySeverity,
            APISecurityCategory,
        )

        finding = APISecurityFinding(
            id="finding-1",
            title="No Authentication",
            description="API has no authentication configured",
            severity=APISecuritySeverity.CRITICAL,
            category=APISecurityCategory.AUTHENTICATION,
            api_endpoint_id="api-123",
            api_endpoint_name="Test API",
        )

        assert finding.id == "finding-1"
        assert finding.title == "No Authentication"
        assert finding.severity == APISecuritySeverity.CRITICAL
        assert finding.category == APISecurityCategory.AUTHENTICATION

    def test_finding_to_dict(self):
        """Test finding serialization."""
        from stance.api_security.models import (
            APISecurityFinding,
            APISecuritySeverity,
            APISecurityCategory,
        )

        finding = APISecurityFinding(
            id="finding-1",
            title="No Authentication",
            description="API has no authentication configured",
            severity=APISecuritySeverity.CRITICAL,
            category=APISecurityCategory.AUTHENTICATION,
            api_endpoint_id="api-123",
            api_endpoint_name="Test API",
            cwe_ids=["CWE-306"],
            owasp_ids=["API2:2023"],
        )

        result = finding.to_dict()

        assert result["id"] == "finding-1"
        assert result["severity"] == "critical"
        assert result["category"] == "authentication"
        assert result["cwe_ids"] == ["CWE-306"]
        assert result["owasp_ids"] == ["API2:2023"]


# =============================================================================
# Discoverer Tests
# =============================================================================


class TestAPIInventory:
    """Tests for APIInventory class."""

    def test_empty_inventory(self):
        """Test empty inventory creation."""
        from stance.api_security.discoverer import APIInventory

        inventory = APIInventory()

        assert inventory.total_endpoints == 0
        assert inventory.public_endpoints == 0
        assert inventory.authenticated_endpoints == 0
        assert len(inventory.endpoints) == 0

    def test_add_endpoint(self):
        """Test adding endpoints to inventory."""
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, AuthenticationType

        inventory = APIInventory()
        endpoint = APIEndpoint(
            id="api-1",
            name="Test API",
            is_public=True,
            authentication_required=True,
            authentication_type=AuthenticationType.JWT,
        )

        inventory.add_endpoint(endpoint)

        assert inventory.total_endpoints == 1
        assert inventory.public_endpoints == 1
        assert inventory.authenticated_endpoints == 1
        assert inventory.unauthenticated_endpoints == 0

    def test_get_public_endpoints(self):
        """Test filtering public endpoints."""
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint

        inventory = APIInventory()
        inventory.add_endpoint(APIEndpoint(id="api-1", name="Public", is_public=True))
        inventory.add_endpoint(APIEndpoint(id="api-2", name="Private", is_public=False))

        public = inventory.get_public_endpoints()

        assert len(public) == 1
        assert public[0].id == "api-1"

    def test_get_unauthenticated_endpoints(self):
        """Test filtering unauthenticated endpoints."""
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint

        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(id="api-1", name="Auth", authentication_required=True)
        )
        inventory.add_endpoint(
            APIEndpoint(id="api-2", name="NoAuth", authentication_required=False)
        )

        unauth = inventory.get_unauthenticated_endpoints()

        assert len(unauth) == 1
        assert unauth[0].id == "api-2"

    def test_inventory_to_dict(self):
        """Test inventory serialization."""
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, APIProtocol

        inventory = APIInventory(sources=["cloud_assets"])
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="Test",
                cloud_provider="aws",
                protocol=APIProtocol.REST,
            )
        )

        result = inventory.to_dict()

        assert result["summary"]["total_endpoints"] == 1
        assert result["sources"] == ["cloud_assets"]
        assert result["by_provider"]["aws"] == 1
        assert result["by_protocol"]["rest"] == 1


class TestAPIDiscoverer:
    """Tests for APIDiscoverer class."""

    def test_discoverer_initialization(self):
        """Test discoverer creation."""
        from stance.api_security.discoverer import APIDiscoverer

        discoverer = APIDiscoverer()
        assert discoverer is not None

    def test_discover_from_assets_empty(self):
        """Test discovery with no assets."""
        from stance.api_security.discoverer import APIDiscoverer

        discoverer = APIDiscoverer()
        inventory = discoverer.discover_from_assets([])

        assert inventory.total_endpoints == 0
        assert "cloud_assets" in inventory.sources

    def test_discover_aws_rest_api(self):
        """Test discovery of AWS REST API."""
        from stance.api_security.discoverer import APIDiscoverer

        discoverer = APIDiscoverer()

        asset = Asset(
            id="asset-1",
            cloud_provider="aws",
            name="test-api",
            resource_type="aws_apigateway_rest_api",
            account_id="123456789012",
            region="us-east-1",
            raw_config={
                "api_id": "abc123",
                "api_name": "Test API",
                "authorizers": [{"type": "COGNITO_USER_POOLS"}],
                "authorizer_types": ["COGNITO_USER_POOLS"],
                "stages": [{"stage_name": "prod", "has_access_logging": True}],
                "has_waf": True,
            },
        )

        inventory = discoverer.discover_from_assets([asset])

        assert inventory.total_endpoints == 1
        endpoint = inventory.endpoints[0]
        assert endpoint.cloud_provider == "aws"
        assert endpoint.has_waf is True
        assert endpoint.access_logging_enabled is True

    def test_discover_aws_http_api(self):
        """Test discovery of AWS HTTP API."""
        from stance.api_security.discoverer import APIDiscoverer
        from stance.api_security.models import AuthenticationType

        discoverer = APIDiscoverer()

        asset = Asset(
            id="asset-2",
            cloud_provider="aws",
            name="http-api",
            resource_type="aws_apigateway_http_api",
            account_id="123456789012",
            region="us-west-2",
            raw_config={
                "api_name": "HTTP API",
                "api_type": "HTTP",
                "authorizers": [{"type": "JWT"}],
                "authorizer_types": ["JWT"],
                "has_cors": True,
                "cors_allow_origins": ["https://example.com"],
                "stages": [{"stage_name": "$default"}],
            },
        )

        inventory = discoverer.discover_from_assets([asset])

        assert inventory.total_endpoints == 1
        endpoint = inventory.endpoints[0]
        assert endpoint.authentication_type == AuthenticationType.JWT
        assert endpoint.cors_enabled is True

    def test_discover_from_openapi(self):
        """Test discovery from OpenAPI specification."""
        from stance.api_security.discoverer import APIDiscoverer
        from stance.api_security.models import AuthenticationType

        discoverer = APIDiscoverer()

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Pet Store API", "version": "1.0.0"},
            "servers": [{"url": "https://api.petstore.io"}],
            "paths": {
                "/pets": {"get": {}, "post": {}},
                "/pets/{id}": {"get": {}, "delete": {}},
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"}
                }
            },
            "security": [{"bearerAuth": []}],
        }

        inventory = discoverer.discover_from_openapi(spec)

        assert inventory.total_endpoints == 1
        endpoint = inventory.endpoints[0]
        assert endpoint.name == "Pet Store API"
        assert endpoint.authentication_type == AuthenticationType.BEARER
        assert endpoint.authentication_required is True
        assert endpoint.has_documentation is True
        assert "GET" in endpoint.http_methods
        assert "POST" in endpoint.http_methods

    def test_merge_inventories(self):
        """Test merging multiple inventories."""
        from stance.api_security.discoverer import APIDiscoverer, APIInventory
        from stance.api_security.models import APIEndpoint

        discoverer = APIDiscoverer()

        inv1 = APIInventory(sources=["source1"])
        inv1.add_endpoint(APIEndpoint(id="api-1", name="API 1"))

        inv2 = APIInventory(sources=["source2"])
        inv2.add_endpoint(APIEndpoint(id="api-2", name="API 2"))

        merged = discoverer.merge_inventories(inv1, inv2)

        assert merged.total_endpoints == 2
        assert "source1" in merged.sources
        assert "source2" in merged.sources

    def test_merge_inventories_deduplication(self):
        """Test that merging deduplicates by ID."""
        from stance.api_security.discoverer import APIDiscoverer, APIInventory
        from stance.api_security.models import APIEndpoint

        discoverer = APIDiscoverer()

        inv1 = APIInventory()
        inv1.add_endpoint(APIEndpoint(id="api-1", name="API 1"))

        inv2 = APIInventory()
        inv2.add_endpoint(APIEndpoint(id="api-1", name="API 1 Duplicate"))

        merged = discoverer.merge_inventories(inv1, inv2)

        assert merged.total_endpoints == 1


# =============================================================================
# Analyzer Tests
# =============================================================================


class TestAPISecurityReport:
    """Tests for APISecurityReport class."""

    def test_empty_report(self):
        """Test empty report creation."""
        from stance.api_security.analyzer import APISecurityReport
        from stance.api_security.models import APISecuritySeverity

        report = APISecurityReport()

        assert report.total_findings == 0
        assert report.has_critical_findings is False
        assert report.highest_severity == APISecuritySeverity.INFO

    def test_report_with_findings(self):
        """Test report with findings."""
        from stance.api_security.analyzer import APISecurityReport
        from stance.api_security.models import (
            APISecurityFinding,
            APISecuritySeverity,
            APISecurityCategory,
        )

        report = APISecurityReport()
        report.findings.append(
            APISecurityFinding(
                id="f1",
                title="Critical Finding",
                description="desc",
                severity=APISecuritySeverity.CRITICAL,
                category=APISecurityCategory.AUTHENTICATION,
                api_endpoint_id="api-1",
                api_endpoint_name="API",
            )
        )
        report.critical_count = 1
        report.total_findings = 1

        assert report.has_critical_findings is True
        assert report.highest_severity == APISecuritySeverity.CRITICAL

    def test_report_highest_severity(self):
        """Test highest severity calculation."""
        from stance.api_security.analyzer import APISecurityReport
        from stance.api_security.models import APISecuritySeverity

        report = APISecurityReport()
        report.medium_count = 2
        report.low_count = 1

        assert report.highest_severity == APISecuritySeverity.MEDIUM

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        from stance.api_security.analyzer import APISecurityReport
        from stance.api_security.models import (
            APISecurityFinding,
            APISecuritySeverity,
            APISecurityCategory,
        )

        report = APISecurityReport()
        report.findings = [
            APISecurityFinding(
                id="f1",
                title="High",
                description="",
                severity=APISecuritySeverity.HIGH,
                category=APISecurityCategory.AUTHENTICATION,
                api_endpoint_id="api-1",
                api_endpoint_name="API",
            ),
            APISecurityFinding(
                id="f2",
                title="Low",
                description="",
                severity=APISecuritySeverity.LOW,
                category=APISecurityCategory.LOGGING,
                api_endpoint_id="api-1",
                api_endpoint_name="API",
            ),
        ]

        high = report.get_findings_by_severity(APISecuritySeverity.HIGH)
        assert len(high) == 1
        assert high[0].id == "f1"

    def test_report_to_dict(self):
        """Test report serialization."""
        from stance.api_security.analyzer import APISecurityReport

        report = APISecurityReport(
            total_endpoints=5,
            total_findings=3,
            critical_count=1,
            high_count=2,
        )

        result = report.to_dict()

        assert result["summary"]["total_endpoints"] == 5
        assert result["summary"]["total_findings"] == 3
        assert result["severity_breakdown"]["critical"] == 1
        assert result["severity_breakdown"]["high"] == 2


class TestAPISecurityAnalyzer:
    """Tests for APISecurityAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test analyzer creation."""
        from stance.api_security.analyzer import APISecurityAnalyzer

        analyzer = APISecurityAnalyzer()
        assert len(analyzer._checks) == 10

    def test_analyze_empty_inventory(self):
        """Test analyzing empty inventory."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()

        report = analyzer.analyze(inventory)

        assert report.total_endpoints == 0
        assert report.total_findings == 0

    def test_check_no_authentication(self):
        """Test detection of endpoints without authentication."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, AuthenticationType

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="NoAuth API",
                authentication_required=False,
                authentication_type=AuthenticationType.NONE,
                is_public=True,
            )
        )

        report = analyzer.analyze(inventory)

        # Should find no auth issue (critical for public)
        auth_findings = [
            f for f in report.findings if "Authentication" in f.title
        ]
        assert len(auth_findings) >= 1
        assert report.critical_count >= 1

    def test_check_cors_misconfiguration(self):
        """Test detection of CORS misconfigurations."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, APISecuritySeverity

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="Bad CORS API",
                cors_enabled=True,
                cors_allow_all_origins=True,
                cors_allow_credentials=True,
            )
        )

        report = analyzer.analyze(inventory)

        cors_findings = [f for f in report.findings if "CORS" in f.title]
        assert len(cors_findings) >= 1
        # Wildcard + credentials is critical
        critical_cors = [
            f for f in cors_findings if f.severity == APISecuritySeverity.CRITICAL
        ]
        assert len(critical_cors) >= 1

    def test_check_no_rate_limiting(self):
        """Test detection of missing rate limiting."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, APISecurityCategory

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="No Rate Limit API",
                has_rate_limiting=False,
                is_public=True,
            )
        )

        report = analyzer.analyze(inventory)

        rate_findings = [
            f
            for f in report.findings
            if f.category == APISecurityCategory.RATE_LIMITING
        ]
        assert len(rate_findings) >= 1

    def test_check_no_waf(self):
        """Test detection of missing WAF protection."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="No WAF API",
                is_public=True,
                has_waf=False,
            )
        )

        report = analyzer.analyze(inventory)

        waf_findings = [f for f in report.findings if "WAF" in f.title]
        assert len(waf_findings) >= 1

    def test_check_no_logging(self):
        """Test detection of missing logging."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, APISecurityCategory

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="No Logging API",
                access_logging_enabled=False,
            )
        )

        report = analyzer.analyze(inventory)

        logging_findings = [
            f for f in report.findings if f.category == APISecurityCategory.LOGGING
        ]
        assert len(logging_findings) >= 1

    def test_check_weak_tls(self):
        """Test detection of weak TLS configuration."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, APISecurityCategory

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="Weak TLS API",
                minimum_tls_version="TLS_1_0",
            )
        )

        report = analyzer.analyze(inventory)

        encryption_findings = [
            f for f in report.findings if f.category == APISecurityCategory.ENCRYPTION
        ]
        assert len(encryption_findings) >= 1

    def test_secure_api_minimal_findings(self):
        """Test that well-configured APIs have minimal findings."""
        from stance.api_security.analyzer import APISecurityAnalyzer
        from stance.api_security.discoverer import APIInventory
        from stance.api_security.models import APIEndpoint, AuthenticationType

        analyzer = APISecurityAnalyzer()
        inventory = APIInventory()
        inventory.add_endpoint(
            APIEndpoint(
                id="api-1",
                name="Secure API",
                authentication_required=True,
                authentication_type=AuthenticationType.JWT,
                authorizers=[{"type": "JWT"}],
                is_public=False,
                has_waf=True,
                has_rate_limiting=True,
                access_logging_enabled=True,
                has_documentation=True,
                minimum_tls_version="TLS_1_2",
            )
        )

        report = analyzer.analyze(inventory)

        # Secure API should have no critical or high findings
        assert report.critical_count == 0
        assert report.high_count == 0


# =============================================================================
# Authentication Tester Tests
# =============================================================================


class TestAuthTestStatus:
    """Tests for AuthTestStatus enum."""

    def test_status_values(self):
        """Test that all status values are defined."""
        from stance.api_security.auth_tester import AuthTestStatus

        assert AuthTestStatus.PASSED.value == "passed"
        assert AuthTestStatus.FAILED.value == "failed"
        assert AuthTestStatus.WARNING.value == "warning"
        assert AuthTestStatus.SKIPPED.value == "skipped"
        assert AuthTestStatus.ERROR.value == "error"


class TestAuthTestResult:
    """Tests for AuthTestResult class."""

    def test_basic_result(self):
        """Test basic result creation."""
        from stance.api_security.auth_tester import AuthTestResult, AuthTestStatus

        result = AuthTestResult(
            test_name="test_auth",
            status=AuthTestStatus.PASSED,
            message="Authentication passed",
        )

        assert result.test_name == "test_auth"
        assert result.status == AuthTestStatus.PASSED

    def test_result_to_dict(self):
        """Test result serialization."""
        from stance.api_security.auth_tester import AuthTestResult, AuthTestStatus
        from stance.api_security.models import APISecuritySeverity

        result = AuthTestResult(
            test_name="test_auth",
            status=AuthTestStatus.FAILED,
            message="No authentication",
            severity=APISecuritySeverity.CRITICAL,
            recommendation="Add authentication",
        )

        data = result.to_dict()

        assert data["test_name"] == "test_auth"
        assert data["status"] == "failed"
        assert data["severity"] == "critical"
        assert data["recommendation"] == "Add authentication"


class TestAuthTestReport:
    """Tests for AuthTestReport class."""

    def test_empty_report(self):
        """Test empty report creation."""
        from stance.api_security.auth_tester import AuthTestReport, AuthTestStatus

        report = AuthTestReport(
            endpoint_id="api-1",
            endpoint_name="Test API",
            authentication_type="jwt",
        )

        assert report.passed_count == 0
        assert report.failed_count == 0
        assert report.overall_status == AuthTestStatus.PASSED

    def test_add_result(self):
        """Test adding results to report."""
        from stance.api_security.auth_tester import (
            AuthTestReport,
            AuthTestResult,
            AuthTestStatus,
        )

        report = AuthTestReport(
            endpoint_id="api-1",
            endpoint_name="Test API",
            authentication_type="jwt",
        )

        report.add_result(
            AuthTestResult(
                test_name="test1",
                status=AuthTestStatus.PASSED,
                message="Passed",
            )
        )
        report.add_result(
            AuthTestResult(
                test_name="test2",
                status=AuthTestStatus.FAILED,
                message="Failed",
            )
        )

        assert report.passed_count == 1
        assert report.failed_count == 1
        assert report.overall_status == AuthTestStatus.FAILED

    def test_report_to_dict(self):
        """Test report serialization."""
        from stance.api_security.auth_tester import AuthTestReport

        report = AuthTestReport(
            endpoint_id="api-1",
            endpoint_name="Test API",
            authentication_type="jwt",
        )

        data = report.to_dict()

        assert data["endpoint_id"] == "api-1"
        assert data["authentication_type"] == "jwt"
        assert "summary" in data


class TestAuthenticationTester:
    """Tests for AuthenticationTester class."""

    def test_tester_initialization(self):
        """Test tester creation."""
        from stance.api_security.auth_tester import AuthenticationTester

        tester = AuthenticationTester()
        assert tester is not None

    def test_test_endpoint_with_auth(self):
        """Test endpoint with authentication configured."""
        from stance.api_security.auth_tester import (
            AuthenticationTester,
            AuthTestStatus,
        )
        from stance.api_security.models import APIEndpoint, AuthenticationType

        tester = AuthenticationTester()
        endpoint = APIEndpoint(
            id="api-1",
            name="Auth API",
            authentication_required=True,
            authentication_type=AuthenticationType.JWT,
            authorizers=[{"type": "JWT", "jwt_configuration": {"Issuer": "https://auth.example.com", "Audience": ["api"]}}],
        )

        report = tester.test_endpoint(endpoint)

        assert report.endpoint_id == "api-1"
        assert report.failed_count == 0
        auth_required = [r for r in report.results if r.test_name == "authentication_required"]
        assert len(auth_required) == 1
        assert auth_required[0].status == AuthTestStatus.PASSED

    def test_test_endpoint_without_auth(self):
        """Test endpoint without authentication."""
        from stance.api_security.auth_tester import (
            AuthenticationTester,
            AuthTestStatus,
        )
        from stance.api_security.models import APIEndpoint, AuthenticationType

        tester = AuthenticationTester()
        endpoint = APIEndpoint(
            id="api-1",
            name="NoAuth API",
            authentication_required=False,
            authentication_type=AuthenticationType.NONE,
            is_public=True,
        )

        report = tester.test_endpoint(endpoint)

        assert report.failed_count >= 1
        auth_required = [r for r in report.results if r.test_name == "authentication_required"]
        assert len(auth_required) == 1
        assert auth_required[0].status == AuthTestStatus.FAILED

    def test_test_iam_authentication(self):
        """Test IAM authentication validation."""
        from stance.api_security.auth_tester import (
            AuthenticationTester,
            AuthTestStatus,
        )
        from stance.api_security.models import APIEndpoint, AuthenticationType

        tester = AuthenticationTester()
        endpoint = APIEndpoint(
            id="api-1",
            name="IAM API",
            authentication_required=True,
            authentication_type=AuthenticationType.IAM,
        )

        report = tester.test_endpoint(endpoint)

        iam_results = [r for r in report.results if r.test_name == "iam_configuration"]
        assert len(iam_results) == 1
        assert iam_results[0].status == AuthTestStatus.PASSED

    def test_test_cognito_authentication(self):
        """Test Cognito authentication validation."""
        from stance.api_security.auth_tester import (
            AuthenticationTester,
            AuthTestStatus,
        )
        from stance.api_security.models import APIEndpoint, AuthenticationType

        tester = AuthenticationTester()
        endpoint = APIEndpoint(
            id="api-1",
            name="Cognito API",
            authentication_required=True,
            authentication_type=AuthenticationType.COGNITO,
            authorizers=[
                {
                    "type": "COGNITO_USER_POOLS",
                    "provider_arns": ["arn:aws:cognito-idp:us-east-1:123456789012:userpool/us-east-1_xxxxx"],
                }
            ],
        )

        report = tester.test_endpoint(endpoint)

        cognito_results = [r for r in report.results if r.test_name == "cognito_configuration"]
        assert len(cognito_results) == 1
        assert cognito_results[0].status == AuthTestStatus.PASSED

    def test_test_lambda_authorizer(self):
        """Test Lambda authorizer validation."""
        from stance.api_security.auth_tester import (
            AuthenticationTester,
            AuthTestStatus,
        )
        from stance.api_security.models import APIEndpoint, AuthenticationType

        tester = AuthenticationTester()
        endpoint = APIEndpoint(
            id="api-1",
            name="Lambda Auth API",
            authentication_required=True,
            authentication_type=AuthenticationType.LAMBDA,
            authorizers=[
                {
                    "type": "REQUEST",
                    "authorizer_uri": "arn:aws:lambda:us-east-1:123456789012:function:authorizer",
                }
            ],
        )

        report = tester.test_endpoint(endpoint)

        lambda_results = [r for r in report.results if r.test_name == "lambda_authorizer"]
        assert len(lambda_results) == 1
        assert lambda_results[0].status == AuthTestStatus.PASSED

    def test_test_jwt_without_issuer(self):
        """Test JWT configuration without issuer fails."""
        from stance.api_security.auth_tester import (
            AuthenticationTester,
            AuthTestStatus,
        )
        from stance.api_security.models import APIEndpoint, AuthenticationType

        tester = AuthenticationTester()
        # JWT config with audience but no issuer - triggers the no-issuer check
        endpoint = APIEndpoint(
            id="api-1",
            name="Bad JWT API",
            authentication_required=True,
            authentication_type=AuthenticationType.JWT,
            authorizers=[{"type": "JWT", "jwt_configuration": {"Audience": ["api"]}}],
        )

        report = tester.test_endpoint(endpoint)

        jwt_results = [r for r in report.results if r.test_name == "jwt_configuration"]
        assert len(jwt_results) == 1
        assert jwt_results[0].status == AuthTestStatus.FAILED


# =============================================================================
# Module Import Tests
# =============================================================================


class TestModuleExports:
    """Tests for module exports."""

    def test_all_exports_available(self):
        """Test that all expected exports are available."""
        from stance.api_security import (
            APIEndpoint,
            APISecurityFinding,
            APISecuritySeverity,
            AuthenticationType,
            APIProtocol,
            APISecurityCategory,
            APIDiscoverer,
            APIInventory,
            APISecurityAnalyzer,
            APISecurityReport,
            AuthenticationTester,
            AuthTestResult,
        )

        # Verify all imports succeeded
        assert APIEndpoint is not None
        assert APISecurityFinding is not None
        assert APISecuritySeverity is not None
        assert AuthenticationType is not None
        assert APIProtocol is not None
        assert APISecurityCategory is not None
        assert APIDiscoverer is not None
        assert APIInventory is not None
        assert APISecurityAnalyzer is not None
        assert APISecurityReport is not None
        assert AuthenticationTester is not None
        assert AuthTestResult is not None
