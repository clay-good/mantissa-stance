"""
Authentication Testing for API Security.

Provides testing capabilities for API authentication mechanisms
including validation of authentication configurations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from stance.api_security.models import (
    APIEndpoint,
    AuthenticationType,
    APISecuritySeverity,
)

logger = logging.getLogger(__name__)


class AuthTestStatus(Enum):
    """Status of an authentication test."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass
class AuthTestResult:
    """Result of an authentication test."""

    test_name: str
    status: AuthTestStatus
    message: str
    severity: APISecuritySeverity = APISecuritySeverity.INFO
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "status": self.status.value,
            "message": self.message,
            "severity": self.severity.value,
            "details": self.details,
            "recommendation": self.recommendation,
        }


@dataclass
class AuthTestReport:
    """Report containing authentication test results."""

    endpoint_id: str
    endpoint_name: str
    authentication_type: str

    # Results
    results: list[AuthTestResult] = field(default_factory=list)
    passed_count: int = 0
    failed_count: int = 0
    warning_count: int = 0

    # Metadata
    tested_at: datetime = field(default_factory=datetime.utcnow)

    @property
    def overall_status(self) -> AuthTestStatus:
        """Get overall test status."""
        if self.failed_count > 0:
            return AuthTestStatus.FAILED
        if self.warning_count > 0:
            return AuthTestStatus.WARNING
        return AuthTestStatus.PASSED

    def add_result(self, result: AuthTestResult) -> None:
        """Add a test result."""
        self.results.append(result)
        if result.status == AuthTestStatus.PASSED:
            self.passed_count += 1
        elif result.status == AuthTestStatus.FAILED:
            self.failed_count += 1
        elif result.status == AuthTestStatus.WARNING:
            self.warning_count += 1

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "endpoint_id": self.endpoint_id,
            "endpoint_name": self.endpoint_name,
            "authentication_type": self.authentication_type,
            "overall_status": self.overall_status.value,
            "summary": {
                "passed": self.passed_count,
                "failed": self.failed_count,
                "warning": self.warning_count,
                "total": len(self.results),
            },
            "results": [r.to_dict() for r in self.results],
            "tested_at": self.tested_at.isoformat(),
        }


class AuthenticationTester:
    """
    Tests API authentication configurations.

    Performs static analysis of authentication settings to identify
    potential security issues without making actual API calls.

    Tests include:
    - Authentication requirement verification
    - Authorizer configuration validation
    - Token/key configuration checks
    - OAuth/OIDC configuration validation
    """

    def test_endpoint(self, endpoint: APIEndpoint) -> AuthTestReport:
        """
        Test authentication configuration for an endpoint.

        Args:
            endpoint: API endpoint to test

        Returns:
            AuthTestReport with test results
        """
        report = AuthTestReport(
            endpoint_id=endpoint.id,
            endpoint_name=endpoint.name,
            authentication_type=endpoint.authentication_type.value,
        )

        # Run authentication tests
        tests = [
            self._test_auth_required,
            self._test_auth_type_configured,
            self._test_authorizer_configuration,
            self._test_jwt_configuration,
            self._test_api_key_configuration,
            self._test_iam_configuration,
            self._test_cognito_configuration,
            self._test_lambda_authorizer,
        ]

        for test in tests:
            try:
                result = test(endpoint)
                if result:
                    report.add_result(result)
            except Exception as e:
                logger.debug(f"Auth test failed for {endpoint.id}: {e}")
                report.add_result(AuthTestResult(
                    test_name=test.__name__,
                    status=AuthTestStatus.ERROR,
                    message=f"Test error: {str(e)}",
                ))

        return report

    def _test_auth_required(self, endpoint: APIEndpoint) -> AuthTestResult | None:
        """Test if authentication is required."""
        if endpoint.authentication_required:
            return AuthTestResult(
                test_name="authentication_required",
                status=AuthTestStatus.PASSED,
                message="Authentication is required for this endpoint",
                details={
                    "authentication_required": True,
                    "authentication_type": endpoint.authentication_type.value,
                },
            )
        else:
            severity = (
                APISecuritySeverity.CRITICAL
                if endpoint.is_public
                else APISecuritySeverity.HIGH
            )
            return AuthTestResult(
                test_name="authentication_required",
                status=AuthTestStatus.FAILED,
                message="Authentication is not required for this endpoint",
                severity=severity,
                details={
                    "authentication_required": False,
                    "is_public": endpoint.is_public,
                },
                recommendation="Configure authentication for the API endpoint",
            )

    def _test_auth_type_configured(
        self, endpoint: APIEndpoint
    ) -> AuthTestResult | None:
        """Test if authentication type is properly configured."""
        if endpoint.authentication_type == AuthenticationType.UNKNOWN:
            return AuthTestResult(
                test_name="auth_type_configured",
                status=AuthTestStatus.WARNING,
                message="Authentication type could not be determined",
                severity=APISecuritySeverity.LOW,
                details={
                    "authentication_type": endpoint.authentication_type.value,
                },
                recommendation="Review and document the authentication mechanism",
            )
        elif endpoint.authentication_type == AuthenticationType.NONE:
            if not endpoint.authentication_required:
                return None  # Already handled by auth_required test
            return AuthTestResult(
                test_name="auth_type_configured",
                status=AuthTestStatus.FAILED,
                message="No authentication type configured",
                severity=APISecuritySeverity.HIGH,
                details={
                    "authentication_type": endpoint.authentication_type.value,
                },
                recommendation="Configure an authentication mechanism",
            )
        else:
            return AuthTestResult(
                test_name="auth_type_configured",
                status=AuthTestStatus.PASSED,
                message=f"Authentication type: {endpoint.authentication_type.value}",
                details={
                    "authentication_type": endpoint.authentication_type.value,
                },
            )

    def _test_authorizer_configuration(
        self, endpoint: APIEndpoint
    ) -> AuthTestResult | None:
        """Test authorizer configuration."""
        if not endpoint.authorizers:
            if endpoint.authentication_required:
                return AuthTestResult(
                    test_name="authorizer_configuration",
                    status=AuthTestStatus.WARNING,
                    message="No authorizers configured but auth is required",
                    severity=APISecuritySeverity.LOW,
                    details={
                        "authorizer_count": 0,
                    },
                    recommendation="Configure authorizers for authentication",
                )
            return None

        # Check authorizer details
        for authorizer in endpoint.authorizers:
            auth_type = authorizer.get("type") or authorizer.get("authorizer_type")

            # Check for TOKEN authorizer without validation expression
            if auth_type == "TOKEN":
                identity_validation = authorizer.get("identity_validation_expression")
                if not identity_validation:
                    return AuthTestResult(
                        test_name="authorizer_configuration",
                        status=AuthTestStatus.WARNING,
                        message="Token authorizer without identity validation expression",
                        severity=APISecuritySeverity.LOW,
                        details={
                            "authorizer_type": auth_type,
                            "has_validation_expression": False,
                        },
                        recommendation="Add identity validation expression to authorizer",
                    )

            # Check for caching settings
            ttl = authorizer.get("authorizer_result_ttl_in_seconds")
            if ttl is not None and ttl > 3600:
                return AuthTestResult(
                    test_name="authorizer_configuration",
                    status=AuthTestStatus.WARNING,
                    message="Authorizer cache TTL is very long",
                    severity=APISecuritySeverity.LOW,
                    details={
                        "ttl_seconds": ttl,
                    },
                    recommendation="Consider reducing cache TTL for security",
                )

        return AuthTestResult(
            test_name="authorizer_configuration",
            status=AuthTestStatus.PASSED,
            message=f"Authorizers configured: {len(endpoint.authorizers)}",
            details={
                "authorizer_count": len(endpoint.authorizers),
            },
        )

    def _test_jwt_configuration(
        self, endpoint: APIEndpoint
    ) -> AuthTestResult | None:
        """Test JWT configuration if applicable."""
        if endpoint.authentication_type not in (
            AuthenticationType.JWT,
            AuthenticationType.BEARER,
        ):
            return None

        # Check JWT configuration in authorizers
        for authorizer in endpoint.authorizers:
            jwt_config = authorizer.get("jwt_configuration", {})
            if jwt_config:
                issuer = jwt_config.get("Issuer") or jwt_config.get("issuer")
                audience = jwt_config.get("Audience") or jwt_config.get("audience", [])

                if not issuer:
                    return AuthTestResult(
                        test_name="jwt_configuration",
                        status=AuthTestStatus.FAILED,
                        message="JWT authorizer without issuer configured",
                        severity=APISecuritySeverity.HIGH,
                        details={
                            "has_issuer": False,
                            "has_audience": bool(audience),
                        },
                        recommendation="Configure JWT issuer for validation",
                    )

                if not audience:
                    return AuthTestResult(
                        test_name="jwt_configuration",
                        status=AuthTestStatus.WARNING,
                        message="JWT authorizer without audience configured",
                        severity=APISecuritySeverity.MEDIUM,
                        details={
                            "has_issuer": True,
                            "has_audience": False,
                        },
                        recommendation="Configure JWT audience for validation",
                    )

                return AuthTestResult(
                    test_name="jwt_configuration",
                    status=AuthTestStatus.PASSED,
                    message="JWT configuration validated",
                    details={
                        "has_issuer": True,
                        "has_audience": True,
                    },
                )

        return None

    def _test_api_key_configuration(
        self, endpoint: APIEndpoint
    ) -> AuthTestResult | None:
        """Test API key configuration if applicable."""
        if endpoint.authentication_type != AuthenticationType.API_KEY:
            if not endpoint.requires_api_key:
                return None

        if endpoint.requires_api_key:
            # Check API key source
            config = endpoint.raw_config
            api_key_source = config.get("api_key_source", "HEADER")

            if api_key_source == "AUTHORIZER":
                return AuthTestResult(
                    test_name="api_key_configuration",
                    status=AuthTestStatus.WARNING,
                    message="API key passed via query string/authorizer",
                    severity=APISecuritySeverity.LOW,
                    details={
                        "api_key_source": api_key_source,
                    },
                    recommendation="Use header-based API key transmission",
                )

            return AuthTestResult(
                test_name="api_key_configuration",
                status=AuthTestStatus.PASSED,
                message="API key configuration validated",
                details={
                    "api_key_source": api_key_source,
                },
            )

        return None

    def _test_iam_configuration(
        self, endpoint: APIEndpoint
    ) -> AuthTestResult | None:
        """Test IAM authentication configuration."""
        if endpoint.authentication_type != AuthenticationType.IAM:
            return None

        # IAM auth is generally secure by default
        return AuthTestResult(
            test_name="iam_configuration",
            status=AuthTestStatus.PASSED,
            message="IAM authentication is configured",
            details={
                "authentication_type": "iam",
            },
        )

    def _test_cognito_configuration(
        self, endpoint: APIEndpoint
    ) -> AuthTestResult | None:
        """Test Cognito authentication configuration."""
        if endpoint.authentication_type != AuthenticationType.COGNITO:
            return None

        # Check for Cognito authorizer configuration
        for authorizer in endpoint.authorizers:
            auth_type = authorizer.get("type")
            if auth_type == "COGNITO_USER_POOLS":
                provider_arns = authorizer.get("provider_arns", [])
                if not provider_arns:
                    return AuthTestResult(
                        test_name="cognito_configuration",
                        status=AuthTestStatus.FAILED,
                        message="Cognito authorizer without user pool ARN",
                        severity=APISecuritySeverity.HIGH,
                        details={
                            "has_provider_arns": False,
                        },
                        recommendation="Configure Cognito User Pool ARN",
                    )

                return AuthTestResult(
                    test_name="cognito_configuration",
                    status=AuthTestStatus.PASSED,
                    message="Cognito configuration validated",
                    details={
                        "provider_count": len(provider_arns),
                    },
                )

        return None

    def _test_lambda_authorizer(
        self, endpoint: APIEndpoint
    ) -> AuthTestResult | None:
        """Test Lambda authorizer configuration."""
        if endpoint.authentication_type != AuthenticationType.LAMBDA:
            return None

        for authorizer in endpoint.authorizers:
            auth_type = authorizer.get("type") or authorizer.get("authorizer_type")
            if auth_type in ("REQUEST", "TOKEN"):
                authorizer_uri = authorizer.get("authorizer_uri")
                if not authorizer_uri:
                    return AuthTestResult(
                        test_name="lambda_authorizer",
                        status=AuthTestStatus.FAILED,
                        message="Lambda authorizer without URI configured",
                        severity=APISecuritySeverity.HIGH,
                        details={
                            "authorizer_type": auth_type,
                            "has_uri": False,
                        },
                        recommendation="Configure Lambda authorizer function URI",
                    )

                # Check for credentials
                has_credentials = authorizer.get("authorizer_credentials", False)

                return AuthTestResult(
                    test_name="lambda_authorizer",
                    status=AuthTestStatus.PASSED,
                    message="Lambda authorizer configured",
                    details={
                        "authorizer_type": auth_type,
                        "has_credentials": has_credentials,
                    },
                )

        return None
