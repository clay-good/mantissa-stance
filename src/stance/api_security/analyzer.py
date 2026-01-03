"""
API Security Analyzer for API Security Testing.

Analyzes API endpoints for security issues including authentication,
authorization, CORS, rate limiting, and configuration problems.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from stance.api_security.models import (
    APIEndpoint,
    APISecurityFinding,
    APISecuritySeverity,
    APISecurityCategory,
    AuthenticationType,
)
from stance.api_security.discoverer import APIInventory

logger = logging.getLogger(__name__)


@dataclass
class APISecurityReport:
    """Report containing API security analysis results."""

    # Summary
    total_endpoints: int = 0
    total_findings: int = 0
    endpoints_with_findings: int = 0

    # Severity breakdown
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Category breakdown
    by_category: dict[str, int] = field(default_factory=dict)

    # Findings
    findings: list[APISecurityFinding] = field(default_factory=list)

    # Metadata
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    analysis_duration_ms: int = 0

    @property
    def has_critical_findings(self) -> bool:
        """Check if any critical findings exist."""
        return self.critical_count > 0

    @property
    def highest_severity(self) -> APISecuritySeverity:
        """Get the highest severity found."""
        if self.critical_count > 0:
            return APISecuritySeverity.CRITICAL
        if self.high_count > 0:
            return APISecuritySeverity.HIGH
        if self.medium_count > 0:
            return APISecuritySeverity.MEDIUM
        if self.low_count > 0:
            return APISecuritySeverity.LOW
        return APISecuritySeverity.INFO

    def get_findings_by_severity(
        self, severity: APISecuritySeverity
    ) -> list[APISecurityFinding]:
        """Get findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(
        self, category: APISecurityCategory
    ) -> list[APISecurityFinding]:
        """Get findings of a specific category."""
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": {
                "total_endpoints": self.total_endpoints,
                "total_findings": self.total_findings,
                "endpoints_with_findings": self.endpoints_with_findings,
                "highest_severity": self.highest_severity.value,
                "has_critical_findings": self.has_critical_findings,
            },
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "by_category": self.by_category,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": {
                "analyzed_at": self.analyzed_at.isoformat(),
                "analysis_duration_ms": self.analysis_duration_ms,
            },
        }


class APISecurityAnalyzer:
    """
    Analyzes API endpoints for security issues.

    Performs comprehensive security checks including:
    - Authentication configuration
    - Authorization controls
    - CORS policy analysis
    - Rate limiting verification
    - Encryption/TLS settings
    - Logging configuration
    - Public exposure assessment
    """

    def __init__(self):
        """Initialize the analyzer."""
        self._checks = [
            self._check_no_authentication,
            self._check_weak_authentication,
            self._check_cors_misconfiguration,
            self._check_no_rate_limiting,
            self._check_public_exposure,
            self._check_no_waf,
            self._check_no_logging,
            self._check_no_documentation,
            self._check_tls_configuration,
            self._check_api_key_exposure,
        ]

    def analyze(self, inventory: APIInventory) -> APISecurityReport:
        """
        Analyze API inventory for security issues.

        Args:
            inventory: APIInventory to analyze

        Returns:
            APISecurityReport with findings
        """
        import time
        start_time = time.time()

        report = APISecurityReport(total_endpoints=inventory.total_endpoints)
        endpoints_with_findings: set[str] = set()

        for endpoint in inventory.endpoints:
            findings = self._analyze_endpoint(endpoint)

            for finding in findings:
                report.findings.append(finding)
                endpoints_with_findings.add(endpoint.id)

                # Update severity counts
                if finding.severity == APISecuritySeverity.CRITICAL:
                    report.critical_count += 1
                elif finding.severity == APISecuritySeverity.HIGH:
                    report.high_count += 1
                elif finding.severity == APISecuritySeverity.MEDIUM:
                    report.medium_count += 1
                elif finding.severity == APISecuritySeverity.LOW:
                    report.low_count += 1
                else:
                    report.info_count += 1

                # Update category counts
                category = finding.category.value
                report.by_category[category] = report.by_category.get(category, 0) + 1

        report.total_findings = len(report.findings)
        report.endpoints_with_findings = len(endpoints_with_findings)
        report.analysis_duration_ms = int((time.time() - start_time) * 1000)

        return report

    def _analyze_endpoint(self, endpoint: APIEndpoint) -> list[APISecurityFinding]:
        """Analyze a single endpoint for security issues."""
        findings = []

        for check in self._checks:
            try:
                finding = check(endpoint)
                if finding:
                    findings.append(finding)
            except Exception as e:
                logger.debug(f"Check failed for {endpoint.id}: {e}")

        return findings

    def _generate_finding_id(self, endpoint: APIEndpoint, check_name: str) -> str:
        """Generate a unique finding ID."""
        data = f"{endpoint.id}:{check_name}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _check_no_authentication(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check for APIs without authentication."""
        if endpoint.authentication_required:
            return None

        if endpoint.authentication_type != AuthenticationType.NONE:
            return None

        # Public APIs without auth on internet are critical
        if endpoint.is_public:
            severity = APISecuritySeverity.CRITICAL
        else:
            severity = APISecuritySeverity.HIGH

        return APISecurityFinding(
            id=self._generate_finding_id(endpoint, "no_authentication"),
            title="API Endpoint Without Authentication",
            description=(
                f"The API endpoint '{endpoint.name}' does not require authentication. "
                "This allows any user to access the API without credentials, "
                "potentially exposing sensitive data or functionality."
            ),
            severity=severity,
            category=APISecurityCategory.AUTHENTICATION,
            api_endpoint_id=endpoint.id,
            api_endpoint_name=endpoint.name,
            cloud_provider=endpoint.cloud_provider,
            account_id=endpoint.account_id,
            region=endpoint.region,
            evidence={
                "authentication_type": endpoint.authentication_type.value,
                "authentication_required": endpoint.authentication_required,
                "is_public": endpoint.is_public,
            },
            recommendation="Configure authentication for the API endpoint.",
            remediation_steps=[
                "Add an authorizer (IAM, Cognito, JWT, or Lambda) to the API",
                "Require API keys for access control",
                "Implement OAuth 2.0 or OpenID Connect authentication",
                "Consider using mutual TLS for service-to-service communication",
            ],
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
            ],
            cwe_ids=["CWE-306"],
            owasp_ids=["API2:2023"],
            compliance_frameworks=["PCI-DSS", "SOC2", "HIPAA"],
        )

    def _check_weak_authentication(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check for weak authentication mechanisms."""
        if not endpoint.authentication_required:
            return None  # Handled by no_authentication check

        # API key only is weak if the endpoint is public
        if (
            endpoint.authentication_type == AuthenticationType.API_KEY
            and endpoint.is_public
            and not endpoint.authorizers
        ):
            return APISecurityFinding(
                id=self._generate_finding_id(endpoint, "weak_authentication"),
                title="API Key Only Authentication on Public Endpoint",
                description=(
                    f"The API endpoint '{endpoint.name}' uses only API key authentication. "
                    "API keys can be easily leaked or shared, providing insufficient "
                    "protection for public-facing APIs."
                ),
                severity=APISecuritySeverity.MEDIUM,
                category=APISecurityCategory.AUTHENTICATION,
                api_endpoint_id=endpoint.id,
                api_endpoint_name=endpoint.name,
                cloud_provider=endpoint.cloud_provider,
                account_id=endpoint.account_id,
                region=endpoint.region,
                evidence={
                    "authentication_type": endpoint.authentication_type.value,
                    "requires_api_key": endpoint.requires_api_key,
                    "has_authorizers": len(endpoint.authorizers) > 0,
                },
                recommendation=(
                    "Add a stronger authentication mechanism such as "
                    "OAuth 2.0, JWT, or IAM authentication."
                ),
                remediation_steps=[
                    "Implement OAuth 2.0 or OpenID Connect for user authentication",
                    "Add a Lambda or Cognito authorizer for enhanced security",
                    "Consider using IAM authentication for AWS service-to-service calls",
                    "Combine API keys with other authentication methods",
                ],
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                ],
                cwe_ids=["CWE-287"],
                owasp_ids=["API2:2023"],
            )

        return None

    def _check_cors_misconfiguration(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check for CORS misconfigurations."""
        if not endpoint.cors_enabled:
            return None

        # Check for wildcard origin with credentials
        if endpoint.cors_allow_all_origins and endpoint.cors_allow_credentials:
            return APISecurityFinding(
                id=self._generate_finding_id(endpoint, "cors_wildcard_credentials"),
                title="CORS Allows All Origins with Credentials",
                description=(
                    f"The API endpoint '{endpoint.name}' has CORS configured to allow "
                    "all origins (*) while also allowing credentials. This is a critical "
                    "security misconfiguration that can lead to credential theft."
                ),
                severity=APISecuritySeverity.CRITICAL,
                category=APISecurityCategory.CORS,
                api_endpoint_id=endpoint.id,
                api_endpoint_name=endpoint.name,
                cloud_provider=endpoint.cloud_provider,
                account_id=endpoint.account_id,
                region=endpoint.region,
                evidence={
                    "cors_enabled": endpoint.cors_enabled,
                    "allow_all_origins": endpoint.cors_allow_all_origins,
                    "allow_credentials": endpoint.cors_allow_credentials,
                    "allowed_origins": endpoint.cors_allow_origins,
                },
                recommendation=(
                    "Remove wildcard origin or disable credentials in CORS configuration."
                ),
                remediation_steps=[
                    "Specify explicit allowed origins instead of wildcard (*)",
                    "If credentials are needed, only allow trusted origins",
                    "Review and restrict CORS headers to minimum required",
                    "Consider disabling CORS if not needed for cross-origin access",
                ],
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                ],
                cwe_ids=["CWE-942"],
                owasp_ids=["API7:2023"],
            )

        # Check for wildcard origin (less severe without credentials)
        if endpoint.cors_allow_all_origins:
            return APISecurityFinding(
                id=self._generate_finding_id(endpoint, "cors_wildcard"),
                title="CORS Allows All Origins",
                description=(
                    f"The API endpoint '{endpoint.name}' has CORS configured to allow "
                    "all origins (*). This permits any website to make requests to "
                    "your API, which may not be intended."
                ),
                severity=APISecuritySeverity.LOW,
                category=APISecurityCategory.CORS,
                api_endpoint_id=endpoint.id,
                api_endpoint_name=endpoint.name,
                cloud_provider=endpoint.cloud_provider,
                account_id=endpoint.account_id,
                region=endpoint.region,
                evidence={
                    "cors_enabled": endpoint.cors_enabled,
                    "allow_all_origins": endpoint.cors_allow_all_origins,
                    "allowed_origins": endpoint.cors_allow_origins,
                },
                recommendation="Specify explicit allowed origins in CORS configuration.",
                remediation_steps=[
                    "List specific trusted origins that need cross-origin access",
                    "Review CORS configuration to match application requirements",
                ],
                cwe_ids=["CWE-942"],
            )

        return None

    def _check_no_rate_limiting(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check for APIs without rate limiting."""
        if endpoint.has_rate_limiting:
            return None

        # Public APIs without rate limiting are more severe
        if endpoint.is_public:
            severity = APISecuritySeverity.HIGH
        else:
            severity = APISecuritySeverity.MEDIUM

        return APISecurityFinding(
            id=self._generate_finding_id(endpoint, "no_rate_limiting"),
            title="API Endpoint Without Rate Limiting",
            description=(
                f"The API endpoint '{endpoint.name}' does not have rate limiting "
                "configured. This makes the API vulnerable to denial-of-service "
                "attacks and brute force attempts."
            ),
            severity=severity,
            category=APISecurityCategory.RATE_LIMITING,
            api_endpoint_id=endpoint.id,
            api_endpoint_name=endpoint.name,
            cloud_provider=endpoint.cloud_provider,
            account_id=endpoint.account_id,
            region=endpoint.region,
            evidence={
                "has_rate_limiting": endpoint.has_rate_limiting,
                "rate_limit": endpoint.rate_limit,
                "burst_limit": endpoint.burst_limit,
                "is_public": endpoint.is_public,
            },
            recommendation="Configure rate limiting and throttling for the API.",
            remediation_steps=[
                "Configure throttling settings at the stage or route level",
                "Set appropriate rate limits based on expected traffic",
                "Configure burst limits to handle traffic spikes",
                "Consider implementing per-client rate limiting",
            ],
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
            ],
            cwe_ids=["CWE-770"],
            owasp_ids=["API4:2023"],
        )

    def _check_public_exposure(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check for publicly exposed APIs."""
        if not endpoint.is_public:
            return None

        # Public API without WAF and without strong auth is concerning
        if not endpoint.has_waf and not endpoint.authentication_required:
            return APISecurityFinding(
                id=self._generate_finding_id(endpoint, "public_unprotected"),
                title="Publicly Exposed API Without Protection",
                description=(
                    f"The API endpoint '{endpoint.name}' is publicly accessible "
                    "without WAF protection or authentication. This creates a "
                    "significant attack surface for the application."
                ),
                severity=APISecuritySeverity.HIGH,
                category=APISecurityCategory.EXPOSURE,
                api_endpoint_id=endpoint.id,
                api_endpoint_name=endpoint.name,
                cloud_provider=endpoint.cloud_provider,
                account_id=endpoint.account_id,
                region=endpoint.region,
                evidence={
                    "is_public": endpoint.is_public,
                    "has_waf": endpoint.has_waf,
                    "authentication_required": endpoint.authentication_required,
                },
                recommendation=(
                    "Add WAF protection and authentication to the public API."
                ),
                remediation_steps=[
                    "Associate AWS WAF WebACL with the API stage",
                    "Configure authentication (IAM, Cognito, JWT)",
                    "Consider making the API private if public access is not required",
                    "Implement IP allowlisting if access should be restricted",
                ],
                cwe_ids=["CWE-749"],
                compliance_frameworks=["PCI-DSS", "SOC2"],
            )

        return None

    def _check_no_waf(self, endpoint: APIEndpoint) -> APISecurityFinding | None:
        """Check for public APIs without WAF."""
        if not endpoint.is_public:
            return None

        if endpoint.has_waf:
            return None

        return APISecurityFinding(
            id=self._generate_finding_id(endpoint, "no_waf"),
            title="Public API Without WAF Protection",
            description=(
                f"The public API endpoint '{endpoint.name}' does not have a "
                "Web Application Firewall (WAF) configured. WAF provides "
                "protection against common web attacks."
            ),
            severity=APISecuritySeverity.MEDIUM,
            category=APISecurityCategory.CONFIGURATION,
            api_endpoint_id=endpoint.id,
            api_endpoint_name=endpoint.name,
            cloud_provider=endpoint.cloud_provider,
            account_id=endpoint.account_id,
            region=endpoint.region,
            evidence={
                "is_public": endpoint.is_public,
                "has_waf": endpoint.has_waf,
            },
            recommendation="Associate a WAF WebACL with the API.",
            remediation_steps=[
                "Create an AWS WAF WebACL with appropriate rules",
                "Associate the WebACL with the API Gateway stage",
                "Configure managed rule groups for common threats",
                "Add rate-based rules for DDoS protection",
            ],
            references=[
                "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html",
            ],
            cwe_ids=["CWE-693"],
        )

    def _check_no_logging(self, endpoint: APIEndpoint) -> APISecurityFinding | None:
        """Check for APIs without access logging."""
        if endpoint.access_logging_enabled:
            return None

        return APISecurityFinding(
            id=self._generate_finding_id(endpoint, "no_logging"),
            title="API Endpoint Without Access Logging",
            description=(
                f"The API endpoint '{endpoint.name}' does not have access logging "
                "enabled. Without logging, it's difficult to monitor API usage, "
                "detect attacks, and perform forensic analysis."
            ),
            severity=APISecuritySeverity.LOW,
            category=APISecurityCategory.LOGGING,
            api_endpoint_id=endpoint.id,
            api_endpoint_name=endpoint.name,
            cloud_provider=endpoint.cloud_provider,
            account_id=endpoint.account_id,
            region=endpoint.region,
            evidence={
                "access_logging_enabled": endpoint.access_logging_enabled,
                "execution_logging_enabled": endpoint.execution_logging_enabled,
            },
            recommendation="Enable access logging for the API.",
            remediation_steps=[
                "Configure access logging in API Gateway stage settings",
                "Create a CloudWatch Log Group for API logs",
                "Set appropriate log format to capture relevant fields",
                "Configure log retention policy",
            ],
            cwe_ids=["CWE-778"],
            compliance_frameworks=["PCI-DSS", "SOC2", "HIPAA"],
        )

    def _check_no_documentation(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check for APIs without documentation."""
        if endpoint.has_documentation:
            return None

        return APISecurityFinding(
            id=self._generate_finding_id(endpoint, "no_documentation"),
            title="API Endpoint Without Documentation",
            description=(
                f"The API endpoint '{endpoint.name}' does not have documentation. "
                "API documentation is important for security reviews and helps "
                "developers understand proper API usage."
            ),
            severity=APISecuritySeverity.INFO,
            category=APISecurityCategory.DOCUMENTATION,
            api_endpoint_id=endpoint.id,
            api_endpoint_name=endpoint.name,
            cloud_provider=endpoint.cloud_provider,
            account_id=endpoint.account_id,
            region=endpoint.region,
            evidence={
                "has_documentation": endpoint.has_documentation,
            },
            recommendation="Create API documentation using OpenAPI/Swagger.",
            remediation_steps=[
                "Create an OpenAPI specification for the API",
                "Document authentication requirements",
                "Document request/response schemas",
                "Include security considerations in documentation",
            ],
        )

    def _check_tls_configuration(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check TLS configuration."""
        # Check for minimum TLS version
        if endpoint.minimum_tls_version:
            if endpoint.minimum_tls_version in ("TLS_1_0", "TLSv1", "1.0"):
                return APISecurityFinding(
                    id=self._generate_finding_id(endpoint, "weak_tls"),
                    title="API Using Weak TLS Version",
                    description=(
                        f"The API endpoint '{endpoint.name}' allows TLS 1.0 which "
                        "is deprecated and has known vulnerabilities."
                    ),
                    severity=APISecuritySeverity.HIGH,
                    category=APISecurityCategory.ENCRYPTION,
                    api_endpoint_id=endpoint.id,
                    api_endpoint_name=endpoint.name,
                    cloud_provider=endpoint.cloud_provider,
                    account_id=endpoint.account_id,
                    region=endpoint.region,
                    evidence={
                        "minimum_tls_version": endpoint.minimum_tls_version,
                    },
                    recommendation="Configure minimum TLS version to 1.2 or higher.",
                    remediation_steps=[
                        "Update API Gateway security policy to TLS 1.2",
                        "Test client compatibility before enforcement",
                        "Consider requiring TLS 1.3 for new APIs",
                    ],
                    cwe_ids=["CWE-326"],
                    compliance_frameworks=["PCI-DSS"],
                )

        return None

    def _check_api_key_exposure(
        self, endpoint: APIEndpoint
    ) -> APISecurityFinding | None:
        """Check for potential API key exposure in configuration."""
        # Check if API key is in query string (less secure)
        config = endpoint.raw_config
        api_key_source = config.get("api_key_source", "HEADER")

        if api_key_source == "AUTHORIZER":
            return APISecurityFinding(
                id=self._generate_finding_id(endpoint, "api_key_query"),
                title="API Key in Query String",
                description=(
                    f"The API endpoint '{endpoint.name}' is configured to accept "
                    "API keys from query strings. API keys in URLs can be logged "
                    "and exposed in browser history."
                ),
                severity=APISecuritySeverity.LOW,
                category=APISecurityCategory.AUTHENTICATION,
                api_endpoint_id=endpoint.id,
                api_endpoint_name=endpoint.name,
                cloud_provider=endpoint.cloud_provider,
                account_id=endpoint.account_id,
                region=endpoint.region,
                evidence={
                    "api_key_source": api_key_source,
                },
                recommendation="Configure API to accept keys in headers instead.",
                remediation_steps=[
                    "Change API key source to HEADER",
                    "Update client applications to send keys in headers",
                ],
                cwe_ids=["CWE-598"],
            )

        return None
