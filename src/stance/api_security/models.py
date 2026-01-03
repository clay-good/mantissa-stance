"""
Data models for API Security Testing.

Provides data structures for representing API endpoints, security findings,
and assessment results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class APIProtocol(Enum):
    """API protocol types."""

    REST = "rest"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    SOAP = "soap"
    UNKNOWN = "unknown"


class AuthenticationType(Enum):
    """Authentication mechanism types."""

    NONE = "none"
    API_KEY = "api_key"
    BASIC = "basic"
    BEARER = "bearer"
    JWT = "jwt"
    OAUTH2 = "oauth2"
    IAM = "iam"
    COGNITO = "cognito"
    LAMBDA = "lambda"
    MTLS = "mtls"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class APISecuritySeverity(Enum):
    """Severity levels for API security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class APISecurityCategory(Enum):
    """Categories of API security issues."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INPUT_VALIDATION = "input_validation"
    RATE_LIMITING = "rate_limiting"
    ENCRYPTION = "encryption"
    CORS = "cors"
    LOGGING = "logging"
    DOCUMENTATION = "documentation"
    EXPOSURE = "exposure"
    CONFIGURATION = "configuration"
    INJECTION = "injection"
    DATA_EXPOSURE = "data_exposure"


@dataclass
class APIEndpoint:
    """Represents an API endpoint."""

    # Identification
    id: str
    name: str
    url: str | None = None

    # API metadata
    protocol: APIProtocol = APIProtocol.REST
    http_methods: list[str] = field(default_factory=list)
    path: str | None = None

    # Cloud context
    cloud_provider: str = ""
    account_id: str = ""
    region: str = ""
    resource_type: str = ""

    # Authentication
    authentication_type: AuthenticationType = AuthenticationType.UNKNOWN
    authentication_required: bool = True
    authorizers: list[dict[str, Any]] = field(default_factory=list)

    # Security configuration
    is_public: bool = False
    requires_api_key: bool = False
    has_waf: bool = False
    has_rate_limiting: bool = False
    rate_limit: int | None = None
    burst_limit: int | None = None

    # CORS
    cors_enabled: bool = False
    cors_allow_origins: list[str] = field(default_factory=list)
    cors_allow_all_origins: bool = False
    cors_allow_credentials: bool = False

    # TLS/Encryption
    tls_enabled: bool = True
    minimum_tls_version: str | None = None
    client_certificate_required: bool = False

    # Logging
    access_logging_enabled: bool = False
    execution_logging_enabled: bool = False

    # Documentation
    has_documentation: bool = False
    openapi_spec: dict[str, Any] | None = None

    # Metadata
    stages: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    created_at: datetime | None = None
    last_modified: datetime | None = None

    # Raw configuration
    raw_config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "protocol": self.protocol.value,
            "http_methods": self.http_methods,
            "path": self.path,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "region": self.region,
            "resource_type": self.resource_type,
            "authentication": {
                "type": self.authentication_type.value,
                "required": self.authentication_required,
                "authorizers": len(self.authorizers),
            },
            "security": {
                "is_public": self.is_public,
                "requires_api_key": self.requires_api_key,
                "has_waf": self.has_waf,
                "has_rate_limiting": self.has_rate_limiting,
                "rate_limit": self.rate_limit,
                "burst_limit": self.burst_limit,
            },
            "cors": {
                "enabled": self.cors_enabled,
                "allow_all_origins": self.cors_allow_all_origins,
                "allow_credentials": self.cors_allow_credentials,
            },
            "tls": {
                "enabled": self.tls_enabled,
                "minimum_version": self.minimum_tls_version,
                "client_cert_required": self.client_certificate_required,
            },
            "logging": {
                "access_logging": self.access_logging_enabled,
                "execution_logging": self.execution_logging_enabled,
            },
            "documentation": {
                "has_documentation": self.has_documentation,
            },
            "stages": self.stages,
            "tags": self.tags,
        }


@dataclass
class APISecurityFinding:
    """Represents an API security finding."""

    # Identification
    id: str
    title: str
    description: str

    # Severity and category
    severity: APISecuritySeverity
    category: APISecurityCategory

    # Affected resource
    api_endpoint_id: str
    api_endpoint_name: str
    cloud_provider: str = ""
    account_id: str = ""
    region: str = ""

    # Finding details
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""
    remediation_steps: list[str] = field(default_factory=list)

    # References
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)

    # Compliance
    compliance_frameworks: list[str] = field(default_factory=list)

    # Metadata
    detected_at: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 1.0  # 0.0 to 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "api_endpoint": {
                "id": self.api_endpoint_id,
                "name": self.api_endpoint_name,
            },
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "region": self.region,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "remediation_steps": self.remediation_steps,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "owasp_ids": self.owasp_ids,
            "compliance_frameworks": self.compliance_frameworks,
            "detected_at": self.detected_at.isoformat(),
            "confidence": self.confidence,
        }


@dataclass
class APIRoute:
    """Represents an individual API route/path."""

    path: str
    http_method: str
    operation_id: str | None = None
    summary: str | None = None
    authentication_required: bool = True
    authorization_scopes: list[str] = field(default_factory=list)
    rate_limit: int | None = None
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body_schema: dict[str, Any] | None = None
    response_schemas: dict[str, Any] = field(default_factory=dict)


@dataclass
class APISchema:
    """Represents an API schema/specification."""

    format: str  # openapi, swagger, graphql, etc.
    version: str
    title: str | None = None
    description: str | None = None
    routes: list[APIRoute] = field(default_factory=list)
    security_definitions: dict[str, Any] = field(default_factory=dict)
    servers: list[str] = field(default_factory=list)
    raw_spec: dict[str, Any] = field(default_factory=dict)
