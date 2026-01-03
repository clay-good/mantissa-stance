"""
API Security Testing module for Mantissa Stance.

Provides API security assessment capabilities including:
- API endpoint discovery and inventory
- Authentication and authorization testing
- Security configuration analysis
- Input validation assessment
- Rate limiting and throttling verification
- CORS policy analysis

Key Components:
- APIDiscoverer: Discovers and inventories API endpoints
- APISecurityAnalyzer: Analyzes API security configurations
- AuthenticationTester: Tests authentication mechanisms
- APISecurityFinding: Represents API security issues

Example:
    from stance.api_security import APIDiscoverer, APISecurityAnalyzer

    discoverer = APIDiscoverer()
    apis = discoverer.discover_from_assets(assets)

    analyzer = APISecurityAnalyzer()
    findings = analyzer.analyze(apis)
"""

from stance.api_security.models import (
    APIEndpoint,
    APISecurityFinding,
    APISecuritySeverity,
    AuthenticationType,
    APIProtocol,
    APISecurityCategory,
)
from stance.api_security.discoverer import (
    APIDiscoverer,
    APIInventory,
)
from stance.api_security.analyzer import (
    APISecurityAnalyzer,
    APISecurityReport,
)
from stance.api_security.auth_tester import (
    AuthenticationTester,
    AuthTestResult,
)

__all__ = [
    # Models
    "APIEndpoint",
    "APISecurityFinding",
    "APISecuritySeverity",
    "AuthenticationType",
    "APIProtocol",
    "APISecurityCategory",
    # Discoverer
    "APIDiscoverer",
    "APIInventory",
    # Analyzer
    "APISecurityAnalyzer",
    "APISecurityReport",
    # Auth Tester
    "AuthenticationTester",
    "AuthTestResult",
]
