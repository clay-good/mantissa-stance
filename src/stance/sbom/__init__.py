"""
Software Bill of Materials (SBOM) module for Mantissa Stance.

Provides SBOM generation, parsing, and analysis capabilities for
supply chain security assessment. Supports multiple package ecosystems
and SBOM formats.

Key Components:
- DependencyParser: Parses dependency files (package.json, requirements.txt, etc.)
- SBOMGenerator: Generates SBOM in CycloneDX/SPDX formats
- LicenseAnalyzer: Analyzes and validates software licenses
- SupplyChainAnalyzer: Comprehensive supply chain risk assessment
- VulnerabilityScanner: Scans dependencies for known vulnerabilities (NVD/OSV)
- DependencyGraphBuilder: Builds and visualizes dependency graphs
- AttestationBuilder: Creates cryptographically signed SBOM attestations
- VEXGenerator: Creates VEX documents for vulnerability status

Example:
    from stance.sbom import DependencyParser, LicenseAnalyzer, VulnerabilityScanner

    parser = DependencyParser()
    dependencies = parser.parse_file("package.json")

    analyzer = LicenseAnalyzer()
    risks = analyzer.analyze(dependencies)

    scanner = VulnerabilityScanner()
    vulns = scanner.scan_dependencies(dependencies.dependencies)

    # Visualize dependency graph
    from stance.sbom import DependencyGraphBuilder
    builder = DependencyGraphBuilder()
    graph = builder.build_from_file(dependencies)
    print(graph.to_tree_string())
"""

from stance.sbom.parser import (
    Dependency,
    DependencyFile,
    DependencyParser,
    PackageEcosystem,
    DependencyScope,
)
from stance.sbom.generator import (
    SBOM,
    SBOMFormat,
    SBOMGenerator,
    SBOMComponent,
)
from stance.sbom.license import (
    License,
    LicenseRisk,
    LicenseCategory,
    LicenseAnalyzer,
    LicenseCompatibility,
)
from stance.sbom.analyzer import (
    SupplyChainRisk,
    SupplyChainAnalyzer,
    DependencyRisk,
    RiskLevel,
)
from stance.sbom.vulnerability import (
    Vulnerability,
    VulnerabilityDatabase,
    VulnerabilityMatch,
    VulnerabilityScanResult,
    VulnerabilityScanner,
    VulnerabilitySeverity,
    VulnerabilitySource,
    AffectedVersion,
    scan_vulnerabilities,
)
from stance.sbom.graph import (
    DependencyGraph,
    DependencyGraphBuilder,
    GraphNode,
    GraphEdge,
    GraphMetrics,
    DependencyCycle,
    NodeType,
    EdgeType,
    build_dependency_graph,
    visualize_dependencies,
)
from stance.sbom.attestation import (
    Attestation,
    AttestationBuilder,
    AttestationSigner,
    AttestationVerifier,
    AttestationType,
    SignatureAlgorithm,
    VerificationStatus,
    VerificationResult,
    Signer,
    Signature,
    Subject,
    Predicate,
    create_sbom_attestation,
    verify_sbom_attestation,
)
from stance.sbom.vex import (
    VEXDocument,
    VEXStatement,
    VEXProduct,
    VEXVulnerability,
    VEXStatus,
    VEXJustification,
    VEXGenerator,
    VEXParser,
    ActionType,
    create_vex_document,
)

__all__ = [
    # Parser
    "Dependency",
    "DependencyFile",
    "DependencyParser",
    "PackageEcosystem",
    "DependencyScope",
    # Generator
    "SBOM",
    "SBOMFormat",
    "SBOMGenerator",
    "SBOMComponent",
    # License
    "License",
    "LicenseRisk",
    "LicenseCategory",
    "LicenseAnalyzer",
    "LicenseCompatibility",
    # Analyzer
    "SupplyChainRisk",
    "SupplyChainAnalyzer",
    "DependencyRisk",
    "RiskLevel",
    # Vulnerability
    "Vulnerability",
    "VulnerabilityDatabase",
    "VulnerabilityMatch",
    "VulnerabilityScanResult",
    "VulnerabilityScanner",
    "VulnerabilitySeverity",
    "VulnerabilitySource",
    "AffectedVersion",
    "scan_vulnerabilities",
    # Graph
    "DependencyGraph",
    "DependencyGraphBuilder",
    "GraphNode",
    "GraphEdge",
    "GraphMetrics",
    "DependencyCycle",
    "NodeType",
    "EdgeType",
    "build_dependency_graph",
    "visualize_dependencies",
    # Attestation
    "Attestation",
    "AttestationBuilder",
    "AttestationSigner",
    "AttestationVerifier",
    "AttestationType",
    "SignatureAlgorithm",
    "VerificationStatus",
    "VerificationResult",
    "Signer",
    "Signature",
    "Subject",
    "Predicate",
    "create_sbom_attestation",
    "verify_sbom_attestation",
    # VEX
    "VEXDocument",
    "VEXStatement",
    "VEXProduct",
    "VEXVulnerability",
    "VEXStatus",
    "VEXJustification",
    "VEXGenerator",
    "VEXParser",
    "ActionType",
    "create_vex_document",
]
