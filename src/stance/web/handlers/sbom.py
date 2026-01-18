"""
SBOM handlers for the Stance web API.

This module handles all /api/sbom/* endpoints for Software Bill of Materials
generation, parsing, and analysis.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class SbomHandler(RoutedHandler):
    """
    Handler for SBOM API endpoints.

    Handles:
    - SBOM generation and parsing
    - License analysis
    - Supply chain risk assessment
    - Dependency graphs
    - Attestation and VEX
    """

    base_path = "/api/sbom/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("info")
    def sbom_info(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get SBOM module information."""
        return HandlerResponse.success({
            "module": "stance.sbom",
            "description": "Software Bill of Materials for supply chain security",
            "capabilities": [
                "Dependency file parsing (npm, pip, go, cargo, ruby, php)",
                "SBOM generation (CycloneDX, SPDX, Stance native)",
                "License identification and risk assessment",
                "License compatibility checking",
                "Supply chain risk analysis",
                "Typosquatting detection",
                "Deprecated package detection",
                "Vulnerability integration",
            ],
            "components": {
                "DependencyParser": "Parses dependency files from multiple ecosystems",
                "SBOMGenerator": "Generates SBOM in various formats",
                "LicenseAnalyzer": "Analyzes and validates software licenses",
                "SupplyChainAnalyzer": "Comprehensive supply chain risk assessment",
            },
        })

    @route("formats")
    def sbom_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported SBOM formats."""
        formats = [
            {
                "name": "CycloneDX JSON",
                "id": "cyclonedx-json",
                "spec_version": "1.5",
                "description": "OWASP CycloneDX JSON format",
                "file_extensions": [".json"],
                "standards": ["OWASP", "NTIA"],
            },
            {
                "name": "CycloneDX XML",
                "id": "cyclonedx-xml",
                "spec_version": "1.5",
                "description": "OWASP CycloneDX XML format",
                "file_extensions": [".xml"],
                "standards": ["OWASP", "NTIA"],
            },
            {
                "name": "SPDX JSON",
                "id": "spdx-json",
                "spec_version": "2.3",
                "description": "Linux Foundation SPDX JSON format",
                "file_extensions": [".json", ".spdx.json"],
                "standards": ["Linux Foundation", "ISO/IEC 5962:2021"],
            },
            {
                "name": "SPDX Tag-Value",
                "id": "spdx-tag",
                "spec_version": "2.3",
                "description": "Linux Foundation SPDX tag-value format",
                "file_extensions": [".spdx", ".spdx.tv"],
                "standards": ["Linux Foundation", "ISO/IEC 5962:2021"],
            },
            {
                "name": "Stance Native",
                "id": "stance",
                "spec_version": "1.0",
                "description": "Mantissa Stance native SBOM format",
                "file_extensions": [".json", ".stance.json"],
                "standards": ["Proprietary"],
            },
        ]
        return HandlerResponse.success({"formats": formats, "total": len(formats)})

    @route("ecosystems")
    def sbom_ecosystems(self, params: dict, body: dict | None) -> HandlerResponse:
        """List supported package ecosystems."""
        ecosystems = [
            {
                "name": "NPM",
                "id": "npm",
                "language": "JavaScript/TypeScript",
                "files": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
                "registry": "https://registry.npmjs.org",
            },
            {
                "name": "PyPI",
                "id": "pypi",
                "language": "Python",
                "files": ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock", "setup.py"],
                "registry": "https://pypi.org",
            },
            {
                "name": "Go Modules",
                "id": "go",
                "language": "Go",
                "files": ["go.mod", "go.sum"],
                "registry": "https://proxy.golang.org",
            },
            {
                "name": "Cargo",
                "id": "cargo",
                "language": "Rust",
                "files": ["Cargo.toml", "Cargo.lock"],
                "registry": "https://crates.io",
            },
            {
                "name": "RubyGems",
                "id": "rubygems",
                "language": "Ruby",
                "files": ["Gemfile", "Gemfile.lock", "*.gemspec"],
                "registry": "https://rubygems.org",
            },
            {
                "name": "Composer",
                "id": "composer",
                "language": "PHP",
                "files": ["composer.json", "composer.lock"],
                "registry": "https://packagist.org",
            },
        ]
        return HandlerResponse.success({"ecosystems": ecosystems, "total": len(ecosystems)})

    @route("licenses")
    def sbom_licenses(self, params: dict, body: dict | None) -> HandlerResponse:
        """List known software licenses."""
        try:
            from stance.sbom import LicenseAnalyzer
            analyzer = LicenseAnalyzer()

            category_filter = self.get_param(params, "category", "all")
            licenses = []

            for lic in analyzer.list_known_licenses():
                if category_filter == "all" or lic.category.value == category_filter:
                    licenses.append({
                        "spdx_id": lic.spdx_id,
                        "name": lic.name,
                        "category": lic.category.value,
                        "risk": lic.risk.value,
                        "osi_approved": lic.osi_approved,
                        "copyleft": lic.copyleft,
                        "patent_grant": lic.patent_grant,
                    })

            licenses.sort(key=lambda x: (x["category"], x["spdx_id"]))
            return HandlerResponse.success({"licenses": licenses, "total": len(licenses)})
        except ImportError as e:
            return HandlerResponse.error(f"SBOM module not available: {e}")

    @route("license-categories")
    def sbom_license_categories(self, params: dict, body: dict | None) -> HandlerResponse:
        """List license categories."""
        categories = [
            {"id": "permissive", "name": "Permissive", "description": "Liberal licenses with minimal restrictions"},
            {"id": "weak_copyleft", "name": "Weak Copyleft", "description": "Copyleft for modifications, not linking"},
            {"id": "strong_copyleft", "name": "Strong Copyleft", "description": "Full copyleft requiring derivative works"},
            {"id": "proprietary", "name": "Proprietary", "description": "Restricted or commercial licenses"},
            {"id": "public_domain", "name": "Public Domain", "description": "No restrictions, public domain"},
            {"id": "unknown", "name": "Unknown", "description": "License not recognized"},
        ]
        return HandlerResponse.success({"categories": categories, "total": len(categories)})

    @route("risk-levels")
    def sbom_risk_levels(self, params: dict, body: dict | None) -> HandlerResponse:
        """List risk levels."""
        levels = [
            {"id": "critical", "name": "Critical", "description": "Requires immediate attention", "score_range": "90-100"},
            {"id": "high", "name": "High", "description": "Significant risk", "score_range": "70-89"},
            {"id": "medium", "name": "Medium", "description": "Moderate risk", "score_range": "40-69"},
            {"id": "low", "name": "Low", "description": "Minor risk", "score_range": "10-39"},
            {"id": "info", "name": "Info", "description": "Informational only", "score_range": "0-9"},
        ]
        return HandlerResponse.success({"levels": levels, "total": len(levels)})

    @route("parse")
    def sbom_parse(self, params: dict, body: dict | None) -> HandlerResponse:
        """Parse a dependency file."""
        try:
            from stance.sbom import DependencyParser

            path = self.get_param(params, "path", "")
            if not path:
                return HandlerResponse.error("Missing required parameter: path", HttpStatus.BAD_REQUEST)

            parser = DependencyParser()
            dep_file = parser.parse_file(path)

            if not dep_file:
                return HandlerResponse.error(f"Could not parse file: {path}")

            return HandlerResponse.success({
                "path": dep_file.path,
                "ecosystem": dep_file.ecosystem.value,
                "dependencies": [
                    {
                        "name": d.name,
                        "version": d.version or "any",
                        "scope": d.scope.value,
                        "ecosystem": d.ecosystem.value,
                    }
                    for d in dep_file.dependencies
                ],
                "total": len(dep_file.dependencies),
            })
        except ImportError as e:
            return HandlerResponse.error(f"SBOM module not available: {e}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("analyze-license")
    def sbom_analyze_license(self, params: dict, body: dict | None) -> HandlerResponse:
        """Analyze licenses in dependencies."""
        try:
            from stance.sbom import DependencyParser, LicenseAnalyzer

            path = self.get_param(params, "path", "")
            if not path:
                return HandlerResponse.error("Missing required parameter: path", HttpStatus.BAD_REQUEST)

            parser = DependencyParser()
            analyzer = LicenseAnalyzer()

            dep_file = parser.parse_file(path)
            if not dep_file:
                return HandlerResponse.error(f"Could not parse file: {path}")

            report = analyzer.analyze_dependencies(dep_file.dependencies)

            return HandlerResponse.success({
                "path": path,
                "total_dependencies": len(dep_file.dependencies),
                "licenses_found": len(report.results),
                "unknown_licenses": report.unknown_count,
                "summary": {
                    "permissive": report.permissive_count,
                    "weak_copyleft": report.weak_copyleft_count,
                    "strong_copyleft": report.strong_copyleft_count,
                    "proprietary": report.proprietary_count,
                    "unknown": report.unknown_count,
                },
                "risk_counts": {
                    risk.value: count
                    for risk, count in report.risk_counts.items()
                },
            })
        except ImportError as e:
            return HandlerResponse.error(f"SBOM module not available: {e}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("analyze-risk")
    def sbom_analyze_risk(self, params: dict, body: dict | None) -> HandlerResponse:
        """Analyze supply chain risks."""
        try:
            from stance.sbom import DependencyParser, SupplyChainAnalyzer

            path = self.get_param(params, "path", "")
            if not path:
                return HandlerResponse.error("Missing required parameter: path", HttpStatus.BAD_REQUEST)

            parser = DependencyParser()
            analyzer = SupplyChainAnalyzer()

            dep_file = parser.parse_file(path)
            if not dep_file:
                return HandlerResponse.error(f"Could not parse file: {path}")

            report = analyzer.analyze(dep_file.dependencies)

            return HandlerResponse.success({
                "path": path,
                "total_dependencies": len(dep_file.dependencies),
                "overall_risk": report.overall_risk.value,
                "risk_score": report.risk_score,
                "summary": {
                    "critical": report.critical_count,
                    "high": report.high_count,
                    "medium": report.medium_count,
                    "low": report.low_count,
                },
                "risks": [
                    {
                        "package": dr.dependency.name,
                        "risks": [
                            {
                                "type": r.risk_type,
                                "level": r.level.value,
                                "description": r.description,
                            }
                            for r in dr.risks
                        ],
                    }
                    for dr in report.dependency_risks
                    if dr.risks
                ],
            })
        except ImportError as e:
            return HandlerResponse.error(f"SBOM module not available: {e}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("status")
    def sbom_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get SBOM module status."""
        try:
            from stance.sbom import (
                DependencyParser,
                SBOMGenerator,
                LicenseAnalyzer,
                SupplyChainAnalyzer,
                Dependency,
                SBOM,
                License,
                SupplyChainRisk,
            )

            return HandlerResponse.success({
                "status": "ok",
                "module": "sbom",
                "components": {
                    "DependencyParser": DependencyParser is not None,
                    "SBOMGenerator": SBOMGenerator is not None,
                    "LicenseAnalyzer": LicenseAnalyzer is not None,
                    "SupplyChainAnalyzer": SupplyChainAnalyzer is not None,
                },
                "dataclasses": {
                    "Dependency": Dependency is not None,
                    "SBOM": SBOM is not None,
                    "License": License is not None,
                    "SupplyChainRisk": SupplyChainRisk is not None,
                },
                "capabilities": [
                    "dependency_parsing",
                    "sbom_generation",
                    "license_analysis",
                    "supply_chain_risk",
                ],
            })
        except ImportError as e:
            return HandlerResponse.success({"status": "error", "error": str(e)})

    @route("summary")
    def sbom_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get comprehensive SBOM module summary."""
        return HandlerResponse.success({
            "overview": {
                "description": "Software Bill of Materials for supply chain security",
                "purpose": "Generate, analyze, and validate software dependencies",
                "standards": ["CycloneDX 1.5", "SPDX 2.3"],
            },
            "features": [
                "Multi-ecosystem dependency parsing",
                "SBOM generation in multiple formats",
                "License identification and compliance",
                "Supply chain risk assessment",
                "Typosquatting detection",
                "Deprecated package detection",
                "Package URL (purl) generation",
                "License compatibility checking",
            ],
            "supported_ecosystems": ["NPM", "PyPI", "Go", "Cargo", "RubyGems", "Composer"],
            "supported_formats": ["CycloneDX JSON", "CycloneDX XML", "SPDX JSON", "SPDX Tag-Value", "Stance Native"],
            "architecture": {
                "parsers": ["DependencyParser"],
                "generators": ["SBOMGenerator"],
                "analyzers": ["LicenseAnalyzer", "SupplyChainAnalyzer"],
            },
        })

    @route("graph")
    def sbom_graph(self, params: dict, body: dict | None) -> HandlerResponse:
        """Build and return dependency graph from a dependency file."""
        try:
            from stance.sbom import (
                DependencyParser,
                DependencyGraphBuilder,
            )

            file_path = self.get_param(params, "file", "")
            output_format = self.get_param(params, "format", "json")
            max_depth_str = self.get_param(params, "max_depth", "")

            if not file_path:
                return HandlerResponse.error("file parameter is required", HttpStatus.BAD_REQUEST)

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Build graph
            builder = DependencyGraphBuilder()
            graph = builder.build_from_file(dep_file)

            # Convert max_depth to int if provided
            depth = int(max_depth_str) if max_depth_str else None

            # Return in requested format
            if output_format == "tree":
                return HandlerResponse.success({
                    "format": "tree",
                    "tree": graph.to_tree_string(max_depth=depth),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                })
            elif output_format == "dot":
                return HandlerResponse.success({
                    "format": "dot",
                    "dot": graph.to_dot(),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                })
            elif output_format == "mermaid":
                return HandlerResponse.success({
                    "format": "mermaid",
                    "mermaid": graph.to_mermaid(),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                })
            else:
                # JSON format (default)
                return HandlerResponse.success({
                    "format": "json",
                    "graph": graph.to_dict(),
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                })

        except FileNotFoundError:
            return HandlerResponse.not_found(f"File: {file_path}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("graph-metrics")
    def sbom_graph_metrics(self, params: dict, body: dict | None) -> HandlerResponse:
        """Compute and return dependency graph metrics."""
        try:
            from stance.sbom import (
                DependencyParser,
                DependencyGraphBuilder,
            )

            file_path = self.get_param(params, "file", "")

            if not file_path:
                return HandlerResponse.error("file parameter is required", HttpStatus.BAD_REQUEST)

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Build graph
            builder = DependencyGraphBuilder()
            graph = builder.build_from_file(dep_file)

            # Compute metrics
            metrics = graph.compute_metrics()

            # Detect cycles
            cycles = graph.detect_cycles()

            return HandlerResponse.success({
                "metrics": {
                    "total_nodes": metrics.total_nodes,
                    "total_edges": metrics.total_edges,
                    "max_depth": metrics.max_depth,
                    "avg_depth": metrics.avg_depth,
                    "has_cycles": metrics.has_cycles,
                    "cycle_count": metrics.cycle_count,
                    "max_in_degree": metrics.max_in_degree,
                    "max_out_degree": metrics.max_out_degree,
                    "hub_nodes": metrics.hub_nodes,
                },
                "cycles": [
                    {
                        "nodes": cycle.nodes,
                        "length": cycle.length,
                    }
                    for cycle in cycles
                ],
            })

        except FileNotFoundError:
            return HandlerResponse.not_found(f"File: {file_path}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("attest")
    def sbom_attest(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create SBOM attestation."""
        try:
            from stance.sbom import (
                DependencyParser,
                SBOMGenerator,
                SBOMFormat,
                create_sbom_attestation,
            )

            file_path = self.get_param(params, "file", "")
            signer_name = self.get_param(params, "signer", "Mantissa Stance")
            secret_key = self.get_param(params, "key", "")

            if not file_path:
                return HandlerResponse.error("file parameter is required", HttpStatus.BAD_REQUEST)

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Generate SBOM
            generator = SBOMGenerator()
            sbom = generator.generate(dep_file, format=SBOMFormat.CYCLONEDX_JSON)

            # Create attestation
            attestation = create_sbom_attestation(
                sbom_data=sbom.to_dict(),
                sbom_file_path=file_path,
                signer_name=signer_name,
                secret_key=secret_key if secret_key else None,
            )

            return HandlerResponse.success({
                "attestation": attestation.to_dict(),
                "envelope": attestation.to_dsse_envelope(),
            })

        except FileNotFoundError:
            return HandlerResponse.not_found(f"File: {file_path}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("attest-verify")
    def sbom_attest_verify(self, params: dict, body: dict | None) -> HandlerResponse:
        """Verify SBOM attestation."""
        try:
            from stance.sbom import (
                AttestationVerifier,
                Attestation,
            )
            import json

            attestation_data = self.get_param(params, "attestation", "")
            secret_key = self.get_param(params, "key", "")

            if not attestation_data:
                return HandlerResponse.error("attestation parameter is required", HttpStatus.BAD_REQUEST)

            # Parse attestation data
            if isinstance(attestation_data, str):
                attestation_dict = json.loads(attestation_data)
            else:
                attestation_dict = attestation_data

            # Reconstruct attestation
            attestation = Attestation.from_dict(attestation_dict)

            # Verify
            verifier = AttestationVerifier()
            result = verifier.verify(attestation, secret_key=secret_key if secret_key else None)

            return HandlerResponse.success({
                "verification": {
                    "is_valid": result.is_valid,
                    "status": result.status.value,
                    "message": result.message,
                    "verified_at": result.verified_at.isoformat() if result.verified_at else None,
                    "details": result.details,
                },
            })

        except json.JSONDecodeError:
            return HandlerResponse.error("Invalid attestation JSON")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("vex")
    def sbom_vex(self, params: dict, body: dict | None) -> HandlerResponse:
        """Generate VEX document for dependencies."""
        try:
            from stance.sbom import (
                DependencyParser,
                VulnerabilityScanner,
                VEXGenerator,
            )

            file_path = self.get_param(params, "file", "")
            output_format = self.get_param(params, "format", "openvex")
            product_name = self.get_param(params, "product", "Unknown Product")

            if not file_path:
                return HandlerResponse.error("file parameter is required", HttpStatus.BAD_REQUEST)

            # Parse dependencies
            parser = DependencyParser()
            dep_file = parser.parse_file(file_path)

            # Scan for vulnerabilities
            scanner = VulnerabilityScanner()
            scan_result = scanner.scan_dependencies(dep_file.dependencies)

            # Generate VEX
            generator = VEXGenerator()
            vex_doc = generator.generate_from_scan_result(
                scan_result=scan_result,
                product_name=product_name,
            )

            # Return in requested format
            if output_format == "cyclonedx":
                return HandlerResponse.success({
                    "format": "cyclonedx",
                    "vex": vex_doc.to_cyclonedx_vex(),
                    "statement_count": len(vex_doc.statements),
                })
            elif output_format == "csaf":
                return HandlerResponse.success({
                    "format": "csaf",
                    "vex": vex_doc.to_csaf_vex(),
                    "statement_count": len(vex_doc.statements),
                })
            else:
                # OpenVEX (default)
                return HandlerResponse.success({
                    "format": "openvex",
                    "vex": vex_doc.to_openvex(),
                    "statement_count": len(vex_doc.statements),
                })

        except FileNotFoundError:
            return HandlerResponse.not_found(f"File: {file_path}")
        except Exception as e:
            return HandlerResponse.error(str(e))

    @route("vex-formats")
    def sbom_vex_formats(self, params: dict, body: dict | None) -> HandlerResponse:
        """Return supported VEX formats."""
        return HandlerResponse.success({
            "formats": [
                {
                    "id": "openvex",
                    "name": "OpenVEX",
                    "description": "Open VEX format (default)",
                    "spec_url": "https://openvex.dev/",
                },
                {
                    "id": "cyclonedx",
                    "name": "CycloneDX VEX",
                    "description": "CycloneDX VEX format",
                    "spec_url": "https://cyclonedx.org/capabilities/vex/",
                },
                {
                    "id": "csaf",
                    "name": "CSAF VEX",
                    "description": "Common Security Advisory Framework VEX",
                    "spec_url": "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html",
                },
            ],
            "total": 3,
        })
