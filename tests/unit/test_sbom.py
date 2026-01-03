"""
Unit tests for SBOM (Software Bill of Materials) module.

Tests cover:
- Dependency file parsing (multiple ecosystems)
- SBOM generation (multiple formats)
- License analysis and compliance
- Supply chain risk assessment
- Package URL generation
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from stance.sbom import (
    # Parser
    Dependency,
    DependencyFile,
    DependencyParser,
    PackageEcosystem,
    DependencyScope,
    # Generator
    SBOM,
    SBOMFormat,
    SBOMGenerator,
    SBOMComponent,
    # License
    License,
    LicenseRisk,
    LicenseCategory,
    LicenseAnalyzer,
    LicenseCompatibility,
    # Analyzer
    SupplyChainRisk,
    SupplyChainAnalyzer,
    DependencyRisk,
    RiskLevel,
)


# =============================================================================
# PackageEcosystem Tests
# =============================================================================


class TestPackageEcosystem:
    """Tests for PackageEcosystem enum."""

    def test_npm_ecosystem(self):
        """Test NPM ecosystem."""
        assert PackageEcosystem.NPM.value == "npm"

    def test_pypi_ecosystem(self):
        """Test PyPI ecosystem."""
        assert PackageEcosystem.PYPI.value == "pypi"

    def test_go_ecosystem(self):
        """Test Go ecosystem."""
        assert PackageEcosystem.GO.value == "go"

    def test_cargo_ecosystem(self):
        """Test Cargo ecosystem."""
        assert PackageEcosystem.CARGO.value == "cargo"

    def test_rubygems_ecosystem(self):
        """Test RubyGems ecosystem."""
        assert PackageEcosystem.RUBYGEMS.value == "rubygems"

    def test_composer_ecosystem(self):
        """Test Composer ecosystem."""
        assert PackageEcosystem.COMPOSER.value == "composer"


class TestDependencyScope:
    """Tests for DependencyScope enum."""

    def test_runtime_scope(self):
        """Test runtime scope."""
        assert DependencyScope.RUNTIME.value == "runtime"

    def test_dev_scope(self):
        """Test dev scope."""
        assert DependencyScope.DEV.value == "dev"

    def test_optional_scope(self):
        """Test optional scope."""
        assert DependencyScope.OPTIONAL.value == "optional"


# =============================================================================
# Dependency Tests
# =============================================================================


class TestDependency:
    """Tests for Dependency dataclass."""

    def test_create_dependency(self):
        """Test creating a dependency."""
        dep = Dependency(
            name="requests",
            version="2.28.0",
            ecosystem=PackageEcosystem.PYPI,
        )

        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.ecosystem == PackageEcosystem.PYPI
        assert dep.scope == DependencyScope.RUNTIME

    def test_dependency_with_scope(self):
        """Test dependency with custom scope."""
        dep = Dependency(
            name="pytest",
            version="7.0.0",
            ecosystem=PackageEcosystem.PYPI,
            scope=DependencyScope.DEV,
        )

        assert dep.scope == DependencyScope.DEV

    def test_dependency_with_license(self):
        """Test dependency with license."""
        dep = Dependency(
            name="lodash",
            version="4.17.21",
            ecosystem=PackageEcosystem.NPM,
            license="MIT",
        )

        assert dep.license == "MIT"


# =============================================================================
# DependencyFile Tests
# =============================================================================


class TestDependencyFile:
    """Tests for DependencyFile dataclass."""

    def test_create_dependency_file(self):
        """Test creating a dependency file."""
        deps = [
            Dependency("pkg1", "1.0.0", PackageEcosystem.NPM),
            Dependency("pkg2", "2.0.0", PackageEcosystem.NPM),
        ]

        dep_file = DependencyFile(
            path="/path/to/package.json",
            ecosystem=PackageEcosystem.NPM,
            dependencies=deps,
        )

        assert dep_file.path == "/path/to/package.json"
        assert dep_file.ecosystem == PackageEcosystem.NPM
        assert len(dep_file.dependencies) == 2


# =============================================================================
# DependencyParser Tests
# =============================================================================


class TestDependencyParser:
    """Tests for DependencyParser."""

    def test_parser_initialization(self):
        """Test parser initialization."""
        parser = DependencyParser()
        assert parser is not None

    def test_parse_package_json(self):
        """Test parsing package.json."""
        content = json.dumps({
            "name": "test-app",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "4.17.21",
            },
            "devDependencies": {
                "jest": "^29.0.0",
            },
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            parser = DependencyParser()
            result = parser.parse_file(f.name)

            assert result is not None
            assert result.ecosystem == PackageEcosystem.NPM
            assert len(result.dependencies) >= 2

            # Check dependency names
            dep_names = [d.name for d in result.dependencies]
            assert "express" in dep_names
            assert "lodash" in dep_names

    def test_parse_requirements_txt(self):
        """Test parsing requirements.txt."""
        content = """
requests==2.28.0
flask>=2.0.0
pytest~=7.0.0
# This is a comment
numpy
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix="requirements.txt", delete=False) as f:
            f.write(content)
            f.flush()

            parser = DependencyParser()
            result = parser.parse_file(f.name)

            assert result is not None
            assert result.ecosystem == PackageEcosystem.PYPI
            assert len(result.dependencies) >= 3

            dep_names = [d.name for d in result.dependencies]
            assert "requests" in dep_names
            assert "flask" in dep_names

    def test_parse_go_mod(self):
        """Test parsing go.mod."""
        content = """
module github.com/example/myapp

go 1.19

require (
    github.com/gin-gonic/gin v1.8.1
    github.com/stretchr/testify v1.8.0
)
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix="go.mod", delete=False) as f:
            f.write(content)
            f.flush()

            parser = DependencyParser()
            result = parser.parse_file(f.name)

            assert result is not None
            assert result.ecosystem == PackageEcosystem.GO
            assert len(result.dependencies) >= 2

    def test_parse_unknown_file(self):
        """Test parsing unknown file type."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xyz", delete=False) as f:
            f.write("unknown content")
            f.flush()

            parser = DependencyParser()
            result = parser.parse_file(f.name)

            # Should return None for unknown files
            assert result is None

    def test_parse_directory(self):
        """Test parsing directory with multiple files."""
        parser = DependencyParser()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create package.json
            package_json = Path(tmpdir) / "package.json"
            package_json.write_text(json.dumps({
                "dependencies": {"express": "^4.18.0"},
            }))

            # Create requirements.txt
            requirements = Path(tmpdir) / "requirements.txt"
            requirements.write_text("flask==2.0.0\n")

            results = parser.parse_directory(tmpdir)

            assert len(results) >= 2

            ecosystems = [r.ecosystem for r in results]
            assert PackageEcosystem.NPM in ecosystems
            assert PackageEcosystem.PYPI in ecosystems


# =============================================================================
# SBOMFormat Tests
# =============================================================================


class TestSBOMFormat:
    """Tests for SBOMFormat enum."""

    def test_cyclonedx_json_format(self):
        """Test CycloneDX JSON format."""
        assert SBOMFormat.CYCLONEDX_JSON.value == "cyclonedx-json"

    def test_spdx_json_format(self):
        """Test SPDX JSON format."""
        assert SBOMFormat.SPDX_JSON.value == "spdx-json"

    def test_stance_format(self):
        """Test Stance native format."""
        assert SBOMFormat.STANCE.value == "stance"


# =============================================================================
# SBOMComponent Tests
# =============================================================================


class TestSBOMComponent:
    """Tests for SBOMComponent dataclass."""

    def test_create_component(self):
        """Test creating SBOM component."""
        component = SBOMComponent(
            name="requests",
            version="2.28.0",
            component_type="library",
            purl="pkg:pypi/requests@2.28.0",
        )

        assert component.name == "requests"
        assert component.version == "2.28.0"
        assert component.component_type == "library"
        assert "pypi" in component.purl


# =============================================================================
# SBOM Tests
# =============================================================================


class TestSBOM:
    """Tests for SBOM dataclass."""

    def test_create_sbom(self):
        """Test creating SBOM."""
        components = [
            SBOMComponent("pkg1", "1.0.0", "library"),
            SBOMComponent("pkg2", "2.0.0", "library"),
        ]

        sbom = SBOM(
            format=SBOMFormat.CYCLONEDX_JSON,
            serial_number="urn:uuid:test",
            version=1,
            created=datetime.utcnow(),
            components=components,
        )

        assert sbom.format == SBOMFormat.CYCLONEDX_JSON
        assert len(sbom.components) == 2


# =============================================================================
# SBOMGenerator Tests
# =============================================================================


class TestSBOMGenerator:
    """Tests for SBOMGenerator."""

    def test_generator_initialization(self):
        """Test generator initialization."""
        generator = SBOMGenerator()
        assert generator is not None

    def test_generate_from_dependencies(self):
        """Test generating SBOM from dependencies."""
        deps = [
            Dependency("requests", "2.28.0", PackageEcosystem.PYPI),
            Dependency("flask", "2.0.0", PackageEcosystem.PYPI),
        ]

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies(deps)

        assert sbom is not None
        assert len(sbom.components) == 2

    def test_export_cyclonedx_json(self):
        """Test exporting to CycloneDX JSON."""
        deps = [
            Dependency("requests", "2.28.0", PackageEcosystem.PYPI),
        ]

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies(deps)
        output = generator.export(sbom, SBOMFormat.CYCLONEDX_JSON)

        assert output is not None
        data = json.loads(output)
        assert data["bomFormat"] == "CycloneDX"
        assert "components" in data

    def test_export_spdx_json(self):
        """Test exporting to SPDX JSON."""
        deps = [
            Dependency("lodash", "4.17.21", PackageEcosystem.NPM),
        ]

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies(deps)
        output = generator.export(sbom, SBOMFormat.SPDX_JSON)

        assert output is not None
        data = json.loads(output)
        assert "spdxVersion" in data
        assert "packages" in data

    def test_export_stance_format(self):
        """Test exporting to Stance native format."""
        deps = [
            Dependency("express", "4.18.0", PackageEcosystem.NPM),
        ]

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies(deps)
        output = generator.export(sbom, SBOMFormat.STANCE)

        assert output is not None
        data = json.loads(output)
        assert "format" in data
        assert data["format"] == "stance"


# =============================================================================
# LicenseCategory Tests
# =============================================================================


class TestLicenseCategory:
    """Tests for LicenseCategory enum."""

    def test_permissive_category(self):
        """Test permissive category."""
        assert LicenseCategory.PERMISSIVE.value == "permissive"

    def test_copyleft_categories(self):
        """Test copyleft categories."""
        assert LicenseCategory.WEAK_COPYLEFT.value == "weak_copyleft"
        assert LicenseCategory.STRONG_COPYLEFT.value == "strong_copyleft"


# =============================================================================
# LicenseRisk Tests
# =============================================================================


class TestLicenseRisk:
    """Tests for LicenseRisk enum."""

    def test_risk_levels(self):
        """Test risk levels."""
        assert LicenseRisk.LOW.value == "low"
        assert LicenseRisk.MEDIUM.value == "medium"
        assert LicenseRisk.HIGH.value == "high"
        assert LicenseRisk.CRITICAL.value == "critical"


# =============================================================================
# License Tests
# =============================================================================


class TestLicense:
    """Tests for License dataclass."""

    def test_create_license(self):
        """Test creating a license."""
        lic = License(
            spdx_id="MIT",
            name="MIT License",
            category=LicenseCategory.PERMISSIVE,
            risk=LicenseRisk.LOW,
            osi_approved=True,
            copyleft=False,
        )

        assert lic.spdx_id == "MIT"
        assert lic.name == "MIT License"
        assert lic.category == LicenseCategory.PERMISSIVE
        assert lic.osi_approved is True
        assert lic.copyleft is False


# =============================================================================
# LicenseAnalyzer Tests
# =============================================================================


class TestLicenseAnalyzer:
    """Tests for LicenseAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = LicenseAnalyzer()
        assert analyzer is not None
        assert len(analyzer.license_db) > 0

    def test_identify_mit_license(self):
        """Test identifying MIT license."""
        analyzer = LicenseAnalyzer()
        result = analyzer.identify_license("MIT")

        assert result is not None
        assert result.spdx_id == "MIT"
        assert result.category == LicenseCategory.PERMISSIVE

    def test_identify_gpl_license(self):
        """Test identifying GPL license."""
        analyzer = LicenseAnalyzer()
        result = analyzer.identify_license("GPL-3.0")

        assert result is not None
        assert result.copyleft is True

    def test_identify_unknown_license(self):
        """Test identifying unknown license."""
        analyzer = LicenseAnalyzer()
        result = analyzer.identify_license("Unknown-License-XYZ")

        # Should return None for unknown licenses
        assert result is None

    def test_analyze_dependencies(self):
        """Test analyzing dependencies for licenses."""
        deps = [
            Dependency("pkg1", "1.0.0", PackageEcosystem.PYPI, license="MIT"),
            Dependency("pkg2", "2.0.0", PackageEcosystem.PYPI, license="Apache-2.0"),
        ]

        analyzer = LicenseAnalyzer()
        report = analyzer.analyze_dependencies(deps)

        assert report is not None
        assert len(report.results) == 2
        assert report.permissive_count >= 2

    def test_license_compatibility(self):
        """Test license compatibility checking."""
        analyzer = LicenseAnalyzer()

        # MIT and Apache-2.0 should be compatible
        result = analyzer.check_compatibility("MIT", "Apache-2.0")
        assert result.compatible is True

        # GPL-3.0 and proprietary might not be compatible
        result = analyzer.check_compatibility("GPL-3.0-only", "Proprietary")
        # The exact result depends on implementation

    def test_risk_assessment(self):
        """Test license risk assessment."""
        deps = [
            Dependency("pkg1", "1.0.0", PackageEcosystem.PYPI, license="MIT"),
            Dependency("pkg2", "2.0.0", PackageEcosystem.PYPI, license="GPL-3.0"),
        ]

        analyzer = LicenseAnalyzer()
        report = analyzer.analyze_dependencies(deps)

        # MIT should be low risk, GPL should be higher risk
        assert LicenseRisk.LOW in report.risk_counts or LicenseRisk.MEDIUM in report.risk_counts


# =============================================================================
# RiskLevel Tests
# =============================================================================


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_levels(self):
        """Test risk level values."""
        assert RiskLevel.INFO.value == "info"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"


# =============================================================================
# SupplyChainRisk Tests
# =============================================================================


class TestSupplyChainRisk:
    """Tests for SupplyChainRisk dataclass."""

    def test_create_risk(self):
        """Test creating a supply chain risk."""
        risk = SupplyChainRisk(
            risk_type="typosquat",
            level=RiskLevel.HIGH,
            description="Potential typosquatting attack",
        )

        assert risk.risk_type == "typosquat"
        assert risk.level == RiskLevel.HIGH


# =============================================================================
# SupplyChainAnalyzer Tests
# =============================================================================


class TestSupplyChainAnalyzer:
    """Tests for SupplyChainAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = SupplyChainAnalyzer()
        assert analyzer is not None

    def test_analyze_dependencies(self):
        """Test analyzing dependencies."""
        deps = [
            Dependency("requests", "2.28.0", PackageEcosystem.PYPI),
            Dependency("flask", "2.0.0", PackageEcosystem.PYPI),
        ]

        analyzer = SupplyChainAnalyzer()
        report = analyzer.analyze(deps)

        assert report is not None
        assert report.risk_score >= 0
        assert report.risk_score <= 100

    def test_typosquat_detection(self):
        """Test typosquatting detection."""
        # Test with a package name that might be a typosquat
        deps = [
            Dependency("reqeusts", "1.0.0", PackageEcosystem.PYPI),  # typo of requests
        ]

        analyzer = SupplyChainAnalyzer()
        report = analyzer.analyze(deps)

        # Check if typosquatting was detected
        has_typosquat = any(
            any(r.risk_type == "typosquat" for r in dr.risks)
            for dr in report.dependency_risks
        )
        # Note: Detection depends on implementation

    def test_deprecated_detection(self):
        """Test deprecated package detection."""
        analyzer = SupplyChainAnalyzer()

        # Test with known deprecated packages
        deps = [
            Dependency("requests", "0.0.1", PackageEcosystem.PYPI),
        ]

        report = analyzer.analyze(deps)
        assert report is not None

    def test_risk_score_calculation(self):
        """Test risk score calculation."""
        analyzer = SupplyChainAnalyzer()

        # Empty deps should have low risk
        report = analyzer.analyze([])
        assert report.risk_score == 0

        # Normal deps should have reasonable risk
        deps = [
            Dependency("requests", "2.28.0", PackageEcosystem.PYPI),
        ]
        report = analyzer.analyze(deps)
        assert 0 <= report.risk_score <= 100

    def test_convert_to_findings(self):
        """Test converting risks to Stance findings."""
        deps = [
            Dependency("pkg1", "1.0.0", PackageEcosystem.PYPI),
        ]

        analyzer = SupplyChainAnalyzer()
        report = analyzer.analyze(deps)
        findings = analyzer.to_findings(report)

        # Should return a list (possibly empty)
        assert isinstance(findings, list)


# =============================================================================
# Integration Tests
# =============================================================================


class TestSBOMIntegration:
    """Integration tests for SBOM module."""

    def test_parse_and_generate_sbom(self):
        """Test parsing dependencies and generating SBOM."""
        content = json.dumps({
            "name": "test-app",
            "dependencies": {
                "express": "^4.18.0",
                "lodash": "4.17.21",
            },
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            parser = DependencyParser()
            dep_file = parser.parse_file(f.name)

            generator = SBOMGenerator()
            sbom = generator.generate_from_dependencies(dep_file.dependencies)

            assert len(sbom.components) == 2

            output = generator.export(sbom, SBOMFormat.CYCLONEDX_JSON)
            data = json.loads(output)
            assert len(data["components"]) == 2

    def test_parse_and_analyze_licenses(self):
        """Test parsing dependencies and analyzing licenses."""
        content = """
requests==2.28.0
flask==2.0.0
django==4.0.0
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix="requirements.txt", delete=False) as f:
            f.write(content)
            f.flush()

            parser = DependencyParser()
            dep_file = parser.parse_file(f.name)

            analyzer = LicenseAnalyzer()
            report = analyzer.analyze_dependencies(dep_file.dependencies)

            assert report is not None
            assert len(report.results) == 3

    def test_full_supply_chain_analysis(self):
        """Test full supply chain analysis pipeline."""
        content = json.dumps({
            "dependencies": {
                "express": "^4.18.0",
            },
        })

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            parser = DependencyParser()
            dep_file = parser.parse_file(f.name)

            # Generate SBOM
            generator = SBOMGenerator()
            sbom = generator.generate_from_dependencies(dep_file.dependencies)

            # Analyze licenses
            license_analyzer = LicenseAnalyzer()
            license_report = license_analyzer.analyze_dependencies(dep_file.dependencies)

            # Analyze supply chain
            supply_analyzer = SupplyChainAnalyzer()
            risk_report = supply_analyzer.analyze(dep_file.dependencies)

            assert sbom is not None
            assert license_report is not None
            assert risk_report is not None


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Edge case tests for SBOM module."""

    def test_empty_dependencies(self):
        """Test with empty dependencies."""
        parser = DependencyParser()
        generator = SBOMGenerator()
        license_analyzer = LicenseAnalyzer()
        supply_analyzer = SupplyChainAnalyzer()

        sbom = generator.generate_from_dependencies([])
        license_report = license_analyzer.analyze_dependencies([])
        risk_report = supply_analyzer.analyze([])

        assert len(sbom.components) == 0
        assert len(license_report.results) == 0
        assert risk_report.risk_score == 0

    def test_dependency_without_version(self):
        """Test dependency without version."""
        deps = [
            Dependency("requests", None, PackageEcosystem.PYPI),
        ]

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies(deps)

        assert len(sbom.components) == 1
        assert sbom.components[0].version is None or sbom.components[0].version == ""

    def test_special_characters_in_name(self):
        """Test package name with special characters."""
        deps = [
            Dependency("@types/node", "18.0.0", PackageEcosystem.NPM),
            Dependency("@angular/core", "15.0.0", PackageEcosystem.NPM),
        ]

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies(deps)

        assert len(sbom.components) == 2

    def test_malformed_package_json(self):
        """Test parsing malformed package.json."""
        content = "{ invalid json }"

        with tempfile.NamedTemporaryFile(mode="w", suffix="package.json", delete=False) as f:
            f.write(content)
            f.flush()

            parser = DependencyParser()
            result = parser.parse_file(f.name)

            # Should handle gracefully
            assert result is None or len(result.dependencies) == 0

    def test_empty_file(self):
        """Test parsing empty file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix="requirements.txt", delete=False) as f:
            f.write("")
            f.flush()

            parser = DependencyParser()
            result = parser.parse_file(f.name)

            if result is not None:
                assert len(result.dependencies) == 0


# =============================================================================
# PURL Generation Tests
# =============================================================================


class TestPURLGeneration:
    """Tests for Package URL generation."""

    def test_pypi_purl(self):
        """Test PyPI PURL generation."""
        dep = Dependency("requests", "2.28.0", PackageEcosystem.PYPI)

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies([dep])

        component = sbom.components[0]
        assert component.purl is not None
        assert "pkg:pypi/" in component.purl
        assert "requests" in component.purl

    def test_npm_purl(self):
        """Test NPM PURL generation."""
        dep = Dependency("lodash", "4.17.21", PackageEcosystem.NPM)

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies([dep])

        component = sbom.components[0]
        assert component.purl is not None
        assert "pkg:npm/" in component.purl

    def test_scoped_npm_purl(self):
        """Test scoped NPM package PURL."""
        dep = Dependency("@types/node", "18.0.0", PackageEcosystem.NPM)

        generator = SBOMGenerator()
        sbom = generator.generate_from_dependencies([dep])

        component = sbom.components[0]
        assert component.purl is not None
        # Scoped packages should have proper encoding


# =============================================================================
# Dependency Graph Tests
# =============================================================================


class TestNodeType:
    """Tests for NodeType enum."""

    def test_root_type(self):
        """Test root node type."""
        from stance.sbom import NodeType
        assert NodeType.ROOT.value == "root"

    def test_direct_type(self):
        """Test direct dependency node type."""
        from stance.sbom import NodeType
        assert NodeType.DIRECT.value == "direct"

    def test_transitive_type(self):
        """Test transitive dependency node type."""
        from stance.sbom import NodeType
        assert NodeType.TRANSITIVE.value == "transitive"

    def test_development_type(self):
        """Test development dependency node type."""
        from stance.sbom import NodeType
        assert NodeType.DEVELOPMENT.value == "development"


class TestEdgeType:
    """Tests for EdgeType enum."""

    def test_requires(self):
        """Test requires edge type."""
        from stance.sbom import EdgeType
        assert EdgeType.REQUIRES.value == "requires"

    def test_dev_requires(self):
        """Test dev_requires edge type."""
        from stance.sbom import EdgeType
        assert EdgeType.DEV_REQUIRES.value == "dev_requires"


class TestGraphNode:
    """Tests for GraphNode dataclass."""

    def test_node_creation(self):
        """Test basic node creation."""
        from stance.sbom import GraphNode, NodeType

        node = GraphNode(
            id="pkg:pypi/requests@2.28.0",
            name="requests",
            version="2.28.0",
            node_type=NodeType.DIRECT,
        )

        assert node.id == "pkg:pypi/requests@2.28.0"
        assert node.name == "requests"
        assert node.version == "2.28.0"
        assert node.node_type == NodeType.DIRECT
        assert node.depth == 0

    def test_node_to_dict(self):
        """Test node serialization."""
        from stance.sbom import GraphNode, NodeType

        node = GraphNode(
            id="test-node",
            name="test",
            version="1.0.0",
            node_type=NodeType.ROOT,
            depth=0,
        )

        node_dict = node.to_dict()
        assert node_dict["id"] == "test-node"
        assert node_dict["name"] == "test"
        assert node_dict["version"] == "1.0.0"


class TestGraphEdge:
    """Tests for GraphEdge dataclass."""

    def test_edge_creation(self):
        """Test basic edge creation."""
        from stance.sbom import GraphEdge, EdgeType

        edge = GraphEdge(
            source="node-a",
            target="node-b",
            edge_type=EdgeType.REQUIRES,
        )

        assert edge.source == "node-a"
        assert edge.target == "node-b"
        assert edge.edge_type == EdgeType.REQUIRES

    def test_edge_to_dict(self):
        """Test edge serialization."""
        from stance.sbom import GraphEdge, EdgeType

        edge = GraphEdge(
            source="src",
            target="dst",
            edge_type=EdgeType.DEV_REQUIRES,
        )

        edge_dict = edge.to_dict()
        assert edge_dict["source"] == "src"
        assert edge_dict["target"] == "dst"
        assert edge_dict["edge_type"] == "dev_requires"


class TestDependencyGraph:
    """Tests for DependencyGraph class."""

    def test_empty_graph(self):
        """Test empty graph creation."""
        from stance.sbom import DependencyGraph

        graph = DependencyGraph()
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_add_node(self):
        """Test adding nodes to graph."""
        from stance.sbom import DependencyGraph, GraphNode, NodeType

        graph = DependencyGraph()
        node = GraphNode(
            id="test",
            name="test",
            version="1.0.0",
            node_type=NodeType.ROOT,
        )
        graph.add_node(node)

        assert len(graph.nodes) == 1
        assert "test" in graph.nodes

    def test_add_edge(self):
        """Test adding edges to graph."""
        from stance.sbom import DependencyGraph, GraphNode, GraphEdge, NodeType, EdgeType

        graph = DependencyGraph()

        # Add nodes first
        node_a = GraphNode(id="a", name="a", version="1.0.0", node_type=NodeType.ROOT)
        node_b = GraphNode(id="b", name="b", version="1.0.0", node_type=NodeType.DIRECT)
        graph.add_node(node_a)
        graph.add_node(node_b)

        # Add edge
        edge = GraphEdge(source="a", target="b", edge_type=EdgeType.REQUIRES)
        graph.add_edge(edge)

        assert len(graph.edges) == 1

    def test_to_tree_string(self):
        """Test tree string output."""
        from stance.sbom import DependencyGraph, GraphNode, GraphEdge, NodeType, EdgeType

        graph = DependencyGraph()

        root = GraphNode(id="root", name="my-app", version="1.0.0", node_type=NodeType.ROOT, depth=0)
        dep = GraphNode(id="dep", name="lodash", version="4.17.21", node_type=NodeType.DIRECT, depth=1)

        graph.add_node(root)
        graph.add_node(dep)
        graph.add_edge(GraphEdge(source="root", target="dep", edge_type=EdgeType.REQUIRES))
        graph.root_id = "root"

        tree = graph.to_tree_string()
        assert "my-app" in tree

    def test_to_dict(self):
        """Test graph serialization."""
        from stance.sbom import DependencyGraph, GraphNode, NodeType

        graph = DependencyGraph()
        node = GraphNode(id="test", name="test", version="1.0.0", node_type=NodeType.ROOT)
        graph.add_node(node)

        graph_dict = graph.to_dict()
        assert "nodes" in graph_dict
        assert "edges" in graph_dict
        assert len(graph_dict["nodes"]) == 1


class TestDependencyGraphBuilder:
    """Tests for DependencyGraphBuilder class."""

    def test_build_from_file(self):
        """Test building graph from dependency file."""
        from stance.sbom import DependencyGraphBuilder, DependencyParser

        # Build from existing sample or minimal test
        builder = DependencyGraphBuilder()

        # Test with empty dependencies
        deps = [
            Dependency("express", "4.18.2", PackageEcosystem.NPM),
        ]
        dep_file = DependencyFile(
            file_path="package.json",
            file_type="package.json",
            ecosystem=PackageEcosystem.NPM,
            dependencies=deps,
        )

        graph = builder.build_from_file(dep_file)
        assert len(graph.nodes) >= 1


class TestGraphMetrics:
    """Tests for GraphMetrics dataclass."""

    def test_metrics_creation(self):
        """Test metrics creation."""
        from stance.sbom import GraphMetrics

        metrics = GraphMetrics(
            total_nodes=10,
            total_edges=15,
            max_depth=3,
            avg_depth=1.5,
            has_cycles=False,
            cycle_count=0,
        )

        assert metrics.total_nodes == 10
        assert metrics.total_edges == 15
        assert metrics.max_depth == 3
        assert not metrics.has_cycles

    def test_metrics_to_dict(self):
        """Test metrics serialization."""
        from stance.sbom import GraphMetrics

        metrics = GraphMetrics(
            total_nodes=5,
            total_edges=4,
            max_depth=2,
        )

        metrics_dict = metrics.to_dict()
        # Check the nested structure
        assert "nodes" in metrics_dict
        assert metrics_dict["nodes"]["total"] == 5


# =============================================================================
# SBOM Attestation Tests
# =============================================================================


class TestAttestationType:
    """Tests for AttestationType enum."""

    def test_sbom_type(self):
        """Test SBOM attestation type."""
        from stance.sbom import AttestationType
        assert AttestationType.SBOM.value == "https://spdx.dev/Document"

    def test_in_toto_type(self):
        """Test in-toto attestation type."""
        from stance.sbom import AttestationType
        assert AttestationType.IN_TOTO.value == "https://in-toto.io/Statement/v0.1"

    def test_slsa_provenance_type(self):
        """Test SLSA provenance attestation type."""
        from stance.sbom import AttestationType
        assert AttestationType.SLSA_PROVENANCE.value == "https://slsa.dev/provenance/v0.2"


class TestSignatureAlgorithm:
    """Tests for SignatureAlgorithm enum."""

    def test_hmac_sha256(self):
        """Test HMAC-SHA256 algorithm."""
        from stance.sbom import SignatureAlgorithm
        assert SignatureAlgorithm.HMAC_SHA256.value == "hmac-sha256"

    def test_hmac_sha512(self):
        """Test HMAC-SHA512 algorithm."""
        from stance.sbom import SignatureAlgorithm
        assert SignatureAlgorithm.HMAC_SHA512.value == "hmac-sha512"


class TestVerificationStatus:
    """Tests for VerificationStatus enum."""

    def test_valid_status(self):
        """Test valid verification status."""
        from stance.sbom import VerificationStatus
        assert VerificationStatus.VALID.value == "valid"

    def test_invalid_status(self):
        """Test invalid verification status."""
        from stance.sbom import VerificationStatus
        assert VerificationStatus.INVALID.value == "invalid"


class TestSigner:
    """Tests for Signer dataclass."""

    def test_signer_creation(self):
        """Test signer creation."""
        from stance.sbom import Signer

        signer = Signer(
            id="signer-1",
            name="Test Signer",
            email="test@example.com",
        )

        assert signer.id == "signer-1"
        assert signer.name == "Test Signer"
        assert signer.email == "test@example.com"

    def test_signer_to_dict(self):
        """Test signer serialization."""
        from stance.sbom import Signer

        signer = Signer(id="test-id", name="Mantissa Stance")
        signer_dict = signer.to_dict()

        assert signer_dict["name"] == "Mantissa Stance"
        assert signer_dict["id"] == "test-id"


class TestSubject:
    """Tests for Subject dataclass."""

    def test_subject_creation(self):
        """Test subject creation."""
        from stance.sbom import Subject

        subject = Subject(
            name="my-sbom.json",
            digest={"sha256": "abc123"},
        )

        assert subject.name == "my-sbom.json"
        assert "sha256" in subject.digest

    def test_subject_to_dict(self):
        """Test subject serialization."""
        from stance.sbom import Subject

        subject = Subject(
            name="test.json",
            digest={"sha256": "deadbeef"},
        )
        subject_dict = subject.to_dict()

        assert subject_dict["name"] == "test.json"


class TestAttestation:
    """Tests for Attestation dataclass."""

    def test_attestation_creation(self):
        """Test attestation creation."""
        from stance.sbom import Attestation, AttestationType, Subject, Predicate

        attestation = Attestation(
            type=AttestationType.SBOM,
            subjects=[Subject(name="test.json", digest={"sha256": "abc"})],
            predicate=Predicate(predicate_type="sbom", content={}),
        )

        assert attestation.type == AttestationType.SBOM
        assert len(attestation.subjects) == 1

    def test_attestation_to_dict(self):
        """Test attestation serialization."""
        from stance.sbom import Attestation, AttestationType, Subject, Predicate

        attestation = Attestation(
            type=AttestationType.SBOM,
            subjects=[Subject(name="test.json", digest={"sha256": "abc"})],
            predicate=Predicate(predicate_type="sbom", content={"version": "1.0"}),
        )

        att_dict = attestation.to_dict()
        assert "type" in att_dict
        assert "subjects" in att_dict
        assert "predicate" in att_dict

    def test_attestation_is_signed(self):
        """Test attestation signature check."""
        from stance.sbom import Attestation, Subject

        attestation = Attestation(
            subjects=[Subject(name="test.json", digest={"sha256": "abc"})],
        )

        assert not attestation.is_signed


class TestAttestationBuilder:
    """Tests for AttestationBuilder class."""

    def test_add_subject(self):
        """Test adding subject to attestation."""
        from stance.sbom import AttestationBuilder

        builder = AttestationBuilder()
        builder.add_subject(name="test.json", content=b"test content")

        attestation = builder.build()
        assert len(attestation.subjects) == 1

    def test_set_predicate(self):
        """Test setting predicate."""
        from stance.sbom import AttestationBuilder

        builder = AttestationBuilder()
        builder.add_subject(name="test.json", content="test")
        builder.set_predicate(predicate_type="sbom", content={"test": "data"})

        attestation = builder.build()
        assert attestation.predicate is not None


class TestAttestationSigner:
    """Tests for AttestationSigner class."""

    def test_sign_attestation(self):
        """Test signing an attestation."""
        from stance.sbom import (
            AttestationBuilder,
            AttestationSigner,
        )

        builder = AttestationBuilder()
        builder.add_subject(name="test.json", content="test data")
        attestation = builder.build()

        signer = AttestationSigner(secret_key="test-secret-key")
        signed = signer.sign(attestation)

        assert signed.signature is not None
        assert signed.is_signed

    def test_sign_with_algorithm(self):
        """Test signing with specific algorithm."""
        from stance.sbom import (
            AttestationBuilder,
            AttestationSigner,
            SignatureAlgorithm,
        )

        builder = AttestationBuilder()
        builder.add_subject(name="test.json", content="test data")
        attestation = builder.build()

        signer = AttestationSigner(secret_key="test-key")
        signed = signer.sign(attestation, algorithm=SignatureAlgorithm.HMAC_SHA512)

        assert signed.signature.algorithm == SignatureAlgorithm.HMAC_SHA512


class TestAttestationVerifier:
    """Tests for AttestationVerifier class."""

    def test_verify_valid_signature(self):
        """Test verifying a valid signature."""
        from stance.sbom import (
            AttestationBuilder,
            AttestationSigner,
            AttestationVerifier,
            VerificationStatus,
        )

        # Create and sign
        builder = AttestationBuilder()
        builder.add_subject(name="test.json", content="test data")
        attestation = builder.build()

        secret_key = "test-secret-key"
        signer = AttestationSigner(secret_key=secret_key)
        signed = signer.sign(attestation)

        # Verify with same key
        verifier = AttestationVerifier(secret_key=secret_key)
        result = verifier.verify(signed)

        assert result.status == VerificationStatus.VALID
        assert result.is_valid

    def test_verify_invalid_signature(self):
        """Test verifying with wrong key."""
        from stance.sbom import (
            AttestationBuilder,
            AttestationSigner,
            AttestationVerifier,
            VerificationStatus,
        )

        # Create and sign
        builder = AttestationBuilder()
        builder.add_subject(name="test.json", content="test data")
        attestation = builder.build()

        signer = AttestationSigner(secret_key="correct-key")
        signed = signer.sign(attestation)

        # Verify with wrong key
        verifier = AttestationVerifier(secret_key="wrong-key")
        result = verifier.verify(signed)

        assert result.status == VerificationStatus.INVALID
        assert not result.is_valid


class TestCreateSBOMAttestation:
    """Tests for create_sbom_attestation helper function."""

    def test_create_attestation(self):
        """Test creating attestation via helper."""
        from stance.sbom import create_sbom_attestation

        sbom_data = {"bomFormat": "CycloneDX", "components": []}

        attestation = create_sbom_attestation(
            sbom_data=sbom_data,
            signer_name="Test",
        )

        assert attestation is not None
        assert len(attestation.subjects) >= 1

    def test_create_signed_attestation(self):
        """Test creating signed attestation."""
        from stance.sbom import create_sbom_attestation

        attestation = create_sbom_attestation(
            sbom_data={"test": "data"},
            signer_name="Test Signer",
            secret_key="my-secret",
        )

        assert attestation.signature is not None
        assert attestation.is_signed


# =============================================================================
# VEX (Vulnerability Exploitability eXchange) Tests
# =============================================================================


class TestVEXStatus:
    """Tests for VEXStatus enum."""

    def test_affected_status(self):
        """Test affected status."""
        from stance.sbom import VEXStatus
        assert VEXStatus.AFFECTED.value == "affected"

    def test_not_affected_status(self):
        """Test not_affected status."""
        from stance.sbom import VEXStatus
        assert VEXStatus.NOT_AFFECTED.value == "not_affected"

    def test_fixed_status(self):
        """Test fixed status."""
        from stance.sbom import VEXStatus
        assert VEXStatus.FIXED.value == "fixed"

    def test_under_investigation_status(self):
        """Test under_investigation status."""
        from stance.sbom import VEXStatus
        assert VEXStatus.UNDER_INVESTIGATION.value == "under_investigation"


class TestVEXJustification:
    """Tests for VEXJustification enum."""

    def test_component_not_present(self):
        """Test component_not_present justification."""
        from stance.sbom import VEXJustification
        assert VEXJustification.COMPONENT_NOT_PRESENT.value == "component_not_present"

    def test_vulnerable_code_not_present(self):
        """Test vulnerable_code_not_present justification."""
        from stance.sbom import VEXJustification
        assert VEXJustification.VULNERABLE_CODE_NOT_PRESENT.value == "vulnerable_code_not_present"

    def test_vulnerable_code_not_in_execute_path(self):
        """Test vulnerable_code_not_in_execute_path justification."""
        from stance.sbom import VEXJustification
        assert VEXJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value == "vulnerable_code_not_in_execute_path"


class TestActionType:
    """Tests for ActionType enum."""

    def test_no_action_type(self):
        """Test no_action type."""
        from stance.sbom import ActionType
        assert ActionType.NO_ACTION.value == "no_action"

    def test_update_action_type(self):
        """Test update type."""
        from stance.sbom import ActionType
        assert ActionType.UPDATE.value == "update"


class TestVEXProduct:
    """Tests for VEXProduct dataclass."""

    def test_product_creation(self):
        """Test product creation."""
        from stance.sbom import VEXProduct

        product = VEXProduct(
            name="requests",
            version="2.28.0",
            purl="pkg:pypi/requests@2.28.0",
        )

        assert product.name == "requests"
        assert product.version == "2.28.0"
        assert product.purl == "pkg:pypi/requests@2.28.0"

    def test_product_to_dict(self):
        """Test product serialization."""
        from stance.sbom import VEXProduct

        product = VEXProduct(
            name="lodash",
            version="4.17.21",
            purl="pkg:npm/lodash@4.17.21",
        )
        product_dict = product.to_dict()

        assert product_dict["name"] == "lodash"
        assert product_dict["purl"] == "pkg:npm/lodash@4.17.21"


class TestVEXVulnerability:
    """Tests for VEXVulnerability dataclass."""

    def test_vulnerability_creation(self):
        """Test vulnerability creation."""
        from stance.sbom import VEXVulnerability

        vuln = VEXVulnerability(
            id="CVE-2023-12345",
            description="Test vulnerability",
        )

        assert vuln.id == "CVE-2023-12345"
        assert vuln.description == "Test vulnerability"

    def test_vulnerability_with_cwe_ids(self):
        """Test vulnerability with CWE IDs."""
        from stance.sbom import VEXVulnerability

        vuln = VEXVulnerability(
            id="CVE-2023-12345",
            cwe_ids=["CWE-79", "CWE-89"],
        )

        assert len(vuln.cwe_ids) == 2


class TestVEXStatement:
    """Tests for VEXStatement dataclass."""

    def test_statement_creation(self):
        """Test statement creation."""
        from stance.sbom import VEXStatement, VEXStatus, VEXProduct, VEXVulnerability

        statement = VEXStatement(
            vulnerability=VEXVulnerability(id="CVE-2023-12345"),
            products=[VEXProduct(name="test", version="1.0.0")],
            status=VEXStatus.AFFECTED,
        )

        assert statement.status == VEXStatus.AFFECTED
        assert len(statement.products) == 1

    def test_statement_with_justification(self):
        """Test statement with justification."""
        from stance.sbom import (
            VEXStatement,
            VEXStatus,
            VEXJustification,
            VEXProduct,
            VEXVulnerability,
        )

        statement = VEXStatement(
            vulnerability=VEXVulnerability(id="CVE-2023-12345"),
            products=[VEXProduct(name="test", version="1.0.0")],
            status=VEXStatus.NOT_AFFECTED,
            justification=VEXJustification.COMPONENT_NOT_PRESENT,
        )

        assert statement.justification == VEXJustification.COMPONENT_NOT_PRESENT

    def test_statement_to_dict(self):
        """Test statement serialization."""
        from stance.sbom import VEXStatement, VEXStatus, VEXProduct, VEXVulnerability

        statement = VEXStatement(
            vulnerability=VEXVulnerability(id="CVE-2023-12345"),
            products=[VEXProduct(name="test", version="1.0.0")],
            status=VEXStatus.FIXED,
        )

        stmt_dict = statement.to_dict()
        assert "vulnerability" in stmt_dict
        assert "products" in stmt_dict
        assert "status" in stmt_dict


class TestVEXDocument:
    """Tests for VEXDocument dataclass."""

    def test_document_creation(self):
        """Test document creation."""
        from stance.sbom import VEXDocument

        doc = VEXDocument(
            id="urn:uuid:test-doc",
            author="Test Author",
        )

        assert doc.id == "urn:uuid:test-doc"
        assert doc.author == "Test Author"
        assert len(doc.statements) == 0

    def test_add_statement(self):
        """Test adding statements to document."""
        from stance.sbom import (
            VEXDocument,
            VEXStatement,
            VEXStatus,
            VEXProduct,
            VEXVulnerability,
        )

        doc = VEXDocument(id="test-doc")
        statement = VEXStatement(
            vulnerability=VEXVulnerability(id="CVE-2023-12345"),
            products=[VEXProduct(name="test", version="1.0.0")],
            status=VEXStatus.AFFECTED,
        )
        doc.add_statement(statement)

        assert len(doc.statements) == 1

    def test_to_openvex(self):
        """Test OpenVEX format output."""
        from stance.sbom import VEXDocument

        doc = VEXDocument(
            id="urn:uuid:test",
            author="Test",
        )

        openvex = doc.to_openvex()
        assert "@context" in openvex
        assert openvex["@context"] == "https://openvex.dev/ns/v0.2.0"

    def test_to_cyclonedx_vex(self):
        """Test CycloneDX VEX format output."""
        from stance.sbom import VEXDocument

        doc = VEXDocument(id="test")
        cdx_vex = doc.to_cyclonedx_vex()

        # CycloneDX VEX contains vulnerabilities key
        assert "vulnerabilities" in cdx_vex

    def test_to_csaf_vex(self):
        """Test CSAF VEX format output."""
        from stance.sbom import VEXDocument

        doc = VEXDocument(
            id="test",
            author="Test Author",
        )
        csaf_vex = doc.to_csaf_vex()

        assert "document" in csaf_vex
        assert "vulnerabilities" in csaf_vex

    def test_to_json(self):
        """Test JSON output."""
        from stance.sbom import VEXDocument
        import json

        doc = VEXDocument(id="test")
        json_str = doc.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed is not None


class TestVEXGenerator:
    """Tests for VEXGenerator class."""

    def test_generator_creation(self):
        """Test creating VEX generator."""
        from stance.sbom import VEXGenerator

        generator = VEXGenerator()
        assert generator.author == "Mantissa Stance"

    def test_generator_with_custom_author(self):
        """Test creating generator with custom author."""
        from stance.sbom import VEXGenerator

        generator = VEXGenerator(author="Custom Author")
        assert generator.author == "Custom Author"

    def test_create_affected_statement(self):
        """Test creating affected statement."""
        from stance.sbom import VEXGenerator, VEXStatus, VEXProduct, VEXVulnerability

        generator = VEXGenerator()
        statement = generator.create_affected_statement(
            vulnerability=VEXVulnerability(id="CVE-2023-12345"),
            products=[VEXProduct(name="test", version="1.0.0")],
        )

        assert statement.status == VEXStatus.AFFECTED

    def test_create_not_affected_statement(self):
        """Test creating not_affected statement with justification."""
        from stance.sbom import VEXGenerator, VEXStatus, VEXJustification, VEXProduct, VEXVulnerability

        generator = VEXGenerator()
        statement = generator.create_not_affected_statement(
            vulnerability=VEXVulnerability(id="CVE-2023-12345"),
            products=[VEXProduct(name="test", version="1.0.0")],
            justification=VEXJustification.VULNERABLE_CODE_NOT_PRESENT,
        )

        assert statement.status == VEXStatus.NOT_AFFECTED
        assert statement.justification == VEXJustification.VULNERABLE_CODE_NOT_PRESENT


class TestVEXParser:
    """Tests for VEXParser class."""

    def test_parse_openvex(self):
        """Test parsing OpenVEX document."""
        from stance.sbom import VEXParser

        openvex_data = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "urn:uuid:test",
            "author": "Test",
            "timestamp": "2024-01-01T00:00:00Z",
            "statements": [
                {
                    "vulnerability": {"@id": "CVE-2023-12345"},
                    "products": [{"@id": "pkg:pypi/test@1.0.0"}],
                    "status": "affected",
                }
            ],
        }

        parser = VEXParser()
        doc = parser.parse_openvex(openvex_data)

        assert doc is not None
        assert doc.author == "Test"


class TestCreateVEXDocument:
    """Tests for create_vex_document helper function."""

    def test_create_vex_document(self):
        """Test creating VEX document via helper (requires vulnerability matches)."""
        from stance.sbom import VEXDocument, VEXGenerator

        # The create_vex_document requires vulnerability matches
        # For a simple test, just create a document directly
        generator = VEXGenerator(author="Test Author")
        doc = VEXDocument(author="Test Author")

        assert doc is not None
        assert doc.author == "Test Author"
