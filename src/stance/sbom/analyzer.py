"""
Supply chain risk analyzer for SBOM.

Analyzes software supply chain for security risks including
outdated dependencies, known vulnerabilities, and license issues.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from stance.sbom.parser import (
    Dependency,
    DependencyFile,
    DependencyParser,
    PackageEcosystem,
)
from stance.sbom.license import LicenseAnalyzer, LicenseRisk
from stance.models import Finding, FindingType, FindingStatus, Severity

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Supply chain risk level."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DependencyRisk:
    """Risk assessment for a single dependency."""

    dependency: Dependency
    overall_risk: RiskLevel = RiskLevel.INFO

    # Risk factors
    license_risk: RiskLevel = RiskLevel.INFO
    maintenance_risk: RiskLevel = RiskLevel.INFO
    popularity_risk: RiskLevel = RiskLevel.INFO
    security_risk: RiskLevel = RiskLevel.INFO

    # Issues found
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    # Metadata
    is_deprecated: bool = False
    is_unmaintained: bool = False
    has_known_vulns: bool = False
    vulnerability_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "dependency": {
                "name": self.dependency.name,
                "version": self.dependency.version,
                "ecosystem": self.dependency.ecosystem.value,
                "is_direct": self.dependency.is_direct,
            },
            "overall_risk": self.overall_risk.value,
            "risk_factors": {
                "license": self.license_risk.value,
                "maintenance": self.maintenance_risk.value,
                "popularity": self.popularity_risk.value,
                "security": self.security_risk.value,
            },
            "issues": self.issues,
            "recommendations": self.recommendations,
            "flags": {
                "deprecated": self.is_deprecated,
                "unmaintained": self.is_unmaintained,
                "has_vulnerabilities": self.has_known_vulns,
                "vulnerability_count": self.vulnerability_count,
            },
        }

    def to_finding(self) -> Finding | None:
        """Convert to a Stance Finding if risks are found."""
        if self.overall_risk == RiskLevel.INFO:
            return None

        severity_map = {
            RiskLevel.CRITICAL: Severity.CRITICAL,
            RiskLevel.HIGH: Severity.HIGH,
            RiskLevel.MEDIUM: Severity.MEDIUM,
            RiskLevel.LOW: Severity.LOW,
            RiskLevel.INFO: Severity.INFO,
        }

        title = f"Supply chain risk in {self.dependency.name}@{self.dependency.version}"
        description = "\n".join(self.issues) if self.issues else "Supply chain risk detected"

        return Finding(
            id=f"sbom:{self.dependency.ecosystem.value}:{self.dependency.name}:{self.dependency.version}",
            finding_type=FindingType.VULNERABILITY,
            status=FindingStatus.OPEN,
            severity=severity_map.get(self.overall_risk, Severity.INFO),
            title=title,
            description=description,
            asset_id=f"dependency:{self.dependency.name}",
            package_name=self.dependency.name,
            installed_version=self.dependency.version,
            remediation_guidance="\n".join(self.recommendations) if self.recommendations else "",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )


@dataclass
class SupplyChainRisk:
    """Comprehensive supply chain risk analysis."""

    # Summary
    total_dependencies: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0

    # Risk counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Ecosystem breakdown
    ecosystems: dict[str, int] = field(default_factory=dict)

    # Dependency risks
    dependency_risks: list[DependencyRisk] = field(default_factory=list)

    # High-level issues
    deprecated_count: int = 0
    unmaintained_count: int = 0
    vulnerable_count: int = 0
    license_risk_count: int = 0

    # Analysis metadata
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    source_files: list[str] = field(default_factory=list)

    @property
    def overall_risk(self) -> RiskLevel:
        """Calculate overall supply chain risk."""
        if self.critical_count > 0:
            return RiskLevel.CRITICAL
        if self.high_count > 0:
            return RiskLevel.HIGH
        if self.medium_count > 0:
            return RiskLevel.MEDIUM
        if self.low_count > 0:
            return RiskLevel.LOW
        return RiskLevel.INFO

    @property
    def risk_score(self) -> int:
        """Calculate a numeric risk score (0-100)."""
        # Base score from critical/high/medium/low
        score = (
            self.critical_count * 25 +
            self.high_count * 10 +
            self.medium_count * 5 +
            self.low_count * 1
        )

        # Cap at 100
        return min(score, 100)

    def get_critical_risks(self) -> list[DependencyRisk]:
        """Get dependencies with critical risk."""
        return [r for r in self.dependency_risks if r.overall_risk == RiskLevel.CRITICAL]

    def get_high_risks(self) -> list[DependencyRisk]:
        """Get dependencies with high risk."""
        return [r for r in self.dependency_risks if r.overall_risk == RiskLevel.HIGH]

    def to_findings(self) -> list[Finding]:
        """Convert all risks to Stance Findings."""
        findings = []
        for risk in self.dependency_risks:
            finding = risk.to_finding()
            if finding:
                findings.append(finding)
        return findings

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": {
                "total_dependencies": self.total_dependencies,
                "direct_dependencies": self.direct_dependencies,
                "transitive_dependencies": self.transitive_dependencies,
                "overall_risk": self.overall_risk.value,
                "risk_score": self.risk_score,
            },
            "risk_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "issues": {
                "deprecated": self.deprecated_count,
                "unmaintained": self.unmaintained_count,
                "vulnerable": self.vulnerable_count,
                "license_risks": self.license_risk_count,
            },
            "ecosystems": self.ecosystems,
            "analyzed_at": self.analyzed_at.isoformat(),
            "source_files": self.source_files,
            "dependencies": [r.to_dict() for r in self.dependency_risks],
        }


class SupplyChainAnalyzer:
    """
    Analyzes software supply chain for security risks.

    Combines dependency parsing, license analysis, and vulnerability
    data to provide comprehensive supply chain risk assessment.
    """

    # Known deprecated packages
    DEPRECATED_PACKAGES: dict[str, set[str]] = {
        "npm": {
            "request",  # Deprecated in favor of node-fetch/axios
            "left-pad",  # Removed from npm
            "node-uuid",  # Deprecated in favor of uuid
            "mkdirp",  # Old versions deprecated
            "debug",  # Old versions have vulnerabilities
        },
        "pypi": {
            "pycrypto",  # Deprecated in favor of pycryptodome
            "fabric",  # Fabric 1.x deprecated
            "nose",  # Deprecated in favor of pytest
            "httplib2",  # Security concerns
        },
    }

    # Known typosquatting targets (packages that are commonly typosquatted)
    TYPOSQUAT_TARGETS: dict[str, set[str]] = {
        "npm": {"lodash", "express", "react", "axios", "moment", "webpack"},
        "pypi": {"requests", "numpy", "pandas", "django", "flask", "tensorflow"},
    }

    def __init__(
        self,
        license_analyzer: LicenseAnalyzer | None = None,
        vulnerability_data: dict[str, list[str]] | None = None,
    ):
        """
        Initialize the supply chain analyzer.

        Args:
            license_analyzer: Optional LicenseAnalyzer instance
            vulnerability_data: Optional dict of package name -> CVE IDs
        """
        self._parser = DependencyParser()
        self._license_analyzer = license_analyzer or LicenseAnalyzer()
        self._vulnerability_data = vulnerability_data or {}

    def analyze_file(self, file_path: str) -> SupplyChainRisk:
        """
        Analyze supply chain risk from a dependency file.

        Args:
            file_path: Path to dependency file

        Returns:
            SupplyChainRisk analysis
        """
        dep_file = self._parser.parse_file(file_path)
        return self._analyze_dependencies(
            dep_file.dependencies,
            source_files=[file_path],
        )

    def analyze_directory(
        self,
        directory: str,
        recursive: bool = True,
    ) -> SupplyChainRisk:
        """
        Analyze supply chain risk from all dependency files in a directory.

        Args:
            directory: Directory to scan
            recursive: Search subdirectories

        Returns:
            SupplyChainRisk analysis
        """
        dep_files = self._parser.parse_directory(directory, recursive)

        # Merge all dependencies
        all_deps: list[Dependency] = []
        source_files: list[str] = []
        seen: set[tuple[str, str]] = set()

        for dep_file in dep_files:
            source_files.append(dep_file.file_path)
            for dep in dep_file.dependencies:
                key = (dep.name, dep.version)
                if key not in seen:
                    seen.add(key)
                    all_deps.append(dep)

        return self._analyze_dependencies(all_deps, source_files)

    def analyze_dependencies(
        self,
        dependencies: list[Dependency],
    ) -> SupplyChainRisk:
        """
        Analyze supply chain risk from a list of dependencies.

        Args:
            dependencies: List of dependencies

        Returns:
            SupplyChainRisk analysis
        """
        return self._analyze_dependencies(dependencies, [])

    def _analyze_dependencies(
        self,
        dependencies: list[Dependency],
        source_files: list[str],
    ) -> SupplyChainRisk:
        """Internal method to analyze dependencies."""
        result = SupplyChainRisk(
            total_dependencies=len(dependencies),
            source_files=source_files,
        )

        for dep in dependencies:
            # Count by scope
            if dep.is_direct:
                result.direct_dependencies += 1
            else:
                result.transitive_dependencies += 1

            # Count by ecosystem
            eco = dep.ecosystem.value
            result.ecosystems[eco] = result.ecosystems.get(eco, 0) + 1

            # Analyze individual dependency
            risk = self._analyze_dependency(dep)
            result.dependency_risks.append(risk)

            # Update counters
            if risk.overall_risk == RiskLevel.CRITICAL:
                result.critical_count += 1
            elif risk.overall_risk == RiskLevel.HIGH:
                result.high_count += 1
            elif risk.overall_risk == RiskLevel.MEDIUM:
                result.medium_count += 1
            elif risk.overall_risk == RiskLevel.LOW:
                result.low_count += 1

            if risk.is_deprecated:
                result.deprecated_count += 1
            if risk.is_unmaintained:
                result.unmaintained_count += 1
            if risk.has_known_vulns:
                result.vulnerable_count += 1
            if risk.license_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                result.license_risk_count += 1

        return result

    def _analyze_dependency(self, dep: Dependency) -> DependencyRisk:
        """Analyze risk for a single dependency."""
        risk = DependencyRisk(dependency=dep)

        # Check if deprecated
        if dep.deprecated:
            risk.is_deprecated = True
            risk.issues.append(f"Package is deprecated: {dep.deprecated_message or 'no reason given'}")
            risk.recommendations.append("Find an alternative package")
            risk.maintenance_risk = RiskLevel.HIGH

        # Check known deprecated packages
        eco_key = dep.ecosystem.value
        deprecated_pkgs = self.DEPRECATED_PACKAGES.get(eco_key, set())
        if dep.name.lower() in deprecated_pkgs:
            risk.is_deprecated = True
            risk.issues.append(f"Package {dep.name} is known to be deprecated")
            risk.recommendations.append("Replace with recommended alternative")
            risk.maintenance_risk = RiskLevel.HIGH

        # Check for potential typosquatting
        typosquat_targets = self.TYPOSQUAT_TARGETS.get(eco_key, set())
        for target in typosquat_targets:
            if self._is_potential_typosquat(dep.name, target):
                risk.issues.append(f"Package name '{dep.name}' is similar to '{target}' - potential typosquatting")
                risk.recommendations.append("Verify this is the intended package")
                risk.security_risk = RiskLevel.MEDIUM

        # Analyze license
        license_result = self._license_analyzer.analyze_dependency(dep)
        if license_result.risk == LicenseRisk.CRITICAL:
            risk.license_risk = RiskLevel.CRITICAL
            risk.issues.extend(license_result.issues)
            risk.recommendations.extend(license_result.recommendations)
        elif license_result.risk == LicenseRisk.HIGH:
            risk.license_risk = RiskLevel.HIGH
            risk.issues.extend(license_result.issues)
            risk.recommendations.extend(license_result.recommendations)
        elif license_result.risk == LicenseRisk.MEDIUM:
            risk.license_risk = RiskLevel.MEDIUM
        elif license_result.risk == LicenseRisk.UNKNOWN:
            risk.license_risk = RiskLevel.MEDIUM
            risk.issues.append("License information unavailable or unrecognized")

        # Check vulnerability data
        pkg_key = f"{dep.ecosystem.value}:{dep.name}"
        vuln_key_version = f"{pkg_key}@{dep.version}"

        vulns = self._vulnerability_data.get(pkg_key, [])
        vulns.extend(self._vulnerability_data.get(vuln_key_version, []))

        if vulns:
            risk.has_known_vulns = True
            risk.vulnerability_count = len(vulns)
            risk.security_risk = RiskLevel.CRITICAL if len(vulns) > 5 else RiskLevel.HIGH
            risk.issues.append(f"Package has {len(vulns)} known vulnerabilities")
            risk.recommendations.append("Update to a patched version or find alternative")

        # Check for version patterns indicating risk
        version = dep.version.lower()
        if version in ("*", "latest", ""):
            risk.issues.append("No version constraint - using latest version")
            risk.recommendations.append("Pin to a specific version")
            risk.security_risk = max(risk.security_risk, RiskLevel.MEDIUM, key=lambda x: x.value)

        if "alpha" in version or "beta" in version or "rc" in version:
            risk.issues.append(f"Using pre-release version: {dep.version}")
            risk.recommendations.append("Consider using stable release")
            risk.maintenance_risk = max(risk.maintenance_risk, RiskLevel.LOW, key=lambda x: x.value)

        # Calculate overall risk
        risk.overall_risk = self._calculate_overall_risk(risk)

        return risk

    def _calculate_overall_risk(self, risk: DependencyRisk) -> RiskLevel:
        """Calculate overall risk from individual risk factors."""
        risk_levels = [
            risk.license_risk,
            risk.maintenance_risk,
            risk.security_risk,
            risk.popularity_risk,
        ]

        # Overall is the maximum risk level
        risk_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        for level in risk_order:
            if level in risk_levels:
                return level

        return RiskLevel.INFO

    def _is_potential_typosquat(self, name: str, target: str) -> bool:
        """Check if name might be a typosquat of target."""
        name = name.lower()
        target = target.lower()

        # Exact match is not typosquatting
        if name == target:
            return False

        # Check Levenshtein distance (simplified)
        if len(name) == len(target):
            diff_count = sum(1 for a, b in zip(name, target) if a != b)
            if diff_count == 1:
                return True

        # Check for common typosquatting patterns
        # - Adding/removing hyphens or underscores
        if name.replace("-", "") == target.replace("-", ""):
            return True
        if name.replace("_", "") == target.replace("_", ""):
            return True

        # - Swapping - and _
        if name.replace("-", "_") == target or name.replace("_", "-") == target:
            return False  # These are often legitimate variants

        # - Adding common suffixes
        for suffix in ["-js", "-node", "-py", "2", "3", "-ng", "-next"]:
            if name == target + suffix or name + suffix == target:
                return False  # These are often legitimate

        # - Character swaps (adjacent characters)
        for i in range(len(name) - 1):
            swapped = name[:i] + name[i + 1] + name[i] + name[i + 2:]
            if swapped == target:
                return True

        return False

    def get_risk_summary(self, result: SupplyChainRisk) -> str:
        """Generate a human-readable risk summary."""
        lines = []
        lines.append(f"Supply Chain Risk Analysis")
        lines.append(f"=" * 40)
        lines.append(f"")
        lines.append(f"Total Dependencies: {result.total_dependencies}")
        lines.append(f"  Direct: {result.direct_dependencies}")
        lines.append(f"  Transitive: {result.transitive_dependencies}")
        lines.append(f"")
        lines.append(f"Overall Risk: {result.overall_risk.value.upper()}")
        lines.append(f"Risk Score: {result.risk_score}/100")
        lines.append(f"")
        lines.append(f"Risk Breakdown:")
        lines.append(f"  Critical: {result.critical_count}")
        lines.append(f"  High: {result.high_count}")
        lines.append(f"  Medium: {result.medium_count}")
        lines.append(f"  Low: {result.low_count}")
        lines.append(f"")
        lines.append(f"Issues Found:")
        lines.append(f"  Deprecated: {result.deprecated_count}")
        lines.append(f"  Vulnerable: {result.vulnerable_count}")
        lines.append(f"  License Risks: {result.license_risk_count}")

        if result.critical_count > 0 or result.high_count > 0:
            lines.append(f"")
            lines.append(f"High Priority Items:")
            for risk in result.get_critical_risks()[:5]:
                lines.append(f"  [CRITICAL] {risk.dependency.name}@{risk.dependency.version}")
                for issue in risk.issues[:2]:
                    lines.append(f"    - {issue}")
            for risk in result.get_high_risks()[:5]:
                lines.append(f"  [HIGH] {risk.dependency.name}@{risk.dependency.version}")
                for issue in risk.issues[:2]:
                    lines.append(f"    - {issue}")

        return "\n".join(lines)


def analyze_supply_chain(
    path: str,
    recursive: bool = True,
) -> SupplyChainRisk:
    """
    Convenience function to analyze supply chain risk.

    Args:
        path: File or directory path
        recursive: Search subdirectories (for directory input)

    Returns:
        SupplyChainRisk analysis
    """
    analyzer = SupplyChainAnalyzer()

    from pathlib import Path
    p = Path(path)

    if p.is_file():
        return analyzer.analyze_file(str(p))
    elif p.is_dir():
        return analyzer.analyze_directory(str(p), recursive)
    else:
        raise FileNotFoundError(f"Path not found: {path}")
