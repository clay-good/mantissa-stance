"""
License analysis and compliance for SBOM.

Provides license identification, risk assessment, and compatibility
checking for software dependencies.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.sbom.parser import Dependency

logger = logging.getLogger(__name__)


class LicenseCategory(Enum):
    """License category classification."""

    PERMISSIVE = "permissive"  # MIT, BSD, Apache
    WEAK_COPYLEFT = "weak_copyleft"  # LGPL, MPL
    STRONG_COPYLEFT = "strong_copyleft"  # GPL, AGPL
    PROPRIETARY = "proprietary"
    PUBLIC_DOMAIN = "public_domain"  # Unlicense, CC0
    UNKNOWN = "unknown"


class LicenseRisk(Enum):
    """License risk level for commercial use."""

    LOW = "low"  # Permissive, public domain
    MEDIUM = "medium"  # Weak copyleft
    HIGH = "high"  # Strong copyleft
    CRITICAL = "critical"  # AGPL, proprietary restrictions
    UNKNOWN = "unknown"


@dataclass
class License:
    """Represents a software license."""

    # Identification
    spdx_id: str | None = None  # SPDX identifier (e.g., MIT, Apache-2.0)
    name: str = ""  # Full name
    url: str | None = None  # License text URL

    # Classification
    category: LicenseCategory = LicenseCategory.UNKNOWN
    risk: LicenseRisk = LicenseRisk.UNKNOWN

    # Properties
    osi_approved: bool = False  # OSI approved
    fsf_libre: bool = False  # FSF free/libre
    copyleft: bool = False
    patent_grant: bool = False  # Includes patent grant
    attribution_required: bool = True
    notice_required: bool = True
    state_changes: bool = False  # Must state changes
    disclose_source: bool = False  # Must disclose source

    # Compatibility
    gpl_compatible: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "spdx_id": self.spdx_id,
            "name": self.name,
            "url": self.url,
            "category": self.category.value,
            "risk": self.risk.value,
            "osi_approved": self.osi_approved,
            "fsf_libre": self.fsf_libre,
            "copyleft": self.copyleft,
            "patent_grant": self.patent_grant,
            "attribution_required": self.attribution_required,
            "notice_required": self.notice_required,
            "state_changes": self.state_changes,
            "disclose_source": self.disclose_source,
            "gpl_compatible": self.gpl_compatible,
        }


@dataclass
class LicenseCompatibility:
    """Result of license compatibility check."""

    compatible: bool
    source_license: str
    target_license: str
    reason: str | None = None
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "compatible": self.compatible,
            "source_license": self.source_license,
            "target_license": self.target_license,
            "reason": self.reason,
            "recommendations": self.recommendations,
        }


# License database with known licenses and their properties
LICENSE_DATABASE: dict[str, License] = {
    # Permissive licenses
    "MIT": License(
        spdx_id="MIT",
        name="MIT License",
        url="https://opensource.org/licenses/MIT",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        patent_grant=False,
        gpl_compatible=True,
    ),
    "Apache-2.0": License(
        spdx_id="Apache-2.0",
        name="Apache License 2.0",
        url="https://opensource.org/licenses/Apache-2.0",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        patent_grant=True,
        gpl_compatible=True,
    ),
    "BSD-2-Clause": License(
        spdx_id="BSD-2-Clause",
        name="BSD 2-Clause License",
        url="https://opensource.org/licenses/BSD-2-Clause",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        gpl_compatible=True,
    ),
    "BSD-3-Clause": License(
        spdx_id="BSD-3-Clause",
        name="BSD 3-Clause License",
        url="https://opensource.org/licenses/BSD-3-Clause",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        gpl_compatible=True,
    ),
    "ISC": License(
        spdx_id="ISC",
        name="ISC License",
        url="https://opensource.org/licenses/ISC",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        gpl_compatible=True,
    ),
    "0BSD": License(
        spdx_id="0BSD",
        name="Zero-Clause BSD",
        url="https://opensource.org/licenses/0BSD",
        category=LicenseCategory.PUBLIC_DOMAIN,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        copyleft=False,
        attribution_required=False,
        notice_required=False,
        gpl_compatible=True,
    ),
    # Public domain
    "Unlicense": License(
        spdx_id="Unlicense",
        name="The Unlicense",
        url="https://unlicense.org/",
        category=LicenseCategory.PUBLIC_DOMAIN,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        attribution_required=False,
        notice_required=False,
        gpl_compatible=True,
    ),
    "CC0-1.0": License(
        spdx_id="CC0-1.0",
        name="Creative Commons Zero v1.0 Universal",
        url="https://creativecommons.org/publicdomain/zero/1.0/",
        category=LicenseCategory.PUBLIC_DOMAIN,
        risk=LicenseRisk.LOW,
        copyleft=False,
        attribution_required=False,
        notice_required=False,
        gpl_compatible=True,
    ),
    "WTFPL": License(
        spdx_id="WTFPL",
        name="Do What The F*ck You Want To Public License",
        url="http://www.wtfpl.net/",
        category=LicenseCategory.PUBLIC_DOMAIN,
        risk=LicenseRisk.LOW,
        fsf_libre=True,
        copyleft=False,
        attribution_required=False,
        gpl_compatible=True,
    ),
    # Weak copyleft
    "LGPL-2.1": License(
        spdx_id="LGPL-2.1",
        name="GNU Lesser General Public License v2.1",
        url="https://opensource.org/licenses/LGPL-2.1",
        category=LicenseCategory.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        state_changes=True,
        gpl_compatible=True,
    ),
    "LGPL-3.0": License(
        spdx_id="LGPL-3.0",
        name="GNU Lesser General Public License v3.0",
        url="https://opensource.org/licenses/LGPL-3.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        patent_grant=True,
        state_changes=True,
        gpl_compatible=True,
    ),
    "MPL-2.0": License(
        spdx_id="MPL-2.0",
        name="Mozilla Public License 2.0",
        url="https://opensource.org/licenses/MPL-2.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        patent_grant=True,
        gpl_compatible=True,
    ),
    "EPL-2.0": License(
        spdx_id="EPL-2.0",
        name="Eclipse Public License 2.0",
        url="https://opensource.org/licenses/EPL-2.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        osi_approved=True,
        copyleft=True,
        patent_grant=True,
        gpl_compatible=True,
    ),
    "CDDL-1.0": License(
        spdx_id="CDDL-1.0",
        name="Common Development and Distribution License 1.0",
        url="https://opensource.org/licenses/CDDL-1.0",
        category=LicenseCategory.WEAK_COPYLEFT,
        risk=LicenseRisk.MEDIUM,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        gpl_compatible=False,
    ),
    # Strong copyleft
    "GPL-2.0": License(
        spdx_id="GPL-2.0",
        name="GNU General Public License v2.0",
        url="https://opensource.org/licenses/GPL-2.0",
        category=LicenseCategory.STRONG_COPYLEFT,
        risk=LicenseRisk.HIGH,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        state_changes=True,
        disclose_source=True,
        gpl_compatible=True,
    ),
    "GPL-2.0-only": License(
        spdx_id="GPL-2.0-only",
        name="GNU General Public License v2.0 only",
        url="https://www.gnu.org/licenses/old-licenses/gpl-2.0.html",
        category=LicenseCategory.STRONG_COPYLEFT,
        risk=LicenseRisk.HIGH,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        state_changes=True,
        disclose_source=True,
        gpl_compatible=True,
    ),
    "GPL-3.0": License(
        spdx_id="GPL-3.0",
        name="GNU General Public License v3.0",
        url="https://opensource.org/licenses/GPL-3.0",
        category=LicenseCategory.STRONG_COPYLEFT,
        risk=LicenseRisk.HIGH,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        patent_grant=True,
        state_changes=True,
        disclose_source=True,
        gpl_compatible=True,
    ),
    "GPL-3.0-only": License(
        spdx_id="GPL-3.0-only",
        name="GNU General Public License v3.0 only",
        url="https://www.gnu.org/licenses/gpl-3.0.html",
        category=LicenseCategory.STRONG_COPYLEFT,
        risk=LicenseRisk.HIGH,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        patent_grant=True,
        state_changes=True,
        disclose_source=True,
        gpl_compatible=True,
    ),
    "AGPL-3.0": License(
        spdx_id="AGPL-3.0",
        name="GNU Affero General Public License v3.0",
        url="https://opensource.org/licenses/AGPL-3.0",
        category=LicenseCategory.STRONG_COPYLEFT,
        risk=LicenseRisk.CRITICAL,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        patent_grant=True,
        state_changes=True,
        disclose_source=True,
        gpl_compatible=True,
    ),
    "AGPL-3.0-only": License(
        spdx_id="AGPL-3.0-only",
        name="GNU Affero General Public License v3.0 only",
        url="https://www.gnu.org/licenses/agpl-3.0.html",
        category=LicenseCategory.STRONG_COPYLEFT,
        risk=LicenseRisk.CRITICAL,
        osi_approved=True,
        fsf_libre=True,
        copyleft=True,
        patent_grant=True,
        state_changes=True,
        disclose_source=True,
        gpl_compatible=True,
    ),
    # Other
    "Artistic-2.0": License(
        spdx_id="Artistic-2.0",
        name="Artistic License 2.0",
        url="https://opensource.org/licenses/Artistic-2.0",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        gpl_compatible=True,
    ),
    "BSL-1.0": License(
        spdx_id="BSL-1.0",
        name="Boost Software License 1.0",
        url="https://opensource.org/licenses/BSL-1.0",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        gpl_compatible=True,
    ),
    "Zlib": License(
        spdx_id="Zlib",
        name="zlib License",
        url="https://opensource.org/licenses/Zlib",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        osi_approved=True,
        fsf_libre=True,
        copyleft=False,
        gpl_compatible=True,
    ),
    "CC-BY-4.0": License(
        spdx_id="CC-BY-4.0",
        name="Creative Commons Attribution 4.0",
        url="https://creativecommons.org/licenses/by/4.0/",
        category=LicenseCategory.PERMISSIVE,
        risk=LicenseRisk.LOW,
        copyleft=False,
        gpl_compatible=True,
    ),
}

# License name aliases
LICENSE_ALIASES: dict[str, str] = {
    # MIT variants
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "mit/x11": "MIT",
    "x11": "MIT",
    # Apache variants
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    # BSD variants
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "modified bsd": "BSD-3-Clause",
    # GPL variants
    "gpl": "GPL-3.0",
    "gpl2": "GPL-2.0",
    "gpl-2": "GPL-2.0",
    "gpl v2": "GPL-2.0",
    "gplv2": "GPL-2.0",
    "gnu gpl v2": "GPL-2.0",
    "gpl3": "GPL-3.0",
    "gpl-3": "GPL-3.0",
    "gpl v3": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "gnu gpl v3": "GPL-3.0",
    # LGPL variants
    "lgpl": "LGPL-3.0",
    "lgpl2.1": "LGPL-2.1",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl v2.1": "LGPL-2.1",
    "lgpl3": "LGPL-3.0",
    "lgpl-3": "LGPL-3.0",
    "lgpl v3": "LGPL-3.0",
    # AGPL variants
    "agpl": "AGPL-3.0",
    "agpl3": "AGPL-3.0",
    "agpl-3": "AGPL-3.0",
    "agpl v3": "AGPL-3.0",
    "affero gpl": "AGPL-3.0",
    # MPL variants
    "mpl": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mpl-2": "MPL-2.0",
    "mozilla public license": "MPL-2.0",
    # Other
    "isc": "ISC",
    "isc license": "ISC",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "cc0": "CC0-1.0",
    "cc0 1.0": "CC0-1.0",
    "wtfpl": "WTFPL",
    "artistic": "Artistic-2.0",
    "artistic 2.0": "Artistic-2.0",
    "boost": "BSL-1.0",
    "boost software license": "BSL-1.0",
    "zlib": "Zlib",
    "zlib/libpng": "Zlib",
}


@dataclass
class LicenseResult:
    """Result of license analysis for a dependency."""

    dependency_name: str
    dependency_version: str
    license_string: str | None
    identified_license: License | None
    risk: LicenseRisk
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "dependency": f"{self.dependency_name}@{self.dependency_version}",
            "license_string": self.license_string,
            "identified_license": self.identified_license.to_dict() if self.identified_license else None,
            "risk": self.risk.value,
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


@dataclass
class LicenseAnalysisReport:
    """Complete license analysis report."""

    total_dependencies: int = 0
    analyzed_count: int = 0
    unknown_count: int = 0

    # Risk breakdown
    low_risk_count: int = 0
    medium_risk_count: int = 0
    high_risk_count: int = 0
    critical_risk_count: int = 0

    # Category breakdown
    permissive_count: int = 0
    weak_copyleft_count: int = 0
    strong_copyleft_count: int = 0
    public_domain_count: int = 0

    # Results
    results: list[LicenseResult] = field(default_factory=list)

    # Issues found
    high_risk_licenses: list[str] = field(default_factory=list)
    incompatible_licenses: list[str] = field(default_factory=list)
    unknown_licenses: list[str] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        """Check if any issues were found."""
        return bool(self.high_risk_licenses or self.incompatible_licenses or self.unknown_licenses)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": {
                "total_dependencies": self.total_dependencies,
                "analyzed": self.analyzed_count,
                "unknown": self.unknown_count,
            },
            "risk_breakdown": {
                "low": self.low_risk_count,
                "medium": self.medium_risk_count,
                "high": self.high_risk_count,
                "critical": self.critical_risk_count,
            },
            "category_breakdown": {
                "permissive": self.permissive_count,
                "weak_copyleft": self.weak_copyleft_count,
                "strong_copyleft": self.strong_copyleft_count,
                "public_domain": self.public_domain_count,
            },
            "issues": {
                "high_risk_licenses": self.high_risk_licenses,
                "incompatible_licenses": self.incompatible_licenses,
                "unknown_licenses": self.unknown_licenses,
            },
            "has_issues": self.has_issues,
            "results": [r.to_dict() for r in self.results],
        }


class LicenseAnalyzer:
    """
    Analyzes software licenses for risk and compliance.

    Identifies licenses from dependency metadata, assesses risk levels,
    and checks for compatibility issues.
    """

    def __init__(
        self,
        allowed_licenses: list[str] | None = None,
        denied_licenses: list[str] | None = None,
        project_license: str | None = None,
    ):
        """
        Initialize the license analyzer.

        Args:
            allowed_licenses: List of explicitly allowed license SPDX IDs
            denied_licenses: List of denied license SPDX IDs
            project_license: License of the project (for compatibility checks)
        """
        self._allowed = set(allowed_licenses) if allowed_licenses else None
        self._denied = set(denied_licenses) if denied_licenses else set()
        self._project_license = project_license

    def analyze_dependency(self, dep: Dependency) -> LicenseResult:
        """
        Analyze license for a single dependency.

        Args:
            dep: Dependency to analyze

        Returns:
            LicenseResult with analysis
        """
        license_str = dep.license
        identified = self.identify_license(license_str) if license_str else None

        issues: list[str] = []
        recommendations: list[str] = []

        # Determine risk
        if identified:
            risk = identified.risk

            # Check if denied
            if identified.spdx_id and identified.spdx_id in self._denied:
                issues.append(f"License {identified.spdx_id} is on the denied list")
                risk = LicenseRisk.CRITICAL

            # Check if allowed list exists and license not in it
            if self._allowed and identified.spdx_id and identified.spdx_id not in self._allowed:
                issues.append(f"License {identified.spdx_id} is not on the allowed list")

            # Add risk-specific recommendations
            if risk == LicenseRisk.HIGH:
                recommendations.append(
                    f"Review GPL obligations for {dep.name} - source disclosure may be required"
                )
            elif risk == LicenseRisk.CRITICAL:
                if identified.spdx_id and "AGPL" in identified.spdx_id:
                    recommendations.append(
                        f"AGPL license on {dep.name} requires source disclosure for network use"
                    )
                recommendations.append(f"Consider replacing {dep.name} with a permissively licensed alternative")

            # Check project license compatibility
            if self._project_license and identified:
                compat = self.check_compatibility(identified.spdx_id or "", self._project_license)
                if not compat.compatible:
                    issues.append(f"License may be incompatible with project license: {compat.reason}")
        else:
            risk = LicenseRisk.UNKNOWN
            if license_str:
                issues.append(f"Unknown license: {license_str}")
                recommendations.append(f"Manually review license for {dep.name}: {license_str}")
            else:
                issues.append("No license information available")
                recommendations.append(f"Check package registry for license information for {dep.name}")

        return LicenseResult(
            dependency_name=dep.name,
            dependency_version=dep.version,
            license_string=license_str,
            identified_license=identified,
            risk=risk,
            issues=issues,
            recommendations=recommendations,
        )

    def analyze_dependencies(
        self,
        dependencies: list[Dependency],
    ) -> LicenseAnalysisReport:
        """
        Analyze licenses for multiple dependencies.

        Args:
            dependencies: List of dependencies to analyze

        Returns:
            LicenseAnalysisReport with full analysis
        """
        report = LicenseAnalysisReport(total_dependencies=len(dependencies))

        for dep in dependencies:
            result = self.analyze_dependency(dep)
            report.results.append(result)

            if result.identified_license:
                report.analyzed_count += 1

                # Count by risk
                if result.risk == LicenseRisk.LOW:
                    report.low_risk_count += 1
                elif result.risk == LicenseRisk.MEDIUM:
                    report.medium_risk_count += 1
                elif result.risk == LicenseRisk.HIGH:
                    report.high_risk_count += 1
                    report.high_risk_licenses.append(
                        f"{dep.name}@{dep.version} ({result.identified_license.spdx_id})"
                    )
                elif result.risk == LicenseRisk.CRITICAL:
                    report.critical_risk_count += 1
                    report.high_risk_licenses.append(
                        f"{dep.name}@{dep.version} ({result.identified_license.spdx_id})"
                    )

                # Count by category
                cat = result.identified_license.category
                if cat == LicenseCategory.PERMISSIVE:
                    report.permissive_count += 1
                elif cat == LicenseCategory.WEAK_COPYLEFT:
                    report.weak_copyleft_count += 1
                elif cat == LicenseCategory.STRONG_COPYLEFT:
                    report.strong_copyleft_count += 1
                elif cat == LicenseCategory.PUBLIC_DOMAIN:
                    report.public_domain_count += 1
            else:
                report.unknown_count += 1
                if dep.license:
                    report.unknown_licenses.append(f"{dep.name}@{dep.version} ({dep.license})")
                else:
                    report.unknown_licenses.append(f"{dep.name}@{dep.version} (no license)")

        return report

    def identify_license(self, license_string: str | None) -> License | None:
        """
        Identify a license from a string.

        Args:
            license_string: License string to identify

        Returns:
            License object if identified, None otherwise
        """
        if not license_string:
            return None

        # Direct SPDX ID match
        if license_string in LICENSE_DATABASE:
            return LICENSE_DATABASE[license_string]

        # Try alias lookup
        normalized = license_string.lower().strip()
        if normalized in LICENSE_ALIASES:
            spdx_id = LICENSE_ALIASES[normalized]
            return LICENSE_DATABASE.get(spdx_id)

        # Try partial matching
        for alias, spdx_id in LICENSE_ALIASES.items():
            if alias in normalized or normalized in alias:
                return LICENSE_DATABASE.get(spdx_id)

        # Try SPDX expression parsing (simple)
        # Handle expressions like "MIT OR Apache-2.0"
        if " OR " in license_string.upper():
            parts = re.split(r"\s+OR\s+", license_string, flags=re.IGNORECASE)
            for part in parts:
                lic = self.identify_license(part.strip())
                if lic:
                    return lic

        # Handle expressions like "(MIT AND Apache-2.0)"
        if " AND " in license_string.upper():
            parts = re.split(r"\s+AND\s+", license_string, flags=re.IGNORECASE)
            # Return the most restrictive
            most_restrictive: License | None = None
            for part in parts:
                lic = self.identify_license(part.strip("() "))
                if lic:
                    if most_restrictive is None or lic.risk.value > most_restrictive.risk.value:
                        most_restrictive = lic
            return most_restrictive

        return None

    def check_compatibility(
        self,
        source_license: str,
        target_license: str,
    ) -> LicenseCompatibility:
        """
        Check if two licenses are compatible.

        Args:
            source_license: License of the dependency
            target_license: License of the project using the dependency

        Returns:
            LicenseCompatibility result
        """
        source = self.identify_license(source_license)
        target = self.identify_license(target_license)

        if not source or not target:
            return LicenseCompatibility(
                compatible=True,  # Assume compatible if unknown
                source_license=source_license,
                target_license=target_license,
                reason="Unable to determine compatibility - license not recognized",
                recommendations=["Manually verify license compatibility"],
            )

        # Permissive -> anything is usually OK
        if source.category == LicenseCategory.PERMISSIVE:
            return LicenseCompatibility(
                compatible=True,
                source_license=source_license,
                target_license=target_license,
            )

        # Public domain -> anything is OK
        if source.category == LicenseCategory.PUBLIC_DOMAIN:
            return LicenseCompatibility(
                compatible=True,
                source_license=source_license,
                target_license=target_license,
            )

        # Copyleft -> needs same or compatible copyleft
        if source.category in (LicenseCategory.WEAK_COPYLEFT, LicenseCategory.STRONG_COPYLEFT):
            if source.gpl_compatible and target.gpl_compatible:
                return LicenseCompatibility(
                    compatible=True,
                    source_license=source_license,
                    target_license=target_license,
                    recommendations=[
                        f"Ensure compliance with {source.spdx_id} terms (attribution, source disclosure if modified)"
                    ],
                )

            # AGPL is problematic for most uses
            if source.spdx_id and "AGPL" in source.spdx_id:
                return LicenseCompatibility(
                    compatible=False,
                    source_license=source_license,
                    target_license=target_license,
                    reason="AGPL requires source disclosure for network use",
                    recommendations=[
                        "Consider using an alternative library with permissive license",
                        "Ensure you can comply with AGPL source disclosure requirements",
                    ],
                )

            # Strong copyleft into non-copyleft
            if source.category == LicenseCategory.STRONG_COPYLEFT and \
               target.category == LicenseCategory.PERMISSIVE:
                return LicenseCompatibility(
                    compatible=False,
                    source_license=source_license,
                    target_license=target_license,
                    reason=f"{source.spdx_id} is copyleft and requires derivative works to use the same license",
                    recommendations=[
                        f"Change project license to {source.spdx_id} compatible license",
                        "Find an alternative dependency with permissive license",
                    ],
                )

        return LicenseCompatibility(
            compatible=True,
            source_license=source_license,
            target_license=target_license,
            reason="Licenses appear compatible, but verify specific terms",
        )

    def get_license_info(self, license_id: str) -> License | None:
        """Get license information by SPDX ID or alias."""
        return self.identify_license(license_id)

    def list_known_licenses(self) -> list[License]:
        """List all known licenses in the database."""
        return list(LICENSE_DATABASE.values())

    def list_high_risk_licenses(self) -> list[License]:
        """List licenses with high or critical risk."""
        return [
            lic for lic in LICENSE_DATABASE.values()
            if lic.risk in (LicenseRisk.HIGH, LicenseRisk.CRITICAL)
        ]
