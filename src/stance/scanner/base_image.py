"""
Base image vulnerability detection and management.

This module provides functionality for:
- Base image identification and tracking
- Known vulnerable base image detection
- Base image update recommendations
- Base image version pinning analysis
- Official image verification
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class BaseImageStatus(Enum):
    """Status of a base image."""

    CURRENT = "current"  # Using latest/recommended version
    OUTDATED = "outdated"  # Newer version available
    DEPRECATED = "deprecated"  # Image is deprecated
    EOL = "eol"  # End of life
    UNKNOWN = "unknown"  # Cannot determine status


class BaseImageRisk(Enum):
    """Risk level for base image issues."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BaseImageVersion:
    """Represents a version of a base image."""

    tag: str
    digest: Optional[str] = None
    created_at: Optional[datetime] = None
    os_version: Optional[str] = None
    size_bytes: int = 0
    is_latest: bool = False
    is_lts: bool = False
    eol_date: Optional[datetime] = None
    known_cve_count: int = 0


@dataclass
class BaseImageRecommendation:
    """Recommendation for base image update."""

    recommendation_type: str  # update, switch, pin
    severity: BaseImageRisk
    current_image: str
    recommended_image: Optional[str] = None
    reason: str = ""
    details: str = ""
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class BaseImageAnalysis:
    """Analysis result for a base image."""

    # Image identification
    image_reference: str
    image_digest: Optional[str] = None
    normalized_name: Optional[str] = None  # e.g., "python:3.11"

    # Image metadata
    os_family: Optional[str] = None  # debian, alpine, rhel
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    created_at: Optional[datetime] = None

    # Version analysis
    current_version: Optional[BaseImageVersion] = None
    latest_version: Optional[BaseImageVersion] = None
    available_versions: list[BaseImageVersion] = field(default_factory=list)

    # Status
    status: BaseImageStatus = BaseImageStatus.UNKNOWN
    is_official: bool = False
    is_pinned: bool = False
    uses_latest_tag: bool = False

    # Security analysis
    known_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    has_known_exploits: bool = False

    # Recommendations
    recommendations: list[BaseImageRecommendation] = field(default_factory=list)

    # Analysis metadata
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if analysis completed without errors."""
        return len(self.errors) == 0

    def summary(self) -> dict[str, Any]:
        """Get analysis summary."""
        return {
            "image_reference": self.image_reference,
            "normalized_name": self.normalized_name,
            "status": self.status.value,
            "is_official": self.is_official,
            "is_pinned": self.is_pinned,
            "uses_latest_tag": self.uses_latest_tag,
            "os_family": self.os_family,
            "known_vulnerabilities": self.known_vulnerabilities,
            "critical_vulnerabilities": self.critical_vulnerabilities,
            "recommendations_count": len(self.recommendations),
            "latest_available": self.latest_version.tag if self.latest_version else None,
        }


# Known vulnerable base images database
# This would typically be fetched from an external service
KNOWN_VULNERABLE_IMAGES = {
    # Alpine with known CVEs
    "alpine:3.14": {
        "cves": ["CVE-2021-36159", "CVE-2021-3711"],
        "status": BaseImageStatus.OUTDATED,
        "recommended": "alpine:3.19",
    },
    "alpine:3.15": {
        "cves": ["CVE-2022-28391"],
        "status": BaseImageStatus.OUTDATED,
        "recommended": "alpine:3.19",
    },
    # Ubuntu with known CVEs
    "ubuntu:18.04": {
        "cves": [],
        "status": BaseImageStatus.EOL,
        "recommended": "ubuntu:22.04",
        "eol_date": "2023-04-01",
    },
    "ubuntu:20.04": {
        "cves": [],
        "status": BaseImageStatus.CURRENT,
        "recommended": "ubuntu:22.04",
    },
    # Debian with known CVEs
    "debian:stretch": {
        "cves": [],
        "status": BaseImageStatus.EOL,
        "recommended": "debian:bookworm",
        "eol_date": "2022-07-01",
    },
    "debian:buster": {
        "cves": [],
        "status": BaseImageStatus.OUTDATED,
        "recommended": "debian:bookworm",
    },
    # Python images
    "python:3.7": {
        "cves": [],
        "status": BaseImageStatus.EOL,
        "recommended": "python:3.12",
        "eol_date": "2023-06-27",
    },
    "python:3.8": {
        "cves": [],
        "status": BaseImageStatus.OUTDATED,
        "recommended": "python:3.12",
    },
    # Node.js images
    "node:14": {
        "cves": [],
        "status": BaseImageStatus.EOL,
        "recommended": "node:20",
        "eol_date": "2023-04-30",
    },
    "node:16": {
        "cves": [],
        "status": BaseImageStatus.EOL,
        "recommended": "node:20",
        "eol_date": "2023-09-11",
    },
    "node:18": {
        "cves": [],
        "status": BaseImageStatus.CURRENT,
        "recommended": "node:20",
    },
}

# Official image registries
OFFICIAL_REGISTRIES = [
    "docker.io/library/",
    "library/",
    "gcr.io/distroless/",
    "mcr.microsoft.com/",
]

# Distroless recommendations for reduced attack surface
DISTROLESS_ALTERNATIVES = {
    "python": "gcr.io/distroless/python3",
    "node": "gcr.io/distroless/nodejs",
    "java": "gcr.io/distroless/java",
    "golang": "gcr.io/distroless/static",
    "rust": "gcr.io/distroless/cc",
}


class BaseImageAnalyzer:
    """
    Analyzer for base image vulnerabilities and recommendations.

    Provides:
    - Base image identification from container images
    - Known vulnerability detection
    - Update recommendations
    - Version pinning analysis
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        cache_ttl_hours: int = 24,
    ):
        """
        Initialize BaseImageAnalyzer.

        Args:
            cache_dir: Directory for caching data
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.cache_dir = cache_dir or Path.home() / ".stance" / "cache" / "base_images"
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def analyze(
        self,
        image_reference: str,
        check_registry: bool = True,
    ) -> BaseImageAnalysis:
        """
        Analyze a base image for vulnerabilities and issues.

        Args:
            image_reference: Image reference to analyze
            check_registry: Whether to check registry for updates

        Returns:
            BaseImageAnalysis with findings and recommendations
        """
        analysis = BaseImageAnalysis(image_reference=image_reference)

        # Parse image reference
        self._parse_image_reference(analysis)

        # Check if official image
        self._check_official_status(analysis)

        # Check known vulnerabilities database
        self._check_known_vulnerabilities(analysis)

        # Check for :latest tag usage
        self._check_latest_tag(analysis)

        # Check version pinning
        self._check_version_pinning(analysis)

        # Generate recommendations
        self._generate_recommendations(analysis)

        # Check for distroless alternatives
        self._check_distroless_alternatives(analysis)

        return analysis

    def analyze_from_layers(
        self,
        layers: list[dict],
        image_reference: str,
    ) -> BaseImageAnalysis:
        """
        Analyze base image from layer information.

        Args:
            layers: List of layer information dicts
            image_reference: Original image reference

        Returns:
            BaseImageAnalysis with findings
        """
        analysis = BaseImageAnalysis(image_reference=image_reference)

        # Try to detect base image from layer commands
        base_image = self._detect_base_from_layers(layers)
        if base_image:
            analysis.normalized_name = base_image
            self._parse_image_reference(analysis)

        # Analyze the detected base
        self._check_official_status(analysis)
        self._check_known_vulnerabilities(analysis)
        self._generate_recommendations(analysis)

        return analysis

    def _parse_image_reference(self, analysis: BaseImageAnalysis) -> None:
        """Parse and normalize image reference."""
        ref = analysis.image_reference

        # Remove registry prefix for normalization
        for registry in ["docker.io/", "index.docker.io/"]:
            if ref.startswith(registry):
                ref = ref[len(registry):]
                break

        # Handle library/ prefix
        if ref.startswith("library/"):
            ref = ref[8:]

        # Extract tag and digest
        if "@sha256:" in ref:
            base, digest = ref.split("@", 1)
            analysis.image_digest = digest
            analysis.is_pinned = True
            ref = base

        if ":" in ref:
            base, tag = ref.rsplit(":", 1)
            if tag == "latest":
                analysis.uses_latest_tag = True
        else:
            analysis.uses_latest_tag = True  # No tag implies :latest

        analysis.normalized_name = ref

        # Detect OS family from image name
        self._detect_os_family(analysis)

    def _detect_os_family(self, analysis: BaseImageAnalysis) -> None:
        """Detect OS family from image name."""
        name = (analysis.normalized_name or "").lower()

        os_patterns = {
            "alpine": "alpine",
            "ubuntu": "ubuntu",
            "debian": "debian",
            "centos": "centos",
            "fedora": "fedora",
            "rhel": "rhel",
            "ubi": "rhel",
            "amazonlinux": "amazonlinux",
            "busybox": "busybox",
            "distroless": "distroless",
        }

        for pattern, os_family in os_patterns.items():
            if pattern in name:
                analysis.os_family = os_family
                break

        # Language-based images typically use Debian
        if analysis.os_family is None:
            for lang in ["python", "node", "ruby", "golang", "java"]:
                if lang in name:
                    analysis.os_family = "debian"  # Default for official language images
                    break

    def _check_official_status(self, analysis: BaseImageAnalysis) -> None:
        """Check if image is from official registry."""
        ref = analysis.image_reference.lower()

        # Check for official registries
        for registry in OFFICIAL_REGISTRIES:
            if registry in ref:
                analysis.is_official = True
                return

        # Docker Hub official images have no namespace
        name = analysis.normalized_name or ""
        if "/" not in name and name:
            # Single-name images (alpine, ubuntu, python) are official
            official_images = [
                "alpine", "ubuntu", "debian", "centos", "fedora",
                "python", "node", "ruby", "golang", "java", "openjdk",
                "nginx", "httpd", "redis", "postgres", "mysql", "mongo",
                "busybox", "scratch",
            ]
            base_name = name.split(":")[0]
            if base_name in official_images:
                analysis.is_official = True

    def _check_known_vulnerabilities(self, analysis: BaseImageAnalysis) -> None:
        """Check against known vulnerable images database."""
        # Normalize for lookup
        lookup_keys = []

        if analysis.normalized_name:
            lookup_keys.append(analysis.normalized_name)

            # Also check without patch version (e.g., python:3.11 -> python:3.11)
            parts = analysis.normalized_name.split(":")
            if len(parts) == 2:
                base, tag = parts
                # Add version variants
                lookup_keys.append(f"{base}:{tag}")

                # For version tags, also check major.minor
                version_match = re.match(r"(\d+)\.(\d+)", tag)
                if version_match:
                    major_minor = f"{version_match.group(1)}.{version_match.group(2)}"
                    lookup_keys.append(f"{base}:{major_minor}")

                    # Check major only
                    lookup_keys.append(f"{base}:{version_match.group(1)}")

        # Check each variant
        for key in lookup_keys:
            if key in KNOWN_VULNERABLE_IMAGES:
                vuln_info = KNOWN_VULNERABLE_IMAGES[key]
                analysis.status = vuln_info.get("status", BaseImageStatus.UNKNOWN)
                analysis.known_vulnerabilities = len(vuln_info.get("cves", []))

                # Count severity
                for cve in vuln_info.get("cves", []):
                    # Simplified severity check (would need CVE lookup for real severity)
                    if "2021" in cve or "2022" in cve:
                        analysis.high_vulnerabilities += 1

                # Add recommendation if newer version available
                if "recommended" in vuln_info:
                    analysis.recommendations.append(
                        BaseImageRecommendation(
                            recommendation_type="update",
                            severity=BaseImageRisk.HIGH if analysis.status == BaseImageStatus.EOL else BaseImageRisk.MEDIUM,
                            current_image=analysis.image_reference,
                            recommended_image=vuln_info["recommended"],
                            reason=f"Current image is {analysis.status.value}",
                            cve_ids=vuln_info.get("cves", []),
                        )
                    )

                    # Add EOL details if applicable
                    if "eol_date" in vuln_info:
                        analysis.recommendations[-1].details = (
                            f"End of life: {vuln_info['eol_date']}"
                        )

                break

    def _check_latest_tag(self, analysis: BaseImageAnalysis) -> None:
        """Check for :latest tag usage."""
        if analysis.uses_latest_tag:
            analysis.recommendations.append(
                BaseImageRecommendation(
                    recommendation_type="pin",
                    severity=BaseImageRisk.MEDIUM,
                    current_image=analysis.image_reference,
                    reason="Using :latest tag makes builds non-reproducible",
                    details="Pin to specific version tag or digest for reproducible builds",
                )
            )

    def _check_version_pinning(self, analysis: BaseImageAnalysis) -> None:
        """Check for proper version pinning."""
        if not analysis.is_pinned and not analysis.uses_latest_tag:
            # Check if using only major version
            ref = analysis.image_reference
            version_match = re.search(r":(\d+)$", ref)
            if version_match:
                analysis.recommendations.append(
                    BaseImageRecommendation(
                        recommendation_type="pin",
                        severity=BaseImageRisk.LOW,
                        current_image=analysis.image_reference,
                        reason="Using only major version tag",
                        details="Consider pinning to minor or patch version for stability",
                    )
                )

    def _generate_recommendations(self, analysis: BaseImageAnalysis) -> None:
        """Generate additional recommendations based on analysis."""
        # Recommend distroless for production
        if not analysis.is_official:
            analysis.recommendations.append(
                BaseImageRecommendation(
                    recommendation_type="switch",
                    severity=BaseImageRisk.INFO,
                    current_image=analysis.image_reference,
                    reason="Not using official base image",
                    details="Consider using official Docker Hub images for better security",
                )
            )

        # Recommend smaller base if using full OS image
        if analysis.os_family in ["debian", "ubuntu", "centos", "fedora"]:
            if "-slim" not in analysis.image_reference and "-minimal" not in analysis.image_reference:
                analysis.recommendations.append(
                    BaseImageRecommendation(
                        recommendation_type="switch",
                        severity=BaseImageRisk.LOW,
                        current_image=analysis.image_reference,
                        reason="Using full OS image",
                        details="Consider using slim variant (e.g., python:3.11-slim) to reduce attack surface",
                    )
                )

    def _check_distroless_alternatives(self, analysis: BaseImageAnalysis) -> None:
        """Check if distroless alternative is available."""
        if analysis.os_family == "distroless":
            return  # Already using distroless

        name = (analysis.normalized_name or "").lower().split(":")[0]

        for lang, distroless in DISTROLESS_ALTERNATIVES.items():
            if lang in name:
                analysis.recommendations.append(
                    BaseImageRecommendation(
                        recommendation_type="switch",
                        severity=BaseImageRisk.INFO,
                        current_image=analysis.image_reference,
                        recommended_image=distroless,
                        reason="Distroless alternative available",
                        details="Distroless images have minimal attack surface with no shell or package manager",
                    )
                )
                break

    def _detect_base_from_layers(self, layers: list[dict]) -> Optional[str]:
        """Detect base image from layer commands."""
        # Look for FROM patterns in layer history
        from_patterns = [
            r"FROM\s+(\S+)",
            r"#\(nop\)\s+FROM\s+(\S+)",
        ]

        for layer in layers[:5]:  # Check first 5 layers
            cmd = layer.get("created_by", "") or layer.get("CreatedBy", "")

            for pattern in from_patterns:
                match = re.search(pattern, cmd, re.IGNORECASE)
                if match:
                    return match.group(1)

        return None

    def get_update_recommendations(
        self,
        image_reference: str,
    ) -> list[BaseImageRecommendation]:
        """
        Get update recommendations for a base image.

        Args:
            image_reference: Image to check

        Returns:
            List of recommendations
        """
        analysis = self.analyze(image_reference)
        return [r for r in analysis.recommendations if r.recommendation_type == "update"]

    def check_eol_status(
        self,
        image_reference: str,
    ) -> tuple[bool, Optional[str]]:
        """
        Check if base image has reached end of life.

        Args:
            image_reference: Image to check

        Returns:
            Tuple of (is_eol, eol_date)
        """
        analysis = self.analyze(image_reference)

        if analysis.status == BaseImageStatus.EOL:
            # Find EOL date from recommendations
            for rec in analysis.recommendations:
                if "End of life:" in rec.details:
                    date_str = rec.details.replace("End of life:", "").strip()
                    return True, date_str

            return True, None

        return False, None


@dataclass
class BaseImageInventory:
    """Inventory of base images across a container fleet."""

    images: dict[str, BaseImageAnalysis] = field(default_factory=dict)
    total_images: int = 0
    unique_base_images: int = 0
    eol_count: int = 0
    outdated_count: int = 0
    unpinned_count: int = 0
    unofficial_count: int = 0

    def add_analysis(self, analysis: BaseImageAnalysis) -> None:
        """Add analysis result to inventory."""
        key = analysis.normalized_name or analysis.image_reference
        self.images[key] = analysis
        self.total_images += 1

        if key not in self.images:
            self.unique_base_images += 1

        if analysis.status == BaseImageStatus.EOL:
            self.eol_count += 1
        elif analysis.status == BaseImageStatus.OUTDATED:
            self.outdated_count += 1

        if not analysis.is_pinned:
            self.unpinned_count += 1

        if not analysis.is_official:
            self.unofficial_count += 1

    def get_summary(self) -> dict[str, Any]:
        """Get inventory summary."""
        return {
            "total_images": self.total_images,
            "unique_base_images": self.unique_base_images,
            "eol_count": self.eol_count,
            "outdated_count": self.outdated_count,
            "unpinned_count": self.unpinned_count,
            "unofficial_count": self.unofficial_count,
            "images": {
                name: analysis.summary()
                for name, analysis in self.images.items()
            },
        }


def analyze_base_image(
    image_reference: str,
) -> BaseImageAnalysis:
    """
    Convenience function to analyze a base image.

    Args:
        image_reference: Image to analyze

    Returns:
        BaseImageAnalysis with findings

    Example:
        >>> analysis = analyze_base_image("python:3.8")
        >>> print(f"Status: {analysis.status.value}")
        >>> for rec in analysis.recommendations:
        ...     print(f"  {rec.reason}")
    """
    analyzer = BaseImageAnalyzer()
    return analyzer.analyze(image_reference)


def check_base_image_vulnerabilities(
    image_references: list[str],
) -> BaseImageInventory:
    """
    Check multiple images for base image vulnerabilities.

    Args:
        image_references: List of images to check

    Returns:
        BaseImageInventory with all analyses

    Example:
        >>> inventory = check_base_image_vulnerabilities([
        ...     "python:3.8",
        ...     "node:16",
        ...     "nginx:latest"
        ... ])
        >>> print(f"EOL images: {inventory.eol_count}")
    """
    analyzer = BaseImageAnalyzer()
    inventory = BaseImageInventory()

    for ref in image_references:
        try:
            analysis = analyzer.analyze(ref)
            inventory.add_analysis(analysis)
        except Exception as e:
            logger.warning(f"Failed to analyze {ref}: {e}")
            # Add error entry
            error_analysis = BaseImageAnalysis(
                image_reference=ref,
                errors=[str(e)],
            )
            inventory.add_analysis(error_analysis)

    return inventory
