"""
Container image layer analysis.

This module provides detailed analysis of container image layers,
including:
- Layer-by-layer vulnerability attribution
- Base image identification and tracking
- Layer size and efficiency analysis
- Added file tracking per layer
- Security-relevant layer changes detection
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class LayerType(Enum):
    """Types of container image layers."""

    BASE = "base"  # From base image
    PACKAGE_INSTALL = "package_install"  # Package manager operations
    FILE_COPY = "file_copy"  # COPY/ADD instructions
    CONFIG = "config"  # Configuration changes
    USER = "user"  # User/permission changes
    WORKDIR = "workdir"  # Working directory changes
    ENV = "env"  # Environment variable changes
    RUN = "run"  # Generic RUN commands
    ENTRYPOINT = "entrypoint"  # Entrypoint/CMD changes
    UNKNOWN = "unknown"  # Cannot determine type


class LayerRisk(Enum):
    """Risk levels for layer changes."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class LayerFile:
    """Represents a file added or modified in a layer."""

    path: str
    size_bytes: int
    mode: str  # File mode (e.g., "0755")
    is_executable: bool
    is_setuid: bool
    is_setgid: bool
    is_world_writable: bool
    file_type: str  # file, directory, symlink


@dataclass
class LayerSecurityIssue:
    """Security issue detected in a layer."""

    issue_type: str
    severity: LayerRisk
    description: str
    file_path: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class ImageLayer:
    """Represents a single layer in a container image."""

    # Layer identification
    digest: str  # Layer digest (sha256:...)
    index: int  # Layer index (0 = oldest/base)

    # Layer metadata
    created_by: str  # Command that created the layer
    created_at: Optional[datetime] = None
    size_bytes: int = 0

    # Layer classification
    layer_type: LayerType = LayerType.UNKNOWN
    is_empty: bool = False
    is_base_layer: bool = False

    # Content analysis
    files_added: list[LayerFile] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)

    # Package changes
    packages_installed: list[str] = field(default_factory=list)
    packages_removed: list[str] = field(default_factory=list)

    # Security analysis
    security_issues: list[LayerSecurityIssue] = field(default_factory=list)
    vulnerability_count: int = 0

    # Raw data
    raw_config: dict = field(default_factory=dict)

    def get_command_summary(self) -> str:
        """Get a short summary of the layer command."""
        cmd = self.created_by
        if len(cmd) > 80:
            return cmd[:77] + "..."
        return cmd

    def get_size_human(self) -> str:
        """Get human-readable size."""
        size = self.size_bytes
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


@dataclass
class BaseImageInfo:
    """Information about the base image."""

    # Base image reference
    image_reference: Optional[str] = None  # e.g., "ubuntu:22.04"
    image_digest: Optional[str] = None

    # Base image metadata
    os_family: Optional[str] = None  # debian, alpine, rhel, etc.
    os_version: Optional[str] = None
    architecture: Optional[str] = None

    # Layer information
    layer_count: int = 0
    layer_digests: list[str] = field(default_factory=list)
    total_size_bytes: int = 0

    # Security status
    is_official: bool = False
    is_latest_tag: bool = False
    is_pinned: bool = False  # Has digest or specific tag
    known_vulnerabilities: int = 0

    # Recommendations
    recommendations: list[str] = field(default_factory=list)

    def get_size_human(self) -> str:
        """Get human-readable size."""
        size = self.total_size_bytes
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


@dataclass
class LayerAnalysisResult:
    """Result of container image layer analysis."""

    # Image identification
    image_reference: str
    image_digest: Optional[str] = None

    # Analysis metadata
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    analysis_duration_seconds: float = 0.0

    # Layers
    layers: list[ImageLayer] = field(default_factory=list)
    total_layers: int = 0
    base_layers: int = 0
    application_layers: int = 0

    # Base image
    base_image: Optional[BaseImageInfo] = None

    # Size analysis
    total_size_bytes: int = 0
    base_image_size_bytes: int = 0
    application_size_bytes: int = 0

    # Security summary
    total_security_issues: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0

    # Errors
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if analysis completed without errors."""
        return len(self.errors) == 0

    def get_size_human(self) -> str:
        """Get human-readable total size."""
        size = self.total_size_bytes
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def summary(self) -> dict[str, Any]:
        """Get analysis summary."""
        return {
            "image_reference": self.image_reference,
            "image_digest": self.image_digest,
            "total_layers": self.total_layers,
            "base_layers": self.base_layers,
            "application_layers": self.application_layers,
            "total_size": self.get_size_human(),
            "base_image_size": self.base_image.get_size_human() if self.base_image else "unknown",
            "application_size_bytes": self.application_size_bytes,
            "total_security_issues": self.total_security_issues,
            "issues_by_severity": {
                "critical": self.critical_issues,
                "high": self.high_issues,
                "medium": self.medium_issues,
                "low": self.low_issues,
            },
            "base_image": {
                "reference": self.base_image.image_reference if self.base_image else None,
                "is_pinned": self.base_image.is_pinned if self.base_image else None,
                "is_official": self.base_image.is_official if self.base_image else None,
            },
        }


class LayerAnalyzer:
    """
    Analyzer for container image layers.

    Provides detailed analysis of container image layers including:
    - Layer-by-layer breakdown
    - Base image identification
    - Security issue detection per layer
    - Size and efficiency analysis

    Requires Docker or Skopeo for image inspection.
    """

    # Known base image patterns
    BASE_IMAGE_PATTERNS = {
        "alpine": r"alpine[:\d.]*",
        "ubuntu": r"ubuntu[:\d.]*",
        "debian": r"debian[:\d.]*",
        "centos": r"centos[:\d.]*",
        "fedora": r"fedora[:\d.]*",
        "rhel": r"(?:rhel|ubi)[:\d.]*",
        "amazonlinux": r"amazonlinux[:\d.]*",
        "busybox": r"busybox[:\d.]*",
        "scratch": r"scratch",
        "distroless": r"gcr\.io/distroless/.*",
        "python": r"python[:\d.]*",
        "node": r"node[:\d.]*",
        "golang": r"golang[:\d.]*",
        "openjdk": r"openjdk[:\d.]*",
        "nginx": r"nginx[:\d.]*",
    }

    # Package manager commands by OS
    PACKAGE_MANAGERS = {
        "apt-get": ["install", "update", "upgrade"],
        "apt": ["install", "update", "upgrade"],
        "apk": ["add", "update", "upgrade"],
        "yum": ["install", "update", "upgrade"],
        "dnf": ["install", "update", "upgrade"],
        "pip": ["install"],
        "pip3": ["install"],
        "npm": ["install", "ci"],
        "yarn": ["install", "add"],
        "gem": ["install"],
        "cargo": ["install"],
    }

    def __init__(
        self,
        docker_path: Optional[str] = None,
        skopeo_path: Optional[str] = None,
    ):
        """
        Initialize LayerAnalyzer.

        Args:
            docker_path: Path to docker binary (auto-detected if None)
            skopeo_path: Path to skopeo binary (auto-detected if None)
        """
        self._docker_path = docker_path
        self._skopeo_path = skopeo_path

    def _get_docker_path(self) -> Optional[str]:
        """Get path to docker binary."""
        if self._docker_path:
            return self._docker_path
        return shutil.which("docker")

    def _get_skopeo_path(self) -> Optional[str]:
        """Get path to skopeo binary."""
        if self._skopeo_path:
            return self._skopeo_path
        return shutil.which("skopeo")

    def is_available(self) -> bool:
        """Check if analyzer tools are available."""
        return bool(self._get_docker_path() or self._get_skopeo_path())

    def analyze(
        self,
        image_reference: str,
        timeout_seconds: int = 120,
    ) -> LayerAnalysisResult:
        """
        Analyze container image layers.

        Args:
            image_reference: Image to analyze (e.g., nginx:latest)
            timeout_seconds: Maximum time for analysis

        Returns:
            LayerAnalysisResult with layer details
        """
        import time
        start_time = time.time()

        result = LayerAnalysisResult(image_reference=image_reference)

        # Try docker first, then skopeo
        docker_path = self._get_docker_path()
        if docker_path:
            try:
                self._analyze_with_docker(result, docker_path, timeout_seconds)
            except Exception as e:
                logger.warning(f"Docker analysis failed: {e}")
                result.errors.append(str(e))
        else:
            skopeo_path = self._get_skopeo_path()
            if skopeo_path:
                try:
                    self._analyze_with_skopeo(result, skopeo_path, timeout_seconds)
                except Exception as e:
                    logger.warning(f"Skopeo analysis failed: {e}")
                    result.errors.append(str(e))
            else:
                result.errors.append(
                    "Neither docker nor skopeo available for image analysis"
                )

        # Post-process results
        self._identify_base_image(result)
        self._classify_layers(result)
        self._detect_security_issues(result)
        self._calculate_statistics(result)

        result.analysis_duration_seconds = time.time() - start_time
        return result

    def _analyze_with_docker(
        self,
        result: LayerAnalysisResult,
        docker_path: str,
        timeout_seconds: int,
    ) -> None:
        """Analyze image using docker inspect."""
        try:
            # Get image configuration
            cmd = [docker_path, "inspect", result.image_reference]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            if proc.returncode != 0:
                raise RuntimeError(f"docker inspect failed: {proc.stderr}")

            inspect_data = json.loads(proc.stdout)
            if not inspect_data:
                raise RuntimeError("Empty inspect result")

            image_info = inspect_data[0]

            # Extract image digest
            if "RepoDigests" in image_info and image_info["RepoDigests"]:
                for digest in image_info["RepoDigests"]:
                    if "@sha256:" in digest:
                        result.image_digest = digest.split("@")[-1]
                        break

            # Get history for layer information
            cmd = [docker_path, "history", "--no-trunc", "--format", "json", result.image_reference]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            if proc.returncode == 0:
                self._parse_docker_history(result, proc.stdout, image_info)
            else:
                # Fallback to regular history
                self._parse_docker_history_fallback(result, image_info)

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Docker analysis timed out after {timeout_seconds}s")

    def _parse_docker_history(
        self,
        result: LayerAnalysisResult,
        history_output: str,
        image_info: dict,
    ) -> None:
        """Parse docker history JSON output."""
        layers = []

        # Parse JSONL output
        for line in history_output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                layers.append(entry)
            except json.JSONDecodeError:
                continue

        # Reverse to get oldest first
        layers.reverse()

        # Get layer digests from RootFS
        layer_digests = []
        if "RootFS" in image_info:
            layer_digests = image_info["RootFS"].get("Layers", [])

        # Process layers
        for i, entry in enumerate(layers):
            layer = ImageLayer(
                digest=layer_digests[i] if i < len(layer_digests) else f"unknown:{i}",
                index=i,
                created_by=entry.get("CreatedBy", ""),
                size_bytes=self._parse_size(entry.get("Size", "0")),
                is_empty=entry.get("Size", "0") == "0B" or entry.get("Size", "0") == "0",
            )

            # Parse created time
            created_str = entry.get("CreatedAt", "")
            if created_str:
                try:
                    layer.created_at = datetime.fromisoformat(
                        created_str.replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            result.layers.append(layer)

    def _parse_docker_history_fallback(
        self,
        result: LayerAnalysisResult,
        image_info: dict,
    ) -> None:
        """Parse layer info from image config when history command fails."""
        history = image_info.get("History", [])
        layer_digests = []
        if "RootFS" in image_info:
            layer_digests = image_info["RootFS"].get("Layers", [])

        digest_idx = 0
        for i, entry in enumerate(history):
            is_empty = entry.get("empty_layer", False)

            layer = ImageLayer(
                digest=layer_digests[digest_idx] if digest_idx < len(layer_digests) and not is_empty else f"empty:{i}",
                index=i,
                created_by=entry.get("created_by", ""),
                is_empty=is_empty,
            )

            if not is_empty:
                digest_idx += 1

            result.layers.append(layer)

    def _analyze_with_skopeo(
        self,
        result: LayerAnalysisResult,
        skopeo_path: str,
        timeout_seconds: int,
    ) -> None:
        """Analyze image using skopeo inspect."""
        try:
            cmd = [
                skopeo_path, "inspect",
                f"docker://{result.image_reference}",
                "--config",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )

            if proc.returncode != 0:
                raise RuntimeError(f"skopeo inspect failed: {proc.stderr}")

            config = json.loads(proc.stdout)

            # Get digest
            if "digest" in config:
                result.image_digest = config["digest"]

            # Parse history
            history = config.get("history", [])
            layer_digests = config.get("rootfs", {}).get("diff_ids", [])

            digest_idx = 0
            for i, entry in enumerate(history):
                is_empty = entry.get("empty_layer", False)

                layer = ImageLayer(
                    digest=layer_digests[digest_idx] if digest_idx < len(layer_digests) and not is_empty else f"empty:{i}",
                    index=i,
                    created_by=entry.get("created_by", ""),
                    is_empty=is_empty,
                )

                if not is_empty:
                    digest_idx += 1

                result.layers.append(layer)

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Skopeo analysis timed out after {timeout_seconds}s")

    def _identify_base_image(self, result: LayerAnalysisResult) -> None:
        """Identify the base image from layer history."""
        if not result.layers:
            return

        base_info = BaseImageInfo()

        # Look for FROM instruction pattern in first layers
        for layer in result.layers[:10]:  # Check first 10 layers
            cmd = layer.created_by.lower()

            # Check for known base image patterns
            for os_name, pattern in self.BASE_IMAGE_PATTERNS.items():
                if re.search(pattern, cmd, re.IGNORECASE):
                    base_info.os_family = os_name
                    break

            # Check if using official images
            if "library/" in cmd or any(
                off in cmd for off in ["alpine", "ubuntu", "debian", "python", "node"]
            ):
                base_info.is_official = True

        # Determine base layer count (heuristic: layers before first COPY/ADD)
        for i, layer in enumerate(result.layers):
            cmd = layer.created_by.upper()
            if cmd.startswith("COPY") or cmd.startswith("ADD"):
                base_info.layer_count = i
                break
        else:
            # No COPY/ADD found, assume all are base layers
            base_info.layer_count = len(result.layers)

        # Mark base layers
        for i in range(min(base_info.layer_count, len(result.layers))):
            result.layers[i].is_base_layer = True

        # Calculate base image size
        base_info.total_size_bytes = sum(
            layer.size_bytes for layer in result.layers[:base_info.layer_count]
        )

        # Collect base layer digests
        base_info.layer_digests = [
            layer.digest for layer in result.layers[:base_info.layer_count]
            if not layer.is_empty
        ]

        # Check for :latest tag usage
        if ":latest" in result.image_reference or ":" not in result.image_reference:
            base_info.is_latest_tag = True
            base_info.recommendations.append(
                "Avoid using :latest tag; pin to specific version for reproducibility"
            )

        # Check if image is pinned
        if "@sha256:" in result.image_reference:
            base_info.is_pinned = True
        elif re.search(r":\d+\.\d+", result.image_reference):
            base_info.is_pinned = True

        if not base_info.is_pinned:
            base_info.recommendations.append(
                "Pin base image to specific version or digest"
            )

        result.base_image = base_info

    def _classify_layers(self, result: LayerAnalysisResult) -> None:
        """Classify each layer by type."""
        for layer in result.layers:
            layer.layer_type = self._classify_layer_command(layer.created_by)

            # Extract installed packages if package manager command
            if layer.layer_type == LayerType.PACKAGE_INSTALL:
                layer.packages_installed = self._extract_packages(layer.created_by)

    def _classify_layer_command(self, command: str) -> LayerType:
        """Classify a layer based on its command."""
        cmd = command.strip()
        cmd_upper = cmd.upper()

        # Empty layer check
        if not cmd or cmd == "<missing>":
            return LayerType.BASE

        # COPY/ADD
        if cmd_upper.startswith("COPY") or cmd_upper.startswith("ADD"):
            return LayerType.FILE_COPY

        # USER
        if cmd_upper.startswith("USER"):
            return LayerType.USER

        # WORKDIR
        if cmd_upper.startswith("WORKDIR"):
            return LayerType.WORKDIR

        # ENV
        if cmd_upper.startswith("ENV"):
            return LayerType.ENV

        # ENTRYPOINT/CMD
        if cmd_upper.startswith("ENTRYPOINT") or cmd_upper.startswith("CMD"):
            return LayerType.ENTRYPOINT

        # Check for package manager commands
        cmd_lower = cmd.lower()
        for pkg_mgr, actions in self.PACKAGE_MANAGERS.items():
            if pkg_mgr in cmd_lower:
                for action in actions:
                    if action in cmd_lower:
                        return LayerType.PACKAGE_INSTALL

        # Generic RUN
        if cmd_upper.startswith("RUN") or cmd_upper.startswith("/BIN/SH"):
            return LayerType.RUN

        return LayerType.UNKNOWN

    def _extract_packages(self, command: str) -> list[str]:
        """Extract package names from package manager commands."""
        packages = []
        cmd = command.lower()

        # apt-get/apt install
        if "apt-get install" in cmd or "apt install" in cmd:
            # Extract packages after 'install'
            match = re.search(r"install\s+(.+?)(?:&&|$)", cmd)
            if match:
                pkg_str = match.group(1)
                # Remove options like -y, --no-install-recommends
                pkg_str = re.sub(r"-\w+|--\w+(-\w+)*", "", pkg_str)
                packages = [p.strip() for p in pkg_str.split() if p.strip() and not p.startswith("-")]

        # apk add
        elif "apk add" in cmd:
            match = re.search(r"add\s+(.+?)(?:&&|$)", cmd)
            if match:
                pkg_str = match.group(1)
                pkg_str = re.sub(r"--\w+(-\w+)*", "", pkg_str)
                packages = [p.strip() for p in pkg_str.split() if p.strip() and not p.startswith("-")]

        # yum/dnf install
        elif "yum install" in cmd or "dnf install" in cmd:
            match = re.search(r"install\s+(.+?)(?:&&|$)", cmd)
            if match:
                pkg_str = match.group(1)
                pkg_str = re.sub(r"-\w+", "", pkg_str)
                packages = [p.strip() for p in pkg_str.split() if p.strip() and not p.startswith("-")]

        return packages

    def _detect_security_issues(self, result: LayerAnalysisResult) -> None:
        """Detect security issues in layers."""
        for layer in result.layers:
            issues = self._analyze_layer_security(layer)
            layer.security_issues.extend(issues)

    def _analyze_layer_security(self, layer: ImageLayer) -> list[LayerSecurityIssue]:
        """Analyze a single layer for security issues."""
        issues = []
        cmd = layer.created_by.lower()

        # Check for running as root
        if "user root" in cmd:
            issues.append(LayerSecurityIssue(
                issue_type="root_user",
                severity=LayerRisk.MEDIUM,
                description="Layer explicitly sets USER to root",
                remediation="Run container as non-root user",
            ))

        # Check for curl/wget to download and execute
        if ("curl" in cmd or "wget" in cmd) and ("|" in cmd or ">" in cmd):
            if "bash" in cmd or "sh" in cmd or "chmod" in cmd:
                issues.append(LayerSecurityIssue(
                    issue_type="remote_execution",
                    severity=LayerRisk.HIGH,
                    description="Layer downloads and executes remote script",
                    remediation="Vendor scripts locally and verify integrity",
                ))

        # Check for package cache not cleaned
        if "apt-get install" in cmd or "apt install" in cmd:
            if "rm -rf /var/lib/apt/lists" not in cmd and "apt-get clean" not in cmd:
                issues.append(LayerSecurityIssue(
                    issue_type="package_cache_retained",
                    severity=LayerRisk.LOW,
                    description="Package cache not cleaned after install",
                    remediation="Add 'rm -rf /var/lib/apt/lists/*' after apt operations",
                ))

        # Check for apk cache
        if "apk add" in cmd and "--no-cache" not in cmd:
            if "rm -rf /var/cache/apk" not in cmd:
                issues.append(LayerSecurityIssue(
                    issue_type="package_cache_retained",
                    severity=LayerRisk.LOW,
                    description="APK cache not cleaned",
                    remediation="Use 'apk add --no-cache' option",
                ))

        # Check for hardcoded secrets patterns
        secret_patterns = [
            (r"password\s*=\s*['\"][^'\"]+['\"]", "hardcoded_password"),
            (r"api_key\s*=\s*['\"][^'\"]+['\"]", "hardcoded_api_key"),
            (r"secret\s*=\s*['\"][^'\"]+['\"]", "hardcoded_secret"),
            (r"aws_access_key_id\s*=\s*['\"]?[A-Z0-9]{20}", "aws_access_key"),
            (r"aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}", "aws_secret_key"),
        ]

        for pattern, issue_type in secret_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                issues.append(LayerSecurityIssue(
                    issue_type=issue_type,
                    severity=LayerRisk.CRITICAL,
                    description=f"Potential {issue_type.replace('_', ' ')} in layer command",
                    remediation="Use build-time secrets or environment variables at runtime",
                ))

        # Check for chmod 777
        if "chmod 777" in cmd or "chmod -R 777" in cmd:
            issues.append(LayerSecurityIssue(
                issue_type="world_writable",
                severity=LayerRisk.HIGH,
                description="Layer sets world-writable permissions (777)",
                remediation="Use least privilege permissions (e.g., 755 for directories, 644 for files)",
            ))

        # Check for setuid binaries creation
        if "chmod u+s" in cmd or "chmod +s" in cmd:
            issues.append(LayerSecurityIssue(
                issue_type="setuid_binary",
                severity=LayerRisk.HIGH,
                description="Layer creates setuid binary",
                remediation="Avoid setuid binaries; use capabilities instead",
            ))

        # Check for SSH keys in layer
        if ".ssh" in cmd and ("copy" in cmd.lower() or "add" in cmd.lower()):
            issues.append(LayerSecurityIssue(
                issue_type="ssh_keys_copied",
                severity=LayerRisk.CRITICAL,
                description="SSH keys may be copied into image",
                remediation="Use SSH agent forwarding or multi-stage builds",
            ))

        # Check for installation of specific risky packages
        risky_packages = ["telnet", "ftp", "rsh", "rlogin", "netcat", "nc"]
        for pkg in risky_packages:
            if re.search(rf"\b{pkg}\b", cmd):
                issues.append(LayerSecurityIssue(
                    issue_type="risky_package",
                    severity=LayerRisk.MEDIUM,
                    description=f"Potentially risky package installed: {pkg}",
                    remediation=f"Remove {pkg} unless specifically required",
                ))

        return issues

    def _calculate_statistics(self, result: LayerAnalysisResult) -> None:
        """Calculate summary statistics."""
        result.total_layers = len(result.layers)
        result.base_layers = sum(1 for l in result.layers if l.is_base_layer)
        result.application_layers = result.total_layers - result.base_layers

        result.total_size_bytes = sum(l.size_bytes for l in result.layers)
        result.base_image_size_bytes = sum(
            l.size_bytes for l in result.layers if l.is_base_layer
        )
        result.application_size_bytes = result.total_size_bytes - result.base_image_size_bytes

        # Count security issues
        for layer in result.layers:
            for issue in layer.security_issues:
                result.total_security_issues += 1
                if issue.severity == LayerRisk.CRITICAL:
                    result.critical_issues += 1
                elif issue.severity == LayerRisk.HIGH:
                    result.high_issues += 1
                elif issue.severity == LayerRisk.MEDIUM:
                    result.medium_issues += 1
                elif issue.severity == LayerRisk.LOW:
                    result.low_issues += 1

    def _parse_size(self, size_str: str) -> int:
        """Parse size string to bytes."""
        if not size_str or size_str == "0":
            return 0

        size_str = size_str.strip().upper()

        multipliers = {
            "B": 1,
            "KB": 1024,
            "MB": 1024 * 1024,
            "GB": 1024 * 1024 * 1024,
            "TB": 1024 * 1024 * 1024 * 1024,
        }

        for suffix, mult in multipliers.items():
            if size_str.endswith(suffix):
                try:
                    return int(float(size_str[:-len(suffix)].strip()) * mult)
                except ValueError:
                    return 0

        try:
            return int(size_str)
        except ValueError:
            return 0


def analyze_layers(
    image_reference: str,
    timeout_seconds: int = 120,
) -> LayerAnalysisResult:
    """
    Convenience function to analyze container image layers.

    Args:
        image_reference: Image to analyze (e.g., nginx:latest)
        timeout_seconds: Maximum time for analysis

    Returns:
        LayerAnalysisResult with layer details

    Example:
        >>> result = analyze_layers("nginx:1.21")
        >>> print(f"Total layers: {result.total_layers}")
        >>> print(f"Base layers: {result.base_layers}")
        >>> for layer in result.layers:
        ...     print(f"  {layer.index}: {layer.get_command_summary()}")
    """
    analyzer = LayerAnalyzer()
    return analyzer.analyze(image_reference, timeout_seconds)
