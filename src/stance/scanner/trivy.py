"""
Trivy scanner implementation.

Provides container image vulnerability scanning using Trivy.
Trivy is an open source vulnerability scanner for containers and
other artifacts.

https://github.com/aquasecurity/trivy
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from datetime import datetime
from typing import Any

from stance.scanner.base import (
    ImageScanner,
    ScanResult,
    Vulnerability,
    VulnerabilitySeverity,
    ScannerError,
    ScannerNotAvailableError,
    ScannerTimeoutError,
)

logger = logging.getLogger(__name__)


class TrivyScanner(ImageScanner):
    """
    Container image scanner using Trivy.

    Trivy is a comprehensive vulnerability scanner that supports:
    - Container images
    - Filesystems
    - Git repositories
    - Kubernetes clusters

    This implementation focuses on container image scanning.

    Installation:
        brew install trivy
        # or
        apt-get install trivy
        # or
        docker run aquasec/trivy image <image>

    Usage:
        scanner = TrivyScanner()
        if scanner.is_available():
            result = scanner.scan("nginx:latest")
            print(f"Found {result.vulnerability_count} vulnerabilities")
    """

    scanner_name: str = "trivy"

    def __init__(
        self,
        trivy_path: str | None = None,
        cache_dir: str | None = None,
    ):
        """
        Initialize TrivyScanner.

        Args:
            trivy_path: Path to trivy binary (auto-detected if None)
            cache_dir: Directory for Trivy cache (uses default if None)
        """
        self._trivy_path = trivy_path
        self._cache_dir = cache_dir
        self._version: str | None = None

    def _get_trivy_path(self) -> str | None:
        """Get the path to the trivy binary."""
        if self._trivy_path:
            return self._trivy_path

        # Try to find trivy in PATH
        path = shutil.which("trivy")
        if path:
            return path

        # Common installation locations
        common_paths = [
            "/usr/local/bin/trivy",
            "/usr/bin/trivy",
            "/opt/homebrew/bin/trivy",
        ]
        for p in common_paths:
            if shutil.which(p):
                return p

        return None

    def is_available(self) -> bool:
        """Check if Trivy is available on the system."""
        trivy_path = self._get_trivy_path()
        if not trivy_path:
            return False

        try:
            result = subprocess.run(
                [trivy_path, "--version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    def get_version(self) -> str | None:
        """Get the Trivy version."""
        if self._version:
            return self._version

        trivy_path = self._get_trivy_path()
        if not trivy_path:
            return None

        try:
            result = subprocess.run(
                [trivy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                # Parse version from output like "Version: 0.48.0"
                output = result.stdout.strip()
                for line in output.split("\n"):
                    if line.startswith("Version:"):
                        self._version = line.split(":", 1)[1].strip()
                        return self._version
                # Fallback: return first line
                self._version = output.split("\n")[0]
                return self._version
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return None

    def scan(
        self,
        image_reference: str,
        timeout_seconds: int = 300,
        skip_db_update: bool = False,
        ignore_unfixed: bool = False,
    ) -> ScanResult:
        """
        Scan a container image using Trivy.

        Args:
            image_reference: Image to scan (e.g., nginx:latest)
            timeout_seconds: Maximum time to wait for scan
            skip_db_update: Skip vulnerability database update
            ignore_unfixed: Exclude vulnerabilities without fixes

        Returns:
            ScanResult with vulnerabilities found
        """
        trivy_path = self._get_trivy_path()
        if not trivy_path:
            raise ScannerNotAvailableError(
                "Trivy is not installed. Install with: brew install trivy"
            )

        start_time = time.time()

        # Build trivy command
        cmd = [
            trivy_path,
            "image",
            "--format", "json",
            "--quiet",
        ]

        # Add options
        if skip_db_update:
            cmd.append("--skip-db-update")

        if ignore_unfixed:
            cmd.append("--ignore-unfixed")

        if self._cache_dir:
            cmd.extend(["--cache-dir", self._cache_dir])

        # Add image reference
        cmd.append(image_reference)

        logger.debug(f"Running trivy: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise ScannerTimeoutError(
                f"Trivy scan of {image_reference} timed out after {timeout_seconds}s"
            )
        except FileNotFoundError:
            raise ScannerNotAvailableError("Trivy binary not found")
        except OSError as e:
            raise ScannerError(f"Failed to run Trivy: {e}")

        duration = time.time() - start_time

        # Check for errors
        errors: list[str] = []
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                errors.append(stderr)
            if not result.stdout:
                # Complete failure
                return ScanResult(
                    image_reference=image_reference,
                    scanner_name=self.scanner_name,
                    scanner_version=self.get_version(),
                    scan_timestamp=datetime.utcnow(),
                    scan_duration_seconds=duration,
                    errors=errors or [f"Trivy exited with code {result.returncode}"],
                    skip_db_update=skip_db_update,
                    ignore_unfixed=ignore_unfixed,
                )

        # Parse JSON output
        try:
            trivy_output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            return ScanResult(
                image_reference=image_reference,
                scanner_name=self.scanner_name,
                scanner_version=self.get_version(),
                scan_timestamp=datetime.utcnow(),
                scan_duration_seconds=duration,
                errors=[f"Failed to parse Trivy output: {e}"],
                skip_db_update=skip_db_update,
                ignore_unfixed=ignore_unfixed,
            )

        # Extract vulnerabilities from Trivy output
        return self._parse_trivy_output(
            trivy_output=trivy_output,
            image_reference=image_reference,
            duration=duration,
            errors=errors,
            skip_db_update=skip_db_update,
            ignore_unfixed=ignore_unfixed,
        )

    def _parse_trivy_output(
        self,
        trivy_output: dict[str, Any],
        image_reference: str,
        duration: float,
        errors: list[str],
        skip_db_update: bool,
        ignore_unfixed: bool,
    ) -> ScanResult:
        """Parse Trivy JSON output into ScanResult."""
        vulnerabilities: list[Vulnerability] = []

        # Extract image metadata
        metadata = trivy_output.get("Metadata", {})
        image_digest = None
        os_family = None
        os_version = None
        architecture = None
        image_size = None

        # Handle different Trivy output formats
        if "RepoDigests" in metadata:
            digests = metadata.get("RepoDigests", [])
            if digests:
                # Extract sha256 digest
                for d in digests:
                    if "@sha256:" in d:
                        image_digest = d.split("@")[-1]
                        break

        if "OS" in metadata:
            os_info = metadata.get("OS", {})
            os_family = os_info.get("Family")
            os_version = os_info.get("Name")

        if "ImageConfig" in metadata:
            config = metadata.get("ImageConfig", {})
            architecture = config.get("architecture")

        if "Size" in metadata:
            image_size = metadata.get("Size")

        # Also check ArtifactName for image reference if different
        artifact_name = trivy_output.get("ArtifactName", image_reference)

        # Process results
        results = trivy_output.get("Results", [])
        for target_result in results:
            target_type = target_result.get("Type", "")
            target_class = target_result.get("Class", "")

            # Get vulnerabilities for this target
            target_vulns = target_result.get("Vulnerabilities") or []

            for vuln_data in target_vulns:
                vuln = self._parse_vulnerability(vuln_data, target_type)
                if vuln:
                    vulnerabilities.append(vuln)

        return ScanResult(
            image_reference=image_reference,
            image_digest=image_digest,
            scanner_name=self.scanner_name,
            scanner_version=self.get_version(),
            scan_timestamp=datetime.utcnow(),
            scan_duration_seconds=duration,
            vulnerabilities=vulnerabilities,
            errors=errors,
            os_family=os_family,
            os_version=os_version,
            architecture=architecture,
            image_size_bytes=image_size,
            skip_db_update=skip_db_update,
            ignore_unfixed=ignore_unfixed,
        )

    def _parse_vulnerability(
        self,
        vuln_data: dict[str, Any],
        package_type: str,
    ) -> Vulnerability | None:
        """Parse a single vulnerability from Trivy output."""
        vuln_id = vuln_data.get("VulnerabilityID")
        if not vuln_id:
            return None

        pkg_name = vuln_data.get("PkgName", "unknown")
        installed_version = vuln_data.get("InstalledVersion", "unknown")

        # Parse severity
        severity_str = vuln_data.get("Severity", "UNKNOWN")
        severity = VulnerabilitySeverity.from_string(severity_str)

        # Parse CVSS information
        cvss_score = None
        cvss_vector = None

        # Try CVSS v3 first, then v2
        cvss = vuln_data.get("CVSS", {})
        for source in ["nvd", "redhat", "ghsa"]:
            if source in cvss:
                cvss_data = cvss[source]
                if "V3Score" in cvss_data:
                    cvss_score = cvss_data.get("V3Score")
                    cvss_vector = cvss_data.get("V3Vector")
                    break
                elif "V2Score" in cvss_data:
                    cvss_score = cvss_data.get("V2Score")
                    cvss_vector = cvss_data.get("V2Vector")
                    break

        # Fixed version
        fixed_version = vuln_data.get("FixedVersion")
        is_fixable = bool(fixed_version)

        # Parse dates
        published_date = None
        last_modified = None
        if vuln_data.get("PublishedDate"):
            try:
                published_date = datetime.fromisoformat(
                    vuln_data["PublishedDate"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        if vuln_data.get("LastModifiedDate"):
            try:
                last_modified = datetime.fromisoformat(
                    vuln_data["LastModifiedDate"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        # References
        refs = vuln_data.get("References", []) or []
        primary_url = vuln_data.get("PrimaryURL")

        # CWE IDs
        cwe_ids = vuln_data.get("CweIDs", []) or []

        # Data source
        data_source = vuln_data.get("DataSource", {}).get("Name")

        return Vulnerability(
            vulnerability_id=vuln_id,
            package_name=pkg_name,
            installed_version=installed_version,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            fixed_version=fixed_version,
            is_fixable=is_fixable,
            title=vuln_data.get("Title"),
            description=vuln_data.get("Description"),
            references=refs,
            package_type=package_type,
            package_path=vuln_data.get("PkgPath"),
            published_date=published_date,
            last_modified_date=last_modified,
            data_source=data_source,
            primary_url=primary_url,
            cwe_ids=cwe_ids,
        )


def scan_image(
    image_reference: str,
    timeout_seconds: int = 300,
    skip_db_update: bool = False,
    ignore_unfixed: bool = False,
) -> ScanResult:
    """
    Convenience function to scan a single image with Trivy.

    Args:
        image_reference: Image to scan (e.g., nginx:latest)
        timeout_seconds: Maximum time to wait for scan
        skip_db_update: Skip vulnerability database update
        ignore_unfixed: Exclude vulnerabilities without fixes

    Returns:
        ScanResult with vulnerabilities found

    Example:
        >>> result = scan_image("nginx:1.21")
        >>> print(f"Found {result.vulnerability_count} vulnerabilities")
        >>> for v in result.get_vulnerabilities_by_severity(VulnerabilitySeverity.CRITICAL):
        ...     print(f"  {v.vulnerability_id}: {v.package_name}")
    """
    scanner = TrivyScanner()
    return scanner.scan(
        image_reference=image_reference,
        timeout_seconds=timeout_seconds,
        skip_db_update=skip_db_update,
        ignore_unfixed=ignore_unfixed,
    )


def scan_images(
    image_references: list[str],
    timeout_seconds: int = 300,
    skip_db_update: bool = False,
    ignore_unfixed: bool = False,
    continue_on_error: bool = True,
) -> list[ScanResult]:
    """
    Convenience function to scan multiple images with Trivy.

    Args:
        image_references: List of images to scan
        timeout_seconds: Maximum time per scan
        skip_db_update: Skip vulnerability database update
        ignore_unfixed: Exclude vulnerabilities without fixes
        continue_on_error: Continue scanning if one image fails

    Returns:
        List of ScanResults (one per image)
    """
    scanner = TrivyScanner()
    return scanner.scan_batch(
        image_references=image_references,
        timeout_seconds=timeout_seconds,
        skip_db_update=skip_db_update,
        ignore_unfixed=ignore_unfixed,
        continue_on_error=continue_on_error,
    )
