"""
Container image scanning module for Mantissa Stance.

Provides vulnerability scanning for container images using external
tools like Trivy or Grype, plus layer analysis, base image detection,
and Dockerfile security best practices analysis.
"""

from stance.scanner.base import (
    ImageScanner,
    ScanResult,
    Vulnerability,
    VulnerabilitySeverity,
    ScannerError,
    ScannerNotAvailableError,
    ScannerTimeoutError,
)
from stance.scanner.trivy import TrivyScanner
from stance.scanner.cve_enrichment import (
    CVEEnricher,
    EnrichedVulnerability,
    EPSSScore,
    KEVEntry,
    prioritize_vulnerabilities,
)
from stance.scanner.layer_analyzer import (
    LayerAnalyzer,
    LayerAnalysisResult,
    ImageLayer,
    LayerType,
    LayerRisk,
    LayerFile,
    LayerSecurityIssue,
    BaseImageInfo,
    analyze_layers,
)
from stance.scanner.base_image import (
    BaseImageAnalyzer,
    BaseImageAnalysis,
    BaseImageVersion,
    BaseImageRecommendation,
    BaseImageStatus,
    BaseImageRisk,
    BaseImageInventory,
    analyze_base_image,
    check_base_image_vulnerabilities,
)
from stance.scanner.dockerfile import (
    DockerfileAnalyzer,
    DockerfileAnalysisResult,
    DockerfileFinding,
    DockerfileInstruction,
    DockerfileSeverity,
    DockerfileCategory,
    analyze_dockerfile,
    analyze_dockerfile_content,
    scan_dockerfiles,
)

__all__ = [
    # Base classes
    "ImageScanner",
    "ScanResult",
    "Vulnerability",
    "VulnerabilitySeverity",
    "ScannerError",
    "ScannerNotAvailableError",
    "ScannerTimeoutError",
    # Implementations
    "TrivyScanner",
    # CVE Enrichment
    "CVEEnricher",
    "EnrichedVulnerability",
    "EPSSScore",
    "KEVEntry",
    "prioritize_vulnerabilities",
    # Layer Analysis
    "LayerAnalyzer",
    "LayerAnalysisResult",
    "ImageLayer",
    "LayerType",
    "LayerRisk",
    "LayerFile",
    "LayerSecurityIssue",
    "BaseImageInfo",
    "analyze_layers",
    # Base Image Analysis
    "BaseImageAnalyzer",
    "BaseImageAnalysis",
    "BaseImageVersion",
    "BaseImageRecommendation",
    "BaseImageStatus",
    "BaseImageRisk",
    "BaseImageInventory",
    "analyze_base_image",
    "check_base_image_vulnerabilities",
    # Dockerfile Analysis
    "DockerfileAnalyzer",
    "DockerfileAnalysisResult",
    "DockerfileFinding",
    "DockerfileInstruction",
    "DockerfileSeverity",
    "DockerfileCategory",
    "analyze_dockerfile",
    "analyze_dockerfile_content",
    "scan_dockerfiles",
]
