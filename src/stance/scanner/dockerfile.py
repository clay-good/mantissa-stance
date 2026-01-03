"""
Dockerfile security best practices analyzer.

This module provides static analysis of Dockerfiles for:
- Security best practices
- Common misconfigurations
- Hardening recommendations
- CIS Docker Benchmark compliance
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class DockerfileSeverity(Enum):
    """Severity levels for Dockerfile issues."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DockerfileCategory(Enum):
    """Categories of Dockerfile issues."""

    SECURITY = "security"
    BEST_PRACTICE = "best_practice"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    COMPLIANCE = "compliance"


@dataclass
class DockerfileInstruction:
    """Represents a single Dockerfile instruction."""

    line_number: int
    instruction: str  # FROM, RUN, COPY, etc.
    arguments: str
    raw_line: str
    is_continuation: bool = False


@dataclass
class DockerfileFinding:
    """A security or best practice finding in a Dockerfile."""

    rule_id: str
    severity: DockerfileSeverity
    category: DockerfileCategory
    title: str
    description: str
    line_number: Optional[int] = None
    instruction: Optional[str] = None
    remediation: str = ""
    reference: str = ""
    cis_benchmark: Optional[str] = None  # CIS Docker Benchmark reference


@dataclass
class DockerfileAnalysisResult:
    """Result of Dockerfile analysis."""

    # File information
    file_path: str
    content_hash: str = ""

    # Parsing results
    instructions: list[DockerfileInstruction] = field(default_factory=list)
    base_images: list[str] = field(default_factory=list)
    stages: list[str] = field(default_factory=list)  # Multi-stage build stages

    # Findings
    findings: list[DockerfileFinding] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Analysis metadata
    total_lines: int = 0
    instruction_count: int = 0
    is_multi_stage: bool = False
    has_user_instruction: bool = False
    has_healthcheck: bool = False

    # Errors
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if analysis completed without errors."""
        return len(self.errors) == 0

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    def get_findings_by_severity(
        self, severity: DockerfileSeverity
    ) -> list[DockerfileFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(
        self, category: DockerfileCategory
    ) -> list[DockerfileFinding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]

    def summary(self) -> dict[str, Any]:
        """Get analysis summary."""
        return {
            "file_path": self.file_path,
            "total_lines": self.total_lines,
            "instruction_count": self.instruction_count,
            "is_multi_stage": self.is_multi_stage,
            "has_user_instruction": self.has_user_instruction,
            "has_healthcheck": self.has_healthcheck,
            "base_images": self.base_images,
            "stages": self.stages,
            "findings": {
                "total": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
        }


# Dockerfile security rules
DOCKERFILE_RULES = [
    # Critical severity rules
    {
        "rule_id": "DF-SEC-001",
        "severity": DockerfileSeverity.CRITICAL,
        "category": DockerfileCategory.SECURITY,
        "title": "Secrets in RUN instruction",
        "pattern": r"(password|secret|api_key|apikey|auth_token|access_token)\s*=\s*['\"][^'\"]+['\"]",
        "instruction": "RUN",
        "description": "Hardcoded secrets detected in RUN instruction",
        "remediation": "Use build-time secrets (--secret) or environment variables at runtime",
        "cis_benchmark": "4.10",
    },
    {
        "rule_id": "DF-SEC-002",
        "severity": DockerfileSeverity.CRITICAL,
        "category": DockerfileCategory.SECURITY,
        "title": "AWS credentials in Dockerfile",
        "pattern": r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY",
        "instruction": "ENV",
        "description": "AWS credentials should not be hardcoded in Dockerfile",
        "remediation": "Use IAM roles or secrets management",
        "cis_benchmark": "4.10",
    },
    {
        "rule_id": "DF-SEC-003",
        "severity": DockerfileSeverity.CRITICAL,
        "category": DockerfileCategory.SECURITY,
        "title": "Private key in COPY/ADD",
        "pattern": r"\.(pem|key|p12|pfx|ppk)(\s|$)",
        "instruction": "COPY|ADD",
        "description": "Private key files should not be copied into image",
        "remediation": "Mount secrets at runtime or use multi-stage builds",
        "cis_benchmark": "4.10",
    },

    # High severity rules
    {
        "rule_id": "DF-SEC-010",
        "severity": DockerfileSeverity.HIGH,
        "category": DockerfileCategory.SECURITY,
        "title": "Running as root",
        "check_type": "no_user",
        "description": "No USER instruction found; container will run as root",
        "remediation": "Add 'USER nonroot' or 'USER nobody' before ENTRYPOINT/CMD",
        "cis_benchmark": "4.1",
    },
    {
        "rule_id": "DF-SEC-011",
        "severity": DockerfileSeverity.HIGH,
        "category": DockerfileCategory.SECURITY,
        "title": "Using latest tag",
        "pattern": r":latest(\s|$|@)",
        "instruction": "FROM",
        "description": "Using :latest tag makes builds non-reproducible",
        "remediation": "Pin to specific version (e.g., python:3.11-slim)",
        "cis_benchmark": "4.7",
    },
    {
        "rule_id": "DF-SEC-012",
        "severity": DockerfileSeverity.HIGH,
        "category": DockerfileCategory.SECURITY,
        "title": "ADD with URL",
        "pattern": r"^ADD\s+(https?|ftp)://",
        "instruction": "ADD",
        "description": "ADD with URL downloads without verification",
        "remediation": "Use 'RUN curl' with checksum verification instead",
        "cis_benchmark": "4.9",
    },
    {
        "rule_id": "DF-SEC-013",
        "severity": DockerfileSeverity.HIGH,
        "category": DockerfileCategory.SECURITY,
        "title": "Curl pipe to shell",
        "pattern": r"curl.*\|\s*(ba)?sh",
        "instruction": "RUN",
        "description": "Downloading and executing scripts without verification",
        "remediation": "Download file, verify checksum, then execute",
        "cis_benchmark": "4.9",
    },
    {
        "rule_id": "DF-SEC-014",
        "severity": DockerfileSeverity.HIGH,
        "category": DockerfileCategory.SECURITY,
        "title": "Wget pipe to shell",
        "pattern": r"wget.*\|\s*(ba)?sh",
        "instruction": "RUN",
        "description": "Downloading and executing scripts without verification",
        "remediation": "Download file, verify checksum, then execute",
        "cis_benchmark": "4.9",
    },
    {
        "rule_id": "DF-SEC-015",
        "severity": DockerfileSeverity.HIGH,
        "category": DockerfileCategory.SECURITY,
        "title": "Setuid binary creation",
        "pattern": r"chmod\s+[ugo]*\+?s|chmod\s+[0-7]*[4-7][0-7]{2}",
        "instruction": "RUN",
        "description": "Creating setuid/setgid binaries increases attack surface",
        "remediation": "Use capabilities instead of setuid binaries",
    },

    # Medium severity rules
    {
        "rule_id": "DF-SEC-020",
        "severity": DockerfileSeverity.MEDIUM,
        "category": DockerfileCategory.SECURITY,
        "title": "World-writable permissions",
        "pattern": r"chmod\s+(-R\s+)?777",
        "instruction": "RUN",
        "description": "World-writable permissions are too permissive",
        "remediation": "Use least privilege permissions (755 for dirs, 644 for files)",
    },
    {
        "rule_id": "DF-SEC-021",
        "severity": DockerfileSeverity.MEDIUM,
        "category": DockerfileCategory.SECURITY,
        "title": "Installing sudo",
        "pattern": r"(apt-get|apt|apk|yum|dnf)\s+install.*\bsudo\b",
        "instruction": "RUN",
        "description": "Installing sudo in container is generally unnecessary",
        "remediation": "Remove sudo; use USER instruction for privilege separation",
        "cis_benchmark": "4.5",
    },
    {
        "rule_id": "DF-SEC-022",
        "severity": DockerfileSeverity.MEDIUM,
        "category": DockerfileCategory.SECURITY,
        "title": "SSH server in container",
        "pattern": r"(apt-get|apt|apk|yum|dnf)\s+install.*\bopenssh-server\b",
        "instruction": "RUN",
        "description": "SSH server should not run in containers",
        "remediation": "Use 'docker exec' for debugging; remove SSH server",
        "cis_benchmark": "4.5",
    },
    {
        "rule_id": "DF-SEC-023",
        "severity": DockerfileSeverity.MEDIUM,
        "category": DockerfileCategory.SECURITY,
        "title": "No HEALTHCHECK instruction",
        "check_type": "no_healthcheck",
        "description": "No HEALTHCHECK instruction found",
        "remediation": "Add HEALTHCHECK to enable container health monitoring",
        "cis_benchmark": "4.6",
    },

    # Best practice rules
    {
        "rule_id": "DF-BP-001",
        "severity": DockerfileSeverity.LOW,
        "category": DockerfileCategory.BEST_PRACTICE,
        "title": "apt-get without cleanup",
        "pattern": r"apt-get\s+install(?!.*rm\s+-rf\s+/var/lib/apt/lists)",
        "instruction": "RUN",
        "description": "Package cache not cleaned after apt-get install",
        "remediation": "Add 'rm -rf /var/lib/apt/lists/*' after apt-get install",
    },
    {
        "rule_id": "DF-BP-002",
        "severity": DockerfileSeverity.LOW,
        "category": DockerfileCategory.BEST_PRACTICE,
        "title": "apk without --no-cache",
        "pattern": r"apk\s+add(?!\s+--no-cache)",
        "instruction": "RUN",
        "description": "apk add without --no-cache retains package cache",
        "remediation": "Use 'apk add --no-cache' to avoid storing cache in layer",
    },
    {
        "rule_id": "DF-BP-003",
        "severity": DockerfileSeverity.LOW,
        "category": DockerfileCategory.BEST_PRACTICE,
        "title": "Multiple RUN instructions",
        "check_type": "run_consolidation",
        "threshold": 5,
        "description": "Multiple RUN instructions create unnecessary layers",
        "remediation": "Combine related RUN instructions with '&&'",
    },
    {
        "rule_id": "DF-BP-004",
        "severity": DockerfileSeverity.INFO,
        "category": DockerfileCategory.BEST_PRACTICE,
        "title": "COPY instead of ADD",
        "pattern": r"^ADD\s+[^\s]+\s+[^\s]+$",
        "instruction": "ADD",
        "description": "ADD used where COPY would suffice",
        "remediation": "Use COPY for local files; ADD only for tar extraction or URLs",
        "cis_benchmark": "4.9",
    },
    {
        "rule_id": "DF-BP-005",
        "severity": DockerfileSeverity.LOW,
        "category": DockerfileCategory.BEST_PRACTICE,
        "title": "Missing .dockerignore",
        "check_type": "no_dockerignore",
        "description": "No .dockerignore file found",
        "remediation": "Add .dockerignore to exclude unnecessary files from build context",
    },
    {
        "rule_id": "DF-BP-006",
        "severity": DockerfileSeverity.INFO,
        "category": DockerfileCategory.BEST_PRACTICE,
        "title": "No LABEL instruction",
        "check_type": "no_label",
        "description": "No LABEL instruction for image metadata",
        "remediation": "Add LABEL instructions for maintainer, version, description",
    },

    # Performance rules
    {
        "rule_id": "DF-PERF-001",
        "severity": DockerfileSeverity.LOW,
        "category": DockerfileCategory.PERFORMANCE,
        "title": "COPY before dependency install",
        "check_type": "copy_order",
        "description": "Copying all files before installing dependencies reduces cache efficiency",
        "remediation": "COPY dependency files first, install, then COPY remaining files",
    },
    {
        "rule_id": "DF-PERF-002",
        "severity": DockerfileSeverity.INFO,
        "category": DockerfileCategory.PERFORMANCE,
        "title": "Not using multi-stage build",
        "check_type": "no_multistage",
        "description": "Single-stage build may include unnecessary build tools",
        "remediation": "Use multi-stage builds to reduce final image size",
    },

    # Compliance rules
    {
        "rule_id": "DF-CIS-001",
        "severity": DockerfileSeverity.MEDIUM,
        "category": DockerfileCategory.COMPLIANCE,
        "title": "Root filesystem not read-only",
        "check_type": "readonly_hint",
        "description": "Consider making root filesystem read-only at runtime",
        "remediation": "Run container with --read-only flag",
        "cis_benchmark": "5.12",
    },
]


class DockerfileAnalyzer:
    """
    Analyzer for Dockerfile security best practices.

    Provides static analysis of Dockerfiles against security
    best practices and CIS Docker Benchmark.
    """

    def __init__(self):
        """Initialize DockerfileAnalyzer."""
        self.rules = DOCKERFILE_RULES

    def analyze(
        self,
        dockerfile_path: str | Path,
        check_dockerignore: bool = True,
    ) -> DockerfileAnalysisResult:
        """
        Analyze a Dockerfile for security issues.

        Args:
            dockerfile_path: Path to Dockerfile
            check_dockerignore: Whether to check for .dockerignore

        Returns:
            DockerfileAnalysisResult with findings
        """
        path = Path(dockerfile_path)
        result = DockerfileAnalysisResult(file_path=str(path))

        # Read Dockerfile
        try:
            content = path.read_text()
        except Exception as e:
            result.errors.append(f"Failed to read Dockerfile: {e}")
            return result

        # Calculate content hash
        import hashlib
        result.content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        # Parse Dockerfile
        result.instructions = self._parse_dockerfile(content)
        result.total_lines = len(content.splitlines())
        result.instruction_count = len(result.instructions)

        # Extract metadata
        self._extract_metadata(result)

        # Run pattern-based checks
        self._run_pattern_checks(result)

        # Run structural checks
        self._run_structural_checks(result)

        # Check for .dockerignore if requested
        if check_dockerignore:
            self._check_dockerignore(result, path)

        # Count findings by severity
        self._count_findings(result)

        return result

    def analyze_content(
        self,
        content: str,
        file_path: str = "<inline>",
    ) -> DockerfileAnalysisResult:
        """
        Analyze Dockerfile content directly.

        Args:
            content: Dockerfile content as string
            file_path: Virtual file path for reporting

        Returns:
            DockerfileAnalysisResult with findings
        """
        result = DockerfileAnalysisResult(file_path=file_path)

        # Calculate content hash
        import hashlib
        result.content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        # Parse Dockerfile
        result.instructions = self._parse_dockerfile(content)
        result.total_lines = len(content.splitlines())
        result.instruction_count = len(result.instructions)

        # Extract metadata
        self._extract_metadata(result)

        # Run pattern-based checks
        self._run_pattern_checks(result)

        # Run structural checks
        self._run_structural_checks(result)

        # Count findings by severity
        self._count_findings(result)

        return result

    def _parse_dockerfile(self, content: str) -> list[DockerfileInstruction]:
        """Parse Dockerfile into instructions."""
        instructions = []
        lines = content.splitlines()

        current_instruction = None
        current_args = []
        start_line = 0

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Check for line continuation
            is_continuation = stripped.endswith("\\")
            if is_continuation:
                stripped = stripped[:-1].strip()

            # Check if this starts a new instruction
            if current_instruction is None:
                # Parse instruction and arguments
                match = re.match(r"^([A-Z]+)\s*(.*)?$", stripped)
                if match:
                    current_instruction = match.group(1)
                    args = match.group(2) or ""
                    current_args = [args] if args else []
                    start_line = i + 1
                else:
                    # Malformed line
                    continue
            else:
                # Continuation of previous instruction
                current_args.append(stripped)

            # If not continuing, save the instruction
            if not is_continuation and current_instruction:
                instructions.append(DockerfileInstruction(
                    line_number=start_line,
                    instruction=current_instruction,
                    arguments=" ".join(current_args),
                    raw_line=line,
                ))
                current_instruction = None
                current_args = []

        return instructions

    def _extract_metadata(self, result: DockerfileAnalysisResult) -> None:
        """Extract metadata from parsed instructions."""
        stage_count = 0

        for inst in result.instructions:
            if inst.instruction == "FROM":
                # Handle multi-stage builds
                args = inst.arguments
                if " AS " in args.upper():
                    match = re.search(r"\s+AS\s+(\S+)", args, re.IGNORECASE)
                    if match:
                        result.stages.append(match.group(1))
                        stage_count += 1

                # Extract base image
                base_image = args.split()[0] if args else "unknown"
                if " AS " in args.upper():
                    base_image = args.split()[0]
                result.base_images.append(base_image)
                stage_count += 1

            elif inst.instruction == "USER":
                result.has_user_instruction = True

            elif inst.instruction == "HEALTHCHECK":
                result.has_healthcheck = True

        result.is_multi_stage = stage_count > 1

    def _run_pattern_checks(self, result: DockerfileAnalysisResult) -> None:
        """Run pattern-based checks against instructions."""
        for rule in self.rules:
            if "pattern" not in rule:
                continue

            pattern = rule["pattern"]
            target_instructions = rule.get("instruction", "").split("|")

            for inst in result.instructions:
                # Check if this instruction matches the rule target
                if target_instructions[0] and inst.instruction not in target_instructions:
                    continue

                # Check the pattern
                full_text = f"{inst.instruction} {inst.arguments}"
                if re.search(pattern, full_text, re.IGNORECASE):
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        line_number=inst.line_number,
                        instruction=inst.instruction,
                        remediation=rule.get("remediation", ""),
                        reference=rule.get("reference", ""),
                        cis_benchmark=rule.get("cis_benchmark"),
                    ))

    def _run_structural_checks(self, result: DockerfileAnalysisResult) -> None:
        """Run structural checks on Dockerfile."""
        for rule in self.rules:
            check_type = rule.get("check_type")
            if not check_type:
                continue

            if check_type == "no_user":
                if not result.has_user_instruction:
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule.get("remediation", ""),
                        cis_benchmark=rule.get("cis_benchmark"),
                    ))

            elif check_type == "no_healthcheck":
                if not result.has_healthcheck:
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule.get("remediation", ""),
                        cis_benchmark=rule.get("cis_benchmark"),
                    ))

            elif check_type == "run_consolidation":
                run_count = sum(1 for i in result.instructions if i.instruction == "RUN")
                threshold = rule.get("threshold", 5)
                if run_count > threshold:
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=f"{run_count} RUN instructions found (threshold: {threshold})",
                        remediation=rule.get("remediation", ""),
                    ))

            elif check_type == "no_label":
                has_label = any(i.instruction == "LABEL" for i in result.instructions)
                if not has_label:
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule.get("remediation", ""),
                    ))

            elif check_type == "no_multistage":
                if not result.is_multi_stage:
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule.get("remediation", ""),
                    ))

            elif check_type == "copy_order":
                # Check if COPY . happens before package install
                copy_all_line = None
                install_line = None

                for inst in result.instructions:
                    if inst.instruction == "COPY" and ". ." in inst.arguments:
                        copy_all_line = inst.line_number
                    if inst.instruction == "RUN" and any(
                        pm in inst.arguments.lower()
                        for pm in ["npm install", "pip install", "yarn install", "go build"]
                    ):
                        install_line = inst.line_number

                if copy_all_line and install_line and copy_all_line < install_line:
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        line_number=copy_all_line,
                        instruction="COPY",
                        remediation=rule.get("remediation", ""),
                    ))

    def _check_dockerignore(
        self,
        result: DockerfileAnalysisResult,
        dockerfile_path: Path,
    ) -> None:
        """Check for presence of .dockerignore file."""
        dockerignore_path = dockerfile_path.parent / ".dockerignore"

        if not dockerignore_path.exists():
            for rule in self.rules:
                if rule.get("check_type") == "no_dockerignore":
                    result.findings.append(DockerfileFinding(
                        rule_id=rule["rule_id"],
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        remediation=rule.get("remediation", ""),
                    ))
                    break

    def _count_findings(self, result: DockerfileAnalysisResult) -> None:
        """Count findings by severity."""
        for finding in result.findings:
            if finding.severity == DockerfileSeverity.CRITICAL:
                result.critical_count += 1
            elif finding.severity == DockerfileSeverity.HIGH:
                result.high_count += 1
            elif finding.severity == DockerfileSeverity.MEDIUM:
                result.medium_count += 1
            elif finding.severity == DockerfileSeverity.LOW:
                result.low_count += 1
            elif finding.severity == DockerfileSeverity.INFO:
                result.info_count += 1

    def get_rules(self) -> list[dict]:
        """Get all analysis rules."""
        return [
            {
                "rule_id": r["rule_id"],
                "severity": r["severity"].value,
                "category": r["category"].value,
                "title": r["title"],
                "description": r.get("description", ""),
                "cis_benchmark": r.get("cis_benchmark"),
            }
            for r in self.rules
        ]


def analyze_dockerfile(
    dockerfile_path: str | Path,
) -> DockerfileAnalysisResult:
    """
    Convenience function to analyze a Dockerfile.

    Args:
        dockerfile_path: Path to Dockerfile

    Returns:
        DockerfileAnalysisResult with findings

    Example:
        >>> result = analyze_dockerfile("./Dockerfile")
        >>> print(f"Found {result.total_findings} issues")
        >>> for finding in result.get_findings_by_severity(DockerfileSeverity.HIGH):
        ...     print(f"  Line {finding.line_number}: {finding.title}")
    """
    analyzer = DockerfileAnalyzer()
    return analyzer.analyze(dockerfile_path)


def analyze_dockerfile_content(
    content: str,
    file_path: str = "<inline>",
) -> DockerfileAnalysisResult:
    """
    Convenience function to analyze Dockerfile content.

    Args:
        content: Dockerfile content as string
        file_path: Virtual file path for reporting

    Returns:
        DockerfileAnalysisResult with findings

    Example:
        >>> content = '''
        ... FROM python:latest
        ... COPY . /app
        ... RUN pip install -r requirements.txt
        ... '''
        >>> result = analyze_dockerfile_content(content)
        >>> print(f"Found {result.total_findings} issues")
    """
    analyzer = DockerfileAnalyzer()
    return analyzer.analyze_content(content, file_path)


def scan_dockerfiles(
    directory: str | Path,
    recursive: bool = True,
) -> list[DockerfileAnalysisResult]:
    """
    Scan a directory for Dockerfiles and analyze them.

    Args:
        directory: Directory to scan
        recursive: Whether to scan recursively

    Returns:
        List of DockerfileAnalysisResult for each Dockerfile found

    Example:
        >>> results = scan_dockerfiles("./projects")
        >>> for result in results:
        ...     if result.critical_count > 0:
        ...         print(f"{result.file_path}: {result.critical_count} critical issues")
    """
    directory = Path(directory)
    results = []
    analyzer = DockerfileAnalyzer()

    # Find Dockerfiles
    pattern = "**/Dockerfile*" if recursive else "Dockerfile*"
    dockerfiles = list(directory.glob(pattern))

    # Also look for *.dockerfile
    dockerfiles.extend(directory.glob("**/*.dockerfile" if recursive else "*.dockerfile"))

    for dockerfile in dockerfiles:
        if dockerfile.is_file():
            try:
                result = analyzer.analyze(dockerfile)
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to analyze {dockerfile}: {e}")
                error_result = DockerfileAnalysisResult(
                    file_path=str(dockerfile),
                    errors=[str(e)],
                )
                results.append(error_result)

    return results
