"""
Unit tests for container scanning Phase 79 components.

Tests cover:
- Image layer analysis
- Base image vulnerability detection
- Dockerfile security best practices analyzer
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

# Layer Analyzer Tests
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

# Base Image Tests
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

# Dockerfile Analyzer Tests
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


# =============================================================================
# Layer Analyzer Tests
# =============================================================================

class TestLayerType:
    """Tests for LayerType enum."""

    def test_layer_type_values(self):
        """Test all layer type values exist."""
        assert LayerType.BASE.value == "base"
        assert LayerType.PACKAGE_INSTALL.value == "package_install"
        assert LayerType.FILE_COPY.value == "file_copy"
        assert LayerType.CONFIG.value == "config"
        assert LayerType.USER.value == "user"
        assert LayerType.RUN.value == "run"
        assert LayerType.UNKNOWN.value == "unknown"


class TestLayerRisk:
    """Tests for LayerRisk enum."""

    def test_risk_levels(self):
        """Test all risk levels exist."""
        assert LayerRisk.CRITICAL.value == "critical"
        assert LayerRisk.HIGH.value == "high"
        assert LayerRisk.MEDIUM.value == "medium"
        assert LayerRisk.LOW.value == "low"
        assert LayerRisk.INFO.value == "info"


class TestImageLayer:
    """Tests for ImageLayer dataclass."""

    def test_layer_creation(self):
        """Test creating an image layer."""
        layer = ImageLayer(
            digest="sha256:abc123",
            index=0,
            created_by="FROM python:3.11",
            size_bytes=50 * 1024 * 1024,  # 50 MB
        )
        assert layer.digest == "sha256:abc123"
        assert layer.index == 0
        assert layer.layer_type == LayerType.UNKNOWN
        assert not layer.is_empty

    def test_layer_size_human(self):
        """Test human-readable size formatting."""
        layer = ImageLayer(
            digest="sha256:abc",
            index=0,
            created_by="test",
            size_bytes=1024 * 1024 * 50,  # 50 MB
        )
        assert "50" in layer.get_size_human()
        assert "MB" in layer.get_size_human()

    def test_command_summary_truncation(self):
        """Test command summary truncation for long commands."""
        long_cmd = "RUN apt-get update && apt-get install -y " + "package " * 20
        layer = ImageLayer(
            digest="sha256:abc",
            index=0,
            created_by=long_cmd,
        )
        summary = layer.get_command_summary()
        assert len(summary) <= 80
        assert summary.endswith("...")


class TestLayerSecurityIssue:
    """Tests for LayerSecurityIssue dataclass."""

    def test_issue_creation(self):
        """Test creating a security issue."""
        issue = LayerSecurityIssue(
            issue_type="hardcoded_password",
            severity=LayerRisk.CRITICAL,
            description="Password found in layer",
            file_path="/app/config.py",
            remediation="Use environment variables",
        )
        assert issue.severity == LayerRisk.CRITICAL
        assert "password" in issue.issue_type.lower()


class TestLayerAnalyzer:
    """Tests for LayerAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        analyzer = LayerAnalyzer()
        assert analyzer is not None

    def test_classify_layer_from(self):
        """Test classification of FROM layer."""
        analyzer = LayerAnalyzer()
        layer_type = analyzer._classify_layer_command("<missing>")
        assert layer_type == LayerType.BASE

    def test_classify_layer_copy(self):
        """Test classification of COPY layer."""
        analyzer = LayerAnalyzer()
        layer_type = analyzer._classify_layer_command("COPY . /app")
        assert layer_type == LayerType.FILE_COPY

    def test_classify_layer_user(self):
        """Test classification of USER layer."""
        analyzer = LayerAnalyzer()
        layer_type = analyzer._classify_layer_command("USER nonroot")
        assert layer_type == LayerType.USER

    def test_classify_layer_package_install(self):
        """Test classification of package install layer."""
        analyzer = LayerAnalyzer()

        # apt-get
        layer_type = analyzer._classify_layer_command("RUN apt-get install -y curl")
        assert layer_type == LayerType.PACKAGE_INSTALL

        # apk
        layer_type = analyzer._classify_layer_command("RUN apk add --no-cache python3")
        assert layer_type == LayerType.PACKAGE_INSTALL

    def test_extract_packages_apt(self):
        """Test package extraction from apt commands."""
        analyzer = LayerAnalyzer()
        packages = analyzer._extract_packages(
            "RUN apt-get install -y curl wget python3"
        )
        assert "curl" in packages
        assert "wget" in packages
        assert "python3" in packages

    def test_extract_packages_apk(self):
        """Test package extraction from apk commands."""
        analyzer = LayerAnalyzer()
        packages = analyzer._extract_packages(
            "RUN apk add --no-cache python3 py3-pip"
        )
        assert "python3" in packages
        assert "py3-pip" in packages

    def test_analyze_layer_security_root(self):
        """Test detection of root user in layer."""
        analyzer = LayerAnalyzer()
        layer = ImageLayer(
            digest="sha256:abc",
            index=0,
            created_by="USER root",
        )
        issues = analyzer._analyze_layer_security(layer)
        assert any(i.issue_type == "root_user" for i in issues)

    def test_analyze_layer_security_curl_pipe(self):
        """Test detection of curl pipe to shell."""
        analyzer = LayerAnalyzer()
        layer = ImageLayer(
            digest="sha256:abc",
            index=0,
            created_by="RUN curl https://example.com/script.sh | bash",
        )
        issues = analyzer._analyze_layer_security(layer)
        assert any(i.issue_type == "remote_execution" for i in issues)

    def test_analyze_layer_security_chmod_777(self):
        """Test detection of world-writable permissions."""
        analyzer = LayerAnalyzer()
        layer = ImageLayer(
            digest="sha256:abc",
            index=0,
            created_by="RUN chmod 777 /app",
        )
        issues = analyzer._analyze_layer_security(layer)
        assert any(i.issue_type == "world_writable" for i in issues)

    def test_analyze_layer_security_hardcoded_secret(self):
        """Test detection of hardcoded secrets."""
        analyzer = LayerAnalyzer()
        layer = ImageLayer(
            digest="sha256:abc",
            index=0,
            created_by='RUN echo password="mysecret123"',
        )
        issues = analyzer._analyze_layer_security(layer)
        assert any(i.severity == LayerRisk.CRITICAL for i in issues)


class TestLayerAnalysisResult:
    """Tests for LayerAnalysisResult dataclass."""

    def test_result_creation(self):
        """Test creating analysis result."""
        result = LayerAnalysisResult(image_reference="nginx:latest")
        assert result.image_reference == "nginx:latest"
        assert result.success
        assert result.total_layers == 0

    def test_result_summary(self):
        """Test result summary generation."""
        result = LayerAnalysisResult(
            image_reference="nginx:latest",
            total_layers=5,
            base_layers=3,
            application_layers=2,
        )
        summary = result.summary()
        assert summary["total_layers"] == 5
        assert summary["base_layers"] == 3


# =============================================================================
# Base Image Analyzer Tests
# =============================================================================

class TestBaseImageStatus:
    """Tests for BaseImageStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        assert BaseImageStatus.CURRENT.value == "current"
        assert BaseImageStatus.OUTDATED.value == "outdated"
        assert BaseImageStatus.DEPRECATED.value == "deprecated"
        assert BaseImageStatus.EOL.value == "eol"
        assert BaseImageStatus.UNKNOWN.value == "unknown"


class TestBaseImageRisk:
    """Tests for BaseImageRisk enum."""

    def test_risk_values(self):
        """Test all risk values exist."""
        assert BaseImageRisk.CRITICAL.value == "critical"
        assert BaseImageRisk.HIGH.value == "high"


class TestBaseImageAnalysis:
    """Tests for BaseImageAnalysis dataclass."""

    def test_analysis_creation(self):
        """Test creating base image analysis."""
        analysis = BaseImageAnalysis(image_reference="python:3.11")
        assert analysis.image_reference == "python:3.11"
        assert analysis.status == BaseImageStatus.UNKNOWN
        assert analysis.success

    def test_analysis_summary(self):
        """Test analysis summary generation."""
        analysis = BaseImageAnalysis(
            image_reference="python:3.11",
            normalized_name="python:3.11",
            is_official=True,
            is_pinned=True,
        )
        summary = analysis.summary()
        assert summary["is_official"] is True
        assert summary["is_pinned"] is True


class TestBaseImageRecommendation:
    """Tests for BaseImageRecommendation dataclass."""

    def test_recommendation_creation(self):
        """Test creating recommendation."""
        rec = BaseImageRecommendation(
            recommendation_type="update",
            severity=BaseImageRisk.HIGH,
            current_image="python:3.8",
            recommended_image="python:3.12",
            reason="Python 3.8 is EOL",
        )
        assert rec.recommendation_type == "update"
        assert rec.severity == BaseImageRisk.HIGH


class TestBaseImageAnalyzer:
    """Tests for BaseImageAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        analyzer = BaseImageAnalyzer()
        assert analyzer is not None

    def test_analyze_official_image(self):
        """Test analyzing official Docker Hub image."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("python:3.11")
        assert analysis.is_official is True

    def test_analyze_latest_tag(self):
        """Test detection of :latest tag."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("python:latest")
        assert analysis.uses_latest_tag is True
        assert any(r.recommendation_type == "pin" for r in analysis.recommendations)

    def test_analyze_no_tag(self):
        """Test detection when no tag specified."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("python")
        assert analysis.uses_latest_tag is True

    def test_analyze_pinned_digest(self):
        """Test detection of digest-pinned image."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze(
            "python@sha256:abc123def456"
        )
        assert analysis.is_pinned is True

    def test_analyze_eol_image(self):
        """Test detection of EOL image."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("python:3.7")
        assert analysis.status == BaseImageStatus.EOL
        assert any(r.recommendation_type == "update" for r in analysis.recommendations)

    def test_analyze_outdated_image(self):
        """Test detection of outdated image."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("node:16")
        # Node 16 is EOL
        assert analysis.status in [BaseImageStatus.EOL, BaseImageStatus.OUTDATED]

    def test_detect_os_family_alpine(self):
        """Test OS family detection for Alpine."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("alpine:3.19")
        assert analysis.os_family == "alpine"

    def test_detect_os_family_ubuntu(self):
        """Test OS family detection for Ubuntu."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("ubuntu:22.04")
        assert analysis.os_family == "ubuntu"

    def test_distroless_recommendation(self):
        """Test distroless alternative recommendation."""
        analyzer = BaseImageAnalyzer()
        analysis = analyzer.analyze("python:3.11")
        assert any(
            "distroless" in r.reason.lower()
            for r in analysis.recommendations
        )


class TestBaseImageInventory:
    """Tests for BaseImageInventory dataclass."""

    def test_inventory_creation(self):
        """Test creating inventory."""
        inventory = BaseImageInventory()
        assert inventory.total_images == 0

    def test_inventory_add_analysis(self):
        """Test adding analysis to inventory."""
        inventory = BaseImageInventory()
        analysis = BaseImageAnalysis(
            image_reference="python:3.8",
            status=BaseImageStatus.EOL,
        )
        inventory.add_analysis(analysis)
        assert inventory.total_images == 1
        assert inventory.eol_count == 1

    def test_check_multiple_images(self):
        """Test checking multiple images."""
        inventory = check_base_image_vulnerabilities([
            "python:3.11",
            "node:20",
        ])
        assert inventory.total_images == 2


# =============================================================================
# Dockerfile Analyzer Tests
# =============================================================================

class TestDockerfileSeverity:
    """Tests for DockerfileSeverity enum."""

    def test_severity_values(self):
        """Test all severity values exist."""
        assert DockerfileSeverity.CRITICAL.value == "critical"
        assert DockerfileSeverity.HIGH.value == "high"
        assert DockerfileSeverity.MEDIUM.value == "medium"
        assert DockerfileSeverity.LOW.value == "low"
        assert DockerfileSeverity.INFO.value == "info"


class TestDockerfileCategory:
    """Tests for DockerfileCategory enum."""

    def test_category_values(self):
        """Test all category values exist."""
        assert DockerfileCategory.SECURITY.value == "security"
        assert DockerfileCategory.BEST_PRACTICE.value == "best_practice"
        assert DockerfileCategory.PERFORMANCE.value == "performance"


class TestDockerfileInstruction:
    """Tests for DockerfileInstruction dataclass."""

    def test_instruction_creation(self):
        """Test creating Dockerfile instruction."""
        inst = DockerfileInstruction(
            line_number=1,
            instruction="FROM",
            arguments="python:3.11",
            raw_line="FROM python:3.11",
        )
        assert inst.instruction == "FROM"
        assert inst.line_number == 1


class TestDockerfileFinding:
    """Tests for DockerfileFinding dataclass."""

    def test_finding_creation(self):
        """Test creating Dockerfile finding."""
        finding = DockerfileFinding(
            rule_id="DF-SEC-001",
            severity=DockerfileSeverity.CRITICAL,
            category=DockerfileCategory.SECURITY,
            title="Hardcoded secret",
            description="Secret found in Dockerfile",
            line_number=5,
        )
        assert finding.rule_id == "DF-SEC-001"
        assert finding.severity == DockerfileSeverity.CRITICAL


class TestDockerfileAnalysisResult:
    """Tests for DockerfileAnalysisResult dataclass."""

    def test_result_creation(self):
        """Test creating analysis result."""
        result = DockerfileAnalysisResult(file_path="./Dockerfile")
        assert result.file_path == "./Dockerfile"
        assert result.success

    def test_result_total_findings(self):
        """Test total findings property."""
        result = DockerfileAnalysisResult(file_path="./Dockerfile")
        result.findings.append(DockerfileFinding(
            rule_id="test",
            severity=DockerfileSeverity.HIGH,
            category=DockerfileCategory.SECURITY,
            title="Test",
            description="Test finding",
        ))
        assert result.total_findings == 1


class TestDockerfileAnalyzer:
    """Tests for DockerfileAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        analyzer = DockerfileAnalyzer()
        assert analyzer is not None
        assert len(analyzer.rules) > 0

    def test_parse_simple_dockerfile(self):
        """Test parsing simple Dockerfile."""
        analyzer = DockerfileAnalyzer()
        content = """FROM python:3.11
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
"""
        result = analyzer.analyze_content(content)
        assert result.instruction_count == 5
        assert "python:3.11" in result.base_images

    def test_parse_multiline_instruction(self):
        """Test parsing multiline instruction."""
        analyzer = DockerfileAnalyzer()
        content = """FROM alpine
RUN apk add --no-cache \\
    python3 \\
    py3-pip
"""
        result = analyzer.analyze_content(content)
        assert result.instruction_count == 2

    def test_detect_latest_tag(self):
        """Test detection of :latest tag."""
        analyzer = DockerfileAnalyzer()
        content = "FROM python:latest\n"
        result = analyzer.analyze_content(content)
        assert any(
            f.rule_id == "DF-SEC-011"
            for f in result.findings
        )

    def test_detect_no_user(self):
        """Test detection of missing USER instruction."""
        analyzer = DockerfileAnalyzer()
        content = """FROM python:3.11
COPY . /app
CMD ["python", "app.py"]
"""
        result = analyzer.analyze_content(content)
        assert not result.has_user_instruction
        assert any(
            f.rule_id == "DF-SEC-010"
            for f in result.findings
        )

    def test_detect_hardcoded_secret(self):
        """Test detection of hardcoded secrets."""
        analyzer = DockerfileAnalyzer()
        content = """FROM python:3.11
RUN export password="mysecret123"
"""
        result = analyzer.analyze_content(content)
        assert any(
            f.severity == DockerfileSeverity.CRITICAL
            for f in result.findings
        )

    def test_detect_curl_pipe(self):
        """Test detection of curl | bash pattern."""
        analyzer = DockerfileAnalyzer()
        content = """FROM alpine
RUN curl https://example.com/install.sh | bash
"""
        result = analyzer.analyze_content(content)
        assert any(
            "curl" in f.title.lower() or "pipe" in f.title.lower()
            for f in result.findings
        )

    def test_detect_add_url(self):
        """Test detection of ADD with URL."""
        analyzer = DockerfileAnalyzer()
        content = """FROM alpine
ADD https://example.com/file.tar.gz /app/
"""
        result = analyzer.analyze_content(content)
        assert any(
            f.rule_id == "DF-SEC-012"
            for f in result.findings
        )

    def test_detect_world_writable(self):
        """Test detection of chmod 777."""
        analyzer = DockerfileAnalyzer()
        content = """FROM alpine
RUN chmod 777 /app
"""
        result = analyzer.analyze_content(content)
        assert any(
            f.rule_id == "DF-SEC-020"
            for f in result.findings
        )

    def test_detect_sudo_install(self):
        """Test detection of sudo installation."""
        analyzer = DockerfileAnalyzer()
        content = """FROM ubuntu
RUN apt-get install -y sudo
"""
        result = analyzer.analyze_content(content)
        assert any(
            f.rule_id == "DF-SEC-021"
            for f in result.findings
        )

    def test_detect_no_healthcheck(self):
        """Test detection of missing HEALTHCHECK."""
        analyzer = DockerfileAnalyzer()
        content = """FROM python:3.11
CMD ["python", "app.py"]
"""
        result = analyzer.analyze_content(content)
        assert not result.has_healthcheck
        assert any(
            f.rule_id == "DF-SEC-023"
            for f in result.findings
        )

    def test_detect_apt_no_cleanup(self):
        """Test detection of apt without cleanup."""
        analyzer = DockerfileAnalyzer()
        content = """FROM ubuntu
RUN apt-get update && apt-get install -y curl
"""
        result = analyzer.analyze_content(content)
        assert any(
            f.rule_id == "DF-BP-001"
            for f in result.findings
        )

    def test_detect_apk_no_cache(self):
        """Test detection of apk without --no-cache."""
        analyzer = DockerfileAnalyzer()
        content = """FROM alpine
RUN apk add python3
"""
        result = analyzer.analyze_content(content)
        assert any(
            f.rule_id == "DF-BP-002"
            for f in result.findings
        )

    def test_detect_multistage_build(self):
        """Test detection of multi-stage build."""
        analyzer = DockerfileAnalyzer()
        content = """FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o app

FROM alpine
COPY --from=builder /app/app /app
CMD ["/app"]
"""
        result = analyzer.analyze_content(content)
        assert result.is_multi_stage
        assert len(result.stages) == 1  # Only "builder" stage named

    def test_no_multistage_recommendation(self):
        """Test recommendation for non-multistage build."""
        analyzer = DockerfileAnalyzer()
        content = """FROM golang:1.21
COPY . .
RUN go build -o app
CMD ["./app"]
"""
        result = analyzer.analyze_content(content)
        assert not result.is_multi_stage
        assert any(
            f.rule_id == "DF-PERF-002"
            for f in result.findings
        )

    def test_detect_ssh_keys(self):
        """Test detection of SSH keys being copied."""
        analyzer = DockerfileAnalyzer()
        content = """FROM ubuntu
COPY id_rsa.pem /root/.ssh/
"""
        result = analyzer.analyze_content(content)
        assert any(
            f.rule_id == "DF-SEC-003"
            for f in result.findings
        )

    def test_get_rules(self):
        """Test getting all rules."""
        analyzer = DockerfileAnalyzer()
        rules = analyzer.get_rules()
        assert len(rules) > 0
        assert all("rule_id" in r for r in rules)

    def test_findings_by_severity(self):
        """Test filtering findings by severity."""
        result = DockerfileAnalysisResult(file_path="test")
        result.findings.append(DockerfileFinding(
            rule_id="test1",
            severity=DockerfileSeverity.HIGH,
            category=DockerfileCategory.SECURITY,
            title="High",
            description="High finding",
        ))
        result.findings.append(DockerfileFinding(
            rule_id="test2",
            severity=DockerfileSeverity.LOW,
            category=DockerfileCategory.BEST_PRACTICE,
            title="Low",
            description="Low finding",
        ))

        high_findings = result.get_findings_by_severity(DockerfileSeverity.HIGH)
        assert len(high_findings) == 1
        assert high_findings[0].rule_id == "test1"

    def test_findings_by_category(self):
        """Test filtering findings by category."""
        result = DockerfileAnalysisResult(file_path="test")
        result.findings.append(DockerfileFinding(
            rule_id="test1",
            severity=DockerfileSeverity.HIGH,
            category=DockerfileCategory.SECURITY,
            title="Security",
            description="Security finding",
        ))
        result.findings.append(DockerfileFinding(
            rule_id="test2",
            severity=DockerfileSeverity.LOW,
            category=DockerfileCategory.BEST_PRACTICE,
            title="BP",
            description="BP finding",
        ))

        security_findings = result.get_findings_by_category(DockerfileCategory.SECURITY)
        assert len(security_findings) == 1
        assert security_findings[0].rule_id == "test1"


class TestDockerfileConvenienceFunctions:
    """Tests for Dockerfile convenience functions."""

    def test_analyze_dockerfile_content(self):
        """Test analyze_dockerfile_content function."""
        content = """FROM python:3.11
CMD ["python", "app.py"]
"""
        result = analyze_dockerfile_content(content)
        assert result.instruction_count == 2
        assert result.file_path == "<inline>"


# =============================================================================
# Integration Tests
# =============================================================================

class TestContainerScanningIntegration:
    """Integration tests for container scanning components."""

    def test_full_dockerfile_analysis(self):
        """Test complete Dockerfile analysis workflow."""
        content = """FROM python:latest
RUN apt-get update && apt-get install -y curl
RUN pip install flask
COPY . /app
WORKDIR /app
RUN chmod 777 /app
CMD ["python", "app.py"]
"""
        result = analyze_dockerfile_content(content)

        # Should have multiple findings
        assert result.total_findings > 0

        # Should detect :latest
        assert any("latest" in f.title.lower() for f in result.findings)

        # Should detect no USER
        assert any("root" in f.title.lower() for f in result.findings)

        # Should detect chmod 777
        assert any("777" in f.title or "writable" in f.title.lower()
                   for f in result.findings)

    def test_base_image_with_layer_info(self):
        """Test base image analysis combined with layer info."""
        # Analyze base image
        base_analysis = analyze_base_image("python:3.8")

        # Should be EOL
        assert base_analysis.status == BaseImageStatus.EOL

        # Should have update recommendation
        update_recs = [r for r in base_analysis.recommendations
                       if r.recommendation_type == "update"]
        assert len(update_recs) > 0
        assert "3.12" in update_recs[0].recommended_image

    def test_secure_dockerfile(self):
        """Test a well-written secure Dockerfile."""
        content = """FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /app .
USER nobody
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1
CMD ["python", "app.py"]
"""
        result = analyze_dockerfile_content(content)

        # Should be multi-stage
        assert result.is_multi_stage

        # Should have USER instruction
        assert result.has_user_instruction

        # Should have HEALTHCHECK
        assert result.has_healthcheck

        # Should have fewer findings than insecure version
        # (may still have some INFO level findings)
        critical_high = result.critical_count + result.high_count
        assert critical_high == 0


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_dockerfile(self):
        """Test handling empty Dockerfile."""
        result = analyze_dockerfile_content("")
        assert result.instruction_count == 0

    def test_comments_only_dockerfile(self):
        """Test handling Dockerfile with only comments."""
        content = """# This is a comment
# Another comment
"""
        result = analyze_dockerfile_content(content)
        assert result.instruction_count == 0

    def test_malformed_instruction(self):
        """Test handling malformed instructions."""
        content = """FROM python:3.11
not a valid instruction
RUN echo hello
"""
        result = analyze_dockerfile_content(content)
        # Should still parse valid instructions
        assert result.instruction_count >= 2

    def test_base_image_unknown(self):
        """Test analyzing unknown base image."""
        analysis = analyze_base_image("my-custom-registry.io/custom-image:v1.0")
        assert analysis.is_official is False
        assert analysis.status == BaseImageStatus.UNKNOWN

    def test_layer_analyzer_no_docker(self):
        """Test layer analyzer when docker is not available."""
        with patch('shutil.which', return_value=None):
            analyzer = LayerAnalyzer()
            assert not analyzer.is_available()
