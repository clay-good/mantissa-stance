"""
Unit tests for Kubernetes Runtime Security module (Phase 80).

Tests cover:
- Pod Security Standards (PSS) validation
- Network Policy analysis
- Runtime Security policy engine
"""

import pytest
from datetime import datetime

# PSS Validator Tests
from stance.k8s_security.pss_validator import (
    PSSValidator,
    PSSLevel,
    PSSVersion,
    PSSViolation,
    PSSValidationResult,
    PSSSeverity,
    validate_pod_security,
    validate_workload_security,
)

# Network Analyzer Tests
from stance.k8s_security.network_analyzer import (
    NetworkPolicyAnalyzer,
    NetworkPolicyAnalysis,
    NetworkSegment,
    NetworkFlow,
    NetworkCoverage,
    PolicyGap,
    PolicyDirection,
    CoverageLevel,
    SegmentationLevel,
    GapSeverity,
    analyze_network_policies,
    check_network_segmentation,
)

# Runtime Policy Tests
from stance.k8s_security.runtime_policy import (
    RuntimePolicyEngine,
    RuntimePolicy,
    RuntimeRule,
    RuntimeAction,
    RuntimeScope,
    RuntimeEnforcement,
    RuntimeViolation,
    RuntimeCategory,
    RuleSeverity,
    EnforcementMode,
    create_runtime_policy,
    evaluate_runtime_policy,
)


# =============================================================================
# PSS Validator Tests
# =============================================================================

class TestPSSLevel:
    """Tests for PSSLevel enum."""

    def test_level_values(self):
        """Test all PSS level values exist."""
        assert PSSLevel.PRIVILEGED.value == "privileged"
        assert PSSLevel.BASELINE.value == "baseline"
        assert PSSLevel.RESTRICTED.value == "restricted"


class TestPSSVersion:
    """Tests for PSSVersion enum."""

    def test_version_values(self):
        """Test PSS version values."""
        assert PSSVersion.LATEST.value == "latest"
        assert PSSVersion.V1_30.value == "v1.30"


class TestPSSViolation:
    """Tests for PSSViolation dataclass."""

    def test_violation_creation(self):
        """Test creating a PSS violation."""
        violation = PSSViolation(
            rule_id="PSS-B-001",
            level=PSSLevel.BASELINE,
            severity=PSSSeverity.CRITICAL,
            field_path="spec.hostNetwork",
            message="Pod uses host network",
            current_value=True,
            allowed_values=[False],
        )
        assert violation.rule_id == "PSS-B-001"
        assert violation.level == PSSLevel.BASELINE
        assert violation.severity == PSSSeverity.CRITICAL


class TestPSSValidationResult:
    """Tests for PSSValidationResult dataclass."""

    def test_result_creation(self):
        """Test creating validation result."""
        result = PSSValidationResult(
            workload_name="test-pod",
            workload_namespace="default",
            workload_kind="Pod",
        )
        assert result.workload_name == "test-pod"
        assert result.passes_baseline is True
        assert result.passes_restricted is True

    def test_result_summary(self):
        """Test result summary generation."""
        result = PSSValidationResult(
            workload_name="test-pod",
            workload_namespace="default",
            workload_kind="Deployment",
            max_allowed_level=PSSLevel.BASELINE,
        )
        summary = result.summary()
        assert summary["workload"] == "default/test-pod"
        assert summary["max_allowed_level"] == "baseline"


class TestPSSValidator:
    """Tests for PSSValidator class."""

    def test_validator_initialization(self):
        """Test validator initializes correctly."""
        validator = PSSValidator()
        assert validator.version == PSSVersion.LATEST

    def test_validate_secure_pod(self):
        """Test validating a secure pod."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {
                            "drop": ["ALL"],
                        },
                        "seccompProfile": {
                            "type": "RuntimeDefault",
                        },
                    },
                }],
                "securityContext": {
                    "runAsNonRoot": True,
                    "seccompProfile": {
                        "type": "RuntimeDefault",
                    },
                },
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_baseline is True

    def test_validate_privileged_container(self):
        """Test detecting privileged container."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "privileged": True,
                    },
                }],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_baseline is False
        assert result.max_allowed_level == PSSLevel.PRIVILEGED
        assert any(v.rule_id == "PSS-B-003" for v in result.violations)

    def test_validate_host_network(self):
        """Test detecting host network usage."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "hostNetwork": True,
                "containers": [{"name": "app", "image": "nginx"}],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_baseline is False
        assert any("hostNetwork" in v.field_path for v in result.violations)

    def test_validate_host_pid(self):
        """Test detecting host PID namespace."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "hostPID": True,
                "containers": [{"name": "app", "image": "nginx"}],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_baseline is False

    def test_validate_host_ipc(self):
        """Test detecting host IPC namespace."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "hostIPC": True,
                "containers": [{"name": "app", "image": "nginx"}],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_baseline is False

    def test_validate_dangerous_capabilities(self):
        """Test detecting dangerous capabilities."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "capabilities": {
                            "add": ["SYS_ADMIN", "NET_RAW"],
                        },
                    },
                }],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_baseline is False
        assert any(v.rule_id == "PSS-B-004" for v in result.violations)

    def test_validate_hostpath_volume(self):
        """Test detecting hostPath volume."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "volumes": [{
                    "name": "host-vol",
                    "hostPath": {"path": "/var/run/docker.sock"},
                }],
                "containers": [{"name": "app", "image": "nginx"}],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_baseline is False
        assert any(v.rule_id == "PSS-B-005" for v in result.violations)

    def test_validate_host_ports(self):
        """Test detecting host ports."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "ports": [{"containerPort": 80, "hostPort": 8080}],
                }],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert any(v.rule_id == "PSS-B-006" for v in result.violations)

    def test_validate_privilege_escalation(self):
        """Test detecting privilege escalation (restricted)."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        # Missing allowPrivilegeEscalation: false
                    },
                }],
            },
        }
        result = validator.validate_pod(pod_spec)
        # Should fail restricted
        assert result.passes_restricted is False
        assert any(v.rule_id == "PSS-R-002" for v in result.violations)

    def test_validate_run_as_non_root(self):
        """Test detecting non-root requirement (restricted)."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        # Missing runAsNonRoot: true
                    },
                }],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_restricted is False
        assert any(v.rule_id == "PSS-R-003" for v in result.violations)

    def test_validate_run_as_root_user(self):
        """Test detecting UID 0 (restricted)."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "securityContext": {
                    "runAsUser": 0,
                },
                "containers": [{"name": "app", "image": "nginx"}],
            },
        }
        result = validator.validate_pod(pod_spec)
        assert any(v.rule_id == "PSS-R-004" for v in result.violations)

    def test_validate_capabilities_restricted(self):
        """Test capabilities must drop ALL (restricted)."""
        validator = PSSValidator()
        pod_spec = {
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "allowPrivilegeEscalation": False,
                        "capabilities": {
                            "drop": ["NET_RAW"],  # Should drop ALL
                        },
                    },
                }],
                "securityContext": {"runAsNonRoot": True},
            },
        }
        result = validator.validate_pod(pod_spec)
        assert result.passes_restricted is False
        assert any(v.rule_id == "PSS-R-006" for v in result.violations)

    def test_validate_workload(self):
        """Test validating a Deployment workload."""
        validator = PSSValidator()
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "test-deploy", "namespace": "prod"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,
                        "containers": [{"name": "app", "image": "nginx"}],
                    },
                },
            },
        }
        result = validator.validate_workload(deployment)
        assert result.workload_kind == "Deployment"
        assert result.workload_name == "test-deploy"
        assert result.passes_baseline is False


class TestPSSConvenienceFunctions:
    """Tests for PSS convenience functions."""

    def test_validate_pod_security(self):
        """Test validate_pod_security function."""
        pod_spec = {
            "spec": {
                "containers": [{"name": "app", "image": "nginx"}],
            },
        }
        result = validate_pod_security(pod_spec, "test", "default")
        assert result.workload_name == "test"


# =============================================================================
# Network Policy Analyzer Tests
# =============================================================================

class TestPolicyDirection:
    """Tests for PolicyDirection enum."""

    def test_direction_values(self):
        """Test direction values."""
        assert PolicyDirection.INGRESS.value == "ingress"
        assert PolicyDirection.EGRESS.value == "egress"
        assert PolicyDirection.BOTH.value == "both"


class TestCoverageLevel:
    """Tests for CoverageLevel enum."""

    def test_coverage_values(self):
        """Test coverage level values."""
        assert CoverageLevel.FULL.value == "full"
        assert CoverageLevel.PARTIAL.value == "partial"
        assert CoverageLevel.NONE.value == "none"


class TestNetworkCoverage:
    """Tests for NetworkCoverage dataclass."""

    def test_coverage_creation(self):
        """Test creating network coverage."""
        coverage = NetworkCoverage(
            namespace="default",
            total_pods=10,
            pods_with_ingress_policy=8,
        )
        assert coverage.namespace == "default"
        assert coverage.total_pods == 10


class TestPolicyGap:
    """Tests for PolicyGap dataclass."""

    def test_gap_creation(self):
        """Test creating policy gap."""
        gap = PolicyGap(
            gap_id="NP-GAP-001",
            severity=GapSeverity.CRITICAL,
            gap_type="no_policy_critical_namespace",
            namespace="kube-system",
            description="No network policies in kube-system",
        )
        assert gap.severity == GapSeverity.CRITICAL


class TestNetworkPolicyAnalysis:
    """Tests for NetworkPolicyAnalysis dataclass."""

    def test_analysis_creation(self):
        """Test creating analysis result."""
        result = NetworkPolicyAnalysis()
        assert result.total_namespaces == 0
        assert result.success is True

    def test_analysis_summary(self):
        """Test analysis summary."""
        result = NetworkPolicyAnalysis(
            total_namespaces=5,
            total_policies=10,
            total_pods=50,
        )
        summary = result.summary()
        assert summary["total_namespaces"] == 5


class TestNetworkPolicyAnalyzer:
    """Tests for NetworkPolicyAnalyzer class."""

    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly."""
        analyzer = NetworkPolicyAnalyzer()
        assert analyzer is not None

    def test_analyze_empty(self):
        """Test analyzing empty resources."""
        analyzer = NetworkPolicyAnalyzer()
        result = analyzer.analyze([], [], [])
        assert result.total_policies == 0
        assert result.total_pods == 0

    def test_analyze_with_policies(self):
        """Test analyzing with network policies."""
        analyzer = NetworkPolicyAnalyzer()

        namespaces = [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "prod"}},
        ]

        pods = [
            {"metadata": {"name": "pod1", "namespace": "default", "labels": {"app": "web"}}},
            {"metadata": {"name": "pod2", "namespace": "prod", "labels": {"app": "api"}}},
        ]

        policies = [
            {
                "metadata": {"name": "deny-all", "namespace": "default"},
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress"],
                    "ingress": [],
                },
            },
        ]

        result = analyzer.analyze(policies, pods, namespaces)
        assert result.total_policies == 1
        assert result.total_namespaces == 2
        assert result.default_deny_policies == 1

    def test_detect_default_deny(self):
        """Test detecting default deny policy."""
        analyzer = NetworkPolicyAnalyzer()

        policy = {
            "metadata": {"name": "deny-all", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress"],
                "ingress": [],
            },
        }

        assert analyzer._is_default_deny(policy) is True

    def test_detect_overly_permissive(self):
        """Test detecting overly permissive policy."""
        analyzer = NetworkPolicyAnalyzer()

        policy = {
            "metadata": {"name": "allow-all", "namespace": "default"},
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress"],
                "ingress": [{}],  # Empty rule = allow all
            },
        }

        assert analyzer._is_overly_permissive(policy) is True

    def test_detect_not_overly_permissive(self):
        """Test policy that is not overly permissive."""
        analyzer = NetworkPolicyAnalyzer()

        policy = {
            "metadata": {"name": "restricted", "namespace": "default"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "web"}},
                "policyTypes": ["Ingress"],
                "ingress": [{
                    "from": [{
                        "podSelector": {"matchLabels": {"role": "db"}},
                    }],
                }],
            },
        }

        assert analyzer._is_overly_permissive(policy) is False

    def test_find_gaps_critical_namespace(self):
        """Test finding gaps in security-critical namespace."""
        analyzer = NetworkPolicyAnalyzer()

        namespaces = [{"metadata": {"name": "kube-system"}}]
        pods = [{"metadata": {"name": "pod1", "namespace": "kube-system", "labels": {}}}]

        result = analyzer.analyze([], pods, namespaces)

        assert len(result.gaps) > 0
        assert any(g.namespace == "kube-system" for g in result.gaps)
        assert any(g.severity == GapSeverity.CRITICAL for g in result.gaps)

    def test_generate_default_deny_policy(self):
        """Test generating default deny policy."""
        analyzer = NetworkPolicyAnalyzer()

        policy = analyzer.generate_default_deny_policy("prod", PolicyDirection.BOTH)

        assert policy["metadata"]["namespace"] == "prod"
        assert "Ingress" in policy["spec"]["policyTypes"]
        assert "Egress" in policy["spec"]["policyTypes"]
        assert policy["spec"]["ingress"] == []
        assert policy["spec"]["egress"] == []

    def test_analyze_policy(self):
        """Test analyzing single policy."""
        analyzer = NetworkPolicyAnalyzer()

        policy = {
            "metadata": {"name": "web-policy", "namespace": "default"},
            "spec": {
                "podSelector": {"matchLabels": {"app": "web"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "api"}}}]}],
                "egress": [{"to": [{"podSelector": {"matchLabels": {"app": "db"}}}]}],
            },
        }

        analysis = analyzer.analyze_policy(policy)
        assert analysis["name"] == "web-policy"
        assert "Ingress" in analysis["policy_types"]
        assert "Egress" in analysis["policy_types"]
        assert analysis["ingress_rules_count"] == 1
        assert analysis["egress_rules_count"] == 1


class TestNetworkConvenienceFunctions:
    """Tests for Network convenience functions."""

    def test_analyze_network_policies(self):
        """Test analyze_network_policies function."""
        result = analyze_network_policies([], [], [])
        assert result.total_policies == 0


# =============================================================================
# Runtime Policy Engine Tests
# =============================================================================

class TestRuntimeAction:
    """Tests for RuntimeAction enum."""

    def test_action_values(self):
        """Test action values."""
        assert RuntimeAction.ALLOW.value == "allow"
        assert RuntimeAction.DENY.value == "deny"
        assert RuntimeAction.AUDIT.value == "audit"


class TestRuntimeScope:
    """Tests for RuntimeScope enum."""

    def test_scope_values(self):
        """Test scope values."""
        assert RuntimeScope.CLUSTER.value == "cluster"
        assert RuntimeScope.NAMESPACE.value == "namespace"


class TestRuntimeCategory:
    """Tests for RuntimeCategory enum."""

    def test_category_values(self):
        """Test category values."""
        assert RuntimeCategory.PROCESS.value == "process"
        assert RuntimeCategory.FILE.value == "file"
        assert RuntimeCategory.NETWORK.value == "network"
        assert RuntimeCategory.CAPABILITY.value == "capability"
        assert RuntimeCategory.SYSCALL.value == "syscall"


class TestRuntimeRule:
    """Tests for RuntimeRule dataclass."""

    def test_rule_creation(self):
        """Test creating runtime rule."""
        rule = RuntimeRule(
            rule_id="RT-001",
            name="Test Rule",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            description="Test description",
            match_process=r"^bash$",
        )
        assert rule.rule_id == "RT-001"
        assert rule.enabled is True


class TestRuntimeViolation:
    """Tests for RuntimeViolation dataclass."""

    def test_violation_creation(self):
        """Test creating violation."""
        violation = RuntimeViolation(
            rule_id="RT-001",
            rule_name="Test Rule",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            action_taken=RuntimeAction.DENY,
            process_name="bash",
        )
        assert violation.process_name == "bash"

    def test_violation_to_dict(self):
        """Test violation to_dict method."""
        violation = RuntimeViolation(
            rule_id="RT-001",
            rule_name="Test Rule",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            action_taken=RuntimeAction.AUDIT,
        )
        d = violation.to_dict()
        assert d["rule_id"] == "RT-001"
        assert d["category"] == "process"


class TestRuntimePolicy:
    """Tests for RuntimePolicy dataclass."""

    def test_policy_creation(self):
        """Test creating policy."""
        policy = RuntimePolicy(
            policy_id="test-policy",
            name="Test Policy",
            description="Test description",
        )
        assert policy.policy_id == "test-policy"
        assert policy.mode == EnforcementMode.AUDIT

    def test_policy_summary(self):
        """Test policy summary."""
        policy = RuntimePolicy(
            policy_id="test-policy",
            name="Test Policy",
            description="Test",
            rules=[
                RuntimeRule(
                    rule_id="R1",
                    name="Rule 1",
                    category=RuntimeCategory.PROCESS,
                    severity=RuleSeverity.HIGH,
                    description="Test",
                ),
            ],
        )
        summary = policy.summary()
        assert summary["total_rules"] == 1


class TestRuntimeEnforcement:
    """Tests for RuntimeEnforcement dataclass."""

    def test_enforcement_creation(self):
        """Test creating enforcement result."""
        result = RuntimeEnforcement(
            policy_id="test",
            policy_name="Test Policy",
            enforcement_mode=EnforcementMode.AUDIT,
        )
        assert result.success is True
        assert result.has_violations is False


class TestRuntimePolicyEngine:
    """Tests for RuntimePolicyEngine class."""

    def test_engine_initialization(self):
        """Test engine initializes correctly."""
        engine = RuntimePolicyEngine()
        assert len(engine.predefined_rules) > 0

    def test_create_policy(self):
        """Test creating policy."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy(
            "prod-policy",
            "Production Security",
            mode=EnforcementMode.ENFORCE,
        )
        assert policy.policy_id == "prod-policy"
        assert policy.mode == EnforcementMode.ENFORCE

    def test_add_predefined_rules(self):
        """Test adding predefined rules."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        count = engine.add_predefined_rules(policy)
        assert count > 0
        assert policy.rule_count > 0

    def test_add_predefined_rules_filtered(self):
        """Test adding filtered predefined rules."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        count = engine.add_predefined_rules(
            policy,
            categories=[RuntimeCategory.PROCESS],
        )
        assert all(r.category == RuntimeCategory.PROCESS for r in policy.rules)

    def test_evaluate_process_rule(self):
        """Test evaluating process rule."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST-001",
            name="Detect Bash",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            description="Detect bash execution",
            match_process=r"^bash$",
            action=RuntimeAction.AUDIT,
        ))

        event = {
            "process_name": "bash",
            "namespace": "default",
            "pod_name": "test-pod",
        }

        result = engine.evaluate(policy, event)
        assert result.has_violations is True
        assert len(result.violations) == 1
        assert result.violations[0].process_name == "bash"

    def test_evaluate_file_rule(self):
        """Test evaluating file rule."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST-002",
            name="Detect Shadow Access",
            category=RuntimeCategory.FILE,
            severity=RuleSeverity.HIGH,
            description="Detect shadow file access",
            match_file=r"^/etc/shadow$",
            action=RuntimeAction.DENY,
        ))

        event = {
            "file_path": "/etc/shadow",
            "namespace": "default",
        }

        result = engine.evaluate(policy, event)
        assert result.has_violations is True
        assert result.violations[0].file_path == "/etc/shadow"

    def test_evaluate_capability_rule(self):
        """Test evaluating capability rule."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST-003",
            name="Detect SYS_ADMIN",
            category=RuntimeCategory.CAPABILITY,
            severity=RuleSeverity.CRITICAL,
            description="Detect SYS_ADMIN capability",
            match_capability=["SYS_ADMIN"],
            action=RuntimeAction.DENY,
        ))

        event = {
            "capabilities": ["SYS_ADMIN", "NET_ADMIN"],
            "namespace": "default",
        }

        result = engine.evaluate(policy, event)
        assert result.has_violations is True

    def test_evaluate_network_rule(self):
        """Test evaluating network rule."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST-004",
            name="Detect Metadata Access",
            category=RuntimeCategory.NETWORK,
            severity=RuleSeverity.HIGH,
            description="Detect metadata service access",
            match_network={"destination": "169.254.169.254", "port": 80},
            action=RuntimeAction.AUDIT,
        ))

        event = {
            "network": {
                "destination": "169.254.169.254",
                "port": 80,
            },
            "namespace": "default",
        }

        result = engine.evaluate(policy, event)
        assert result.has_violations is True

    def test_evaluate_syscall_rule(self):
        """Test evaluating syscall rule."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST-005",
            name="Detect ptrace",
            category=RuntimeCategory.SYSCALL,
            severity=RuleSeverity.HIGH,
            description="Detect ptrace syscall",
            match_syscall=["ptrace"],
            action=RuntimeAction.AUDIT,
        ))

        event = {
            "syscall": "ptrace",
            "namespace": "default",
        }

        result = engine.evaluate(policy, event)
        assert result.has_violations is True
        assert result.violations[0].syscall == "ptrace"

    def test_evaluate_scope_filtering(self):
        """Test scope filtering in evaluation."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        policy.scope = RuntimeScope.NAMESPACE
        policy.target_namespaces = ["prod"]

        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST",
            name="Test",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            description="Test",
            match_process=r".*",
        ))

        # Event in wrong namespace - should not match
        event = {
            "process_name": "bash",
            "namespace": "dev",
        }

        result = engine.evaluate(policy, event)
        assert result.has_violations is False

    def test_evaluate_enforce_mode(self):
        """Test enforce mode."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test", mode=EnforcementMode.ENFORCE)
        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST",
            name="Test",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            description="Test",
            match_process=r"^bash$",
            action=RuntimeAction.DENY,
        ))

        event = {"process_name": "bash"}
        result = engine.evaluate(policy, event)

        assert result.denied_actions == 1

    def test_evaluate_disabled_mode(self):
        """Test disabled mode."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test", mode=EnforcementMode.DISABLED)
        policy.rules.append(RuntimeRule(
            rule_id="RT-TEST",
            name="Test",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            description="Test",
            match_process=r"^bash$",
        ))

        event = {"process_name": "bash"}
        result = engine.evaluate(policy, event)

        assert result.rules_evaluated == 0

    def test_evaluate_pod_spec(self):
        """Test evaluating pod spec."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test")
        engine.add_predefined_rules(policy, categories=[RuntimeCategory.CAPABILITY])

        pod_spec = {
            "containers": [{
                "name": "app",
                "image": "nginx",
                "securityContext": {
                    "capabilities": {
                        "add": ["SYS_ADMIN"],
                    },
                },
            }],
        }

        result = engine.evaluate_pod_spec(policy, pod_spec, {"namespace": "default", "name": "test"})
        # Should find SYS_ADMIN capability violation
        assert result.has_violations is True

    def test_get_predefined_rules(self):
        """Test getting predefined rules."""
        engine = RuntimePolicyEngine()
        all_rules = engine.get_predefined_rules()
        assert len(all_rules) > 0

        process_rules = engine.get_predefined_rules(RuntimeCategory.PROCESS)
        assert all(r.category == RuntimeCategory.PROCESS for r in process_rules)

    def test_export_policy(self):
        """Test exporting policy."""
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("test", "Test Policy")
        policy.rules.append(RuntimeRule(
            rule_id="R1",
            name="Rule 1",
            category=RuntimeCategory.PROCESS,
            severity=RuleSeverity.HIGH,
            description="Test",
        ))

        exported = engine.export_policy(policy, "json")
        import json
        data = json.loads(exported)
        assert data["kind"] == "RuntimePolicy"
        assert len(data["spec"]["rules"]) == 1


class TestRuntimeConvenienceFunctions:
    """Tests for Runtime convenience functions."""

    def test_create_runtime_policy(self):
        """Test create_runtime_policy function."""
        policy = create_runtime_policy("test", "Test Policy")
        assert policy.policy_id == "test"
        assert policy.rule_count > 0  # Has predefined rules

    def test_create_runtime_policy_no_predefined(self):
        """Test create_runtime_policy without predefined rules."""
        policy = create_runtime_policy("test", "Test", include_predefined=False)
        assert policy.rule_count == 0

    def test_evaluate_runtime_policy(self):
        """Test evaluate_runtime_policy function."""
        policy = create_runtime_policy("test", "Test")
        event = {"process_name": "xmrig", "namespace": "default"}
        result = evaluate_runtime_policy(policy, event)
        # Should detect cryptocurrency miner
        assert result.has_violations is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestK8sSecurityIntegration:
    """Integration tests for K8s security module."""

    def test_full_pss_workflow(self):
        """Test complete PSS validation workflow."""
        # Create a workload with mixed security issues
        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "risky-app", "namespace": "default"},
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": True,  # Baseline violation
                        "containers": [{
                            "name": "app",
                            "image": "nginx",
                            "securityContext": {
                                "privileged": True,  # Baseline violation
                                "capabilities": {
                                    "add": ["SYS_ADMIN"],  # Baseline violation
                                },
                            },
                        }],
                    },
                },
            },
        }

        result = validate_workload_security(deployment)
        assert result.passes_baseline is False
        assert result.passes_restricted is False
        assert result.max_allowed_level == PSSLevel.PRIVILEGED
        assert result.critical_violations >= 2

    def test_full_network_policy_workflow(self):
        """Test complete network policy analysis workflow."""
        namespaces = [
            {"metadata": {"name": "kube-system"}},
            {"metadata": {"name": "prod"}},
        ]

        pods = [
            {"metadata": {"name": "coredns", "namespace": "kube-system", "labels": {"app": "coredns"}}},
            {"metadata": {"name": "api", "namespace": "prod", "labels": {"app": "api"}}},
            {"metadata": {"name": "web", "namespace": "prod", "labels": {"app": "web"}}},
        ]

        policies = [
            {
                "metadata": {"name": "api-ingress", "namespace": "prod"},
                "spec": {
                    "podSelector": {"matchLabels": {"app": "api"}},
                    "policyTypes": ["Ingress"],
                    "ingress": [{
                        "from": [{"podSelector": {"matchLabels": {"app": "web"}}}],
                    }],
                },
            },
        ]

        result = analyze_network_policies(policies, pods, namespaces)

        # Should find gaps in kube-system (no policies)
        assert result.critical_gaps >= 1

        # Should identify partial coverage
        assert result.overall_coverage_level in [CoverageLevel.PARTIAL, CoverageLevel.NONE]

    def test_full_runtime_policy_workflow(self):
        """Test complete runtime policy workflow."""
        # Create policy with predefined rules
        policy = create_runtime_policy(
            "production-security",
            "Production Runtime Security",
            mode=EnforcementMode.AUDIT,
        )

        # Simulate various events
        events = [
            {"process_name": "bash", "namespace": "prod", "pod_name": "web-1"},
            {"file_path": "/etc/shadow", "namespace": "prod", "pod_name": "api-1"},
            {"process_name": "xmrig", "namespace": "prod", "pod_name": "compromised"},
            {"syscall": "ptrace", "namespace": "prod", "pod_name": "debug"},
        ]

        total_violations = 0
        for event in events:
            result = evaluate_runtime_policy(policy, event)
            total_violations += len(result.violations)

        # Should detect multiple violations
        assert total_violations > 0
