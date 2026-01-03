"""
Kubernetes Runtime Security Policy Engine.

Provides runtime security policy definition and enforcement for:
- Process execution controls
- File system access controls
- Network connection controls
- Capability restrictions
- System call filtering
- Container behavior monitoring
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class RuntimeAction(Enum):
    """Action to take when a rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"  # Log but don't block
    ALERT = "alert"  # Generate alert


class RuntimeScope(Enum):
    """Scope of runtime policy."""

    CLUSTER = "cluster"  # Applies to entire cluster
    NAMESPACE = "namespace"  # Applies to specific namespace(s)
    WORKLOAD = "workload"  # Applies to specific workload(s)
    CONTAINER = "container"  # Applies to specific container(s)


class RuntimeCategory(Enum):
    """Category of runtime rule."""

    PROCESS = "process"  # Process execution
    FILE = "file"  # File system access
    NETWORK = "network"  # Network connections
    CAPABILITY = "capability"  # Linux capabilities
    SYSCALL = "syscall"  # System calls
    MOUNT = "mount"  # Mount operations
    PRIVILEGE = "privilege"  # Privilege escalation
    CONTAINER = "container"  # Container behavior


class RuleSeverity(Enum):
    """Severity of rule violations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EnforcementMode(Enum):
    """Policy enforcement mode."""

    ENFORCE = "enforce"  # Block violations
    AUDIT = "audit"  # Log violations only
    DISABLED = "disabled"  # Policy disabled


@dataclass
class RuntimeRule:
    """A single runtime security rule."""

    rule_id: str
    name: str
    category: RuntimeCategory
    severity: RuleSeverity
    description: str
    action: RuntimeAction = RuntimeAction.DENY

    # Matching criteria
    match_process: Optional[str] = None  # Process name pattern
    match_file: Optional[str] = None  # File path pattern
    match_network: Optional[dict] = None  # Network criteria
    match_capability: Optional[list[str]] = None  # Capabilities
    match_syscall: Optional[list[str]] = None  # Syscalls
    match_container_image: Optional[str] = None  # Image pattern
    match_labels: Optional[dict[str, str]] = None  # Label selector

    # Exceptions
    except_process: Optional[list[str]] = None
    except_file: Optional[list[str]] = None
    except_container: Optional[list[str]] = None

    # Additional metadata
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class RuntimeViolation:
    """A runtime policy violation."""

    rule_id: str
    rule_name: str
    category: RuntimeCategory
    severity: RuleSeverity
    action_taken: RuntimeAction

    # Context
    timestamp: datetime = field(default_factory=datetime.utcnow)
    namespace: str = ""
    pod_name: str = ""
    container_name: str = ""
    container_image: str = ""

    # Violation details
    description: str = ""
    matched_value: Any = None
    expected_value: Any = None

    # Additional context
    process_name: Optional[str] = None
    process_args: Optional[list[str]] = None
    file_path: Optional[str] = None
    network_connection: Optional[dict] = None
    syscall: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category.value,
            "severity": self.severity.value,
            "action_taken": self.action_taken.value,
            "timestamp": self.timestamp.isoformat(),
            "namespace": self.namespace,
            "pod_name": self.pod_name,
            "container_name": self.container_name,
            "container_image": self.container_image,
            "description": self.description,
            "matched_value": self.matched_value,
            "process_name": self.process_name,
            "file_path": self.file_path,
        }


@dataclass
class RuntimePolicy:
    """A complete runtime security policy."""

    policy_id: str
    name: str
    description: str
    version: str = "1.0.0"

    # Scope
    scope: RuntimeScope = RuntimeScope.CLUSTER
    target_namespaces: list[str] = field(default_factory=list)
    target_workloads: list[str] = field(default_factory=list)
    target_labels: dict[str, str] = field(default_factory=dict)

    # Enforcement
    mode: EnforcementMode = EnforcementMode.AUDIT
    rules: list[RuntimeRule] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        """Number of rules in policy."""
        return len(self.rules)

    @property
    def enabled_rules(self) -> int:
        """Number of enabled rules."""
        return sum(1 for r in self.rules if r.enabled)

    def get_rules_by_category(self, category: RuntimeCategory) -> list[RuntimeRule]:
        """Get rules filtered by category."""
        return [r for r in self.rules if r.category == category and r.enabled]

    def summary(self) -> dict[str, Any]:
        """Get policy summary."""
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "version": self.version,
            "scope": self.scope.value,
            "mode": self.mode.value,
            "total_rules": self.rule_count,
            "enabled_rules": self.enabled_rules,
            "rules_by_category": {
                cat.value: len(self.get_rules_by_category(cat))
                for cat in RuntimeCategory
            },
        }


@dataclass
class RuntimeEnforcement:
    """Result of runtime policy enforcement."""

    policy_id: str
    policy_name: str
    enforcement_mode: EnforcementMode
    enforced_at: datetime = field(default_factory=datetime.utcnow)

    # Results
    rules_evaluated: int = 0
    violations: list[RuntimeViolation] = field(default_factory=list)
    allowed_actions: int = 0
    denied_actions: int = 0
    audited_actions: int = 0

    # Errors
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if enforcement completed without errors."""
        return len(self.errors) == 0

    @property
    def has_violations(self) -> bool:
        """Check if any violations occurred."""
        return len(self.violations) > 0

    @property
    def critical_violations(self) -> int:
        """Number of critical violations."""
        return sum(1 for v in self.violations if v.severity == RuleSeverity.CRITICAL)

    def summary(self) -> dict[str, Any]:
        """Get enforcement summary."""
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "mode": self.enforcement_mode.value,
            "rules_evaluated": self.rules_evaluated,
            "total_violations": len(self.violations),
            "critical_violations": self.critical_violations,
            "allowed_actions": self.allowed_actions,
            "denied_actions": self.denied_actions,
            "audited_actions": self.audited_actions,
        }


# Predefined runtime rules for common security controls
PREDEFINED_RULES = [
    # Process rules
    RuntimeRule(
        rule_id="RT-PROC-001",
        name="Shell Execution in Container",
        category=RuntimeCategory.PROCESS,
        severity=RuleSeverity.HIGH,
        description="Detect shell execution in production containers",
        match_process=r"^(bash|sh|zsh|ksh|csh|fish)$",
        action=RuntimeAction.AUDIT,
        remediation="Investigate shell access; may indicate container compromise",
    ),
    RuntimeRule(
        rule_id="RT-PROC-002",
        name="Package Manager Execution",
        category=RuntimeCategory.PROCESS,
        severity=RuleSeverity.MEDIUM,
        description="Detect package manager execution in running containers",
        match_process=r"^(apt-get|apt|apk|yum|dnf|pip|npm|gem)$",
        action=RuntimeAction.AUDIT,
        remediation="Package managers should not run in production containers",
    ),
    RuntimeRule(
        rule_id="RT-PROC-003",
        name="Cryptocurrency Miner Detection",
        category=RuntimeCategory.PROCESS,
        severity=RuleSeverity.CRITICAL,
        description="Detect known cryptocurrency mining processes",
        match_process=r"(xmrig|minerd|cgminer|bfgminer|cpuminer|ethminer)",
        action=RuntimeAction.DENY,
        remediation="Container may be compromised; investigate immediately",
    ),
    RuntimeRule(
        rule_id="RT-PROC-004",
        name="Reverse Shell Detection",
        category=RuntimeCategory.PROCESS,
        severity=RuleSeverity.CRITICAL,
        description="Detect reverse shell patterns",
        match_process=r"(nc|netcat|ncat).*(-e|-c|/bin)",
        action=RuntimeAction.DENY,
        remediation="Potential reverse shell; container may be compromised",
    ),

    # File rules
    RuntimeRule(
        rule_id="RT-FILE-001",
        name="Sensitive File Access",
        category=RuntimeCategory.FILE,
        severity=RuleSeverity.HIGH,
        description="Detect access to sensitive system files",
        match_file=r"^(/etc/passwd|/etc/shadow|/etc/sudoers)",
        action=RuntimeAction.AUDIT,
        remediation="Investigate why container is accessing sensitive files",
    ),
    RuntimeRule(
        rule_id="RT-FILE-002",
        name="SSH Key Access",
        category=RuntimeCategory.FILE,
        severity=RuleSeverity.HIGH,
        description="Detect access to SSH keys",
        match_file=r"\.ssh/(id_rsa|id_dsa|id_ecdsa|id_ed25519|authorized_keys)",
        action=RuntimeAction.AUDIT,
        remediation="SSH keys should not be accessed at runtime",
    ),
    RuntimeRule(
        rule_id="RT-FILE-003",
        name="Container Escape Files",
        category=RuntimeCategory.FILE,
        severity=RuleSeverity.CRITICAL,
        description="Detect access to files commonly used for container escape",
        match_file=r"^(/proc/[0-9]+/root|/proc/sysrq-trigger|/proc/kcore)",
        action=RuntimeAction.DENY,
        remediation="Potential container escape attempt",
    ),
    RuntimeRule(
        rule_id="RT-FILE-004",
        name="Kubernetes Secrets Access",
        category=RuntimeCategory.FILE,
        severity=RuleSeverity.MEDIUM,
        description="Detect access to Kubernetes secrets mount",
        match_file=r"^/var/run/secrets/kubernetes.io",
        action=RuntimeAction.AUDIT,
        remediation="Review if service account token access is expected",
    ),

    # Network rules
    RuntimeRule(
        rule_id="RT-NET-001",
        name="Metadata Service Access",
        category=RuntimeCategory.NETWORK,
        severity=RuleSeverity.HIGH,
        description="Detect access to cloud metadata services",
        match_network={"destination": "169.254.169.254", "port": 80},
        action=RuntimeAction.AUDIT,
        remediation="Metadata access may indicate credential theft attempt",
    ),
    RuntimeRule(
        rule_id="RT-NET-002",
        name="Outbound SSH",
        category=RuntimeCategory.NETWORK,
        severity=RuleSeverity.MEDIUM,
        description="Detect outbound SSH connections",
        match_network={"port": 22, "direction": "outbound"},
        action=RuntimeAction.AUDIT,
        remediation="Investigate outbound SSH; may indicate lateral movement",
    ),
    RuntimeRule(
        rule_id="RT-NET-003",
        name="DNS Exfiltration Patterns",
        category=RuntimeCategory.NETWORK,
        severity=RuleSeverity.HIGH,
        description="Detect suspicious DNS query patterns",
        match_network={"port": 53, "query_length_threshold": 50},
        action=RuntimeAction.AUDIT,
        remediation="Long DNS queries may indicate data exfiltration",
    ),

    # Capability rules
    RuntimeRule(
        rule_id="RT-CAP-001",
        name="NET_RAW Capability",
        category=RuntimeCategory.CAPABILITY,
        severity=RuleSeverity.HIGH,
        description="Container using NET_RAW capability",
        match_capability=["NET_RAW"],
        action=RuntimeAction.AUDIT,
        remediation="NET_RAW enables packet sniffing; remove if not needed",
    ),
    RuntimeRule(
        rule_id="RT-CAP-002",
        name="SYS_ADMIN Capability",
        category=RuntimeCategory.CAPABILITY,
        severity=RuleSeverity.CRITICAL,
        description="Container using SYS_ADMIN capability",
        match_capability=["SYS_ADMIN"],
        action=RuntimeAction.DENY,
        remediation="SYS_ADMIN is equivalent to root; never use in production",
    ),
    RuntimeRule(
        rule_id="RT-CAP-003",
        name="SYS_PTRACE Capability",
        category=RuntimeCategory.CAPABILITY,
        severity=RuleSeverity.HIGH,
        description="Container using SYS_PTRACE capability",
        match_capability=["SYS_PTRACE"],
        action=RuntimeAction.AUDIT,
        remediation="SYS_PTRACE allows process debugging; can enable escape",
    ),

    # Syscall rules
    RuntimeRule(
        rule_id="RT-SYS-001",
        name="ptrace Syscall",
        category=RuntimeCategory.SYSCALL,
        severity=RuleSeverity.HIGH,
        description="Process using ptrace syscall",
        match_syscall=["ptrace"],
        action=RuntimeAction.AUDIT,
        remediation="ptrace can be used for debugging or container escape",
    ),
    RuntimeRule(
        rule_id="RT-SYS-002",
        name="Kernel Module Syscalls",
        category=RuntimeCategory.SYSCALL,
        severity=RuleSeverity.CRITICAL,
        description="Process attempting to load kernel modules",
        match_syscall=["init_module", "finit_module", "delete_module"],
        action=RuntimeAction.DENY,
        remediation="Kernel module loading should never occur in containers",
    ),
    RuntimeRule(
        rule_id="RT-SYS-003",
        name="Namespace Syscalls",
        category=RuntimeCategory.SYSCALL,
        severity=RuleSeverity.HIGH,
        description="Process using namespace manipulation syscalls",
        match_syscall=["unshare", "setns"],
        action=RuntimeAction.AUDIT,
        remediation="Namespace manipulation may indicate escape attempt",
    ),

    # Privilege rules
    RuntimeRule(
        rule_id="RT-PRIV-001",
        name="setuid Binary Execution",
        category=RuntimeCategory.PRIVILEGE,
        severity=RuleSeverity.HIGH,
        description="Execution of setuid binary in container",
        match_file=r".*",  # Combined with setuid check
        action=RuntimeAction.AUDIT,
        remediation="setuid binaries can enable privilege escalation",
    ),
    RuntimeRule(
        rule_id="RT-PRIV-002",
        name="Root Process in Non-Root Container",
        category=RuntimeCategory.PRIVILEGE,
        severity=RuleSeverity.HIGH,
        description="Process running as root in container configured for non-root",
        action=RuntimeAction.AUDIT,
        remediation="Process bypassed non-root configuration; investigate",
    ),

    # Container behavior rules
    RuntimeRule(
        rule_id="RT-CTR-001",
        name="Container Drift",
        category=RuntimeCategory.CONTAINER,
        severity=RuleSeverity.MEDIUM,
        description="Container filesystem has been modified since start",
        action=RuntimeAction.AUDIT,
        remediation="Containers should be immutable; investigate changes",
    ),
    RuntimeRule(
        rule_id="RT-CTR-002",
        name="Unexpected Process Count",
        category=RuntimeCategory.CONTAINER,
        severity=RuleSeverity.LOW,
        description="Container running more processes than expected",
        action=RuntimeAction.AUDIT,
        remediation="Review process list for unexpected entries",
    ),
]


class RuntimePolicyEngine:
    """
    Runtime security policy engine.

    Evaluates runtime events against security policies and
    generates violations/enforcement decisions.

    Example:
        engine = RuntimePolicyEngine()
        policy = engine.create_policy("my-policy", "Production Security")
        engine.add_predefined_rules(policy)
        result = engine.evaluate(policy, event)
    """

    def __init__(self):
        """Initialize RuntimePolicyEngine."""
        self.predefined_rules = PREDEFINED_RULES

    def create_policy(
        self,
        policy_id: str,
        name: str,
        description: str = "",
        scope: RuntimeScope = RuntimeScope.CLUSTER,
        mode: EnforcementMode = EnforcementMode.AUDIT,
    ) -> RuntimePolicy:
        """
        Create a new runtime policy.

        Args:
            policy_id: Unique policy identifier
            name: Policy name
            description: Policy description
            scope: Policy scope
            mode: Enforcement mode

        Returns:
            New RuntimePolicy
        """
        return RuntimePolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            scope=scope,
            mode=mode,
        )

    def add_predefined_rules(
        self,
        policy: RuntimePolicy,
        categories: Optional[list[RuntimeCategory]] = None,
        severity_threshold: RuleSeverity = RuleSeverity.LOW,
    ) -> int:
        """
        Add predefined rules to a policy.

        Args:
            policy: Policy to add rules to
            categories: Categories to include (all if None)
            severity_threshold: Minimum severity to include

        Returns:
            Number of rules added
        """
        severity_order = [
            RuleSeverity.INFO,
            RuleSeverity.LOW,
            RuleSeverity.MEDIUM,
            RuleSeverity.HIGH,
            RuleSeverity.CRITICAL,
        ]
        threshold_idx = severity_order.index(severity_threshold)

        added = 0
        for rule in self.predefined_rules:
            # Check category filter
            if categories and rule.category not in categories:
                continue

            # Check severity threshold
            rule_idx = severity_order.index(rule.severity)
            if rule_idx < threshold_idx:
                continue

            policy.rules.append(rule)
            added += 1

        policy.updated_at = datetime.utcnow()
        return added

    def add_custom_rule(
        self,
        policy: RuntimePolicy,
        rule: RuntimeRule,
    ) -> None:
        """
        Add a custom rule to a policy.

        Args:
            policy: Policy to add rule to
            rule: Rule to add
        """
        policy.rules.append(rule)
        policy.updated_at = datetime.utcnow()

    def evaluate(
        self,
        policy: RuntimePolicy,
        event: dict[str, Any],
    ) -> RuntimeEnforcement:
        """
        Evaluate an event against a policy.

        Args:
            policy: Policy to evaluate
            event: Runtime event to evaluate

        Returns:
            RuntimeEnforcement result
        """
        result = RuntimeEnforcement(
            policy_id=policy.policy_id,
            policy_name=policy.name,
            enforcement_mode=policy.mode,
        )

        if policy.mode == EnforcementMode.DISABLED:
            return result

        # Check scope
        if not self._check_scope(policy, event):
            return result

        # Evaluate each enabled rule
        for rule in policy.rules:
            if not rule.enabled:
                continue

            result.rules_evaluated += 1
            violation = self._evaluate_rule(rule, event)

            if violation:
                # Apply enforcement mode
                if policy.mode == EnforcementMode.AUDIT:
                    violation.action_taken = RuntimeAction.AUDIT
                    result.audited_actions += 1
                elif policy.mode == EnforcementMode.ENFORCE:
                    if rule.action == RuntimeAction.DENY:
                        result.denied_actions += 1
                    else:
                        result.allowed_actions += 1

                result.violations.append(violation)

        return result

    def evaluate_pod_spec(
        self,
        policy: RuntimePolicy,
        pod_spec: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None,
    ) -> RuntimeEnforcement:
        """
        Evaluate a pod spec against runtime policy.

        Args:
            policy: Policy to evaluate
            pod_spec: Pod specification
            metadata: Pod metadata

        Returns:
            RuntimeEnforcement result
        """
        result = RuntimeEnforcement(
            policy_id=policy.policy_id,
            policy_name=policy.name,
            enforcement_mode=policy.mode,
        )

        if policy.mode == EnforcementMode.DISABLED:
            return result

        metadata = metadata or {}
        namespace = metadata.get("namespace", "default")
        pod_name = metadata.get("name", "unknown")

        # Evaluate capability rules
        for container in pod_spec.get("containers", []):
            self._evaluate_container_capabilities(
                result, policy, container, namespace, pod_name
            )

        # Evaluate security context rules
        self._evaluate_security_context(result, policy, pod_spec, namespace, pod_name)

        return result

    def _check_scope(
        self,
        policy: RuntimePolicy,
        event: dict[str, Any],
    ) -> bool:
        """Check if event is in policy scope."""
        if policy.scope == RuntimeScope.CLUSTER:
            return True

        if policy.scope == RuntimeScope.NAMESPACE:
            event_ns = event.get("namespace", "")
            if policy.target_namespaces and event_ns not in policy.target_namespaces:
                return False

        if policy.scope == RuntimeScope.WORKLOAD:
            event_workload = event.get("workload", "")
            if policy.target_workloads and event_workload not in policy.target_workloads:
                return False

        if policy.target_labels:
            event_labels = event.get("labels", {})
            for key, value in policy.target_labels.items():
                if event_labels.get(key) != value:
                    return False

        return True

    def _evaluate_rule(
        self,
        rule: RuntimeRule,
        event: dict[str, Any],
    ) -> Optional[RuntimeViolation]:
        """Evaluate a single rule against an event."""
        violation = None

        # Process matching
        if rule.match_process and rule.category == RuntimeCategory.PROCESS:
            process_name = event.get("process_name", "")
            if re.match(rule.match_process, process_name, re.IGNORECASE):
                # Check exceptions
                if rule.except_process and process_name in rule.except_process:
                    return None

                violation = RuntimeViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    action_taken=rule.action,
                    namespace=event.get("namespace", ""),
                    pod_name=event.get("pod_name", ""),
                    container_name=event.get("container_name", ""),
                    container_image=event.get("container_image", ""),
                    description=rule.description,
                    matched_value=process_name,
                    process_name=process_name,
                    process_args=event.get("process_args"),
                )

        # File matching
        elif rule.match_file and rule.category == RuntimeCategory.FILE:
            file_path = event.get("file_path", "")
            if re.match(rule.match_file, file_path, re.IGNORECASE):
                if rule.except_file and file_path in rule.except_file:
                    return None

                violation = RuntimeViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    action_taken=rule.action,
                    namespace=event.get("namespace", ""),
                    pod_name=event.get("pod_name", ""),
                    container_name=event.get("container_name", ""),
                    description=rule.description,
                    matched_value=file_path,
                    file_path=file_path,
                )

        # Network matching
        elif rule.match_network and rule.category == RuntimeCategory.NETWORK:
            network = event.get("network", {})
            if self._match_network(rule.match_network, network):
                violation = RuntimeViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    action_taken=rule.action,
                    namespace=event.get("namespace", ""),
                    pod_name=event.get("pod_name", ""),
                    container_name=event.get("container_name", ""),
                    description=rule.description,
                    matched_value=network,
                    network_connection=network,
                )

        # Capability matching
        elif rule.match_capability and rule.category == RuntimeCategory.CAPABILITY:
            capabilities = event.get("capabilities", [])
            matched = set(rule.match_capability) & set(capabilities)
            if matched:
                violation = RuntimeViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    action_taken=rule.action,
                    namespace=event.get("namespace", ""),
                    pod_name=event.get("pod_name", ""),
                    container_name=event.get("container_name", ""),
                    description=rule.description,
                    matched_value=list(matched),
                )

        # Syscall matching
        elif rule.match_syscall and rule.category == RuntimeCategory.SYSCALL:
            syscall = event.get("syscall", "")
            if syscall in rule.match_syscall:
                violation = RuntimeViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    action_taken=rule.action,
                    namespace=event.get("namespace", ""),
                    pod_name=event.get("pod_name", ""),
                    container_name=event.get("container_name", ""),
                    description=rule.description,
                    matched_value=syscall,
                    syscall=syscall,
                )

        return violation

    def _match_network(
        self,
        match_criteria: dict,
        network_event: dict,
    ) -> bool:
        """Match network event against criteria."""
        if not network_event:
            return False

        # Check destination
        if "destination" in match_criteria:
            if network_event.get("destination") != match_criteria["destination"]:
                return False

        # Check port
        if "port" in match_criteria:
            if network_event.get("port") != match_criteria["port"]:
                return False

        # Check direction
        if "direction" in match_criteria:
            if network_event.get("direction") != match_criteria["direction"]:
                return False

        return True

    def _evaluate_container_capabilities(
        self,
        result: RuntimeEnforcement,
        policy: RuntimePolicy,
        container: dict[str, Any],
        namespace: str,
        pod_name: str,
    ) -> None:
        """Evaluate container capabilities against policy."""
        security_context = container.get("securityContext", {})
        capabilities = security_context.get("capabilities", {})
        add_caps = capabilities.get("add", [])

        container_name = container.get("name", "unknown")

        for rule in policy.rules:
            if rule.category != RuntimeCategory.CAPABILITY or not rule.enabled:
                continue

            result.rules_evaluated += 1

            if rule.match_capability:
                matched = set(rule.match_capability) & set(add_caps)
                if matched:
                    violation = RuntimeViolation(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        action_taken=rule.action if policy.mode == EnforcementMode.ENFORCE else RuntimeAction.AUDIT,
                        namespace=namespace,
                        pod_name=pod_name,
                        container_name=container_name,
                        container_image=container.get("image", ""),
                        description=rule.description,
                        matched_value=list(matched),
                    )
                    result.violations.append(violation)

                    if policy.mode == EnforcementMode.ENFORCE:
                        result.denied_actions += 1
                    else:
                        result.audited_actions += 1

    def _evaluate_security_context(
        self,
        result: RuntimeEnforcement,
        policy: RuntimePolicy,
        pod_spec: dict[str, Any],
        namespace: str,
        pod_name: str,
    ) -> None:
        """Evaluate pod security context against policy."""
        security_context = pod_spec.get("securityContext", {})

        # Check for privilege-related rules
        for rule in policy.rules:
            if rule.category != RuntimeCategory.PRIVILEGE or not rule.enabled:
                continue

            result.rules_evaluated += 1

            # Example: Check runAsUser = 0
            run_as_user = security_context.get("runAsUser")
            if run_as_user == 0:
                violation = RuntimeViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    category=rule.category,
                    severity=rule.severity,
                    action_taken=rule.action if policy.mode == EnforcementMode.ENFORCE else RuntimeAction.AUDIT,
                    namespace=namespace,
                    pod_name=pod_name,
                    description="Pod configured to run as root (UID 0)",
                    matched_value=run_as_user,
                    expected_value="non-zero UID",
                )
                result.violations.append(violation)

    def get_predefined_rules(
        self,
        category: Optional[RuntimeCategory] = None,
    ) -> list[RuntimeRule]:
        """
        Get predefined rules.

        Args:
            category: Filter by category (all if None)

        Returns:
            List of predefined rules
        """
        if category:
            return [r for r in self.predefined_rules if r.category == category]
        return self.predefined_rules.copy()

    def export_policy(
        self,
        policy: RuntimePolicy,
        format: str = "yaml",
    ) -> str:
        """
        Export policy to string format.

        Args:
            policy: Policy to export
            format: Output format (yaml, json)

        Returns:
            Policy as string
        """
        import json

        policy_dict = {
            "apiVersion": "stance.io/v1",
            "kind": "RuntimePolicy",
            "metadata": {
                "name": policy.name,
                "id": policy.policy_id,
            },
            "spec": {
                "scope": policy.scope.value,
                "mode": policy.mode.value,
                "rules": [
                    {
                        "id": r.rule_id,
                        "name": r.name,
                        "category": r.category.value,
                        "severity": r.severity.value,
                        "action": r.action.value,
                        "enabled": r.enabled,
                    }
                    for r in policy.rules
                ],
            },
        }

        if format == "json":
            return json.dumps(policy_dict, indent=2)
        else:
            # Simple YAML-like format
            import json
            return json.dumps(policy_dict, indent=2)


def create_runtime_policy(
    policy_id: str,
    name: str,
    include_predefined: bool = True,
    mode: EnforcementMode = EnforcementMode.AUDIT,
) -> RuntimePolicy:
    """
    Convenience function to create a runtime policy.

    Args:
        policy_id: Unique policy identifier
        name: Policy name
        include_predefined: Include predefined rules
        mode: Enforcement mode

    Returns:
        New RuntimePolicy

    Example:
        >>> policy = create_runtime_policy("prod-policy", "Production Security")
        >>> print(f"Created policy with {policy.rule_count} rules")
    """
    engine = RuntimePolicyEngine()
    policy = engine.create_policy(policy_id, name, mode=mode)

    if include_predefined:
        engine.add_predefined_rules(policy)

    return policy


def evaluate_runtime_policy(
    policy: RuntimePolicy,
    event: dict[str, Any],
) -> RuntimeEnforcement:
    """
    Convenience function to evaluate a runtime event.

    Args:
        policy: Policy to evaluate
        event: Runtime event

    Returns:
        RuntimeEnforcement result

    Example:
        >>> result = evaluate_runtime_policy(policy, {"process_name": "bash"})
        >>> if result.has_violations:
        ...     print(f"Found {len(result.violations)} violations")
    """
    engine = RuntimePolicyEngine()
    return engine.evaluate(policy, event)
