"""
Pod Security Standards (PSS) Validator.

Validates Kubernetes workloads against Pod Security Standards
as defined by Kubernetes:
- Privileged: Unrestricted policy
- Baseline: Minimally restrictive, prevents known privilege escalations
- Restricted: Heavily restricted, hardened pods

Reference: https://kubernetes.io/docs/concepts/security/pod-security-standards/
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class PSSLevel(Enum):
    """Pod Security Standards levels."""

    PRIVILEGED = "privileged"  # Unrestricted
    BASELINE = "baseline"  # Minimal restrictions
    RESTRICTED = "restricted"  # Heavily restricted


class PSSVersion(Enum):
    """Pod Security Standards versions."""

    V1_25 = "v1.25"
    V1_26 = "v1.26"
    V1_27 = "v1.27"
    V1_28 = "v1.28"
    V1_29 = "v1.29"
    V1_30 = "v1.30"
    LATEST = "latest"


class PSSSeverity(Enum):
    """Severity of PSS violations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PSSViolation:
    """A single PSS violation."""

    rule_id: str
    level: PSSLevel
    severity: PSSSeverity
    field_path: str
    message: str
    current_value: Any = None
    allowed_values: list[Any] = field(default_factory=list)
    remediation: str = ""
    container_name: Optional[str] = None


@dataclass
class PSSValidationResult:
    """Result of PSS validation."""

    # Workload identification
    workload_name: str
    workload_namespace: str
    workload_kind: str

    # Validation metadata
    validated_at: datetime = field(default_factory=datetime.utcnow)
    pss_version: PSSVersion = PSSVersion.LATEST

    # Results
    passes_privileged: bool = True
    passes_baseline: bool = True
    passes_restricted: bool = True
    max_allowed_level: PSSLevel = PSSLevel.RESTRICTED

    # Violations
    violations: list[PSSViolation] = field(default_factory=list)

    # Container analysis
    containers_analyzed: int = 0
    init_containers_analyzed: int = 0
    ephemeral_containers_analyzed: int = 0

    @property
    def total_violations(self) -> int:
        """Total number of violations."""
        return len(self.violations)

    @property
    def critical_violations(self) -> int:
        """Number of critical violations."""
        return sum(1 for v in self.violations if v.severity == PSSSeverity.CRITICAL)

    @property
    def high_violations(self) -> int:
        """Number of high violations."""
        return sum(1 for v in self.violations if v.severity == PSSSeverity.HIGH)

    def get_violations_by_level(self, level: PSSLevel) -> list[PSSViolation]:
        """Get violations for a specific PSS level."""
        return [v for v in self.violations if v.level == level]

    def summary(self) -> dict[str, Any]:
        """Get validation summary."""
        return {
            "workload": f"{self.workload_namespace}/{self.workload_name}",
            "kind": self.workload_kind,
            "max_allowed_level": self.max_allowed_level.value,
            "passes_privileged": self.passes_privileged,
            "passes_baseline": self.passes_baseline,
            "passes_restricted": self.passes_restricted,
            "total_violations": self.total_violations,
            "critical_violations": self.critical_violations,
            "high_violations": self.high_violations,
            "containers_analyzed": self.containers_analyzed,
        }


# PSS Baseline Controls
# These controls prevent known privilege escalations
BASELINE_CONTROLS = [
    {
        "id": "PSS-B-001",
        "name": "HostProcess",
        "description": "Windows pods must not use HostProcess",
        "field_paths": [
            "spec.securityContext.windowsOptions.hostProcess",
            "spec.containers[*].securityContext.windowsOptions.hostProcess",
            "spec.initContainers[*].securityContext.windowsOptions.hostProcess",
        ],
        "disallowed_values": [True],
        "severity": PSSSeverity.CRITICAL,
    },
    {
        "id": "PSS-B-002",
        "name": "Host Namespaces",
        "description": "Sharing host namespaces must be disallowed",
        "checks": [
            {"field": "spec.hostNetwork", "disallowed": [True]},
            {"field": "spec.hostPID", "disallowed": [True]},
            {"field": "spec.hostIPC", "disallowed": [True]},
        ],
        "severity": PSSSeverity.CRITICAL,
    },
    {
        "id": "PSS-B-003",
        "name": "Privileged Containers",
        "description": "Privileged pods must be disallowed",
        "field_paths": [
            "spec.containers[*].securityContext.privileged",
            "spec.initContainers[*].securityContext.privileged",
        ],
        "disallowed_values": [True],
        "severity": PSSSeverity.CRITICAL,
    },
    {
        "id": "PSS-B-004",
        "name": "Capabilities",
        "description": "Adding NET_RAW and other dangerous capabilities must be disallowed",
        "dangerous_capabilities": [
            "ALL", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
            "DAC_READ_SEARCH", "SYS_RAWIO", "SYS_BOOT", "MAC_ADMIN",
            "MAC_OVERRIDE", "AUDIT_CONTROL", "AUDIT_WRITE",
        ],
        "severity": PSSSeverity.HIGH,
    },
    {
        "id": "PSS-B-005",
        "name": "HostPath Volumes",
        "description": "HostPath volumes must be forbidden",
        "volume_type": "hostPath",
        "severity": PSSSeverity.HIGH,
    },
    {
        "id": "PSS-B-006",
        "name": "Host Ports",
        "description": "HostPorts must be disallowed or restricted to a known list",
        "field_paths": [
            "spec.containers[*].ports[*].hostPort",
            "spec.initContainers[*].ports[*].hostPort",
        ],
        "severity": PSSSeverity.MEDIUM,
    },
    {
        "id": "PSS-B-007",
        "name": "AppArmor",
        "description": "AppArmor profiles must be set to runtime/default or localhost/*",
        "allowed_profiles": ["runtime/default", "localhost/"],
        "severity": PSSSeverity.MEDIUM,
    },
    {
        "id": "PSS-B-008",
        "name": "SELinux",
        "description": "SELinux type must be unconfined or a known type",
        "disallowed_types": [],  # Generally all types allowed in baseline
        "severity": PSSSeverity.MEDIUM,
    },
    {
        "id": "PSS-B-009",
        "name": "/proc Mount Type",
        "description": "The /proc mount type must be Default or unset",
        "field_paths": [
            "spec.containers[*].securityContext.procMount",
            "spec.initContainers[*].securityContext.procMount",
        ],
        "allowed_values": [None, "Default"],
        "severity": PSSSeverity.HIGH,
    },
    {
        "id": "PSS-B-010",
        "name": "Seccomp",
        "description": "Seccomp profile must be RuntimeDefault or Localhost",
        "allowed_types": ["RuntimeDefault", "Localhost", None],
        "severity": PSSSeverity.MEDIUM,
    },
    {
        "id": "PSS-B-011",
        "name": "Sysctls",
        "description": "Unsafe sysctls must not be set",
        "safe_sysctls": [
            "kernel.shm_rmid_forced",
            "net.ipv4.ip_local_port_range",
            "net.ipv4.ip_unprivileged_port_start",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.ping_group_range",
        ],
        "severity": PSSSeverity.HIGH,
    },
]

# PSS Restricted Controls
# These are additional restrictions on top of Baseline
RESTRICTED_CONTROLS = [
    {
        "id": "PSS-R-001",
        "name": "Volume Types",
        "description": "Only safe volume types are allowed",
        "allowed_types": [
            "configMap", "csi", "downwardAPI", "emptyDir",
            "ephemeral", "persistentVolumeClaim", "projected", "secret",
        ],
        "severity": PSSSeverity.MEDIUM,
    },
    {
        "id": "PSS-R-002",
        "name": "Privilege Escalation",
        "description": "Privilege escalation must be disallowed",
        "field_paths": [
            "spec.containers[*].securityContext.allowPrivilegeEscalation",
            "spec.initContainers[*].securityContext.allowPrivilegeEscalation",
        ],
        "required_value": False,
        "severity": PSSSeverity.HIGH,
    },
    {
        "id": "PSS-R-003",
        "name": "Running as Non-root",
        "description": "Containers must run as non-root",
        "field_paths": [
            "spec.securityContext.runAsNonRoot",
            "spec.containers[*].securityContext.runAsNonRoot",
            "spec.initContainers[*].securityContext.runAsNonRoot",
        ],
        "required_value": True,
        "severity": PSSSeverity.HIGH,
    },
    {
        "id": "PSS-R-004",
        "name": "Running as Non-root User",
        "description": "Containers must not run as UID 0",
        "field_paths": [
            "spec.securityContext.runAsUser",
            "spec.containers[*].securityContext.runAsUser",
            "spec.initContainers[*].securityContext.runAsUser",
        ],
        "disallowed_values": [0],
        "severity": PSSSeverity.HIGH,
    },
    {
        "id": "PSS-R-005",
        "name": "Seccomp (Restricted)",
        "description": "Seccomp profile must be RuntimeDefault or Localhost",
        "required_types": ["RuntimeDefault", "Localhost"],
        "severity": PSSSeverity.MEDIUM,
    },
    {
        "id": "PSS-R-006",
        "name": "Capabilities (Restricted)",
        "description": "All capabilities must be dropped, only NET_BIND_SERVICE allowed",
        "required_drop": ["ALL"],
        "allowed_add": ["NET_BIND_SERVICE"],
        "severity": PSSSeverity.HIGH,
    },
]


class PSSValidator:
    """
    Validates Kubernetes workloads against Pod Security Standards.

    Supports validation at three levels:
    - Privileged: No restrictions
    - Baseline: Prevents known privilege escalations
    - Restricted: Heavily restricted, security best practices

    Example:
        validator = PSSValidator()
        result = validator.validate_pod(pod_spec)
        if not result.passes_restricted:
            print(f"Pod violates restricted: {result.violations}")
    """

    def __init__(
        self,
        version: PSSVersion = PSSVersion.LATEST,
    ):
        """
        Initialize PSS Validator.

        Args:
            version: PSS version to validate against
        """
        self.version = version
        self.baseline_controls = BASELINE_CONTROLS
        self.restricted_controls = RESTRICTED_CONTROLS

    def validate_pod(
        self,
        pod_spec: dict[str, Any],
        name: str = "unknown",
        namespace: str = "default",
    ) -> PSSValidationResult:
        """
        Validate a pod specification against PSS.

        Args:
            pod_spec: Pod specification dict
            name: Pod name
            namespace: Pod namespace

        Returns:
            PSSValidationResult with violations
        """
        result = PSSValidationResult(
            workload_name=name,
            workload_namespace=namespace,
            workload_kind="Pod",
            pss_version=self.version,
        )

        # Count containers
        spec = pod_spec.get("spec", pod_spec)
        result.containers_analyzed = len(spec.get("containers", []))
        result.init_containers_analyzed = len(spec.get("initContainers", []))
        result.ephemeral_containers_analyzed = len(spec.get("ephemeralContainers", []))

        # Check baseline controls
        baseline_violations = self._check_baseline(spec)
        result.violations.extend(baseline_violations)

        if baseline_violations:
            result.passes_baseline = False
            result.passes_restricted = False
            result.max_allowed_level = PSSLevel.PRIVILEGED
        else:
            # Check restricted controls only if baseline passes
            restricted_violations = self._check_restricted(spec)
            result.violations.extend(restricted_violations)

            if restricted_violations:
                result.passes_restricted = False
                result.max_allowed_level = PSSLevel.BASELINE

        return result

    def validate_workload(
        self,
        workload: dict[str, Any],
    ) -> PSSValidationResult:
        """
        Validate any Kubernetes workload (Deployment, DaemonSet, etc.).

        Args:
            workload: Workload specification dict

        Returns:
            PSSValidationResult with violations
        """
        metadata = workload.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")
        kind = workload.get("kind", "Unknown")

        # Extract pod template
        spec = workload.get("spec", {})
        pod_template = spec.get("template", spec)
        pod_spec = pod_template.get("spec", pod_template)

        result = self.validate_pod(
            pod_spec={"spec": pod_spec},
            name=name,
            namespace=namespace,
        )
        result.workload_kind = kind

        return result

    def _check_baseline(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check baseline controls."""
        violations = []

        # Check host namespaces
        violations.extend(self._check_host_namespaces(spec))

        # Check privileged containers
        violations.extend(self._check_privileged(spec))

        # Check capabilities
        violations.extend(self._check_capabilities_baseline(spec))

        # Check hostPath volumes
        violations.extend(self._check_hostpath_volumes(spec))

        # Check host ports
        violations.extend(self._check_host_ports(spec))

        # Check procMount
        violations.extend(self._check_proc_mount(spec))

        # Check seccomp (baseline)
        violations.extend(self._check_seccomp_baseline(spec))

        # Check sysctls
        violations.extend(self._check_sysctls(spec))

        return violations

    def _check_restricted(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check restricted controls (in addition to baseline)."""
        violations = []

        # Check volume types
        violations.extend(self._check_volume_types(spec))

        # Check privilege escalation
        violations.extend(self._check_privilege_escalation(spec))

        # Check run as non-root
        violations.extend(self._check_run_as_non_root(spec))

        # Check run as user
        violations.extend(self._check_run_as_user(spec))

        # Check seccomp (restricted - required)
        violations.extend(self._check_seccomp_restricted(spec))

        # Check capabilities (restricted - drop ALL)
        violations.extend(self._check_capabilities_restricted(spec))

        return violations

    def _check_host_namespaces(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check for host namespace usage."""
        violations = []

        if spec.get("hostNetwork"):
            violations.append(PSSViolation(
                rule_id="PSS-B-002",
                level=PSSLevel.BASELINE,
                severity=PSSSeverity.CRITICAL,
                field_path="spec.hostNetwork",
                message="Pod uses host network namespace",
                current_value=True,
                allowed_values=[False, None],
                remediation="Set spec.hostNetwork to false or remove it",
            ))

        if spec.get("hostPID"):
            violations.append(PSSViolation(
                rule_id="PSS-B-002",
                level=PSSLevel.BASELINE,
                severity=PSSSeverity.CRITICAL,
                field_path="spec.hostPID",
                message="Pod uses host PID namespace",
                current_value=True,
                allowed_values=[False, None],
                remediation="Set spec.hostPID to false or remove it",
            ))

        if spec.get("hostIPC"):
            violations.append(PSSViolation(
                rule_id="PSS-B-002",
                level=PSSLevel.BASELINE,
                severity=PSSSeverity.CRITICAL,
                field_path="spec.hostIPC",
                message="Pod uses host IPC namespace",
                current_value=True,
                allowed_values=[False, None],
                remediation="Set spec.hostIPC to false or remove it",
            ))

        return violations

    def _check_privileged(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check for privileged containers."""
        violations = []

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                if security_context.get("privileged"):
                    violations.append(PSSViolation(
                        rule_id="PSS-B-003",
                        level=PSSLevel.BASELINE,
                        severity=PSSSeverity.CRITICAL,
                        field_path=f"spec.{container_type}[{i}].securityContext.privileged",
                        message=f"Container '{container.get('name', i)}' is privileged",
                        current_value=True,
                        allowed_values=[False, None],
                        remediation="Set securityContext.privileged to false",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_capabilities_baseline(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check for dangerous capabilities (baseline)."""
        violations = []
        dangerous = {"ALL", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE",
                     "DAC_READ_SEARCH", "SYS_RAWIO", "SYS_BOOT", "MAC_ADMIN",
                     "MAC_OVERRIDE", "AUDIT_CONTROL", "AUDIT_WRITE"}

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                capabilities = security_context.get("capabilities", {})
                add_caps = set(capabilities.get("add", []))

                bad_caps = add_caps & dangerous
                if bad_caps:
                    violations.append(PSSViolation(
                        rule_id="PSS-B-004",
                        level=PSSLevel.BASELINE,
                        severity=PSSSeverity.HIGH,
                        field_path=f"spec.{container_type}[{i}].securityContext.capabilities.add",
                        message=f"Container '{container.get('name', i)}' adds dangerous capabilities: {bad_caps}",
                        current_value=list(add_caps),
                        remediation="Remove dangerous capabilities from securityContext.capabilities.add",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_hostpath_volumes(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check for hostPath volumes."""
        violations = []
        volumes = spec.get("volumes", [])

        for i, volume in enumerate(volumes):
            if "hostPath" in volume:
                violations.append(PSSViolation(
                    rule_id="PSS-B-005",
                    level=PSSLevel.BASELINE,
                    severity=PSSSeverity.HIGH,
                    field_path=f"spec.volumes[{i}]",
                    message=f"Volume '{volume.get('name', i)}' uses hostPath",
                    current_value=volume.get("hostPath", {}).get("path"),
                    remediation="Use a different volume type (emptyDir, configMap, secret, PVC)",
                ))

        return violations

    def _check_host_ports(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check for host ports."""
        violations = []

        for container_type in ["containers", "initContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                ports = container.get("ports", [])
                for j, port in enumerate(ports):
                    host_port = port.get("hostPort")
                    if host_port and host_port != 0:
                        violations.append(PSSViolation(
                            rule_id="PSS-B-006",
                            level=PSSLevel.BASELINE,
                            severity=PSSSeverity.MEDIUM,
                            field_path=f"spec.{container_type}[{i}].ports[{j}].hostPort",
                            message=f"Container '{container.get('name', i)}' uses hostPort {host_port}",
                            current_value=host_port,
                            allowed_values=[0, None],
                            remediation="Remove hostPort or set to 0",
                            container_name=container.get("name"),
                        ))

        return violations

    def _check_proc_mount(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check procMount setting."""
        violations = []

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                proc_mount = security_context.get("procMount")
                if proc_mount and proc_mount != "Default":
                    violations.append(PSSViolation(
                        rule_id="PSS-B-009",
                        level=PSSLevel.BASELINE,
                        severity=PSSSeverity.HIGH,
                        field_path=f"spec.{container_type}[{i}].securityContext.procMount",
                        message=f"Container '{container.get('name', i)}' uses procMount: {proc_mount}",
                        current_value=proc_mount,
                        allowed_values=["Default", None],
                        remediation="Set procMount to 'Default' or remove it",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_seccomp_baseline(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check seccomp profile (baseline - just check for Unconfined)."""
        violations = []

        # Check pod-level seccomp
        pod_security_context = spec.get("securityContext", {})
        seccomp = pod_security_context.get("seccompProfile", {})
        if seccomp.get("type") == "Unconfined":
            violations.append(PSSViolation(
                rule_id="PSS-B-010",
                level=PSSLevel.BASELINE,
                severity=PSSSeverity.MEDIUM,
                field_path="spec.securityContext.seccompProfile.type",
                message="Pod uses Unconfined seccomp profile",
                current_value="Unconfined",
                allowed_values=["RuntimeDefault", "Localhost", None],
                remediation="Set seccompProfile.type to RuntimeDefault or Localhost",
            ))

        # Check container-level seccomp
        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                seccomp = security_context.get("seccompProfile", {})
                if seccomp.get("type") == "Unconfined":
                    violations.append(PSSViolation(
                        rule_id="PSS-B-010",
                        level=PSSLevel.BASELINE,
                        severity=PSSSeverity.MEDIUM,
                        field_path=f"spec.{container_type}[{i}].securityContext.seccompProfile.type",
                        message=f"Container '{container.get('name', i)}' uses Unconfined seccomp",
                        current_value="Unconfined",
                        allowed_values=["RuntimeDefault", "Localhost", None],
                        remediation="Set seccompProfile.type to RuntimeDefault or Localhost",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_sysctls(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check for unsafe sysctls."""
        violations = []
        safe_sysctls = {
            "kernel.shm_rmid_forced",
            "net.ipv4.ip_local_port_range",
            "net.ipv4.ip_unprivileged_port_start",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.ping_group_range",
        }

        security_context = spec.get("securityContext", {})
        sysctls = security_context.get("sysctls", [])

        for sysctl in sysctls:
            name = sysctl.get("name", "")
            if name not in safe_sysctls:
                violations.append(PSSViolation(
                    rule_id="PSS-B-011",
                    level=PSSLevel.BASELINE,
                    severity=PSSSeverity.HIGH,
                    field_path="spec.securityContext.sysctls",
                    message=f"Pod uses unsafe sysctl: {name}",
                    current_value=name,
                    allowed_values=list(safe_sysctls),
                    remediation=f"Remove unsafe sysctl '{name}' or use allowed sysctls",
                ))

        return violations

    def _check_volume_types(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check for disallowed volume types (restricted)."""
        violations = []
        allowed_types = {
            "configMap", "csi", "downwardAPI", "emptyDir",
            "ephemeral", "persistentVolumeClaim", "projected", "secret",
        }

        volumes = spec.get("volumes", [])
        for i, volume in enumerate(volumes):
            volume_name = volume.get("name", f"volume-{i}")
            # Get the volume type (first key that's not 'name')
            volume_type = None
            for key in volume:
                if key != "name":
                    volume_type = key
                    break

            if volume_type and volume_type not in allowed_types:
                violations.append(PSSViolation(
                    rule_id="PSS-R-001",
                    level=PSSLevel.RESTRICTED,
                    severity=PSSSeverity.MEDIUM,
                    field_path=f"spec.volumes[{i}]",
                    message=f"Volume '{volume_name}' uses disallowed type: {volume_type}",
                    current_value=volume_type,
                    allowed_values=list(allowed_types),
                    remediation=f"Use an allowed volume type: {', '.join(allowed_types)}",
                ))

        return violations

    def _check_privilege_escalation(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check allowPrivilegeEscalation (restricted)."""
        violations = []

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                allow_pe = security_context.get("allowPrivilegeEscalation")

                # Must be explicitly false in restricted
                if allow_pe is not False:
                    violations.append(PSSViolation(
                        rule_id="PSS-R-002",
                        level=PSSLevel.RESTRICTED,
                        severity=PSSSeverity.HIGH,
                        field_path=f"spec.{container_type}[{i}].securityContext.allowPrivilegeEscalation",
                        message=f"Container '{container.get('name', i)}' does not explicitly disable privilege escalation",
                        current_value=allow_pe,
                        allowed_values=[False],
                        remediation="Set securityContext.allowPrivilegeEscalation to false",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_run_as_non_root(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check runAsNonRoot (restricted)."""
        violations = []

        pod_security_context = spec.get("securityContext", {})
        pod_run_as_non_root = pod_security_context.get("runAsNonRoot")

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                container_run_as_non_root = security_context.get("runAsNonRoot")

                # Must be true at pod or container level
                if pod_run_as_non_root is not True and container_run_as_non_root is not True:
                    violations.append(PSSViolation(
                        rule_id="PSS-R-003",
                        level=PSSLevel.RESTRICTED,
                        severity=PSSSeverity.HIGH,
                        field_path=f"spec.{container_type}[{i}].securityContext.runAsNonRoot",
                        message=f"Container '{container.get('name', i)}' does not require running as non-root",
                        current_value=container_run_as_non_root,
                        allowed_values=[True],
                        remediation="Set runAsNonRoot to true at pod or container level",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_run_as_user(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check runAsUser is not 0 (restricted)."""
        violations = []

        pod_security_context = spec.get("securityContext", {})
        pod_run_as_user = pod_security_context.get("runAsUser")

        if pod_run_as_user == 0:
            violations.append(PSSViolation(
                rule_id="PSS-R-004",
                level=PSSLevel.RESTRICTED,
                severity=PSSSeverity.HIGH,
                field_path="spec.securityContext.runAsUser",
                message="Pod explicitly runs as root (UID 0)",
                current_value=0,
                remediation="Set runAsUser to a non-zero UID",
            ))

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                run_as_user = security_context.get("runAsUser")

                if run_as_user == 0:
                    violations.append(PSSViolation(
                        rule_id="PSS-R-004",
                        level=PSSLevel.RESTRICTED,
                        severity=PSSSeverity.HIGH,
                        field_path=f"spec.{container_type}[{i}].securityContext.runAsUser",
                        message=f"Container '{container.get('name', i)}' runs as root (UID 0)",
                        current_value=0,
                        remediation="Set runAsUser to a non-zero UID",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_seccomp_restricted(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check seccomp profile is required (restricted)."""
        violations = []

        pod_security_context = spec.get("securityContext", {})
        pod_seccomp = pod_security_context.get("seccompProfile", {})
        pod_seccomp_type = pod_seccomp.get("type")

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                seccomp = security_context.get("seccompProfile", {})
                seccomp_type = seccomp.get("type")

                # Must have seccomp at pod or container level
                if pod_seccomp_type not in ["RuntimeDefault", "Localhost"] and \
                   seccomp_type not in ["RuntimeDefault", "Localhost"]:
                    violations.append(PSSViolation(
                        rule_id="PSS-R-005",
                        level=PSSLevel.RESTRICTED,
                        severity=PSSSeverity.MEDIUM,
                        field_path=f"spec.{container_type}[{i}].securityContext.seccompProfile",
                        message=f"Container '{container.get('name', i)}' does not have required seccomp profile",
                        current_value=seccomp_type,
                        allowed_values=["RuntimeDefault", "Localhost"],
                        remediation="Set seccompProfile.type to RuntimeDefault or Localhost",
                        container_name=container.get("name"),
                    ))

        return violations

    def _check_capabilities_restricted(self, spec: dict[str, Any]) -> list[PSSViolation]:
        """Check capabilities are dropped (restricted)."""
        violations = []

        for container_type in ["containers", "initContainers", "ephemeralContainers"]:
            containers = spec.get(container_type, [])
            for i, container in enumerate(containers):
                security_context = container.get("securityContext", {})
                capabilities = security_context.get("capabilities", {})
                drop_caps = set(capabilities.get("drop", []))
                add_caps = set(capabilities.get("add", []))

                # Must drop ALL
                if "ALL" not in drop_caps:
                    violations.append(PSSViolation(
                        rule_id="PSS-R-006",
                        level=PSSLevel.RESTRICTED,
                        severity=PSSSeverity.HIGH,
                        field_path=f"spec.{container_type}[{i}].securityContext.capabilities.drop",
                        message=f"Container '{container.get('name', i)}' does not drop ALL capabilities",
                        current_value=list(drop_caps),
                        allowed_values=["ALL"],
                        remediation="Add 'ALL' to securityContext.capabilities.drop",
                        container_name=container.get("name"),
                    ))

                # Only NET_BIND_SERVICE allowed to add
                disallowed_add = add_caps - {"NET_BIND_SERVICE"}
                if disallowed_add:
                    violations.append(PSSViolation(
                        rule_id="PSS-R-006",
                        level=PSSLevel.RESTRICTED,
                        severity=PSSSeverity.HIGH,
                        field_path=f"spec.{container_type}[{i}].securityContext.capabilities.add",
                        message=f"Container '{container.get('name', i)}' adds disallowed capabilities: {disallowed_add}",
                        current_value=list(add_caps),
                        allowed_values=["NET_BIND_SERVICE"],
                        remediation="Only NET_BIND_SERVICE can be added in restricted mode",
                        container_name=container.get("name"),
                    ))

        return violations


def validate_pod_security(
    pod_spec: dict[str, Any],
    name: str = "unknown",
    namespace: str = "default",
) -> PSSValidationResult:
    """
    Convenience function to validate a pod against PSS.

    Args:
        pod_spec: Pod specification dict
        name: Pod name
        namespace: Pod namespace

    Returns:
        PSSValidationResult with violations

    Example:
        >>> result = validate_pod_security(pod_spec)
        >>> print(f"Max level: {result.max_allowed_level.value}")
    """
    validator = PSSValidator()
    return validator.validate_pod(pod_spec, name, namespace)


def validate_workload_security(
    workload: dict[str, Any],
) -> PSSValidationResult:
    """
    Convenience function to validate any workload against PSS.

    Args:
        workload: Workload specification dict (Deployment, DaemonSet, etc.)

    Returns:
        PSSValidationResult with violations

    Example:
        >>> result = validate_workload_security(deployment)
        >>> if not result.passes_restricted:
        ...     print("Workload fails restricted PSS")
    """
    validator = PSSValidator()
    return validator.validate_workload(workload)
