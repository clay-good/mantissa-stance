"""
MITRE ATT&CK Mapping for Mantissa Stance.

Maps security findings to MITRE ATT&CK for Cloud tactics, techniques,
and procedures (TTPs), providing detection recommendations and
mitigation strategies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.models.finding import Finding, FindingCollection, Severity


class MitreTactic(Enum):
    """MITRE ATT&CK Tactics relevant to cloud environments."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class KillChainPhase(Enum):
    """Cyber Kill Chain phases for attack progression tracking."""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


@dataclass
class MitreTechnique:
    """
    Represents a MITRE ATT&CK technique.

    Attributes:
        id: MITRE technique ID (e.g., T1078)
        name: Human-readable technique name
        tactic: Primary tactic this technique belongs to
        sub_techniques: List of sub-technique IDs
        description: Description of the technique
        cloud_platforms: Cloud platforms this technique applies to
    """

    id: str
    name: str
    tactic: MitreTactic
    sub_techniques: list[str] = field(default_factory=list)
    description: str = ""
    cloud_platforms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "tactic": self.tactic.value,
            "sub_techniques": self.sub_techniques,
            "description": self.description,
            "cloud_platforms": self.cloud_platforms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MitreTechnique:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            tactic=MitreTactic(data["tactic"]),
            sub_techniques=data.get("sub_techniques", []),
            description=data.get("description", ""),
            cloud_platforms=data.get("cloud_platforms", []),
        )


@dataclass
class AttackMapping:
    """
    Mapping of a finding to MITRE ATT&CK framework.

    Attributes:
        finding_id: ID of the mapped finding
        techniques: List of MITRE techniques this finding maps to
        kill_chain_phases: Kill chain phases this finding relates to
        detection_recommendations: How to detect exploitation
        mitigation_strategies: How to mitigate the risk
        confidence: Confidence level of the mapping (0.0-1.0)
    """

    finding_id: str
    techniques: list[MitreTechnique]
    kill_chain_phases: list[KillChainPhase]
    detection_recommendations: list[str]
    mitigation_strategies: list[str]
    confidence: float = 1.0

    @property
    def tactics(self) -> list[MitreTactic]:
        """Get unique tactics from all mapped techniques."""
        seen: set[MitreTactic] = set()
        result: list[MitreTactic] = []
        for tech in self.techniques:
            if tech.tactic not in seen:
                seen.add(tech.tactic)
                result.append(tech.tactic)
        return result

    @property
    def technique_ids(self) -> list[str]:
        """Get list of technique IDs."""
        return [t.id for t in self.techniques]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "techniques": [t.to_dict() for t in self.techniques],
            "tactics": [t.value for t in self.tactics],
            "kill_chain_phases": [p.value for p in self.kill_chain_phases],
            "detection_recommendations": self.detection_recommendations,
            "mitigation_strategies": self.mitigation_strategies,
            "confidence": self.confidence,
        }


class MitreAttackMapper:
    """
    Maps security findings to MITRE ATT&CK framework.

    Provides mapping of cloud security misconfigurations and vulnerabilities
    to MITRE ATT&CK tactics, techniques, and procedures.
    """

    # Cloud-specific MITRE ATT&CK techniques database
    TECHNIQUES: dict[str, MitreTechnique] = {
        # Initial Access
        "T1078": MitreTechnique(
            id="T1078",
            name="Valid Accounts",
            tactic=MitreTactic.INITIAL_ACCESS,
            sub_techniques=["T1078.001", "T1078.004"],
            description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1190": MitreTechnique(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=MitreTactic.INITIAL_ACCESS,
            description="Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1199": MitreTechnique(
            id="T1199",
            name="Trusted Relationship",
            tactic=MitreTactic.INITIAL_ACCESS,
            description="Adversaries may breach or otherwise leverage organizations who have access to intended victims.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Persistence
        "T1098": MitreTechnique(
            id="T1098",
            name="Account Manipulation",
            tactic=MitreTactic.PERSISTENCE,
            sub_techniques=["T1098.001", "T1098.003"],
            description="Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1136": MitreTechnique(
            id="T1136",
            name="Create Account",
            tactic=MitreTactic.PERSISTENCE,
            sub_techniques=["T1136.003"],
            description="Adversaries may create an account to maintain access to victim systems.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1525": MitreTechnique(
            id="T1525",
            name="Implant Internal Image",
            tactic=MitreTactic.PERSISTENCE,
            description="Adversaries may implant cloud or container images with malicious code to establish persistence.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Privilege Escalation
        "T1548": MitreTechnique(
            id="T1548",
            name="Abuse Elevation Control Mechanism",
            tactic=MitreTactic.PRIVILEGE_ESCALATION,
            description="Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1484": MitreTechnique(
            id="T1484",
            name="Domain Policy Modification",
            tactic=MitreTactic.PRIVILEGE_ESCALATION,
            description="Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses.",
            cloud_platforms=["Azure", "GCP"],
        ),
        # Defense Evasion
        "T1562": MitreTechnique(
            id="T1562",
            name="Impair Defenses",
            tactic=MitreTactic.DEFENSE_EVASION,
            sub_techniques=["T1562.001", "T1562.007", "T1562.008"],
            description="Adversaries may maliciously modify components of a victim environment in order to hinder defensive mechanisms.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1578": MitreTechnique(
            id="T1578",
            name="Modify Cloud Compute Infrastructure",
            tactic=MitreTactic.DEFENSE_EVASION,
            sub_techniques=["T1578.001", "T1578.002", "T1578.003", "T1578.004"],
            description="An adversary may attempt to modify a cloud account's compute service infrastructure.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1550": MitreTechnique(
            id="T1550",
            name="Use Alternate Authentication Material",
            tactic=MitreTactic.DEFENSE_EVASION,
            sub_techniques=["T1550.001"],
            description="Adversaries may use alternate authentication material to move laterally within an environment.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Credential Access
        "T1528": MitreTechnique(
            id="T1528",
            name="Steal Application Access Token",
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            description="Adversaries can steal application access tokens as a means of acquiring credentials.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1552": MitreTechnique(
            id="T1552",
            name="Unsecured Credentials",
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            sub_techniques=["T1552.001", "T1552.005"],
            description="Adversaries may search compromised systems to find and obtain insecurely stored credentials.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1606": MitreTechnique(
            id="T1606",
            name="Forge Web Credentials",
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            sub_techniques=["T1606.002"],
            description="Adversaries may forge credential materials that can be used to gain access to web applications.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Discovery
        "T1526": MitreTechnique(
            id="T1526",
            name="Cloud Service Discovery",
            tactic=MitreTactic.DISCOVERY,
            description="An adversary may attempt to enumerate the cloud services running on a system.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1580": MitreTechnique(
            id="T1580",
            name="Cloud Infrastructure Discovery",
            tactic=MitreTactic.DISCOVERY,
            description="An adversary may attempt to discover infrastructure and resources available within an IaaS environment.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1619": MitreTechnique(
            id="T1619",
            name="Cloud Storage Object Discovery",
            tactic=MitreTactic.DISCOVERY,
            description="Adversaries may enumerate objects in cloud storage infrastructure.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Lateral Movement
        "T1021": MitreTechnique(
            id="T1021",
            name="Remote Services",
            tactic=MitreTactic.LATERAL_MOVEMENT,
            sub_techniques=["T1021.007"],
            description="Adversaries may use valid accounts to log into a service that accepts remote connections.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Collection
        "T1530": MitreTechnique(
            id="T1530",
            name="Data from Cloud Storage",
            tactic=MitreTactic.COLLECTION,
            description="Adversaries may access data from cloud storage.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Exfiltration
        "T1537": MitreTechnique(
            id="T1537",
            name="Transfer Data to Cloud Account",
            tactic=MitreTactic.EXFILTRATION,
            description="Adversaries may exfiltrate data by transferring the data to another cloud account.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        # Impact
        "T1485": MitreTechnique(
            id="T1485",
            name="Data Destruction",
            tactic=MitreTactic.IMPACT,
            description="Adversaries may destroy data and files on specific systems or in large numbers on a network.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1486": MitreTechnique(
            id="T1486",
            name="Data Encrypted for Impact",
            tactic=MitreTactic.IMPACT,
            description="Adversaries may encrypt data on target systems to interrupt availability.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1496": MitreTechnique(
            id="T1496",
            name="Resource Hijacking",
            tactic=MitreTactic.IMPACT,
            description="Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
        "T1531": MitreTechnique(
            id="T1531",
            name="Account Access Removal",
            tactic=MitreTactic.IMPACT,
            description="Adversaries may interrupt availability of system and network resources by inhibiting access to accounts.",
            cloud_platforms=["AWS", "Azure", "GCP"],
        ),
    }

    # Mapping rules from finding patterns to techniques
    FINDING_PATTERNS: dict[str, list[str]] = {
        # Public exposure findings
        "public": ["T1190", "T1530", "T1619"],
        "publicly_accessible": ["T1190", "T1530", "T1619"],
        "internet_facing": ["T1190"],
        "open_to_internet": ["T1190"],
        # IAM and access findings
        "iam": ["T1078", "T1098", "T1136"],
        "overly_permissive": ["T1078", "T1548"],
        "admin": ["T1078", "T1548"],
        "privilege": ["T1548", "T1078"],
        "mfa": ["T1078", "T1550"],
        "no_mfa": ["T1078", "T1550"],
        "access_key": ["T1528", "T1552"],
        "credentials": ["T1552", "T1528"],
        "password": ["T1078", "T1552"],
        "cross_account": ["T1199", "T1550"],
        "trust": ["T1199"],
        # Encryption findings
        "encryption": ["T1530", "T1486"],
        "unencrypted": ["T1530", "T1537"],
        "not_encrypted": ["T1530", "T1537"],
        # Logging and monitoring findings
        "logging": ["T1562"],
        "cloudtrail": ["T1562"],
        "monitoring": ["T1562"],
        "audit": ["T1562"],
        "flow_logs": ["T1562"],
        # Network security findings
        "security_group": ["T1190", "T1021"],
        "network": ["T1021", "T1190"],
        "firewall": ["T1190", "T1562"],
        "ingress": ["T1190"],
        "egress": ["T1537"],
        # Storage findings
        "s3": ["T1530", "T1619", "T1537"],
        "bucket": ["T1530", "T1619"],
        "storage": ["T1530", "T1619"],
        "blob": ["T1530", "T1619"],
        # Compute findings
        "instance": ["T1578", "T1496"],
        "compute": ["T1578", "T1496"],
        "container": ["T1525", "T1578"],
        "lambda": ["T1578"],
        "function": ["T1578"],
        # Database findings
        "database": ["T1530", "T1485"],
        "rds": ["T1530", "T1485"],
        "sql": ["T1530", "T1485"],
        # Secrets findings
        "secret": ["T1552", "T1528"],
        "key_vault": ["T1552", "T1528"],
        "ssm": ["T1552"],
        # Versioning and backup findings
        "versioning": ["T1485", "T1486"],
        "backup": ["T1485", "T1486"],
        # Vulnerability findings
        "cve": ["T1190", "T1203"],
        "vulnerability": ["T1190"],
        "exploit": ["T1190"],
    }

    # Kill chain phase mappings based on tactic
    TACTIC_TO_KILL_CHAIN: dict[MitreTactic, list[KillChainPhase]] = {
        MitreTactic.RECONNAISSANCE: [KillChainPhase.RECONNAISSANCE],
        MitreTactic.RESOURCE_DEVELOPMENT: [KillChainPhase.WEAPONIZATION],
        MitreTactic.INITIAL_ACCESS: [
            KillChainPhase.DELIVERY,
            KillChainPhase.EXPLOITATION,
        ],
        MitreTactic.EXECUTION: [KillChainPhase.EXPLOITATION],
        MitreTactic.PERSISTENCE: [KillChainPhase.INSTALLATION],
        MitreTactic.PRIVILEGE_ESCALATION: [
            KillChainPhase.EXPLOITATION,
            KillChainPhase.INSTALLATION,
        ],
        MitreTactic.DEFENSE_EVASION: [
            KillChainPhase.INSTALLATION,
            KillChainPhase.COMMAND_AND_CONTROL,
        ],
        MitreTactic.CREDENTIAL_ACCESS: [
            KillChainPhase.EXPLOITATION,
            KillChainPhase.ACTIONS_ON_OBJECTIVES,
        ],
        MitreTactic.DISCOVERY: [KillChainPhase.RECONNAISSANCE],
        MitreTactic.LATERAL_MOVEMENT: [KillChainPhase.ACTIONS_ON_OBJECTIVES],
        MitreTactic.COLLECTION: [KillChainPhase.ACTIONS_ON_OBJECTIVES],
        MitreTactic.EXFILTRATION: [KillChainPhase.ACTIONS_ON_OBJECTIVES],
        MitreTactic.IMPACT: [KillChainPhase.ACTIONS_ON_OBJECTIVES],
    }

    # Detection recommendations by technique
    DETECTION_RECOMMENDATIONS: dict[str, list[str]] = {
        "T1078": [
            "Monitor for unusual login locations or times",
            "Alert on multiple failed authentication attempts",
            "Track API calls from new IP addresses",
            "Enable CloudTrail or equivalent logging",
        ],
        "T1190": [
            "Monitor for unusual inbound connections",
            "Enable web application firewall (WAF) logging",
            "Track exploitation attempts in application logs",
            "Alert on new ports exposed to internet",
        ],
        "T1098": [
            "Monitor for IAM policy changes",
            "Alert on new role attachments",
            "Track permission modifications",
            "Enable IAM Access Analyzer",
        ],
        "T1136": [
            "Alert on new user or service account creation",
            "Monitor for new access keys",
            "Track identity provider changes",
        ],
        "T1548": [
            "Monitor for privilege escalation attempts",
            "Track assume-role activities",
            "Alert on policy changes granting elevated access",
        ],
        "T1562": [
            "Alert on logging configuration changes",
            "Monitor for CloudTrail or audit log deletion",
            "Track security tool modifications",
            "Enable log integrity validation",
        ],
        "T1578": [
            "Monitor for new compute instances",
            "Track snapshot and AMI creation",
            "Alert on unusual instance modifications",
        ],
        "T1528": [
            "Monitor for token theft indicators",
            "Track unusual API call patterns",
            "Alert on token use from new locations",
        ],
        "T1552": [
            "Monitor for credential access in logs",
            "Track secrets manager access",
            "Alert on unusual parameter store queries",
        ],
        "T1530": [
            "Enable storage access logging",
            "Monitor for bulk data downloads",
            "Alert on access from unusual IPs",
            "Track cross-account access",
        ],
        "T1537": [
            "Monitor for large data transfers",
            "Track cross-account data movement",
            "Enable VPC flow logs",
            "Alert on unusual egress patterns",
        ],
        "T1485": [
            "Enable object versioning",
            "Monitor for bulk deletion operations",
            "Alert on backup deletion",
            "Track destructive API calls",
        ],
        "T1486": [
            "Monitor for encryption key changes",
            "Track unusual encryption operations",
            "Alert on ransomware indicators",
        ],
        "T1496": [
            "Monitor for unusual CPU/GPU usage",
            "Track new large instance launches",
            "Alert on cryptocurrency mining indicators",
        ],
    }

    # Mitigation strategies by technique
    MITIGATION_STRATEGIES: dict[str, list[str]] = {
        "T1078": [
            "Enforce multi-factor authentication (MFA)",
            "Implement least-privilege access",
            "Use temporary credentials",
            "Enable account lockout policies",
        ],
        "T1190": [
            "Keep systems patched and updated",
            "Use Web Application Firewalls (WAF)",
            "Implement network segmentation",
            "Minimize public-facing attack surface",
        ],
        "T1098": [
            "Restrict IAM modification permissions",
            "Implement approval workflows for policy changes",
            "Enable IAM Access Analyzer",
        ],
        "T1136": [
            "Restrict account creation permissions",
            "Require approval for new accounts",
            "Monitor and alert on new accounts",
        ],
        "T1548": [
            "Implement least-privilege policies",
            "Use permission boundaries",
            "Regularly audit role permissions",
        ],
        "T1562": [
            "Enable CloudTrail or audit logging in all regions",
            "Protect logging configurations with SCPs",
            "Use immutable logging",
            "Enable log validation",
        ],
        "T1578": [
            "Restrict compute modification permissions",
            "Enable change approval workflows",
            "Use infrastructure as code with reviews",
        ],
        "T1528": [
            "Use short-lived tokens",
            "Implement token binding",
            "Monitor for token abuse",
        ],
        "T1552": [
            "Use secrets management services",
            "Encrypt credentials at rest",
            "Rotate credentials regularly",
            "Remove hardcoded credentials",
        ],
        "T1530": [
            "Enable encryption at rest",
            "Implement bucket policies",
            "Use VPC endpoints for storage access",
            "Enable access logging",
        ],
        "T1537": [
            "Implement egress filtering",
            "Use VPC endpoints",
            "Enable data loss prevention (DLP)",
            "Monitor and restrict cross-account access",
        ],
        "T1485": [
            "Enable versioning on storage",
            "Implement backup retention policies",
            "Use MFA delete protection",
            "Enable cross-region replication",
        ],
        "T1486": [
            "Maintain offline backups",
            "Enable versioning",
            "Implement immutable storage",
            "Test recovery procedures",
        ],
        "T1496": [
            "Implement resource quotas",
            "Monitor for anomalous usage",
            "Use cost alerts",
            "Restrict compute provisioning",
        ],
    }

    def __init__(self) -> None:
        """Initialize the MITRE ATT&CK mapper."""
        pass

    def map_finding(self, finding: Finding) -> AttackMapping:
        """
        Map a single finding to MITRE ATT&CK framework.

        Args:
            finding: The finding to map

        Returns:
            AttackMapping with techniques, kill chain phases, and recommendations
        """
        techniques = self._identify_techniques(finding)
        kill_chain_phases = self._get_kill_chain_phases(techniques)
        detection_recs = self._get_detection_recommendations(techniques)
        mitigation_strats = self._get_mitigation_strategies(techniques)
        confidence = self._calculate_confidence(finding, techniques)

        return AttackMapping(
            finding_id=finding.id,
            techniques=techniques,
            kill_chain_phases=kill_chain_phases,
            detection_recommendations=detection_recs,
            mitigation_strategies=mitigation_strats,
            confidence=confidence,
        )

    def map_findings(
        self, findings: FindingCollection
    ) -> list[AttackMapping]:
        """
        Map multiple findings to MITRE ATT&CK framework.

        Args:
            findings: Collection of findings to map

        Returns:
            List of AttackMapping objects
        """
        return [self.map_finding(f) for f in findings.findings]

    def get_technique(self, technique_id: str) -> MitreTechnique | None:
        """
        Get a technique by ID.

        Args:
            technique_id: MITRE technique ID (e.g., T1078)

        Returns:
            MitreTechnique if found, None otherwise
        """
        return self.TECHNIQUES.get(technique_id)

    def get_techniques_by_tactic(
        self, tactic: MitreTactic
    ) -> list[MitreTechnique]:
        """
        Get all techniques for a given tactic.

        Args:
            tactic: The MITRE tactic

        Returns:
            List of techniques belonging to the tactic
        """
        return [t for t in self.TECHNIQUES.values() if t.tactic == tactic]

    def get_coverage_summary(
        self, mappings: list[AttackMapping]
    ) -> dict[str, Any]:
        """
        Get a summary of ATT&CK coverage across mappings.

        Args:
            mappings: List of attack mappings

        Returns:
            Summary including tactic and technique coverage
        """
        tactics_covered: set[MitreTactic] = set()
        techniques_covered: set[str] = set()
        kill_chain_covered: set[KillChainPhase] = set()

        for mapping in mappings:
            for tactic in mapping.tactics:
                tactics_covered.add(tactic)
            for tech_id in mapping.technique_ids:
                techniques_covered.add(tech_id)
            for phase in mapping.kill_chain_phases:
                kill_chain_covered.add(phase)

        return {
            "total_mappings": len(mappings),
            "tactics_covered": len(tactics_covered),
            "tactics_covered_list": [t.value for t in tactics_covered],
            "techniques_covered": len(techniques_covered),
            "techniques_covered_list": list(techniques_covered),
            "kill_chain_phases_covered": len(kill_chain_covered),
            "kill_chain_phases_list": [p.value for p in kill_chain_covered],
            "tactic_distribution": self._get_tactic_distribution(mappings),
        }

    def _identify_techniques(self, finding: Finding) -> list[MitreTechnique]:
        """Identify relevant MITRE techniques for a finding."""
        technique_ids: set[str] = set()

        # Build search text from finding attributes
        search_text = (
            f"{finding.title} {finding.description} "
            f"{finding.rule_id or ''} {finding.resource_path or ''}"
        ).lower()

        # Match against patterns
        for pattern, tech_ids in self.FINDING_PATTERNS.items():
            if pattern in search_text:
                technique_ids.update(tech_ids)

        # Add vulnerability-specific techniques
        if finding.cve_id:
            technique_ids.add("T1190")

        # Get technique objects
        techniques: list[MitreTechnique] = []
        for tech_id in technique_ids:
            if tech_id in self.TECHNIQUES:
                techniques.append(self.TECHNIQUES[tech_id])

        # Sort by tactic order (attack flow)
        tactic_order = list(MitreTactic)
        techniques.sort(key=lambda t: tactic_order.index(t.tactic))

        return techniques

    def _get_kill_chain_phases(
        self, techniques: list[MitreTechnique]
    ) -> list[KillChainPhase]:
        """Get kill chain phases from techniques."""
        phases: set[KillChainPhase] = set()

        for technique in techniques:
            if technique.tactic in self.TACTIC_TO_KILL_CHAIN:
                phases.update(self.TACTIC_TO_KILL_CHAIN[technique.tactic])

        # Sort by kill chain order
        phase_order = list(KillChainPhase)
        return sorted(phases, key=lambda p: phase_order.index(p))

    def _get_detection_recommendations(
        self, techniques: list[MitreTechnique]
    ) -> list[str]:
        """Get detection recommendations for techniques."""
        recommendations: list[str] = []
        seen: set[str] = set()

        for technique in techniques:
            if technique.id in self.DETECTION_RECOMMENDATIONS:
                for rec in self.DETECTION_RECOMMENDATIONS[technique.id]:
                    if rec not in seen:
                        recommendations.append(rec)
                        seen.add(rec)

        return recommendations

    def _get_mitigation_strategies(
        self, techniques: list[MitreTechnique]
    ) -> list[str]:
        """Get mitigation strategies for techniques."""
        strategies: list[str] = []
        seen: set[str] = set()

        for technique in techniques:
            if technique.id in self.MITIGATION_STRATEGIES:
                for strat in self.MITIGATION_STRATEGIES[technique.id]:
                    if strat not in seen:
                        strategies.append(strat)
                        seen.add(strat)

        return strategies

    def _calculate_confidence(
        self, finding: Finding, techniques: list[MitreTechnique]
    ) -> float:
        """Calculate confidence level of the mapping."""
        if not techniques:
            return 0.0

        base_confidence = 0.5

        # Higher confidence for more specific matches
        if finding.rule_id:
            base_confidence += 0.2

        # Higher confidence for vulnerability findings with CVE
        if finding.cve_id:
            base_confidence += 0.2

        # Higher confidence for higher severity
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            base_confidence += 0.1

        return min(1.0, base_confidence)

    def _get_tactic_distribution(
        self, mappings: list[AttackMapping]
    ) -> dict[str, int]:
        """Get distribution of tactics across mappings."""
        distribution: dict[str, int] = {}

        for mapping in mappings:
            for tactic in mapping.tactics:
                key = tactic.value
                distribution[key] = distribution.get(key, 0) + 1

        return distribution
