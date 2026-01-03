# stance.analytics.mitre_attack

MITRE ATT&CK Mapping for Mantissa Stance.

Maps security findings to MITRE ATT&CK for Cloud tactics, techniques,
and procedures (TTPs), providing detection recommendations and
mitigation strategies.

## Contents

### Classes

- [MitreTactic](#mitretactic)
- [KillChainPhase](#killchainphase)
- [MitreTechnique](#mitretechnique)
- [AttackMapping](#attackmapping)
- [MitreAttackMapper](#mitreattackmapper)

## MitreTactic

**Inherits from:** Enum

MITRE ATT&CK Tactics relevant to cloud environments.

## KillChainPhase

**Inherits from:** Enum

Cyber Kill Chain phases for attack progression tracking.

## MitreTechnique

**Tags:** dataclass

Represents a MITRE ATT&CK technique.

Attributes:
    id: MITRE technique ID (e.g., T1078)
    name: Human-readable technique name
    tactic: Primary tactic this technique belongs to
    sub_techniques: List of sub-technique IDs
    description: Description of the technique
    cloud_platforms: Cloud platforms this technique applies to

### Attributes

| Name | Type | Default |
|------|------|---------|
| `id` | `str` | - |
| `name` | `str` | - |
| `tactic` | `MitreTactic` | - |
| `sub_techniques` | `list[str]` | `field(...)` |
| `description` | `str` | `` |
| `cloud_platforms` | `list[str]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> MitreTechnique`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`MitreTechnique`

## AttackMapping

**Tags:** dataclass

Mapping of a finding to MITRE ATT&CK framework.

Attributes:
    finding_id: ID of the mapped finding
    techniques: List of MITRE techniques this finding maps to
    kill_chain_phases: Kill chain phases this finding relates to
    detection_recommendations: How to detect exploitation
    mitigation_strategies: How to mitigate the risk
    confidence: Confidence level of the mapping (0.0-1.0)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `techniques` | `list[MitreTechnique]` | - |
| `kill_chain_phases` | `list[KillChainPhase]` | - |
| `detection_recommendations` | `list[str]` | - |
| `mitigation_strategies` | `list[str]` | - |
| `confidence` | `float` | `1.0` |

### Properties

#### `tactics(self) -> list[MitreTactic]`

Get unique tactics from all mapped techniques.

**Returns:**

`list[MitreTactic]`

#### `technique_ids(self) -> list[str]`

Get list of technique IDs.

**Returns:**

`list[str]`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## MitreAttackMapper

Maps security findings to MITRE ATT&CK framework.

Provides mapping of cloud security misconfigurations and vulnerabilities
to MITRE ATT&CK tactics, techniques, and procedures.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `TECHNIQUES` | `dict[(str, MitreTechnique)]` | `{'T1078': 'MitreTechnique(...)', 'T1190': 'MitreTechnique(...)', 'T1199': 'MitreTechnique(...)', 'T1098': 'MitreTechnique(...)', 'T1136': 'MitreTechnique(...)', 'T1525': 'MitreTechnique(...)', 'T1548': 'MitreTechnique(...)', 'T1484': 'MitreTechnique(...)', 'T1562': 'MitreTechnique(...)', 'T1578': 'MitreTechnique(...)', 'T1550': 'MitreTechnique(...)', 'T1528': 'MitreTechnique(...)', 'T1552': 'MitreTechnique(...)', 'T1606': 'MitreTechnique(...)', 'T1526': 'MitreTechnique(...)', 'T1580': 'MitreTechnique(...)', 'T1619': 'MitreTechnique(...)', 'T1021': 'MitreTechnique(...)', 'T1530': 'MitreTechnique(...)', 'T1537': 'MitreTechnique(...)', 'T1485': 'MitreTechnique(...)', 'T1486': 'MitreTechnique(...)', 'T1496': 'MitreTechnique(...)', 'T1531': 'MitreTechnique(...)'}` |
| `FINDING_PATTERNS` | `dict[(str, list[str])]` | `{'public': ['T1190', 'T1530', 'T1619'], 'publicly_accessible': ['T1190', 'T1530', 'T1619'], 'internet_facing': ['T1190'], 'open_to_internet': ['T1190'], 'iam': ['T1078', 'T1098', 'T1136'], 'overly_permissive': ['T1078', 'T1548'], 'admin': ['T1078', 'T1548'], 'privilege': ['T1548', 'T1078'], 'mfa': ['T1078', 'T1550'], 'no_mfa': ['T1078', 'T1550'], 'access_key': ['T1528', 'T1552'], 'credentials': ['T1552', 'T1528'], 'password': ['T1078', 'T1552'], 'cross_account': ['T1199', 'T1550'], 'trust': ['T1199'], 'encryption': ['T1530', 'T1486'], 'unencrypted': ['T1530', 'T1537'], 'not_encrypted': ['T1530', 'T1537'], 'logging': ['T1562'], 'cloudtrail': ['T1562'], 'monitoring': ['T1562'], 'audit': ['T1562'], 'flow_logs': ['T1562'], 'security_group': ['T1190', 'T1021'], 'network': ['T1021', 'T1190'], 'firewall': ['T1190', 'T1562'], 'ingress': ['T1190'], 'egress': ['T1537'], 's3': ['T1530', 'T1619', 'T1537'], 'bucket': ['T1530', 'T1619'], 'storage': ['T1530', 'T1619'], 'blob': ['T1530', 'T1619'], 'instance': ['T1578', 'T1496'], 'compute': ['T1578', 'T1496'], 'container': ['T1525', 'T1578'], 'lambda': ['T1578'], 'function': ['T1578'], 'database': ['T1530', 'T1485'], 'rds': ['T1530', 'T1485'], 'sql': ['T1530', 'T1485'], 'secret': ['T1552', 'T1528'], 'key_vault': ['T1552', 'T1528'], 'ssm': ['T1552'], 'versioning': ['T1485', 'T1486'], 'backup': ['T1485', 'T1486'], 'cve': ['T1190', 'T1203'], 'vulnerability': ['T1190'], 'exploit': ['T1190']}` |
| `TACTIC_TO_KILL_CHAIN` | `dict[(MitreTactic, list[KillChainPhase])]` | `{'"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'RECONNAISSANCE\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'RECONNAISSANCE\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'RESOURCE_DEVELOPMENT\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'WEAPONIZATION\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'INITIAL_ACCESS\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'DELIVERY\', ctx=Load())"', '"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'EXPLOITATION\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'EXECUTION\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'EXPLOITATION\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'PERSISTENCE\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'INSTALLATION\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'PRIVILEGE_ESCALATION\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'EXPLOITATION\', ctx=Load())"', '"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'INSTALLATION\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'DEFENSE_EVASION\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'INSTALLATION\', ctx=Load())"', '"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'COMMAND_AND_CONTROL\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'CREDENTIAL_ACCESS\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'EXPLOITATION\', ctx=Load())"', '"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'ACTIONS_ON_OBJECTIVES\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'DISCOVERY\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'RECONNAISSANCE\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'LATERAL_MOVEMENT\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'ACTIONS_ON_OBJECTIVES\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'COLLECTION\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'ACTIONS_ON_OBJECTIVES\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'EXFILTRATION\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'ACTIONS_ON_OBJECTIVES\', ctx=Load())"'], '"Attribute(value=Name(id=\'MitreTactic\', ctx=Load()), attr=\'IMPACT\', ctx=Load())"': ['"Attribute(value=Name(id=\'KillChainPhase\', ctx=Load()), attr=\'ACTIONS_ON_OBJECTIVES\', ctx=Load())"']}` |
| `DETECTION_RECOMMENDATIONS` | `dict[(str, list[str])]` | `{'T1078': ['Monitor for unusual login locations or times', 'Alert on multiple failed authentication attempts', 'Track API calls from new IP addresses', 'Enable CloudTrail or equivalent logging'], 'T1190': ['Monitor for unusual inbound connections', 'Enable web application firewall (WAF) logging', 'Track exploitation attempts in application logs', 'Alert on new ports exposed to internet'], 'T1098': ['Monitor for IAM policy changes', 'Alert on new role attachments', 'Track permission modifications', 'Enable IAM Access Analyzer'], 'T1136': ['Alert on new user or service account creation', 'Monitor for new access keys', 'Track identity provider changes'], 'T1548': ['Monitor for privilege escalation attempts', 'Track assume-role activities', 'Alert on policy changes granting elevated access'], 'T1562': ['Alert on logging configuration changes', 'Monitor for CloudTrail or audit log deletion', 'Track security tool modifications', 'Enable log integrity validation'], 'T1578': ['Monitor for new compute instances', 'Track snapshot and AMI creation', 'Alert on unusual instance modifications'], 'T1528': ['Monitor for token theft indicators', 'Track unusual API call patterns', 'Alert on token use from new locations'], 'T1552': ['Monitor for credential access in logs', 'Track secrets manager access', 'Alert on unusual parameter store queries'], 'T1530': ['Enable storage access logging', 'Monitor for bulk data downloads', 'Alert on access from unusual IPs', 'Track cross-account access'], 'T1537': ['Monitor for large data transfers', 'Track cross-account data movement', 'Enable VPC flow logs', 'Alert on unusual egress patterns'], 'T1485': ['Enable object versioning', 'Monitor for bulk deletion operations', 'Alert on backup deletion', 'Track destructive API calls'], 'T1486': ['Monitor for encryption key changes', 'Track unusual encryption operations', 'Alert on ransomware indicators'], 'T1496': ['Monitor for unusual CPU/GPU usage', 'Track new large instance launches', 'Alert on cryptocurrency mining indicators']}` |
| `MITIGATION_STRATEGIES` | `dict[(str, list[str])]` | `{'T1078': ['Enforce multi-factor authentication (MFA)', 'Implement least-privilege access', 'Use temporary credentials', 'Enable account lockout policies'], 'T1190': ['Keep systems patched and updated', 'Use Web Application Firewalls (WAF)', 'Implement network segmentation', 'Minimize public-facing attack surface'], 'T1098': ['Restrict IAM modification permissions', 'Implement approval workflows for policy changes', 'Enable IAM Access Analyzer'], 'T1136': ['Restrict account creation permissions', 'Require approval for new accounts', 'Monitor and alert on new accounts'], 'T1548': ['Implement least-privilege policies', 'Use permission boundaries', 'Regularly audit role permissions'], 'T1562': ['Enable CloudTrail or audit logging in all regions', 'Protect logging configurations with SCPs', 'Use immutable logging', 'Enable log validation'], 'T1578': ['Restrict compute modification permissions', 'Enable change approval workflows', 'Use infrastructure as code with reviews'], 'T1528': ['Use short-lived tokens', 'Implement token binding', 'Monitor for token abuse'], 'T1552': ['Use secrets management services', 'Encrypt credentials at rest', 'Rotate credentials regularly', 'Remove hardcoded credentials'], 'T1530': ['Enable encryption at rest', 'Implement bucket policies', 'Use VPC endpoints for storage access', 'Enable access logging'], 'T1537': ['Implement egress filtering', 'Use VPC endpoints', 'Enable data loss prevention (DLP)', 'Monitor and restrict cross-account access'], 'T1485': ['Enable versioning on storage', 'Implement backup retention policies', 'Use MFA delete protection', 'Enable cross-region replication'], 'T1486': ['Maintain offline backups', 'Enable versioning', 'Implement immutable storage', 'Test recovery procedures'], 'T1496': ['Implement resource quotas', 'Monitor for anomalous usage', 'Use cost alerts', 'Restrict compute provisioning']}` |

### Methods

#### `__init__(self) -> None`

Initialize the MITRE ATT&CK mapper.

**Returns:**

`None`

#### `map_finding(self, finding: Finding) -> AttackMapping`

Map a single finding to MITRE ATT&CK framework.

**Parameters:**

- `finding` (`Finding`) - The finding to map

**Returns:**

`AttackMapping` - AttackMapping with techniques, kill chain phases, and recommendations

#### `map_findings(self, findings: FindingCollection) -> list[AttackMapping]`

Map multiple findings to MITRE ATT&CK framework.

**Parameters:**

- `findings` (`FindingCollection`) - Collection of findings to map

**Returns:**

`list[AttackMapping]` - List of AttackMapping objects

#### `get_technique(self, technique_id: str) -> MitreTechnique | None`

Get a technique by ID.

**Parameters:**

- `technique_id` (`str`) - MITRE technique ID (e.g., T1078)

**Returns:**

`MitreTechnique | None` - MitreTechnique if found, None otherwise

#### `get_techniques_by_tactic(self, tactic: MitreTactic) -> list[MitreTechnique]`

Get all techniques for a given tactic.

**Parameters:**

- `tactic` (`MitreTactic`) - The MITRE tactic

**Returns:**

`list[MitreTechnique]` - List of techniques belonging to the tactic

#### `get_coverage_summary(self, mappings: list[AttackMapping]) -> dict[(str, Any)]`

Get a summary of ATT&CK coverage across mappings.

**Parameters:**

- `mappings` (`list[AttackMapping]`) - List of attack mappings

**Returns:**

`dict[(str, Any)]` - Summary including tactic and technique coverage
