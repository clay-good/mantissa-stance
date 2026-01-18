# ASM Policy Files

This directory contains Attack Surface Management (ASM) policies for Mantissa Stance.
These policies evaluate externally-discovered assets to identify security risks,
misconfigurations, and compliance issues.

## Overview

ASM policies use the same YAML format as CSPM policies but target external assets
discovered through reconnaissance techniques like certificate transparency monitoring,
DNS enumeration, and port scanning.

## Policy Files

| File | Description |
|------|-------------|
| `certificates.yaml` | SSL/TLS certificate validation (expiration, algorithms, configuration) |
| `exposure.yaml` | Service exposure rules (dangerous ports, admin panels, sensitive services) |
| `dns.yaml` | DNS security policies (dangling records, subdomain takeover, missing SPF/DMARC) |
| `shadow_it.yaml` | Shadow IT detection (assets not in CSPM inventory) |

## Policy Format

Each policy file can contain multiple policies separated by `---`. Here's the structure:

```yaml
id: asm-example-001
name: Human-readable policy name
description: |
  Detailed description of what this policy checks and why it matters.
  Can span multiple lines.

enabled: true
severity: critical | high | medium | low | info

resource_type: external_asset

check:
  type: expression
  expression: |
    resource.field_name == "expected_value" and
    resource.nested.field > 10

remediation:
  guidance: |
    Step-by-step instructions to remediate this finding.
    1. First step
    2. Second step
    3. Verification step
  automation_supported: false

tags:
  - tag1
  - tag2
  - asm

references:
  - https://example.com/documentation
  - https://cwe.mitre.org/data/definitions/XXX.html

benchmarks:
  cis:
    - "1.2.3"
  nist:
    - "AC-3"
```

## Available Fields

When writing policy expressions, you can access these fields on external assets:

### Basic Asset Fields

| Field | Type | Description |
|-------|------|-------------|
| `resource.id` | string | Unique asset identifier |
| `resource.domain` | string | Domain or subdomain name |
| `resource.ip_address` | string | Resolved IP address |
| `resource.port` | int | Open port number |
| `resource.protocol` | string | Protocol (tcp, udp) |
| `resource.service` | string | Detected service name |
| `resource.cloud_provider` | string | Cloud provider (aws, gcp, azure) |
| `resource.cloud_region` | string | Cloud region identifier |
| `resource.risk_score` | float | Calculated risk score (0-10) |
| `resource.first_seen` | datetime | When first discovered |
| `resource.last_seen` | datetime | When last seen |
| `resource.technology_stack` | list | Detected technologies |

### Certificate Fields

Access via `resource.certificate_info`:

| Field | Type | Description |
|-------|------|-------------|
| `subject` | string | Certificate subject |
| `issuer` | string | Certificate issuer |
| `not_before` | datetime | Valid from date |
| `not_after` | datetime | Valid until date |
| `days_until_expiry` | int | Days until expiration |
| `is_expired` | bool | Whether certificate is expired |
| `is_expiring_soon` | bool | Whether expiring within 30 days |
| `is_self_signed` | bool | Whether self-signed |
| `san_domains` | list | Subject Alternative Names |
| `fingerprint_sha256` | string | Certificate fingerprint |
| `key_algorithm` | string | Key algorithm (RSA, ECDSA) |
| `key_size` | int | Key size in bits |

### Derived Fields

| Field | Type | Description |
|-------|------|-------------|
| `resource.has_certificate` | bool | Whether asset has TLS certificate |
| `resource.is_https` | bool | Whether using HTTPS |
| `resource.is_on_dangerous_port` | bool | Whether on a dangerous port |

## Expression Syntax

Policies use a simple expression language for checks:

### Comparison Operators

```yaml
# Equality
resource.port == 22
resource.cloud_provider == "aws"

# Inequality
resource.risk_score != 0

# Numeric comparisons
resource.risk_score > 7.0
resource.risk_score >= 5.0
resource.certificate_info.days_until_expiry < 30
resource.certificate_info.key_size <= 1024

# String operations
resource.domain contains "admin"
resource.domain starts_with "dev"
resource.domain ends_with ".internal.com"
resource.domain matches "^test-.*"
```

### Logical Operators

```yaml
# AND
resource.port == 22 and resource.cloud_provider == "aws"

# OR
resource.port == 3306 or resource.port == 5432

# NOT
not resource.has_certificate

# Grouping
(resource.port == 22 or resource.port == 3389) and resource.risk_score > 5
```

### Existence Checks

```yaml
# Check if field exists
resource.certificate_info exists

# Check if field is missing
resource.certificate_info not_exists

# Check list membership
resource.port in [22, 23, 3389, 5900]
resource.cloud_provider in ["aws", "gcp", "azure"]

# Check list contains value
resource.technology_stack contains "WordPress"
```

### Special Functions

```yaml
# Check age
resource.certificate_info.not_after within_days 30
resource.first_seen older_than_days 90

# Check IP ranges
resource.ip_address in_cidr "10.0.0.0/8"
resource.ip_address not_in_cidr "192.168.0.0/16"
```

## Example Policies

### Check for Exposed SSH

```yaml
id: asm-ssh-exposed
name: SSH service exposed to internet
description: SSH (port 22) is exposed to the internet.
enabled: true
severity: high
resource_type: external_asset

check:
  type: expression
  expression: resource.port != 22

remediation:
  guidance: |
    1. Place SSH behind a VPN
    2. Use bastion/jump host architecture
    3. Implement port knocking
    4. Use key-based authentication only
```

### Check for Weak Certificate

```yaml
id: asm-weak-cert
name: Certificate uses weak key size
description: Certificate key size is less than 2048 bits.
enabled: true
severity: high
resource_type: external_asset

check:
  type: expression
  expression: |
    resource.certificate_info not_exists or
    resource.certificate_info.key_size >= 2048

remediation:
  guidance: |
    Generate a new certificate with at least 2048-bit RSA
    or 256-bit ECDSA key.
```

### Check for Shadow IT

```yaml
id: asm-shadow-it
name: Asset not in internal inventory
description: External asset has no corresponding internal CSPM asset.
enabled: true
severity: high
resource_type: external_asset

check:
  type: correlation
  correlation:
    external_field: resource.domain
    internal_match: assets.public_dns_name
    require_match: true

remediation:
  guidance: |
    1. Determine if this asset belongs to your organization
    2. If legitimate, add to CSPM collection scope
    3. If unauthorized, investigate and decommission
```

## Severity Guidelines

| Severity | Criteria | Examples |
|----------|----------|----------|
| **Critical** | Immediate exploitation risk, data exposure | Expired cert, exposed database, RCE vulnerability |
| **High** | Significant security gap, likely target | Exposed SSH/RDP, weak encryption, missing auth |
| **Medium** | Security concern, indirect risk | Expiring cert, non-standard config, shadow IT |
| **Low** | Minor issue, best practice violation | Missing headers, outdated but patched software |
| **Info** | Informational, no immediate action | New asset detected, configuration change |

## Creating Custom Policies

1. Create a new YAML file in `policies/asm/` or add to existing file
2. Follow the format shown above
3. Test with: `stance asm scan --domains example.com --dry-run`
4. Validate expressions parse correctly
5. Review generated findings

### Tips

- Start with `enabled: false` while testing
- Use `info` severity initially, then adjust
- Include clear remediation steps
- Add relevant tags for filtering
- Reference standards (CIS, NIST) when applicable

## Disabling Policies

To disable a specific policy:

```yaml
# In your stance configuration
policies:
  disabled:
    - asm-cert-001
    - asm-exp-003
```

Or modify the policy file directly:

```yaml
enabled: false
```

## Policy Inheritance

ASM policies can reference CSPM policies for correlation:

```yaml
check:
  type: correlation
  requires:
    - cspm-s3-public  # Only fire if S3 bucket is public
```

## Benchmarks and Compliance

Map policies to compliance frameworks:

```yaml
benchmarks:
  cis_aws:
    - "1.4"    # Ensure access keys are rotated
  nist_800_53:
    - "AC-2"   # Account Management
    - "AC-3"   # Access Enforcement
  pci_dss:
    - "2.1"    # Change vendor defaults
  soc2:
    - "CC6.1"  # Logical and Physical Access
```

## Questions?

- See the main Stance documentation for policy engine details
- Check existing policies for examples
- Open an issue for policy suggestions
