# Mantissa Stance

Mantissa Stance provides comprehensive cloud security visibility across AWS, GCP, and Azure. It combines CSPM (misconfiguration detection), DSPM (sensitive data discovery), CIEM (identity and entitlement management), and vulnerability management in a single, agentless tool.

## Why Mantissa Stance?

### The Problem with Enterprise Tools

- **Expensive**: $100K-500K+ per year
- **Black Box**: Cannot see or modify detection logic
- **Vendor Lock-in**: Proprietary formats make migration difficult
- **Complex**: Hundreds of features you don't need

### Our Approach

- **Open Source**: Full transparency into all detection logic
- **Read-Only by Design**: Never modifies your infrastructure
- **YAML Policies**: Version-controlled, customizable rules
- **Minimal Dependencies**: Core cloud SDKs only (boto3, google-cloud, azure-sdk)
- **Natural Language Queries**: Ask questions in plain English
- **Agentless**: No agents to deploy or maintain

### Key Capabilities

| Capability | Description |
|------------|-------------|
| **CSPM** | 300+ security policies across AWS, GCP, Azure |
| **DSPM** | Sensitive data classification and exposure detection |
| **CIEM** | IAM analysis, effective permissions, least privilege recommendations |
| **Vulnerability Management** | Container image scanning via Trivy integration |
| **IaC Scanning** | Terraform, CloudFormation, ARM template security checks |
| **Kubernetes Security** | EKS, GKE, AKS + native K8s configuration analysis |
| **Secrets Detection** | 28 secret patterns + entropy analysis |
| **Attack Path Analysis** | Identify exploitable paths through your environment |
| **CIS Benchmarks** | CIS AWS, GCP, and Azure benchmark scoring |

## Installation

### Prerequisites

- Python 3.11+
- Git
- Cloud credentials configured (AWS CLI, gcloud, az CLI)

### Install via Git Clone (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/clay-good/mantissa-stance.git
cd mantissa-stance

# Install in development mode with all dev dependencies
make install
# or manually:
pip install -e ".[dev]"
```

### Install via pip

```bash
# Basic installation (AWS support only)
pip install mantissa-stance

# With specific cloud provider support
pip install mantissa-stance[gcp]      # Add GCP support
pip install mantissa-stance[azure]    # Add Azure support
pip install mantissa-stance[all]      # All cloud providers
```

### Verify Installation

```bash
# Check that the CLI is available
stance --help
```

### Development Commands

After cloning, use the Makefile for common development tasks:

```bash
make install           # Install in dev mode with dependencies
make test              # Run all tests with coverage
make test-unit         # Unit tests only
make test-integration  # Integration tests only
make lint              # Run ruff linter
make format            # Format with black + ruff fix
make typecheck         # Type check with mypy
make clean             # Remove build artifacts
```

## Quick Start

### First Scan

```bash
# Scan AWS account
stance scan --provider aws --region us-east-1

# Scan GCP project
stance scan --provider gcp --project-id my-project

# Scan Azure subscription
stance scan --provider azure --subscription-id <subscription-id>

# View findings
stance findings --severity critical

# Natural language query (requires LLM API key - see AI Features section)
stance query -q "show me public S3 buckets with sensitive data"

# Generate CIS benchmark report
stance report --benchmark cis-aws --format html --output cis-report.html

# Start web dashboard
stance dashboard
```

## Features

### Cloud Asset Inventory

37 collectors across three cloud providers gather comprehensive asset data:

**AWS**: IAM, S3, EC2, RDS, Lambda, EKS, ECR, API Gateway, Secrets Manager, DynamoDB, ElastiCache, and more

**GCP**: IAM, Cloud Storage, Compute, Cloud SQL, GKE, Cloud Functions, Artifact Registry, Cloud Run, BigQuery, and more

**Azure**: IAM, Storage, Compute, SQL, AKS, Functions, Container Registry, Key Vault, Cosmos DB, and more

### Security Policies (300+)

Policies are defined in YAML and evaluate cloud configurations deterministically:

```yaml
id: aws-s3-001
name: S3 Bucket Encryption Required
description: Ensure all S3 buckets have server-side encryption enabled
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: resource.encryption.enabled == true
remediation:
  guidance: Enable default encryption on the S3 bucket
benchmark:
  - cis-aws: "2.1.1"
```

### Data Security Posture Management (DSPM)

- **Data Classification**: Automatically detect PII, PHI, PCI, credentials, and 15+ sensitive data types
- **Access Analysis**: Map who has access to sensitive data across cloud storage
- **Exposure Detection**: Find sensitive data in public buckets or overly permissive shares

### Identity and Access Management (CIEM)

- **Effective Permissions**: Calculate actual permissions from complex IAM policies
- **Overprivileged Detection**: Identify unused permissions and excessive access
- **Cross-Account Analysis**: Track trust relationships and assumed roles
- **Attack Paths**: Discover privilege escalation and lateral movement paths

### Container & Kubernetes Security

- **Image Scanning**: Vulnerability detection via Trivy integration
- **Registry Analysis**: ECR, GCR, ACR image inventory and findings
- **K8s Configuration**: Pod security, RBAC, network policies, secrets handling
- **Managed K8s**: EKS, GKE, AKS cluster configuration assessment

### Infrastructure as Code (IaC)

- **Terraform**: HCL parsing and security policy evaluation
- **CloudFormation**: JSON/YAML template scanning
- **ARM Templates**: Azure Resource Manager template analysis
- **Drift Detection**: Compare IaC definitions to actual cloud state

### Secrets Detection

28 built-in patterns detect exposed secrets:
- AWS Access Keys, GCP Service Account Keys, Azure Client Secrets
- Database connection strings, API tokens, private keys
- Entropy analysis for high-randomness strings

### Attack Path Analysis

Identify how an attacker could exploit your environment:
- **Privilege Escalation**: Paths to admin/root access
- **Lateral Movement**: Network and trust relationship abuse
- **Data Exfiltration**: Paths to sensitive data
- **Public Exposure**: Internet-accessible attack surfaces

### Analytics

- **Toxic Combinations**: Detect dangerous configuration patterns
- **Blast Radius**: Calculate impact if a resource is compromised
- **Risk Scoring**: Prioritize findings based on context
- **MITRE ATT&CK Mapping**: Map findings to attack techniques

### CIS Benchmarks

Built-in policy mappings for CIS security benchmarks:
- CIS AWS Foundations Benchmark v1.5
- CIS GCP Foundations Benchmark v1.3
- CIS Azure Foundations Benchmark v1.5

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Mantissa Stance                              │
├──────────────────────────────────────────────────────────────────────┤
│  Interface Layer                                                      │
│  ┌─────────────┐  ┌─────────────────────┐  ┌─────────────────────┐   │
│  │     CLI     │  │   Web Dashboard     │  │   Alerting          │   │
│  │  (stance)   │  │   (localhost:8080)  │  │   Slack/PD/Jira     │   │
│  └─────────────┘  └─────────────────────┘  └─────────────────────┘   │
├──────────────────────────────────────────────────────────────────────┤
│  Analysis Engines                                                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│  │    CSPM      │ │    DSPM      │ │    CIEM      │ │  Vuln Mgmt   │ │
│  │  300+ YAML   │ │  Classifier  │ │  Effective   │ │  Trivy       │ │
│  │  policies    │ │  Access maps │ │  permissions │ │  CVE lookup  │ │
│  │  CIS bench   │ │  Exposure    │ │  Overpriv    │ │  SBOM        │ │
│  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  Correlation & Analytics                                              │
│  ┌──────────────────────────────────────────────────────────────────┐│
│  │ Attack Paths │ Blast Radius │ Risk Scoring │ MITRE ATT&CK       ││
│  │ Trust Graph  │ Toxic Combos │ Cross-Account│ Priv Escalation    ││
│  └──────────────────────────────────────────────────────────────────┘│
├──────────────────────────────────────────────────────────────────────┤
│  Query Engine                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │  Natural Language → SQL (Claude/GPT-4/Gemini) │ Direct SQL     │ │
│  └─────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  Collectors (37 total)                                                │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐            │
│  │  AWS (12)     │  │  GCP (11)     │  │  Azure (11)   │            │
│  │  IAM, S3, EC2 │  │  IAM, GCS     │  │  IAM, Storage │            │
│  │  RDS, Lambda  │  │  Compute, SQL │  │  Compute, SQL │            │
│  │  EKS, ECR     │  │  GKE, GCR     │  │  AKS, ACR     │            │
│  └───────────────┘  └───────────────┘  └───────────────┘            │
├──────────────────────────────────────────────────────────────────────┤
│  Storage Layer                                                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐     │
│  │  SQLite    │  │ S3+Athena  │  │GCS+BigQuery│  │Blob+Synapse│     │
│  │  (local)   │  │  (AWS)     │  │   (GCP)    │  │  (Azure)   │     │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘     │
└──────────────────────────────────────────────────────────────────────┘
```

## AI vs Deterministic Logic

Mantissa Stance is built on a **deterministic core** with **optional AI features**. All security detection, policy evaluation, and risk scoring use transparent, reproducible logic with no machine learning. AI is only used to improve user experience for querying and content generation.

### Deterministic Components (No AI)

These components use pure algorithmic logic with no randomness or ML:

| Component | Implementation | Location |
|-----------|----------------|----------|
| **Asset Collection** | Cloud SDK API calls (boto3, google-cloud, azure-sdk) | `src/stance/collectors/` |
| **Policy Evaluation** | Custom expression evaluator against YAML rules | `src/stance/engine/evaluator.py` |
| **Expression Engine** | Safe expression parser (no `eval()`) with operators like `==`, `in`, `contains`, `matches` | `src/stance/engine/expressions.py` |
| **Finding Detection** | Pattern matching against 300+ YAML policies | `policies/` |
| **CIS Benchmark Scoring** | Calculated from policy evaluation results | `src/stance/engine/benchmark.py` |
| **Risk Scoring** | Weighted formulas, blast radius calculation | Algorithmic |
| **Attack Path Analysis** | Graph traversal algorithms | Algorithmic |
| **Secrets Detection** | 28 regex patterns + entropy analysis | Pattern matching |
| **CIEM** | Effective permissions calculation, trust graph analysis | `src/stance/ciem/` |
| **DSPM** | Data classification rules, exposure detection | `src/stance/dspm/` |
| **IaC Scanning** | Template parsing (Terraform, CloudFormation, ARM) | Deterministic |

### AI-Powered Features (Optional)

AI features are **completely optional** and use a BYOK (Bring Your Own Key) model. No API keys are required for core functionality.

| Feature | Purpose | Command |
|---------|---------|---------|
| **Natural Language Queries** | Translate English → SQL queries | `stance query -q "show me public buckets"` |
| **Finding Explanations** | AI-generated explanations of security findings | `stance llm explain-finding <id>` |
| **Policy Generation** | Generate YAML policies from natural language | `stance llm generate-policy "require encryption"` |
| **Policy Suggestions** | Suggest policies for resource types | `stance llm suggest-policies aws_s3_bucket` |

**Supported LLM Providers:**

| Provider | Environment Variable | Default Model |
|----------|---------------------|---------------|
| Anthropic Claude | `ANTHROPIC_API_KEY` | claude-3-haiku-20240307 |
| OpenAI GPT | `OPENAI_API_KEY` | gpt-4o-mini |
| Google Gemini | `GOOGLE_API_KEY` | gemini-1.5-flash |

**Implementation Details:**
- All LLM integrations use direct HTTP requests (no SDK dependencies)
- Code location: `src/stance/llm/`
- Data sanitization available to redact PII before sending to LLM

**To use AI features:**
```bash
# Set your API key (choose one provider)
export ANTHROPIC_API_KEY="sk-ant-..."   # or OPENAI_API_KEY or GOOGLE_API_KEY

# Natural language query
stance query -q "show me EC2 instances with public IPs and no security groups"

# Explain a finding
stance llm explain-finding finding-abc123

# Generate a custom policy
stance llm generate-policy "ensure all RDS instances have encryption enabled"
```

**To bypass AI entirely:**
- Use `--no-llm` flag to disable LLM features
- Write direct SQL queries instead of natural language
- All core security functionality works without any API keys

## CLI Reference

### Core Commands

| Command | Description |
|---------|-------------|
| `stance scan` | Run security assessment |
| `stance findings` | View and filter findings |
| `stance assets` | View discovered assets |
| `stance query` | Natural language or SQL queries |
| `stance report` | Generate CIS benchmark reports |
| `stance policies` | Manage security policies |
| `stance dashboard` | Start web dashboard (localhost:8080) |
| `stance drift` | Detect configuration drift |
| `stance iac scan` | Scan IaC templates (Terraform, CloudFormation, ARM) |
| `stance secrets scan` | Scan for exposed secrets |
| `stance ciem` | CIEM analysis (permissions, overprivileged, trust) |
| `stance dspm` | DSPM analysis (data classification, exposure) |
| `stance vuln scan` | Container vulnerability scanning |
| `stance alert` | Send findings to Slack, PagerDuty, Jira, Email |
| `stance notify` | Alias for alert command |

### AI-Powered Commands (Optional)

| Command | Description |
|---------|-------------|
| `stance llm generate-query` | Generate SQL from natural language |
| `stance llm explain-finding` | AI-powered finding explanations |
| `stance llm generate-policy` | Generate YAML policy from description |
| `stance llm suggest-policies` | Suggest policies for a resource type |
| `stance llm sanitize` | Redact PII from text before LLM processing |

## Configuration

### LLM Providers (Optional)

For natural language queries, configure one of:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."   # Claude (default)
export OPENAI_API_KEY="sk-..."          # GPT-4
export GOOGLE_API_KEY="..."             # Gemini
```

### Cloud Credentials

Stance uses standard cloud SDK credential chains:

- **AWS**: `~/.aws/credentials`, IAM roles, environment variables
- **GCP**: `gcloud auth`, service account JSON, environment variables
- **Azure**: `az login`, service principal, managed identity

### Minimal IAM Permissions

Stance requires read-only access. See [docs/deployment.md](docs/deployment.md) for minimal IAM policies.

## Web Dashboard

The local web dashboard provides visual exploration of findings:

```bash
stance dashboard --port 8080
```

Features:
- Posture score overview
- Findings by severity, service, CIS benchmark
- Asset inventory browser
- Attack path visualization
- CIS benchmark status

The dashboard binds to `127.0.0.1` only (no authentication) and is intended for local development use.

## Alerting & Integrations

Send findings to external systems:

```bash
# Slack
stance alert --destination slack --webhook-url https://hooks.slack.com/...

# PagerDuty
stance alert --destination pagerduty --routing-key ...

# Jira
stance alert --destination jira --project SEC --url https://company.atlassian.net

# Email
stance alert --destination email --smtp-host smtp.example.com --to security@example.com
```

## Design Principles

1. **Read-Only**: Never modifies cloud resources
2. **Agentless**: No agents to deploy or maintain
3. **Deterministic**: All detection logic is transparent and reproducible
4. **Minimal Dependencies**: Only core cloud SDKs
5. **Privacy-First**: No telemetry, no phone-home
6. **Local-First**: Works entirely offline after data collection

## Out of Scope

The following are intentionally not included:

- **Compliance Evidence Collection**: Use [Attestful](https://github.com/clay-good/attestful) for SOC 2, HIPAA, PCI-DSS, NIST 800-53, FedRAMP, ISO 27001
- **Audit Workflows**: Use Attestful or a GRC platform
- **Auto-Remediation**: Read-only by design
- **Runtime Protection**: Requires agents
- **SAST/DAST**: Separate product category
- **WAF**: Separate product category
- **ML-Based Anomaly Detection**: Complexity vs value tradeoff
- **Multi-Tenant SaaS**: Self-hosted focus

## Documentation

- [docs/architecture.md](docs/architecture.md) - System design
- [docs/policies.md](docs/policies.md) - Writing custom policies
- [docs/deployment.md](docs/deployment.md) - Production deployment
- [docs/benchmarks.md](docs/benchmarks.md) - CIS benchmark mappings


