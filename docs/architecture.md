# Architecture

## System Overview

Mantissa Stance is a Cloud Security Posture Management (CSPM) and Vulnerability Management platform designed to answer one question: "What is wrong with my cloud configuration right now?" The system collects configuration data from AWS services, evaluates it against security policies, stores findings, and provides multiple interfaces for querying and reporting.

### Main Components

- **CLI**: Command-line interface for all operations (scan, query, report, dashboard)
- **Collectors**: Read-only integrations with AWS services to gather configuration data
- **Storage Layer**: Persistence for assets, findings, and scan state (SQLite or S3/Athena)
- **Policy Engine**: YAML-based security rule evaluation with deterministic expression matching
- **Query Engine**: Natural language to SQL translation using LLM providers
- **Web Dashboard**: Local HTTP server providing visual posture summary

## Architecture Diagram

```
                                    MANTISSA STANCE ARCHITECTURE

    +-----------------------------------------------------------------------------------+
    |                                      CLI                                          |
    |   stance scan | stance query | stance report | stance findings | stance dashboard |
    +-----------------------------------------------------------------------------------+
                |                    |                    |                    |
                v                    v                    v                    v
    +-------------------+  +-------------------+  +-------------------+  +-------------+
    |    COLLECTORS     |  |   QUERY ENGINE    |  |  REPORT ENGINE    |  |  DASHBOARD  |
    |                   |  |                   |  |                   |  |             |
    | +---------------+ |  | +---------------+ |  | +---------------+ |  | +---------+ |
    | | IAM Collector | |  | | LLM Provider  | |  | | HTML Report   | |  | | HTTP    | |
    | +---------------+ |  | | - Anthropic   | |  | +---------------+ |  | | Server  | |
    | +---------------+ |  | | - OpenAI      | |  | +---------------+ |  | +---------+ |
    | | S3 Collector  | |  | | - Gemini      | |  | | JSON Report   | |  | +---------+ |
    | +---------------+ |  | +---------------+ |  | +---------------+ |  | | Static  | |
    | +---------------+ |  | +---------------+ |  | +---------------+ |  | | Assets  | |
    | | EC2 Collector | |  | | SQL Generator | |  | | CSV Report    | |  | +---------+ |
    | +---------------+ |  | +---------------+ |  | +---------------+ |  |             |
    | +---------------+ |  | +---------------+ |  |                   |  |             |
    | | Security      | |  | | SQL Validator | |  |                   |  |             |
    | | Collector     | |  | +---------------+ |  |                   |  |             |
    | +---------------+ |  |                   |  |                   |  |             |
    +-------------------+  +-------------------+  +-------------------+  +-------------+
                |                    |                    |                    |
                v                    v                    v                    v
    +-----------------------------------------------------------------------------------+
    |                              POLICY ENGINE                                        |
    |                                                                                   |
    |   +-------------------+  +-------------------+  +-------------------+             |
    |   | Policy Loader     |  | Expression        |  | Compliance        |             |
    |   | (YAML parsing)    |  | Evaluator         |  | Calculator        |             |
    |   +-------------------+  +-------------------+  +-------------------+             |
    +-----------------------------------------------------------------------------------+
                                         |
                                         v
    +-----------------------------------------------------------------------------------+
    |                              STORAGE LAYER                                        |
    |                                                                                   |
    |   +-------------------+              +----------------------------------------+   |
    |   | Local Storage     |              | Cloud Storage                          |   |
    |   | (SQLite)          |              |                                        |   |
    |   |                   |              | +----------------+  +----------------+ |   |
    |   | - Development     |              | | S3             |  | Athena         | |   |
    |   | - Single user     |              | | (Assets/       |  | (Queries)      | |   |
    |   | - Offline mode    |              | |  Findings)     |  |                | |   |
    |   +-------------------+              | +----------------+  +----------------+ |   |
    |                                      +----------------------------------------+   |
    +-----------------------------------------------------------------------------------+
                                         |
                                         v
    +-----------------------------------------------------------------------------------+
    |                              AWS SERVICES (READ-ONLY)                             |
    |                                                                                   |
    |   +----------+  +----------+  +----------+  +-------------+  +--------------+    |
    |   | IAM      |  | S3       |  | EC2      |  | SecurityHub |  | Inspector    |    |
    |   +----------+  +----------+  +----------+  +-------------+  +--------------+    |
    +-----------------------------------------------------------------------------------+
```

## Data Flow

### Scan Operation

1. **User initiates scan**: `stance scan --account-id 123456789012`
2. **Collectors query AWS APIs**: Each collector makes read-only API calls to gather configuration data
3. **Asset inventory created**: Discovered resources are normalized into Asset objects
4. **Assets stored**: Asset collection is persisted to the storage layer with a snapshot ID
5. **Policy engine evaluates**: Each enabled policy is evaluated against matching assets
6. **Findings generated**: Non-compliant resources produce Finding objects
7. **Findings stored**: Finding collection is persisted with the same snapshot ID
8. **Summary displayed**: Scan results are printed to the console

### Query Operation

1. **User submits question**: `stance query -q "show critical findings for S3"`
2. **LLM translates to SQL**: Natural language is converted to a SELECT query
3. **SQL validated**: Query is checked to ensure it is read-only (SELECT only)
4. **Query executed**: SQL runs against the storage layer
5. **Results formatted**: Output is displayed as table, JSON, or CSV

### Report Operation

1. **User requests report**: `stance report --format html --framework cis-aws`
2. **Findings loaded**: Latest findings retrieved from storage
3. **Compliance calculated**: Policy results mapped to framework controls
4. **Report generated**: Output rendered in requested format
5. **Report saved**: Written to file or stdout

## Component Details

### Collectors

Collectors are responsible for gathering configuration data from AWS services. All collectors:

- Inherit from `BaseCollector` abstract class
- Implement `collect()` method returning `AssetCollection`
- Use only read-only AWS API calls (Get*, List*, Describe*)
- Handle pagination automatically
- Normalize data into `Asset` objects

#### Available Collectors

| Collector | AWS Services | Resource Types |
|-----------|--------------|----------------|
| IAMCollector | IAM | Users, Roles, Policies, Groups, Password Policy |
| S3Collector | S3 | Buckets (with encryption, ACL, policy config) |
| EC2Collector | EC2 | Instances, Security Groups, VPCs, Subnets |
| SecurityCollector | SecurityHub, Inspector | Existing findings and vulnerabilities |

#### Collector Runner

The `CollectorRunner` orchestrates multiple collectors:

```python
runner = CollectorRunner([IAMCollector(), S3Collector(), EC2Collector()])
assets, results = runner.run_all()
```

### Storage Layer

The storage layer provides persistence for assets and findings with two backends:

#### Local Storage (SQLite)

- Default for development and single-user scenarios
- Database stored at `~/.stance/stance.db`
- No additional configuration required
- Full SQL query support

#### Cloud Storage (S3 + Athena)

- Production deployment option
- Assets and findings stored as JSON in S3
- Athena provides SQL query interface
- Partitioned by date and account for performance
- DynamoDB tracks scan state and checkpoints

#### Storage Interface

```python
class StorageBackend(ABC):
    def store_assets(self, assets: AssetCollection, snapshot_id: str) -> None
    def store_findings(self, findings: FindingCollection, snapshot_id: str) -> None
    def get_assets(self, snapshot_id: str | None = None) -> AssetCollection
    def get_findings(self, snapshot_id: str | None = None) -> FindingCollection
    def get_latest_snapshot_id(self) -> str | None
    def list_snapshots(self, limit: int = 10) -> list[str]
```

### Policy Engine

The policy engine evaluates YAML-based security policies against collected assets.

#### Policy Format

```yaml
id: aws-s3-001
name: S3 bucket encryption enabled
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.encryption.enabled == true"
compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "2.1.1"
remediation:
  guidance: Enable default encryption on the S3 bucket
```

#### Expression Evaluator

The expression evaluator supports:

- **Comparison operators**: `==`, `!=`, `>`, `<`, `>=`, `<=`
- **Membership operators**: `in`, `not_in`
- **String operators**: `contains`, `starts_with`, `ends_with`, `matches`
- **Existence operators**: `exists`, `not_exists`
- **Boolean operators**: `and`, `or`, `not`
- **Path access**: `resource.field.subfield`

The evaluator is implemented without `eval()` or `exec()` for security.

#### Compliance Calculator

Maps policy results to compliance framework controls and calculates scores:

- Control passes if no open findings exist for related policies
- Framework score = (passed controls / total controls) * 100
- Overall score = weighted average of framework scores

### Query Engine

The query engine translates natural language to SQL and executes queries.

#### LLM Provider Abstraction

```python
class LLMProvider(ABC):
    def generate(self, prompt: str, system_prompt: str | None = None) -> str
    @property
    def provider_name(self) -> str
    @property
    def model_name(self) -> str
```

Supported providers:
- **Anthropic**: Claude models via direct HTTP (no SDK)
- **OpenAI**: GPT models via direct HTTP (no SDK)
- **Google**: Gemini models via direct HTTP (no SDK)

#### SQL Validation

Generated SQL is validated before execution:

- Must start with SELECT
- Cannot contain INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE
- Cannot contain comment sequences (--, /*, */)
- Cannot contain multiple statements (;)

### Web Dashboard

The dashboard provides a local web UI for viewing posture summary.

#### Server

- Built on Python stdlib `http.server`
- Binds to localhost by default (127.0.0.1:8080)
- Serves static files and JSON API endpoints
- No external dependencies

#### API Endpoints

| Endpoint | Description |
|----------|-------------|
| GET /api/summary | Posture summary with finding counts |
| GET /api/assets | Paginated asset list with filters |
| GET /api/findings | Paginated findings with filters |
| GET /api/compliance | Compliance scores by framework |
| GET /api/snapshots | List of scan snapshots |

#### Design

- Monochrome color scheme (black, white, grays)
- Responsive layout (mobile to desktop)
- Single HTML file with embedded CSS and JavaScript
- No external dependencies or CDN links

## Security Model

### IAM Permissions

Stance requires only read permissions. See [deployment.md](deployment.md) for the complete IAM policy.

Required permission categories:
- `iam:Get*`, `iam:List*` - IAM configuration
- `s3:GetBucket*`, `s3:ListBucket` - S3 configuration
- `ec2:Describe*` - EC2 and network configuration
- `securityhub:GetFindings` - SecurityHub findings
- `inspector2:ListFindings` - Inspector vulnerabilities

### Security Principles

- **No write permissions**: Never modifies cloud resources
- **Secrets via environment**: API keys read from environment variables only
- **No eval/exec**: Expression evaluator uses safe parsing
- **SQL injection prevention**: Queries validated before execution
- **Local by default**: No external calls except AWS APIs and chosen LLM

## Deployment Options

### Local Development

```bash
pip install -e ".[dev]"
stance scan
```

### Serverless (AWS Lambda)

- Lambda functions for collection and evaluation
- EventBridge for scheduled scans
- S3 for storage, Athena for queries
- See `infrastructure/aws/terraform/` for IaC

### Container (Docker)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install .
ENTRYPOINT ["stance"]
```

## Extension Points

### Custom Collectors

Implement `BaseCollector` to add new data sources:

```python
class CustomCollector(BaseCollector):
    collector_name = "custom"
    resource_types = ["custom_resource"]

    def collect(self) -> AssetCollection:
        # Implementation
```

### Custom Policies

Add YAML files to `policies/` directory following the policy schema.

### Custom Output Formats

Extend report generation by implementing new formatters.

### LLM Provider Plugins

Implement `LLMProvider` to add new LLM backends:

```python
class CustomProvider(LLMProvider):
    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        # Implementation
```
