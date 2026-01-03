# stance.llm.query_generator

Query generator for Mantissa Stance.

Generates SQL queries from natural language questions using LLM providers.

## Contents

### Classes

- [GeneratedQuery](#generatedquery)
- [QueryGenerator](#querygenerator)

## Constants

### `POSTURE_SCHEMA`

Type: `str`

Value: `
Available tables:

1. assets
   - id: Resource ARN/ID (string)
   - cloud_provider: aws|azure|gcp (string)
   - account_id: Cloud account (string)
   - region: Geographic region (string)
   - resource_type: aws_s3_bucket, aws_ec2_instance, etc. (string)
   - name: Resource name (string)
   - network_exposure: internet_facing|internal|isolated (string)
   - tags: Key-value pairs (JSON)
   - raw_config: Full configuration (JSON)

2. findings
   - id: Finding ID (string)
   - asset_id: FK to assets (string)
   - finding_type: misconfiguration|vulnerability (string)
   - severity: critical|high|medium|low|info (string)
   - status: open|resolved|suppressed|false_positive (string)
   - title: Finding title (string)
   - description: Finding description (string)
   - rule_id: Policy rule ID (string)
   - cve_id: CVE identifier for vulns (string)
   - cvss_score: CVSS score for vulns (float)
   - compliance_frameworks: Array of framework controls (JSON)
   - remediation_guidance: Fix guidance (string)

Common query patterns:
- Critical findings: WHERE severity = 'critical' AND status = 'open'
- Internet-facing: WHERE network_exposure = 'internet_facing'
- By resource type: WHERE resource_type = 'aws_s3_bucket'
- Join for context: SELECT f.*, a.name FROM findings f JOIN assets a ON f.asset_id = a.id
`

### `SYSTEM_PROMPT`

Type: `str`

Value: `You are a SQL query generator for a cloud security posture database.

Rules:
1. Generate only SELECT queries - never INSERT, UPDATE, DELETE, or DROP
2. Use standard SQL syntax compatible with SQLite
3. Return only the SQL query, no explanation or markdown
4. Use lowercase for SQL keywords (select, from, where, etc.)
5. Always include appropriate WHERE clauses based on the question
6. Use JOINs when relating findings to assets
7. Limit results when counting or listing (use LIMIT 100 unless specified)

Common mappings:
- "critical" findings -> severity = 'critical' AND status = 'open'
- "vulnerabilities" -> finding_type = 'vulnerability'
- "misconfigurations" -> finding_type = 'misconfiguration'
- "internet facing" / "public" -> network_exposure = 'internet_facing'
- "S3 buckets" -> resource_type = 'aws_s3_bucket'
- "EC2 instances" -> resource_type = 'aws_ec2_instance'
- "IAM users" -> resource_type = 'aws_iam_user'
`

## GeneratedQuery

**Tags:** dataclass

Result of query generation.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `question` | `str` | - |
| `sql` | `str` | - |
| `explanation` | `str` | - |
| `is_valid` | `bool` | - |
| `validation_errors` | `list[str]` | - |

## QueryGenerator

Generates SQL queries from natural language questions.

Uses an LLM provider to translate natural language into
SQL queries, then validates the generated SQL for safety.

### Methods

#### `__init__(self, llm_provider: LLMProvider, schema_context: str | None)`

Initialize the query generator.

**Parameters:**

- `llm_provider` (`LLMProvider`) - LLM provider for generation
- `schema_context` (`str | None`) - Optional custom schema context. Defaults to POSTURE_SCHEMA.

#### `generate_query(self, question: str, context: dict[(str, Any)] | None) -> GeneratedQuery`

Generate SQL query from natural language question.

**Parameters:**

- `question` (`str`) - Natural language question
- `context` (`dict[(str, Any)] | None`) - Optional additional context

**Returns:**

`GeneratedQuery` - GeneratedQuery with SQL and validation results

#### `validate_query(self, sql: str) -> list[str]`

Validate that generated SQL is safe to execute.

**Parameters:**

- `sql` (`str`) - SQL query to validate

**Returns:**

`list[str]` - List of validation errors (empty if safe)
