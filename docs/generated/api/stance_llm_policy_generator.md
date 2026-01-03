# stance.llm.policy_generator

Policy generator for Mantissa Stance.

Generates security policies from natural language descriptions using LLM providers.
Creates valid YAML policy files that can be used by the policy engine.

## Contents

### Classes

- [GeneratedPolicy](#generatedpolicy)
- [PolicyGenerator](#policygenerator)

### Functions

- [create_policy_generator](#create_policy_generator)
- [save_policy](#save_policy)

## Constants

### `RESOURCE_TYPES`

Type: `dict`

Value: `{'aws': ['aws_iam_user', 'aws_iam_role', 'aws_iam_policy', 'aws_iam_group', 'aws_iam_account_password_policy', 'aws_iam_account_summary', 'aws_s3_bucket', 'aws_ec2_instance', 'aws_security_group', 'aws_vpc', 'aws_subnet', 'aws_rds_instance', 'aws_lambda_function', 'aws_dynamodb_table', 'aws_kms_key', 'aws_cloudtrail_trail', 'aws_sns_topic', 'aws_sqs_queue'], 'gcp': ['gcp_iam_service_account', 'gcp_iam_policy', 'gcp_storage_bucket', 'gcp_compute_instance', 'gcp_compute_firewall', 'gcp_compute_network', 'gcp_cloudsql_instance', 'gcp_cloud_function', 'gcp_pubsub_topic', 'gcp_kms_key'], 'azure': ['azure_user', 'azure_service_principal', 'azure_role_assignment', 'azure_storage_account', 'azure_storage_container', 'azure_vm', 'azure_network_security_group', 'azure_virtual_network', 'azure_sql_database', 'azure_function_app', 'azure_key_vault']}`

### `COMPLIANCE_FRAMEWORKS`

Type: `dict`

Value: `{'cis-aws-foundations': 'CIS Amazon Web Services Foundations Benchmark', 'cis-gcp-foundations': 'CIS Google Cloud Platform Foundations Benchmark', 'cis-azure-foundations': 'CIS Microsoft Azure Foundations Benchmark', 'pci-dss': 'Payment Card Industry Data Security Standard', 'soc2': 'SOC 2 Type II', 'hipaa': 'Health Insurance Portability and Accountability Act', 'nist-800-53': 'NIST Special Publication 800-53', 'aws-foundational-security': 'AWS Foundational Security Best Practices', 'iso-27001': 'ISO/IEC 27001 Information Security'}`

### `POLICY_SYSTEM_PROMPT`

Type: `str`

Value: `You are a cloud security policy expert for Mantissa Stance CSPM.

Generate YAML policies following this exact format:

id: {cloud}-{service}-{number}
name: Short descriptive name
description: |
  Detailed description of what this policy checks and why it matters.
  Include the security rationale.

enabled: true
severity: critical|high|medium|low|info

resource_type: {exact_resource_type}

check:
  type: expression
  expression: "{path.to.field} == expected_value"

compliance:
  - framework: {framework_id}
    version: "{version}"
    control: "{control_id}"

remediation:
  guidance: |
    Step-by-step instructions to fix this issue:
    1. First step
    2. Second step
    3. Third step
  automation_supported: false

tags:
  - relevant
  - tags
  - here

references:
  - https://documentation.url

RULES:
1. Use ONLY expression checks (not SQL)
2. Expression syntax: path.to.field == value, path.to.field != value,
   path.to.field > value, path.to.field >= value, path.to.field < value,
   path.to.field <= value, value in path.to.array, path.to.field exists
3. For boolean checks: use == true or == false
4. For string checks: use == 'string_value'
5. For numeric checks: use == number or >= number etc.
6. Use lowercase for severity values
7. Always set automation_supported: false
8. Generate unique ID based on cloud provider and service
9. Return ONLY the YAML content, no markdown code blocks or explanations
`

## GeneratedPolicy

**Tags:** dataclass

Result of policy generation.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `description` | `str` | - |
| `policy_id` | `str` | - |
| `policy_name` | `str` | - |
| `yaml_content` | `str` | - |
| `resource_type` | `str` | - |
| `severity` | `str` | - |
| `is_valid` | `bool` | - |
| `validation_errors` | `list[str]` | `field(...)` |
| `error` | `str | None` | - |

## PolicyGenerator

Generates security policies from natural language descriptions.

Uses an LLM provider to translate natural language requirements
into valid YAML policy files.

### Methods

#### `__init__(self, llm_provider: LLMProvider, cloud_provider: str = aws)`

Initialize the policy generator.

**Parameters:**

- `llm_provider` (`LLMProvider`) - LLM provider for generation
- `cloud_provider` (`str`) - default: `aws` - Default cloud provider (aws, gcp, azure)

#### `generate_policy(self, description: str, severity: str | None, resource_type: str | None, compliance_framework: str | None) -> GeneratedPolicy`

Generate a security policy from natural language description.

**Parameters:**

- `description` (`str`) - Natural language description of the policy
- `severity` (`str | None`) - Optional severity hint (critical, high, medium, low, info)
- `resource_type` (`str | None`) - Optional specific resource type
- `compliance_framework` (`str | None`) - Optional compliance framework to reference

**Returns:**

`GeneratedPolicy` - GeneratedPolicy with YAML content and validation results

#### `generate_multiple(self, descriptions: list[str], cloud_provider: str | None) -> list[GeneratedPolicy]`

Generate multiple policies from a list of descriptions.

**Parameters:**

- `descriptions` (`list[str]`) - List of natural language descriptions
- `cloud_provider` (`str | None`) - Optional cloud provider override

**Returns:**

`list[GeneratedPolicy]` - List of GeneratedPolicy objects

#### `suggest_policy_ideas(self, resource_type: str, count: int = 5) -> list[str]`

Suggest policy ideas for a given resource type.

**Parameters:**

- `resource_type` (`str`) - Cloud resource type
- `count` (`int`) - default: `5` - Number of suggestions to generate

**Returns:**

`list[str]` - List of policy description suggestions

### `create_policy_generator(provider: str = anthropic, cloud_provider: str = aws, **kwargs) -> PolicyGenerator`

Create a PolicyGenerator with specified configuration.

**Parameters:**

- `provider` (`str`) - default: `anthropic` - LLM provider name (anthropic, openai, gemini)
- `cloud_provider` (`str`) - default: `aws` - Cloud provider (aws, gcp, azure) **kwargs: Additional provider configuration
- `**kwargs`

**Returns:**

`PolicyGenerator` - Configured PolicyGenerator instance

### `save_policy(policy: GeneratedPolicy, output_path: str) -> bool`

Save a generated policy to a YAML file.

**Parameters:**

- `policy` (`GeneratedPolicy`) - Generated policy to save
- `output_path` (`str`) - Path to save the file

**Returns:**

`bool` - True if saved successfully, False otherwise
