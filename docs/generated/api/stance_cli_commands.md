# stance.cli_commands

CLI command handlers for Mantissa Stance.

Implements each CLI subcommand with proper error handling
and output formatting.

## Contents

### Functions

- [cmd_scan](#cmd_scan)
- [cmd_query](#cmd_query)
- [cmd_report](#cmd_report)
- [cmd_policies](#cmd_policies)
- [cmd_policies_list](#cmd_policies_list)
- [cmd_policies_validate](#cmd_policies_validate)
- [cmd_policies_generate](#cmd_policies_generate)
- [cmd_policies_suggest](#cmd_policies_suggest)
- [cmd_findings](#cmd_findings)
- [cmd_findings_list](#cmd_findings_list)
- [cmd_findings_explain](#cmd_findings_explain)
- [cmd_assets](#cmd_assets)
- [cmd_dashboard](#cmd_dashboard)
- [format_output](#format_output)
- [format_table](#format_table)
- [format_compliance_html](#format_compliance_html)
- [cmd_notify](#cmd_notify)
- [format_compliance_csv](#format_compliance_csv)
- [cmd_image_scan](#cmd_image_scan)
- [cmd_iac_scan](#cmd_iac_scan)
- [cmd_secrets_scan](#cmd_secrets_scan)
- [cmd_docs_generate](#cmd_docs_generate)

### `cmd_scan(args: argparse.Namespace) -> int`

Execute posture scan.  Steps: 1. Initialize storage backend 2. Create boto3 session 3. Run collectors 4. Store assets 5. Load and evaluate policies 6. Run secrets detection (if enabled) 7. Store findings 8. Print summary

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code (0 success, 1 error)

### `cmd_query(args: argparse.Namespace) -> int`

Execute natural language or SQL query.  Steps: 1. Get LLM provider (if not --no-llm) 2. Generate SQL from question 3. Validate query 4. Execute against storage 5. Format and print results

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_report(args: argparse.Namespace) -> int`

Generate compliance report.  Steps: 1. Load latest findings and assets 2. Load policies 3. Calculate compliance scores 4. Generate report in requested format 5. Write to file or stdout

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_policies(args: argparse.Namespace) -> int`

Manage policies: list, validate, generate, or get suggestions.  Routes to appropriate handler based on subcommand: - list: List policies with optional filters - validate: Validate policy files - generate: Generate policy from natural language (AI) - suggest: Get policy suggestions for a resource type (AI)

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_policies_list(args: argparse.Namespace) -> int`

List policies with optional filters.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_policies_validate(args: argparse.Namespace) -> int`

Validate policy files.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_policies_generate(args: argparse.Namespace) -> int`

Generate a security policy from natural language description using AI.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_policies_suggest(args: argparse.Namespace) -> int`

Get AI-powered policy suggestions for a resource type.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_findings(args: argparse.Namespace) -> int`

View findings with filters or get AI-powered explanations.  Routes to appropriate handler based on subcommand: - list: View findings with filters (default) - explain: Get AI-powered explanation for a finding

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_findings_list(args: argparse.Namespace) -> int`

List findings with filters.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_findings_explain(args: argparse.Namespace) -> int`

Get AI-powered explanation for a security finding.  Uses LLM to generate detailed, actionable explanations including: - Risk analysis - Business impact assessment - Step-by-step remediation guidance - Technical details

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_assets(args: argparse.Namespace) -> int`

View discovered assets.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `cmd_dashboard(args: argparse.Namespace) -> int`

Start web dashboard.

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `format_output(data: list[dict[(str, Any)]], format_type: str) -> str`

Format data for output.

**Parameters:**

- `data` (`list[dict[(str, Any)]]`) - List of dictionaries to format
- `format_type` (`str`) - Output format (table, json, csv)

**Returns:**

`str` - Formatted string

### `format_table(data: list[dict[(str, Any)]]) -> str`

Format data as ASCII table.

**Parameters:**

- `data` (`list[dict[(str, Any)]]`) - List of dictionaries

**Returns:**

`str` - Formatted table string

### `format_compliance_html(report: Any) -> str`

Format compliance report as HTML.

**Parameters:**

- `report` (`Any`) - ComplianceReport object

**Returns:**

`str` - HTML string

### `cmd_notify(args: argparse.Namespace) -> int`

Send notifications for findings.  Supports sending to various destinations: - Slack (webhook) - PagerDuty (events API) - Email (SMTP) - Microsoft Teams (webhook) - Jira (REST API) - Generic webhook

**Parameters:**

- `args` (`argparse.Namespace`)

**Returns:**

`int` - Exit code

### `format_compliance_csv(report: Any) -> str`

Format compliance report as CSV.

**Parameters:**

- `report` (`Any`) - ComplianceReport object

**Returns:**

`str` - CSV string

### `cmd_image_scan(args: argparse.Namespace) -> int`

Execute container image vulnerability scanning.

**Parameters:**

- `args` (`argparse.Namespace`) - Command line arguments

**Returns:**

`int` - Exit code (0 for success, 1 for vulnerabilities found matching fail-on)

### `cmd_iac_scan(args: argparse.Namespace) -> int`

Execute Infrastructure as Code scanning.  Scans Terraform, CloudFormation, and ARM templates for security issues.

**Parameters:**

- `args` (`argparse.Namespace`) - Command line arguments

**Returns:**

`int` - Exit code (0 for success, 1 for issues found matching fail-on)

### `cmd_secrets_scan(args: argparse.Namespace) -> int`

Execute secrets detection scanning.  Scans files and configurations for hardcoded secrets, API keys, passwords, and other sensitive data.

**Parameters:**

- `args` (`argparse.Namespace`) - Command line arguments

**Returns:**

`int` - Exit code (0 for success, 1 if secrets found and --fail-on-secrets)

### `cmd_docs_generate(args: argparse.Namespace) -> int`

Generate API and CLI documentation.  Generates documentation from source code docstrings and CLI parser.

**Parameters:**

- `args` (`argparse.Namespace`) - Parsed command line arguments

**Returns:**

`int` - Exit code (0 success, 1 error)
