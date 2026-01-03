# stance.llm.explainer

Finding explainer for Mantissa Stance.

Provides AI-powered explanations and remediation guidance for security findings.
Uses LLM providers to generate human-readable explanations tailored to the
specific finding context.

## Contents

### Classes

- [FindingExplanation](#findingexplanation)
- [FindingExplainer](#findingexplainer)

### Functions

- [create_explainer](#create_explainer)

## Constants

### `EXPLANATION_SYSTEM_PROMPT`

Type: `str`

Value: `You are a cloud security expert helping teams understand and remediate security findings.

Your explanations should be:
1. Clear and actionable - avoid jargon when possible
2. Risk-focused - explain WHY this matters, not just WHAT is wrong
3. Prioritized - help teams understand urgency
4. Practical - provide concrete remediation steps

Response format (follow exactly):
SUMMARY: [1-2 sentence summary of the finding]

RISK: [2-3 sentences explaining the security risk]

BUSINESS IMPACT: [1-2 sentences on business/compliance impact]

REMEDIATION STEPS:
1. [First step]
2. [Second step]
3. [Third step]
...

TECHNICAL DETAILS: [Technical explanation for engineers]

REFERENCES:
- [Reference URL or documentation link]
- [Another reference]
`

## FindingExplanation

**Tags:** dataclass

Result of finding explanation generation.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding_id` | `str` | - |
| `summary` | `str` | - |
| `risk_explanation` | `str` | - |
| `business_impact` | `str` | - |
| `remediation_steps` | `list[str]` | - |
| `technical_details` | `str` | - |
| `references` | `list[str]` | - |
| `is_valid` | `bool` | - |
| `error` | `str | None` | - |

## FindingExplainer

Generates AI-powered explanations for security findings.

Uses an LLM provider to create detailed, actionable explanations
that help security teams understand and remediate findings quickly.

### Methods

#### `__init__(self, llm_provider: LLMProvider, sanitizer: Any | None)`

Initialize the finding explainer.

**Parameters:**

- `llm_provider` (`LLMProvider`) - LLM provider for generating explanations
- `sanitizer` (`Any | None`) - Optional DataSanitizer for privacy protection

#### `explain_finding(self, finding: Finding, asset_context: dict[(str, Any)] | None, include_remediation: bool = True) -> FindingExplanation`

Generate a detailed explanation for a security finding.

**Parameters:**

- `finding` (`Finding`) - The finding to explain
- `asset_context` (`dict[(str, Any)] | None`) - Optional additional context about the affected asset
- `include_remediation` (`bool`) - default: `True` - Whether to include remediation steps

**Returns:**

`FindingExplanation` - FindingExplanation with detailed analysis

#### `explain_multiple(self, findings: list[Finding], max_findings: int = 10) -> list[FindingExplanation]`

Generate explanations for multiple findings.

**Parameters:**

- `findings` (`list[Finding]`) - List of findings to explain
- `max_findings` (`int`) - default: `10` - Maximum number of findings to process

**Returns:**

`list[FindingExplanation]` - List of FindingExplanation objects

#### `get_summary_for_severity(self, findings: list[Finding], severity: Severity) -> str`

Generate a summary of findings for a specific severity level.

**Parameters:**

- `findings` (`list[Finding]`) - List of findings to summarize
- `severity` (`Severity`) - Severity level to focus on

**Returns:**

`str` - Summary string

### `create_explainer(provider: str = anthropic, enable_sanitization: bool = True, **kwargs) -> FindingExplainer`

Create a FindingExplainer with specified configuration.

**Parameters:**

- `provider` (`str`) - default: `anthropic` - LLM provider name (anthropic, openai, gemini)
- `enable_sanitization` (`bool`) - default: `True` - Whether to enable data sanitization **kwargs: Additional provider configuration
- `**kwargs`

**Returns:**

`FindingExplainer` - Configured FindingExplainer instance
