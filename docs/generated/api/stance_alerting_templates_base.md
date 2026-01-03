# stance.alerting.templates.base

Base alert templates for Mantissa Stance.

Provides abstract template interface and common template utilities.

## Contents

### Classes

- [TemplateContext](#templatecontext)
- [AlertTemplate](#alerttemplate)
- [DefaultTemplate](#defaulttemplate)
- [MisconfigurationTemplate](#misconfigurationtemplate)
- [VulnerabilityTemplate](#vulnerabilitytemplate)
- [ComplianceTemplate](#compliancetemplate)
- [CriticalExposureTemplate](#criticalexposuretemplate)

### Functions

- [get_template_for_finding](#get_template_for_finding)

## TemplateContext

**Tags:** dataclass

Context for template rendering.

Attributes:
    finding: The finding to render
    asset_name: Human-readable asset name
    account_name: Cloud account name
    environment: Environment tag (prod, staging, dev)
    custom_data: Additional custom data

### Attributes

| Name | Type | Default |
|------|------|---------|
| `finding` | `Finding` | - |
| `asset_name` | `str` | `` |
| `account_name` | `str` | `` |
| `environment` | `str` | `` |
| `custom_data` | `dict[(str, Any)] | None` | - |

## AlertTemplate

**Inherits from:** ABC

Abstract base class for alert templates.

Templates format findings for specific destinations or purposes.

### Methods

#### `format_title(self, context: TemplateContext) -> str`

**Decorators:** @abstractmethod

Format alert title.

**Parameters:**

- `context` (`TemplateContext`) - Template context

**Returns:**

`str` - Formatted title string

#### `format_body(self, context: TemplateContext) -> str`

**Decorators:** @abstractmethod

Format alert body.

**Parameters:**

- `context` (`TemplateContext`) - Template context

**Returns:**

`str` - Formatted body string

#### `format_severity(self, severity: Severity) -> str`

Format severity for display.

**Parameters:**

- `severity` (`Severity`) - Severity level

**Returns:**

`str` - Formatted severity string

#### `get_severity_indicator(self, severity: Severity) -> str`

Get severity indicator symbol.

**Parameters:**

- `severity` (`Severity`) - Severity level

**Returns:**

`str` - Indicator string

## DefaultTemplate

**Inherits from:** AlertTemplate

Default plain text alert template.

### Methods

#### `format_title(self, context: TemplateContext) -> str`

Format title with severity indicator.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

#### `format_body(self, context: TemplateContext) -> str`

Format body as plain text.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

## MisconfigurationTemplate

**Inherits from:** AlertTemplate

Template optimized for misconfiguration findings.

### Methods

#### `format_title(self, context: TemplateContext) -> str`

Format title emphasizing the misconfiguration.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

#### `format_body(self, context: TemplateContext) -> str`

Format body with misconfiguration details.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

## VulnerabilityTemplate

**Inherits from:** AlertTemplate

Template optimized for vulnerability findings.

### Methods

#### `format_title(self, context: TemplateContext) -> str`

Format title with CVE if available.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

#### `format_body(self, context: TemplateContext) -> str`

Format body with vulnerability details.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

## ComplianceTemplate

**Inherits from:** AlertTemplate

Template for compliance-focused alerts.

### Methods

#### `format_title(self, context: TemplateContext) -> str`

Format title with compliance focus.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

#### `format_body(self, context: TemplateContext) -> str`

Format body with compliance details.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

## CriticalExposureTemplate

**Inherits from:** AlertTemplate

Template for critical exposure alerts requiring immediate action.

### Methods

#### `format_title(self, context: TemplateContext) -> str`

Format title with urgency.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

#### `format_body(self, context: TemplateContext) -> str`

Format body with urgency and clear action items.

**Parameters:**

- `context` (`TemplateContext`)

**Returns:**

`str`

### `get_template_for_finding(finding: Finding) -> AlertTemplate`

Get appropriate template based on finding type and severity.

**Parameters:**

- `finding` (`Finding`) - Finding to get template for

**Returns:**

`AlertTemplate` - Appropriate AlertTemplate instance
