# stance.llm.sanitizer

Data sanitizer for Mantissa Stance.

Provides privacy protection by sanitizing sensitive data before
sending to LLM providers. This ensures no secrets, credentials,
or PII are leaked to external services.

## Contents

### Classes

- [SanitizationResult](#sanitizationresult)
- [DataSanitizer](#datasanitizer)

### Functions

- [create_sanitizer](#create_sanitizer)

## SanitizationResult

**Tags:** dataclass

Result of data sanitization.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `sanitized_text` | `str` | - |
| `redactions_made` | `int` | - |
| `redaction_types` | `list[str]` | - |
| `mapping` | `dict[(str, str)]` | `field(...)` |

## DataSanitizer

Sanitizes sensitive data before sending to LLM providers.

Detects and redacts:
- AWS access keys and secret keys
- API keys and tokens
- Passwords and credentials
- Email addresses
- IP addresses (optional)
- Account IDs (optional)
- ARNs (partial redaction)

### Methods

#### `__init__(self, redact_emails: bool = False, redact_ips: bool = False, redact_account_ids: bool = False, preserve_structure: bool = True)`

Initialize the data sanitizer.

**Parameters:**

- `redact_emails` (`bool`) - default: `False` - Whether to redact email addresses
- `redact_ips` (`bool`) - default: `False` - Whether to redact IP addresses
- `redact_account_ids` (`bool`) - default: `False` - Whether to redact AWS account IDs
- `preserve_structure` (`bool`) - default: `True` - Whether to use consistent replacement tokens

#### `sanitize(self, text: str) -> str`

Sanitize text by redacting sensitive data.

**Parameters:**

- `text` (`str`) - Text to sanitize

**Returns:**

`str` - Sanitized text with sensitive data redacted

#### `sanitize_with_details(self, text: str) -> SanitizationResult`

Sanitize text and return detailed results.

**Parameters:**

- `text` (`str`) - Text to sanitize

**Returns:**

`SanitizationResult` - SanitizationResult with sanitized text and metadata

#### `sanitize_dict(self, data: dict[(str, Any)]) -> dict[(str, Any)]`

Recursively sanitize a dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`) - Dictionary to sanitize

**Returns:**

`dict[(str, Any)]` - Sanitized dictionary copy

#### `desanitize(self, text: str, mapping: dict[(str, str)]) -> str`

Restore original values using a mapping.

**Parameters:**

- `text` (`str`) - Sanitized text
- `mapping` (`dict[(str, str)]`) - Original to token mapping

**Returns:**

`str` - Text with original values restored

#### `is_sensitive(self, text: str) -> bool`

Check if text contains sensitive data.

**Parameters:**

- `text` (`str`) - Text to check

**Returns:**

`bool` - True if sensitive data is detected

#### `get_sensitive_types(self, text: str) -> list[str]`

Get list of sensitive data types found in text.

**Parameters:**

- `text` (`str`) - Text to analyze

**Returns:**

`list[str]` - List of sensitive data type names

### `create_sanitizer(redact_emails: bool = False, redact_ips: bool = False, redact_account_ids: bool = False) -> DataSanitizer`

Create a DataSanitizer with specified configuration.

**Parameters:**

- `redact_emails` (`bool`) - default: `False` - Whether to redact email addresses
- `redact_ips` (`bool`) - default: `False` - Whether to redact IP addresses
- `redact_account_ids` (`bool`) - default: `False` - Whether to redact AWS account IDs

**Returns:**

`DataSanitizer` - Configured DataSanitizer instance
