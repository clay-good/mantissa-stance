# stance.detection.secrets

Secrets detector for Mantissa Stance.

Provides deterministic secrets detection in cloud configurations using:
- Pattern-based detection (regex for known secret formats)
- Entropy analysis (for high-entropy strings)
- Context analysis (field names suggesting secrets)

This module generates findings for detected secrets in cloud assets.

## Contents

### Classes

- [SecretMatch](#secretmatch)
- [SecretsResult](#secretsresult)
- [SecretsDetector](#secretsdetector)

### Functions

- [create_secrets_detector](#create_secrets_detector)
- [scan_assets_for_secrets](#scan_assets_for_secrets)

## Constants

### `SECRET_PATTERNS`

Type: `dict`

Value: `{'aws_access_key_id': {'pattern': '(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'AWS Access Key ID'}, 'aws_secret_access_key': {'pattern': '(?<![A-Za-z0-9/+])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'AWS Secret Access Key', 'entropy_threshold': 4.5}, 'aws_session_token': {'pattern': '(?i)aws[_-]?session[_-]?token\\s*[=:]\\s*[\'\\"]?([A-Za-z0-9/+=]{100,})[\'\\"]?', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'AWS Session Token'}, 'gcp_api_key': {'pattern': 'AIza[0-9A-Za-z_-]{35}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'GCP API Key'}, 'gcp_service_account_key': {'pattern': '"type"\\s*:\\s*"service_account"', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'GCP Service Account Key (JSON)'}, 'gcp_private_key': {'pattern': '-----BEGIN (RSA )?PRIVATE KEY-----', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'Private Key'}, 'azure_storage_key': {'pattern': '(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9/+=]{88})', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'Azure Storage Account Key'}, 'azure_connection_string': {'pattern': '(?i)(Server|Data Source)=[^;]+;.*Password=([^;]+)', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Azure Connection String with Password'}, 'azure_sas_token': {'pattern': 'sv=\\d{4}-\\d{2}-\\d{2}&s[a-z]=[^&]+&sig=[A-Za-z0-9%/+=]+', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Azure SAS Token'}, 'generic_api_key': {'pattern': '(?i)(api[_-]?key|apikey|api[_-]?token)\\s*[=:]\\s*[\'\\"]?([A-Za-z0-9_-]{20,})[\'\\"]?', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Generic API Key'}, 'generic_secret': {'pattern': '(?i)(secret|password|passwd|pwd|token|auth[_-]?key)\\s*[=:]\\s*[\'\\"]?([^\\s\'\\"]{8,})[\'\\"]?', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Generic Secret/Password'}, 'bearer_token': {'pattern': '(?i)bearer\\s+([A-Za-z0-9_-]{20,})', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Bearer Token'}, 'jwt_token': {'pattern': 'eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'MEDIUM\', ctx=Load())"', 'description': 'JWT Token'}, 'basic_auth': {'pattern': '(?i)basic\\s+([A-Za-z0-9+/]+=*)', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Basic Authentication Header'}, 'private_key': {'pattern': '-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\\s\\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'Private Key'}, 'ssh_private_key': {'pattern': '-----BEGIN OPENSSH PRIVATE KEY-----[\\s\\S]*?-----END OPENSSH PRIVATE KEY-----', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'SSH Private Key'}, 'mysql_connection': {'pattern': 'mysql://[^:]+:([^@]+)@', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'MySQL Connection String with Password'}, 'postgres_connection': {'pattern': 'postgres(?:ql)?://[^:]+:([^@]+)@', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'PostgreSQL Connection String with Password'}, 'mongodb_connection': {'pattern': 'mongodb(?:\\+srv)?://[^:]+:([^@]+)@', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'MongoDB Connection String with Password'}, 'redis_connection': {'pattern': 'redis://:[^@]+@', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Redis Connection String with Password'}, 'github_token': {'pattern': 'gh[pousr]_[A-Za-z0-9]{36,}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'GitHub Token'}, 'gitlab_token': {'pattern': 'glpat-[A-Za-z0-9_-]{20,}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'GitLab Personal Access Token'}, 'npm_token': {'pattern': 'npm_[A-Za-z0-9]{36}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'NPM Token'}, 'slack_token': {'pattern': 'xox[baprs]-[A-Za-z0-9-]{10,}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'MEDIUM\', ctx=Load())"', 'description': 'Slack Token'}, 'slack_webhook': {'pattern': 'https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'MEDIUM\', ctx=Load())"', 'description': 'Slack Webhook URL'}, 'sendgrid_api_key': {'pattern': 'SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'SendGrid API Key'}, 'twilio_api_key': {'pattern': 'SK[a-f0-9]{32}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'HIGH\', ctx=Load())"', 'description': 'Twilio API Key'}, 'stripe_api_key': {'pattern': '(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}', 'severity': '"Attribute(value=Name(id=\'Severity\', ctx=Load()), attr=\'CRITICAL\', ctx=Load())"', 'description': 'Stripe API Key'}}`

### `SENSITIVE_FIELD_NAMES`

Type: `list`

Value: `['password', 'passwd', 'pwd', 'pass', 'secret', 'api_key', 'apikey', 'api-key', 'token', 'auth_token', 'access_token', 'refresh_token', 'private_key', 'privatekey', 'private-key', 'credentials', 'creds', 'credential', 'connection_string', 'connectionstring', 'connection-string', 'database_url', 'db_password', 'db_pass', 'aws_secret', 'azure_key', 'gcp_key', 'encryption_key', 'master_key', 'signing_key']`

## SecretMatch

**Tags:** dataclass

A detected secret match.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `secret_type` | `str` | - |
| `field_path` | `str` | - |
| `matched_value` | `str` | - |
| `confidence` | `str` | - |
| `entropy` | `float | None` | - |
| `line_number` | `int | None` | - |

## SecretsResult

**Tags:** dataclass

Result of secrets detection on an asset.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset_id` | `str` | - |
| `secrets_found` | `int` | - |
| `matches` | `list[SecretMatch]` | `field(...)` |
| `scan_duration_seconds` | `float` | `0.0` |

## SecretsDetector

Detects secrets in cloud configurations.

Uses a combination of:
- Pattern matching (regex)
- Entropy analysis
- Context analysis (field names)

This is a deterministic detector (no LLM required).

### Methods

#### `__init__(self, patterns: dict[(str, dict)] | None, min_entropy: float = 3.5, scan_environment_vars: bool = True, scan_tags: bool = True, scan_raw_config: bool = True)`

Initialize the secrets detector.

**Parameters:**

- `patterns` (`dict[(str, dict)] | None`) - Custom patterns to use (defaults to SECRET_PATTERNS)
- `min_entropy` (`float`) - default: `3.5` - Minimum entropy for high-entropy detection
- `scan_environment_vars` (`bool`) - default: `True` - Whether to scan environment variables
- `scan_tags` (`bool`) - default: `True` - Whether to scan resource tags
- `scan_raw_config` (`bool`) - default: `True` - Whether to scan raw configuration

#### `detect_in_asset(self, asset: Asset) -> SecretsResult`

Detect secrets in an asset's configuration.

**Parameters:**

- `asset` (`Asset`) - Asset to scan

**Returns:**

`SecretsResult` - SecretsResult with detected secrets

#### `detect_in_text(self, text: str, source: str = text) -> list[SecretMatch]`

Detect secrets in a text string.

**Parameters:**

- `text` (`str`) - Text to scan
- `source` (`str`) - default: `text` - Source identifier for the text

**Returns:**

`list[SecretMatch]` - List of SecretMatch objects

#### `detect_in_dict(self, data: dict[(str, Any)], source: str = config) -> list[SecretMatch]`

Detect secrets in a dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`) - Dictionary to scan
- `source` (`str`) - default: `config` - Source identifier

**Returns:**

`list[SecretMatch]` - List of SecretMatch objects

#### `generate_findings(self, asset: Asset, result: SecretsResult) -> list[Finding]`

Generate findings from secrets detection results.

**Parameters:**

- `asset` (`Asset`) - Asset that was scanned
- `result` (`SecretsResult`) - Secrets detection result

**Returns:**

`list[Finding]` - List of Finding objects

### `create_secrets_detector(min_entropy: float = 3.5, scan_environment_vars: bool = True, scan_tags: bool = True, scan_raw_config: bool = True) -> SecretsDetector`

Create a SecretsDetector with specified configuration.

**Parameters:**

- `min_entropy` (`float`) - default: `3.5` - Minimum entropy for high-entropy detection
- `scan_environment_vars` (`bool`) - default: `True` - Whether to scan environment variables
- `scan_tags` (`bool`) - default: `True` - Whether to scan resource tags
- `scan_raw_config` (`bool`) - default: `True` - Whether to scan raw configuration

**Returns:**

`SecretsDetector` - Configured SecretsDetector instance

### `scan_assets_for_secrets(assets: list[Asset], detector: SecretsDetector | None) -> tuple[(list[SecretsResult], list[Finding])]`

Scan multiple assets for secrets.

**Parameters:**

- `assets` (`list[Asset]`) - List of assets to scan
- `detector` (`SecretsDetector | None`) - Optional SecretsDetector instance

**Returns:**

`tuple[(list[SecretsResult], list[Finding])]` - Tuple of (results, findings)
