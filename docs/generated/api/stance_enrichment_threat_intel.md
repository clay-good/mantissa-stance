# stance.enrichment.threat_intel

Threat intelligence enrichment for Mantissa Stance.

Provides threat intelligence enrichment including known malicious IPs,
vulnerable software identification, and CVE severity enrichment.

## Contents

### Classes

- [ThreatIndicator](#threatindicator)
- [CVEEnricher](#cveenricher)
- [VulnerableSoftwareEnricher](#vulnerablesoftwareenricher)
- [ThreatIntelEnricher](#threatintelenricher)
- [KEVEnricher](#kevenricher)

## Constants

### `KNOWN_VULNERABLE_SOFTWARE`

Type: `dict`

Value: `{'log4j': {'pattern': 'log4j.*2\\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)(\\..*)?$', 'cves': ['CVE-2021-44228', 'CVE-2021-45046', 'CVE-2021-45105'], 'severity': 'critical', 'description': 'Apache Log4j Remote Code Execution vulnerability'}, 'spring4shell': {'pattern': 'spring-.*5\\.(3\\.[0-9]|3\\.1[0-7])$', 'cves': ['CVE-2022-22965'], 'severity': 'critical', 'description': 'Spring Framework RCE vulnerability'}, 'openssl_heartbleed': {'pattern': 'openssl.*1\\.0\\.1[a-f]$', 'cves': ['CVE-2014-0160'], 'severity': 'high', 'description': 'OpenSSL Heartbleed vulnerability'}, 'struts2_rce': {'pattern': 'struts2?-core-2\\.(3\\.(5|[6-9]|[12][0-9]|3[01])|5\\.[0-9]|5\\.1[0-2])\\.jar$', 'cves': ['CVE-2017-5638', 'CVE-2018-11776'], 'severity': 'critical', 'description': 'Apache Struts 2 Remote Code Execution'}}`

## ThreatIndicator

**Tags:** dataclass

Threat intelligence indicator.

Attributes:
    indicator_type: Type of indicator (ip, domain, hash, cve)
    value: Indicator value
    threat_type: Type of threat
    severity: Severity level
    source: Source of intelligence
    confidence: Confidence score
    first_seen: When first observed
    last_seen: When last observed
    tags: Associated tags
    references: Reference URLs

### Attributes

| Name | Type | Default |
|------|------|---------|
| `indicator_type` | `str` | - |
| `value` | `str` | - |
| `threat_type` | `str` | - |
| `severity` | `str` | - |
| `source` | `str` | - |
| `confidence` | `float` | `0.8` |
| `first_seen` | `datetime | None` | - |
| `last_seen` | `datetime | None` | - |
| `tags` | `list[str]` | `field(...)` |
| `references` | `list[str]` | `field(...)` |

## CVEEnricher

**Inherits from:** FindingEnricher

Enriches findings with CVE details.

Fetches additional CVE information from NVD and other sources.

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self, nvd_api_key: str | None, cache_ttl_hours: int = 24)`

Initialize CVE enricher.

**Parameters:**

- `nvd_api_key` (`str | None`) - NVD API key for higher rate limits
- `cache_ttl_hours` (`int`) - default: `24` - Cache TTL in hours

#### `enrich(self, finding: Finding) -> list[EnrichmentData]`

Enrich finding with CVE details.

**Parameters:**

- `finding` (`Finding`) - Finding to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

## VulnerableSoftwareEnricher

**Inherits from:** FindingEnricher

Enriches findings with known vulnerable software information.

Identifies if a finding relates to known vulnerable software patterns.

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self, vulnerability_patterns: dict[(str, dict)] | None)`

Initialize vulnerable software enricher.

**Parameters:**

- `vulnerability_patterns` (`dict[(str, dict)] | None`) - Custom vulnerability patterns

#### `enrich(self, finding: Finding) -> list[EnrichmentData]`

Enrich finding with vulnerable software information.

**Parameters:**

- `finding` (`Finding`) - Finding to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

#### `add_pattern(self, name: str, pattern: str, cves: list[str], severity: str, description: str) -> None`

Add a custom vulnerability pattern.

**Parameters:**

- `name` (`str`)
- `pattern` (`str`)
- `cves` (`list[str]`)
- `severity` (`str`)
- `description` (`str`)

**Returns:**

`None`

## ThreatIntelEnricher

**Inherits from:** FindingEnricher

Enriches findings with threat intelligence data.

Checks indicators against threat intelligence feeds.

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self, indicators: list[ThreatIndicator] | None, enable_external_lookup: bool = False)`

Initialize threat intelligence enricher.

**Parameters:**

- `indicators` (`list[ThreatIndicator] | None`) - Pre-loaded threat indicators
- `enable_external_lookup` (`bool`) - default: `False` - Whether to query external feeds

#### `add_indicator(self, indicator: ThreatIndicator) -> None`

Add a threat indicator.

**Parameters:**

- `indicator` (`ThreatIndicator`)

**Returns:**

`None`

#### `add_indicators_from_file(self, file_path: str) -> None`

Load indicators from a JSON file.  Expected format: [ { "indicator_type": "ip", "value": "1.2.3.4", "threat_type": "malware", "severity": "high", "source": "feed_name" }, ... ]

**Parameters:**

- `file_path` (`str`)

**Returns:**

`None`

#### `enrich(self, finding: Finding) -> list[EnrichmentData]`

Enrich finding with threat intelligence.

**Parameters:**

- `finding` (`Finding`) - Finding to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

## KEVEnricher

**Inherits from:** FindingEnricher

Enriches findings with CISA Known Exploited Vulnerabilities data.

Checks CVEs against the CISA KEV catalog.

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self, kev_data: dict[(str, dict)] | None, auto_fetch: bool = True)`

Initialize KEV enricher.

**Parameters:**

- `kev_data` (`dict[(str, dict)] | None`) - Pre-loaded KEV data
- `auto_fetch` (`bool`) - default: `True` - Whether to fetch KEV data automatically

#### `enrich(self, finding: Finding) -> list[EnrichmentData]`

Enrich finding with KEV data.

**Parameters:**

- `finding` (`Finding`) - Finding to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

#### `is_known_exploited(self, cve_id: str) -> bool`

Check if a CVE is in the KEV catalog.

**Parameters:**

- `cve_id` (`str`)

**Returns:**

`bool`
