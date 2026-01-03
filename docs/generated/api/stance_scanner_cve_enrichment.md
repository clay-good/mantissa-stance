# stance.scanner.cve_enrichment

CVE correlation and enrichment for vulnerability data.

This module provides enrichment of vulnerability data with:
- EPSS (Exploit Prediction Scoring System) scores
- CISA KEV (Known Exploited Vulnerabilities) catalog data
- NVD (National Vulnerability Database) details
- CVE correlation across multiple images/resources

## Contents

### Classes

- [EPSSScore](#epssscore)
- [KEVEntry](#keventry)
- [EnrichedVulnerability](#enrichedvulnerability)
- [CVEEnricher](#cveenricher)

### Functions

- [prioritize_vulnerabilities](#prioritize_vulnerabilities)

## EPSSScore

**Tags:** dataclass

EPSS (Exploit Prediction Scoring System) score for a CVE.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `cve_id` | `str` | - |
| `epss` | `float` | - |
| `percentile` | `float` | - |
| `date` | `str` | - |

## KEVEntry

**Tags:** dataclass

CISA Known Exploited Vulnerabilities catalog entry.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `cve_id` | `str` | - |
| `vendor_project` | `str` | - |
| `product` | `str` | - |
| `vulnerability_name` | `str` | - |
| `date_added` | `str` | - |
| `short_description` | `str` | - |
| `required_action` | `str` | - |
| `due_date` | `str` | - |
| `known_ransomware_campaign_use` | `bool` | `False` |

## EnrichedVulnerability

**Tags:** dataclass

Vulnerability with enrichment data.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `vulnerability` | `Vulnerability` | - |
| `epss_score` | `Optional[EPSSScore]` | - |
| `kev_entry` | `Optional[KEVEntry]` | - |
| `nvd_data` | `Optional[dict]` | - |
| `priority_score` | `float` | `0.0` |
| `priority_factors` | `list[str]` | `field(...)` |

### Methods

#### `calculate_priority(self) -> float`

Calculate priority score based on multiple factors.

**Returns:**

`float`

## CVEEnricher

Enriches vulnerability data with additional context.

### Methods

#### `__init__(self, cache_dir: Optional[Path], cache_ttl_hours: int = 24)`

Initialize CVE enricher.

**Parameters:**

- `cache_dir` (`Optional[Path]`) - Directory for caching enrichment data
- `cache_ttl_hours` (`int`) - default: `24` - Cache time-to-live in hours

#### `enrich_vulnerability(self, vuln: Vulnerability, fetch_epss: bool = True, fetch_kev: bool = True) -> EnrichedVulnerability`

Enrich a single vulnerability with additional data.

**Parameters:**

- `vuln` (`Vulnerability`) - Vulnerability to enrich
- `fetch_epss` (`bool`) - default: `True` - Whether to fetch EPSS scores
- `fetch_kev` (`bool`) - default: `True` - Whether to check KEV catalog

**Returns:**

`EnrichedVulnerability` - EnrichedVulnerability with additional context

#### `enrich_scan_result(self, result: ScanResult, fetch_epss: bool = True, fetch_kev: bool = True) -> list[EnrichedVulnerability]`

Enrich all vulnerabilities in a scan result.

**Parameters:**

- `result` (`ScanResult`) - Scan result to enrich
- `fetch_epss` (`bool`) - default: `True` - Whether to fetch EPSS scores
- `fetch_kev` (`bool`) - default: `True` - Whether to check KEV catalog

**Returns:**

`list[EnrichedVulnerability]` - List of enriched vulnerabilities

#### `correlate_vulnerabilities(self, results: list[ScanResult]) -> dict[(str, list[tuple[(str, Vulnerability)]])]`

Correlate vulnerabilities across multiple scan results.

**Parameters:**

- `results` (`list[ScanResult]`) - List of scan results

**Returns:**

`dict[(str, list[tuple[(str, Vulnerability)]])]` - Dict mapping CVE IDs to list of (image_ref, vulnerability) tuples

#### `get_vulnerability_summary(self, enriched_vulns: list[EnrichedVulnerability]) -> dict[(str, Any)]`

Generate summary statistics for enriched vulnerabilities.

**Parameters:**

- `enriched_vulns` (`list[EnrichedVulnerability]`) - List of enriched vulnerabilities

**Returns:**

`dict[(str, Any)]` - Summary statistics dict

### `prioritize_vulnerabilities(vulnerabilities: list[Vulnerability], enricher: Optional[CVEEnricher]) -> list[EnrichedVulnerability]`

Convenience function to enrich and prioritize vulnerabilities.

**Parameters:**

- `vulnerabilities` (`list[Vulnerability]`) - List of vulnerabilities to prioritize
- `enricher` (`Optional[CVEEnricher]`) - Optional CVEEnricher instance

**Returns:**

`list[EnrichedVulnerability]` - List of enriched vulnerabilities sorted by priority
