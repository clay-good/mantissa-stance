# stance.enrichment.ip_enrichment

IP enrichment for Mantissa Stance.

Provides IP address enrichment including geolocation,
ASN information, and cloud provider identification.

## Contents

### Classes

- [IPInfo](#ipinfo)
- [IPEnricher](#ipenricher)
- [CloudProviderRangeEnricher](#cloudproviderrangeenricher)

### Functions


## Constants

### `CLOUD_PROVIDER_RANGES`

Type: `dict`

Value: `{'aws': ['"Tuple(elts=[Constant(value=\'3.0.0.0\'), Constant(value=\'3.255.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'13.32.0.0\'), Constant(value=\'13.35.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'15.177.0.0\'), Constant(value=\'15.177.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'18.0.0.0\'), Constant(value=\'18.255.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'34.192.0.0\'), Constant(value=\'34.255.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'35.80.0.0\'), Constant(value=\'35.191.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'52.0.0.0\'), Constant(value=\'52.255.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'54.0.0.0\'), Constant(value=\'54.255.255.255\')], ctx=Load())"'], 'gcp': ['"Tuple(elts=[Constant(value=\'34.64.0.0\'), Constant(value=\'34.79.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'34.80.0.0\'), Constant(value=\'34.95.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'34.96.0.0\'), Constant(value=\'34.111.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'35.184.0.0\'), Constant(value=\'35.199.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'35.200.0.0\'), Constant(value=\'35.215.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'35.216.0.0\'), Constant(value=\'35.231.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'35.232.0.0\'), Constant(value=\'35.247.255.255\')], ctx=Load())"'], 'azure': ['"Tuple(elts=[Constant(value=\'13.64.0.0\'), Constant(value=\'13.107.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'20.0.0.0\'), Constant(value=\'20.255.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'40.64.0.0\'), Constant(value=\'40.127.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'52.0.0.0\'), Constant(value=\'52.255.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'104.40.0.0\'), Constant(value=\'104.47.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'137.116.0.0\'), Constant(value=\'137.135.255.255\')], ctx=Load())"', '"Tuple(elts=[Constant(value=\'168.61.0.0\'), Constant(value=\'168.63.255.255\')], ctx=Load())"']}`

## IPInfo

**Tags:** dataclass

IP address information.

Attributes:
    ip: IP address
    is_public: Whether IP is public
    is_private: Whether IP is private (RFC 1918)
    version: IP version (4 or 6)

### Attributes

| Name | Type | Default |
|------|------|---------|
| `ip` | `str` | - |
| `is_public` | `bool` | - |
| `is_private` | `bool` | - |
| `version` | `int` | - |

### Class Methods

#### `from_string(cls, ip_str: str) -> IPInfo | None`

**Decorators:** @classmethod

Parse IP address string.

**Parameters:**

- `ip_str` (`str`)

**Returns:**

`IPInfo | None`

## IPEnricher

**Inherits from:** AssetEnricher

Enriches assets with IP-related information.

Provides:
- GeoIP lookup (country, city, coordinates)
- ASN information (organization, network)
- Cloud provider identification

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self, geoip_api_key: str | None, cache_ttl_hours: int = 24, enable_geoip: bool = True)`

Initialize IP enricher.

**Parameters:**

- `geoip_api_key` (`str | None`) - API key for GeoIP service (optional)
- `cache_ttl_hours` (`int`) - default: `24` - Cache TTL in hours
- `enable_geoip` (`bool`) - default: `True` - Whether to enable GeoIP lookups

#### `enrich(self, asset: Asset) -> list[EnrichmentData]`

Enrich asset with IP information.

**Parameters:**

- `asset` (`Asset`) - Asset to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

#### `is_available(self) -> bool`

Check if enricher is available.

**Returns:**

`bool`

#### `lookup_ip(self, ip: str) -> dict[(str, Any)]`

Look up information for a single IP.  Public method for direct IP lookups.

**Parameters:**

- `ip` (`str`) - IP address to look up

**Returns:**

`dict[(str, Any)]` - Dictionary with IP information

## CloudProviderRangeEnricher

**Inherits from:** AssetEnricher

Enriches assets with cloud provider range information.

Identifies which cloud provider an IP belongs to based on
known IP ranges.

### Properties

#### `enricher_name(self) -> str`

**Returns:**

`str`

#### `enrichment_types(self) -> list[EnrichmentType]`

**Returns:**

`list[EnrichmentType]`

### Methods

#### `__init__(self)`

Initialize cloud provider range enricher.

#### `enrich(self, asset: Asset) -> list[EnrichmentData]`

Enrich asset with cloud provider information.

**Parameters:**

- `asset` (`Asset`) - Asset to enrich

**Returns:**

`list[EnrichmentData]` - List of enrichment data

#### `add_custom_range(self, provider: str, start: str, end: str) -> None`

Add a custom IP range for a provider.

**Parameters:**

- `provider` (`str`) - Provider name
- `start` (`str`) - Range start IP
- `end` (`str`) - Range end IP

**Returns:**

`None`

#### `identify_provider(self, ip: str) -> str | None`

Identify cloud provider for an IP.

**Parameters:**

- `ip` (`str`) - IP address

**Returns:**

`str | None` - Provider name or None
