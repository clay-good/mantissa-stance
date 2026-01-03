# stance.collectors.aws_security

AWS Security collector for Mantissa Stance.

Collects security findings from AWS SecurityHub and Inspector
for vulnerability management.

## Contents

### Classes

- [SecurityCollector](#securitycollector)

## SecurityCollector

**Inherits from:** BaseCollector

Collects security findings from AWS SecurityHub and Inspector.

Gathers findings from security services and converts them to
the unified Finding model. All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect security service resources (for asset tracking).

**Returns:**

`AssetCollection` - Collection of security service assets

#### `collect_findings(self) -> FindingCollection`

Collect findings from security services.

**Returns:**

`FindingCollection` - Collection of security findings
