# stance.collectors.aws_ec2

AWS EC2 collector for Mantissa Stance.

Collects EC2 instances, security groups, VPCs, and subnets
for security posture assessment.

## Contents

### Classes

- [EC2Collector](#ec2collector)

## Constants

### `SENSITIVE_PORTS`

Type: `dict`

Value: `{22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'MSSQL', 1434: 'MSSQL Browser', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch', 5601: 'Kibana', 8080: 'HTTP Alt', 23: 'Telnet', 21: 'FTP', 445: 'SMB', 135: 'RPC', 139: 'NetBIOS'}`

## EC2Collector

**Inherits from:** BaseCollector

Collects AWS EC2 instances, security groups, and network configuration.

Gathers EC2 instances, security groups, VPCs, and subnets.
All API calls are read-only.

### Methods

#### `collect(self) -> AssetCollection`

Collect all EC2 and network resources.

**Returns:**

`AssetCollection` - Collection of EC2 and network assets
