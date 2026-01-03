# stance.models

Data models for Mantissa Stance.

This package provides the core data models used throughout Stance:

- Asset: Represents cloud resources discovered during scanning
- Finding: Represents security findings (misconfigurations and vulnerabilities)
- Policy: Represents security policy definitions loaded from YAML

Each model has an associated Collection class for managing groups of objects
with filtering and aggregation capabilities.
