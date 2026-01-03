# stance.analytics.asset_graph

Asset Graph for Mantissa Stance.

Builds a graph of cloud assets and their relationships for finding
correlation and attack path analysis.

## Contents

### Classes

- [RelationshipType](#relationshiptype)
- [Relationship](#relationship)
- [AssetNode](#assetnode)
- [AssetGraph](#assetgraph)
- [AssetGraphBuilder](#assetgraphbuilder)

## RelationshipType

**Inherits from:** Enum

Types of relationships between assets.

## Relationship

**Tags:** dataclass

Represents a relationship between two assets.

Attributes:
    source_id: ID of the source asset
    target_id: ID of the target asset
    relationship_type: Type of relationship
    properties: Additional properties about the relationship

### Attributes

| Name | Type | Default |
|------|------|---------|
| `source_id` | `str` | - |
| `target_id` | `str` | - |
| `relationship_type` | `RelationshipType` | - |
| `properties` | `dict[(str, Any)]` | `field(...)` |

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

### Class Methods

#### `from_dict(cls, data: dict[(str, Any)]) -> Relationship`

**Decorators:** @classmethod

Create from dictionary.

**Parameters:**

- `data` (`dict[(str, Any)]`)

**Returns:**

`Relationship`

## AssetNode

**Tags:** dataclass

Node in the asset graph representing a single asset.

Attributes:
    asset: The underlying asset
    inbound: Relationships pointing to this asset
    outbound: Relationships pointing from this asset
    risk_score: Calculated risk score for this asset

### Attributes

| Name | Type | Default |
|------|------|---------|
| `asset` | `Asset` | - |
| `inbound` | `list[Relationship]` | `field(...)` |
| `outbound` | `list[Relationship]` | `field(...)` |
| `risk_score` | `float` | `0.0` |

### Properties

#### `id(self) -> str`

Get the asset ID.

**Returns:**

`str`

#### `is_internet_facing(self) -> bool`

Check if asset is internet-facing.

**Returns:**

`bool`

### Methods

#### `get_neighbors(self) -> list[str]`

Get IDs of all connected assets.

**Returns:**

`list[str]`

## AssetGraph

Graph representation of cloud assets and their relationships.

Enables finding correlation, attack path analysis, and risk scoring
based on asset connectivity.

### Properties

#### `node_count(self) -> int`

Get number of nodes in the graph.

**Returns:**

`int`

#### `relationship_count(self) -> int`

Get number of relationships in the graph.

**Returns:**

`int`

### Methods

#### `__init__(self) -> None`

Initialize empty asset graph.

**Returns:**

`None`

#### `add_asset(self, asset: Asset) -> AssetNode`

Add an asset to the graph.

**Parameters:**

- `asset` (`Asset`) - Asset to add

**Returns:**

`AssetNode` - The created AssetNode

#### `add_relationship(self, source_id: str, target_id: str, relationship_type: RelationshipType, properties: dict[(str, Any)] | None) -> Relationship | None`

Add a relationship between two assets.

**Parameters:**

- `source_id` (`str`) - ID of the source asset
- `target_id` (`str`) - ID of the target asset
- `relationship_type` (`RelationshipType`) - Type of relationship
- `properties` (`dict[(str, Any)] | None`) - Additional properties

**Returns:**

`Relationship | None` - The created Relationship, or None if either asset doesn't exist

#### `get_node(self, asset_id: str) -> AssetNode | None`

Get a node by asset ID.

**Parameters:**

- `asset_id` (`str`)

**Returns:**

`AssetNode | None`

#### `get_nodes(self) -> Iterator[AssetNode]`

Iterate over all nodes.

**Returns:**

`Iterator[AssetNode]`

#### `get_relationships(self) -> list[Relationship]`

Get all relationships.

**Returns:**

`list[Relationship]`

#### `get_internet_facing_nodes(self) -> list[AssetNode]`

Get all internet-facing asset nodes.

**Returns:**

`list[AssetNode]`

#### `get_connected_components(self) -> list[set[str]]`

Find all connected components in the graph.

**Returns:**

`list[set[str]]` - List of sets, each containing asset IDs in a connected component

#### `find_path(self, source_id: str, target_id: str, max_depth: int = 10) -> list[str] | None`

Find a path between two assets using BFS.

**Parameters:**

- `source_id` (`str`) - Starting asset ID
- `target_id` (`str`) - Ending asset ID
- `max_depth` (`int`) - default: `10` - Maximum path length to search

**Returns:**

`list[str] | None` - List of asset IDs in the path, or None if no path exists

#### `get_reachable_from(self, source_id: str, max_depth: int = 5, direction: str = outbound) -> set[str]`

Find all assets reachable from a source asset.

**Parameters:**

- `source_id` (`str`) - Starting asset ID
- `max_depth` (`int`) - default: `5` - Maximum traversal depth
- `direction` (`str`) - default: `outbound` - 'outbound', 'inbound', or 'both'

**Returns:**

`set[str]` - Set of reachable asset IDs

#### `to_dict(self) -> dict[(str, Any)]`

Convert graph to dictionary representation.

**Returns:**

`dict[(str, Any)]`

## AssetGraphBuilder

Builds an asset graph from a collection of assets.

Automatically detects relationships based on asset configurations.

### Methods

#### `__init__(self) -> None`

Initialize the graph builder.

**Returns:**

`None`

#### `build(self, assets: AssetCollection) -> AssetGraph`

Build a graph from an asset collection.

**Parameters:**

- `assets` (`AssetCollection`) - Collection of assets to build graph from

**Returns:**

`AssetGraph` - The built asset graph
