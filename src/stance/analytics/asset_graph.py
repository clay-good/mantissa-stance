"""
Asset Graph for Mantissa Stance.

Builds a graph of cloud assets and their relationships for finding
correlation and attack path analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator

from stance.models.asset import Asset, AssetCollection


class RelationshipType(Enum):
    """Types of relationships between assets."""

    NETWORK_CONNECTED = "network_connected"
    IAM_ATTACHED = "iam_attached"
    CONTAINS = "contains"
    REFERENCES = "references"
    ENCRYPTS = "encrypts"
    LOGS_TO = "logs_to"
    ROUTES_TO = "routes_to"
    TRUSTS = "trusts"


@dataclass
class Relationship:
    """
    Represents a relationship between two assets.

    Attributes:
        source_id: ID of the source asset
        target_id: ID of the target asset
        relationship_type: Type of relationship
        properties: Additional properties about the relationship
    """

    source_id: str
    target_id: str
    relationship_type: RelationshipType
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relationship_type": self.relationship_type.value,
            "properties": self.properties,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Relationship:
        """Create from dictionary."""
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            relationship_type=RelationshipType(data["relationship_type"]),
            properties=data.get("properties", {}),
        )


@dataclass
class AssetNode:
    """
    Node in the asset graph representing a single asset.

    Attributes:
        asset: The underlying asset
        inbound: Relationships pointing to this asset
        outbound: Relationships pointing from this asset
        risk_score: Calculated risk score for this asset
    """

    asset: Asset
    inbound: list[Relationship] = field(default_factory=list)
    outbound: list[Relationship] = field(default_factory=list)
    risk_score: float = 0.0

    @property
    def id(self) -> str:
        """Get the asset ID."""
        return self.asset.id

    @property
    def is_internet_facing(self) -> bool:
        """Check if asset is internet-facing."""
        return self.asset.is_internet_facing()

    def get_neighbors(self) -> list[str]:
        """Get IDs of all connected assets."""
        neighbors = set()
        for rel in self.inbound:
            neighbors.add(rel.source_id)
        for rel in self.outbound:
            neighbors.add(rel.target_id)
        return list(neighbors)


class AssetGraph:
    """
    Graph representation of cloud assets and their relationships.

    Enables finding correlation, attack path analysis, and risk scoring
    based on asset connectivity.
    """

    def __init__(self) -> None:
        """Initialize empty asset graph."""
        self._nodes: dict[str, AssetNode] = {}
        self._relationships: list[Relationship] = []

    def add_asset(self, asset: Asset) -> AssetNode:
        """
        Add an asset to the graph.

        Args:
            asset: Asset to add

        Returns:
            The created AssetNode
        """
        if asset.id in self._nodes:
            return self._nodes[asset.id]

        node = AssetNode(asset=asset)
        self._nodes[asset.id] = node
        return node

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: RelationshipType,
        properties: dict[str, Any] | None = None,
    ) -> Relationship | None:
        """
        Add a relationship between two assets.

        Args:
            source_id: ID of the source asset
            target_id: ID of the target asset
            relationship_type: Type of relationship
            properties: Additional properties

        Returns:
            The created Relationship, or None if either asset doesn't exist
        """
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        relationship = Relationship(
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type,
            properties=properties or {},
        )

        self._relationships.append(relationship)
        self._nodes[source_id].outbound.append(relationship)
        self._nodes[target_id].inbound.append(relationship)

        return relationship

    def get_node(self, asset_id: str) -> AssetNode | None:
        """Get a node by asset ID."""
        return self._nodes.get(asset_id)

    def get_nodes(self) -> Iterator[AssetNode]:
        """Iterate over all nodes."""
        return iter(self._nodes.values())

    def get_relationships(self) -> list[Relationship]:
        """Get all relationships."""
        return self._relationships.copy()

    def get_internet_facing_nodes(self) -> list[AssetNode]:
        """Get all internet-facing asset nodes."""
        return [node for node in self._nodes.values() if node.is_internet_facing]

    def get_connected_components(self) -> list[set[str]]:
        """
        Find all connected components in the graph.

        Returns:
            List of sets, each containing asset IDs in a connected component
        """
        visited: set[str] = set()
        components: list[set[str]] = []

        def dfs(node_id: str, component: set[str]) -> None:
            if node_id in visited:
                return
            visited.add(node_id)
            component.add(node_id)
            node = self._nodes.get(node_id)
            if node:
                for neighbor_id in node.get_neighbors():
                    dfs(neighbor_id, component)

        for node_id in self._nodes:
            if node_id not in visited:
                component: set[str] = set()
                dfs(node_id, component)
                components.append(component)

        return components

    def find_path(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
    ) -> list[str] | None:
        """
        Find a path between two assets using BFS.

        Args:
            source_id: Starting asset ID
            target_id: Ending asset ID
            max_depth: Maximum path length to search

        Returns:
            List of asset IDs in the path, or None if no path exists
        """
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        if source_id == target_id:
            return [source_id]

        # BFS
        from collections import deque

        queue: deque[tuple[str, list[str]]] = deque([(source_id, [source_id])])
        visited: set[str] = {source_id}

        while queue:
            current_id, path = queue.popleft()

            if len(path) > max_depth:
                continue

            current_node = self._nodes.get(current_id)
            if not current_node:
                continue

            for neighbor_id in current_node.get_neighbors():
                if neighbor_id == target_id:
                    return path + [target_id]

                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return None

    def get_reachable_from(
        self,
        source_id: str,
        max_depth: int = 5,
        direction: str = "outbound",
    ) -> set[str]:
        """
        Find all assets reachable from a source asset.

        Args:
            source_id: Starting asset ID
            max_depth: Maximum traversal depth
            direction: 'outbound', 'inbound', or 'both'

        Returns:
            Set of reachable asset IDs
        """
        if source_id not in self._nodes:
            return set()

        reachable: set[str] = set()
        visited: set[str] = set()

        def dfs(node_id: str, depth: int) -> None:
            if depth > max_depth or node_id in visited:
                return
            visited.add(node_id)
            reachable.add(node_id)

            node = self._nodes.get(node_id)
            if not node:
                return

            if direction in ("outbound", "both"):
                for rel in node.outbound:
                    dfs(rel.target_id, depth + 1)

            if direction in ("inbound", "both"):
                for rel in node.inbound:
                    dfs(rel.source_id, depth + 1)

        dfs(source_id, 0)
        reachable.discard(source_id)  # Don't include source
        return reachable

    @property
    def node_count(self) -> int:
        """Get number of nodes in the graph."""
        return len(self._nodes)

    @property
    def relationship_count(self) -> int:
        """Get number of relationships in the graph."""
        return len(self._relationships)

    def to_dict(self) -> dict[str, Any]:
        """Convert graph to dictionary representation."""
        return {
            "nodes": [
                {
                    "id": node.id,
                    "asset": node.asset.to_dict(),
                    "risk_score": node.risk_score,
                }
                for node in self._nodes.values()
            ],
            "relationships": [rel.to_dict() for rel in self._relationships],
        }


class AssetGraphBuilder:
    """
    Builds an asset graph from a collection of assets.

    Automatically detects relationships based on asset configurations.
    """

    def __init__(self) -> None:
        """Initialize the graph builder."""
        self._graph = AssetGraph()

    def build(self, assets: AssetCollection) -> AssetGraph:
        """
        Build a graph from an asset collection.

        Args:
            assets: Collection of assets to build graph from

        Returns:
            The built asset graph
        """
        # Add all assets as nodes
        for asset in assets.assets:
            self._graph.add_asset(asset)

        # Detect relationships
        self._detect_network_relationships(assets)
        self._detect_iam_relationships(assets)
        self._detect_containment_relationships(assets)
        self._detect_logging_relationships(assets)

        return self._graph

    def _detect_network_relationships(self, assets: AssetCollection) -> None:
        """Detect network-based relationships between assets."""
        # Find security groups and their attached resources
        security_groups = {}
        for asset in assets.filter_by_type("aws_security_group").assets:
            sg_id = asset.raw_config.get("group_id", asset.id)
            security_groups[sg_id] = asset

        for asset in assets.assets:
            if asset.resource_type in ("aws_ec2_instance", "aws_rds_instance"):
                attached_sgs = asset.raw_config.get("security_groups", [])
                for sg_id in attached_sgs:
                    if sg_id in security_groups:
                        self._graph.add_relationship(
                            source_id=security_groups[sg_id].id,
                            target_id=asset.id,
                            relationship_type=RelationshipType.NETWORK_CONNECTED,
                            properties={"security_group_id": sg_id},
                        )

        # VPC and subnet relationships
        vpcs = {}
        for asset in assets.filter_by_type("aws_vpc").assets:
            vpc_id = asset.raw_config.get("vpc_id", asset.id)
            vpcs[vpc_id] = asset

        for asset in assets.assets:
            vpc_id = asset.raw_config.get("vpc_id")
            if vpc_id and vpc_id in vpcs:
                self._graph.add_relationship(
                    source_id=vpcs[vpc_id].id,
                    target_id=asset.id,
                    relationship_type=RelationshipType.CONTAINS,
                    properties={"vpc_id": vpc_id},
                )

    def _detect_iam_relationships(self, assets: AssetCollection) -> None:
        """Detect IAM-based relationships between assets."""
        # IAM roles and their attached policies
        for asset in assets.filter_by_type("aws_iam_role").assets:
            attached_policies = asset.raw_config.get("attached_policies", [])
            for policy_arn in attached_policies:
                # Find the policy asset
                for policy in assets.filter_by_type("aws_iam_policy").assets:
                    if policy.id == policy_arn:
                        self._graph.add_relationship(
                            source_id=policy.id,
                            target_id=asset.id,
                            relationship_type=RelationshipType.IAM_ATTACHED,
                        )
                        break

        # EC2 instances with IAM instance profiles
        for asset in assets.filter_by_type("aws_ec2_instance").assets:
            instance_profile = asset.raw_config.get("iam_instance_profile")
            if instance_profile:
                for role in assets.filter_by_type("aws_iam_role").assets:
                    if role.name == instance_profile or role.id.endswith(
                        f"/{instance_profile}"
                    ):
                        self._graph.add_relationship(
                            source_id=role.id,
                            target_id=asset.id,
                            relationship_type=RelationshipType.IAM_ATTACHED,
                            properties={"instance_profile": instance_profile},
                        )
                        break

    def _detect_containment_relationships(self, assets: AssetCollection) -> None:
        """Detect containment relationships (e.g., S3 bucket contains objects)."""
        # S3 buckets in accounts
        for asset in assets.filter_by_type("aws_s3_bucket").assets:
            account_id = asset.account_id
            # Find account asset if exists
            for account in assets.filter_by_type("aws_account").assets:
                if account.raw_config.get("account_id") == account_id:
                    self._graph.add_relationship(
                        source_id=account.id,
                        target_id=asset.id,
                        relationship_type=RelationshipType.CONTAINS,
                    )
                    break

    def _detect_logging_relationships(self, assets: AssetCollection) -> None:
        """Detect logging relationships between assets."""
        # S3 bucket logging configurations
        for asset in assets.filter_by_type("aws_s3_bucket").assets:
            logging_config = asset.raw_config.get("logging", {})
            target_bucket = logging_config.get("target_bucket")
            if target_bucket:
                for target in assets.filter_by_type("aws_s3_bucket").assets:
                    if target.name == target_bucket:
                        self._graph.add_relationship(
                            source_id=asset.id,
                            target_id=target.id,
                            relationship_type=RelationshipType.LOGS_TO,
                        )
                        break

        # CloudTrail logging to S3
        for asset in assets.filter_by_type("aws_cloudtrail").assets:
            s3_bucket = asset.raw_config.get("s3_bucket_name")
            if s3_bucket:
                for bucket in assets.filter_by_type("aws_s3_bucket").assets:
                    if bucket.name == s3_bucket:
                        self._graph.add_relationship(
                            source_id=asset.id,
                            target_id=bucket.id,
                            relationship_type=RelationshipType.LOGS_TO,
                        )
                        break
