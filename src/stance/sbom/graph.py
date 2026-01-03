"""
Dependency Graph Analysis and Visualization for SBOM.

Provides dependency graph representation, visualization, cycle detection,
and graph-based analysis for software supply chain assessment.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator

from stance.sbom.parser import Dependency, DependencyFile, PackageEcosystem

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the dependency graph."""

    ROOT = "root"  # Project/application root
    DIRECT = "direct"  # Direct dependency
    TRANSITIVE = "transitive"  # Transitive dependency
    DEVELOPMENT = "development"  # Development dependency
    OPTIONAL = "optional"  # Optional dependency
    PEER = "peer"  # Peer dependency


class EdgeType(Enum):
    """Types of edges in the dependency graph."""

    REQUIRES = "requires"  # Standard dependency
    DEV_REQUIRES = "dev_requires"  # Development dependency
    OPTIONAL_REQUIRES = "optional_requires"  # Optional dependency
    PEER_REQUIRES = "peer_requires"  # Peer dependency


@dataclass
class GraphNode:
    """Represents a node in the dependency graph."""

    # Identification
    id: str  # Unique identifier (name@version)
    name: str
    version: str

    # Node properties
    node_type: NodeType = NodeType.DIRECT
    ecosystem: PackageEcosystem = PackageEcosystem.UNKNOWN

    # Depth in the graph (from root)
    depth: int = 0

    # License and security
    license: str | None = None
    has_vulnerabilities: bool = False
    vulnerability_count: int = 0

    # Graph metrics
    in_degree: int = 0  # Number of packages that depend on this
    out_degree: int = 0  # Number of packages this depends on

    # Additional metadata
    deprecated: bool = False
    purl: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    def __hash__(self):
        return hash(self.id)

    def __eq__(self, other):
        if isinstance(other, GraphNode):
            return self.id == other.id
        return False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "node_type": self.node_type.value,
            "ecosystem": self.ecosystem.value,
            "depth": self.depth,
            "license": self.license,
            "has_vulnerabilities": self.has_vulnerabilities,
            "vulnerability_count": self.vulnerability_count,
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "deprecated": self.deprecated,
            "purl": self.purl,
        }


@dataclass
class GraphEdge:
    """Represents an edge in the dependency graph."""

    source: str  # Source node ID
    target: str  # Target node ID
    edge_type: EdgeType = EdgeType.REQUIRES
    version_constraint: str | None = None  # Original version constraint

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "edge_type": self.edge_type.value,
            "version_constraint": self.version_constraint,
        }


@dataclass
class DependencyCycle:
    """Represents a cycle detected in the dependency graph."""

    nodes: list[str]  # Node IDs in the cycle
    length: int = 0

    def __post_init__(self):
        self.length = len(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "nodes": self.nodes,
            "length": self.length,
            "cycle_path": " -> ".join(self.nodes + [self.nodes[0]]),
        }


@dataclass
class GraphMetrics:
    """Metrics computed from the dependency graph."""

    # Node counts
    total_nodes: int = 0
    direct_dependencies: int = 0
    transitive_dependencies: int = 0

    # Depth metrics
    max_depth: int = 0
    avg_depth: float = 0.0

    # Connectivity
    total_edges: int = 0
    avg_in_degree: float = 0.0
    avg_out_degree: float = 0.0

    # Hot spots (highly depended upon)
    hub_nodes: list[str] = field(default_factory=list)  # High in-degree
    hub_threshold: int = 5

    # Cycles
    has_cycles: bool = False
    cycle_count: int = 0
    cycles: list[DependencyCycle] = field(default_factory=list)

    # License diversity
    unique_licenses: int = 0
    license_distribution: dict[str, int] = field(default_factory=dict)

    # Ecosystem diversity
    ecosystems: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "nodes": {
                "total": self.total_nodes,
                "direct": self.direct_dependencies,
                "transitive": self.transitive_dependencies,
            },
            "depth": {
                "max": self.max_depth,
                "average": round(self.avg_depth, 2),
            },
            "edges": {
                "total": self.total_edges,
                "avg_in_degree": round(self.avg_in_degree, 2),
                "avg_out_degree": round(self.avg_out_degree, 2),
            },
            "hub_nodes": self.hub_nodes[:10],  # Top 10 hubs
            "cycles": {
                "detected": self.has_cycles,
                "count": self.cycle_count,
                "cycles": [c.to_dict() for c in self.cycles[:5]],  # Top 5 cycles
            },
            "licenses": {
                "unique_count": self.unique_licenses,
                "distribution": self.license_distribution,
            },
            "ecosystems": self.ecosystems,
        }


@dataclass
class DependencyGraph:
    """
    Represents a dependency graph for software components.

    Provides graph-based analysis including cycle detection,
    depth analysis, and visualization output.
    """

    # Graph data
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    # Root node (project)
    root_id: str | None = None
    root_name: str | None = None
    root_version: str | None = None

    # Adjacency lists for traversal
    _adjacency: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    _reverse_adjacency: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    source_files: list[str] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)
        self._adjacency[edge.source].append(edge.target)
        self._reverse_adjacency[edge.target].append(edge.source)

        # Update degrees
        if edge.source in self.nodes:
            self.nodes[edge.source].out_degree += 1
        if edge.target in self.nodes:
            self.nodes[edge.target].in_degree += 1

    def get_node(self, node_id: str) -> GraphNode | None:
        """Get a node by ID."""
        return self.nodes.get(node_id)

    def get_children(self, node_id: str) -> list[GraphNode]:
        """Get child nodes (dependencies) of a node."""
        child_ids = self._adjacency.get(node_id, [])
        return [self.nodes[cid] for cid in child_ids if cid in self.nodes]

    def get_parents(self, node_id: str) -> list[GraphNode]:
        """Get parent nodes (dependents) of a node."""
        parent_ids = self._reverse_adjacency.get(node_id, [])
        return [self.nodes[pid] for pid in parent_ids if pid in self.nodes]

    def get_path_to_root(self, node_id: str) -> list[str]:
        """Get the path from a node to the root."""
        if node_id not in self.nodes:
            return []

        path = [node_id]
        visited = {node_id}
        current = node_id

        while current != self.root_id:
            parents = self._reverse_adjacency.get(current, [])
            if not parents:
                break

            # Take the first parent (shortest path)
            parent = parents[0]
            if parent in visited:
                break  # Cycle detected

            visited.add(parent)
            path.append(parent)
            current = parent

        return list(reversed(path))

    def detect_cycles(self) -> list[DependencyCycle]:
        """
        Detect cycles in the dependency graph using DFS.

        Returns a list of detected cycles.
        """
        cycles: list[DependencyCycle] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(node_id: str) -> None:
            visited.add(node_id)
            rec_stack.add(node_id)
            path.append(node_id)

            for neighbor in self._adjacency.get(node_id, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # Cycle detected
                    cycle_start = path.index(neighbor)
                    cycle_nodes = path[cycle_start:]
                    cycles.append(DependencyCycle(nodes=cycle_nodes.copy()))

            path.pop()
            rec_stack.remove(node_id)

        for node_id in self.nodes:
            if node_id not in visited:
                dfs(node_id)

        return cycles

    def compute_metrics(self) -> GraphMetrics:
        """Compute graph metrics."""
        metrics = GraphMetrics()

        if not self.nodes:
            return metrics

        # Node counts
        metrics.total_nodes = len(self.nodes)
        metrics.direct_dependencies = sum(
            1 for n in self.nodes.values() if n.node_type == NodeType.DIRECT
        )
        metrics.transitive_dependencies = sum(
            1 for n in self.nodes.values() if n.node_type == NodeType.TRANSITIVE
        )

        # Depth metrics
        depths = [n.depth for n in self.nodes.values()]
        metrics.max_depth = max(depths) if depths else 0
        metrics.avg_depth = sum(depths) / len(depths) if depths else 0

        # Edge metrics
        metrics.total_edges = len(self.edges)
        in_degrees = [n.in_degree for n in self.nodes.values()]
        out_degrees = [n.out_degree for n in self.nodes.values()]
        metrics.avg_in_degree = sum(in_degrees) / len(in_degrees) if in_degrees else 0
        metrics.avg_out_degree = sum(out_degrees) / len(out_degrees) if out_degrees else 0

        # Hub nodes (high in-degree)
        sorted_nodes = sorted(
            self.nodes.values(), key=lambda n: n.in_degree, reverse=True
        )
        metrics.hub_nodes = [
            n.id for n in sorted_nodes if n.in_degree >= metrics.hub_threshold
        ]

        # Cycle detection
        cycles = self.detect_cycles()
        metrics.has_cycles = len(cycles) > 0
        metrics.cycle_count = len(cycles)
        metrics.cycles = cycles

        # License distribution
        license_counts: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            license_name = node.license or "Unknown"
            license_counts[license_name] += 1
        metrics.license_distribution = dict(license_counts)
        metrics.unique_licenses = len(license_counts)

        # Ecosystems
        ecosystems = set(n.ecosystem.value for n in self.nodes.values())
        metrics.ecosystems = sorted(ecosystems)

        return metrics

    def to_tree_string(self, max_depth: int | None = None) -> str:
        """
        Generate a tree-style string representation of the graph.

        Args:
            max_depth: Maximum depth to display (None for all)

        Returns:
            Tree-formatted string
        """
        if not self.root_id:
            return "No root node defined"

        lines: list[str] = []
        visited: set[str] = set()

        def render_node(
            node_id: str, prefix: str = "", is_last: bool = True, depth: int = 0
        ) -> None:
            if max_depth is not None and depth > max_depth:
                return

            if node_id in visited:
                # Already rendered, show as reference
                node = self.nodes.get(node_id)
                if node:
                    connector = "└── " if is_last else "├── "
                    lines.append(f"{prefix}{connector}{node.name}@{node.version} (circular)")
                return

            visited.add(node_id)
            node = self.nodes.get(node_id)
            if not node:
                return

            # Render this node
            if depth == 0:
                lines.append(f"{node.name}@{node.version}")
            else:
                connector = "└── " if is_last else "├── "
                vuln_marker = " [VULN]" if node.has_vulnerabilities else ""
                depr_marker = " [DEPRECATED]" if node.deprecated else ""
                lines.append(f"{prefix}{connector}{node.name}@{node.version}{vuln_marker}{depr_marker}")

            # Render children
            children = self._adjacency.get(node_id, [])
            child_prefix = prefix + ("    " if is_last else "│   ")
            for i, child_id in enumerate(children):
                is_last_child = i == len(children) - 1
                render_node(child_id, child_prefix, is_last_child, depth + 1)

        render_node(self.root_id)
        return "\n".join(lines)

    def to_dot(self) -> str:
        """
        Generate DOT format for Graphviz visualization.

        Returns:
            DOT format string
        """
        lines: list[str] = [
            "digraph dependencies {",
            '    rankdir=TB;',
            '    node [shape=box, style=filled, fontname="Arial"];',
            '    edge [fontname="Arial", fontsize=10];',
            "",
        ]

        # Define node colors based on type
        color_map = {
            NodeType.ROOT: "#4CAF50",  # Green
            NodeType.DIRECT: "#2196F3",  # Blue
            NodeType.TRANSITIVE: "#9E9E9E",  # Gray
            NodeType.DEVELOPMENT: "#FF9800",  # Orange
            NodeType.OPTIONAL: "#FFEB3B",  # Yellow
            NodeType.PEER: "#E91E63",  # Pink
        }

        # Add nodes
        for node in self.nodes.values():
            color = color_map.get(node.node_type, "#FFFFFF")
            label = f"{node.name}\\n{node.version}"
            if node.has_vulnerabilities:
                color = "#F44336"  # Red for vulnerabilities
                label += f"\\n({node.vulnerability_count} vulns)"
            if node.deprecated:
                label += "\\n[DEPRECATED]"

            lines.append(
                f'    "{node.id}" [label="{label}", fillcolor="{color}"];'
            )

        lines.append("")

        # Add edges
        for edge in self.edges:
            style = "solid"
            if edge.edge_type == EdgeType.DEV_REQUIRES:
                style = "dashed"
            elif edge.edge_type == EdgeType.OPTIONAL_REQUIRES:
                style = "dotted"

            lines.append(
                f'    "{edge.source}" -> "{edge.target}" [style={style}];'
            )

        lines.append("}")
        return "\n".join(lines)

    def to_mermaid(self) -> str:
        """
        Generate Mermaid diagram format.

        Returns:
            Mermaid format string
        """
        lines: list[str] = ["graph TD"]

        # Add nodes with styling
        for node in self.nodes.values():
            node_def = f"    {self._sanitize_id(node.id)}"
            if node.node_type == NodeType.ROOT:
                node_def += f"[{node.name}@{node.version}]"
            elif node.has_vulnerabilities:
                node_def += f"(({node.name}@{node.version}))"
            else:
                node_def += f"({node.name}@{node.version})"
            lines.append(node_def)

        # Add edges
        for edge in self.edges:
            src = self._sanitize_id(edge.source)
            tgt = self._sanitize_id(edge.target)
            if edge.edge_type == EdgeType.DEV_REQUIRES:
                lines.append(f"    {src} -.-> {tgt}")
            elif edge.edge_type == EdgeType.OPTIONAL_REQUIRES:
                lines.append(f"    {src} -.- {tgt}")
            else:
                lines.append(f"    {src} --> {tgt}")

        # Add styling
        lines.append("")
        lines.append("    classDef vulnerable fill:#f44336,color:white")
        lines.append("    classDef deprecated fill:#ff9800,color:white")

        # Apply styles to vulnerable nodes
        vuln_nodes = [
            self._sanitize_id(n.id)
            for n in self.nodes.values()
            if n.has_vulnerabilities
        ]
        if vuln_nodes:
            lines.append(f"    class {','.join(vuln_nodes)} vulnerable")

        depr_nodes = [
            self._sanitize_id(n.id)
            for n in self.nodes.values()
            if n.deprecated
        ]
        if depr_nodes:
            lines.append(f"    class {','.join(depr_nodes)} deprecated")

        return "\n".join(lines)

    def _sanitize_id(self, node_id: str) -> str:
        """Sanitize node ID for diagram formats."""
        # Replace special characters
        return node_id.replace("@", "_").replace("/", "_").replace("-", "_").replace(".", "_")

    def to_json(self) -> str:
        """Convert graph to JSON format."""
        import json as json_module

        return json_module.dumps(self.to_dict(), indent=2)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "root": {
                "id": self.root_id,
                "name": self.root_name,
                "version": self.root_version,
            },
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "metrics": self.compute_metrics().to_dict(),
            "source_files": self.source_files,
            "created_at": self.created_at.isoformat(),
        }


class DependencyGraphBuilder:
    """
    Builds dependency graphs from parsed dependency files.
    """

    def __init__(self):
        """Initialize the graph builder."""
        pass

    def build_from_file(self, dep_file: DependencyFile) -> DependencyGraph:
        """
        Build a dependency graph from a parsed dependency file.

        Args:
            dep_file: Parsed dependency file

        Returns:
            DependencyGraph
        """
        graph = DependencyGraph(source_files=[dep_file.file_path])

        # Create root node
        root_name = dep_file.project_name or "project"
        root_version = dep_file.project_version or "0.0.0"
        root_id = f"{root_name}@{root_version}"

        root_node = GraphNode(
            id=root_id,
            name=root_name,
            version=root_version,
            node_type=NodeType.ROOT,
            ecosystem=dep_file.ecosystem,
            depth=0,
            license=dep_file.project_license,
        )

        graph.add_node(root_node)
        graph.root_id = root_id
        graph.root_name = root_name
        graph.root_version = root_version

        # Build a map of dependencies by name for parent lookup
        dep_map: dict[str, Dependency] = {}
        for dep in dep_file.dependencies:
            dep_map[dep.name] = dep

        # Add dependency nodes
        for dep in dep_file.dependencies:
            node_id = f"{dep.name}@{dep.version}"

            # Determine node type
            if dep.is_direct:
                if dep.scope.value == "development":
                    node_type = NodeType.DEVELOPMENT
                elif dep.scope.value == "optional":
                    node_type = NodeType.OPTIONAL
                elif dep.scope.value == "peer":
                    node_type = NodeType.PEER
                else:
                    node_type = NodeType.DIRECT
            else:
                node_type = NodeType.TRANSITIVE

            # Calculate depth
            depth = self._calculate_depth(dep, dep_map)

            node = GraphNode(
                id=node_id,
                name=dep.name,
                version=dep.version,
                node_type=node_type,
                ecosystem=dep.ecosystem,
                depth=depth,
                license=dep.license,
                deprecated=dep.deprecated,
                purl=self._generate_purl(dep),
            )

            graph.add_node(node)

            # Add edge from parent or root
            if dep.parent:
                parent_dep = dep_map.get(dep.parent)
                if parent_dep:
                    parent_id = f"{parent_dep.name}@{parent_dep.version}"
                else:
                    parent_id = root_id
            else:
                parent_id = root_id

            edge_type = self._get_edge_type(dep)
            edge = GraphEdge(
                source=parent_id,
                target=node_id,
                edge_type=edge_type,
                version_constraint=dep.version_constraint,
            )
            graph.add_edge(edge)

        return graph

    def build_from_files(self, dep_files: list[DependencyFile]) -> DependencyGraph:
        """
        Build a merged dependency graph from multiple dependency files.

        Args:
            dep_files: List of parsed dependency files

        Returns:
            Merged DependencyGraph
        """
        if not dep_files:
            return DependencyGraph()

        if len(dep_files) == 1:
            return self.build_from_file(dep_files[0])

        # Build individual graphs and merge
        merged = DependencyGraph(source_files=[f.file_path for f in dep_files])

        # Create a synthetic root
        root_id = "project@merged"
        root_node = GraphNode(
            id=root_id,
            name="project",
            version="merged",
            node_type=NodeType.ROOT,
            depth=0,
        )
        merged.add_node(root_node)
        merged.root_id = root_id
        merged.root_name = "project"
        merged.root_version = "merged"

        # Add all dependencies from all files
        seen_nodes: set[str] = set()

        for dep_file in dep_files:
            for dep in dep_file.dependencies:
                node_id = f"{dep.name}@{dep.version}"

                if node_id not in seen_nodes:
                    seen_nodes.add(node_id)

                    node_type = NodeType.DIRECT if dep.is_direct else NodeType.TRANSITIVE
                    node = GraphNode(
                        id=node_id,
                        name=dep.name,
                        version=dep.version,
                        node_type=node_type,
                        ecosystem=dep.ecosystem,
                        depth=1 if dep.is_direct else 2,
                        license=dep.license,
                        deprecated=dep.deprecated,
                    )
                    merged.add_node(node)

                    # Add edge from root for direct dependencies
                    if dep.is_direct:
                        edge = GraphEdge(
                            source=root_id,
                            target=node_id,
                            edge_type=self._get_edge_type(dep),
                        )
                        merged.add_edge(edge)

        return merged

    def _calculate_depth(
        self, dep: Dependency, dep_map: dict[str, Dependency]
    ) -> int:
        """Calculate the depth of a dependency in the tree."""
        depth = 1
        current = dep

        while current.parent and depth < 100:  # Prevent infinite loops
            parent = dep_map.get(current.parent)
            if not parent:
                break
            depth += 1
            current = parent

        return depth

    def _get_edge_type(self, dep: Dependency) -> EdgeType:
        """Determine edge type from dependency scope."""
        if dep.scope.value == "development":
            return EdgeType.DEV_REQUIRES
        if dep.scope.value == "optional":
            return EdgeType.OPTIONAL_REQUIRES
        if dep.scope.value == "peer":
            return EdgeType.PEER_REQUIRES
        return EdgeType.REQUIRES

    def _generate_purl(self, dep: Dependency) -> str | None:
        """Generate Package URL for a dependency."""
        ecosystem_map = {
            PackageEcosystem.NPM: "npm",
            PackageEcosystem.PYPI: "pypi",
            PackageEcosystem.GO: "golang",
            PackageEcosystem.CARGO: "cargo",
            PackageEcosystem.MAVEN: "maven",
            PackageEcosystem.NUGET: "nuget",
            PackageEcosystem.RUBYGEMS: "gem",
            PackageEcosystem.COMPOSER: "composer",
        }

        purl_type = ecosystem_map.get(dep.ecosystem)
        if not purl_type:
            return None

        name = dep.name
        version = dep.version

        # Handle scoped packages
        if name.startswith("@") and "/" in name:
            # npm scoped package
            namespace, name = name.lstrip("@").split("/", 1)
            return f"pkg:{purl_type}/%40{namespace}/{name}@{version}"

        return f"pkg:{purl_type}/{name}@{version}"


def build_dependency_graph(dep_file: DependencyFile) -> DependencyGraph:
    """
    Convenience function to build a dependency graph.

    Args:
        dep_file: Parsed dependency file

    Returns:
        DependencyGraph
    """
    builder = DependencyGraphBuilder()
    return builder.build_from_file(dep_file)


def visualize_dependencies(
    dep_file: DependencyFile,
    format: str = "tree",
    max_depth: int | None = None,
) -> str:
    """
    Convenience function to visualize dependencies.

    Args:
        dep_file: Parsed dependency file
        format: Output format (tree, dot, mermaid, json)
        max_depth: Maximum depth for tree format

    Returns:
        Formatted string
    """
    graph = build_dependency_graph(dep_file)

    if format == "tree":
        return graph.to_tree_string(max_depth=max_depth)
    elif format == "dot":
        return graph.to_dot()
    elif format == "mermaid":
        return graph.to_mermaid()
    elif format == "json":
        return graph.to_json()
    else:
        raise ValueError(f"Unknown format: {format}")
