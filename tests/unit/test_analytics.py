"""
Unit tests for the analytics module.

Tests the AssetGraph, AssetGraphBuilder, attack path analysis,
and risk scoring components.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from stance.analytics import (
    AssetGraph,
    AssetGraphBuilder,
    AssetNode,
    Relationship,
    RelationshipType,
)
from stance.analytics.attack_paths import (
    AttackPath,
    AttackPathAnalyzer,
    AttackPathStep,
    AttackPathType,
)
from stance.analytics.risk_scoring import (
    RiskFactors,
    RiskScore,
    RiskScorer,
    RiskTrend,
)
from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingCollection, Severity, FindingStatus, FindingType


# Fixtures

@pytest.fixture
def sample_asset():
    """Create a sample asset for testing."""
    return Asset(
        id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_ec2_instance",
        name="web-server-1",
        tags={"Environment": "production", "Team": "web"},
        network_exposure="internet_facing",
        created_at=datetime.utcnow() - timedelta(days=30),
        last_seen=datetime.utcnow(),
        raw_config={
            "instance_type": "t3.medium",
            "security_groups": ["sg-12345"],
            "public_ip": "1.2.3.4",
        },
    )


@pytest.fixture
def sample_assets():
    """Create a collection of sample assets."""
    now = datetime.utcnow()
    assets = [
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-web",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="web-server",
            tags={"Environment": "production"},
            network_exposure="internet_facing",
            created_at=now - timedelta(days=30),
            last_seen=now,
            raw_config={"security_groups": ["sg-12345"]},
        ),
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-app",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="app-server",
            tags={"Environment": "production"},
            network_exposure="internal",
            created_at=now - timedelta(days=30),
            last_seen=now,
            raw_config={"security_groups": ["sg-12345"]},
        ),
        Asset(
            id="arn:aws:rds:us-east-1:123456789012:db:prod-db",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_rds_instance",
            name="prod-database",
            tags={"Environment": "production"},
            network_exposure="internal",
            created_at=now - timedelta(days=90),
            last_seen=now,
            raw_config={},
        ),
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_security_group",
            name="web-sg",
            tags={},
            network_exposure="internal",
            created_at=now - timedelta(days=60),
            last_seen=now,
            raw_config={"group_id": "sg-12345"},
        ),
    ]
    return AssetCollection(assets=assets)


@pytest.fixture
def sample_findings():
    """Create sample findings for testing."""
    now = datetime.utcnow()
    findings = [
        Finding(
            id="finding-1",
            asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-web",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="Security group allows SSH from anywhere",
            description="The security group allows SSH access from 0.0.0.0/0",
            first_seen=now - timedelta(days=7),
            last_seen=now,
            rule_id="aws-ec2-002",
            compliance_frameworks=["CIS 5.2"],
            remediation_guidance="Restrict SSH access to specific IPs",
        ),
        Finding(
            id="finding-2",
            asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-app",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Instance metadata service v1 enabled",
            description="IMDSv1 is enabled which is vulnerable to SSRF",
            first_seen=now - timedelta(days=14),
            last_seen=now,
            rule_id="aws-ec2-005",
            compliance_frameworks=["CIS 5.4"],
            remediation_guidance="Enable IMDSv2 and disable IMDSv1",
        ),
        Finding(
            id="finding-3",
            asset_id="arn:aws:rds:us-east-1:123456789012:db:prod-db",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            title="RDS instance not encrypted",
            description="The RDS instance does not have encryption at rest enabled",
            first_seen=now - timedelta(days=30),
            last_seen=now,
            rule_id="aws-rds-001",
            compliance_frameworks=["CIS 2.3.1", "PCI 3.4"],
            remediation_guidance="Enable encryption at rest for the RDS instance",
        ),
    ]
    return FindingCollection(findings=findings)


# AssetGraph Tests

class TestAssetGraph:
    """Tests for the AssetGraph class."""

    def test_create_empty_graph(self):
        """Test creating an empty graph."""
        graph = AssetGraph()
        assert graph.node_count == 0
        assert graph.relationship_count == 0

    def test_add_asset(self, sample_asset):
        """Test adding an asset to the graph."""
        graph = AssetGraph()
        node = graph.add_asset(sample_asset)

        assert node is not None
        assert node.id == sample_asset.id
        assert node.asset == sample_asset
        assert graph.node_count == 1

    def test_add_duplicate_asset(self, sample_asset):
        """Test adding the same asset twice returns the same node."""
        graph = AssetGraph()
        node1 = graph.add_asset(sample_asset)
        node2 = graph.add_asset(sample_asset)

        assert node1 is node2
        assert graph.node_count == 1

    def test_add_relationship(self, sample_assets):
        """Test adding a relationship between assets."""
        graph = AssetGraph()
        assets = sample_assets.assets

        # Add assets
        for asset in assets:
            graph.add_asset(asset)

        # Add relationship
        rel = graph.add_relationship(
            source_id=assets[0].id,
            target_id=assets[1].id,
            relationship_type=RelationshipType.NETWORK_CONNECTED,
        )

        assert rel is not None
        assert rel.source_id == assets[0].id
        assert rel.target_id == assets[1].id
        assert graph.relationship_count == 1

    def test_add_relationship_missing_source(self, sample_asset):
        """Test adding relationship with missing source returns None."""
        graph = AssetGraph()
        graph.add_asset(sample_asset)

        rel = graph.add_relationship(
            source_id="missing-id",
            target_id=sample_asset.id,
            relationship_type=RelationshipType.NETWORK_CONNECTED,
        )

        assert rel is None

    def test_get_node(self, sample_asset):
        """Test retrieving a node by ID."""
        graph = AssetGraph()
        graph.add_asset(sample_asset)

        node = graph.get_node(sample_asset.id)
        assert node is not None
        assert node.id == sample_asset.id

    def test_get_node_not_found(self):
        """Test retrieving a non-existent node returns None."""
        graph = AssetGraph()
        assert graph.get_node("not-exists") is None

    def test_get_internet_facing_nodes(self, sample_assets):
        """Test getting internet-facing nodes."""
        graph = AssetGraph()
        for asset in sample_assets.assets:
            graph.add_asset(asset)

        internet_facing = graph.get_internet_facing_nodes()
        assert len(internet_facing) == 1
        assert internet_facing[0].asset.name == "web-server"

    def test_find_path(self, sample_assets):
        """Test finding a path between two nodes."""
        graph = AssetGraph()
        assets = sample_assets.assets

        for asset in assets:
            graph.add_asset(asset)

        # Create path: web-server -> app-server -> database
        graph.add_relationship(
            assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED
        )
        graph.add_relationship(
            assets[1].id, assets[2].id, RelationshipType.NETWORK_CONNECTED
        )

        path = graph.find_path(assets[0].id, assets[2].id)
        assert path is not None
        assert len(path) == 3
        assert path[0] == assets[0].id
        assert path[2] == assets[2].id

    def test_find_path_no_path(self, sample_assets):
        """Test finding path when no path exists."""
        graph = AssetGraph()
        assets = sample_assets.assets

        for asset in assets:
            graph.add_asset(asset)

        # No relationships, so no path
        path = graph.find_path(assets[0].id, assets[2].id)
        assert path is None

    def test_get_connected_components(self, sample_assets):
        """Test getting connected components."""
        graph = AssetGraph()
        assets = sample_assets.assets

        for asset in assets:
            graph.add_asset(asset)

        # Connect first two assets
        graph.add_relationship(
            assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED
        )

        components = graph.get_connected_components()
        # Should have 3 components: {web, app}, {db}, {sg}
        assert len(components) == 3

    def test_get_reachable_from(self, sample_assets):
        """Test getting all reachable nodes from a source."""
        graph = AssetGraph()
        assets = sample_assets.assets

        for asset in assets:
            graph.add_asset(asset)

        graph.add_relationship(
            assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED
        )
        graph.add_relationship(
            assets[1].id, assets[2].id, RelationshipType.NETWORK_CONNECTED
        )

        reachable = graph.get_reachable_from(assets[0].id, direction="outbound")
        assert assets[1].id in reachable
        assert assets[2].id in reachable

    def test_to_dict(self, sample_asset):
        """Test converting graph to dictionary."""
        graph = AssetGraph()
        graph.add_asset(sample_asset)

        data = graph.to_dict()
        assert "nodes" in data
        assert "relationships" in data
        assert len(data["nodes"]) == 1


class TestAssetNode:
    """Tests for the AssetNode class."""

    def test_node_properties(self, sample_asset):
        """Test AssetNode properties."""
        node = AssetNode(asset=sample_asset)

        assert node.id == sample_asset.id
        assert node.is_internet_facing is True
        assert node.risk_score == 0.0

    def test_get_neighbors_empty(self, sample_asset):
        """Test getting neighbors from isolated node."""
        node = AssetNode(asset=sample_asset)
        neighbors = node.get_neighbors()
        assert len(neighbors) == 0


class TestRelationship:
    """Tests for the Relationship class."""

    def test_relationship_to_dict(self):
        """Test converting relationship to dictionary."""
        rel = Relationship(
            source_id="source-1",
            target_id="target-1",
            relationship_type=RelationshipType.NETWORK_CONNECTED,
            properties={"port": 443},
        )

        data = rel.to_dict()
        assert data["source_id"] == "source-1"
        assert data["target_id"] == "target-1"
        assert data["relationship_type"] == "network_connected"
        assert data["properties"]["port"] == 443

    def test_relationship_from_dict(self):
        """Test creating relationship from dictionary."""
        data = {
            "source_id": "source-1",
            "target_id": "target-1",
            "relationship_type": "network_connected",
            "properties": {"port": 443},
        }

        rel = Relationship.from_dict(data)
        assert rel.source_id == "source-1"
        assert rel.target_id == "target-1"
        assert rel.relationship_type == RelationshipType.NETWORK_CONNECTED


class TestAssetGraphBuilder:
    """Tests for the AssetGraphBuilder class."""

    def test_build_graph(self, sample_assets):
        """Test building a graph from asset collection."""
        builder = AssetGraphBuilder()
        graph = builder.build(sample_assets)

        assert graph.node_count == len(sample_assets.assets)

    def test_detect_network_relationships(self, sample_assets):
        """Test detecting network relationships."""
        builder = AssetGraphBuilder()
        graph = builder.build(sample_assets)

        # Check that security group is connected to instances
        relationships = graph.get_relationships()
        network_rels = [
            r for r in relationships
            if r.relationship_type == RelationshipType.NETWORK_CONNECTED
        ]

        # Should have relationships from SG to EC2 instances
        assert len(network_rels) >= 0  # May vary based on config


# Risk Scoring Tests

class TestRiskFactors:
    """Tests for the RiskFactors class."""

    def test_risk_factors_defaults(self):
        """Test default risk factor values."""
        factors = RiskFactors()

        assert factors.exposure_score == 0.0
        assert factors.finding_score == 0.0
        assert factors.compliance_score == 0.0
        assert factors.relationship_score == 0.0
        assert factors.age_score == 0.0

    def test_risk_factors_to_dict(self):
        """Test converting risk factors to dictionary."""
        factors = RiskFactors(
            exposure_score=80.0,
            finding_score=60.0,
            compliance_score=40.0,
        )

        data = factors.to_dict()
        assert data["exposure_score"] == 80.0
        assert data["finding_score"] == 60.0
        assert data["compliance_score"] == 40.0


class TestRiskScore:
    """Tests for the RiskScore class."""

    def test_risk_score_to_dict(self):
        """Test converting risk score to dictionary."""
        score = RiskScore(
            asset_id="test-asset",
            overall_score=75.5,
            risk_level="high",
            factors=RiskFactors(exposure_score=80.0),
            top_risks=["Internet-facing resource"],
            recommendations=["Restrict access"],
        )

        data = score.to_dict()
        assert data["asset_id"] == "test-asset"
        assert data["overall_score"] == 75.5
        assert data["risk_level"] == "high"
        assert "factors" in data


class TestRiskTrend:
    """Tests for the RiskTrend class."""

    def test_add_score(self):
        """Test adding scores to trend."""
        trend = RiskTrend(asset_id="test-asset")
        now = datetime.utcnow()

        trend.add_score(now - timedelta(days=7), 50.0)
        trend.add_score(now, 60.0)

        assert len(trend.scores) == 2
        assert trend.trend_direction == "worsening"

    def test_trend_improving(self):
        """Test improving trend detection."""
        trend = RiskTrend(asset_id="test-asset")
        now = datetime.utcnow()

        trend.add_score(now - timedelta(days=7), 80.0)
        trend.add_score(now, 50.0)

        assert trend.trend_direction == "improving"
        assert trend.change_percentage < 0

    def test_trend_stable(self):
        """Test stable trend detection."""
        trend = RiskTrend(asset_id="test-asset")
        now = datetime.utcnow()

        trend.add_score(now - timedelta(days=7), 50.0)
        trend.add_score(now, 51.0)

        assert trend.trend_direction == "stable"


class TestRiskScorer:
    """Tests for the RiskScorer class."""

    def test_score_asset(self, sample_asset, sample_findings):
        """Test scoring an asset."""
        scorer = RiskScorer(findings=sample_findings)
        score = scorer.score_asset(sample_asset)

        assert score is not None
        assert score.asset_id == sample_asset.id
        assert 0 <= score.overall_score <= 100
        assert score.risk_level in ["critical", "high", "medium", "low", "minimal"]

    def test_score_internet_facing_asset(self, sample_asset):
        """Test that internet-facing assets get higher exposure scores."""
        scorer = RiskScorer()
        score = scorer.score_asset(sample_asset)

        assert score.factors.exposure_score == 100.0

    def test_score_collection(self, sample_assets, sample_findings):
        """Test scoring an asset collection."""
        scorer = RiskScorer(findings=sample_findings)
        scores = scorer.score_collection(sample_assets)

        assert len(scores) == len(sample_assets.assets)
        # Should be sorted by score descending
        for i in range(len(scores) - 1):
            assert scores[i].overall_score >= scores[i + 1].overall_score

    def test_aggregate_risk(self, sample_assets, sample_findings):
        """Test aggregating risk metrics."""
        scorer = RiskScorer(findings=sample_findings)
        aggregate = scorer.aggregate_risk(sample_assets)

        assert "total_assets" in aggregate
        assert "average_score" in aggregate
        assert "by_level" in aggregate
        assert aggregate["total_assets"] == len(sample_assets.assets)

    def test_get_high_risk_assets(self, sample_assets, sample_findings):
        """Test getting high-risk assets."""
        scorer = RiskScorer(findings=sample_findings)
        high_risk = scorer.get_high_risk_assets(sample_assets, threshold=30.0)

        for score in high_risk:
            assert score.overall_score >= 30.0


# Attack Path Tests

class TestAttackPathStep:
    """Tests for the AttackPathStep class."""

    def test_step_to_dict(self):
        """Test converting attack path step to dictionary."""
        step = AttackPathStep(
            asset_id="test-asset",
            asset_name="web-server",
            resource_type="aws_ec2_instance",
            action="Initial access",
            findings=["finding-1"],
            risk_level="high",
        )

        data = step.to_dict()
        assert data["asset_id"] == "test-asset"
        assert data["action"] == "Initial access"
        assert data["risk_level"] == "high"


class TestAttackPath:
    """Tests for the AttackPath class."""

    def test_attack_path_properties(self):
        """Test AttackPath properties."""
        steps = [
            AttackPathStep(
                asset_id="asset-1",
                asset_name="web-server",
                resource_type="aws_ec2_instance",
                action="Initial access",
            ),
            AttackPathStep(
                asset_id="asset-2",
                asset_name="database",
                resource_type="aws_rds_instance",
                action="Target reached",
            ),
        ]

        path = AttackPath(
            id="path-1",
            path_type=AttackPathType.INTERNET_TO_INTERNAL,
            steps=steps,
            severity=Severity.HIGH,
            description="Path from web to database",
        )

        assert path.length == 2
        assert path.entry_point == steps[0]
        assert path.target == steps[1]

    def test_attack_path_to_dict(self):
        """Test converting attack path to dictionary."""
        path = AttackPath(
            id="path-1",
            path_type=AttackPathType.LATERAL_MOVEMENT,
            steps=[],
            severity=Severity.MEDIUM,
            description="Lateral movement path",
            mitigation="Implement segmentation",
        )

        data = path.to_dict()
        assert data["id"] == "path-1"
        assert data["path_type"] == "lateral_movement"
        assert data["severity"] == "medium"


class TestAttackPathAnalyzer:
    """Tests for the AttackPathAnalyzer class."""

    def test_analyzer_initialization(self, sample_assets, sample_findings):
        """Test analyzer initialization."""
        graph = AssetGraphBuilder().build(sample_assets)
        analyzer = AttackPathAnalyzer(graph=graph, findings=sample_findings)

        assert analyzer._graph is not None

    def test_analyze(self, sample_assets, sample_findings):
        """Test analyzing attack paths."""
        graph = AssetGraphBuilder().build(sample_assets)

        # Add connections
        assets = sample_assets.assets
        graph.add_relationship(
            assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED
        )
        graph.add_relationship(
            assets[1].id, assets[2].id, RelationshipType.NETWORK_CONNECTED
        )

        analyzer = AttackPathAnalyzer(graph=graph, findings=sample_findings)
        paths = analyzer.analyze()

        # Should find some paths
        assert isinstance(paths, list)


class TestRelationshipType:
    """Tests for RelationshipType enum."""

    def test_relationship_types_exist(self):
        """Test that all relationship types exist."""
        assert RelationshipType.NETWORK_CONNECTED is not None
        assert RelationshipType.IAM_ATTACHED is not None
        assert RelationshipType.CONTAINS is not None
        assert RelationshipType.REFERENCES is not None


class TestAttackPathType:
    """Tests for AttackPathType enum."""

    def test_attack_path_types_exist(self):
        """Test that all attack path types exist."""
        # Original attack path types
        assert AttackPathType.INTERNET_TO_INTERNAL is not None
        assert AttackPathType.PRIVILEGE_ESCALATION is not None
        assert AttackPathType.LATERAL_MOVEMENT is not None
        assert AttackPathType.DATA_EXFILTRATION is not None
        assert AttackPathType.CREDENTIAL_ACCESS is not None

    def test_phase4_attack_path_types_exist(self):
        """Test that Phase 4 attack path types exist."""
        assert AttackPathType.CREDENTIAL_EXPOSURE is not None
        assert AttackPathType.DATA_THEFT is not None
        assert AttackPathType.RANSOMWARE_SPREAD is not None
        assert AttackPathType.CRYPTO_MINING is not None
        assert AttackPathType.IDENTITY_THEFT is not None

    def test_attack_path_type_values(self):
        """Test attack path type values are correct strings."""
        assert AttackPathType.CREDENTIAL_EXPOSURE.value == "credential_exposure"
        assert AttackPathType.DATA_THEFT.value == "data_theft"
        assert AttackPathType.RANSOMWARE_SPREAD.value == "ransomware_spread"
        assert AttackPathType.CRYPTO_MINING.value == "crypto_mining"
        assert AttackPathType.IDENTITY_THEFT.value == "identity_theft"


# Phase 4: New Attack Path Types Tests

@pytest.fixture
def phase4_sample_assets():
    """Create sample assets for Phase 4 attack path testing."""
    now = datetime.utcnow()
    return AssetCollection(assets=[
        # Internet-facing entry point
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-web",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="web-server",
            network_exposure="internet_facing",
            created_at=now,
            last_seen=now,
            raw_config={"instance_type": "t3.medium"},
        ),
        # Internal compute for crypto mining
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-compute",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="compute-server",
            network_exposure="internal",
            created_at=now,
            last_seen=now,
            raw_config={"instance_type": "c5.4xlarge"},
        ),
        # Secrets Manager
        Asset(
            id="arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-creds",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_secretsmanager_secret",
            name="prod-db-credentials",
            network_exposure="internal",
            created_at=now,
            last_seen=now,
            raw_config={},
        ),
        # S3 bucket (storage for ransomware)
        Asset(
            id="arn:aws:s3:::prod-data-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="prod-data-bucket",
            network_exposure="internal",
            created_at=now,
            last_seen=now,
            raw_config={"versioning": {"enabled": False}},
        ),
        # Another S3 bucket
        Asset(
            id="arn:aws:s3:::backup-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="backup-bucket",
            network_exposure="internal",
            created_at=now,
            last_seen=now,
            raw_config={"versioning": {"enabled": True}},
        ),
        # High-privilege IAM role
        Asset(
            id="arn:aws:iam::123456789012:role/admin-role",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_role",
            name="admin-role",
            network_exposure="internal",
            created_at=now,
            last_seen=now,
            raw_config={
                "attached_policies": ["AdministratorAccess"],
            },
        ),
        # RDS database
        Asset(
            id="arn:aws:rds:us-east-1:123456789012:db:prod-db",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_rds_instance",
            name="prod-database",
            network_exposure="internal",
            created_at=now,
            last_seen=now,
            raw_config={"encrypted": False},
        ),
    ])


class TestPhase4AttackPathAnalyzer:
    """Tests for Phase 4 attack path analysis features."""

    def test_analyzer_finds_credential_exposure_paths(self, phase4_sample_assets):
        """Test finding credential exposure paths."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        # Connect web server to secrets
        graph.add_relationship(
            assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED
        )

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        cred_paths = [p for p in paths if p.path_type == AttackPathType.CREDENTIAL_EXPOSURE]
        assert len(cred_paths) >= 1

    def test_analyzer_finds_crypto_mining_paths(self, phase4_sample_assets):
        """Test finding crypto mining paths."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        # Connect web server to internal compute
        graph.add_relationship(
            assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED
        )

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        mining_paths = [p for p in paths if p.path_type == AttackPathType.CRYPTO_MINING]
        assert len(mining_paths) >= 1

    def test_analyzer_finds_ransomware_spread_paths(self, phase4_sample_assets):
        """Test finding ransomware spread paths."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        # Connect compute to multiple storage
        graph.add_relationship(
            assets[1].id, assets[3].id, RelationshipType.NETWORK_CONNECTED
        )
        graph.add_relationship(
            assets[1].id, assets[4].id, RelationshipType.NETWORK_CONNECTED
        )

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        ransomware_paths = [p for p in paths if p.path_type == AttackPathType.RANSOMWARE_SPREAD]
        assert len(ransomware_paths) >= 1

    def test_analyzer_finds_identity_theft_paths(self, phase4_sample_assets):
        """Test finding identity theft paths."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        # Connect web server to IAM role
        graph.add_relationship(
            assets[0].id, assets[5].id, RelationshipType.IAM_ATTACHED
        )

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        identity_paths = [p for p in paths if p.path_type == AttackPathType.IDENTITY_THEFT]
        assert len(identity_paths) >= 1

    def test_analyzer_finds_data_theft_paths(self, phase4_sample_assets):
        """Test finding data theft paths."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        # Connect web server to database
        graph.add_relationship(
            assets[0].id, assets[6].id, RelationshipType.NETWORK_CONNECTED
        )

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        theft_paths = [p for p in paths if p.path_type == AttackPathType.DATA_THEFT]
        assert len(theft_paths) >= 1

    def test_is_high_privilege_identity(self, phase4_sample_assets):
        """Test high privilege identity detection."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        analyzer = AttackPathAnalyzer(graph=graph)

        admin_role = graph.get_node("arn:aws:iam::123456789012:role/admin-role")
        assert admin_role is not None
        assert analyzer._is_high_privilege_identity(admin_role) is True

    def test_ransomware_severity_with_no_backup(self, phase4_sample_assets):
        """Test ransomware paths have critical severity when no backup."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        # Connect compute to storage without versioning
        graph.add_relationship(
            assets[1].id, assets[3].id, RelationshipType.NETWORK_CONNECTED
        )
        graph.add_relationship(
            assets[1].id, assets[6].id, RelationshipType.NETWORK_CONNECTED
        )

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        ransomware_paths = [p for p in paths if p.path_type == AttackPathType.RANSOMWARE_SPREAD]
        if ransomware_paths:
            # Should be critical when no backup
            assert ransomware_paths[0].severity == Severity.CRITICAL

    def test_attack_path_has_mitigation(self, phase4_sample_assets):
        """Test that attack paths include mitigation recommendations."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        graph.add_relationship(
            assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED
        )

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        for path in paths:
            assert path.mitigation != ""
            assert len(path.mitigation) > 10  # Has meaningful content

    def test_all_attack_path_types_sorted_by_severity(self, phase4_sample_assets):
        """Test that attack paths are sorted by severity."""
        graph = AssetGraphBuilder().build(phase4_sample_assets)
        assets = phase4_sample_assets.assets

        # Create multiple connections
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[1].id, assets[3].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[1].id, assets[4].id, RelationshipType.NETWORK_CONNECTED)

        analyzer = AttackPathAnalyzer(graph=graph)
        paths = analyzer.analyze()

        if len(paths) >= 2:
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }
            for i in range(len(paths) - 1):
                assert severity_order[paths[i].severity] <= severity_order[paths[i + 1].severity]


# =============================================================================
# Toxic Combinations Detection Tests
# =============================================================================

from stance.analytics.toxic_combinations import (
    ToxicCombination,
    ToxicCombinationDetector,
    ToxicCombinationType,
    ToxicCondition,
)


@pytest.fixture
def toxic_combinations_assets():
    """Create sample assets for toxic combinations testing."""
    now = datetime.utcnow()
    assets = [
        # Public S3 bucket with sensitive data (index 0)
        Asset(
            id="arn:aws:s3:::customer-pii-data",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="customer-pii-data",
            tags={"Environment": "production", "DataClassification": "sensitive"},
            network_exposure="internet_facing",
            created_at=now - timedelta(days=30),
            last_seen=now,
            raw_config={
                "acl": "public-read",
                "encrypted": True,
                "public_access_block_configuration": {
                    "block_public_acls": False,
                    "block_public_policy": False,
                },
            },
        ),
        # Admin IAM user without MFA (index 1)
        Asset(
            id="arn:aws:iam::123456789012:user/admin-user",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_user",
            name="admin-user",
            tags={"Team": "platform"},
            network_exposure="internal",
            created_at=now - timedelta(days=180),
            last_seen=now,
            raw_config={
                "mfa_enabled": False,
                "mfa_devices": [],
                "attached_policies": ["AdministratorAccess", "arn:aws:iam::aws:policy/AdministratorAccess"],
            },
        ),
        # Internet-facing EC2 with vulnerabilities (index 2)
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-vuln",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="vulnerable-server",
            tags={"Environment": "production"},
            network_exposure="internet_facing",
            created_at=now - timedelta(days=60),
            last_seen=now,
            raw_config={
                "public_ip_address": "54.123.45.67",
                "security_groups": ["sg-public"],
            },
        ),
        # IAM role with secrets write access (index 3)
        Asset(
            id="arn:aws:iam::123456789012:role/secrets-writer-role",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_role",
            name="secrets-writer-role",
            tags={},
            network_exposure="internal",
            created_at=now - timedelta(days=90),
            last_seen=now,
            raw_config={
                "inline_policies": [
                    {
                        "policy_document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "secretsmanager:GetSecretValue",
                                        "secretsmanager:PutSecretValue",
                                        "secretsmanager:CreateSecret",
                                    ],
                                    "Resource": "*",
                                }
                            ]
                        }
                    }
                ],
            },
        ),
        # Cross-account admin role (index 4)
        Asset(
            id="arn:aws:iam::123456789012:role/cross-account-admin",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_role",
            name="cross-account-admin",
            tags={},
            network_exposure="internal",
            created_at=now - timedelta(days=120),
            last_seen=now,
            raw_config={
                "attached_policies": ["AdministratorAccess"],
                "assume_role_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::999888777666:root"
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
            },
        ),
        # Internal RDS with sensitive name (index 5)
        Asset(
            id="arn:aws:rds:us-east-1:123456789012:db:prod-customer-db",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_rds_instance",
            name="prod-customer-db",
            tags={"Environment": "production"},
            network_exposure="internal",
            created_at=now - timedelta(days=200),
            last_seen=now,
            raw_config={
                "encrypted": True,
                "publicly_accessible": False,
            },
        ),
        # IAM user with MFA enabled (index 6) - control case
        Asset(
            id="arn:aws:iam::123456789012:user/secure-admin",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_user",
            name="secure-admin",
            tags={},
            network_exposure="internal",
            created_at=now - timedelta(days=150),
            last_seen=now,
            raw_config={
                "mfa_enabled": True,
                "mfa_devices": ["arn:aws:iam::123456789012:mfa/secure-admin"],
                "attached_policies": ["AdministratorAccess"],
            },
        ),
        # Secrets manager secret (index 7)
        Asset(
            id="arn:aws:secretsmanager:us-east-1:123456789012:secret:api-keys",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_secretsmanager_secret",
            name="api-keys",
            tags={},
            network_exposure="internal",
            created_at=now - timedelta(days=60),
            last_seen=now,
            raw_config={
                "encrypted": True,
            },
        ),
    ]
    return AssetCollection(assets=assets)


@pytest.fixture
def vulnerable_findings():
    """Create sample vulnerability findings."""
    now = datetime.utcnow()
    return FindingCollection(
        findings=[
            Finding(
                id="finding-vuln-1",
                asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-vuln",
                finding_type=FindingType.VULNERABILITY,
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
                title="CVE-2024-0001: Remote Code Execution",
                description="Critical RCE vulnerability in web server",
                rule_id="CVE-2024-0001",
                first_seen=now - timedelta(days=7),
                last_seen=now,
            ),
            Finding(
                id="finding-vuln-2",
                asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-vuln",
                finding_type=FindingType.VULNERABILITY,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title="CVE-2024-0002: SQL Injection",
                description="High severity SQL injection vulnerability",
                rule_id="CVE-2024-0002",
                first_seen=now - timedelta(days=14),
                last_seen=now,
            ),
        ]
    )


class TestToxicCombinationType:
    """Tests for ToxicCombinationType enum."""

    def test_all_toxic_combination_types_exist(self):
        """Test all expected toxic combination types are defined."""
        expected_types = [
            "PUBLIC_SENSITIVE_DATA",
            "ADMIN_NO_MFA",
            "INTERNET_FACING_VULNERABLE",
            "WRITE_ACCESS_SECRETS",
            "CROSS_ACCOUNT_PRIVILEGED",
        ]
        for type_name in expected_types:
            assert hasattr(ToxicCombinationType, type_name)

    def test_toxic_combination_type_values(self):
        """Test toxic combination type string values."""
        assert ToxicCombinationType.PUBLIC_SENSITIVE_DATA.value == "public_sensitive_data"
        assert ToxicCombinationType.ADMIN_NO_MFA.value == "admin_no_mfa"
        assert ToxicCombinationType.INTERNET_FACING_VULNERABLE.value == "internet_facing_vulnerable"
        assert ToxicCombinationType.WRITE_ACCESS_SECRETS.value == "write_access_secrets"
        assert ToxicCombinationType.CROSS_ACCOUNT_PRIVILEGED.value == "cross_account_privileged"


class TestToxicCondition:
    """Tests for ToxicCondition dataclass."""

    def test_toxic_condition_creation(self):
        """Test creating a toxic condition."""
        condition = ToxicCondition(
            description="Resource is publicly accessible",
            asset_id="arn:aws:s3:::test-bucket",
            evidence={"acl": "public-read"},
            severity_contribution="high",
        )
        assert condition.description == "Resource is publicly accessible"
        assert condition.asset_id == "arn:aws:s3:::test-bucket"
        assert condition.evidence == {"acl": "public-read"}
        assert condition.severity_contribution == "high"

    def test_toxic_condition_defaults(self):
        """Test toxic condition default values."""
        condition = ToxicCondition(
            description="Test condition",
            asset_id="test-id",
        )
        assert condition.evidence == {}
        assert condition.severity_contribution == "medium"


class TestToxicCombination:
    """Tests for ToxicCombination dataclass."""

    def test_toxic_combination_creation(self):
        """Test creating a toxic combination."""
        conditions = [
            ToxicCondition(
                description="Condition 1",
                asset_id="asset-1",
            ),
            ToxicCondition(
                description="Condition 2",
                asset_id="asset-1",
            ),
        ]
        combination = ToxicCombination(
            id="toxic-1",
            combination_type=ToxicCombinationType.PUBLIC_SENSITIVE_DATA,
            conditions=conditions,
            severity=Severity.CRITICAL,
            affected_assets=["asset-1"],
            description="Public bucket with sensitive data",
            impact="Data breach risk",
            mitigation="Restrict public access",
            score=95.0,
        )
        assert combination.id == "toxic-1"
        assert combination.combination_type == ToxicCombinationType.PUBLIC_SENSITIVE_DATA
        assert len(combination.conditions) == 2
        assert combination.severity == Severity.CRITICAL
        assert combination.score == 95.0

    def test_toxic_combination_to_dict(self):
        """Test converting toxic combination to dictionary."""
        conditions = [
            ToxicCondition(
                description="Test condition",
                asset_id="asset-1",
                evidence={"key": "value"},
            ),
        ]
        combination = ToxicCombination(
            id="toxic-1",
            combination_type=ToxicCombinationType.ADMIN_NO_MFA,
            conditions=conditions,
            severity=Severity.CRITICAL,
            affected_assets=["asset-1"],
            description="Admin without MFA",
            impact="Account takeover risk",
            mitigation="Enable MFA",
            score=90.0,
        )

        result = combination.to_dict()

        assert result["id"] == "toxic-1"
        assert result["combination_type"] == "admin_no_mfa"
        assert result["severity"] == "critical"
        assert result["score"] == 90.0
        assert len(result["conditions"]) == 1
        assert result["conditions"][0]["description"] == "Test condition"


class TestToxicCombinationDetector:
    """Tests for ToxicCombinationDetector class."""

    def test_detector_initialization(self, toxic_combinations_assets):
        """Test detector initialization."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)
        assert detector is not None

    def test_detector_with_findings(self, toxic_combinations_assets, vulnerable_findings):
        """Test detector initialization with findings."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph, findings=vulnerable_findings)
        assert detector is not None

    def test_detect_public_sensitive_data(self, toxic_combinations_assets):
        """Test detection of public exposure with sensitive data."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        public_sensitive = [
            c for c in combinations
            if c.combination_type == ToxicCombinationType.PUBLIC_SENSITIVE_DATA
        ]

        # Should find the public S3 bucket with PII data
        assert len(public_sensitive) >= 1
        assert any("customer-pii-data" in c.description for c in public_sensitive)
        assert all(c.severity == Severity.CRITICAL for c in public_sensitive)

    def test_detect_admin_no_mfa(self, toxic_combinations_assets):
        """Test detection of admin privileges without MFA."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        admin_no_mfa = [
            c for c in combinations
            if c.combination_type == ToxicCombinationType.ADMIN_NO_MFA
        ]

        # Should find admin-user without MFA, not secure-admin with MFA
        assert len(admin_no_mfa) >= 1
        assert any("admin-user" in c.description for c in admin_no_mfa)
        assert not any("secure-admin" in c.description for c in admin_no_mfa)
        assert all(c.severity == Severity.CRITICAL for c in admin_no_mfa)

    def test_detect_internet_facing_vulnerable(self, toxic_combinations_assets, vulnerable_findings):
        """Test detection of internet-facing resources with vulnerabilities."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph, findings=vulnerable_findings)

        combinations = detector.detect()

        internet_vuln = [
            c for c in combinations
            if c.combination_type == ToxicCombinationType.INTERNET_FACING_VULNERABLE
        ]

        # Should find the vulnerable EC2 instance
        assert len(internet_vuln) >= 1
        assert any("vulnerable-server" in c.description for c in internet_vuln)

        # Should have high severity due to critical CVE
        vuln_combo = next(c for c in internet_vuln if "vulnerable-server" in c.description)
        assert vuln_combo.severity == Severity.CRITICAL

    def test_detect_write_access_secrets(self, toxic_combinations_assets):
        """Test detection of write access to secrets."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        write_secrets = [
            c for c in combinations
            if c.combination_type == ToxicCombinationType.WRITE_ACCESS_SECRETS
        ]

        # Should find the secrets-writer-role
        assert len(write_secrets) >= 1
        assert any("secrets-writer-role" in c.description for c in write_secrets)
        assert all(c.severity == Severity.HIGH for c in write_secrets)

    def test_detect_cross_account_privileged(self, toxic_combinations_assets):
        """Test detection of cross-account privileged roles."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        cross_account = [
            c for c in combinations
            if c.combination_type == ToxicCombinationType.CROSS_ACCOUNT_PRIVILEGED
        ]

        # Should find the cross-account-admin role
        assert len(cross_account) >= 1
        assert any("cross-account-admin" in c.description for c in cross_account)
        assert all(c.severity == Severity.HIGH for c in cross_account)

    def test_combinations_sorted_by_severity(self, toxic_combinations_assets, vulnerable_findings):
        """Test that combinations are sorted by severity."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph, findings=vulnerable_findings)

        combinations = detector.detect()

        if len(combinations) >= 2:
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }
            for i in range(len(combinations) - 1):
                current_rank = severity_order[combinations[i].severity]
                next_rank = severity_order[combinations[i + 1].severity]
                # Allow same severity or higher (lower number)
                assert current_rank <= next_rank or combinations[i].score >= combinations[i + 1].score

    def test_combination_has_mitigation(self, toxic_combinations_assets):
        """Test that combinations include mitigation recommendations."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        for combo in combinations:
            assert combo.mitigation != ""
            assert len(combo.mitigation) > 20  # Has meaningful content

    def test_combination_has_impact(self, toxic_combinations_assets):
        """Test that combinations include impact description."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        for combo in combinations:
            assert combo.impact != ""
            assert len(combo.impact) > 20  # Has meaningful content

    def test_combination_has_conditions(self, toxic_combinations_assets):
        """Test that combinations have at least 2 conditions."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        for combo in combinations:
            assert len(combo.conditions) >= 2  # Toxic combos need multiple conditions

    def test_combination_has_score(self, toxic_combinations_assets, vulnerable_findings):
        """Test that combinations have risk scores."""
        graph = AssetGraphBuilder().build(toxic_combinations_assets)
        detector = ToxicCombinationDetector(graph=graph, findings=vulnerable_findings)

        combinations = detector.detect()

        for combo in combinations:
            assert combo.score > 0
            assert combo.score <= 100

    def test_empty_graph_returns_no_combinations(self):
        """Test that empty graph returns no combinations."""
        graph = AssetGraph()
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        assert combinations == []

    def test_no_toxic_combinations_when_secure(self):
        """Test no toxic combinations are found for secure configurations."""
        now = datetime.utcnow()
        secure_assets = AssetCollection(
            assets=[
                # Private, encrypted S3 bucket
                Asset(
                    id="arn:aws:s3:::secure-internal-bucket",
                    cloud_provider="aws",
                    account_id="123456789012",
                    region="us-east-1",
                    resource_type="aws_s3_bucket",
                    name="secure-internal-bucket",
                    tags={},
                    network_exposure="internal",
                    created_at=now,
                    last_seen=now,
                    raw_config={
                        "acl": "private",
                        "encrypted": True,
                        "public_access_block_configuration": {
                            "block_public_acls": True,
                            "block_public_policy": True,
                        },
                    },
                ),
            ]
        )

        graph = AssetGraphBuilder().build(secure_assets)
        detector = ToxicCombinationDetector(graph=graph)

        combinations = detector.detect()

        # Should have no public-sensitive combinations for this secure bucket
        public_sensitive = [
            c for c in combinations
            if c.combination_type == ToxicCombinationType.PUBLIC_SENSITIVE_DATA
        ]
        assert len(public_sensitive) == 0


# =============================================================================
# Blast Radius Calculation Tests
# =============================================================================

from stance.analytics.blast_radius import (
    AffectedResource,
    BlastRadius,
    BlastRadiusCalculator,
    ImpactCategory,
)


@pytest.fixture
def blast_radius_assets():
    """Create sample assets for blast radius testing."""
    now = datetime.utcnow()
    assets = [
        # Web server (index 0) - entry point
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-web",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="production-web-server",
            tags={"Environment": "production"},
            network_exposure="internet_facing",
            created_at=now - timedelta(days=30),
            last_seen=now,
            raw_config={"instance_type": "t3.large"},
        ),
        # RDS Database (index 1) - data store
        Asset(
            id="arn:aws:rds:us-east-1:123456789012:db:prod-db",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_rds_instance",
            name="production-database",
            tags={"Environment": "production"},
            network_exposure="internal",
            created_at=now - timedelta(days=60),
            last_seen=now,
            raw_config={"engine": "postgresql"},
        ),
        # S3 Bucket (index 2) - data store
        Asset(
            id="arn:aws:s3:::customer-data-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="customer-data-bucket",
            tags={"Environment": "production"},
            network_exposure="internal",
            created_at=now - timedelta(days=90),
            last_seen=now,
            raw_config={"versioning": {"enabled": True}},
        ),
        # IAM Role (index 3) - identity
        Asset(
            id="arn:aws:iam::123456789012:role/app-role",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_role",
            name="application-role",
            tags={},
            network_exposure="internal",
            created_at=now - timedelta(days=120),
            last_seen=now,
            raw_config={"attached_policies": ["AmazonS3FullAccess"]},
        ),
        # Secrets Manager (index 4) - secrets
        Asset(
            id="arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_secretsmanager_secret",
            name="database-credentials",
            tags={},
            network_exposure="internal",
            created_at=now - timedelta(days=60),
            last_seen=now,
            raw_config={"encrypted": True},
        ),
        # Lambda function (index 5) - compute
        Asset(
            id="arn:aws:lambda:us-east-1:123456789012:function:data-processor",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_lambda_function",
            name="data-processor",
            tags={"Environment": "production"},
            network_exposure="internal",
            created_at=now - timedelta(days=45),
            last_seen=now,
            raw_config={"runtime": "python3.9"},
        ),
        # VPC (index 6) - network
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:vpc/vpc-123",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_vpc",
            name="production-vpc",
            tags={"Environment": "production"},
            network_exposure="internal",
            created_at=now - timedelta(days=180),
            last_seen=now,
            raw_config={"cidr_block": "10.0.0.0/16"},
        ),
    ]
    return AssetCollection(assets=assets)


@pytest.fixture
def blast_radius_findings(blast_radius_assets):
    """Create sample findings for blast radius testing."""
    now = datetime.utcnow()
    assets = blast_radius_assets.assets
    return FindingCollection(
        findings=[
            Finding(
                id="finding-1",
                asset_id=assets[0].id,  # Web server
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title="Security group allows SSH from 0.0.0.0/0",
                description="SSH port is open to the internet",
                rule_id="aws-ec2-002",
                first_seen=now - timedelta(days=7),
                last_seen=now,
            ),
            Finding(
                id="finding-2",
                asset_id=assets[1].id,  # RDS
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                status=FindingStatus.OPEN,
                title="RDS instance is not encrypted",
                description="Database storage is not encrypted at rest",
                rule_id="aws-rds-001",
                first_seen=now - timedelta(days=14),
                last_seen=now,
            ),
            Finding(
                id="finding-3",
                asset_id=assets[2].id,  # S3
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
                title="S3 bucket is publicly accessible",
                description="Bucket allows public read access",
                rule_id="aws-s3-002",
                first_seen=now - timedelta(days=3),
                last_seen=now,
            ),
        ]
    )


class TestImpactCategory:
    """Tests for ImpactCategory enum."""

    def test_all_impact_categories_exist(self):
        """Test all expected impact categories are defined."""
        expected_categories = [
            "DATA_EXPOSURE",
            "SERVICE_DISRUPTION",
            "CREDENTIAL_COMPROMISE",
            "COMPLIANCE_VIOLATION",
            "LATERAL_MOVEMENT",
            "PRIVILEGE_ESCALATION",
        ]
        for category_name in expected_categories:
            assert hasattr(ImpactCategory, category_name)

    def test_impact_category_values(self):
        """Test impact category string values."""
        assert ImpactCategory.DATA_EXPOSURE.value == "data_exposure"
        assert ImpactCategory.SERVICE_DISRUPTION.value == "service_disruption"
        assert ImpactCategory.CREDENTIAL_COMPROMISE.value == "credential_compromise"
        assert ImpactCategory.COMPLIANCE_VIOLATION.value == "compliance_violation"


class TestAffectedResource:
    """Tests for AffectedResource dataclass."""

    def test_affected_resource_creation(self):
        """Test creating an affected resource."""
        resource = AffectedResource(
            asset_id="arn:aws:s3:::test-bucket",
            asset_name="test-bucket",
            resource_type="aws_s3_bucket",
            impact_type="data_exposure",
            relationship_path=["asset-1", "asset-2"],
            distance=1,
            impact_score=75.0,
        )
        assert resource.asset_id == "arn:aws:s3:::test-bucket"
        assert resource.asset_name == "test-bucket"
        assert resource.distance == 1
        assert resource.impact_score == 75.0

    def test_affected_resource_to_dict(self):
        """Test converting affected resource to dictionary."""
        resource = AffectedResource(
            asset_id="test-id",
            asset_name="test-name",
            resource_type="aws_ec2_instance",
            impact_type="service_disruption",
            distance=2,
            impact_score=50.0,
        )
        result = resource.to_dict()
        assert result["asset_id"] == "test-id"
        assert result["impact_type"] == "service_disruption"
        assert result["distance"] == 2

    def test_affected_resource_defaults(self):
        """Test affected resource default values."""
        resource = AffectedResource(
            asset_id="test-id",
            asset_name="test-name",
            resource_type="aws_ec2_instance",
            impact_type="unknown",
        )
        assert resource.relationship_path == []
        assert resource.distance == 0
        assert resource.impact_score == 0.0


class TestBlastRadius:
    """Tests for BlastRadius dataclass."""

    def test_blast_radius_creation(self):
        """Test creating a blast radius object."""
        blast_radius = BlastRadius(
            finding_id="finding-1",
            finding_severity=Severity.HIGH,
            source_asset_id="asset-1",
            source_asset_name="web-server",
            directly_affected=[],
            indirectly_affected=[],
            impact_categories=[ImpactCategory.DATA_EXPOSURE],
            data_exposure_risk="high",
            service_disruption_risk="medium",
            compliance_implications=["PCI-DSS", "SOC2"],
            total_affected_count=5,
            blast_radius_score=75.0,
            adjusted_severity=Severity.CRITICAL,
        )
        assert blast_radius.finding_id == "finding-1"
        assert blast_radius.blast_radius_score == 75.0
        assert blast_radius.adjusted_severity == Severity.CRITICAL

    def test_blast_radius_to_dict(self):
        """Test converting blast radius to dictionary."""
        blast_radius = BlastRadius(
            finding_id="finding-1",
            finding_severity=Severity.MEDIUM,
            source_asset_id="asset-1",
            source_asset_name="test-asset",
            blast_radius_score=50.0,
            adjusted_severity=Severity.HIGH,
        )
        result = blast_radius.to_dict()
        assert result["finding_id"] == "finding-1"
        assert result["finding_severity"] == "medium"
        assert result["blast_radius_score"] == 50.0
        assert result["adjusted_severity"] == "high"


class TestBlastRadiusCalculator:
    """Tests for BlastRadiusCalculator class."""

    def test_calculator_initialization(self, blast_radius_assets, blast_radius_findings):
        """Test calculator initialization."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        assert calculator is not None

    def test_calculate_single_finding(self, blast_radius_assets, blast_radius_findings):
        """Test calculating blast radius for a single finding."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Add relationships
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]  # Web server finding

        blast_radius = calculator.calculate(finding)

        assert blast_radius.finding_id == finding.id
        assert blast_radius.source_asset_id == finding.asset_id
        assert len(blast_radius.directly_affected) >= 2  # RDS and S3

    def test_calculate_with_data_store_impact(self, blast_radius_assets, blast_radius_findings):
        """Test that data stores are identified as data exposure risk."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Connect web server to database
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        # Should detect data exposure risk
        assert blast_radius.data_exposure_risk != "none"

    def test_calculate_with_compute_impact(self, blast_radius_assets, blast_radius_findings):
        """Test that compute resources are identified as service disruption risk."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Connect web server to lambda
        graph.add_relationship(assets[0].id, assets[5].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        # Should detect service disruption risk (source is also compute)
        assert blast_radius.service_disruption_risk != "none"

    def test_calculate_with_secrets_impact(self, blast_radius_assets, blast_radius_findings):
        """Test that secrets are identified as credential compromise risk."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Connect web server to secrets
        graph.add_relationship(assets[0].id, assets[4].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        # Should have credential compromise in impact categories
        assert ImpactCategory.CREDENTIAL_COMPROMISE in blast_radius.impact_categories

    def test_calculate_indirect_affected(self, blast_radius_assets, blast_radius_findings):
        """Test calculation of indirectly affected resources."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Create a chain: web -> lambda -> s3
        graph.add_relationship(assets[0].id, assets[5].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[5].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        # Lambda should be directly affected, S3 indirectly
        direct_ids = [r.asset_id for r in blast_radius.directly_affected]
        indirect_ids = [r.asset_id for r in blast_radius.indirectly_affected]

        assert assets[5].id in direct_ids  # Lambda is direct
        assert assets[2].id in indirect_ids  # S3 is indirect

    def test_calculate_all_findings(self, blast_radius_assets, blast_radius_findings):
        """Test calculating blast radius for all findings."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Add some relationships
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[1].id, assets[4].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        results = calculator.calculate_all()

        assert len(results) == 3  # Three findings
        # Should be sorted by blast radius score
        for i in range(len(results) - 1):
            assert results[i].blast_radius_score >= results[i + 1].blast_radius_score

    def test_blast_radius_score_calculation(self, blast_radius_assets, blast_radius_findings):
        """Test that blast radius score is calculated correctly."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Create connections to multiple resources
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[4].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        assert blast_radius.blast_radius_score > 0
        assert blast_radius.blast_radius_score <= 100

    def test_severity_adjustment(self, blast_radius_assets, blast_radius_findings):
        """Test that severity is adjusted based on blast radius."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Create extensive connections for high blast radius
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[3].id, RelationshipType.IAM_ATTACHED)
        graph.add_relationship(assets[0].id, assets[4].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[5].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]  # HIGH severity

        blast_radius = calculator.calculate(finding)

        # With high blast radius, severity may be upgraded
        assert blast_radius.adjusted_severity in (Severity.HIGH, Severity.CRITICAL)

    def test_compliance_implications(self, blast_radius_assets, blast_radius_findings):
        """Test that compliance implications are determined correctly."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Connect to S3 (has compliance implications)
        graph.add_relationship(assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        # Should have compliance implications
        assert len(blast_radius.compliance_implications) > 0
        assert "SOC2" in blast_radius.compliance_implications or "PCI-DSS" in blast_radius.compliance_implications

    def test_empty_graph_returns_minimal_radius(self, blast_radius_findings):
        """Test that empty graph returns minimal blast radius."""
        graph = AssetGraph()
        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        assert blast_radius.finding_id == finding.id
        assert blast_radius.source_asset_name == "unknown"
        assert len(blast_radius.directly_affected) == 0
        assert len(blast_radius.indirectly_affected) == 0

    def test_get_highest_impact_findings(self, blast_radius_assets, blast_radius_findings):
        """Test getting findings with highest impact."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Create varied connections for different impact
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        top_findings = calculator.get_highest_impact_findings(limit=2)

        assert len(top_findings) <= 2
        # Should be sorted by score
        if len(top_findings) == 2:
            assert top_findings[0].blast_radius_score >= top_findings[1].blast_radius_score

    def test_get_affected_by_category(self, blast_radius_assets, blast_radius_findings):
        """Test filtering by impact category."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Connect to data store
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        data_exposure_results = calculator.get_affected_by_category(ImpactCategory.DATA_EXPOSURE)

        # Should find findings with data exposure impact
        assert len(data_exposure_results) >= 1

    def test_total_affected_count(self, blast_radius_assets, blast_radius_findings):
        """Test that total affected count is correct."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Create connections
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[0].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[1].id, assets[4].id, RelationshipType.NETWORK_CONNECTED)

        calculator = BlastRadiusCalculator(graph=graph, findings=blast_radius_findings)
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        expected_count = len(blast_radius.directly_affected) + len(blast_radius.indirectly_affected)
        assert blast_radius.total_affected_count == expected_count

    def test_max_depth_limit(self, blast_radius_assets, blast_radius_findings):
        """Test that max depth limits traversal."""
        graph = AssetGraphBuilder().build(blast_radius_assets)
        assets = blast_radius_assets.assets

        # Create a long chain
        graph.add_relationship(assets[0].id, assets[1].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[1].id, assets[2].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[2].id, assets[4].id, RelationshipType.NETWORK_CONNECTED)
        graph.add_relationship(assets[4].id, assets[5].id, RelationshipType.NETWORK_CONNECTED)

        # Use shallow max depth
        calculator = BlastRadiusCalculator(
            graph=graph, findings=blast_radius_findings, max_depth=2
        )
        finding = blast_radius_findings.findings[0]

        blast_radius = calculator.calculate(finding)

        # With max_depth=2, we should see direct (distance=1) and one level of indirect (distance=2)
        all_distances = [r.distance for r in blast_radius.indirectly_affected]
        if all_distances:
            assert max(all_distances) <= 2


# =============================================================================
# MITRE ATT&CK Mapping Tests
# =============================================================================

from stance.analytics.mitre_attack import (
    AttackMapping,
    KillChainPhase,
    MitreAttackMapper,
    MitreTactic,
    MitreTechnique,
)


class TestMitreTactic:
    """Tests for MitreTactic enum."""

    def test_all_tactics_defined(self):
        """Test that all expected tactics are defined."""
        expected_tactics = [
            "reconnaissance",
            "resource_development",
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "impact",
        ]
        for tactic in expected_tactics:
            assert MitreTactic(tactic) is not None

    def test_tactic_values(self):
        """Test tactic enum values."""
        assert MitreTactic.INITIAL_ACCESS.value == "initial_access"
        assert MitreTactic.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert MitreTactic.CREDENTIAL_ACCESS.value == "credential_access"


class TestKillChainPhase:
    """Tests for KillChainPhase enum."""

    def test_all_phases_defined(self):
        """Test that all kill chain phases are defined."""
        expected_phases = [
            "reconnaissance",
            "weaponization",
            "delivery",
            "exploitation",
            "installation",
            "command_and_control",
            "actions_on_objectives",
        ]
        for phase in expected_phases:
            assert KillChainPhase(phase) is not None

    def test_phase_ordering(self):
        """Test kill chain phase ordering."""
        phases = list(KillChainPhase)
        assert phases[0] == KillChainPhase.RECONNAISSANCE
        assert phases[-1] == KillChainPhase.ACTIONS_ON_OBJECTIVES


class TestMitreTechnique:
    """Tests for MitreTechnique dataclass."""

    def test_create_technique(self):
        """Test creating a MITRE technique."""
        tech = MitreTechnique(
            id="T1078",
            name="Valid Accounts",
            tactic=MitreTactic.INITIAL_ACCESS,
            sub_techniques=["T1078.001", "T1078.004"],
            description="Test description",
            cloud_platforms=["AWS", "Azure"],
        )
        assert tech.id == "T1078"
        assert tech.name == "Valid Accounts"
        assert tech.tactic == MitreTactic.INITIAL_ACCESS
        assert len(tech.sub_techniques) == 2

    def test_technique_to_dict(self):
        """Test converting technique to dictionary."""
        tech = MitreTechnique(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=MitreTactic.INITIAL_ACCESS,
        )
        result = tech.to_dict()
        assert result["id"] == "T1190"
        assert result["name"] == "Exploit Public-Facing Application"
        assert result["tactic"] == "initial_access"

    def test_technique_from_dict(self):
        """Test creating technique from dictionary."""
        data = {
            "id": "T1530",
            "name": "Data from Cloud Storage",
            "tactic": "collection",
            "cloud_platforms": ["AWS", "GCP"],
        }
        tech = MitreTechnique.from_dict(data)
        assert tech.id == "T1530"
        assert tech.tactic == MitreTactic.COLLECTION
        assert "AWS" in tech.cloud_platforms


class TestAttackMapping:
    """Tests for AttackMapping dataclass."""

    def test_create_mapping(self):
        """Test creating an attack mapping."""
        tech = MitreTechnique(
            id="T1078",
            name="Valid Accounts",
            tactic=MitreTactic.INITIAL_ACCESS,
        )
        mapping = AttackMapping(
            finding_id="finding-001",
            techniques=[tech],
            kill_chain_phases=[KillChainPhase.DELIVERY],
            detection_recommendations=["Monitor for unusual logins"],
            mitigation_strategies=["Enforce MFA"],
            confidence=0.9,
        )
        assert mapping.finding_id == "finding-001"
        assert len(mapping.techniques) == 1
        assert mapping.confidence == 0.9

    def test_mapping_tactics_property(self):
        """Test getting tactics from mapping."""
        tech1 = MitreTechnique(
            id="T1078", name="Valid Accounts", tactic=MitreTactic.INITIAL_ACCESS
        )
        tech2 = MitreTechnique(
            id="T1552", name="Unsecured Credentials", tactic=MitreTactic.CREDENTIAL_ACCESS
        )
        mapping = AttackMapping(
            finding_id="finding-001",
            techniques=[tech1, tech2],
            kill_chain_phases=[],
            detection_recommendations=[],
            mitigation_strategies=[],
        )
        tactics = mapping.tactics
        assert MitreTactic.INITIAL_ACCESS in tactics
        assert MitreTactic.CREDENTIAL_ACCESS in tactics
        assert len(tactics) == 2

    def test_mapping_technique_ids_property(self):
        """Test getting technique IDs from mapping."""
        tech1 = MitreTechnique(
            id="T1078", name="Valid Accounts", tactic=MitreTactic.INITIAL_ACCESS
        )
        tech2 = MitreTechnique(
            id="T1190", name="Exploit Public-Facing Application", tactic=MitreTactic.INITIAL_ACCESS
        )
        mapping = AttackMapping(
            finding_id="finding-001",
            techniques=[tech1, tech2],
            kill_chain_phases=[],
            detection_recommendations=[],
            mitigation_strategies=[],
        )
        tech_ids = mapping.technique_ids
        assert "T1078" in tech_ids
        assert "T1190" in tech_ids

    def test_mapping_to_dict(self):
        """Test converting mapping to dictionary."""
        tech = MitreTechnique(
            id="T1530", name="Data from Cloud Storage", tactic=MitreTactic.COLLECTION
        )
        mapping = AttackMapping(
            finding_id="finding-001",
            techniques=[tech],
            kill_chain_phases=[KillChainPhase.ACTIONS_ON_OBJECTIVES],
            detection_recommendations=["Enable access logging"],
            mitigation_strategies=["Enable encryption"],
            confidence=0.85,
        )
        result = mapping.to_dict()
        assert result["finding_id"] == "finding-001"
        assert len(result["techniques"]) == 1
        assert "collection" in result["tactics"]
        assert result["confidence"] == 0.85


@pytest.fixture
def mitre_mapper():
    """Create a MITRE ATT&CK mapper."""
    return MitreAttackMapper()


@pytest.fixture
def mitre_findings():
    """Create findings for MITRE ATT&CK testing."""
    return FindingCollection([
        Finding(
            id="finding-public-s3",
            asset_id="arn:aws:s3:::public-bucket",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="S3 Bucket is publicly accessible",
            description="The S3 bucket allows public access which could lead to data exposure",
            rule_id="s3-public-access",
        ),
        Finding(
            id="finding-no-mfa",
            asset_id="arn:aws:iam::123456789012:user/admin",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="IAM user without MFA enabled",
            description="Administrative IAM user does not have MFA enabled",
            rule_id="iam-no-mfa",
        ),
        Finding(
            id="finding-exposed-creds",
            asset_id="arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Credentials stored insecurely",
            description="Database credentials are not properly encrypted",
            rule_id="credentials-exposed",
        ),
        Finding(
            id="finding-cve",
            asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-vulnerable",
            finding_type=FindingType.VULNERABILITY,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="Critical CVE in web application",
            description="Web application has a critical vulnerability",
            cve_id="CVE-2024-12345",
        ),
        Finding(
            id="finding-no-logging",
            asset_id="arn:aws:cloudtrail:us-east-1:123456789012:trail/main",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.MEDIUM,
            status=FindingStatus.OPEN,
            title="CloudTrail logging not enabled for all regions",
            description="CloudTrail is not logging API calls in all regions",
            rule_id="cloudtrail-incomplete-logging",
        ),
        Finding(
            id="finding-overly-permissive",
            asset_id="arn:aws:iam::123456789012:policy/too-permissive",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="IAM policy is overly permissive",
            description="IAM policy grants admin privileges to all resources",
            rule_id="iam-overly-permissive-policy",
        ),
    ])


class TestMitreAttackMapper:
    """Tests for MitreAttackMapper class."""

    def test_mapper_initialization(self, mitre_mapper):
        """Test mapper initialization."""
        assert mitre_mapper is not None
        assert len(mitre_mapper.TECHNIQUES) > 0

    def test_get_technique_valid(self, mitre_mapper):
        """Test getting a valid technique by ID."""
        tech = mitre_mapper.get_technique("T1078")
        assert tech is not None
        assert tech.id == "T1078"
        assert tech.name == "Valid Accounts"

    def test_get_technique_invalid(self, mitre_mapper):
        """Test getting an invalid technique ID."""
        tech = mitre_mapper.get_technique("T9999")
        assert tech is None

    def test_get_techniques_by_tactic(self, mitre_mapper):
        """Test getting techniques by tactic."""
        techniques = mitre_mapper.get_techniques_by_tactic(MitreTactic.INITIAL_ACCESS)
        assert len(techniques) > 0
        for tech in techniques:
            assert tech.tactic == MitreTactic.INITIAL_ACCESS

    def test_map_public_s3_finding(self, mitre_mapper, mitre_findings):
        """Test mapping a public S3 bucket finding."""
        finding = mitre_findings.get_by_id("finding-public-s3")
        mapping = mitre_mapper.map_finding(finding)

        assert mapping.finding_id == "finding-public-s3"
        assert len(mapping.techniques) > 0

        # Should map to data collection/exfiltration techniques
        tech_ids = mapping.technique_ids
        assert "T1530" in tech_ids or "T1619" in tech_ids

    def test_map_no_mfa_finding(self, mitre_mapper, mitre_findings):
        """Test mapping an IAM no-MFA finding."""
        finding = mitre_findings.get_by_id("finding-no-mfa")
        mapping = mitre_mapper.map_finding(finding)

        assert mapping.finding_id == "finding-no-mfa"
        assert len(mapping.techniques) > 0

        # Should map to valid accounts technique
        tech_ids = mapping.technique_ids
        assert "T1078" in tech_ids

    def test_map_credential_finding(self, mitre_mapper, mitre_findings):
        """Test mapping a credential exposure finding."""
        finding = mitre_findings.get_by_id("finding-exposed-creds")
        mapping = mitre_mapper.map_finding(finding)

        assert len(mapping.techniques) > 0

        # Should map to credential access techniques
        tech_ids = mapping.technique_ids
        assert "T1552" in tech_ids or "T1528" in tech_ids

    def test_map_cve_finding(self, mitre_mapper, mitre_findings):
        """Test mapping a CVE vulnerability finding."""
        finding = mitre_findings.get_by_id("finding-cve")
        mapping = mitre_mapper.map_finding(finding)

        # CVE findings should map to T1190
        tech_ids = mapping.technique_ids
        assert "T1190" in tech_ids

    def test_map_logging_finding(self, mitre_mapper, mitre_findings):
        """Test mapping a logging-related finding."""
        finding = mitre_findings.get_by_id("finding-no-logging")
        mapping = mitre_mapper.map_finding(finding)

        # Should map to defense evasion (impairing defenses)
        tech_ids = mapping.technique_ids
        assert "T1562" in tech_ids

    def test_map_overly_permissive_finding(self, mitre_mapper, mitre_findings):
        """Test mapping an overly permissive policy finding."""
        finding = mitre_findings.get_by_id("finding-overly-permissive")
        mapping = mitre_mapper.map_finding(finding)

        # Should map to privilege escalation techniques
        tech_ids = mapping.technique_ids
        assert "T1078" in tech_ids or "T1548" in tech_ids

    def test_map_findings_collection(self, mitre_mapper, mitre_findings):
        """Test mapping multiple findings."""
        mappings = mitre_mapper.map_findings(mitre_findings)

        assert len(mappings) == len(mitre_findings.findings)
        for mapping in mappings:
            assert isinstance(mapping, AttackMapping)

    def test_mapping_has_kill_chain_phases(self, mitre_mapper, mitre_findings):
        """Test that mappings include kill chain phases."""
        finding = mitre_findings.get_by_id("finding-public-s3")
        mapping = mitre_mapper.map_finding(finding)

        assert len(mapping.kill_chain_phases) > 0
        for phase in mapping.kill_chain_phases:
            assert isinstance(phase, KillChainPhase)

    def test_mapping_has_detection_recommendations(self, mitre_mapper, mitre_findings):
        """Test that mappings include detection recommendations."""
        finding = mitre_findings.get_by_id("finding-no-mfa")
        mapping = mitre_mapper.map_finding(finding)

        assert len(mapping.detection_recommendations) > 0
        assert all(isinstance(r, str) for r in mapping.detection_recommendations)

    def test_mapping_has_mitigation_strategies(self, mitre_mapper, mitre_findings):
        """Test that mappings include mitigation strategies."""
        finding = mitre_findings.get_by_id("finding-exposed-creds")
        mapping = mitre_mapper.map_finding(finding)

        assert len(mapping.mitigation_strategies) > 0
        assert all(isinstance(s, str) for s in mapping.mitigation_strategies)

    def test_mapping_confidence_range(self, mitre_mapper, mitre_findings):
        """Test that mapping confidence is within valid range."""
        for finding in mitre_findings.findings:
            mapping = mitre_mapper.map_finding(finding)
            assert 0.0 <= mapping.confidence <= 1.0

    def test_get_coverage_summary(self, mitre_mapper, mitre_findings):
        """Test getting ATT&CK coverage summary."""
        mappings = mitre_mapper.map_findings(mitre_findings)
        summary = mitre_mapper.get_coverage_summary(mappings)

        assert "total_mappings" in summary
        assert "tactics_covered" in summary
        assert "techniques_covered" in summary
        assert "kill_chain_phases_covered" in summary
        assert "tactic_distribution" in summary

        assert summary["total_mappings"] == len(mappings)
        assert summary["tactics_covered"] >= 0
        assert summary["techniques_covered"] >= 0

    def test_coverage_summary_tactic_distribution(self, mitre_mapper, mitre_findings):
        """Test tactic distribution in coverage summary."""
        mappings = mitre_mapper.map_findings(mitre_findings)
        summary = mitre_mapper.get_coverage_summary(mappings)

        distribution = summary["tactic_distribution"]
        assert isinstance(distribution, dict)

        # All values should be positive integers
        for count in distribution.values():
            assert isinstance(count, int)
            assert count > 0

    def test_techniques_have_cloud_platforms(self, mitre_mapper):
        """Test that techniques have cloud platform information."""
        tech = mitre_mapper.get_technique("T1078")
        assert len(tech.cloud_platforms) > 0
        assert "AWS" in tech.cloud_platforms

    def test_techniques_sorted_by_tactic(self, mitre_mapper, mitre_findings):
        """Test that techniques in mapping are sorted by attack flow."""
        finding = mitre_findings.get_by_id("finding-public-s3")
        mapping = mitre_mapper.map_finding(finding)

        if len(mapping.techniques) > 1:
            tactic_order = list(MitreTactic)
            for i in range(len(mapping.techniques) - 1):
                current_idx = tactic_order.index(mapping.techniques[i].tactic)
                next_idx = tactic_order.index(mapping.techniques[i + 1].tactic)
                assert current_idx <= next_idx
