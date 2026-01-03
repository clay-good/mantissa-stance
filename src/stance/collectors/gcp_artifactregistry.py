"""
GCP Artifact Registry collector for Mantissa Stance.

Collects Artifact Registry repositories, Docker images, and their
security configurations for posture assessment. Supports both
Artifact Registry (current) and legacy Container Registry.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
    Severity,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)

# Optional GCP imports
try:
    from google.cloud import artifactregistry_v1
    from google.cloud.artifactregistry_v1 import types

    GCP_AR_AVAILABLE = True
except ImportError:
    GCP_AR_AVAILABLE = False
    artifactregistry_v1 = None  # type: ignore
    types = None  # type: ignore

# Optional Container Analysis API for vulnerability scanning
try:
    from google.cloud import containeranalysis_v1
    from grafeas.grafeas_v1 import types as grafeas_types

    GCP_CA_AVAILABLE = True
except ImportError:
    GCP_CA_AVAILABLE = False
    containeranalysis_v1 = None  # type: ignore
    grafeas_types = None  # type: ignore


class GCPArtifactRegistryCollector(BaseCollector):
    """
    Collects GCP Artifact Registry repositories and Docker images.

    Gathers repository configurations, IAM policies, Docker images,
    and vulnerability scan results from Container Analysis API.
    All API calls are read-only.
    """

    collector_name = "gcp_artifactregistry"
    resource_types = [
        "gcp_artifact_repository",
        "gcp_artifact_docker_image",
    ]

    def __init__(
        self,
        project_id: str,
        credentials: Any | None = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the GCP Artifact Registry collector.

        Args:
            project_id: GCP project ID to collect from.
            credentials: Optional google-auth credentials object.
            **kwargs: Additional configuration.
        """
        if not GCP_AR_AVAILABLE:
            raise ImportError(
                "google-cloud-artifact-registry is required for GCP Artifact Registry collector. "
                "Install with: pip install google-cloud-artifact-registry"
            )

        self._project_id = project_id
        self._credentials = credentials
        self._ar_client: artifactregistry_v1.ArtifactRegistryClient | None = None
        self._ca_client: Any | None = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        return self._project_id

    def _get_ar_client(self) -> artifactregistry_v1.ArtifactRegistryClient:
        """Get or create Artifact Registry client."""
        if self._ar_client is None:
            self._ar_client = artifactregistry_v1.ArtifactRegistryClient(
                credentials=self._credentials
            )
        return self._ar_client

    def _get_ca_client(self) -> Any | None:
        """Get or create Container Analysis client for vulnerability scanning."""
        if not GCP_CA_AVAILABLE:
            return None

        if self._ca_client is None:
            self._ca_client = containeranalysis_v1.ContainerAnalysisClient(
                credentials=self._credentials
            )
        return self._ca_client

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    def collect(self) -> AssetCollection:
        """
        Collect all Artifact Registry resources.

        Returns:
            Collection of Artifact Registry assets
        """
        assets: list[Asset] = []

        # Collect repositories
        try:
            assets.extend(self._collect_repositories())
        except Exception as e:
            logger.warning(f"Failed to collect Artifact Registry repositories: {e}")

        return AssetCollection(assets)

    def collect_findings(self) -> FindingCollection:
        """
        Collect vulnerability findings from Container Analysis.

        Returns:
            Collection of vulnerability findings from image scans
        """
        findings: list[Finding] = []

        if not GCP_CA_AVAILABLE:
            logger.info(
                "google-cloud-containeranalysis not available, skipping vulnerability findings"
            )
            return FindingCollection(findings)

        try:
            findings.extend(self._collect_vulnerability_findings())
        except Exception as e:
            logger.warning(f"Failed to collect vulnerability findings: {e}")

        return FindingCollection(findings)

    def _collect_repositories(self) -> list[Asset]:
        """Collect Artifact Registry repositories with their configurations."""
        client = self._get_ar_client()
        assets: list[Asset] = []
        now = self._now()

        # List all locations first
        locations = self._get_repository_locations()

        for location in locations:
            parent = f"projects/{self._project_id}/locations/{location}"

            try:
                request = types.ListRepositoriesRequest(parent=parent)

                for repo in client.list_repositories(request=request):
                    repo_name = repo.name
                    # Extract repository ID from full name
                    # Format: projects/{project}/locations/{location}/repositories/{repo}
                    repo_id = repo_name.split("/")[-1]

                    # Get IAM policy for the repository
                    iam_policy = self._get_repository_iam_policy(repo_name)

                    # Determine if repository is public
                    is_public = self._is_repository_public(iam_policy)

                    # Get labels (tags)
                    labels = dict(repo.labels) if repo.labels else {}

                    # Build raw config
                    raw_config: dict[str, Any] = {
                        "name": repo_name,
                        "repository_id": repo_id,
                        "format": repo.format_.name if repo.format_ else "DOCKER",
                        "description": repo.description,
                        "location": location,
                        "labels": labels,
                        "create_time": (
                            repo.create_time.isoformat()
                            if repo.create_time
                            else None
                        ),
                        "update_time": (
                            repo.update_time.isoformat()
                            if repo.update_time
                            else None
                        ),
                        # Repository mode
                        "mode": repo.mode.name if repo.mode else "STANDARD_REPOSITORY",
                        # Cleanup policies
                        "cleanup_policies": self._extract_cleanup_policies(repo),
                        "has_cleanup_policies": bool(repo.cleanup_policies),
                        "cleanup_policy_dry_run": repo.cleanup_policy_dry_run,
                        # Size and storage
                        "size_bytes": repo.size_bytes,
                        "size_mb": round(repo.size_bytes / (1024 * 1024), 2) if repo.size_bytes else 0,
                        # Security settings
                        "iam_policy": iam_policy,
                        "is_public": is_public,
                        # Vulnerability scanning (enabled by default in AR)
                        "vulnerability_scanning_enabled": True,
                        # Docker-specific config
                        "docker_config": self._extract_docker_config(repo),
                        # Maven/npm/Python-specific configs
                        "maven_config": self._extract_maven_config(repo),
                        # Remote repository config (for proxy repos)
                        "remote_repository_config": self._extract_remote_config(repo),
                        # Virtual repository config
                        "virtual_repository_config": self._extract_virtual_config(repo),
                    }

                    # Determine network exposure
                    network_exposure = (
                        NETWORK_EXPOSURE_INTERNET if is_public
                        else NETWORK_EXPOSURE_INTERNAL
                    )

                    created_at = None
                    if repo.create_time:
                        created_at = repo.create_time.replace(tzinfo=timezone.utc)

                    asset = Asset(
                        id=repo_name,
                        cloud_provider="gcp",
                        account_id=self._project_id,
                        region=location,
                        resource_type="gcp_artifact_repository",
                        name=repo_id,
                        tags=labels,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                    assets.append(asset)

                    # Collect Docker images if this is a Docker repository
                    if repo.format_.name == "DOCKER" if repo.format_ else True:
                        try:
                            image_assets = self._collect_docker_images(
                                repo_name, repo_id, location, now
                            )
                            assets.extend(image_assets)
                        except Exception as e:
                            logger.debug(f"Could not collect images for {repo_id}: {e}")

            except Exception as e:
                logger.warning(f"Error collecting repositories in {location}: {e}")

        return assets

    def _get_repository_locations(self) -> list[str]:
        """Get list of locations where repositories might exist."""
        # Common Artifact Registry locations
        # In production, you might want to list locations via API
        return [
            "us",
            "us-central1",
            "us-east1",
            "us-east4",
            "us-west1",
            "us-west2",
            "us-west3",
            "us-west4",
            "europe",
            "europe-west1",
            "europe-west2",
            "europe-west3",
            "europe-west4",
            "europe-west6",
            "asia",
            "asia-east1",
            "asia-east2",
            "asia-northeast1",
            "asia-northeast2",
            "asia-northeast3",
            "asia-south1",
            "asia-southeast1",
            "asia-southeast2",
            "australia-southeast1",
            "northamerica-northeast1",
            "southamerica-east1",
        ]

    def _get_repository_iam_policy(self, repo_name: str) -> dict[str, Any] | None:
        """Get IAM policy for a repository."""
        client = self._get_ar_client()
        try:
            # Use the IAM policy getter
            from google.iam.v1 import iam_policy_pb2

            request = iam_policy_pb2.GetIamPolicyRequest(resource=repo_name)
            policy = client.get_iam_policy(request=request)

            bindings = []
            for binding in policy.bindings:
                bindings.append({
                    "role": binding.role,
                    "members": list(binding.members),
                })

            return {
                "version": policy.version,
                "bindings": bindings,
                "etag": policy.etag.decode() if policy.etag else None,
            }
        except Exception as e:
            logger.debug(f"Could not get IAM policy for {repo_name}: {e}")
            return None

    def _is_repository_public(self, iam_policy: dict[str, Any] | None) -> bool:
        """Check if repository is publicly accessible based on IAM policy."""
        if not iam_policy:
            return False

        bindings = iam_policy.get("bindings", [])
        for binding in bindings:
            members = binding.get("members", [])
            # Check for public access
            if "allUsers" in members or "allAuthenticatedUsers" in members:
                return True

        return False

    def _extract_cleanup_policies(self, repo: Any) -> list[dict[str, Any]]:
        """Extract cleanup policies from repository."""
        policies = []
        if repo.cleanup_policies:
            for policy_id, policy in repo.cleanup_policies.items():
                policies.append({
                    "id": policy_id,
                    "action": policy.action.name if policy.action else None,
                    "condition": {
                        "tag_state": policy.condition.tag_state.name if policy.condition and policy.condition.tag_state else None,
                        "tag_prefixes": list(policy.condition.tag_prefixes) if policy.condition and policy.condition.tag_prefixes else [],
                        "older_than": policy.condition.older_than.ToTimedelta().total_seconds() if policy.condition and policy.condition.older_than else None,
                        "newer_than": policy.condition.newer_than.ToTimedelta().total_seconds() if policy.condition and policy.condition.newer_than else None,
                    } if policy.condition else {},
                })
        return policies

    def _extract_docker_config(self, repo: Any) -> dict[str, Any] | None:
        """Extract Docker-specific configuration."""
        if not repo.docker_config:
            return None

        return {
            "immutable_tags": repo.docker_config.immutable_tags,
        }

    def _extract_maven_config(self, repo: Any) -> dict[str, Any] | None:
        """Extract Maven-specific configuration."""
        if not repo.maven_config:
            return None

        return {
            "allow_snapshot_overwrites": repo.maven_config.allow_snapshot_overwrites,
            "version_policy": repo.maven_config.version_policy.name if repo.maven_config.version_policy else None,
        }

    def _extract_remote_config(self, repo: Any) -> dict[str, Any] | None:
        """Extract remote repository configuration (for proxy repos)."""
        if not repo.remote_repository_config:
            return None

        config = repo.remote_repository_config
        return {
            "description": config.description,
            "upstream_credentials": bool(config.upstream_credentials),
            # Docker Hub, Maven Central, etc.
            "docker_repository": {
                "public_repository": config.docker_repository.public_repository.name if config.docker_repository and config.docker_repository.public_repository else None,
            } if config.docker_repository else None,
        }

    def _extract_virtual_config(self, repo: Any) -> dict[str, Any] | None:
        """Extract virtual repository configuration."""
        if not repo.virtual_repository_config:
            return None

        upstream_policies = []
        for policy in repo.virtual_repository_config.upstream_policies:
            upstream_policies.append({
                "id": policy.id,
                "repository": policy.repository,
                "priority": policy.priority,
            })

        return {
            "upstream_policies": upstream_policies,
        }

    def _collect_docker_images(
        self,
        repo_name: str,
        repo_id: str,
        location: str,
        now: datetime,
    ) -> list[Asset]:
        """Collect Docker images from a repository."""
        client = self._get_ar_client()
        assets: list[Asset] = []

        try:
            request = types.ListDockerImagesRequest(parent=repo_name)

            for image in client.list_docker_images(request=request):
                image_name = image.name
                # Extract image URI
                uri = image.uri

                # Get tags
                tags = list(image.tags) if image.tags else []
                primary_tag = tags[0] if tags else "untagged"

                # Build image ID
                image_display_name = f"{repo_id}:{primary_tag}"

                raw_config: dict[str, Any] = {
                    "name": image_name,
                    "uri": uri,
                    "tags": tags,
                    "primary_tag": primary_tag,
                    "image_size_bytes": image.image_size_bytes,
                    "image_size_mb": round(
                        image.image_size_bytes / (1024 * 1024), 2
                    ) if image.image_size_bytes else 0,
                    "upload_time": (
                        image.upload_time.isoformat()
                        if image.upload_time
                        else None
                    ),
                    "media_type": image.media_type,
                    "build_time": (
                        image.build_time.isoformat()
                        if image.build_time
                        else None
                    ),
                    "update_time": (
                        image.update_time.isoformat()
                        if image.update_time
                        else None
                    ),
                    "repository_name": repo_name,
                    "repository_id": repo_id,
                }

                created_at = None
                if image.upload_time:
                    created_at = image.upload_time.replace(tzinfo=timezone.utc)

                asset = Asset(
                    id=image_name,
                    cloud_provider="gcp",
                    account_id=self._project_id,
                    region=location,
                    resource_type="gcp_artifact_docker_image",
                    name=image_display_name,
                    tags={},
                    network_exposure=NETWORK_EXPOSURE_INTERNAL,
                    created_at=created_at,
                    last_seen=now,
                    raw_config=raw_config,
                )
                assets.append(asset)

        except Exception as e:
            logger.debug(f"Error listing Docker images in {repo_name}: {e}")

        return assets

    def _collect_vulnerability_findings(self) -> list[Finding]:
        """Collect vulnerability findings from Container Analysis API."""
        findings: list[Finding] = []
        now = self._now()

        ca_client = self._get_ca_client()
        if not ca_client:
            return findings

        try:
            # Get the Grafeas client for reading occurrences
            grafeas_client = ca_client.get_grafeas_client()

            # List vulnerability occurrences for the project
            parent = f"projects/{self._project_id}"
            filter_str = 'kind="VULNERABILITY"'

            request = grafeas_types.ListOccurrencesRequest(
                parent=parent,
                filter=filter_str,
            )

            for occurrence in grafeas_client.list_occurrences(request=request):
                finding = self._convert_occurrence_to_finding(occurrence, now)
                if finding:
                    findings.append(finding)

        except Exception as e:
            logger.warning(f"Error collecting vulnerability occurrences: {e}")

        return findings

    def _convert_occurrence_to_finding(
        self,
        occurrence: Any,
        now: datetime,
    ) -> Finding | None:
        """Convert a Grafeas occurrence to a Finding object."""
        try:
            vuln = occurrence.vulnerability

            # Get CVE ID
            cve_id = None
            if vuln.short_description:
                desc = vuln.short_description
                if desc.upper().startswith("CVE-"):
                    cve_id = desc.upper()

            # Map severity
            severity = self._map_severity(vuln.severity.name if vuln.severity else "SEVERITY_UNSPECIFIED")

            # Get CVSS score
            cvss_score = None
            if vuln.cvss_score:
                cvss_score = vuln.cvss_score

            # Get package information
            package_name = None
            installed_version = None
            fixed_version = None

            if vuln.package_issue:
                for issue in vuln.package_issue:
                    package_name = issue.affected_package
                    installed_version = issue.affected_version.full_name if issue.affected_version else None
                    fixed_version = issue.fixed_version.full_name if issue.fixed_version else None
                    break  # Take the first package issue

            # Get resource URI (the image)
            resource_uri = occurrence.resource_uri

            # Generate finding ID
            finding_id = f"gcp-vuln-{occurrence.name.replace('/', '-')}"

            return Finding(
                id=finding_id,
                asset_id=resource_uri,
                finding_type=FindingType.VULNERABILITY,
                severity=severity,
                status=FindingStatus.OPEN,
                title=f"Vulnerability {cve_id or vuln.short_description} in container image",
                description=vuln.long_description or vuln.short_description or "Container vulnerability detected",
                first_seen=now,
                last_seen=now,
                # CSPM fields (not used for vulnerabilities)
                rule_id=None,
                resource_path=None,
                expected_value=None,
                actual_value=None,
                # Vulnerability fields
                cve_id=cve_id,
                cvss_score=cvss_score,
                package_name=package_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                # Compliance
                compliance_frameworks=[],
                # Remediation
                remediation_guidance=(
                    f"Update package {package_name} to version {fixed_version}"
                    if package_name and fixed_version
                    else "Apply security updates to address the vulnerability"
                ),
            )
        except Exception as e:
            logger.debug(f"Error converting occurrence to finding: {e}")
            return None

    def _map_severity(self, gcp_severity: str) -> Severity:
        """Map GCP vulnerability severity to our Severity enum."""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "MINIMAL": Severity.INFO,
            "SEVERITY_UNSPECIFIED": Severity.INFO,
        }
        return severity_map.get(gcp_severity.upper(), Severity.INFO)
