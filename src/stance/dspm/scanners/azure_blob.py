"""
Azure Blob Storage Data Scanner for DSPM.

Scans Azure Blob containers to detect sensitive data using sampling
and pattern matching.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.dspm.scanners.base import (
    BaseDataScanner,
    ScanConfig,
    ScanResult,
    ScanFinding,
    ScanSummary,
    FindingSeverity,
)

logger = logging.getLogger(__name__)

# Import Azure SDK optionally
try:
    from azure.storage.blob import BlobServiceClient, ContainerClient
    from azure.core.exceptions import (
        AzureError,
        ResourceNotFoundError,
        ClientAuthenticationError,
    )

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    BlobServiceClient = None  # type: ignore
    ContainerClient = None  # type: ignore
    AzureError = Exception  # type: ignore
    ResourceNotFoundError = Exception  # type: ignore
    ClientAuthenticationError = Exception  # type: ignore


class AzureBlobDataScanner(BaseDataScanner):
    """
    Azure Blob Storage scanner for sensitive data detection.

    Samples blobs from Azure containers and scans content to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only.
    """

    storage_type = "azure_blob"

    def __init__(
        self,
        config: ScanConfig | None = None,
        connection_string: str | None = None,
        account_url: str | None = None,
        credential: Any | None = None,
    ):
        """
        Initialize Azure Blob scanner.

        Args:
            config: Optional scan configuration
            connection_string: Azure Storage connection string
            account_url: Storage account URL (alternative to connection_string)
            credential: Credential for authentication (used with account_url)
        """
        super().__init__(config)

        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-storage-blob is required for Azure scanning. "
                "Install with: pip install azure-storage-blob"
            )

        if connection_string:
            self._blob_service = BlobServiceClient.from_connection_string(
                connection_string
            )
        elif account_url:
            self._blob_service = BlobServiceClient(
                account_url=account_url, credential=credential
            )
        else:
            raise ValueError(
                "Either connection_string or account_url must be provided"
            )

    def scan_bucket(self, bucket_name: str) -> ScanResult:
        """
        Scan an Azure Blob container for sensitive data.

        Args:
            bucket_name: Name of the container (bucket_name used for API consistency)

        Returns:
            Scan result with findings and summary
        """
        container_name = bucket_name  # Azure uses "container" terminology
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting Azure Blob scan: container={container_name}, scan_id={scan_id}"
        )

        result = ScanResult(
            scan_id=scan_id,
            storage_type=self.storage_type,
            target=container_name,
            config=self._config,
            started_at=started_at,
        )

        summary = ScanSummary()
        findings: list[ScanFinding] = []

        try:
            # Get container metadata
            bucket_metadata = self.get_bucket_metadata(container_name)

            # Scan blobs
            objects_scanned = 0
            for obj in self.list_objects(container_name):
                if self._config.sample_size and objects_scanned >= self._config.sample_size:
                    break

                object_key = obj.get("name", "")
                object_size = obj.get("size", 0)

                # Check if blob should be scanned
                should_scan, skip_reason = self._should_scan_object(
                    object_key, object_size
                )

                if not should_scan:
                    summary.total_objects_skipped += 1
                    logger.debug(f"Skipping {object_key}: {skip_reason}")
                    continue

                # Scan the blob
                finding = self.scan_object(container_name, object_key)
                if finding:
                    findings.append(finding)
                    summary.total_findings += 1

                    # Update severity counts
                    sev = finding.severity.value
                    summary.findings_by_severity[sev] = (
                        summary.findings_by_severity.get(sev, 0) + 1
                    )

                    # Update category counts
                    for cat in finding.categories:
                        cat_val = cat.value
                        summary.findings_by_category[cat_val] = (
                            summary.findings_by_category.get(cat_val, 0) + 1
                        )

                objects_scanned += 1
                summary.total_objects_scanned += 1
                summary.total_bytes_scanned += min(
                    object_size, self._config.content_sample_bytes
                )

        except AzureError as e:
            error_msg = f"Azure error: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Scan error: {type(e).__name__}: {str(e)}"
            summary.errors.append(error_msg)
            logger.error(error_msg)

        # Finalize result
        completed_at = datetime.now(timezone.utc)
        summary.scan_duration_seconds = (completed_at - started_at).total_seconds()

        result.findings = findings
        result.summary = summary
        result.completed_at = completed_at

        logger.info(
            f"Azure Blob scan complete: {summary.total_objects_scanned} blobs, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None:
        """
        Scan a specific Azure blob for sensitive data.

        Args:
            bucket_name: Container name
            object_key: Blob name

        Returns:
            ScanFinding if sensitive data found, None otherwise
        """
        try:
            # Get blob content sample
            content = self.get_object_content(
                bucket_name, object_key, self._config.content_sample_bytes
            )

            if content is None:
                return None

            # Try to decode as text
            text_content = self._decode_content(content)
            if text_content is None:
                logger.debug(f"Skipping binary file: {object_key}")
                return None

            # Scan the content
            detection_result = self._detector.scan_records(
                records=[{"content": text_content}],
                asset_id=f"azure://{bucket_name}/{object_key}",
                asset_type="azure_blob",
                sample_size=1,
            )

            # Get container metadata for context
            bucket_metadata = self.get_bucket_metadata(bucket_name)

            # Create finding if sensitive data detected
            return self._create_finding_from_detection(
                bucket_name, object_key, detection_result, bucket_metadata
            )

        except ResourceNotFoundError:
            logger.debug(f"Blob not found: {object_key}")
            return None
        except ClientAuthenticationError:
            logger.debug(f"Access denied: {object_key}")
            return None
        except Exception as e:
            logger.warning(f"Error scanning {object_key}: {type(e).__name__}: {e}")
            return None

    def list_objects(
        self, bucket_name: str, prefix: str = ""
    ) -> Iterator[dict[str, Any]]:
        """
        List blobs in an Azure container.

        Args:
            bucket_name: Container name
            prefix: Optional prefix filter

        Yields:
            Blob metadata dictionaries
        """
        container_client = self._blob_service.get_container_client(bucket_name)
        blobs = container_client.list_blobs(name_starts_with=prefix if prefix else None)

        for blob in blobs:
            yield {
                "name": blob.name,
                "size": blob.size or 0,
                "last_modified": blob.last_modified,
                "content_type": blob.content_settings.content_type if blob.content_settings else None,
                "blob_type": blob.blob_type,
                "etag": blob.etag,
            }

    def get_object_content(
        self, bucket_name: str, object_key: str, max_bytes: int | None = None
    ) -> bytes | None:
        """
        Get Azure blob content (or sample).

        Args:
            bucket_name: Container name
            object_key: Blob name
            max_bytes: Maximum bytes to read

        Returns:
            Blob content as bytes
        """
        try:
            container_client = self._blob_service.get_container_client(bucket_name)
            blob_client = container_client.get_blob_client(object_key)

            if max_bytes:
                # Use range read for sampling
                stream = blob_client.download_blob(offset=0, length=max_bytes)
            else:
                stream = blob_client.download_blob()

            return stream.readall()

        except ResourceNotFoundError:
            logger.debug(f"Blob not found: {object_key}")
            return None
        except ClientAuthenticationError:
            logger.debug(f"Access denied: {object_key}")
            return None

    def get_bucket_metadata(self, bucket_name: str) -> dict[str, Any]:
        """
        Get Azure container metadata.

        Args:
            bucket_name: Container name

        Returns:
            Container metadata including encryption, public access status
        """
        metadata: dict[str, Any] = {
            "bucket_name": bucket_name,
            "encrypted": True,  # Azure Storage always encrypts at rest
            "encryption_type": "Microsoft-managed",
            "public_access": False,
            "lease_state": None,
            "last_modified": None,
        }

        try:
            container_client = self._blob_service.get_container_client(bucket_name)
            properties = container_client.get_container_properties()

            # Check public access level
            public_access = properties.get("public_access")
            metadata["public_access"] = public_access is not None

            # Lease state
            metadata["lease_state"] = properties.get("lease", {}).get("state")

            # Last modified
            if properties.get("last_modified"):
                metadata["last_modified"] = properties["last_modified"].isoformat()

            # Check for customer-managed keys (would need storage account level check)
            # For now, we just note that Azure always encrypts

        except ResourceNotFoundError:
            logger.warning(f"Container not found: {bucket_name}")
        except ClientAuthenticationError:
            logger.warning(f"Access denied to container: {bucket_name}")
        except Exception as e:
            logger.warning(f"Error getting container metadata: {e}")

        return metadata

    def get_storage_account_info(self) -> dict[str, Any]:
        """
        Get storage account information.

        Returns:
            Storage account metadata
        """
        try:
            account_info = self._blob_service.get_account_information()
            return {
                "sku_name": account_info.get("sku_name"),
                "account_kind": account_info.get("account_kind"),
            }
        except Exception as e:
            logger.warning(f"Error getting storage account info: {e}")
            return {}

    def list_containers(self) -> Iterator[dict[str, Any]]:
        """
        List all containers in the storage account.

        Yields:
            Container metadata dictionaries
        """
        for container in self._blob_service.list_containers():
            yield {
                "name": container.name,
                "last_modified": container.last_modified,
                "public_access": container.public_access,
            }
