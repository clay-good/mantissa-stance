"""
Google Drive Data Scanner for DSPM.

Scans Google Drive files to detect sensitive data using
API-based file sampling.
"""

from __future__ import annotations

import io
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.dspm.extended.base import (
    BaseExtendedScanner,
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
    ExtendedScanFinding,
    ExtendedScanSummary,
)
from stance.dspm.scanners.base import FindingSeverity

logger = logging.getLogger(__name__)

# Import Google API client optionally
try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseDownload
    from googleapiclient.errors import HttpError

    GOOGLE_API_AVAILABLE = True
except ImportError:
    GOOGLE_API_AVAILABLE = False
    service_account = None  # type: ignore
    build = None  # type: ignore
    MediaIoBaseDownload = None  # type: ignore
    HttpError = Exception  # type: ignore


@dataclass
class GoogleDriveConfig:
    """
    Configuration for Google Drive connection.

    Attributes:
        service_account_file: Path to service account JSON file
        service_account_info: Service account info dict (alternative to file)
        delegated_user: User email to impersonate (for domain-wide delegation)
        scopes: OAuth scopes to request
    """

    service_account_file: str | None = None
    service_account_info: dict[str, Any] | None = None
    delegated_user: str | None = None
    scopes: list[str] = field(
        default_factory=lambda: [
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/drive.metadata.readonly",
        ]
    )

    def __post_init__(self):
        """Validate configuration."""
        if not self.service_account_file and not self.service_account_info:
            raise ValueError(
                "Either service_account_file or service_account_info must be provided"
            )


@dataclass
class DriveFileInfo:
    """
    Information about a Google Drive file.

    Attributes:
        id: File ID
        name: File name
        mime_type: MIME type
        size: File size in bytes
        created_time: Creation timestamp
        modified_time: Last modified timestamp
        owners: List of owner email addresses
        shared: Whether file is shared
        web_view_link: Link to view file
        parents: Parent folder IDs
    """

    id: str
    name: str
    mime_type: str
    size: int = 0
    created_time: datetime | None = None
    modified_time: datetime | None = None
    owners: list[str] = field(default_factory=list)
    shared: bool = False
    web_view_link: str | None = None
    parents: list[str] = field(default_factory=list)

    @property
    def is_folder(self) -> bool:
        """Check if this is a folder."""
        return self.mime_type == "application/vnd.google-apps.folder"

    @property
    def is_google_doc(self) -> bool:
        """Check if this is a Google Docs/Sheets/Slides file."""
        return self.mime_type.startswith("application/vnd.google-apps.")

    @property
    def extension(self) -> str:
        """Get file extension."""
        if "." in self.name:
            return self.name.rsplit(".", 1)[-1].lower()
        return ""


class GoogleDriveScanner(BaseExtendedScanner):
    """
    Google Drive scanner for sensitive data detection.

    Samples files from Google Drive and scans content to identify
    PII, PCI, PHI, and other sensitive data patterns.

    All operations are read-only.
    """

    source_type = ExtendedSourceType.GOOGLE_DRIVE

    # MIME types that can be scanned for text content
    SCANNABLE_MIME_TYPES = {
        "text/plain",
        "text/csv",
        "text/html",
        "text/xml",
        "application/json",
        "application/xml",
        "application/javascript",
        "text/markdown",
        "text/x-python",
        "text/x-java",
    }

    # Google Docs types that can be exported as text
    GOOGLE_DOCS_TYPES = {
        "application/vnd.google-apps.document": "text/plain",
        "application/vnd.google-apps.spreadsheet": "text/csv",
        "application/vnd.google-apps.presentation": "text/plain",
    }

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        "txt", "csv", "json", "xml", "html", "htm", "md", "log",
        "py", "js", "java", "sql", "yaml", "yml", "ini", "conf",
        "env", "config", "properties", "sh", "bash",
    }

    # Max file size to download (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(
        self,
        drive_config: GoogleDriveConfig,
        scan_config: ExtendedScanConfig | None = None,
    ):
        """
        Initialize Google Drive scanner.

        Args:
            drive_config: Google Drive connection configuration
            scan_config: Optional scan configuration
        """
        super().__init__(scan_config)

        if not GOOGLE_API_AVAILABLE:
            raise ImportError(
                "google-api-python-client is required. "
                "Install with: pip install google-api-python-client google-auth"
            )

        self._drive_config = drive_config
        self._service: Any = None

    def _get_service(self) -> Any:
        """Get or create Drive API service."""
        if self._service is None:
            credentials = self._get_credentials()
            self._service = build("drive", "v3", credentials=credentials)
        return self._service

    def _get_credentials(self) -> Any:
        """Get credentials from config."""
        if self._drive_config.service_account_file:
            credentials = service_account.Credentials.from_service_account_file(
                self._drive_config.service_account_file,
                scopes=self._drive_config.scopes,
            )
        else:
            credentials = service_account.Credentials.from_service_account_info(
                self._drive_config.service_account_info,
                scopes=self._drive_config.scopes,
            )

        # Handle domain-wide delegation
        if self._drive_config.delegated_user:
            credentials = credentials.with_subject(self._drive_config.delegated_user)

        return credentials

    def test_connection(self) -> bool:
        """
        Test connection to Google Drive.

        Returns:
            True if connection successful
        """
        try:
            service = self._get_service()
            # Try to list a single file to test access
            service.files().list(pageSize=1, fields="files(id)").execute()
            return True
        except HttpError as e:
            logger.error(f"Google Drive connection test failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Connection test failed: {type(e).__name__}: {e}")
            return False

    def scan(self, target: str) -> ExtendedScanResult:
        """
        Scan a Google Drive folder for sensitive data.

        Args:
            target: Folder ID to scan (use 'root' for root folder)

        Returns:
            Scan result with findings and summary
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(f"Starting Google Drive scan: folder={target}, scan_id={scan_id}")

        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=target,
            config=self._config,
            started_at=started_at,
        )

        summary = ExtendedScanSummary()
        findings: list[ExtendedScanFinding] = []

        try:
            service = self._get_service()

            # List files to scan
            files_scanned = 0
            for file_info in self._list_files(service, target):
                if files_scanned >= self._config.sample_size:
                    logger.info(f"Reached sample size limit: {self._config.sample_size}")
                    break

                # Check if file should be scanned
                if not self._should_scan_file(file_info):
                    summary.total_objects_skipped += 1
                    continue

                # Scan the file
                finding = self._scan_file(service, file_info)
                if finding:
                    findings.append(finding)
                    summary.total_findings += 1

                    sev = finding.severity.value
                    summary.findings_by_severity[sev] = (
                        summary.findings_by_severity.get(sev, 0) + 1
                    )
                    for cat in finding.categories:
                        cat_val = cat.value
                        summary.findings_by_category[cat_val] = (
                            summary.findings_by_category.get(cat_val, 0) + 1
                        )

                files_scanned += 1
                summary.total_files_scanned += 1
                summary.total_objects_scanned += 1

        except HttpError as e:
            error_msg = f"Google Drive API error: {str(e)}"
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
            f"Google Drive scan complete: {summary.total_files_scanned} files, "
            f"{summary.total_findings} findings, "
            f"{summary.scan_duration_seconds:.2f}s"
        )

        return result

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        """
        List files that can be scanned in the folder.

        Args:
            target: Folder ID

        Returns:
            List of file metadata dictionaries
        """
        try:
            service = self._get_service()
            files = list(self._list_files(service, target))
            return [
                {
                    "id": f.id,
                    "name": f.name,
                    "mime_type": f.mime_type,
                    "size": f.size,
                    "shared": f.shared,
                    "is_folder": f.is_folder,
                    "owners": f.owners,
                }
                for f in files
            ]
        except HttpError as e:
            logger.error(f"Error listing files: {e}")
            return []

    def _list_files(
        self, service: Any, folder_id: str
    ) -> Iterator[DriveFileInfo]:
        """
        List files in a folder recursively.

        Args:
            service: Drive API service
            folder_id: Folder ID

        Yields:
            DriveFileInfo for each file
        """
        page_token = None

        while True:
            # Build query
            if folder_id == "root":
                query = "trashed = false"
            else:
                query = f"'{folder_id}' in parents and trashed = false"

            response = service.files().list(
                q=query,
                pageSize=100,
                pageToken=page_token,
                fields="nextPageToken, files(id, name, mimeType, size, createdTime, "
                       "modifiedTime, owners, shared, webViewLink, parents)",
            ).execute()

            for file in response.get("files", []):
                file_info = self._parse_file_info(file)

                # If it's a folder, recurse into it
                if file_info.is_folder:
                    yield from self._list_files(service, file_info.id)
                else:
                    yield file_info

            page_token = response.get("nextPageToken")
            if not page_token:
                break

    def _parse_file_info(self, file: dict[str, Any]) -> DriveFileInfo:
        """Parse API response into DriveFileInfo."""
        owners = []
        for owner in file.get("owners", []):
            if "emailAddress" in owner:
                owners.append(owner["emailAddress"])

        created_time = None
        if file.get("createdTime"):
            try:
                created_time = datetime.fromisoformat(
                    file["createdTime"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        modified_time = None
        if file.get("modifiedTime"):
            try:
                modified_time = datetime.fromisoformat(
                    file["modifiedTime"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass

        return DriveFileInfo(
            id=file.get("id", ""),
            name=file.get("name", ""),
            mime_type=file.get("mimeType", ""),
            size=int(file.get("size", 0)),
            created_time=created_time,
            modified_time=modified_time,
            owners=owners,
            shared=file.get("shared", False),
            web_view_link=file.get("webViewLink"),
            parents=file.get("parents", []),
        )

    def _should_scan_file(self, file_info: DriveFileInfo) -> bool:
        """Check if file should be scanned."""
        # Skip folders
        if file_info.is_folder:
            return False

        # Skip files that are too large
        if file_info.size > self.MAX_FILE_SIZE:
            return False

        # Check file extension filter
        if self._config.file_extensions:
            if file_info.extension not in self._config.file_extensions:
                return False

        # Check if MIME type is scannable
        if file_info.mime_type in self.SCANNABLE_MIME_TYPES:
            return True

        # Check if it's a Google Docs type we can export
        if file_info.mime_type in self.GOOGLE_DOCS_TYPES:
            return True

        # Check extension
        if file_info.extension in self.SCANNABLE_EXTENSIONS:
            return True

        return False

    def _scan_file(
        self, service: Any, file_info: DriveFileInfo
    ) -> ExtendedScanFinding | None:
        """
        Scan a file for sensitive data.

        Args:
            service: Drive API service
            file_info: File information

        Returns:
            Finding if sensitive data found
        """
        try:
            # Download file content
            content = self._download_file(service, file_info)

            if content is None:
                return None

            # Try to decode as text
            text_content = self._decode_content(content)
            if text_content is None:
                logger.debug(f"Skipping binary file: {file_info.name}")
                return None

            if not text_content.strip():
                return None

            # Scan for sensitive data
            detection_result = self._detector.scan_records(
                records=[{"content": text_content}],
                asset_id=f"googledrive://{file_info.id}",
                asset_type="drive_file",
                sample_size=1,
            )

            # Create finding
            return self._create_finding_from_detection(
                source_location=f"googledrive://{file_info.id}",
                object_type="file",
                object_name=file_info.name,
                detection_result=detection_result,
                metadata={
                    "file_id": file_info.id,
                    "file_name": file_info.name,
                    "mime_type": file_info.mime_type,
                    "size": file_info.size,
                    "shared": file_info.shared,
                    "owners": file_info.owners,
                    "web_view_link": file_info.web_view_link,
                },
            )

        except HttpError as e:
            logger.warning(f"Error scanning file {file_info.name}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error scanning file {file_info.name}: {type(e).__name__}: {e}")
            return None

    def _download_file(
        self, service: Any, file_info: DriveFileInfo
    ) -> bytes | None:
        """
        Download file content.

        Args:
            service: Drive API service
            file_info: File information

        Returns:
            File content as bytes
        """
        try:
            if file_info.is_google_doc:
                # Export Google Docs as text
                export_mime = self.GOOGLE_DOCS_TYPES.get(file_info.mime_type, "text/plain")
                request = service.files().export_media(
                    fileId=file_info.id, mimeType=export_mime
                )
            else:
                # Download regular file
                request = service.files().get_media(fileId=file_info.id)

            buffer = io.BytesIO()
            downloader = MediaIoBaseDownload(buffer, request)

            done = False
            while not done:
                _, done = downloader.next_chunk()

            return buffer.getvalue()

        except HttpError as e:
            if e.resp.status == 403:
                logger.debug(f"Access denied to file: {file_info.name}")
            else:
                logger.warning(f"Error downloading file {file_info.name}: {e}")
            return None

    def _decode_content(self, content: bytes) -> str | None:
        """Attempt to decode binary content to text."""
        encodings = ["utf-8", "latin-1", "cp1252"]
        for encoding in encodings:
            try:
                return content.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return None

    def scan_file(self, file_id: str) -> ExtendedScanResult:
        """
        Scan a specific file for sensitive data.

        Args:
            file_id: File ID to scan

        Returns:
            Scan result with findings
        """
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=file_id,
            config=self._config,
            started_at=started_at,
        )

        summary = ExtendedScanSummary()
        findings: list[ExtendedScanFinding] = []

        try:
            service = self._get_service()

            # Get file metadata
            file = service.files().get(
                fileId=file_id,
                fields="id, name, mimeType, size, createdTime, modifiedTime, "
                       "owners, shared, webViewLink, parents",
            ).execute()

            file_info = self._parse_file_info(file)

            # Scan the file
            finding = self._scan_file(service, file_info)
            if finding:
                findings.append(finding)
                summary.total_findings += 1

                sev = finding.severity.value
                summary.findings_by_severity[sev] = 1
                for cat in finding.categories:
                    summary.findings_by_category[cat.value] = 1

            summary.total_files_scanned = 1
            summary.total_objects_scanned = 1

        except HttpError as e:
            summary.errors.append(f"Google Drive API error: {str(e)}")
        except Exception as e:
            summary.errors.append(f"Scan error: {type(e).__name__}: {str(e)}")

        completed_at = datetime.now(timezone.utc)
        summary.scan_duration_seconds = (completed_at - started_at).total_seconds()

        result.findings = findings
        result.summary = summary
        result.completed_at = completed_at

        return result


def scan_google_drive(
    drive_config: GoogleDriveConfig,
    folder_id: str = "root",
    scan_config: ExtendedScanConfig | None = None,
) -> ExtendedScanResult:
    """
    Convenience function to scan a Google Drive folder.

    Args:
        drive_config: Google Drive connection configuration
        folder_id: Folder ID to scan (default: 'root')
        scan_config: Optional scan configuration

    Returns:
        Scan result with findings
    """
    scanner = GoogleDriveScanner(drive_config, scan_config)
    return scanner.scan(folder_id)
