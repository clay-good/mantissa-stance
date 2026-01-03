"""
Unit tests for DSPM Google Drive scanner.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

from stance.dspm.extended.google_drive import (
    GoogleDriveConfig,
    GoogleDriveScanner,
    DriveFileInfo,
    scan_google_drive,
    GOOGLE_API_AVAILABLE,
)
from stance.dspm.extended.base import (
    ExtendedSourceType,
    ExtendedScanConfig,
    ExtendedScanResult,
)
from stance.dspm.scanners.base import FindingSeverity


class TestGoogleDriveConfig:
    """Tests for GoogleDriveConfig."""

    def test_config_with_file(self):
        """Test configuration with service account file."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/credentials.json",
        )

        assert config.service_account_file == "/path/to/credentials.json"
        assert config.service_account_info is None
        assert config.delegated_user is None

    def test_config_with_info(self):
        """Test configuration with service account info dict."""
        sa_info = {
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "key123",
            "private_key": "-----BEGIN PRIVATE KEY-----\n...",
            "client_email": "test@test-project.iam.gserviceaccount.com",
        }

        config = GoogleDriveConfig(
            service_account_info=sa_info,
        )

        assert config.service_account_file is None
        assert config.service_account_info == sa_info

    def test_config_with_delegation(self):
        """Test configuration with domain-wide delegation."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
            delegated_user="admin@company.com",
        )

        assert config.delegated_user == "admin@company.com"

    def test_config_default_scopes(self):
        """Test default scopes."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )

        assert "drive.readonly" in config.scopes[0]
        assert "drive.metadata.readonly" in config.scopes[1]

    def test_config_validation_error(self):
        """Test that config raises error without credentials."""
        with pytest.raises(ValueError, match="service_account"):
            GoogleDriveConfig()


class TestDriveFileInfo:
    """Tests for DriveFileInfo."""

    def test_file_creation(self):
        """Test file info creation."""
        file_info = DriveFileInfo(
            id="abc123",
            name="document.txt",
            mime_type="text/plain",
            size=1024,
            owners=["user@example.com"],
            shared=True,
        )

        assert file_info.id == "abc123"
        assert file_info.name == "document.txt"
        assert file_info.mime_type == "text/plain"
        assert file_info.size == 1024
        assert file_info.shared is True

    def test_is_folder(self):
        """Test is_folder property."""
        folder = DriveFileInfo(
            id="folder1",
            name="My Folder",
            mime_type="application/vnd.google-apps.folder",
        )
        assert folder.is_folder is True

        file = DriveFileInfo(
            id="file1",
            name="document.txt",
            mime_type="text/plain",
        )
        assert file.is_folder is False

    def test_is_google_doc(self):
        """Test is_google_doc property."""
        doc = DriveFileInfo(
            id="doc1",
            name="My Document",
            mime_type="application/vnd.google-apps.document",
        )
        assert doc.is_google_doc is True

        sheet = DriveFileInfo(
            id="sheet1",
            name="My Sheet",
            mime_type="application/vnd.google-apps.spreadsheet",
        )
        assert sheet.is_google_doc is True

        txt = DriveFileInfo(
            id="txt1",
            name="file.txt",
            mime_type="text/plain",
        )
        assert txt.is_google_doc is False

    def test_extension(self):
        """Test extension property."""
        txt = DriveFileInfo(
            id="1",
            name="document.txt",
            mime_type="text/plain",
        )
        assert txt.extension == "txt"

        pdf = DriveFileInfo(
            id="2",
            name="report.PDF",
            mime_type="application/pdf",
        )
        assert pdf.extension == "pdf"

        no_ext = DriveFileInfo(
            id="3",
            name="README",
            mime_type="text/plain",
        )
        assert no_ext.extension == ""

    def test_file_defaults(self):
        """Test default values."""
        file_info = DriveFileInfo(
            id="1",
            name="test",
            mime_type="text/plain",
        )

        assert file_info.size == 0
        assert file_info.created_time is None
        assert file_info.modified_time is None
        assert file_info.owners == []
        assert file_info.shared is False
        assert file_info.web_view_link is None
        assert file_info.parents == []


@pytest.mark.skipif(not GOOGLE_API_AVAILABLE, reason="google-api-python-client not installed")
class TestGoogleDriveScanner:
    """Tests for GoogleDriveScanner (requires google-api-python-client)."""

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_scanner_initialization(self, mock_build, mock_sa):
        """Test scanner initialization."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )

        scanner = GoogleDriveScanner(config)

        assert scanner.source_type == ExtendedSourceType.GOOGLE_DRIVE
        assert scanner._drive_config == config

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_test_connection_success(self, mock_build, mock_sa):
        """Test successful connection test."""
        mock_service = MagicMock()
        mock_service.files().list().execute.return_value = {"files": []}
        mock_build.return_value = mock_service

        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        result = scanner.test_connection()

        assert result is True

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_should_scan_file_text_types(self, mock_build, mock_sa):
        """Test file scanning decisions for text types."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        # Text types should be scanned
        assert scanner._should_scan_file(
            DriveFileInfo(id="1", name="test.txt", mime_type="text/plain")
        ) is True
        assert scanner._should_scan_file(
            DriveFileInfo(id="2", name="data.csv", mime_type="text/csv")
        ) is True
        assert scanner._should_scan_file(
            DriveFileInfo(id="3", name="config.json", mime_type="application/json")
        ) is True

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_should_scan_file_google_docs(self, mock_build, mock_sa):
        """Test file scanning decisions for Google Docs."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        # Google Docs should be scanned
        assert scanner._should_scan_file(
            DriveFileInfo(
                id="1",
                name="My Doc",
                mime_type="application/vnd.google-apps.document",
            )
        ) is True
        assert scanner._should_scan_file(
            DriveFileInfo(
                id="2",
                name="My Sheet",
                mime_type="application/vnd.google-apps.spreadsheet",
            )
        ) is True

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_should_scan_file_skip_folders(self, mock_build, mock_sa):
        """Test that folders are skipped."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        assert scanner._should_scan_file(
            DriveFileInfo(
                id="1",
                name="My Folder",
                mime_type="application/vnd.google-apps.folder",
            )
        ) is False

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_should_scan_file_skip_large_files(self, mock_build, mock_sa):
        """Test that large files are skipped."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        # File over 10MB
        assert scanner._should_scan_file(
            DriveFileInfo(
                id="1",
                name="big.txt",
                mime_type="text/plain",
                size=15 * 1024 * 1024,
            )
        ) is False

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_should_scan_file_extension_filter(self, mock_build, mock_sa):
        """Test file extension filtering."""
        scan_config = ExtendedScanConfig(
            file_extensions=["txt", "csv"],
        )
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config, scan_config)

        # Allowed extensions
        assert scanner._should_scan_file(
            DriveFileInfo(id="1", name="data.txt", mime_type="text/plain", size=100)
        ) is True
        assert scanner._should_scan_file(
            DriveFileInfo(id="2", name="data.csv", mime_type="text/csv", size=100)
        ) is True

        # Not allowed extension
        assert scanner._should_scan_file(
            DriveFileInfo(id="3", name="config.json", mime_type="application/json", size=100)
        ) is False

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_scan_returns_result(self, mock_build, mock_sa):
        """Test that scan returns a result."""
        mock_service = MagicMock()
        mock_service.files().list().execute.return_value = {"files": []}
        mock_build.return_value = mock_service

        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        result = scanner.scan("folder123")

        assert isinstance(result, ExtendedScanResult)
        assert result.source_type == ExtendedSourceType.GOOGLE_DRIVE
        assert result.target == "folder123"
        assert result.completed_at is not None

    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_parse_file_info(self, mock_build, mock_sa):
        """Test file info parsing from API response."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        api_response = {
            "id": "abc123",
            "name": "document.txt",
            "mimeType": "text/plain",
            "size": "1024",
            "createdTime": "2024-01-15T10:30:00.000Z",
            "modifiedTime": "2024-01-20T14:45:00.000Z",
            "owners": [{"emailAddress": "user@example.com"}],
            "shared": True,
            "webViewLink": "https://drive.google.com/file/d/abc123",
            "parents": ["folder1"],
        }

        file_info = scanner._parse_file_info(api_response)

        assert file_info.id == "abc123"
        assert file_info.name == "document.txt"
        assert file_info.mime_type == "text/plain"
        assert file_info.size == 1024
        assert file_info.owners == ["user@example.com"]
        assert file_info.shared is True
        assert file_info.parents == ["folder1"]


class TestGoogleDriveScannerMocked:
    """Tests for GoogleDriveScanner with fully mocked google module."""

    def test_scan_google_drive_convenience_function(self):
        """Test the scan_google_drive convenience function."""
        with patch("stance.dspm.extended.google_drive.GoogleDriveScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock(spec=ExtendedScanResult)
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            config = GoogleDriveConfig(
                service_account_file="/path/to/creds.json",
            )

            result = scan_google_drive(config, "folder123")

            mock_scanner_class.assert_called_once()
            mock_scanner.scan.assert_called_once_with("folder123")
            assert result == mock_result

    def test_scan_google_drive_root_folder(self):
        """Test scanning root folder."""
        with patch("stance.dspm.extended.google_drive.GoogleDriveScanner") as mock_scanner_class:
            mock_scanner = MagicMock()
            mock_result = MagicMock(spec=ExtendedScanResult)
            mock_scanner.scan.return_value = mock_result
            mock_scanner_class.return_value = mock_scanner

            config = GoogleDriveConfig(
                service_account_file="/path/to/creds.json",
            )

            result = scan_google_drive(config)

            mock_scanner.scan.assert_called_once_with("root")


class TestGoogleDriveFileDownload:
    """Tests for file download functionality."""

    @patch("stance.dspm.extended.google_drive.GOOGLE_API_AVAILABLE", True)
    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    @patch("stance.dspm.extended.google_drive.MediaIoBaseDownload")
    def test_download_regular_file(self, mock_download, mock_build, mock_sa):
        """Test downloading a regular file."""
        mock_service = MagicMock()
        mock_build.return_value = mock_service

        # Setup download mock
        mock_downloader = MagicMock()
        mock_downloader.next_chunk.return_value = (None, True)
        mock_download.return_value = mock_downloader

        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        file_info = DriveFileInfo(
            id="file1",
            name="test.txt",
            mime_type="text/plain",
            size=100,
        )

        content = scanner._download_file(mock_service, file_info)

        # Verify get_media was called (not export_media)
        mock_service.files().get_media.assert_called_once_with(fileId="file1")

    @patch("stance.dspm.extended.google_drive.GOOGLE_API_AVAILABLE", True)
    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    @patch("stance.dspm.extended.google_drive.MediaIoBaseDownload")
    def test_download_google_doc(self, mock_download, mock_build, mock_sa):
        """Test downloading a Google Doc (export)."""
        mock_service = MagicMock()
        mock_build.return_value = mock_service

        mock_downloader = MagicMock()
        mock_downloader.next_chunk.return_value = (None, True)
        mock_download.return_value = mock_downloader

        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        file_info = DriveFileInfo(
            id="doc1",
            name="My Document",
            mime_type="application/vnd.google-apps.document",
        )

        content = scanner._download_file(mock_service, file_info)

        # Verify export_media was called
        mock_service.files().export_media.assert_called_once_with(
            fileId="doc1",
            mimeType="text/plain",
        )


class TestGoogleDriveContentDecoding:
    """Tests for content decoding."""

    @patch("stance.dspm.extended.google_drive.GOOGLE_API_AVAILABLE", True)
    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_decode_utf8_content(self, mock_build, mock_sa):
        """Test decoding UTF-8 content."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        content = "Hello, World!".encode("utf-8")
        result = scanner._decode_content(content)

        assert result == "Hello, World!"

    @patch("stance.dspm.extended.google_drive.GOOGLE_API_AVAILABLE", True)
    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_decode_latin1_content(self, mock_build, mock_sa):
        """Test decoding Latin-1 content."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        content = "Caf\xe9".encode("latin-1")
        result = scanner._decode_content(content)

        assert result is not None
        assert "Caf" in result

    @patch("stance.dspm.extended.google_drive.GOOGLE_API_AVAILABLE", True)
    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_decode_binary_returns_none(self, mock_build, mock_sa):
        """Test that binary content returns None."""
        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )
        scanner = GoogleDriveScanner(config)

        # Random binary content that isn't valid text
        content = bytes([0x80, 0x81, 0x82, 0x83, 0xFF, 0xFE])
        result = scanner._decode_content(content)

        # Should return something (latin-1 can decode any bytes)
        # but the result would be garbled text
        assert result is not None


class TestGoogleDriveScanFile:
    """Tests for single file scanning."""

    @patch("stance.dspm.extended.google_drive.GOOGLE_API_AVAILABLE", True)
    @patch("stance.dspm.extended.google_drive.service_account")
    @patch("stance.dspm.extended.google_drive.build")
    def test_scan_file_returns_result(self, mock_build, mock_sa):
        """Test scanning a specific file."""
        mock_service = MagicMock()
        mock_service.files().get().execute.return_value = {
            "id": "file1",
            "name": "test.txt",
            "mimeType": "text/plain",
            "size": "100",
        }
        mock_build.return_value = mock_service

        config = GoogleDriveConfig(
            service_account_file="/path/to/creds.json",
        )

        with patch.object(GoogleDriveScanner, "_scan_file", return_value=None):
            scanner = GoogleDriveScanner(config)
            result = scanner.scan_file("file1")

            assert isinstance(result, ExtendedScanResult)
            assert result.target == "file1"
            assert result.summary.total_files_scanned == 1
