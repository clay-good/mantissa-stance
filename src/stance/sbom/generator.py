"""
SBOM (Software Bill of Materials) generator for Mantissa Stance.

Generates SBOM documents in standard formats (CycloneDX, SPDX) from
parsed dependency information.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from stance.sbom.parser import (
    Dependency,
    DependencyFile,
    DependencyParser,
    PackageEcosystem,
    DependencyScope,
)

logger = logging.getLogger(__name__)


class SBOMFormat(Enum):
    """Supported SBOM output formats."""

    CYCLONEDX_JSON = "cyclonedx-json"
    CYCLONEDX_XML = "cyclonedx-xml"
    SPDX_JSON = "spdx-json"
    SPDX_TAG_VALUE = "spdx-tag-value"
    STANCE_JSON = "stance-json"  # Native format


@dataclass
class SBOMComponent:
    """Represents a component in an SBOM."""

    # Component identification
    name: str
    version: str
    purl: str | None = None  # Package URL (pkg:npm/lodash@4.17.21)

    # Component type
    component_type: str = "library"  # library, application, framework, etc.
    ecosystem: PackageEcosystem = PackageEcosystem.UNKNOWN

    # Hashes
    sha256: str | None = None
    sha512: str | None = None
    sha1: str | None = None
    md5: str | None = None

    # License information
    licenses: list[str] = field(default_factory=list)

    # Source information
    supplier: str | None = None
    author: str | None = None
    description: str | None = None
    homepage: str | None = None
    repository_url: str | None = None
    download_url: str | None = None

    # Scope
    scope: DependencyScope = DependencyScope.RUNTIME
    is_direct: bool = True

    # External references
    external_references: list[dict] = field(default_factory=list)

    # Properties/metadata
    properties: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dependency(cls, dep: Dependency) -> "SBOMComponent":
        """Create SBOMComponent from a Dependency."""
        purl = cls._generate_purl(dep)

        return cls(
            name=dep.name,
            version=dep.version,
            purl=purl,
            ecosystem=dep.ecosystem,
            licenses=[dep.license] if dep.license else [],
            author=dep.author,
            description=dep.description,
            homepage=dep.homepage,
            repository_url=dep.source_url,
            scope=dep.scope,
            is_direct=dep.is_direct,
        )

    @staticmethod
    def _generate_purl(dep: Dependency) -> str | None:
        """Generate Package URL (purl) for a dependency."""
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

        # Handle scoped packages (e.g., @types/node)
        name = dep.name
        namespace = None
        if name.startswith("@") and "/" in name:
            namespace, name = name[1:].split("/", 1)

        if namespace:
            return f"pkg:{purl_type}/{namespace}/{name}@{dep.version}"
        return f"pkg:{purl_type}/{name}@{dep.version}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "type": self.component_type,
            "ecosystem": self.ecosystem.value,
            "licenses": self.licenses,
            "supplier": self.supplier,
            "author": self.author,
            "description": self.description,
            "homepage": self.homepage,
            "repository_url": self.repository_url,
            "scope": self.scope.value,
            "is_direct": self.is_direct,
            "hashes": {
                "sha256": self.sha256,
                "sha512": self.sha512,
                "sha1": self.sha1,
                "md5": self.md5,
            },
        }


@dataclass
class SBOM:
    """Software Bill of Materials document."""

    # Document identification
    serial_number: str = field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    version: int = 1

    # Creation info
    created: datetime = field(default_factory=datetime.utcnow)
    tool_name: str = "Mantissa Stance"
    tool_version: str = "1.0.0"
    tool_vendor: str = "Mantissa"

    # Subject
    subject_name: str | None = None
    subject_version: str | None = None
    subject_description: str | None = None

    # Components
    components: list[SBOMComponent] = field(default_factory=list)

    # Dependencies (relationships)
    dependencies: list[dict] = field(default_factory=list)

    # Metadata
    properties: dict[str, Any] = field(default_factory=dict)

    @property
    def component_count(self) -> int:
        """Total number of components."""
        return len(self.components)

    @property
    def direct_count(self) -> int:
        """Number of direct dependencies."""
        return sum(1 for c in self.components if c.is_direct)

    @property
    def transitive_count(self) -> int:
        """Number of transitive dependencies."""
        return sum(1 for c in self.components if not c.is_direct)

    @property
    def ecosystem_counts(self) -> dict[str, int]:
        """Count components by ecosystem."""
        counts: dict[str, int] = {}
        for comp in self.components:
            eco = comp.ecosystem.value
            counts[eco] = counts.get(eco, 0) + 1
        return counts

    def add_component(self, component: SBOMComponent) -> None:
        """Add a component to the SBOM."""
        self.components.append(component)

    def add_dependency_relationship(
        self,
        parent: str,
        child: str,
    ) -> None:
        """Add a dependency relationship."""
        self.dependencies.append({
            "ref": parent,
            "dependsOn": [child],
        })

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (Stance native format)."""
        return {
            "serial_number": self.serial_number,
            "version": self.version,
            "created": self.created.isoformat(),
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
                "vendor": self.tool_vendor,
            },
            "subject": {
                "name": self.subject_name,
                "version": self.subject_version,
                "description": self.subject_description,
            },
            "summary": {
                "total_components": self.component_count,
                "direct_dependencies": self.direct_count,
                "transitive_dependencies": self.transitive_count,
                "ecosystems": self.ecosystem_counts,
            },
            "components": [c.to_dict() for c in self.components],
            "dependencies": self.dependencies,
            "properties": self.properties,
        }

    def to_cyclonedx(self) -> dict[str, Any]:
        """Convert to CycloneDX 1.5 JSON format."""
        components = []
        for comp in self.components:
            cdx_comp: dict[str, Any] = {
                "type": comp.component_type,
                "name": comp.name,
                "version": comp.version,
            }

            if comp.purl:
                cdx_comp["purl"] = comp.purl
                cdx_comp["bom-ref"] = comp.purl

            if comp.licenses:
                cdx_comp["licenses"] = [
                    {"license": {"id": lic}} if self._is_spdx_id(lic)
                    else {"license": {"name": lic}}
                    for lic in comp.licenses
                ]

            if comp.description:
                cdx_comp["description"] = comp.description

            if comp.author:
                cdx_comp["author"] = comp.author

            if comp.supplier:
                cdx_comp["supplier"] = {"name": comp.supplier}

            # Hashes
            hashes = []
            if comp.sha256:
                hashes.append({"alg": "SHA-256", "content": comp.sha256})
            if comp.sha512:
                hashes.append({"alg": "SHA-512", "content": comp.sha512})
            if comp.sha1:
                hashes.append({"alg": "SHA-1", "content": comp.sha1})
            if comp.md5:
                hashes.append({"alg": "MD5", "content": comp.md5})
            if hashes:
                cdx_comp["hashes"] = hashes

            # External references
            ext_refs = []
            if comp.homepage:
                ext_refs.append({"type": "website", "url": comp.homepage})
            if comp.repository_url:
                ext_refs.append({"type": "vcs", "url": comp.repository_url})
            if ext_refs:
                cdx_comp["externalReferences"] = ext_refs

            # Properties
            if comp.scope != DependencyScope.RUNTIME:
                cdx_comp["scope"] = "optional" if comp.scope == DependencyScope.OPTIONAL else "excluded"

            components.append(cdx_comp)

        # Build dependencies
        cdx_dependencies = []
        for dep in self.dependencies:
            cdx_dependencies.append({
                "ref": dep["ref"],
                "dependsOn": dep.get("dependsOn", []),
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": self.serial_number,
            "version": self.version,
            "metadata": {
                "timestamp": self.created.isoformat() + "Z",
                "tools": {
                    "components": [{
                        "type": "application",
                        "name": self.tool_name,
                        "version": self.tool_version,
                        "vendor": self.tool_vendor,
                    }]
                },
                "component": {
                    "type": "application",
                    "name": self.subject_name or "unknown",
                    "version": self.subject_version or "0.0.0",
                } if self.subject_name else None,
            },
            "components": components,
            "dependencies": cdx_dependencies if cdx_dependencies else None,
        }

    def to_spdx(self) -> dict[str, Any]:
        """Convert to SPDX 2.3 JSON format."""
        doc_namespace = f"https://mantissa.io/sbom/{self.serial_number}"

        packages = []
        relationships = []

        # Add document describes relationship
        root_id = "SPDXRef-DOCUMENT"
        if self.subject_name:
            subject_id = f"SPDXRef-Package-{self._spdx_id(self.subject_name)}"
            relationships.append({
                "spdxElementId": root_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": subject_id,
            })

            # Add root package
            packages.append({
                "SPDXID": subject_id,
                "name": self.subject_name,
                "versionInfo": self.subject_version or "NOASSERTION",
                "downloadLocation": "NOASSERTION",
            })

        for comp in self.components:
            pkg_id = f"SPDXRef-Package-{self._spdx_id(comp.name)}-{self._spdx_id(comp.version)}"

            pkg: dict[str, Any] = {
                "SPDXID": pkg_id,
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": comp.download_url or "NOASSERTION",
            }

            if comp.purl:
                pkg["externalRefs"] = [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl,
                }]

            if comp.licenses:
                # Use first license
                lic = comp.licenses[0]
                if self._is_spdx_id(lic):
                    pkg["licenseConcluded"] = lic
                    pkg["licenseDeclared"] = lic
                else:
                    pkg["licenseConcluded"] = "NOASSERTION"
                    pkg["licenseDeclared"] = f"LicenseRef-{self._spdx_id(lic)}"
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
                pkg["licenseDeclared"] = "NOASSERTION"

            pkg["copyrightText"] = "NOASSERTION"

            if comp.supplier:
                pkg["supplier"] = f"Organization: {comp.supplier}"

            if comp.homepage:
                pkg["homepage"] = comp.homepage

            if comp.description:
                pkg["description"] = comp.description

            # Checksums
            checksums = []
            if comp.sha256:
                checksums.append({"algorithm": "SHA256", "checksumValue": comp.sha256})
            if comp.sha1:
                checksums.append({"algorithm": "SHA1", "checksumValue": comp.sha1})
            if comp.md5:
                checksums.append({"algorithm": "MD5", "checksumValue": comp.md5})
            if checksums:
                pkg["checksums"] = checksums

            packages.append(pkg)

            # Add dependency relationship
            if self.subject_name:
                relationships.append({
                    "spdxElementId": subject_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": pkg_id,
                })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": root_id,
            "name": f"{self.subject_name or 'unknown'}-sbom",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": self.created.isoformat() + "Z",
                "creators": [
                    f"Tool: {self.tool_name}-{self.tool_version}",
                    f"Organization: {self.tool_vendor}",
                ],
            },
            "packages": packages,
            "relationships": relationships,
        }

    def _is_spdx_id(self, license_str: str) -> bool:
        """Check if string is a valid SPDX license identifier."""
        # Common SPDX identifiers
        spdx_ids = {
            "MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0",
            "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "AGPL-3.0",
            "Unlicense", "CC0-1.0", "WTFPL", "Zlib", "BSL-1.0", "EPL-2.0",
            "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
            "Apache-1.0", "Apache-1.1", "Artistic-2.0", "0BSD", "CC-BY-4.0",
        }
        return license_str in spdx_ids

    def _spdx_id(self, value: str) -> str:
        """Convert string to valid SPDX ID."""
        # Replace invalid characters
        return "".join(c if c.isalnum() or c in "-." else "-" for c in value)


class SBOMGenerator:
    """
    Generator for Software Bill of Materials documents.

    Generates SBOM from dependency files or directories, outputting
    in standard formats (CycloneDX, SPDX) or native Stance format.
    """

    def __init__(self):
        """Initialize the SBOM generator."""
        self._parser = DependencyParser()

    def generate_from_file(
        self,
        file_path: str,
        output_format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON,
    ) -> tuple[SBOM, str]:
        """
        Generate SBOM from a single dependency file.

        Args:
            file_path: Path to dependency file
            output_format: Output format

        Returns:
            Tuple of (SBOM object, formatted output string)
        """
        dep_file = self._parser.parse_file(file_path)
        sbom = self._create_sbom(dep_file)
        output = self._format_output(sbom, output_format)
        return sbom, output

    def generate_from_directory(
        self,
        directory: str,
        recursive: bool = True,
        output_format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON,
    ) -> tuple[SBOM, str]:
        """
        Generate SBOM from all dependency files in a directory.

        Args:
            directory: Directory to scan
            recursive: Search subdirectories
            output_format: Output format

        Returns:
            Tuple of (SBOM object, formatted output string)
        """
        dep_files = self._parser.parse_directory(directory, recursive)
        sbom = self._merge_sboms(dep_files, directory)
        output = self._format_output(sbom, output_format)
        return sbom, output

    def generate_from_dependencies(
        self,
        dependencies: list[Dependency],
        project_name: str | None = None,
        project_version: str | None = None,
        output_format: SBOMFormat = SBOMFormat.CYCLONEDX_JSON,
    ) -> tuple[SBOM, str]:
        """
        Generate SBOM from a list of dependencies.

        Args:
            dependencies: List of dependencies
            project_name: Name of the project
            project_version: Version of the project
            output_format: Output format

        Returns:
            Tuple of (SBOM object, formatted output string)
        """
        sbom = SBOM(
            subject_name=project_name,
            subject_version=project_version,
        )

        for dep in dependencies:
            component = SBOMComponent.from_dependency(dep)
            sbom.add_component(component)

        output = self._format_output(sbom, output_format)
        return sbom, output

    def _create_sbom(self, dep_file: DependencyFile) -> SBOM:
        """Create SBOM from a parsed dependency file."""
        sbom = SBOM(
            subject_name=dep_file.project_name,
            subject_version=dep_file.project_version,
            subject_description=dep_file.project_description,
        )

        for dep in dep_file.dependencies:
            component = SBOMComponent.from_dependency(dep)
            sbom.add_component(component)

            # Add dependency relationship if parent is known
            if dep.parent:
                parent_purl = self._find_component_ref(sbom, dep.parent)
                if parent_purl and component.purl:
                    sbom.add_dependency_relationship(parent_purl, component.purl)

        return sbom

    def _merge_sboms(
        self,
        dep_files: list[DependencyFile],
        directory: str,
    ) -> SBOM:
        """Merge multiple dependency files into a single SBOM."""
        sbom = SBOM(
            subject_name=directory.split("/")[-1],
        )

        seen_components: set[str] = set()

        for dep_file in dep_files:
            # Use project info from first file with it
            if not sbom.subject_name and dep_file.project_name:
                sbom.subject_name = dep_file.project_name
            if not sbom.subject_version and dep_file.project_version:
                sbom.subject_version = dep_file.project_version

            for dep in dep_file.dependencies:
                # Deduplicate by name@version
                key = f"{dep.name}@{dep.version}"
                if key not in seen_components:
                    seen_components.add(key)
                    component = SBOMComponent.from_dependency(dep)
                    sbom.add_component(component)

        sbom.properties["source_files"] = [df.file_path for df in dep_files]

        return sbom

    def _find_component_ref(self, sbom: SBOM, name: str) -> str | None:
        """Find component reference (purl) by name."""
        for comp in sbom.components:
            if comp.name == name:
                return comp.purl
        return None

    def _format_output(self, sbom: SBOM, output_format: SBOMFormat) -> str:
        """Format SBOM to requested output format."""
        if output_format == SBOMFormat.CYCLONEDX_JSON:
            data = sbom.to_cyclonedx()
            # Remove None values
            data = self._clean_dict(data)
            return json.dumps(data, indent=2, default=str)

        elif output_format == SBOMFormat.SPDX_JSON:
            data = sbom.to_spdx()
            return json.dumps(data, indent=2, default=str)

        elif output_format == SBOMFormat.STANCE_JSON:
            return json.dumps(sbom.to_dict(), indent=2, default=str)

        elif output_format == SBOMFormat.SPDX_TAG_VALUE:
            return self._format_spdx_tag_value(sbom)

        elif output_format == SBOMFormat.CYCLONEDX_XML:
            return self._format_cyclonedx_xml(sbom)

        else:
            return json.dumps(sbom.to_dict(), indent=2, default=str)

    def _clean_dict(self, d: dict | list | Any) -> Any:
        """Recursively remove None values from dict."""
        if isinstance(d, dict):
            return {k: self._clean_dict(v) for k, v in d.items() if v is not None}
        elif isinstance(d, list):
            return [self._clean_dict(i) for i in d if i is not None]
        return d

    def _format_spdx_tag_value(self, sbom: SBOM) -> str:
        """Format SBOM as SPDX tag-value format."""
        lines = []

        lines.append(f"SPDXVersion: SPDX-2.3")
        lines.append(f"DataLicense: CC0-1.0")
        lines.append(f"SPDXID: SPDXRef-DOCUMENT")
        lines.append(f"DocumentName: {sbom.subject_name or 'unknown'}-sbom")
        lines.append(f"DocumentNamespace: https://mantissa.io/sbom/{sbom.serial_number}")
        lines.append(f"Creator: Tool: {sbom.tool_name}-{sbom.tool_version}")
        lines.append(f"Creator: Organization: {sbom.tool_vendor}")
        lines.append(f"Created: {sbom.created.isoformat()}Z")
        lines.append("")

        for i, comp in enumerate(sbom.components):
            pkg_id = f"SPDXRef-Package-{i}"
            lines.append(f"##### Package: {comp.name}")
            lines.append(f"PackageName: {comp.name}")
            lines.append(f"SPDXID: {pkg_id}")
            lines.append(f"PackageVersion: {comp.version}")
            lines.append(f"PackageDownloadLocation: NOASSERTION")

            if comp.licenses:
                lines.append(f"PackageLicenseConcluded: {comp.licenses[0]}")
            else:
                lines.append(f"PackageLicenseConcluded: NOASSERTION")

            lines.append(f"PackageLicenseDeclared: NOASSERTION")
            lines.append(f"PackageCopyrightText: NOASSERTION")

            if comp.purl:
                lines.append(f"ExternalRef: PACKAGE-MANAGER purl {comp.purl}")

            lines.append("")

        return "\n".join(lines)

    def _format_cyclonedx_xml(self, sbom: SBOM) -> str:
        """Format SBOM as CycloneDX XML format."""
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append('<bom xmlns="http://cyclonedx.org/schema/bom/1.5"')
        lines.append(f'     serialNumber="{sbom.serial_number}"')
        lines.append(f'     version="{sbom.version}">')

        # Metadata
        lines.append("  <metadata>")
        lines.append(f"    <timestamp>{sbom.created.isoformat()}Z</timestamp>")
        lines.append("    <tools>")
        lines.append("      <tool>")
        lines.append(f"        <vendor>{sbom.tool_vendor}</vendor>")
        lines.append(f"        <name>{sbom.tool_name}</name>")
        lines.append(f"        <version>{sbom.tool_version}</version>")
        lines.append("      </tool>")
        lines.append("    </tools>")
        if sbom.subject_name:
            lines.append("    <component type=\"application\">")
            lines.append(f"      <name>{sbom.subject_name}</name>")
            lines.append(f"      <version>{sbom.subject_version or '0.0.0'}</version>")
            lines.append("    </component>")
        lines.append("  </metadata>")

        # Components
        lines.append("  <components>")
        for comp in sbom.components:
            lines.append(f'    <component type="{comp.component_type}">')
            lines.append(f"      <name>{self._xml_escape(comp.name)}</name>")
            lines.append(f"      <version>{self._xml_escape(comp.version)}</version>")
            if comp.purl:
                lines.append(f"      <purl>{self._xml_escape(comp.purl)}</purl>")
            if comp.licenses:
                lines.append("      <licenses>")
                for lic in comp.licenses:
                    lines.append("        <license>")
                    lines.append(f"          <name>{self._xml_escape(lic)}</name>")
                    lines.append("        </license>")
                lines.append("      </licenses>")
            lines.append("    </component>")
        lines.append("  </components>")

        lines.append("</bom>")

        return "\n".join(lines)

    def _xml_escape(self, text: str) -> str:
        """Escape XML special characters."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;"))


def generate_sbom(
    path: str,
    output_format: str = "cyclonedx-json",
    recursive: bool = True,
) -> tuple[SBOM, str]:
    """
    Convenience function to generate an SBOM.

    Args:
        path: File or directory path
        output_format: Output format name
        recursive: Search subdirectories (for directory input)

    Returns:
        Tuple of (SBOM object, formatted output string)
    """
    generator = SBOMGenerator()

    # Parse format
    try:
        fmt = SBOMFormat(output_format)
    except ValueError:
        fmt = SBOMFormat.CYCLONEDX_JSON

    from pathlib import Path
    p = Path(path)

    if p.is_file():
        return generator.generate_from_file(str(p), fmt)
    elif p.is_dir():
        return generator.generate_from_directory(str(p), recursive, fmt)
    else:
        raise FileNotFoundError(f"Path not found: {path}")
