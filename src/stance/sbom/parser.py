"""
Dependency file parser for SBOM generation.

Parses various dependency manifest files from different package ecosystems
to extract dependency information for SBOM generation and analysis.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PackageEcosystem(Enum):
    """Package ecosystem identifiers."""

    NPM = "npm"
    PYPI = "pypi"
    GO = "go"
    CARGO = "cargo"
    MAVEN = "maven"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"
    COMPOSER = "composer"
    APK = "apk"
    DEB = "deb"
    RPM = "rpm"
    UNKNOWN = "unknown"


class DependencyScope(Enum):
    """Dependency scope/type."""

    RUNTIME = "runtime"
    DEVELOPMENT = "development"
    BUILD = "build"
    TEST = "test"
    OPTIONAL = "optional"
    PEER = "peer"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    """Represents a single dependency."""

    name: str
    version: str
    ecosystem: PackageEcosystem = PackageEcosystem.UNKNOWN
    scope: DependencyScope = DependencyScope.RUNTIME

    # Version constraints
    version_constraint: str | None = None  # Original constraint (^1.0.0, >=2.0, etc.)
    resolved_version: str | None = None  # Actual resolved version

    # Source information
    source_url: str | None = None  # Repository URL
    registry_url: str | None = None  # Package registry URL
    integrity_hash: str | None = None  # SHA256, SHA512, or SHA1 hash

    # Metadata
    license: str | None = None
    description: str | None = None
    author: str | None = None
    homepage: str | None = None

    # Dependency graph
    is_direct: bool = True  # Direct vs transitive
    parent: str | None = None  # Parent dependency (for transitive)
    dependencies: list[str] = field(default_factory=list)  # Child dependencies

    # Additional metadata
    deprecated: bool = False
    deprecated_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem.value,
            "scope": self.scope.value,
            "version_constraint": self.version_constraint,
            "resolved_version": self.resolved_version,
            "source_url": self.source_url,
            "registry_url": self.registry_url,
            "integrity_hash": self.integrity_hash,
            "license": self.license,
            "description": self.description,
            "author": self.author,
            "homepage": self.homepage,
            "is_direct": self.is_direct,
            "parent": self.parent,
            "dependencies": self.dependencies,
            "deprecated": self.deprecated,
            "deprecated_message": self.deprecated_message,
        }


@dataclass
class DependencyFile:
    """Represents a parsed dependency file."""

    file_path: str
    file_type: str
    ecosystem: PackageEcosystem
    dependencies: list[Dependency] = field(default_factory=list)

    # Project metadata
    project_name: str | None = None
    project_version: str | None = None
    project_description: str | None = None
    project_license: str | None = None

    # Parse metadata
    parse_timestamp: datetime = field(default_factory=datetime.utcnow)
    parse_errors: list[str] = field(default_factory=list)

    @property
    def direct_dependencies(self) -> list[Dependency]:
        """Get only direct dependencies."""
        return [d for d in self.dependencies if d.is_direct]

    @property
    def transitive_dependencies(self) -> list[Dependency]:
        """Get only transitive dependencies."""
        return [d for d in self.dependencies if not d.is_direct]

    @property
    def runtime_dependencies(self) -> list[Dependency]:
        """Get runtime dependencies."""
        return [d for d in self.dependencies if d.scope == DependencyScope.RUNTIME]

    @property
    def dev_dependencies(self) -> list[Dependency]:
        """Get development dependencies."""
        return [d for d in self.dependencies if d.scope == DependencyScope.DEVELOPMENT]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "file_path": self.file_path,
            "file_type": self.file_type,
            "ecosystem": self.ecosystem.value,
            "project_name": self.project_name,
            "project_version": self.project_version,
            "project_description": self.project_description,
            "project_license": self.project_license,
            "total_dependencies": len(self.dependencies),
            "direct_count": len(self.direct_dependencies),
            "transitive_count": len(self.transitive_dependencies),
            "dependencies": [d.to_dict() for d in self.dependencies],
            "parse_timestamp": self.parse_timestamp.isoformat(),
            "parse_errors": self.parse_errors,
        }


class DependencyParser:
    """
    Parser for dependency manifest files.

    Supports multiple package ecosystems and file formats:
    - NPM: package.json, package-lock.json, yarn.lock
    - Python: requirements.txt, Pipfile, Pipfile.lock, pyproject.toml, poetry.lock
    - Go: go.mod, go.sum
    - Rust: Cargo.toml, Cargo.lock
    - Maven: pom.xml
    - NuGet: packages.config, *.csproj
    - Ruby: Gemfile, Gemfile.lock
    - PHP: composer.json, composer.lock
    """

    # File type to parser method mapping
    PARSERS = {
        "package.json": "_parse_package_json",
        "package-lock.json": "_parse_package_lock_json",
        "yarn.lock": "_parse_yarn_lock",
        "requirements.txt": "_parse_requirements_txt",
        "Pipfile": "_parse_pipfile",
        "Pipfile.lock": "_parse_pipfile_lock",
        "pyproject.toml": "_parse_pyproject_toml",
        "poetry.lock": "_parse_poetry_lock",
        "go.mod": "_parse_go_mod",
        "go.sum": "_parse_go_sum",
        "Cargo.toml": "_parse_cargo_toml",
        "Cargo.lock": "_parse_cargo_lock",
        "Gemfile": "_parse_gemfile",
        "Gemfile.lock": "_parse_gemfile_lock",
        "composer.json": "_parse_composer_json",
        "composer.lock": "_parse_composer_lock",
    }

    def parse_file(self, file_path: str | Path) -> DependencyFile:
        """
        Parse a dependency file.

        Args:
            file_path: Path to the dependency file

        Returns:
            DependencyFile with parsed dependencies
        """
        path = Path(file_path)
        if not path.exists():
            return DependencyFile(
                file_path=str(path),
                file_type="unknown",
                ecosystem=PackageEcosystem.UNKNOWN,
                parse_errors=[f"File not found: {path}"],
            )

        file_name = path.name
        parser_method = self.PARSERS.get(file_name)

        if parser_method is None:
            # Try matching by extension or pattern
            parser_method = self._get_parser_by_pattern(file_name)

        if parser_method is None:
            return DependencyFile(
                file_path=str(path),
                file_type="unknown",
                ecosystem=PackageEcosystem.UNKNOWN,
                parse_errors=[f"Unsupported file type: {file_name}"],
            )

        try:
            content = path.read_text(encoding="utf-8")
            parser = getattr(self, parser_method)
            return parser(str(path), content)
        except Exception as e:
            logger.exception(f"Failed to parse {path}")
            return DependencyFile(
                file_path=str(path),
                file_type=file_name,
                ecosystem=PackageEcosystem.UNKNOWN,
                parse_errors=[f"Parse error: {str(e)}"],
            )

    def parse_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> list[DependencyFile]:
        """
        Parse all dependency files in a directory.

        Args:
            directory: Directory to scan
            recursive: Search subdirectories

        Returns:
            List of parsed DependencyFile objects
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return []

        results: list[DependencyFile] = []
        patterns = list(self.PARSERS.keys())

        for pattern in patterns:
            if recursive:
                files = dir_path.rglob(pattern)
            else:
                files = dir_path.glob(pattern)

            for file_path in files:
                # Skip node_modules, vendor, etc.
                if self._should_skip_path(file_path):
                    continue
                result = self.parse_file(file_path)
                results.append(result)

        return results

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped."""
        skip_dirs = {
            "node_modules",
            "vendor",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "env",
            ".tox",
            "dist",
            "build",
            "target",
        }
        return any(part in skip_dirs for part in path.parts)

    def _get_parser_by_pattern(self, file_name: str) -> str | None:
        """Get parser method by file pattern."""
        if file_name.endswith(".csproj"):
            return "_parse_csproj"
        if file_name == "packages.config":
            return "_parse_packages_config"
        return None

    # =========================================================================
    # NPM Parsers
    # =========================================================================

    def _parse_package_json(self, file_path: str, content: str) -> DependencyFile:
        """Parse package.json (NPM)."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return DependencyFile(
                file_path=file_path,
                file_type="package.json",
                ecosystem=PackageEcosystem.NPM,
                parse_errors=[f"Invalid JSON: {e}"],
            )

        # Parse regular dependencies
        for name, version in data.get("dependencies", {}).items():
            dep = Dependency(
                name=name,
                version=self._normalize_npm_version(version),
                version_constraint=version,
                ecosystem=PackageEcosystem.NPM,
                scope=DependencyScope.RUNTIME,
                is_direct=True,
            )
            dependencies.append(dep)

        # Parse dev dependencies
        for name, version in data.get("devDependencies", {}).items():
            dep = Dependency(
                name=name,
                version=self._normalize_npm_version(version),
                version_constraint=version,
                ecosystem=PackageEcosystem.NPM,
                scope=DependencyScope.DEVELOPMENT,
                is_direct=True,
            )
            dependencies.append(dep)

        # Parse peer dependencies
        for name, version in data.get("peerDependencies", {}).items():
            dep = Dependency(
                name=name,
                version=self._normalize_npm_version(version),
                version_constraint=version,
                ecosystem=PackageEcosystem.NPM,
                scope=DependencyScope.PEER,
                is_direct=True,
            )
            dependencies.append(dep)

        # Parse optional dependencies
        for name, version in data.get("optionalDependencies", {}).items():
            dep = Dependency(
                name=name,
                version=self._normalize_npm_version(version),
                version_constraint=version,
                ecosystem=PackageEcosystem.NPM,
                scope=DependencyScope.OPTIONAL,
                is_direct=True,
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="package.json",
            ecosystem=PackageEcosystem.NPM,
            dependencies=dependencies,
            project_name=data.get("name"),
            project_version=data.get("version"),
            project_description=data.get("description"),
            project_license=data.get("license"),
            parse_errors=errors,
        )

    def _parse_package_lock_json(self, file_path: str, content: str) -> DependencyFile:
        """Parse package-lock.json (NPM lockfile)."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return DependencyFile(
                file_path=file_path,
                file_type="package-lock.json",
                ecosystem=PackageEcosystem.NPM,
                parse_errors=[f"Invalid JSON: {e}"],
            )

        # NPM v2/v3 lockfile format (packages key)
        packages = data.get("packages", {})
        if packages:
            for pkg_path, pkg_info in packages.items():
                if not pkg_path:  # Root package
                    continue

                # Extract package name from path
                name = pkg_path.replace("node_modules/", "")
                if "/" in name and not name.startswith("@"):
                    # Nested dependency
                    parts = name.split("/node_modules/")
                    name = parts[-1]

                version = pkg_info.get("version", "unknown")
                dep = Dependency(
                    name=name,
                    version=version,
                    resolved_version=version,
                    ecosystem=PackageEcosystem.NPM,
                    scope=DependencyScope.DEVELOPMENT if pkg_info.get("dev") else DependencyScope.RUNTIME,
                    is_direct="node_modules/" + name == pkg_path,
                    integrity_hash=pkg_info.get("integrity"),
                    license=pkg_info.get("license"),
                )
                dependencies.append(dep)
        else:
            # NPM v1 lockfile format (dependencies key)
            self._parse_npm_v1_dependencies(
                data.get("dependencies", {}),
                dependencies,
                is_direct=True,
            )

        return DependencyFile(
            file_path=file_path,
            file_type="package-lock.json",
            ecosystem=PackageEcosystem.NPM,
            dependencies=dependencies,
            project_name=data.get("name"),
            project_version=data.get("version"),
            parse_errors=errors,
        )

    def _parse_npm_v1_dependencies(
        self,
        deps: dict,
        result: list[Dependency],
        is_direct: bool,
        parent: str | None = None,
    ) -> None:
        """Recursively parse NPM v1 lockfile dependencies."""
        for name, info in deps.items():
            version = info.get("version", "unknown")
            dep = Dependency(
                name=name,
                version=version,
                resolved_version=version,
                ecosystem=PackageEcosystem.NPM,
                scope=DependencyScope.DEVELOPMENT if info.get("dev") else DependencyScope.RUNTIME,
                is_direct=is_direct,
                parent=parent,
                integrity_hash=info.get("integrity"),
            )
            result.append(dep)

            # Recurse into nested dependencies
            if "dependencies" in info:
                self._parse_npm_v1_dependencies(
                    info["dependencies"],
                    result,
                    is_direct=False,
                    parent=name,
                )

    def _parse_yarn_lock(self, file_path: str, content: str) -> DependencyFile:
        """Parse yarn.lock."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        # Yarn.lock uses a custom format
        # Pattern: "package@version": with resolved version and integrity
        current_package = None
        current_version = None
        current_resolved = None
        current_integrity = None

        lines = content.split("\n")
        for line in lines:
            line = line.rstrip()

            # New package entry
            if line and not line.startswith(" ") and line.endswith(":"):
                # Save previous package
                if current_package and current_version:
                    dep = Dependency(
                        name=current_package,
                        version=current_version,
                        resolved_version=current_resolved,
                        ecosystem=PackageEcosystem.NPM,
                        scope=DependencyScope.RUNTIME,
                        integrity_hash=current_integrity,
                    )
                    dependencies.append(dep)

                # Parse new package
                pkg_spec = line.rstrip(":").strip('"')
                # Handle multiple version specs: "pkg@^1.0.0, pkg@^1.2.0":
                first_spec = pkg_spec.split(",")[0].strip()
                if "@" in first_spec:
                    # Handle scoped packages (@org/pkg@version)
                    if first_spec.startswith("@"):
                        parts = first_spec[1:].split("@")
                        current_package = "@" + parts[0]
                    else:
                        parts = first_spec.split("@")
                        current_package = parts[0]
                else:
                    current_package = first_spec

                current_version = None
                current_resolved = None
                current_integrity = None

            elif line.startswith("  version"):
                current_version = line.split('"')[1] if '"' in line else line.split()[-1]
            elif line.startswith("  resolved"):
                current_resolved = line.split('"')[1] if '"' in line else None
            elif line.startswith("  integrity"):
                current_integrity = line.split()[-1]

        # Don't forget last package
        if current_package and current_version:
            dep = Dependency(
                name=current_package,
                version=current_version,
                resolved_version=current_resolved,
                ecosystem=PackageEcosystem.NPM,
                scope=DependencyScope.RUNTIME,
                integrity_hash=current_integrity,
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="yarn.lock",
            ecosystem=PackageEcosystem.NPM,
            dependencies=dependencies,
            parse_errors=errors,
        )

    def _normalize_npm_version(self, version: str) -> str:
        """Normalize NPM version constraint to base version."""
        # Remove prefix operators
        version = version.lstrip("^~>=<!")
        # Take first version if range
        if " " in version:
            version = version.split()[0]
        return version

    # =========================================================================
    # Python Parsers
    # =========================================================================

    def _parse_requirements_txt(self, file_path: str, content: str) -> DependencyFile:
        """Parse requirements.txt."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        for line in content.split("\n"):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Skip -r, -e, -i options
            if line.startswith("-"):
                continue

            # Parse package specification
            dep = self._parse_pip_requirement(line)
            if dep:
                dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="requirements.txt",
            ecosystem=PackageEcosystem.PYPI,
            dependencies=dependencies,
            parse_errors=errors,
        )

    def _parse_pip_requirement(self, line: str) -> Dependency | None:
        """Parse a single pip requirement line."""
        # Remove inline comments
        if "#" in line:
            line = line.split("#")[0].strip()

        if not line:
            return None

        # Handle extras: package[extra1,extra2]
        extras_match = re.match(r"([a-zA-Z0-9_-]+)\[([^\]]+)\](.*)$", line)
        if extras_match:
            name = extras_match.group(1)
            line = name + extras_match.group(3)

        # Parse version specifiers
        # Patterns: ==, >=, <=, ~=, !=, <, >
        version_pattern = r"([a-zA-Z0-9_-]+)\s*([=<>!~]+)\s*([^\s,;]+)"
        match = re.match(version_pattern, line)

        if match:
            name = match.group(1)
            operator = match.group(2)
            version = match.group(3)
            return Dependency(
                name=name.lower(),
                version=version,
                version_constraint=f"{operator}{version}",
                ecosystem=PackageEcosystem.PYPI,
                scope=DependencyScope.RUNTIME,
                is_direct=True,
            )

        # No version specified
        name_match = re.match(r"([a-zA-Z0-9_-]+)", line)
        if name_match:
            return Dependency(
                name=name_match.group(1).lower(),
                version="*",
                ecosystem=PackageEcosystem.PYPI,
                scope=DependencyScope.RUNTIME,
                is_direct=True,
            )

        return None

    def _parse_pipfile(self, file_path: str, content: str) -> DependencyFile:
        """Parse Pipfile (TOML format)."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        try:
            # Simple TOML parsing for Pipfile
            data = self._parse_simple_toml(content)
        except Exception as e:
            return DependencyFile(
                file_path=file_path,
                file_type="Pipfile",
                ecosystem=PackageEcosystem.PYPI,
                parse_errors=[f"Parse error: {e}"],
            )

        # Parse packages
        for name, spec in data.get("packages", {}).items():
            version = self._extract_pipfile_version(spec)
            dep = Dependency(
                name=name.lower(),
                version=version,
                version_constraint=str(spec) if spec != "*" else None,
                ecosystem=PackageEcosystem.PYPI,
                scope=DependencyScope.RUNTIME,
                is_direct=True,
            )
            dependencies.append(dep)

        # Parse dev-packages
        for name, spec in data.get("dev-packages", {}).items():
            version = self._extract_pipfile_version(spec)
            dep = Dependency(
                name=name.lower(),
                version=version,
                version_constraint=str(spec) if spec != "*" else None,
                ecosystem=PackageEcosystem.PYPI,
                scope=DependencyScope.DEVELOPMENT,
                is_direct=True,
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="Pipfile",
            ecosystem=PackageEcosystem.PYPI,
            dependencies=dependencies,
            parse_errors=errors,
        )

    def _parse_pipfile_lock(self, file_path: str, content: str) -> DependencyFile:
        """Parse Pipfile.lock (JSON format)."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return DependencyFile(
                file_path=file_path,
                file_type="Pipfile.lock",
                ecosystem=PackageEcosystem.PYPI,
                parse_errors=[f"Invalid JSON: {e}"],
            )

        # Parse default (runtime) dependencies
        for name, info in data.get("default", {}).items():
            version = info.get("version", "").lstrip("=")
            dep = Dependency(
                name=name.lower(),
                version=version,
                resolved_version=version,
                ecosystem=PackageEcosystem.PYPI,
                scope=DependencyScope.RUNTIME,
                integrity_hash=info.get("hashes", [None])[0] if info.get("hashes") else None,
            )
            dependencies.append(dep)

        # Parse develop dependencies
        for name, info in data.get("develop", {}).items():
            version = info.get("version", "").lstrip("=")
            dep = Dependency(
                name=name.lower(),
                version=version,
                resolved_version=version,
                ecosystem=PackageEcosystem.PYPI,
                scope=DependencyScope.DEVELOPMENT,
                integrity_hash=info.get("hashes", [None])[0] if info.get("hashes") else None,
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="Pipfile.lock",
            ecosystem=PackageEcosystem.PYPI,
            dependencies=dependencies,
            parse_errors=errors,
        )

    def _parse_pyproject_toml(self, file_path: str, content: str) -> DependencyFile:
        """Parse pyproject.toml."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        try:
            data = self._parse_simple_toml(content)
        except Exception as e:
            return DependencyFile(
                file_path=file_path,
                file_type="pyproject.toml",
                ecosystem=PackageEcosystem.PYPI,
                parse_errors=[f"Parse error: {e}"],
            )

        project_name = None
        project_version = None

        # PEP 621 format
        project = data.get("project", {})
        if project:
            project_name = project.get("name")
            project_version = project.get("version")

            for dep_str in project.get("dependencies", []):
                dep = self._parse_pip_requirement(dep_str)
                if dep:
                    dependencies.append(dep)

            # Optional dependencies
            for group, deps in project.get("optional-dependencies", {}).items():
                for dep_str in deps:
                    dep = self._parse_pip_requirement(dep_str)
                    if dep:
                        dep.scope = DependencyScope.OPTIONAL
                        dependencies.append(dep)

        # Poetry format
        poetry = data.get("tool", {}).get("poetry", {})
        if poetry:
            project_name = project_name or poetry.get("name")
            project_version = project_version or poetry.get("version")

            for name, spec in poetry.get("dependencies", {}).items():
                if name.lower() == "python":
                    continue
                version = self._extract_poetry_version(spec)
                dep = Dependency(
                    name=name.lower(),
                    version=version,
                    ecosystem=PackageEcosystem.PYPI,
                    scope=DependencyScope.RUNTIME,
                    is_direct=True,
                )
                dependencies.append(dep)

            for name, spec in poetry.get("dev-dependencies", {}).items():
                version = self._extract_poetry_version(spec)
                dep = Dependency(
                    name=name.lower(),
                    version=version,
                    ecosystem=PackageEcosystem.PYPI,
                    scope=DependencyScope.DEVELOPMENT,
                    is_direct=True,
                )
                dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="pyproject.toml",
            ecosystem=PackageEcosystem.PYPI,
            dependencies=dependencies,
            project_name=project_name,
            project_version=project_version,
            parse_errors=errors,
        )

    def _parse_poetry_lock(self, file_path: str, content: str) -> DependencyFile:
        """Parse poetry.lock."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        try:
            data = self._parse_simple_toml(content)
        except Exception as e:
            return DependencyFile(
                file_path=file_path,
                file_type="poetry.lock",
                ecosystem=PackageEcosystem.PYPI,
                parse_errors=[f"Parse error: {e}"],
            )

        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            category = pkg.get("category", "main")

            dep = Dependency(
                name=name.lower(),
                version=version,
                resolved_version=version,
                ecosystem=PackageEcosystem.PYPI,
                scope=DependencyScope.DEVELOPMENT if category == "dev" else DependencyScope.RUNTIME,
                description=pkg.get("description"),
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="poetry.lock",
            ecosystem=PackageEcosystem.PYPI,
            dependencies=dependencies,
            parse_errors=errors,
        )

    def _extract_pipfile_version(self, spec: Any) -> str:
        """Extract version from Pipfile spec."""
        if isinstance(spec, str):
            return spec.lstrip("=<>~!")
        if isinstance(spec, dict):
            return spec.get("version", "*").lstrip("=<>~!")
        return "*"

    def _extract_poetry_version(self, spec: Any) -> str:
        """Extract version from Poetry spec."""
        if isinstance(spec, str):
            return spec.lstrip("^~>=<!")
        if isinstance(spec, dict):
            return spec.get("version", "*").lstrip("^~>=<!")
        return "*"

    # =========================================================================
    # Go Parsers
    # =========================================================================

    def _parse_go_mod(self, file_path: str, content: str) -> DependencyFile:
        """Parse go.mod."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        module_name = None
        go_version = None
        in_require = False

        for line in content.split("\n"):
            line = line.strip()

            # Module declaration
            if line.startswith("module "):
                module_name = line.split()[1]
                continue

            # Go version
            if line.startswith("go "):
                go_version = line.split()[1]
                continue

            # Start of require block
            if line == "require (" or line.startswith("require ("):
                in_require = True
                continue

            # End of require block
            if line == ")":
                in_require = False
                continue

            # Single require line
            if line.startswith("require "):
                parts = line.split()[1:]
                if len(parts) >= 2:
                    dep = Dependency(
                        name=parts[0],
                        version=parts[1],
                        ecosystem=PackageEcosystem.GO,
                        scope=DependencyScope.RUNTIME,
                        is_direct=True,
                    )
                    dependencies.append(dep)
                continue

            # Inside require block
            if in_require and line and not line.startswith("//"):
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1]
                    is_indirect = "// indirect" in line

                    dep = Dependency(
                        name=name,
                        version=version,
                        ecosystem=PackageEcosystem.GO,
                        scope=DependencyScope.RUNTIME,
                        is_direct=not is_indirect,
                    )
                    dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="go.mod",
            ecosystem=PackageEcosystem.GO,
            dependencies=dependencies,
            project_name=module_name,
            project_version=go_version,
            parse_errors=errors,
        )

    def _parse_go_sum(self, file_path: str, content: str) -> DependencyFile:
        """Parse go.sum."""
        dependencies: list[Dependency] = []
        seen: set[tuple[str, str]] = set()

        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) >= 3:
                name = parts[0]
                version = parts[1].split("/")[0]  # Remove /go.mod suffix
                checksum = parts[2]

                key = (name, version)
                if key not in seen:
                    seen.add(key)
                    dep = Dependency(
                        name=name,
                        version=version,
                        resolved_version=version,
                        ecosystem=PackageEcosystem.GO,
                        scope=DependencyScope.RUNTIME,
                        integrity_hash=checksum,
                    )
                    dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="go.sum",
            ecosystem=PackageEcosystem.GO,
            dependencies=dependencies,
        )

    # =========================================================================
    # Rust (Cargo) Parsers
    # =========================================================================

    def _parse_cargo_toml(self, file_path: str, content: str) -> DependencyFile:
        """Parse Cargo.toml."""
        dependencies: list[Dependency] = []
        errors: list[str] = []

        try:
            data = self._parse_simple_toml(content)
        except Exception as e:
            return DependencyFile(
                file_path=file_path,
                file_type="Cargo.toml",
                ecosystem=PackageEcosystem.CARGO,
                parse_errors=[f"Parse error: {e}"],
            )

        package = data.get("package", {})
        project_name = package.get("name")
        project_version = package.get("version")

        # Regular dependencies
        for name, spec in data.get("dependencies", {}).items():
            version = self._extract_cargo_version(spec)
            dep = Dependency(
                name=name,
                version=version,
                ecosystem=PackageEcosystem.CARGO,
                scope=DependencyScope.RUNTIME,
                is_direct=True,
            )
            dependencies.append(dep)

        # Dev dependencies
        for name, spec in data.get("dev-dependencies", {}).items():
            version = self._extract_cargo_version(spec)
            dep = Dependency(
                name=name,
                version=version,
                ecosystem=PackageEcosystem.CARGO,
                scope=DependencyScope.DEVELOPMENT,
                is_direct=True,
            )
            dependencies.append(dep)

        # Build dependencies
        for name, spec in data.get("build-dependencies", {}).items():
            version = self._extract_cargo_version(spec)
            dep = Dependency(
                name=name,
                version=version,
                ecosystem=PackageEcosystem.CARGO,
                scope=DependencyScope.BUILD,
                is_direct=True,
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="Cargo.toml",
            ecosystem=PackageEcosystem.CARGO,
            dependencies=dependencies,
            project_name=project_name,
            project_version=project_version,
            parse_errors=errors,
        )

    def _parse_cargo_lock(self, file_path: str, content: str) -> DependencyFile:
        """Parse Cargo.lock."""
        dependencies: list[Dependency] = []

        try:
            data = self._parse_simple_toml(content)
        except Exception as e:
            return DependencyFile(
                file_path=file_path,
                file_type="Cargo.lock",
                ecosystem=PackageEcosystem.CARGO,
                parse_errors=[f"Parse error: {e}"],
            )

        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")

            dep = Dependency(
                name=name,
                version=version,
                resolved_version=version,
                ecosystem=PackageEcosystem.CARGO,
                scope=DependencyScope.RUNTIME,
                source_url=pkg.get("source"),
                integrity_hash=pkg.get("checksum"),
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="Cargo.lock",
            ecosystem=PackageEcosystem.CARGO,
            dependencies=dependencies,
        )

    def _extract_cargo_version(self, spec: Any) -> str:
        """Extract version from Cargo spec."""
        if isinstance(spec, str):
            return spec
        if isinstance(spec, dict):
            return spec.get("version", "*")
        return "*"

    # =========================================================================
    # Ruby (Bundler) Parsers
    # =========================================================================

    def _parse_gemfile(self, file_path: str, content: str) -> DependencyFile:
        """Parse Gemfile."""
        dependencies: list[Dependency] = []

        # Pattern: gem 'name', 'version' or gem "name", "version"
        gem_pattern = r"""gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?"""

        for match in re.finditer(gem_pattern, content):
            name = match.group(1)
            version = match.group(2) or "*"

            dep = Dependency(
                name=name,
                version=version.lstrip("~>=<"),
                version_constraint=version if version != "*" else None,
                ecosystem=PackageEcosystem.RUBYGEMS,
                scope=DependencyScope.RUNTIME,
                is_direct=True,
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="Gemfile",
            ecosystem=PackageEcosystem.RUBYGEMS,
            dependencies=dependencies,
        )

    def _parse_gemfile_lock(self, file_path: str, content: str) -> DependencyFile:
        """Parse Gemfile.lock."""
        dependencies: list[Dependency] = []
        in_specs = False

        for line in content.split("\n"):
            if line.strip() == "specs:":
                in_specs = True
                continue

            if in_specs:
                # Gem entry: "    gem_name (version)"
                match = re.match(r"^\s{4}([a-zA-Z0-9_-]+)\s+\(([^)]+)\)$", line)
                if match:
                    name = match.group(1)
                    version = match.group(2)

                    dep = Dependency(
                        name=name,
                        version=version,
                        resolved_version=version,
                        ecosystem=PackageEcosystem.RUBYGEMS,
                        scope=DependencyScope.RUNTIME,
                    )
                    dependencies.append(dep)
                elif line and not line.startswith(" " * 6) and not line.startswith(" " * 4):
                    in_specs = False

        return DependencyFile(
            file_path=file_path,
            file_type="Gemfile.lock",
            ecosystem=PackageEcosystem.RUBYGEMS,
            dependencies=dependencies,
        )

    # =========================================================================
    # PHP (Composer) Parsers
    # =========================================================================

    def _parse_composer_json(self, file_path: str, content: str) -> DependencyFile:
        """Parse composer.json."""
        dependencies: list[Dependency] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return DependencyFile(
                file_path=file_path,
                file_type="composer.json",
                ecosystem=PackageEcosystem.COMPOSER,
                parse_errors=[f"Invalid JSON: {e}"],
            )

        # Runtime dependencies
        for name, version in data.get("require", {}).items():
            if name == "php" or name.startswith("ext-"):
                continue
            dep = Dependency(
                name=name,
                version=version.lstrip("^~>=<"),
                version_constraint=version,
                ecosystem=PackageEcosystem.COMPOSER,
                scope=DependencyScope.RUNTIME,
                is_direct=True,
            )
            dependencies.append(dep)

        # Dev dependencies
        for name, version in data.get("require-dev", {}).items():
            dep = Dependency(
                name=name,
                version=version.lstrip("^~>=<"),
                version_constraint=version,
                ecosystem=PackageEcosystem.COMPOSER,
                scope=DependencyScope.DEVELOPMENT,
                is_direct=True,
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="composer.json",
            ecosystem=PackageEcosystem.COMPOSER,
            dependencies=dependencies,
            project_name=data.get("name"),
            project_description=data.get("description"),
            project_license=data.get("license"),
        )

    def _parse_composer_lock(self, file_path: str, content: str) -> DependencyFile:
        """Parse composer.lock."""
        dependencies: list[Dependency] = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            return DependencyFile(
                file_path=file_path,
                file_type="composer.lock",
                ecosystem=PackageEcosystem.COMPOSER,
                parse_errors=[f"Invalid JSON: {e}"],
            )

        # Runtime packages
        for pkg in data.get("packages", []):
            dep = Dependency(
                name=pkg.get("name", ""),
                version=pkg.get("version", "").lstrip("v"),
                resolved_version=pkg.get("version", "").lstrip("v"),
                ecosystem=PackageEcosystem.COMPOSER,
                scope=DependencyScope.RUNTIME,
                license=pkg.get("license", [None])[0] if pkg.get("license") else None,
                description=pkg.get("description"),
                source_url=pkg.get("source", {}).get("url"),
            )
            dependencies.append(dep)

        # Dev packages
        for pkg in data.get("packages-dev", []):
            dep = Dependency(
                name=pkg.get("name", ""),
                version=pkg.get("version", "").lstrip("v"),
                resolved_version=pkg.get("version", "").lstrip("v"),
                ecosystem=PackageEcosystem.COMPOSER,
                scope=DependencyScope.DEVELOPMENT,
                license=pkg.get("license", [None])[0] if pkg.get("license") else None,
                description=pkg.get("description"),
                source_url=pkg.get("source", {}).get("url"),
            )
            dependencies.append(dep)

        return DependencyFile(
            file_path=file_path,
            file_type="composer.lock",
            ecosystem=PackageEcosystem.COMPOSER,
            dependencies=dependencies,
        )

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _parse_simple_toml(self, content: str) -> dict[str, Any]:
        """
        Simple TOML parser for dependency files.

        This is a basic parser that handles common TOML patterns used in
        dependency files. For full TOML support, use the tomli library.
        """
        result: dict[str, Any] = {}
        current_section: list[str] = []
        current_array: list[dict] | None = None
        current_item: dict | None = None

        for line in content.split("\n"):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Section header: [section] or [section.subsection]
            if line.startswith("[") and line.endswith("]"):
                section_name = line[1:-1].strip()

                # Handle array of tables: [[package]]
                if section_name.startswith("[") and section_name.endswith("]"):
                    section_name = section_name[1:-1]
                    if current_item is not None and current_array is not None:
                        current_array.append(current_item)
                    current_item = {}
                    parts = section_name.split(".")
                    self._ensure_path(result, parts[:-1])
                    parent = self._get_path(result, parts[:-1])
                    if parts[-1] not in parent:
                        parent[parts[-1]] = []
                    current_array = parent[parts[-1]]
                    current_section = parts
                else:
                    if current_item is not None and current_array is not None:
                        current_array.append(current_item)
                        current_item = None
                        current_array = None

                    current_section = section_name.split(".")
                    self._ensure_path(result, current_section)
                continue

            # Key-value pair
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()

                # Parse value
                parsed_value = self._parse_toml_value(value)

                # Store in current section or item
                if current_item is not None:
                    current_item[key] = parsed_value
                elif current_section:
                    target = self._get_path(result, current_section)
                    target[key] = parsed_value
                else:
                    result[key] = parsed_value

        # Don't forget last array item
        if current_item is not None and current_array is not None:
            current_array.append(current_item)

        return result

    def _parse_toml_value(self, value: str) -> Any:
        """Parse a TOML value."""
        # String (double or single quoted)
        if (value.startswith('"') and value.endswith('"')) or \
           (value.startswith("'") and value.endswith("'")):
            return value[1:-1]

        # Array
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            if not inner:
                return []
            items = []
            for item in inner.split(","):
                item = item.strip()
                if item:
                    items.append(self._parse_toml_value(item))
            return items

        # Inline table
        if value.startswith("{") and value.endswith("}"):
            inner = value[1:-1].strip()
            if not inner:
                return {}
            result = {}
            for pair in inner.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    result[k.strip()] = self._parse_toml_value(v.strip())
            return result

        # Boolean
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False

        # Number
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            pass

        return value

    def _ensure_path(self, data: dict, path: list[str]) -> None:
        """Ensure a nested path exists in dictionary."""
        current = data
        for key in path:
            if key not in current:
                current[key] = {}
            current = current[key]

    def _get_path(self, data: dict, path: list[str]) -> dict:
        """Get nested dictionary at path."""
        current = data
        for key in path:
            current = current[key]
        return current
