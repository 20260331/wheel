"""
Build a deterministic, offline repository manifest and lockfile from wheels.

The command only reads wheel files; it never modifies them and never accesses
the network. Every output document is sorted so that scanning the same
directory twice produces byte-identical files.
"""

from __future__ import annotations

import csv
import email.policy
import hashlib
import io
import itertools
import json
import os
import sys
from dataclasses import dataclass
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import TextIO
from zipfile import BadZipFile

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from ..wheelfile import WheelError, WheelFile

MANIFEST_SCHEMA_VERSION = 1
LOCKFILE_SCHEMA_VERSION = 1

# Errors that make an individual file unindexable, without aborting the scan.
_SKIPPABLE_ERRORS = (
    WheelError,
    BadZipFile,
    OSError,
    EOFError,
    KeyError,
    ValueError,
)


@dataclass(frozen=True)
class WheelEntry:
    """Metadata describing a single wheel file."""

    name: str
    version: str
    filename: str
    path: str
    size: int
    sha256: str
    tags: tuple[str, ...]
    metadata_version: str | None
    record_sha256: str
    record_files: int
    record_size: int

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "filename": self.filename,
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "tags": list(self.tags),
            "metadata_version": self.metadata_version,
            "record": {
                "sha256": self.record_sha256,
                "files": self.record_files,
                "size": self.record_size,
            },
        }


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True)
class ConflictArtifact:
    sha256: str
    size: int
    tags: tuple[str, ...]
    paths: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "tags": list(self.tags),
            "paths": list(self.paths),
        }


@dataclass(frozen=True)
class DuplicateGroup:
    """Identical wheel content (same hash) available at multiple paths."""

    name: str
    version: str
    sha256: str
    paths: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "sha256": self.sha256,
            "paths": list(self.paths),
        }


@dataclass(frozen=True)
class ConflictGroup:
    """Wheels with the same project name and version but different content."""

    name: str
    version: str
    artifacts: tuple[ConflictArtifact, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "artifacts": [artifact.as_dict() for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class IndexResult:
    roots: tuple[str, ...]
    wheels: tuple[WheelEntry, ...]
    duplicates: tuple[DuplicateGroup, ...]
    conflicts: tuple[ConflictGroup, ...]
    skipped: tuple[SkippedFile, ...]


def _compile_version_filter(text: str) -> SpecifierSet:
    """Compile a version filter, accepting both exact versions and specifiers.

    ``"1.0"`` is treated as ``"==1.0"``; strings with an explicit PEP 440
    operator are used as-is.
    """
    text = text.strip()
    if not text.startswith(("===", "==", "!=", "~=", ">=", "<=", ">", "<")):
        text = "==" + text

    return SpecifierSet(text)


def _parse_message(wheel: WheelFile, member: str) -> Message | None:
    """Parse an RFC 822-style metadata member, or return ``None`` if absent."""
    try:
        stream = wheel.open(member)
    except KeyError:
        return None

    with stream:
        return BytesParser(policy=email.policy.compat32).parse(stream)


def _tags_from_filename(wheel: WheelFile) -> tuple[str, ...]:
    parsed = wheel.parsed_filename
    return tuple(
        sorted(
            f"{python_tag}-{abi_tag}-{platform_tag}"
            for python_tag, abi_tag, platform_tag in itertools.product(
                parsed.group("pyver").split("."),
                parsed.group("abi").split("."),
                parsed.group("plat").split("."),
            )
        )
    )


def _hash_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _read_wheel(path: str, relative_path: str) -> WheelEntry:
    """Read all indexable metadata from one wheel file."""
    size = os.path.getsize(path)
    file_hash = _hash_file(path)

    with WheelFile(path) as wheel:
        wheel_metadata = _parse_message(wheel, f"{wheel.dist_info_path}/WHEEL")
        tags: tuple[str, ...] = ()
        if wheel_metadata is not None:
            tags = tuple(sorted(set(wheel_metadata.get_all("Tag", ()))))

        if not tags:
            tags = _tags_from_filename(wheel)

        package_metadata = _parse_message(wheel, f"{wheel.dist_info_path}/METADATA")
        metadata_version = (
            package_metadata.get("Metadata-Version")
            if package_metadata is not None
            else None
        )

        raw_name = (
            package_metadata.get("Name") if package_metadata is not None else None
        ) or wheel.parsed_filename.group("name")
        raw_version = (
            package_metadata.get("Version") if package_metadata is not None else None
        ) or wheel.parsed_filename.group("ver")

        # Normalize the identity (PEP 503 name, PEP 440 version).
        name = canonicalize_name(raw_name)
        version = str(Version(raw_version))

        # Summarize RECORD without trusting it for integrity: the hashes of
        # every other member read above are verified by WheelFile against it.
        with wheel.open(wheel.record_path) as record_stream:
            record_bytes = record_stream.read()

        record_files = 0
        record_size = 0
        for row in csv.reader(
            io.TextIOWrapper(io.BytesIO(record_bytes), newline="", encoding="utf-8")
        ):
            if len(row) < 1:
                continue

            member_name = row[0]
            if (
                not member_name
                or member_name.endswith("/")
                or member_name == wheel.record_path
            ):
                continue

            record_files += 1
            if len(row) >= 3 and row[2]:
                record_size += int(row[2])

    return WheelEntry(
        name=name,
        version=version,
        filename=os.path.basename(path),
        path=relative_path,
        size=size,
        sha256=file_hash,
        tags=tags,
        metadata_version=metadata_version,
        record_sha256=hashlib.sha256(record_bytes).hexdigest(),
        record_files=record_files,
        record_size=record_size,
    )


def _iter_wheel_paths(root: Path, recursive: bool) -> list[str]:
    wheels: list[str] = []
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for filename in sorted(filenames):
                if filename.endswith(".whl"):
                    wheels.append(os.path.join(dirpath, filename))
    else:
        for entry in sorted(os.scandir(root), key=lambda e: e.name):
            if entry.is_file() and entry.name.endswith(".whl"):
                wheels.append(entry.path)

    return wheels


def _matches_filters(
    entry: WheelEntry,
    projects: frozenset[str],
    version_filters: tuple[SpecifierSet, ...],
    tags: frozenset[str],
) -> bool:
    if projects and entry.name not in projects:
        return False

    if version_filters:
        parsed_version = Version(entry.version)
        if not any(
            specifier.contains(parsed_version, prereleases=True)
            for specifier in version_filters
        ):
            return False

    return not tags or bool(set(entry.tags) & tags)


def _entry_sort_key(entry: WheelEntry) -> tuple[str, Version, tuple[str, ...], str]:
    return entry.name, Version(entry.version), entry.tags, entry.path


def _find_duplicates(wheels: list[WheelEntry]) -> list[DuplicateGroup]:
    groups: list[DuplicateGroup] = []
    by_artifact: dict[tuple[str, str, str], list[WheelEntry]] = {}
    for entry in wheels:
        by_artifact.setdefault((entry.name, entry.version, entry.sha256), []).append(
            entry
        )

    for (name, version, sha256), entries in by_artifact.items():
        if len(entries) > 1:
            groups.append(
                DuplicateGroup(
                    name=name,
                    version=version,
                    sha256=sha256,
                    paths=tuple(sorted(entry.path for entry in entries)),
                )
            )

    groups.sort(key=lambda group: (group.name, Version(group.version), group.sha256))
    return groups


def _find_conflicts(wheels: list[WheelEntry]) -> list[ConflictGroup]:
    by_project: dict[tuple[str, str], list[WheelEntry]] = {}
    for entry in wheels:
        by_project.setdefault((entry.name, entry.version), []).append(entry)

    groups: list[ConflictGroup] = []
    for (name, version), entries in by_project.items():
        by_hash: dict[str, list[WheelEntry]] = {}
        for entry in entries:
            by_hash.setdefault(entry.sha256, []).append(entry)

        if len(by_hash) > 1:
            artifacts = tuple(
                ConflictArtifact(
                    sha256=sha256,
                    size=artifact_entries[0].size,
                    tags=artifact_entries[0].tags,
                    paths=tuple(sorted(entry.path for entry in artifact_entries)),
                )
                for sha256, artifact_entries in sorted(by_hash.items())
            )
            groups.append(
                ConflictGroup(name=name, version=version, artifacts=artifacts)
            )

    groups.sort(key=lambda group: (group.name, Version(group.version)))
    return groups


def _candidate_rank(entry: WheelEntry) -> tuple[int, int, tuple[str, ...], str]:
    """Deterministic preference when several artifacts share a version.

    Pure wheels (``abi=none``, ``platform=any``) win, then wheels exposing
    more compatibility tags, then the lexicographically smallest tag set and
    path.
    """
    pure = all(
        tag.split("-")[1] == "none" and tag.split("-")[2] == "any" for tag in entry.tags
    )
    return (
        0 if pure else 1,
        -len(entry.tags),
        tuple(sorted(entry.tags)),
        entry.path,
    )


def _build_lockfile(
    wheels: list[WheelEntry],
    duplicates: list[DuplicateGroup],
    conflicts: list[ConflictGroup],
) -> dict[str, object]:
    conflicts_by_project = {(group.name, group.version): group for group in conflicts}

    by_name: dict[str, list[WheelEntry]] = {}
    for entry in wheels:
        by_name.setdefault(entry.name, []).append(entry)

    packages: dict[str, object] = {}
    for name in sorted(by_name):
        candidates = by_name[name]
        newest = max(candidates, key=lambda entry: Version(entry.version))
        same_version = [
            entry for entry in candidates if entry.version == newest.version
        ]
        selected = min(same_version, key=_candidate_rank)
        conflict = conflicts_by_project.get((name, newest.version))

        package: dict[str, object] = {
            "version": selected.version,
            "path": selected.path,
            "filename": selected.filename,
            "sha256": selected.sha256,
            "size": selected.size,
            "tags": list(selected.tags),
            "conflicting": conflict is not None,
        }
        if conflict is not None:
            package["alternates"] = [
                path
                for artifact in conflict.artifacts
                if artifact.sha256 != selected.sha256
                for path in artifact.paths
            ]

        packages[name] = package

    return {
        "schema_version": LOCKFILE_SCHEMA_VERSION,
        "packages": packages,
        "duplicates": [group.as_dict() for group in duplicates],
        "conflicts": [group.as_dict() for group in conflicts],
    }


def _write_json(document: object, path: str) -> None:
    data = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)


def index(
    directories: list[str],
    manifest_path: str = "wheel-manifest.json",
    lockfile_path: str = "wheel-lock.json",
    projects: list[str] | None = None,
    versions: list[str] | None = None,
    tags: list[str] | None = None,
    recursive: bool = True,
) -> IndexResult:
    """Scan directories for wheels and write the manifest and lockfile.

    :param directories: Directories to scan for ``.whl`` files
    :param manifest_path: Where to write the repository manifest
    :param lockfile_path: Where to write the lockfile
    :param projects: Include only wheels whose normalized project name matches
        one of these values
    :param versions: Include only wheels whose version matches one of these
        exact versions or PEP 440 version specifier strings
    :param tags: Include only wheels that provide at least one of these
        compatibility tags
    :param recursive: Descend into subdirectories
    :raises FileNotFoundError: if a given directory does not exist
    :raises ValueError: if a version filter is not a valid specifier
    """
    project_filter = frozenset(canonicalize_name(name) for name in projects or [])
    try:
        version_filters = tuple(
            _compile_version_filter(text) for text in versions or []
        )
    except InvalidSpecifier as e:
        raise ValueError(f"Invalid version filter: {e}") from e

    tag_filter = frozenset(tags or [])

    roots: list[Path] = []
    for directory in directories:
        root = Path(directory)
        if not root.is_dir():
            raise FileNotFoundError(f"Directory not found: {directory}")

        roots.append(root)

    seen: set[str] = set()
    wheels: list[WheelEntry] = []
    skipped: list[SkippedFile] = []
    for root in roots:
        root_label = str(root) if len(roots) > 1 else ""
        for wheel_path in _iter_wheel_paths(root, recursive):
            resolved = str(Path(wheel_path).resolve())
            if resolved in seen:
                continue

            seen.add(resolved)
            relative_path = os.path.relpath(wheel_path, root)
            if root_label:
                relative_path = os.path.join(root_label, relative_path)

            relative_path = PurePosixPath(relative_path).as_posix()
            try:
                entry = _read_wheel(wheel_path, relative_path)
            except _SKIPPABLE_ERRORS as e:
                skipped.append(
                    SkippedFile(path=relative_path, reason=f"{type(e).__name__}: {e}")
                )
                continue

            if _matches_filters(entry, project_filter, version_filters, tag_filter):
                wheels.append(entry)

    wheels.sort(key=_entry_sort_key)
    skipped.sort(key=lambda skipped_file: skipped_file.path)
    duplicates = _find_duplicates(wheels)
    conflicts = _find_conflicts(wheels)

    result = IndexResult(
        roots=tuple(directories),
        wheels=tuple(wheels),
        duplicates=tuple(duplicates),
        conflicts=tuple(conflicts),
        skipped=tuple(skipped),
    )

    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "roots": list(result.roots),
        "filters": {
            "projects": list(projects or []),
            "versions": list(versions or []),
            "tags": list(tags or []),
        },
        "wheels": [entry.as_dict() for entry in result.wheels],
        "duplicates": [group.as_dict() for group in duplicates],
        "conflicts": [group.as_dict() for group in conflicts],
        "skipped": [skipped_file.as_dict() for skipped_file in result.skipped],
    }
    lockfile = _build_lockfile(result.wheels, duplicates, conflicts)

    _write_json(manifest, manifest_path)
    _write_json(lockfile, lockfile_path)
    return result


def print_report(
    result: IndexResult,
    manifest_path: str,
    lockfile_path: str,
    out: TextIO | None = None,
    err: TextIO | None = None,
) -> None:
    """Print a short, deterministic human-readable summary."""
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr

    root_noun = "directory" if len(result.roots) == 1 else "directories"
    wheel_noun = "wheel" if len(result.wheels) == 1 else "wheels"
    print(
        f"Scanned {len(result.roots)} {root_noun}; "
        f"indexed {len(result.wheels)} {wheel_noun}",
        file=out,
    )
    print(f"Wrote manifest: {manifest_path}", file=out)
    print(f"Wrote lockfile: {lockfile_path}", file=out)

    if result.duplicates:
        noun = "group" if len(result.duplicates) == 1 else "groups"
        print(f"warning: {len(result.duplicates)} duplicate {noun}:", file=err)
        for group in result.duplicates:
            print(
                f"  {group.name} {group.version} ({group.sha256[:12]}): "
                + ", ".join(group.paths),
                file=err,
            )

    if result.conflicts:
        noun = "group" if len(result.conflicts) == 1 else "groups"
        print(
            f"warning: {len(result.conflicts)} conflicting candidate {noun}:",
            file=err,
        )
        for group in result.conflicts:
            paths = [path for artifact in group.artifacts for path in artifact.paths]
            print(
                f"  {group.name} {group.version}: "
                f"{len(group.artifacts)} distinct artifacts at " + ", ".join(paths),
                file=err,
            )

    for skipped in result.skipped:
        print(f"warning: skipped {skipped.path}: {skipped.reason}", file=err)
