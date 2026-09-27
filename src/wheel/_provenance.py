"""Keyless, offline build provenance attestations for wheels.

A provenance statement lives in the constrained ``PROVENANCE`` file inside the
wheel's ``.dist-info`` directory.  Unlike cryptographic attestations, it
requires neither private keys nor network access: it is a strictly formatted
hash-based statement that can be generated and verified entirely offline.

The statement records the attestation format version, the build tool and its
version, a digest of the build inputs, the target compatibility tags, the
timestamp policy used while building, and a SHA-256 hash of every archived
file.  The ``PROVENANCE`` file is itself listed (with its hash) in ``RECORD``.

Verification fails on unknown or malformed fields, on any mismatch between the
statement and the actual archive contents, on duplicate statements and on
unsafe (path traversal) file paths.
"""

from __future__ import annotations

__all__ = [
    "PROVENANCE_FILENAME",
    "ProvenanceFile",
    "ProvenanceStatement",
    "build_provenance",
    "find_provenance",
    "parse_provenance",
    "verify_provenance",
]

import csv
import hashlib
import os
import re
import time
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import compat32
from io import StringIO
from typing import TYPE_CHECKING

from . import __version__
from .wheelfile import (
    MINIMUM_TIMESTAMP,
    WheelError,
    urlsafe_b64decode,
    urlsafe_b64encode,
)

if TYPE_CHECKING:
    from .wheelfile import WheelFile

#: Name of the provenance statement inside the ``.dist-info`` directory.
PROVENANCE_FILENAME = "PROVENANCE"

#: Only this attestation format version can be generated or verified.
ATTESTATION_VERSION = "1"

#: Name of the tool that generated the statement.
BUILD_TOOL = "wheel"

#: Hash algorithm used for every digest in the statement.
DIGEST_ALGORITHM = "sha256"

FIELD_VERSION = "Attestation-Version"
FIELD_BUILD_TOOL = "Build-Tool"
FIELD_BUILD_TOOL_VERSION = "Build-Tool-Version"
FIELD_BUILD_INPUT_DIGEST = "Build-Input-Digest"
FIELD_TAG = "Tag"
FIELD_TIME_POLICY = "Time-Policy"

_SCALAR_FIELDS = frozenset(
    {
        FIELD_VERSION,
        FIELD_BUILD_TOOL,
        FIELD_BUILD_TOOL_VERSION,
        FIELD_BUILD_INPUT_DIGEST,
        FIELD_TIME_POLICY,
    }
)
_REPEATED_FIELDS = frozenset({FIELD_TAG})
_KNOWN_FIELDS = _SCALAR_FIELDS | _REPEATED_FIELDS

_TAG_RE = re.compile(r"^[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+$")
_DIGEST_RE = re.compile(r"^sha256=([A-Za-z0-9_-]+)$")
_TIME_POLICY_RE = re.compile(r"^(?:mtime|source-date-epoch=(\d+))$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True)
class ProvenanceFile:
    """A single row in the provenance file manifest.

    ``digest`` is a ``sha256=<urlsafe-b64>`` string, or an empty string for
    the ``PROVENANCE`` self-reference (which cannot hash itself).
    """

    path: str
    digest: str
    size: int | None


@dataclass(frozen=True)
class ProvenanceStatement:
    """A parsed provenance statement."""

    build_tool: str
    build_tool_version: str
    build_input_digest: str
    tags: tuple[str, ...]
    time_policy: str
    files: tuple[ProvenanceFile, ...]


def validate_arcname(path: str) -> None:
    """Reject absolute, normalized-away or traversal-capable paths.

    Archive member paths always use ``/`` as the separator and may not escape
    the extraction directory via ``..``, absolute paths, Windows drives or
    backslashes.
    """
    if not path:
        raise WheelError("Provenance contains an empty file path")
    if "\x00" in path:
        raise WheelError(f"Invalid file path {path!r} in provenance")
    if "\\" in path:
        raise WheelError(
            f"Invalid file path {path!r} in provenance: backslashes are not "
            "permitted in archive paths"
        )
    if path.startswith("/") or _DRIVE_RE.match(path):
        raise WheelError(f"Absolute file path {path!r} in provenance")

    for part in path.split("/"):
        if part in ("", ".", ".."):
            raise WheelError(f"Unsafe path component in provenance entry {path!r}")


def current_time_policy() -> str:
    """Return the timestamp policy in effect for newly written archives."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        return "mtime"

    try:
        value = int(epoch)
    except ValueError:
        raise WheelError(f"Invalid SOURCE_DATE_EPOCH value: {epoch!r}") from None

    if value < 0:
        raise WheelError(f"SOURCE_DATE_EPOCH must not be negative: {value}")

    return f"source-date-epoch={value}"


def _canonical_body(files: Collection[ProvenanceFile]) -> str:
    """Serialize file rows in the canonical (path-sorted) form."""
    buffer = StringIO()
    writer = csv.writer(buffer, delimiter=",", quotechar='"', lineterminator="\n")
    for item in sorted(files, key=lambda row: row.path):
        writer.writerow(
            (item.path, item.digest, "" if item.size is None else str(item.size))
        )

    return buffer.getvalue()


def _validate_digest(value: str) -> None:
    match = _DIGEST_RE.fullmatch(value)
    if match is None:
        raise WheelError(f"Invalid or unsupported digest {value!r} in provenance")

    try:
        raw = urlsafe_b64decode(match.group(1).encode("ascii"))
    except ValueError:
        raise WheelError(f"Malformed digest {value!r} in provenance") from None

    if len(raw) != hashlib.sha256().digest_size:
        raise WheelError(f"Digest {value!r} is not a SHA-256 digest")


def build_provenance(
    *,
    dist_info_path: str,
    file_digests: Mapping[str, tuple[str, int]],
    tags: Collection[str],
) -> bytes:
    """Build the byte contents of a ``PROVENANCE`` file.

    :param dist_info_path: Archive path of the ``.dist-info`` directory
    :param file_digests: Mapping of archive member paths (excluding
        ``RECORD`` and ``PROVENANCE``) to ``(sha256=<digest>, size)`` pairs
    :param tags: Target compatibility tags (``impl-abi-platform``)
    """
    tag_list = sorted(set(tags))
    if not tag_list:
        raise WheelError("Cannot build provenance without compatibility tags")

    for tag in tag_list:
        if not _TAG_RE.fullmatch(tag):
            raise WheelError(f"Invalid compatibility tag {tag!r}")

    provenance_path = f"{dist_info_path}/{PROVENANCE_FILENAME}"
    files: list[ProvenanceFile] = [
        ProvenanceFile(path, digest, size)
        for path, (digest, size) in file_digests.items()
    ]
    files.append(ProvenanceFile(provenance_path, "", None))

    body = _canonical_body(files)
    input_digest = hashlib.sha256(body.encode("utf-8")).digest()
    input_digest_value = (
        f"{DIGEST_ALGORITHM}={urlsafe_b64encode(input_digest).decode('ascii')}"
    )

    lines = [
        f"{FIELD_VERSION}: {ATTESTATION_VERSION}",
        f"{FIELD_BUILD_TOOL}: {BUILD_TOOL}",
        f"{FIELD_BUILD_TOOL_VERSION}: {__version__}",
        f"{FIELD_BUILD_INPUT_DIGEST}: {input_digest_value}",
    ]
    lines.extend(f"{FIELD_TAG}: {tag}" for tag in tag_list)
    lines.append(f"{FIELD_TIME_POLICY}: {current_time_policy()}")

    return ("\n".join(lines) + "\n\n" + body).encode("utf-8")


def parse_provenance(
    data: bytes, *, provenance_path: str, record_path: str
) -> ProvenanceStatement:
    """Parse and strictly validate a ``PROVENANCE`` file.

    Every field must come from the known set, scalar fields must appear
    exactly once, the attestation version must be supported, and the file
    manifest must be internally consistent.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise WheelError("Provenance is not valid UTF-8") from None

    if "\r\n" in text:
        text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise WheelError("Provenance contains bare carriage returns")

    header_text, separator, body = text.partition("\n\n")
    if not separator:
        raise WheelError("Provenance is missing the manifest section")
    if not body or not body.endswith("\n"):
        raise WheelError("Provenance manifest must contain rows terminated by newlines")

    scalar_values: dict[str, str] = {}
    tag_values: list[str] = []
    for line in header_text.split("\n"):
        if not line or line[0] in (" ", "\t"):
            raise WheelError("Malformed header in provenance")

        key, colon, value = line.partition(":")
        if not colon or key not in _KNOWN_FIELDS:
            raise WheelError(f"Unknown or untrusted provenance field {key!r}")

        value = value.removeprefix(" ")
        if not value or value != value.strip():
            raise WheelError(f"Empty or malformed value for {key} in provenance")

        if key in _REPEATED_FIELDS:
            tag_values.append(value)
        elif key in scalar_values:
            raise WheelError(f"Duplicate {key} field in provenance")
        else:
            scalar_values[key] = value

    missing = _SCALAR_FIELDS - scalar_values.keys()
    if missing:
        raise WheelError(
            "Missing required field(s) in provenance: " + ", ".join(sorted(missing))
        )

    version = scalar_values[FIELD_VERSION]
    if version != ATTESTATION_VERSION:
        raise WheelError(
            f"Unsupported attestation version {version!r}; expected "
            f"{ATTESTATION_VERSION!r}"
        )

    build_input_digest = scalar_values[FIELD_BUILD_INPUT_DIGEST]
    _validate_digest(build_input_digest)

    if not tag_values:
        raise WheelError("Provenance does not declare any compatibility tags")

    tags_seen: set[str] = set()
    for tag in tag_values:
        if not _TAG_RE.fullmatch(tag):
            raise WheelError(f"Invalid compatibility tag {tag!r} in provenance")
        if tag in tags_seen:
            raise WheelError(f"Duplicate {FIELD_TAG} value {tag!r} in provenance")
        tags_seen.add(tag)

    time_policy = scalar_values[FIELD_TIME_POLICY]
    if not _TIME_POLICY_RE.fullmatch(time_policy):
        raise WheelError(f"Invalid time policy {time_policy!r} in provenance")

    files: list[ProvenanceFile] = []
    paths_seen: set[str] = set()
    self_row_found = False
    reader = csv.reader(StringIO(body, newline=""), delimiter=",", quotechar='"')
    for row in reader:
        if len(row) != 3:
            raise WheelError("Malformed row in provenance manifest")

        path, digest, size_text = row
        validate_arcname(path)
        if path in paths_seen:
            raise WheelError(f"Duplicate manifest entry for {path!r} in provenance")
        paths_seen.add(path)

        if path == record_path:
            raise WheelError("RECORD must not be listed in the provenance manifest")

        is_self_row = path == provenance_path
        if is_self_row:
            if digest or size_text or self_row_found:
                raise WheelError(
                    f"The {PROVENANCE_FILENAME} self-reference must carry no hash "
                    "and appear exactly once"
                )
            self_row_found = True
            files.append(ProvenanceFile(path, "", None))
            continue

        if not digest:
            raise WheelError(f"Missing hash for {path!r} in provenance")

        _validate_digest(digest)
        if not size_text.isdigit():
            raise WheelError(f"Invalid size for {path!r} in provenance")

        files.append(ProvenanceFile(path, digest, int(size_text)))

    if not self_row_found:
        raise WheelError(
            f"The provenance manifest must reference {provenance_path!r} itself"
        )

    canonical = _canonical_body(files)
    actual_digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    if (
        urlsafe_b64encode(actual_digest).decode("ascii")
        != build_input_digest.split("=", 1)[1]
    ):
        raise WheelError("Build input digest does not match the provenance manifest")

    return ProvenanceStatement(
        build_tool=scalar_values[FIELD_BUILD_TOOL],
        build_tool_version=scalar_values[FIELD_BUILD_TOOL_VERSION],
        build_input_digest=build_input_digest,
        tags=tuple(sorted(tag_values)),
        time_policy=time_policy,
        files=tuple(files),
    )


def find_provenance(wf: WheelFile) -> str:
    """Return the unique archive path of the wheel's provenance statement."""
    candidates = [
        name
        for name in wf.namelist()
        if name.count("/") == 1
        and name.endswith(f"/{PROVENANCE_FILENAME}")
        and name[: -len(f"/{PROVENANCE_FILENAME}")].endswith(".dist-info")
    ]
    if not candidates:
        raise WheelError(
            f"No {wf.dist_info_path}/{PROVENANCE_FILENAME} found in the wheel"
        )
    if len(candidates) > 1:
        raise WheelError(
            "Multiple provenance statements found in the wheel: "
            + ", ".join(sorted(candidates))
        )

    path = candidates[0]
    expected = f"{wf.dist_info_path}/{PROVENANCE_FILENAME}"
    if path != expected:
        raise WheelError(
            f"Provenance found at unexpected location {path!r}; expected {expected!r}"
        )

    return path


def verify_provenance(wf: WheelFile) -> ProvenanceStatement:
    """Verify a wheel's provenance statement against the archive.

    :raises WheelError: if no valid provenance can be found or verified
    """
    # Validate every member against RECORD first.
    bad_member = wf.testzip()
    if bad_member is not None:
        raise WheelError(f"RECORD hash mismatch for {bad_member!r}")

    provenance_path = find_provenance(wf)

    # Reading through WheelFile enforces the RECORD hash of PROVENANCE itself.
    with wf.open(provenance_path) as provenance_file:
        statement = parse_provenance(
            provenance_file.read(),
            provenance_path=provenance_path,
            record_path=wf.record_path,
        )

    # The manifest must cover exactly the regular archive members, minus
    # RECORD (whose final hash does not exist when PROVENANCE is written).
    members = {info.filename for info in wf.infolist() if not info.is_dir()} - {
        wf.record_path
    }
    declared = {item.path for item in statement.files}
    if declared != members:
        missing = sorted(members - declared)
        extra = sorted(declared - members)
        details = []
        if missing:
            details.append("missing from provenance: " + ", ".join(missing))
        if extra:
            details.append("not present in the archive: " + ", ".join(extra))
        raise WheelError("Provenance does not match the archive: " + "; ".join(details))

    # Verify every declared hash against the actual member bytes.
    for item in statement.files:
        if item.size is None:
            continue

        data = wf.read(item.path)
        if len(data) != item.size:
            raise WheelError(
                f"Provenance size mismatch for {item.path!r}: expected {item.size}, "
                f"got {len(data)}"
            )

        actual = hashlib.sha256(data).digest()
        expected = urlsafe_b64decode(item.digest.split("=", 1)[1].encode("ascii"))
        if actual != expected:
            raise WheelError(f"Provenance hash mismatch for {item.path!r}")

    # The declared tags must agree with WHEEL and with the wheel filename.
    with wf.open(f"{wf.dist_info_path}/WHEEL") as wheel_metadata_file:
        wheel_metadata = BytesParser(policy=compat32).parse(wheel_metadata_file)

    wheel_tags = set(wheel_metadata.get_all("Tag", []))
    if wheel_tags != set(statement.tags):
        raise WheelError(
            f"Provenance tags do not match the Tag fields in {wf.dist_info_path}/WHEEL"
        )

    parsed = wf.parsed_filename
    filename_groups = (
        set(parsed.group("pyver").split(".")),
        set(parsed.group("abi").split(".")),
        set(parsed.group("plat").split(".")),
    )
    declared_groups = (
        {tag.split("-")[0] for tag in statement.tags},
        {tag.split("-")[1] for tag in statement.tags},
        {tag.split("-")[2] for tag in statement.tags},
    )
    group_names = ("python", "ABI", "platform")
    for name, declared_group, filename_group in zip(
        group_names, declared_groups, filename_groups
    ):
        if declared_group != filename_group:
            raise WheelError(
                f"Provenance {name} tags {sorted(declared_group)} do not match the "
                f"wheel filename tags {sorted(filename_group)}"
            )

    # Enforce the declared timestamp policy on every member.
    match = _TIME_POLICY_RE.fullmatch(statement.time_policy)
    if match is not None and match.group(1) is not None:
        epoch = max(int(match.group(1)), MINIMUM_TIMESTAMP)
        expected_datetime = time.gmtime(epoch)[0:6]
        for info in wf.infolist():
            if info.is_dir():
                continue
            if info.date_time != expected_datetime:
                raise WheelError(
                    f"Timestamp of {info.filename!r} does not match the declared "
                    f"time policy {statement.time_policy!r}"
                )

    return statement
