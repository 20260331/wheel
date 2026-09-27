"""
Create and apply versioned, offline wheel deltas ("wheel overlays").

A wheel delta is a versioned ZIP archive (``*.whldelta``) that describes how to
turn one specific base wheel into another wheel:

* which files are added, replaced or deleted,
* which ``.dist-info`` metadata headers change,
* and, when explicitly allowed, whether the distribution version changes
  (which renames the ``.dist-info``/``.data`` directories and the output file).

Applying a delta is safe:

1. the base wheel is identified by its whole-file digest, and every file is
   checked against its :pep:`427` ``RECORD`` manifest (paths, sizes and hashes)
   before anything is written;
2. the resulting wheel, complete with a freshly generated ``RECORD``, is built
   in a temporary directory and verified readable before it is moved into
   place, so a failed application never leaves a partial wheel behind.
"""

from __future__ import annotations

import csv
import email.policy
import hashlib
import io
import json
import os
import os.path
import stat
import tempfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from ..wheelfile import (
    WheelError,
    WheelFile,
    get_zipinfo_datetime,
    urlsafe_b64encode,
)
from .pack import DIST_INFO_RE
from .tags import _strip_zip64_extra

DELTA_FORMAT = "wheel-delta"
DELTA_VERSION = 1
MANIFEST_NAME = "delta.json"
PAYLOAD_PREFIX = "files/"

DIST_INFO_TOKEN = "<DIST-INFO>"
DATA_TOKEN = "<DATA>"

_READ_CHUNK = 1 << 20


@dataclass(frozen=True)
class WheelIdentity:
    """The file-name level identity of a wheel (PEP 427/425)."""

    name: str
    version: str
    build: str | None
    python_tags: tuple[str, ...]
    abi_tags: tuple[str, ...]
    platform_tags: tuple[str, ...]
    filename: str | None = None
    digest: str | None = None

    @property
    def namever(self) -> str:
        return f"{self.name}-{self.version}"

    @property
    def wheel_filename(self) -> str:
        parts = [self.namever]
        if self.build:
            parts.append(self.build)

        parts.extend(
            ".".join(tags)
            for tags in (self.python_tags, self.abi_tags, self.platform_tags)
        )
        return "-".join(parts) + ".whl"

    @property
    def delta_filename(self) -> str:
        return self.wheel_filename[: -len(".whl")] + ".whldelta"

    def to_dict(self) -> dict[str, object]:
        return {
            "filename": self.filename,
            "name": self.name,
            "version": self.version,
            "build": self.build,
            "python_tags": list(self.python_tags),
            "abi_tags": list(self.abi_tags),
            "platform_tags": list(self.platform_tags),
            "digest": self.digest,
        }


def _identity_from_wheel(wf: WheelFile, digest: str | None = None) -> WheelIdentity:
    match = wf.parsed_filename
    assert wf.filename
    return WheelIdentity(
        name=match.group("name"),
        version=match.group("ver"),
        build=match.group("build"),
        python_tags=tuple(sorted(match.group("pyver").split("."))),
        abi_tags=tuple(sorted(match.group("abi").split("."))),
        platform_tags=tuple(sorted(match.group("plat").split("."))),
        filename=os.path.basename(wf.filename),
        digest=digest,
    )


def _identity_from_dict(data: dict[str, object]) -> WheelIdentity:
    try:
        return WheelIdentity(
            name=str(data["name"]),
            version=str(data["version"]),
            build=data["build"],
            python_tags=tuple(sorted(data["python_tags"])),  # type: ignore[arg-type]
            abi_tags=tuple(sorted(data["abi_tags"])),  # type: ignore[arg-type]
            platform_tags=tuple(sorted(data["platform_tags"])),  # type: ignore[arg-type]
            filename=data["filename"],  # type: ignore[arg-type]
            digest=data["digest"],  # type: ignore[arg-type]
        )
    except (KeyError, TypeError) as e:
        raise WheelError(f"Invalid wheel identity in delta manifest: {e}") from None


def _sha256_digest(data: bytes) -> str:
    return "sha256=" + urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_READ_CHUNK), b""):
            digest.update(chunk)

    return "sha256=" + urlsafe_b64encode(digest.digest()).decode("ascii")


def _read_record(wf: WheelFile) -> dict[str, tuple[str | None, int | None]]:
    """Parse a wheel's RECORD into a ``{path: (hash, size)}`` mapping."""
    rows: dict[str, tuple[str | None, int | None]] = {}
    with wf.open(wf.record_path) as record_file:
        text = io.TextIOWrapper(record_file, newline="", encoding="utf-8")
        for line_number, row in enumerate(csv.reader(text), 1):
            if len(row) != 3:
                raise WheelError(
                    f"Malformed RECORD line {line_number} in {wf.filename!r}"
                )

            path, hash_sum, size = row
            if path in rows:
                raise WheelError(f"Duplicate RECORD entry {path!r} in {wf.filename!r}")

            rows[path] = (hash_sum or None, int(size) if size else None)

    return rows


def _parse_headers(data: bytes) -> dict[str, list[str]]:
    message = BytesParser(policy=email.policy.compat32).parsebytes(data)
    return {key: [str(value) for value in message.get_all(key, [])] for key in message}


def _check_header_consistency(
    identity: WheelIdentity,
    wheel_data: bytes,
    metadata_data: bytes,
    source: str,
) -> None:
    """Verify that the METADATA/WHEEL headers agree with the wheel identity."""
    metadata = BytesParser(policy=email.policy.compat32).parsebytes(metadata_data)
    metadata_name = metadata.get("Name")
    metadata_version = metadata.get("Version")
    if metadata_name is None:
        raise WheelError(f"{source}: METADATA is missing the Name field")
    if metadata_version is None:
        raise WheelError(f"{source}: METADATA is missing the Version field")
    if canonicalize_name(metadata_name) != canonicalize_name(identity.name):
        raise WheelError(
            f"{source}: METADATA Name {metadata_name!r} does not match wheel name "
            f"{identity.name!r}"
        )

    try:
        if Version(metadata_version) != Version(identity.version):
            raise WheelError(
                f"{source}: METADATA Version {metadata_version!r} does not match "
                f"wheel version {identity.version!r}"
            )
    except InvalidVersion as e:
        raise WheelError(f"{source}: invalid METADATA Version: {e}") from None

    wheel_info = BytesParser(policy=email.policy.compat32).parsebytes(wheel_data)
    tag_headers = wheel_info.get_all("Tag", [])
    if not tag_headers:
        raise WheelError(f"{source}: WHEEL has no Tag fields")

    try:
        python_tags = {tag.split("-")[0] for tag in tag_headers}
        abi_tags = {tag.split("-")[1] for tag in tag_headers}
        platform_tags = {tag.split("-")[2] for tag in tag_headers}
    except IndexError:
        raise WheelError(
            f"{source}: malformed Tag field(s) in WHEEL: {tag_headers!r}"
        ) from None

    if python_tags != set(identity.python_tags):
        raise WheelError(
            f"{source}: WHEEL python tags {sorted(python_tags)!r} do not match file "
            f"name tags {list(identity.python_tags)!r}"
        )
    if abi_tags != set(identity.abi_tags):
        raise WheelError(
            f"{source}: WHEEL ABI tags {sorted(abi_tags)!r} do not match file name "
            f"tags {list(identity.abi_tags)!r}"
        )
    if platform_tags != set(identity.platform_tags):
        raise WheelError(
            f"{source}: WHEEL platform tags {sorted(platform_tags)!r} do not match "
            f"file name tags {list(identity.platform_tags)!r}"
        )

    if wheel_info.get("Build") != identity.build:
        raise WheelError(
            f"{source}: WHEEL Build {wheel_info.get('Build')!r} does not match file "
            f"name build tag {identity.build!r}"
        )


def _verify_wheel(
    path: Path,
) -> tuple[
    WheelIdentity,
    dict[str, tuple[str | None, int | None]],
    dict[str, str],
]:
    """Verify a wheel against its RECORD.

    Returns the wheel identity, the RECORD rows (``{path: (hash, size)}``) and
    the actual SHA-256 digest of every hashed file.
    """
    digest = _hash_file(path)
    try:
        with WheelFile(path) as wf:
            identity = _identity_from_wheel(wf, digest)
            rows = _read_record(wf)

            members = {info.filename for info in wf.infolist() if not info.is_dir()}
            if members != set(rows):
                missing = sorted(set(rows) - members)
                extra = sorted(members - set(rows))
                details = []
                if missing:
                    details.append(f"missing from archive: {missing!r}")
                if extra:
                    details.append(f"not listed in RECORD: {extra!r}")
                raise WheelError(
                    f"File manifest of {path} does not match its RECORD: "
                    + "; ".join(details)
                )

            actual_digests: dict[str, str] = {}
            for record_path, (_, size) in rows.items():
                data = wf.read(record_path)  # WheelFile enforces the RECORD hash
                if size is not None and len(data) != size:
                    raise WheelError(
                        f"Size mismatch for {record_path!r} in {path}: "
                        f"RECORD says {size}, found {len(data)}"
                    )
                if record_path != wf.record_path:
                    actual_digests[record_path] = _sha256_digest(data)

            try:
                wheel_data = wf.read(f"{wf.dist_info_path}/WHEEL")
                metadata_data = wf.read(f"{wf.dist_info_path}/METADATA")
            except KeyError as e:
                raise WheelError(f"{path}: missing {e.args[0]}") from None

            _check_header_consistency(identity, wheel_data, metadata_data, str(path))
    except BadZipFile as e:
        raise WheelError(f"{path} is not a valid wheel file: {e}") from None

    return identity, rows, actual_digests


def _validate_arcname(arcname: str, source: str) -> None:
    if not arcname or arcname.endswith("/"):
        raise WheelError(f"{source}: invalid file name {arcname!r}")
    if arcname.startswith(("/", "\\")) or ":" in arcname.split("/")[0]:
        raise WheelError(f"{source}: absolute path in overlay: {arcname!r}")
    parts = arcname.replace("\\", "/").split("/")
    if any(part in ("", "..") for part in parts):
        raise WheelError(f"{source}: unsafe path in overlay: {arcname!r}")


def _read_overlay_tree(
    directory: Path,
) -> tuple[WheelIdentity, dict[str, tuple[bytes, int]]]:
    """Load an unpacked-wheel directory as overlay ``{arcname: (data, mode)}``."""
    dist_info_dirs = [
        entry
        for entry in directory.iterdir()
        if entry.is_dir() and DIST_INFO_RE.match(entry.name)
    ]
    if len(dist_info_dirs) > 1:
        raise WheelError(f"Multiple .dist-info directories found in {directory}")
    elif not dist_info_dirs:
        raise WheelError(f"No .dist-info directory found in {directory}")

    dist_info_dir = dist_info_dirs[0]
    match = DIST_INFO_RE.match(dist_info_dir.name)
    assert match
    name = match.group("name")
    version = match.group("ver")

    try:
        wheel_data = (dist_info_dir / "WHEEL").read_bytes()
        metadata_data = (dist_info_dir / "METADATA").read_bytes()
    except FileNotFoundError as e:
        raise WheelError(f"{directory}: missing {e.filename}") from None

    wheel_info = BytesParser(policy=email.policy.compat32).parsebytes(wheel_data)
    tag_headers = wheel_info.get_all("Tag", [])
    if not tag_headers:
        raise WheelError(
            f"{dist_info_dir / 'WHEEL'} has no Tag fields; cannot identify overlay"
        )

    identity = WheelIdentity(
        name=name,
        version=version,
        build=wheel_info.get("Build"),
        python_tags=tuple(sorted({tag.split("-")[0] for tag in tag_headers})),
        abi_tags=tuple(sorted({tag.split("-")[1] for tag in tag_headers})),
        platform_tags=tuple(sorted({tag.split("-")[2] for tag in tag_headers})),
        filename=None,
    )
    _check_header_consistency(identity, wheel_data, metadata_data, str(directory))

    files: dict[str, tuple[bytes, int]] = {}
    for root, dirnames, filenames in os.walk(directory):
        dirnames.sort()
        for filename in sorted(filenames):
            full_path = os.path.join(root, filename)
            if not os.path.isfile(full_path):
                continue

            arcname = os.path.relpath(full_path, directory).replace(os.path.sep, "/")
            _validate_arcname(arcname, str(directory))
            if arcname in files:
                raise WheelError(f"{directory}: duplicate overlay file {arcname!r}")
            mode = stat.S_IMODE(os.stat(full_path).st_mode)
            files[arcname] = (Path(full_path).read_bytes(), mode)

    return identity, files


def _canonical_path(arcname: str) -> str:
    """Map identity-prefixed dist-info/data paths to identity-independent names."""
    head, sep, tail = arcname.partition("/")
    if head.endswith(".dist-info"):
        return DIST_INFO_TOKEN + (sep + tail if sep else "")
    if head.endswith(".data"):
        return DATA_TOKEN + (sep + tail if sep else "")
    return arcname


def _target_path(canonical: str, target_namever: str) -> str:
    if canonical == DIST_INFO_TOKEN or canonical.startswith(DIST_INFO_TOKEN + "/"):
        return target_namever + ".dist-info" + canonical[len(DIST_INFO_TOKEN) :]
    if canonical == DATA_TOKEN or canonical.startswith(DATA_TOKEN + "/"):
        return target_namever + ".data" + canonical[len(DATA_TOKEN) :]
    return canonical


def _rewrite_path(arcname: str, source: WheelIdentity, target: WheelIdentity) -> str:
    """Rewrite base-wheel archive paths into target-wheel archive paths."""
    head, sep, tail = arcname.partition("/")
    head_lower = head.lower()
    if head_lower == f"{source.namever}.dist-info".lower():
        head = f"{target.namever}.dist-info"
    elif head_lower == f"{source.namever}.data".lower():
        head = f"{target.namever}.data"

    return head + (sep + tail if sep else "")


def _header_changes(
    old: dict[str, list[str]], new: dict[str, list[str]]
) -> list[dict[str, object]]:
    changes = []
    for header in sorted(set(old) | set(new)):
        old_values = old.get(header, [])
        new_values = new.get(header, [])
        if sorted(old_values) != sorted(new_values):
            changes.append({"header": header, "old": old_values, "new": new_values})

    return changes


def _validate_overlay_identity(
    base: WheelIdentity, overlay: WheelIdentity, allow_version_change: bool
) -> None:
    if canonicalize_name(base.name) != canonicalize_name(overlay.name):
        raise WheelError(
            f"Overlay distribution name {overlay.name!r} does not match base wheel "
            f"name {base.name!r}"
        )
    if base.python_tags != overlay.python_tags:
        raise WheelError(
            f"Overlay python tags {list(overlay.python_tags)!r} do not match base "
            f"wheel tags {list(base.python_tags)!r}; changing tags is not supported"
        )
    if base.abi_tags != overlay.abi_tags:
        raise WheelError(
            f"Overlay ABI tags {list(overlay.abi_tags)!r} do not match base wheel "
            f"tags {list(base.abi_tags)!r}; changing tags is not supported"
        )
    if base.platform_tags != overlay.platform_tags:
        raise WheelError(
            f"Overlay platform tags {list(overlay.platform_tags)!r} do not match "
            f"base wheel tags {list(base.platform_tags)!r}; changing tags is not "
            "supported"
        )
    if base.build != overlay.build:
        raise WheelError(
            f"Overlay build tag {overlay.build!r} does not match base wheel build "
            f"tag {base.build!r}"
        )
    if base.version != overlay.version and not allow_version_change:
        raise WheelError(
            f"Overlay version {overlay.version!r} differs from base wheel version "
            f"{base.version!r}; pass --allow-version-change to create a delta that "
            "changes the version"
        )


def _manifest_zipinfo(name: str) -> ZipInfo:
    info = ZipInfo(name, date_time=get_zipinfo_datetime())
    info.compress_type = ZIP_DEFLATED
    info.external_attr = (0o644 | stat.S_IFREG) << 16
    return info


def make_delta(
    base_wheel: str,
    overlay: str,
    dest_dir: str = os.curdir,
    allow_version_change: bool = False,
) -> str:
    """Create a versioned delta from a base wheel and an overlay.

    :param base_wheel: Path to the base wheel
    :param overlay: Path to a second wheel or to an unpacked wheel directory
    :param dest_dir: Directory to store the delta in
    :param allow_version_change: Allow the overlay to have a different Version
    :return: The path to the created delta archive
    """
    base_path = Path(base_wheel)
    if not base_path.is_file():
        raise WheelError(f"Base wheel not found: {base_wheel}")

    overlay_path = Path(overlay)
    if not overlay_path.exists():
        raise WheelError(f"Overlay not found: {overlay}")

    base_identity, base_rows, base_digests = _verify_wheel(base_path)

    overlay_files: dict[str, tuple[bytes, int]]
    if overlay_path.is_dir():
        target_identity, overlay_files = _read_overlay_tree(overlay_path)
    else:
        target_identity, _, _ = _verify_wheel(overlay_path)
        overlay_files = {}
        with WheelFile(overlay_path) as wf:
            skipped = {
                wf.record_path,
                wf.record_path + ".jws",
                wf.record_path + ".p7s",
            }
            for info in wf.infolist():
                if info.is_dir() or info.filename in skipped:
                    continue
                _validate_arcname(info.filename, str(overlay_path))
                mode = (info.external_attr >> 16) & 0o777 or 0o644
                overlay_files[info.filename] = (wf.read(info), mode)

    _validate_overlay_identity(base_identity, target_identity, allow_version_change)

    base_canonical: dict[str, str] = {}
    overlay_canonical: dict[str, str] = {}
    for path in base_rows:
        canonical = _canonical_path(path)
        if canonical in base_canonical:
            raise WheelError(
                f"Base wheel {base_path} contains conflicting paths "
                f"{base_canonical[canonical]!r} and {path!r}"
            )
        base_canonical[canonical] = path
    for path in overlay_files:
        canonical = _canonical_path(path)
        if canonical in overlay_canonical:
            raise WheelError(
                f"Overlay {overlay} contains conflicting paths "
                f"{overlay_canonical[canonical]!r} and {path!r}"
            )
        overlay_canonical[canonical] = path

    added: list[dict[str, object]] = []
    replaced: list[dict[str, object]] = []
    deleted: list[dict[str, object]] = []
    payloads: dict[str, bytes] = {}

    for canonical in sorted(set(base_canonical) | set(overlay_canonical)):
        # RECORD is always regenerated when the delta is applied
        if canonical == f"{DIST_INFO_TOKEN}/RECORD":
            continue

        base_path_entry = base_canonical.get(canonical)
        overlay_path_entry = overlay_canonical.get(canonical)
        if base_path_entry is not None and overlay_path_entry is not None:
            data, mode = overlay_files[overlay_path_entry]
            new_hash = _sha256_digest(data)
            if base_digests.get(base_path_entry) != new_hash:
                replaced.append(
                    {
                        "path": overlay_path_entry,
                        "base_path": base_path_entry,
                        "base_hash": base_rows[base_path_entry][0],
                        "hash": new_hash,
                        "size": len(data),
                        "mode": mode,
                    }
                )
                payloads[overlay_path_entry] = data
        elif overlay_path_entry is not None:
            data, mode = overlay_files[overlay_path_entry]
            added.append(
                {
                    "path": overlay_path_entry,
                    "hash": _sha256_digest(data),
                    "size": len(data),
                    "mode": mode,
                }
            )
            payloads[overlay_path_entry] = data
        else:
            assert base_path_entry is not None
            base_hash, base_size = base_rows[base_path_entry]
            deleted.append(
                {
                    "path": base_path_entry,
                    "hash": base_hash,
                    "size": base_size,
                }
            )

    # Describe metadata header changes for the files present on both sides
    metadata_changes: dict[str, dict[str, object]] = {}
    with WheelFile(base_path) as wf:
        for metadata_name in ("METADATA", "WHEEL"):
            canonical = f"{DIST_INFO_TOKEN}/{metadata_name}"
            base_entry = base_canonical.get(canonical)
            overlay_entry = overlay_canonical.get(canonical)
            if base_entry is None or overlay_entry is None:
                continue

            old_headers = _parse_headers(wf.read(base_entry))
            new_headers = _parse_headers(overlay_files[overlay_entry][0])
            changes = _header_changes(old_headers, new_headers)
            metadata_changes[metadata_name] = {
                "changed": bool(changes),
                "changes": changes,
            }

    operations = {
        "added": added,
        "replaced": replaced,
        "deleted": deleted,
    }
    manifest = {
        "format": DELTA_FORMAT,
        "delta_version": DELTA_VERSION,
        "base": base_identity.to_dict(),
        "target": target_identity.to_dict() | {"digest": None, "filename": None},
        "record": [
            {"path": path, "hash": hash_sum, "size": size}
            for path, (hash_sum, size) in sorted(base_rows.items())
        ],
        "operations": operations,
        "metadata": metadata_changes,
    }

    destination = Path(dest_dir)
    destination.mkdir(parents=True, exist_ok=True)
    final_path = destination / target_identity.delta_filename
    with tempfile.TemporaryDirectory(dir=destination, prefix=".whldelta-") as tmp_dir:
        tmp_path = Path(tmp_dir) / target_identity.delta_filename
        with ZipFile(tmp_path, "w", ZIP_DEFLATED) as delta_zip:
            delta_zip.writestr(
                _manifest_zipinfo(MANIFEST_NAME),
                json.dumps(manifest, indent=2).encode("utf-8") + b"\n",
            )
            for arcname in sorted(payloads):
                delta_zip.writestr(
                    _manifest_zipinfo(PAYLOAD_PREFIX + arcname),
                    payloads[arcname],
                )

        os.replace(tmp_path, final_path)

    return str(final_path)


def _load_manifest(delta_zip: ZipFile, delta_path: Path) -> dict[str, object]:
    try:
        raw_manifest = delta_zip.read(MANIFEST_NAME)
    except KeyError:
        raise WheelError(
            f"{delta_path} is not a wheel delta: missing {MANIFEST_NAME}"
        ) from None

    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise WheelError(f"Invalid delta manifest in {delta_path}: {e}") from None

    if not isinstance(manifest, dict):
        raise WheelError(f"Invalid delta manifest in {delta_path}")
    if manifest.get("format") != DELTA_FORMAT:
        raise WheelError(
            f"{delta_path}: unsupported delta format {manifest.get('format')!r}"
        )
    if manifest.get("delta_version") != DELTA_VERSION:
        raise WheelError(
            f"{delta_path}: unsupported delta version "
            f"{manifest.get('delta_version')!r} (this tool supports version "
            f"{DELTA_VERSION})"
        )
    for key in ("base", "target", "record", "operations"):
        if key not in manifest:
            raise WheelError(f"{delta_path}: delta manifest is missing {key!r}")

    operations = manifest["operations"]
    if not isinstance(operations, dict) or not all(
        isinstance(operations.get(kind), list)
        for kind in ("added", "replaced", "deleted")
    ):
        raise WheelError(f"{delta_path}: invalid operations section in manifest")
    if not isinstance(manifest["record"], list):
        raise WheelError(f"{delta_path}: invalid record section in manifest")

    return manifest


def _same_identity(actual: WheelIdentity, expected: WheelIdentity) -> bool:
    return (
        canonicalize_name(actual.name) == canonicalize_name(expected.name)
        and actual.version == expected.version
        and actual.build == expected.build
        and actual.python_tags == expected.python_tags
        and actual.abi_tags == expected.abi_tags
        and actual.platform_tags == expected.platform_tags
    )


def _payload_zipinfo(arcname: str, mode: int) -> ZipInfo:
    info = ZipInfo(arcname, date_time=get_zipinfo_datetime())
    info.compress_type = ZIP_DEFLATED
    info.external_attr = (stat.S_IMODE(mode) | stat.S_IFREG) << 16
    return info


def apply_delta(
    base_wheel: str,
    delta: str,
    dest_dir: str = os.curdir,
) -> str:
    """Apply a versioned delta to a base wheel.

    The base wheel's whole-file digest, RECORD manifest and every file hash are
    verified before the output wheel is built. The output is created in a
    temporary directory and moved into place only after it has been verified,
    so failures never leave a partial target wheel behind.

    :param base_wheel: Path to the base wheel
    :param delta: Path to the delta archive
    :param dest_dir: Directory to store the resulting wheel in
    :return: The path to the created wheel
    """
    base_path = Path(base_wheel)
    if not base_path.is_file():
        raise WheelError(f"Base wheel not found: {base_wheel}")

    delta_path = Path(delta)
    if not delta_path.is_file():
        raise WheelError(f"Delta file not found: {delta}")

    try:
        delta_zip_cm = ZipFile(delta_path)
    except BadZipFile as e:
        raise WheelError(f"{delta_path} is not a valid delta archive: {e}") from None

    with delta_zip_cm as delta_zip:
        manifest = _load_manifest(delta_zip, delta_path)
        base_identity = _identity_from_dict(manifest["base"])  # type: ignore[arg-type]
        target_identity = _identity_from_dict(
            manifest["target"]  # type: ignore[arg-type]
        )

        if base_identity.digest is None:
            raise WheelError(f"{delta_path}: delta manifest lacks a base digest")
        # A delta may only change the version, and only if it was created with
        # that explicit permission
        if (
            canonicalize_name(base_identity.name)
            != canonicalize_name(target_identity.name)
            or base_identity.python_tags != target_identity.python_tags
            or base_identity.abi_tags != target_identity.abi_tags
            or base_identity.platform_tags != target_identity.platform_tags
            or base_identity.build != target_identity.build
        ):
            raise WheelError(
                f"{delta_path}: delta changes the distribution name, build tag "
                "or compatibility tags, which is not supported"
            )

        # Verify the whole-file digest before touching the wheel contents
        actual_digest = _hash_file(base_path)
        if actual_digest != base_identity.digest:
            raise WheelError(
                f"Base wheel {base_path} does not match the delta: file digest "
                f"{actual_digest} != expected {base_identity.digest}"
            )

        added = manifest["operations"]["added"]  # type: ignore[index]
        replaced = manifest["operations"]["replaced"]  # type: ignore[index]
        deleted = manifest["operations"]["deleted"]  # type: ignore[index]

        # Read and verify all payloads up front so that a corrupt delta fails
        # before any output file is created
        payloads: dict[str, tuple[bytes, int]] = {}
        for entry in [*added, *replaced]:
            path = entry.get("path")
            if not isinstance(path, str):
                raise WheelError(f"{delta_path}: operation without a valid path")
            _validate_arcname(path, str(delta_path))
            try:
                data = delta_zip.read(PAYLOAD_PREFIX + path)
            except KeyError:
                raise WheelError(
                    f"{delta_path}: missing payload for {path!r}"
                ) from None

            expected_hash = entry.get("hash")
            expected_size = entry.get("size")
            mode = entry.get("mode", 0o644)
            if (
                not isinstance(expected_hash, str)
                or not isinstance(expected_size, int)
                or not isinstance(mode, int)
            ):
                raise WheelError(f"{delta_path}: invalid operation entry for {path!r}")
            if _sha256_digest(data) != expected_hash or len(data) != expected_size:
                raise WheelError(
                    f"{delta_path}: payload for {path!r} is corrupt; refusing to apply"
                )
            payloads[path] = (data, mode)

        try:
            base_wheel_cm = WheelFile(base_path)
        except BadZipFile as e:
            raise WheelError(f"{base_path} is not a valid wheel file: {e}") from None

        with base_wheel_cm as wf:
            actual_identity = _identity_from_wheel(wf, actual_digest)
            if not _same_identity(actual_identity, base_identity):
                raise WheelError(
                    f"Base wheel {base_path} identity {actual_identity.namever} "
                    f"({list(actual_identity.python_tags)}, "
                    f"{list(actual_identity.abi_tags)}, "
                    f"{list(actual_identity.platform_tags)}) does not match the "
                    "delta's base wheel"
                )

            # Verify the RECORD manifest (paths, hashes, sizes)
            rows = _read_record(wf)
            expected_rows = {
                str(entry["path"]): (entry.get("hash"), entry.get("size"))
                for entry in manifest["record"]  # type: ignore[union-attr]
                if isinstance(entry, dict)
            }
            if len(expected_rows) != len(manifest["record"]):
                raise WheelError(f"{delta_path}: invalid record section in manifest")
            if rows != expected_rows:
                raise WheelError(
                    f"RECORD manifest of {base_path} does not match the manifest "
                    "recorded in the delta; refusing to apply"
                )

            # Verify every archived file against its RECORD hash and size
            for record_path, (_, size) in rows.items():
                data = wf.read(record_path)
                if size is not None and len(data) != size:
                    raise WheelError(
                        f"Size mismatch for {record_path!r} in {base_path}"
                    )

            replaced_by_base: dict[str, dict[str, object]] = {}
            deleted_paths: set[str] = set()
            target_paths: set[str] = set()
            for entry in replaced:
                base_entry_path = entry.get("base_path")
                if not isinstance(base_entry_path, str):
                    raise WheelError(
                        f"{delta_path}: replaced entry without a base_path"
                    )
                if base_entry_path in replaced_by_base:
                    raise WheelError(
                        f"{delta_path}: duplicate operation for {base_entry_path!r}"
                    )
                replaced_by_base[base_entry_path] = entry
                base_hash = rows.get(base_entry_path, (None, None))[0]
                if base_hash != entry.get("base_hash"):
                    raise WheelError(
                        f"Delta expects a different hash for {base_entry_path!r} "
                        "than the base wheel RECORD records"
                    )
                target_paths.add(str(entry["path"]))
            for entry in deleted:
                path = entry.get("path")
                if not isinstance(path, str) or path in deleted_paths:
                    raise WheelError(f"{delta_path}: invalid deleted entry")
                if rows.get(path, (None, None))[0] != entry.get("hash"):
                    raise WheelError(
                        f"Delta expects a different hash for {path!r} than the "
                        "base wheel RECORD records"
                    )
                deleted_paths.add(path)
            for entry in added:
                target_paths.add(str(entry["path"]))

            destination = Path(dest_dir)
            destination.mkdir(parents=True, exist_ok=True)
            output_name = target_identity.wheel_filename
            final_path = destination / output_name
            if final_path.exists() and os.path.samefile(final_path, base_path):
                raise WheelError(
                    "Refusing to overwrite the base wheel in place; choose a "
                    "different destination directory"
                )

            # Build the output wheel in a temporary directory and only publish
            # it after a full verification pass; the temporary directory (and
            # any partial wheel) is removed automatically on failure
            with tempfile.TemporaryDirectory(
                dir=destination, prefix=".whldelta-apply-"
            ) as tmp_dir:
                tmp_path = Path(tmp_dir) / output_name
                with WheelFile(tmp_path, "w") as output:
                    written: set[str] = set()

                    def _write(name: str, info: ZipInfo, data: bytes) -> None:
                        if name in written:
                            raise WheelError(f"Conflicting files produce {name!r}")
                        written.add(name)
                        output.writestr(info, data)

                    for item in sorted(wf.infolist(), key=lambda i: i.filename):
                        if item.is_dir() or item.filename == wf.record_path:
                            continue
                        if (
                            item.filename in deleted_paths
                            or item.filename in replaced_by_base
                        ):
                            continue

                        target_name = _rewrite_path(
                            item.filename, actual_identity, target_identity
                        )
                        new_info = ZipInfo(target_name, date_time=item.date_time)
                        new_info.compress_type = item.compress_type
                        new_info.external_attr = item.external_attr
                        new_info.internal_attr = item.internal_attr
                        new_info.create_system = item.create_system
                        new_info.comment = item.comment
                        new_info.extra = _strip_zip64_extra(item.extra)
                        _write(target_name, new_info, wf.read(item))

                    for entry in [*added, *replaced]:
                        path = str(entry["path"])
                        data, mode = payloads[path]
                        _write(path, _payload_zipinfo(path, mode), data)

                # Verify the generated wheel: RECORD must exist and every file
                # must match the freshly generated hashes
                with WheelFile(tmp_path) as verification:
                    if verification.dist_info_path != (
                        f"{target_identity.namever}.dist-info"
                    ):
                        raise WheelError(
                            "Generated wheel has an unexpected .dist-info path: "
                            f"{verification.dist_info_path!r}"
                        )
                    for info in verification.infolist():
                        if not info.is_dir():
                            verification.read(info)

                os.replace(tmp_path, final_path)

    return str(final_path)
