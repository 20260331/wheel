"""Synthetic wheel corpus generation.

A corpus is built from an in-memory :class:`WheelImage`, rendered straight to
zip bytes with the :mod:`zipfile` module.  No build backend, network access or
current working directory state is involved and every byte is deterministic
(fixed zip timestamps, ordered members, seeded RNG) so that a sample rendered
today renders identically during replay next year.
"""

from __future__ import annotations

__all__ = [
    "CORPUS_FORMAT_VERSION",
    "MUTATION_FORMAT_VERSION",
    "SCENARIOS",
    "Member",
    "Scenario",
    "WheelImage",
    "build_scenario_image",
    "build_seeded_image",
    "dist_info_dir",
    "render_wheel",
    "synthesize_record",
    "wheel_filename",
    "write_wheel",
]

import base64
import csv
import hashlib
import os
import random
import stat
import warnings
from dataclasses import dataclass, field
from io import BytesIO, StringIO
from pathlib import Path
from typing import Callable
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

# Bumped whenever a built-in scenario definition or the rendering format
# changes in a way that affects the produced bytes.
CORPUS_FORMAT_VERSION = 1

# Bumped whenever the mutation registry semantics change.
MUTATION_FORMAT_VERSION = 1

# Fixed so rendered bytes do not depend on SOURCE_DATE_EPOCH, the wall clock
# or the local time zone.
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)
_FIXED_EXTERNAL_ATTR = (0o644 | stat.S_IFREG) << 16

_PAYLOAD_ALPHABET = b"012345679ab# x\n"


@dataclass
class Member:
    """A single zip archive member."""

    name: str
    data: bytes = b""
    compress_type: int = ZIP_DEFLATED


@dataclass
class WheelImage:
    """Mutable, declarative description of a wheel archive.

    The regular metadata files (``WHEEL``, ``METADATA``) are represented as
    ordered header field lists so the reducer can drop individual fields.
    ``RECORD`` is regenerated from the member data unless a mutation overrides
    it.
    """

    distribution: str = "example"
    version: str = "1.0"
    build: str | None = None
    python_tag: str = "py3"
    abi_tag: str = "none"
    platform_tag: str = "any"
    wheel_fields: list[tuple[str, str]] = field(default_factory=list)
    metadata_fields: list[tuple[str, str]] = field(default_factory=list)
    #: Regular payload members (may contain duplicate names on purpose after a
    #: duplicate-member mutation).
    payload: list[Member] = field(default_factory=list)
    #: Extra files inside ``.dist-info`` (LICENSE, entry_points.txt, ...).
    dist_extra: list[Member] = field(default_factory=list)
    #: Members that are written into the archive but deliberately left out of
    #: RECORD (managed exclusively by mutations).
    unrecorded: list[Member] = field(default_factory=list)
    include_record: bool = True
    #: Verbatim RECORD text; ``None`` means "synthesize from member data".
    record_override: str | None = None
    #: Compression applied to metadata and RECORD members.
    compression: int = ZIP_DEFLATED
    comment: bytes = b""
    #: Overrides the on-disk file name (managed exclusively by mutations).
    filename_override: str | None = None


def dist_info_dir(image: WheelImage) -> str:
    """Return the ``{name}-{version}.dist-info`` directory name."""
    return f"{image.distribution}-{image.version}.dist-info"


def wheel_filename(image: WheelImage) -> str:
    """Return the wheel file name implied by the image tags."""
    build = f"-{image.build}" if image.build else ""
    return (
        f"{image.distribution}-{image.version}{build}"
        f"-{image.python_tag}-{image.abi_tag}-{image.platform_tag}.whl"
    )


def _urlsafe_b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _render_fields(fields: list[tuple[str, str]]) -> bytes:
    return "".join(f"{key}: {value}\n" for key, value in fields).encode("utf-8")


def _recorded_members(image: WheelImage) -> list[Member]:
    """All members that a legal RECORD needs an entry for, in archive order."""
    dist = dist_info_dir(image)
    members = list(image.payload)
    members.append(Member(f"{dist}/WHEEL", _render_fields(image.wheel_fields)))
    members.append(Member(f"{dist}/METADATA", _render_fields(image.metadata_fields)))
    members.extend(image.dist_extra)
    return members


def synthesize_record(image: WheelImage) -> str:
    """Render a PEP 427 RECORD for every recorded member, plus the empty
    self-reference row for RECORD itself."""
    buffer = StringIO()
    writer = csv.writer(buffer, delimiter=",", quotechar='"', lineterminator="\n")
    for member in _recorded_members(image):
        digest = hashlib.sha256(member.data).digest()
        writer.writerow(
            (member.name, "sha256=" + _urlsafe_b64(digest), len(member.data))
        )

    writer.writerow((f"{dist_info_dir(image)}/RECORD", "", ""))
    return buffer.getvalue()


def _zipinfo(name: str, compress_type: int) -> ZipInfo:
    info = ZipInfo(name, date_time=FIXED_DATE_TIME)
    info.compress_type = compress_type
    info.external_attr = _FIXED_EXTERNAL_ATTR
    info.create_system = 3
    return info


def render_wheel(image: WheelImage) -> bytes:
    """Render the image to a deterministic in-memory wheel file."""
    buffer = BytesIO()
    # Some mutations intentionally write duplicate member names; zipfile only
    # announces that with a UserWarning, which callers running with
    # ``-W error`` would otherwise turn into an exception before the target is
    # ever reached.
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore", message="Duplicate name: ", category=UserWarning
        )
        with ZipFile(buffer, "w") as archive:
            archive.comment = image.comment
            for member in image.payload + image.unrecorded:
                archive.writestr(
                    _zipinfo(member.name, member.compress_type), member.data
                )

            dist = dist_info_dir(image)
            archive.writestr(
                _zipinfo(f"{dist}/WHEEL", image.compression),
                _render_fields(image.wheel_fields),
            )
            archive.writestr(
                _zipinfo(f"{dist}/METADATA", image.compression),
                _render_fields(image.metadata_fields),
            )
            for member in image.dist_extra:
                archive.writestr(
                    _zipinfo(member.name, member.compress_type or image.compression),
                    member.data,
                )

            if image.include_record:
                record = (
                    image.record_override
                    if image.record_override is not None
                    else synthesize_record(image)
                )
                archive.writestr(
                    _zipinfo(f"{dist}/RECORD", image.compression),
                    record.encode("utf-8"),
                )

    return buffer.getvalue()


def write_wheel(
    image: WheelImage,
    directory: str | os.PathLike[str],
    byte_mutation: Callable[[bytes], bytes] | None = None,
) -> Path:
    """Render the image into *directory* and return the written path."""
    data = render_wheel(image)
    if byte_mutation is not None:
        data = byte_mutation(data)

    path = Path(directory) / (image.filename_override or wheel_filename(image))
    path.write_bytes(data)
    return path


@dataclass(frozen=True)
class Scenario:
    """A named, versioned legal wheel template."""

    name: str
    version: int
    description: str
    builder: Callable[[], WheelImage]

    def build(self) -> WheelImage:
        return self.builder()


def _base_wheel_fields(purelib: bool, tag: str) -> list[tuple[str, str]]:
    fields = [
        ("Wheel-Version", "1.0"),
        ("Generator", "wheel-failurelab"),
        ("Root-Is-Purelib", "true" if purelib else "false"),
        ("Tag", tag),
    ]
    return fields


def _minimal_purelib() -> WheelImage:
    return WheelImage(
        distribution="example",
        version="1.0",
        python_tag="py3",
        abi_tag="none",
        platform_tag="any",
        wheel_fields=_base_wheel_fields(True, "py3-none-any"),
        metadata_fields=[
            ("Metadata-Version", "2.1"),
            ("Name", "example"),
            ("Version", "1.0"),
        ],
        payload=[Member("example/__init__.py", b"")],
    )


def _minimal_platlib() -> WheelImage:
    return WheelImage(
        distribution="example",
        version="1.0",
        python_tag="cp312",
        abi_tag="cp312",
        platform_tag="linux_x86_64",
        wheel_fields=_base_wheel_fields(False, "cp312-cp312-linux_x86_64"),
        metadata_fields=[
            ("Metadata-Version", "2.1"),
            ("Name", "example"),
            ("Version", "1.0"),
        ],
        payload=[Member("example/_native.so", b"")],
    )


def _typical_purelib() -> WheelImage:
    metadata: list[tuple[str, str]] = [
        ("Metadata-Version", "2.1"),
        ("Name", "typical"),
        ("Version", "2.3.4"),
        ("Summary", "Typical synthetic corpus wheel"),
        ("Author-email", "maintainers@example.invalid"),
        ("Requires-Python", ">=3.9"),
        ("Classifier", "Programming Language :: Python :: 3"),
        ("Classifier", "License :: OSI Approved :: MIT License"),
        ("Requires-Dist", "packaging>=24.0"),
    ]
    payload = [
        Member("typical/__init__.py", b'"""Typical package."""\n'),
        Member("typical/core.py", b"def answer() -> int:\n    return 42\n"),
        Member(
            "typical/util.py",
            b"def noop() -> None:\n    return None\n",
        ),
    ]
    extras = [
        Member(
            "typical-2.3.4.dist-info/entry_points.txt",
            b"[console_scripts]\ntypical = typical.core:answer\n",
        ),
        Member("typical-2.3.4.dist-info/LICENSE", b"MIT\n"),
    ]
    return WheelImage(
        distribution="typical",
        version="2.3.4",
        build="1",
        python_tag="py3",
        abi_tag="none",
        platform_tag="any",
        wheel_fields=_base_wheel_fields(True, "py3-none-any"),
        metadata_fields=metadata,
        payload=payload,
        dist_extra=extras,
    )


SCENARIOS: dict[str, Scenario] = {
    scenario.name: scenario
    for scenario in (
        Scenario(
            "minimal-purelib",
            CORPUS_FORMAT_VERSION,
            "Smallest legal pure-Python wheel",
            _minimal_purelib,
        ),
        Scenario(
            "minimal-platlib",
            CORPUS_FORMAT_VERSION,
            "Smallest legal platform wheel",
            _minimal_platlib,
        ),
        Scenario(
            "typical-purelib",
            CORPUS_FORMAT_VERSION,
            "Pure-Python wheel with payload, extras and rich metadata",
            _typical_purelib,
        ),
    )
}


def build_scenario_image(name: str) -> WheelImage:
    """Look up a versioned scenario and return a fresh image."""
    try:
        scenario = SCENARIOS[name]
    except KeyError:
        available = ", ".join(sorted(SCENARIOS))
        raise KeyError(f"Unknown scenario {name!r}. Available: {available}") from None

    return scenario.build()


def build_seeded_image(seed: int) -> WheelImage:
    """Build a deterministic legal image from an integer *seed*.

    The same seed always yields byte-identical wheels, independent of the
    Python process, environment variables or current working directory.
    """
    rng = random.Random(seed)
    distribution = rng.choice(["alpha", "beta", "gamma", "delta"])
    purelib = rng.choice([True, False])
    build = rng.choice([None, None, "1"])
    if purelib:
        python_tag, abi_tag, platform_tag = "py3", "none", "any"
    else:
        python_tag, abi_tag, platform_tag = "cp312", "cp312", "linux_x86_64"

    wheel_fields = _base_wheel_fields(purelib, f"{python_tag}-{abi_tag}-{platform_tag}")
    metadata_fields: list[tuple[str, str]] = [
        ("Metadata-Version", "2.1"),
        ("Name", distribution),
        ("Version", "1.0"),
    ]
    optional_metadata = [
        ("Summary", "Seeded synthetic corpus wheel"),
        ("Author-email", "maintainers@example.invalid"),
        ("Requires-Python", ">=3.9"),
        ("Classifier", "Programming Language :: Python :: 3"),
        ("Requires-Dist", "packaging>=24.0"),
    ]
    for field_name, value in optional_metadata:
        if rng.choice([True, False]):
            metadata_fields.append((field_name, value))

    file_count = rng.randint(1, 4)
    payload: list[Member] = []
    for index in range(file_count):
        length = rng.randint(0, 12)
        data = bytes(rng.choice(_PAYLOAD_ALPHABET) for _ in range(length))
        name = (
            f"{distribution}/__init__.py"
            if index == 0
            else f"{distribution}/module_{index}.py"
        )
        payload.append(Member(name, data))

    dist_extra: list[Member] = []
    if rng.choice([True, False]):
        dist_extra.append(Member(f"{distribution}-1.0.dist-info/LICENSE", b"MIT\n"))

    return WheelImage(
        distribution=distribution,
        version="1.0",
        build=build,
        python_tag=python_tag,
        abi_tag=abi_tag,
        platform_tag=platform_tag,
        wheel_fields=wheel_fields,
        metadata_fields=metadata_fields,
        payload=payload,
        dist_extra=dist_extra,
    )
