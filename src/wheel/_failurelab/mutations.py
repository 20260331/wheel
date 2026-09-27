"""Registry of declared structural mutations.

Every mutation takes a legal baseline image and performs **exactly one**
structural change.  Mutations never touch a user-supplied wheel; they only
transform freshly generated corpus images.

Two mutation flavors exist:

* image mutations (``apply_image``) edit the declarative :class:`WheelImage`;
* byte mutations (``apply_bytes``) transform the rendered zip bytes and model
  archive-level damage such as truncation.

Names are stable identifiers embedded in replay manifests.
"""

from __future__ import annotations

__all__ = [
    "MUTATIONS",
    "MUTATION_ORDER",
    "Mutation",
    "apply_mutation",
    "mutation_applies",
]

import copy
import csv
from dataclasses import dataclass
from io import StringIO
from typing import Callable

from .corpus import CORPUS_FORMAT_VERSION, MUTATION_FORMAT_VERSION, Member, WheelImage

ImageFn = Callable[[WheelImage], WheelImage]
ByteFn = Callable[[bytes], bytes]


@dataclass(frozen=True)
class Mutation:
    """A single declared structural mutation."""

    name: str
    description: str
    applies: Callable[[WheelImage], bool]
    apply_image: ImageFn | None = None
    apply_bytes: ByteFn | None = None


def _clone(image: WheelImage) -> WheelImage:
    return copy.deepcopy(image)


def _record_rows(image: WheelImage) -> list[list[str]]:
    text = image.record_override if image.record_override is not None else _synth(image)
    return [row for row in csv.reader(StringIO(text)) if row]


def _synth(image: WheelImage) -> str:
    # Local import to avoid an import cycle at module load time.
    from .corpus import synthesize_record

    return synthesize_record(image)


def _store_rows(image: WheelImage, rows: list[list[str]]) -> None:
    buffer = StringIO()
    writer = csv.writer(buffer, delimiter=",", quotechar='"', lineterminator="\n")
    writer.writerows(rows)
    image.record_override = buffer.getvalue()


def _first_payload_name(image: WheelImage) -> str:
    return image.payload[0].name


def _row_index(rows: list[list[str]], name: str) -> int:
    for index, row in enumerate(rows):
        if row and row[0] == name:
            return index

    raise LookupError(f"no RECORD row for {name!r}")


def _has_payload(image: WheelImage) -> bool:
    return bool(image.payload)


def _record_missing(image: WheelImage) -> WheelImage:
    image.include_record = False
    return image


def _record_drop_row(image: WheelImage) -> WheelImage:
    rows = _record_rows(image)
    del rows[_row_index(rows, _first_payload_name(image))]
    _store_rows(image, rows)
    return image


def _flip_hash_digest(algorithm: str, digest: str) -> str:
    replacement = "B" if digest[:1] != "B" else "A"
    return f"{algorithm}={replacement + digest[1:]}"


def _record_corrupt_hash(image: WheelImage) -> WheelImage:
    rows = _record_rows(image)
    index = _row_index(rows, _first_payload_name(image))
    algorithm, _, digest = rows[index][1].partition("=")
    rows[index][1] = _flip_hash_digest(algorithm, digest)
    _store_rows(image, rows)
    return image


def _record_corrupt_size(image: WheelImage) -> WheelImage:
    rows = _record_rows(image)
    index = _row_index(rows, _first_payload_name(image))
    rows[index][2] = str(int(rows[index][2] or "0") + 1)
    _store_rows(image, rows)
    return image


def _record_weak_hash(image: WheelImage) -> WheelImage:
    # WheelFile rejects md5 while parsing RECORD, before any digest comparison,
    # so a syntactically valid placeholder is enough and also works on FIPS
    # builds where hashlib.md5() may be unavailable.
    rows = _record_rows(image)
    index = _row_index(rows, _first_payload_name(image))
    rows[index][1] = "md5=" + "A" * 22
    _store_rows(image, rows)
    return image


def _record_unknown_algorithm(image: WheelImage) -> WheelImage:
    rows = _record_rows(image)
    index = _row_index(rows, _first_payload_name(image))
    _, _, digest = rows[index][1].partition("=")
    rows[index][1] = f"sha999={digest}"
    _store_rows(image, rows)
    return image


def _record_duplicate_row(image: WheelImage) -> WheelImage:
    rows = _record_rows(image)
    index = _row_index(rows, _first_payload_name(image))
    record_row_index = next(i for i, row in enumerate(rows) if row[1] == "")
    rows.insert(record_row_index, list(rows[index]))
    _store_rows(image, rows)
    return image


def _record_malformed_row(image: WheelImage) -> WheelImage:
    # A single-column row breaks ``path, hash_sum, size = line`` with a raw
    # ValueError instead of the documented WheelError.
    rows = _record_rows(image)
    index = _row_index(rows, _first_payload_name(image))
    rows[index] = ["failurelab-malformed-record-row"]
    _store_rows(image, rows)
    return image


def _payload_unrecorded_extra(image: WheelImage) -> WheelImage:
    name = f"{image.distribution}/_failurelab_extra.py"
    image.unrecorded.append(Member(name, b"# failurelab extra member\n"))
    return image


def _payload_duplicate_divergent(image: WheelImage) -> WheelImage:
    original = image.payload[0]
    divergent_data = (
        original.data + b"x" if not original.data else original.data[:-1] + b"x"
    )
    image.payload.append(Member(original.name, divergent_data, original.compress_type))
    return image


def _distinfo_filename_mismatch(image: WheelImage) -> WheelImage:
    image.filename_override = "zzprobe-9.9-py3-none-any.whl"
    return image


def _wheel_drop_version(image: WheelImage) -> WheelImage:
    image.wheel_fields = [
        (key, value) for key, value in image.wheel_fields if key != "Wheel-Version"
    ]
    return image


def _metadata_drop_name(image: WheelImage) -> WheelImage:
    image.metadata_fields = [
        (key, value) for key, value in image.metadata_fields if key != "Name"
    ]
    return image


def _archive_truncate(data: bytes) -> bytes:
    # Remove the End Of Central Directory record (exactly 22 bytes when the
    # archive carries no comment, which it never does in this corpus).
    return data[:-22]


MUTATION_ORDER = (
    "record-missing",
    "record-drop-row",
    "record-corrupt-hash",
    "record-corrupt-size",
    "record-weak-hash-md5",
    "record-unknown-algorithm",
    "record-duplicate-row",
    "record-malformed-row",
    "payload-unrecorded-extra",
    "payload-duplicate-divergent",
    "distinfo-filename-mismatch",
    "wheel-drop-version",
    "metadata-drop-name",
    "archive-truncated",
)


_MUTATION_DEFS: tuple[Mutation, ...] = (
    Mutation(
        "record-missing",
        "Omit .dist-info/RECORD from the archive",
        lambda image: True,
        _record_missing,
    ),
    Mutation(
        "record-drop-row",
        "Remove the first payload row from RECORD, leaving the member present",
        _has_payload,
        _record_drop_row,
    ),
    Mutation(
        "record-corrupt-hash",
        "Flip one character of the first payload hash in RECORD",
        _has_payload,
        _record_corrupt_hash,
    ),
    Mutation(
        "record-corrupt-size",
        "Increment the recorded size of the first payload member by one",
        _has_payload,
        _record_corrupt_size,
    ),
    Mutation(
        "record-weak-hash-md5",
        "Replace the first payload hash with the weak md5 algorithm marker",
        _has_payload,
        _record_weak_hash,
    ),
    Mutation(
        "record-unknown-algorithm",
        "Replace the hash algorithm name with an unsupported one",
        _has_payload,
        _record_unknown_algorithm,
    ),
    Mutation(
        "record-duplicate-row",
        "Duplicate the first payload RECORD row",
        _has_payload,
        _record_duplicate_row,
    ),
    Mutation(
        "record-malformed-row",
        "Replace a RECORD row with a single-column line",
        _has_payload,
        _record_malformed_row,
    ),
    Mutation(
        "payload-unrecorded-extra",
        "Add one payload member without a matching RECORD row",
        lambda image: True,
        _payload_unrecorded_extra,
    ),
    Mutation(
        "payload-duplicate-divergent",
        "Add a duplicate archive entry of the first member with one byte changed",
        _has_payload,
        _payload_duplicate_divergent,
    ),
    Mutation(
        "distinfo-filename-mismatch",
        "Change only the wheel file name so it no longer matches .dist-info",
        lambda image: True,
        _distinfo_filename_mismatch,
    ),
    Mutation(
        "wheel-drop-version",
        "Remove the Wheel-Version field from WHEEL metadata",
        lambda image: any(k == "Wheel-Version" for k, _ in image.wheel_fields),
        _wheel_drop_version,
    ),
    Mutation(
        "metadata-drop-name",
        "Remove the Name field from METADATA",
        lambda image: any(k == "Name" for k, _ in image.metadata_fields),
        _metadata_drop_name,
    ),
    Mutation(
        "archive-truncated",
        "Truncate the rendered archive by removing the EOCD record",
        lambda image: True,
        None,
        _archive_truncate,
    ),
)


MUTATIONS: dict[str, Mutation] = {item.name: item for item in _MUTATION_DEFS}

#: Combined version of scenario format + mutation semantics, stored in
#: manifests so a replayed sample can be traced to the definitions used.
SCHEMA_VERSION = f"corpus{CORPUS_FORMAT_VERSION}-mutation{MUTATION_FORMAT_VERSION}"


def mutation_applies(name: str, image: WheelImage) -> bool:
    """Return whether the named mutation is applicable to *image*."""
    try:
        mutation = MUTATIONS[name]
    except KeyError:
        available = ", ".join(MUTATION_ORDER)
        raise KeyError(f"Unknown mutation {name!r}. Available: {available}") from None

    return mutation.applies(image)


def apply_mutation(name: str, image: WheelImage) -> WheelImage:
    """Apply exactly one declared mutation to a clone of *image*.

    The original image is never modified.
    """
    try:
        mutation = MUTATIONS[name]
    except KeyError:
        available = ", ".join(MUTATION_ORDER)
        raise KeyError(f"Unknown mutation {name!r}. Available: {available}") from None

    if not mutation.applies(image):
        raise ValueError(f"Mutation {name!r} is not applicable to this image")

    clone = _clone(image)
    if mutation.apply_image is not None:
        return mutation.apply_image(clone)

    return clone
