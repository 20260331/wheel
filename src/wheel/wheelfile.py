from __future__ import annotations

__all__ = [
    "WHEEL_INFO_RE",
    "StreamCancelled",
    "StreamLimitExceeded",
    "StreamLimits",
    "StreamedEntry",
    "WheelContentStream",
    "WheelError",
    "WheelFile",
]

import base64
import csv
import hashlib
import logging
import os.path
import re
import stat
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatchcase
from io import StringIO, TextIOWrapper
from typing import IO, TYPE_CHECKING, Literal
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

if TYPE_CHECKING:
    from _typeshed import SizedBuffer, StrPath


# Non-greedy matching of an optional build number may be too clever (more
# invalid wheel filenames will match). Separate regex for .dist-info?
WHEEL_INFO_RE = re.compile(
    r"""^(?P<namever>(?P<name>[^\s-]+?)-(?P<ver>[^\s-]+?))(-(?P<build>\d[^\s-]*))?
     -(?P<pyver>[^\s-]+?)-(?P<abi>[^\s-]+?)-(?P<plat>\S+)\.whl$""",
    re.VERBOSE,
)
MINIMUM_TIMESTAMP = 315532800  # 1980-01-01 00:00:00 UTC

log = logging.getLogger("wheel")


class WheelError(Exception):
    pass


class StreamLimitExceeded(WheelError):
    """Raised when a streamed read would break a configured limit."""


class StreamCancelled(WheelError):
    """Raised when a streamed wheel content access is cancelled."""


@dataclass(frozen=True)
class StreamLimits:
    """Limits enforced by :meth:`WheelFile.stream_contents`.

    Any field left as ``None`` is not enforced.

    :param max_total_bytes: maximum number of uncompressed bytes readable
        across all streamed entries
    :param max_file_size: maximum uncompressed size of a single entry
    :param max_compression_ratio: maximum ``uncompressed / compressed`` size
        ratio declared for an entry (zip bomb protection)
    :param max_entries: maximum number of entries selected for streaming
    """

    max_total_bytes: int | None = None
    max_file_size: int | None = None
    max_compression_ratio: float | None = None
    max_entries: int | None = None

    def __post_init__(self) -> None:
        for field_name in ("max_total_bytes", "max_file_size", "max_entries"):
            value = getattr(self, field_name)
            if value is not None and value < 0:
                raise ValueError(f"{field_name} must be non-negative")

        if self.max_compression_ratio is not None and self.max_compression_ratio < 0:
            raise ValueError("max_compression_ratio must be non-negative")


#: Named metadata categories accepted by :meth:`WheelFile.stream_contents`
STREAM_CATEGORIES = frozenset(
    {
        "data",
        "entry-points",
        "library",
        "metadata",
        "package-metadata",
        "record",
        "top-level",
        "wheel",
    }
)

#: Categories that select a single well-known .dist-info file
_METADATA_FILE_CATEGORIES = {
    "entry-points": "entry_points.txt",
    "package-metadata": "METADATA",
    "record": "RECORD",
    "top-level": "top_level.txt",
    "wheel": "WHEEL",
}


def _is_safe_member_name(name: str) -> bool:
    """Check that a ZIP member name is a safe, POSIX-style relative path.

    Wheel member names are always relative paths separated by forward slashes.
    Backslashes, absolute paths, drive letters or ``..``/``.`` components are
    refused so that callers can safely use the names when persisting the
    streamed data.
    """
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        return False

    # Windows drive letters (e.g. "C:...")
    if len(name) >= 2 and name[1] == ":":
        return False

    return not any(part in ("", ".", "..") for part in name.split("/"))


def _as_string_tuple(value: str | Iterable[str] | None, what: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)

    try:
        items = tuple(value)
    except TypeError:
        raise TypeError(f"{what} must be a string or an iterable of strings") from None

    if not all(isinstance(item, str) for item in items):
        raise TypeError(f"{what} must only contain strings")

    return items


def urlsafe_b64encode(data: bytes) -> bytes:
    """urlsafe_b64encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def urlsafe_b64decode(data: bytes) -> bytes:
    """urlsafe_b64decode without padding"""
    pad = b"=" * (4 - (len(data) & 3))
    return base64.urlsafe_b64decode(data + pad)


def get_zipinfo_datetime(
    timestamp: float | None = None,
) -> tuple[int, int, int, int, int]:
    # Some applications need reproducible .whl files, but they can't do this without
    # forcing the timestamp of the individual ZipInfo objects. See issue #143.
    timestamp = int(os.environ.get("SOURCE_DATE_EPOCH", timestamp or time.time()))
    timestamp = max(timestamp, MINIMUM_TIMESTAMP)
    return time.gmtime(timestamp)[0:6]


class WheelFile(ZipFile):
    """A ZipFile derivative class that also reads SHA-256 hashes from
    .dist-info/RECORD and checks any read files against those.
    """

    _default_algorithm = hashlib.sha256

    def __init__(
        self,
        file: StrPath,
        mode: Literal["r", "w", "x", "a"] = "r",
        compression: int = ZIP_DEFLATED,
    ):
        basename = os.path.basename(file)
        self.parsed_filename = WHEEL_INFO_RE.match(basename)
        if not basename.endswith(".whl") or self.parsed_filename is None:
            raise WheelError(f"Bad wheel filename {basename!r}")

        ZipFile.__init__(self, file, mode, compression=compression, allowZip64=True)

        self.dist_info_path = "{}.dist-info".format(
            self.parsed_filename.group("namever")
        )
        self.record_path = self.dist_info_path + "/RECORD"
        self._file_hashes: dict[str, tuple[None, None] | tuple[int, bytes]] = {}
        self._file_sizes = {}
        if mode == "r":
            # The .dist-info directory inside the wheel may use normalized
            # (lowercase) naming even when the filename does not. Resolve the
            # actual path case-insensitively.
            if self.record_path not in self.namelist():
                lowered = self.dist_info_path.lower() + "/record"
                for name in self.namelist():
                    if name.lower() == lowered:
                        self.dist_info_path = name.rsplit("/RECORD", 1)[0]
                        self.record_path = name
                        break

            # Ignore RECORD and any embedded wheel signatures
            self._file_hashes[self.record_path] = None, None
            self._file_hashes[self.record_path + ".jws"] = None, None
            self._file_hashes[self.record_path + ".p7s"] = None, None

            # Fill in the expected hashes by reading them from RECORD
            try:
                record = self.open(self.record_path)
            except KeyError:
                raise WheelError(f"Missing {self.record_path} file") from None

            with record:
                for line in csv.reader(
                    TextIOWrapper(record, newline="", encoding="utf-8")
                ):
                    path, hash_sum, size = line
                    if not hash_sum:
                        continue

                    algorithm, hash_sum = hash_sum.split("=")
                    try:
                        hashlib.new(algorithm)
                    except ValueError:
                        raise WheelError(
                            f"Unsupported hash algorithm: {algorithm}"
                        ) from None

                    if algorithm.lower() in {"md5", "sha1"}:
                        raise WheelError(
                            f"Weak hash algorithm ({algorithm}) is not permitted by "
                            f"PEP 427"
                        )

                    self._file_hashes[path] = (
                        algorithm,
                        urlsafe_b64decode(hash_sum.encode("ascii")),
                    )

    def open(
        self,
        name_or_info: str | ZipInfo,
        mode: Literal["r", "w"] = "r",
        pwd: bytes | None = None,
    ) -> IO[bytes]:
        def _update_crc(newdata: bytes) -> None:
            eof = ef._eof
            update_crc_orig(newdata)
            running_hash.update(newdata)
            if eof and running_hash.digest() != expected_hash:
                raise WheelError(f"Hash mismatch for file '{ef_name}'")

        ef_name = (
            name_or_info.filename if isinstance(name_or_info, ZipInfo) else name_or_info
        )
        if (
            mode == "r"
            and not ef_name.endswith("/")
            and ef_name not in self._file_hashes
        ):
            raise WheelError(f"No hash found for file '{ef_name}'")

        ef = ZipFile.open(self, name_or_info, mode, pwd)
        if mode == "r" and not ef_name.endswith("/"):
            algorithm, expected_hash = self._file_hashes[ef_name]
            if expected_hash is not None:
                # Monkey patch the _update_crc method to also check for the hash from
                # RECORD
                running_hash = hashlib.new(algorithm)
                update_crc_orig, ef._update_crc = ef._update_crc, _update_crc

        return ef

    def stream_contents(
        self,
        patterns: str | Iterable[str] | None = None,
        *,
        categories: str | Iterable[str] | None = None,
        limits: StreamLimits | None = None,
        chunk_size: int = 1 << 16,
        is_cancelled: Callable[[], bool] | None = None,
    ) -> WheelContentStream:
        """Return a read-only streaming view over files in this wheel.

        Nothing is extracted to disk and entries are read one fixed-size
        chunk at a time, so neither the whole wheel nor a single file has to
        fit in memory.

        :param patterns: a glob pattern, or several, matched against member
            names with :func:`fnmatch.fnmatchcase` (``*`` also matches ``/``)
        :param categories: a metadata category name, or several:

            * ``metadata`` – every file under ``.dist-info``
            * ``record``, ``wheel``, ``package-metadata``, ``entry-points``,
              ``top-level`` – the corresponding ``.dist-info`` file
            * ``data`` – files under ``<name>-<version>.data``
            * ``library`` – all other (library) files

            When both *patterns* and *categories* are given, their matches
            are combined. When neither is given, every (non-directory) entry
            is selected.
        :param limits: total bytes, per-file size, compression ratio and
            entry count limits (see :class:`StreamLimits`)
        :param chunk_size: maximum number of uncompressed bytes returned per
            chunk (must be positive)
        :param is_cancelled: optional zero-argument callback polled before
            each chunk is read; a truthy result aborts iteration with
            :class:`StreamCancelled`

        Every entry is read through :meth:`open`, so ZIP CRC-32 checks and
            RECORD hash verification are always performed at end of file and
            cannot be bypassed. An error raised while reading one entry does
            not invalidate the stream: close the entry and keep iterating to
            read the remaining entries.
        """
        pattern_tuple = _as_string_tuple(patterns, "patterns")
        category_tuple = _as_string_tuple(categories, "categories")
        return WheelContentStream(
            self,
            pattern_tuple,
            category_tuple,
            limits if limits is not None else StreamLimits(),
            chunk_size,
            is_cancelled,
        )

    def write_files(self, base_dir: str) -> None:
        log.info("creating %r and adding %r to it", self.filename, base_dir)
        deferred: list[tuple[str, str]] = []
        for root, dirnames, filenames in os.walk(base_dir):
            # Sort the directory names so that `os.walk` will walk them in a
            # defined order on the next iteration.
            dirnames.sort()
            for name in sorted(filenames):
                path = os.path.normpath(os.path.join(root, name))
                if os.path.isfile(path):
                    arcname = os.path.relpath(path, base_dir).replace(os.path.sep, "/")
                    if arcname == self.record_path:
                        pass
                    elif root.endswith(".dist-info"):
                        deferred.append((path, arcname))
                    else:
                        self.write(path, arcname)

        deferred.sort()
        for path, arcname in deferred:
            self.write(path, arcname)

    def write(
        self,
        filename: str,
        arcname: str | None = None,
        compress_type: int | None = None,
    ) -> None:
        with open(filename, "rb") as f:
            st = os.fstat(f.fileno())
            data = f.read()

        zinfo = ZipInfo(
            arcname or filename, date_time=get_zipinfo_datetime(st.st_mtime)
        )
        zinfo.external_attr = (stat.S_IMODE(st.st_mode) | stat.S_IFMT(st.st_mode)) << 16
        zinfo.compress_type = compress_type or self.compression
        self.writestr(zinfo, data, compress_type)

    def writestr(
        self,
        zinfo_or_arcname: str | ZipInfo,
        data: SizedBuffer | str,
        compress_type: int | None = None,
    ) -> None:
        if isinstance(zinfo_or_arcname, str):
            zinfo_or_arcname = ZipInfo(
                zinfo_or_arcname, date_time=get_zipinfo_datetime()
            )
            zinfo_or_arcname.compress_type = self.compression
            zinfo_or_arcname.external_attr = (0o664 | stat.S_IFREG) << 16

        if isinstance(data, str):
            data = data.encode("utf-8")

        ZipFile.writestr(self, zinfo_or_arcname, data, compress_type)
        fname = (
            zinfo_or_arcname.filename
            if isinstance(zinfo_or_arcname, ZipInfo)
            else zinfo_or_arcname
        )
        log.info("adding %r", fname)
        if fname != self.record_path:
            hash_ = self._default_algorithm(data)
            self._file_hashes[fname] = (
                hash_.name,
                urlsafe_b64encode(hash_.digest()).decode("ascii"),
            )
            self._file_sizes[fname] = len(data)

    def close(self) -> None:
        # Write RECORD
        if self.fp is not None and self.mode == "w" and self._file_hashes:
            data = StringIO()
            writer = csv.writer(data, delimiter=",", quotechar='"', lineterminator="\n")
            writer.writerows(
                (
                    (fname, algorithm + "=" + hash_, self._file_sizes[fname])
                    for fname, (algorithm, hash_) in self._file_hashes.items()
                )
            )
            writer.writerow((format(self.record_path), "", ""))
            self.writestr(self.record_path, data.getvalue())

        ZipFile.close(self)


class StreamedEntry:
    """A single file entry yielded by :class:`WheelContentStream`.

    Iterate over the entry (or call :meth:`chunks`) to read its uncompressed
    bytes in fixed-size chunks. The underlying ZIP member is closed
    automatically when the chunks are exhausted, when iteration stops early,
    or when :meth:`close` is called.
    """

    def __init__(self, stream: WheelContentStream, info: ZipInfo):
        self._stream = stream
        self.info = info
        self.name = info.filename
        self.bytes_read = 0
        self.started = False
        self.completed = False
        self._counted = False
        self._ef: IO[bytes] | None = None

    @property
    def size(self) -> int:
        """Uncompressed size declared in the archive's central directory."""
        return self.info.file_size

    @property
    def verified(self) -> bool:
        """``True`` if the entry was read to end of file (CRC and RECORD checked)."""
        return self.completed

    def _declared_ratio(self) -> float | None:
        compressed = self.info.compress_size
        if compressed <= 0:
            return None

        return self.info.file_size / compressed

    def chunks(self) -> Iterator[bytes]:
        """Yield the file's uncompressed bytes as fixed-size byte chunks.

        Raises :class:`StreamLimitExceeded` if a configured limit would be
        broken. ZIP CRC-32 and RECORD hash errors surface at end of file
        through the same checks as :meth:`WheelFile.open`.
        """
        if self.started:
            raise WheelError(f"Entry '{self.name}' can only be read once")

        self.started = True
        limits = self._stream.limits

        # This check never bypasses the regular read path; it merely refuses
        # names a caller could otherwise be tricked into persisting.
        if not _is_safe_member_name(self.name):
            raise WheelError(f"Unsafe path in wheel member name: {self.name!r}")

        if (
            limits.max_file_size is not None
            and self.info.file_size > limits.max_file_size
        ):
            raise StreamLimitExceeded(
                f"File '{self.name}' ({self.info.file_size} bytes) exceeds "
                f"max_file_size ({limits.max_file_size} bytes)"
            )

        ratio = self._declared_ratio()
        if (
            ratio is not None
            and limits.max_compression_ratio is not None
            and ratio > limits.max_compression_ratio
        ):
            raise StreamLimitExceeded(
                f"File '{self.name}' has a compression ratio of {ratio:.1f} "
                f"which exceeds max_compression_ratio "
                f"({limits.max_compression_ratio})"
            )

        try:
            ef = self._stream.wheel.open(self.info)
            self._ef = ef
            while True:
                self._stream.check_cancelled()
                chunk = ef.read(self._stream.chunk_size)
                if not chunk:
                    break

                self.bytes_read += len(chunk)
                if (
                    limits.max_file_size is not None
                    and self.bytes_read > limits.max_file_size
                ):
                    raise StreamLimitExceeded(
                        f"File '{self.name}' exceeds max_file_size "
                        f"({limits.max_file_size} bytes)"
                    )

                new_total = self._stream.bytes_read + len(chunk)
                if (
                    limits.max_total_bytes is not None
                    and new_total > limits.max_total_bytes
                ):
                    raise StreamLimitExceeded(
                        f"Total streamed size ({new_total} bytes) exceeds "
                        f"max_total_bytes ({limits.max_total_bytes} bytes)"
                    )

                self._stream.bytes_read = new_total
                yield chunk

            self.completed = True
        finally:
            self.close()

    def __iter__(self) -> Iterator[bytes]:
        return self.chunks()

    def close(self) -> None:
        """Close the underlying ZIP member (safe to call more than once)."""
        ef, self._ef = self._ef, None
        if ef is not None:
            ef.close()

        if self.started and not self._counted:
            self._counted = True
            self._stream._on_entry_closed(self)


class WheelContentStream:
    """A read-only streaming view over the files of a :class:`WheelFile`.

    Instances are created with :meth:`WheelFile.stream_contents` and used as
    an iterator of :class:`StreamedEntry` objects. The owning wheel is never
    closed by the stream.
    """

    def __init__(
        self,
        wheel: WheelFile,
        patterns: tuple[str, ...],
        categories: tuple[str, ...],
        limits: StreamLimits,
        chunk_size: int,
        is_cancelled: Callable[[], bool] | None,
    ):
        if getattr(wheel, "mode", None) != "r":
            raise WheelError("stream_contents() requires a wheel opened in read mode")

        unknown_categories = set(categories) - STREAM_CATEGORIES
        if unknown_categories:
            raise ValueError(
                "Unknown content category(s): " + ", ".join(sorted(unknown_categories))
            )

        if chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")

        self.wheel = wheel
        self.patterns = patterns
        self.categories = categories
        self.limits = limits
        self.chunk_size = chunk_size
        # A WheelFile's constructor rejects filenames that would leave
        # parsed_filename as None, so this only helps static type checkers
        assert wheel.parsed_filename is not None
        namever = wheel.parsed_filename.group("namever")
        self.entries: list[ZipInfo] = [
            info
            for info in wheel.infolist()
            if not info.filename.endswith("/") and self._matches(info.filename, namever)
        ]
        if limits.max_entries is not None and len(self.entries) > limits.max_entries:
            raise StreamLimitExceeded(
                f"{len(self.entries)} matching entries exceed max_entries "
                f"({limits.max_entries})"
            )

        self.bytes_read = 0
        self.entries_completed = 0
        self.entries_failed: list[str] = []
        self._is_cancelled = is_cancelled
        self._cancelled = False
        self._closed = False
        self._current: StreamedEntry | None = None

    def _matches_category(self, name: str, namever: str, category: str) -> bool:
        dist_info = self.wheel.dist_info_path
        if category == "metadata":
            return name.startswith(dist_info + "/")
        if category == "data":
            return name.startswith(f"{namever}.data/")
        if category == "library":
            return not name.startswith(dist_info + "/") and not name.startswith(
                f"{namever}.data/"
            )

        metadata_file = _METADATA_FILE_CATEGORIES.get(category)
        return metadata_file is not None and name == f"{dist_info}/{metadata_file}"

    def _matches(self, name: str, namever: str) -> bool:
        if not self.patterns and not self.categories:
            return True

        if any(fnmatchcase(name, pattern) for pattern in self.patterns):
            return True

        return any(
            self._matches_category(name, namever, category)
            for category in self.categories
        )

    @property
    def cancelled(self) -> bool:
        """Whether :meth:`cancel` was called."""
        return self._cancelled

    @property
    def closed(self) -> bool:
        """Whether :meth:`close` was called."""
        return self._closed

    def cancel(self) -> None:
        """Request cancellation of the stream.

        The next chunk read or entry advance raises :class:`StreamCancelled`.
        """
        self._cancelled = True

    def check_cancelled(self) -> None:
        """Raise :class:`StreamCancelled` if the stream was cancelled."""
        if self._cancelled or (self._is_cancelled is not None and self._is_cancelled()):
            raise StreamCancelled("Streamed wheel content access was cancelled")

    def _on_entry_closed(self, entry: StreamedEntry) -> None:
        if entry.completed:
            self.entries_completed += 1
        else:
            self.entries_failed.append(entry.name)

    def __iter__(self) -> Iterator[StreamedEntry]:
        if self._closed:
            raise WheelError("Cannot iterate over a closed content stream")

        for info in self.entries:
            if self._closed:
                raise WheelError(
                    "Cannot read more entries from a closed content stream"
                )

            self.check_cancelled()
            entry = StreamedEntry(self, info)
            self._current = entry
            try:
                yield entry
            finally:
                entry.close()
                self._current = None

    def close(self) -> None:
        """Close the currently streamed entry; the stream becomes unusable."""
        if self._closed:
            return

        self._closed = True
        if self._current is not None:
            self._current.close()

    def __enter__(self) -> WheelContentStream:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()
