from __future__ import annotations

import base64
import hashlib
import os
import stat
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZIP_STORED, BadZipFile, ZipFile

import pytest
from pytest import MonkeyPatch, TempPathFactory

from wheel.wheelfile import (
    StreamCancelled,
    StreamLimitExceeded,
    StreamLimits,
    WheelError,
    WheelFile,
)


def _make_wheel(path: Path, files: dict[str, bytes]) -> None:
    with WheelFile(path, "w") as wf:
        for name, data in files.items():
            wf.writestr(name, data)


def _record_line(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return f"{name},sha256={digest.decode('ascii')},{len(data)}\n"


@pytest.fixture
def wheel_path(tmp_path: Path) -> Path:
    return tmp_path.joinpath("test-1.0-py2.py3-none-any.whl")


@pytest.mark.parametrize(
    "filename",
    [
        "foo-2-py3-none-any.whl",
        "foo-2-py2.py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    ],
)
def test_wheelfile_re(filename: str, tmp_path: Path) -> None:
    # Regression test for #208 and #485
    path = tmp_path / filename
    with WheelFile(path, "w") as wf:
        assert wf.parsed_filename.group("namever") == "foo-2"


@pytest.mark.parametrize(
    "filename",
    [
        "test.whl",
        "test-1.0.whl",
        "test-1.0-py2.whl",
        "test-1.0-py2-none.whl",
        "test-1.0-py2-none-any",
        "test-1.0-py 2-none-any.whl",
    ],
)
def test_bad_wheel_filename(filename: str) -> None:
    exc = pytest.raises(WheelError, WheelFile, filename)
    exc.match(f"^Bad wheel filename {filename!r}$")


def test_missing_record(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')

    exc = pytest.raises(WheelError, WheelFile, wheel_path)
    exc.match("^Missing test-1.0.dist-info/RECORD file$")


def test_mixed_case_dist_info(tmp_path: Path) -> None:
    """Regression test: wheel filename has uppercase but .dist-info dir is lowercase.

    A wheel named ``Django-3.2.5.whl`` may contain ``django-3.2.5.dist-info/``
    inside (normalized). WheelFile should find RECORD case-insensitively.
    See `#411 <https://github.com/pypa/wheel/issues/411>`_.
    """
    wheel_path = tmp_path / "MixedCase-1.0-py3-none-any.whl"
    with ZipFile(wheel_path, "w", ZIP_DEFLATED) as zf:
        zf.writestr("mixedcase/__init__.py", "")
        # Use lowercase dist-info (as pip/build tools produce)
        zf.writestr("mixedcase-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        zf.writestr(
            "mixedcase-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: MixedCase\nVersion: 1.0\n",
        )
        zf.writestr(
            "mixedcase-1.0.dist-info/RECORD",
            "mixedcase/__init__.py,,\n",
        )

    # Should not raise — this is the fix
    with WheelFile(wheel_path) as wf:
        assert wf.dist_info_path == "mixedcase-1.0.dist-info"
        assert wf.record_path == "mixedcase-1.0.dist-info/RECORD"


def test_unsupported_hash_algorithm(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')
        zf.writestr(
            "test-1.0.dist-info/RECORD",
            "hello/héllö.py,sha000=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25",
        )

    exc = pytest.raises(WheelError, WheelFile, wheel_path)
    exc.match("^Unsupported hash algorithm: sha000$")


@pytest.mark.parametrize(
    "algorithm, digest",
    [
        pytest.param("md5", "4J-scNa2qvSgy07rS4at-Q", id="md5"),
        pytest.param("sha1", "QjCnGu5Qucb6-vir1a6BVptvOA4", id="sha1"),
    ],
)
def test_weak_hash_algorithm(wheel_path: Path, algorithm: str, digest: str) -> None:
    hash_string = f"{algorithm}={digest}"
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')
        zf.writestr("test-1.0.dist-info/RECORD", f"hello/héllö.py,{hash_string},25")

    exc = pytest.raises(WheelError, WheelFile, wheel_path)
    exc.match(rf"^Weak hash algorithm \({algorithm}\) is not permitted by PEP 427$")


@pytest.mark.parametrize(
    "algorithm, digest",
    [
        pytest.param(
            "sha256", "bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo", id="sha256"
        ),
        pytest.param(
            "sha384",
            "cDXriAy_7i02kBeDkN0m2RIDz85w6pwuHkt2PZ4VmT2PQc1TZs8Ebvf6eKDFcD_S",
            id="sha384",
        ),
        pytest.param(
            "sha512",
            "kdX9CQlwNt4FfOpOKO_X0pn_v1opQuksE40SrWtMyP1NqooWVWpzCE3myZTfpy8g2azZON_"
            "iLNpWVxTwuDWqBQ",
            id="sha512",
        ),
    ],
)
def test_testzip(wheel_path: Path, algorithm: str, digest: str) -> None:
    hash_string = f"{algorithm}={digest}"
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, world!")\n')
        zf.writestr("test-1.0.dist-info/RECORD", f"hello/héllö.py,{hash_string},25")

    with WheelFile(wheel_path) as wf:
        wf.testzip()


def test_testzip_missing_hash(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, world!")\n')
        zf.writestr("test-1.0.dist-info/RECORD", "")

    with WheelFile(wheel_path) as wf:
        exc = pytest.raises(WheelError, wf.testzip)
        exc.match("^No hash found for file 'hello/héllö.py'$")


def test_testzip_bad_hash(wheel_path: Path) -> None:
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("hello/héllö.py", 'print("Héllö, w0rld!")\n')
        zf.writestr(
            "test-1.0.dist-info/RECORD",
            "hello/héllö.py,sha256=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25",
        )

    with WheelFile(wheel_path) as wf:
        exc = pytest.raises(WheelError, wf.testzip)
        exc.match("^Hash mismatch for file 'hello/héllö.py'$")


def test_write_str(wheel_path: Path) -> None:
    with WheelFile(wheel_path, "w") as wf:
        wf.writestr("hello/héllö.py", 'print("Héllö, world!")\n')
        wf.writestr("hello/h,ll,.py", 'print("Héllö, world!")\n')

    with ZipFile(wheel_path, "r") as zf:
        infolist = zf.infolist()
        assert len(infolist) == 3
        assert infolist[0].filename == "hello/héllö.py"
        assert infolist[0].file_size == 25
        assert infolist[1].filename == "hello/h,ll,.py"
        assert infolist[1].file_size == 25
        assert infolist[2].filename == "test-1.0.dist-info/RECORD"

        record = zf.read("test-1.0.dist-info/RECORD")
        assert record.decode("utf-8") == (
            "hello/héllö.py,sha256=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25\n"
            '"hello/h,ll,.py",sha256=bv-QV3RciQC2v3zL8Uvhd_arp40J5A9xmyubN34OVwo,25\n'
            "test-1.0.dist-info/RECORD,,\n"
        )


def test_timestamp(
    tmp_path_factory: TempPathFactory, wheel_path: Path, monkeypatch: MonkeyPatch
) -> None:
    # An environment variable can be used to influence the timestamp on
    # TarInfo objects inside the zip.  See issue #143.
    build_dir = tmp_path_factory.mktemp("build")
    for filename in ("one", "two", "three"):
        build_dir.joinpath(filename).write_text(filename + "\n", encoding="utf-8")

    # The earliest date representable in TarInfos, 1980-01-01
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "315576060")

    with WheelFile(wheel_path, "w") as wf:
        wf.write_files(str(build_dir))

    with ZipFile(wheel_path, "r") as zf:
        for info in zf.infolist():
            assert info.date_time[:3] == (1980, 1, 1)
            assert info.compress_type == ZIP_DEFLATED


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not support UNIX-like permissions"
)
def test_attributes(tmp_path_factory: TempPathFactory, wheel_path: Path) -> None:
    # With the change from ZipFile.write() to .writestr(), we need to manually
    # set member attributes.
    build_dir = tmp_path_factory.mktemp("build")
    files = (("foo", 0o644), ("bar", 0o755))
    for filename, mode in files:
        path = build_dir.joinpath(filename)
        path.write_text(filename + "\n", encoding="utf-8")
        path.chmod(mode)

    with WheelFile(wheel_path, "w") as wf:
        wf.write_files(str(build_dir))

    with ZipFile(wheel_path, "r") as zf:
        for filename, mode in files:
            info = zf.getinfo(filename)
            assert info.external_attr == (mode | stat.S_IFREG) << 16
            assert info.compress_type == ZIP_DEFLATED

        info = zf.getinfo("test-1.0.dist-info/RECORD")
        assert info.external_attr == (0o664 | stat.S_IFREG) << 16


# ---------------------------------------------------------------------------
# Read-only streaming content accessor
# ---------------------------------------------------------------------------


def test_stream_by_glob(wheel_path: Path) -> None:
    files = {
        "pkg/a.py": b"print('a')\n",
        "pkg/b.py": b"print('b')\n",
        "pkg/c.txt": b"text\n",
    }
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents("pkg/*.py")
        assert [info.filename for info in stream.entries] == [
            "pkg/a.py",
            "pkg/b.py",
        ]
        streamed: dict[str, bytes] = {}
        for entry in stream:
            assert entry.size == len(files[entry.name])
            streamed[entry.name] = b"".join(entry)
            assert entry.verified

    assert streamed == {"pkg/a.py": files["pkg/a.py"], "pkg/b.py": files["pkg/b.py"]}


def test_stream_by_multiple_globs(wheel_path: Path) -> None:
    files = {
        "pkg/a.py": b"a\n",
        "pkg/b.txt": b"b\n",
        "pkg/c.py": b"c\n",
    }
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(["pkg/a.py", "pkg/b.txt"])
        names = [info.filename for info in stream.entries]

    assert names == ["pkg/a.py", "pkg/b.txt"]


def test_stream_default_selects_all_files(wheel_path: Path) -> None:
    files = {"pkg/a.py": b"a\n", "pkg/b.py": b"b\n"}
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents()
        assert [info.filename for info in stream.entries] == [
            "pkg/a.py",
            "pkg/b.py",
            "test-1.0.dist-info/RECORD",
        ]


def test_stream_category_record(wheel_path: Path) -> None:
    _make_wheel(wheel_path, {"pkg/a.py": b"a\n"})

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(categories="record")
        assert [info.filename for info in stream.entries] == [
            "test-1.0.dist-info/RECORD"
        ]
        entry = next(iter(stream))
        assert b"pkg/a.py" in b"".join(entry)
        assert entry.verified  # CRC is still checked for RECORD itself


def test_stream_category_metadata(wheel_path: Path) -> None:
    with WheelFile(wheel_path, "w") as wf:
        wf.writestr("pkg/a.py", b"a\n")
        wf.writestr("test-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n")

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(categories="metadata")
        assert [info.filename for info in stream.entries] == [
            "test-1.0.dist-info/WHEEL",
            "test-1.0.dist-info/RECORD",
        ]


def test_stream_category_package_metadata(wheel_path: Path) -> None:
    metadata = b"Metadata-Version: 2.1\nName: test\nVersion: 1.0\n"
    with WheelFile(wheel_path, "w") as wf:
        wf.writestr("pkg/a.py", b"a\n")
        wf.writestr("test-1.0.dist-info/METADATA", metadata)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(categories="package-metadata")
        entry = next(iter(stream))
        assert entry.name == "test-1.0.dist-info/METADATA"
        assert b"".join(entry) == metadata


def test_stream_categories_data_and_library(wheel_path: Path) -> None:
    files = {
        "pkg/mod.py": b"x\n",
        "test-1.0.data/scripts/run": b"#!/bin/sh\n",
    }
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        data_stream = wf.stream_contents(categories="data")
        assert [info.filename for info in data_stream.entries] == [
            "test-1.0.data/scripts/run"
        ]

        library_stream = wf.stream_contents(categories="library")
        assert [info.filename for info in library_stream.entries] == ["pkg/mod.py"]

        both_stream = wf.stream_contents(categories=["data", "library"])
        assert [info.filename for info in both_stream.entries] == [
            "pkg/mod.py",
            "test-1.0.data/scripts/run",
        ]


def test_stream_globs_and_categories_combined(wheel_path: Path) -> None:
    files = {
        "pkg/a.py": b"a\n",
        "pkg/b.txt": b"b\n",
        "test-1.0.data/data/x.bin": b"x\n",
    }
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(patterns="pkg/a.py", categories="data")
        assert [info.filename for info in stream.entries] == [
            "pkg/a.py",
            "test-1.0.data/data/x.bin",
        ]


def test_stream_unknown_category(wheel_path: Path) -> None:
    _make_wheel(wheel_path, {"pkg/a.py": b"a\n"})

    with WheelFile(wheel_path) as wf:
        with pytest.raises(ValueError, match="Unknown content category"):
            wf.stream_contents(categories="bogus")


def test_stream_requires_read_mode(wheel_path: Path) -> None:
    with WheelFile(wheel_path, "w") as wf:
        wf.writestr("pkg/a.py", b"a\n")
        with pytest.raises(WheelError, match="read mode"):
            wf.stream_contents()


def test_stream_chunk_sizes(wheel_path: Path) -> None:
    data = os.urandom(50_000)
    _make_wheel(wheel_path, {"pkg/big.bin": data})

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents("pkg/big.bin", chunk_size=8192)
        entry = next(iter(stream))
        chunks = list(entry)

    assert len(chunks) == 7  # 6 full chunks plus a final 848-byte chunk
    assert all(len(chunk) <= 8192 for chunk in chunks)
    assert b"".join(chunks) == data
    assert entry.verified


def test_stream_entry_can_only_be_read_once(wheel_path: Path) -> None:
    _make_wheel(wheel_path, {"pkg/a.py": b"a\n"})

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents()
        entry = next(iter(stream))
        assert b"".join(entry) == b"a\n"
        with pytest.raises(WheelError, match="can only be read once"):
            list(entry.chunks())


def test_stream_max_entries_limit(wheel_path: Path) -> None:
    files = {"pkg/a.py": b"a\n", "pkg/b.py": b"b\n"}
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        with pytest.raises(StreamLimitExceeded, match="max_entries"):
            wf.stream_contents(limits=StreamLimits(max_entries=2))


def test_stream_max_file_size_limit_and_recovery(wheel_path: Path) -> None:
    files = {
        "pkg/small.py": b"abc",
        "pkg/big.bin": b"x" * 1000,
    }
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents("pkg/*", limits=StreamLimits(max_file_size=100))
        results: dict[str, bytes] = {}
        for entry in stream:
            try:
                results[entry.name] = b"".join(entry)
            except StreamLimitExceeded as exc:
                assert "max_file_size" in str(exc)

    assert results == {"pkg/small.py": b"abc"}
    assert stream.entries_completed == 1
    assert stream.entries_failed == ["pkg/big.bin"]


def test_stream_max_total_bytes_limit(wheel_path: Path) -> None:
    files = {
        "pkg/a.bin": b"a" * 100,
        "pkg/b.bin": b"b" * 100,
        "pkg/c.bin": b"c" * 100,
    }
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(
            "pkg/*.bin", limits=StreamLimits(max_total_bytes=250)
        )
        read = bytearray()
        for entry in stream:
            try:
                read.extend(b"".join(entry))
            except StreamLimitExceeded as exc:
                assert "max_total_bytes" in str(exc)

    assert bytes(read) == files["pkg/a.bin"] + files["pkg/b.bin"]
    assert stream.bytes_read == 200
    assert stream.entries_completed == 2
    assert stream.entries_failed == ["pkg/c.bin"]


def test_stream_compression_ratio_limit(wheel_path: Path) -> None:
    files = {
        "pkg/empty.py": b"",
        "pkg/zeros.bin": b"\0" * 100_000,
        "pkg/other.py": b"print('ok')\n",
    }
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(
            "pkg/*", limits=StreamLimits(max_compression_ratio=100)
        )
        results: dict[str, bytes] = {}
        for entry in stream:
            try:
                results[entry.name] = b"".join(entry)
            except StreamLimitExceeded as exc:
                assert "compression ratio" in str(exc)

    assert results == {"pkg/empty.py": b"", "pkg/other.py": files["pkg/other.py"]}
    assert stream.entries_failed == ["pkg/zeros.bin"]


def test_stream_invalid_limit_values() -> None:
    with pytest.raises(ValueError, match="max_total_bytes"):
        StreamLimits(max_total_bytes=-1)
    with pytest.raises(ValueError, match="max_compression_ratio"):
        StreamLimits(max_compression_ratio=-1)


def test_stream_cancel_method(wheel_path: Path) -> None:
    files = {"pkg/a.py": b"a\n", "pkg/b.py": b"b\n"}
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents()
        iterator = iter(stream)
        entry = next(iterator)
        assert b"".join(entry) == b"a\n"
        stream.cancel()
        assert stream.cancelled
        with pytest.raises(StreamCancelled):
            next(iterator)


def test_stream_external_cancel_between_entries(wheel_path: Path) -> None:
    files = {"pkg/a.py": b"a\n", "pkg/b.py": b"b\n"}
    _make_wheel(wheel_path, files)

    should_cancel = {"value": False}
    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(is_cancelled=lambda: should_cancel["value"])
        iterator = iter(stream)
        entry = next(iterator)
        assert b"".join(entry) == b"a\n"
        should_cancel["value"] = True
        with pytest.raises(StreamCancelled):
            next(iterator)


def test_stream_external_cancel_mid_entry(wheel_path: Path) -> None:
    _make_wheel(wheel_path, {"pkg/big.bin": os.urandom(30_000)})

    chunks_seen = 0

    def is_cancelled() -> bool:
        return chunks_seen >= 2

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents(
            "pkg/big.bin",
            chunk_size=4096,
            is_cancelled=is_cancelled,
        )
        entry = next(iter(stream))
        with pytest.raises(StreamCancelled):
            for _chunk in entry:
                chunks_seen += 1

    assert chunks_seen == 2
    assert stream.entries_failed == ["pkg/big.bin"]


def test_stream_close_early(wheel_path: Path) -> None:
    files = {"pkg/a.py": b"a\n", "pkg/b.py": b"b\n"}
    _make_wheel(wheel_path, files)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents()
        iterator = iter(stream)
        entry = next(iterator)
        chunk_iterator = iter(entry)
        assert next(chunk_iterator) == b"a\n"
        stream.close()
        assert stream.closed
        assert entry._ef is None  # active member closed with the stream
        with pytest.raises(WheelError, match="closed content stream"):
            next(iterator)


def test_stream_context_manager(wheel_path: Path) -> None:
    _make_wheel(wheel_path, {"pkg/a.py": b"a\n"})

    with WheelFile(wheel_path) as wf:
        with wf.stream_contents() as stream:
            entry = next(iter(stream))
            assert b"".join(entry) == b"a\n"

        assert stream.closed


def test_stream_hash_mismatch_recovery(wheel_path: Path) -> None:
    content_a = b"aaaa\n"
    content_b = b"bbbb\n"
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("pkg/a.py", content_a)
        zf.writestr("pkg/b.py", content_b)
        zf.writestr(
            "test-1.0.dist-info/RECORD",
            # RECORD claims the wrong hash for a.py
            _record_line("pkg/a.py", b"different")
            + _record_line("pkg/b.py", content_b),
        )

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents("pkg/*.py")
        results: dict[str, bytes] = {}
        for entry in stream:
            try:
                results[entry.name] = b"".join(entry)
            except WheelError:
                continue

    assert results == {"pkg/b.py": content_b}
    assert stream.entries_failed == ["pkg/a.py"]


def test_stream_crc_mismatch(wheel_path: Path) -> None:
    content = b"some uncompressed stored content\n"
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("pkg/a.py", content, compress_type=ZIP_STORED)
        zf.writestr("test-1.0.dist-info/RECORD", _record_line("pkg/a.py", content))

    # Flip a byte in the uncompressed entry payload (after the local header)
    raw = bytearray(wheel_path.read_bytes())
    with ZipFile(wheel_path) as zf:
        header_offset = zf.getinfo("pkg/a.py").header_offset

    name_length = int.from_bytes(raw[header_offset + 26 : header_offset + 28], "little")
    extra_length = int.from_bytes(
        raw[header_offset + 28 : header_offset + 30], "little"
    )
    payload_offset = header_offset + 30 + name_length + extra_length
    raw[payload_offset + 2] ^= 0x01
    wheel_path.write_bytes(raw)

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents()
        entry = next(iter(stream))
        with pytest.raises(BadZipFile, match="Bad CRC-32"):
            b"".join(entry)


def test_stream_unsafe_path_refused(wheel_path: Path) -> None:
    content = b"x"
    with ZipFile(wheel_path, "w") as zf:
        zf.writestr("../evil.py", content)
        zf.writestr("test-1.0.dist-info/RECORD", _record_line("../evil.py", content))

    with WheelFile(wheel_path) as wf:
        stream = wf.stream_contents()
        entry = next(iter(stream))
        with pytest.raises(WheelError, match="Unsafe path"):
            b"".join(entry)


def test_default_open_and_read_unchanged(wheel_path: Path) -> None:
    data = b"print('hello')\n"
    _make_wheel(wheel_path, {"pkg/a.py": data})

    with WheelFile(wheel_path) as wf:
        assert wf.read("pkg/a.py") == data
        with wf.open("pkg/a.py") as f:
            assert f.read() == data
