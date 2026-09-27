from __future__ import annotations

import csv
import hashlib
import io
import os
import sys
from email.message import Message
from io import StringIO
from pathlib import Path
from zipfile import ZipFile

import pytest
from pytest import MonkeyPatch, TempPathFactory

from wheel._commands import main
from wheel._provenance import build_provenance
from wheel.wheelfile import WheelFile, urlsafe_b64encode

from .util import run_command

THISDIR = os.path.dirname(__file__)
TESTWHEEL_PATH = os.path.join(
    THISDIR, "..", "testdata", "test-1.0-py2.py3-none-any.whl"
)
DIST_INFO = "test-1.0.dist-info"
PROVENANCE_NAME = f"{DIST_INFO}/PROVENANCE"
WHEEL_BASENAME = "test-1.0-py2.py3-none-any.whl"


def provenance_for(members: dict[str, bytes], tags: list[str]) -> bytes:
    """Build a provenance statement with correct digests for the members."""
    digests = {
        name: (
            "sha256=" + urlsafe_b64encode(hashlib.sha256(data).digest()).decode(),
            len(data),
        )
        for name, data in members.items()
        if name != f"{DIST_INFO}/RECORD" and name != PROVENANCE_NAME
    }
    return build_provenance(dist_info_path=DIST_INFO, file_digests=digests, tags=tags)


@pytest.fixture
def attested_wheel(
    tmp_path_factory: TempPathFactory, tmp_path: Path
) -> tuple[str, str]:
    """Pack the test wheel with provenance; return (source dir, wheel path)."""
    unpack_dir = tmp_path_factory.mktemp("wheeldir")
    with ZipFile(TESTWHEEL_PATH) as zf:
        zf.extractall(unpack_dir)

    run_command("pack", "--provenance", "--dest", tmp_path, unpack_dir)
    wheel_path = tmp_path / "test-1.0-py2.py3-none-any.whl"
    assert wheel_path.is_file()
    return str(unpack_dir), str(wheel_path)


def run_verify_expect_error(
    monkeypatch: MonkeyPatch, wheel_path: str, message: str
) -> None:
    stdout = StringIO()
    stderr = StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(sys, "argv", ["wheel", "verify", wheel_path])
        patch.setattr(sys, "stdout", stdout)
        patch.setattr(sys, "stderr", stderr)
        returncode = main()

    assert returncode == 1
    assert message in stderr.getvalue()


def rebuild_wheel(
    source: str,
    dest: str,
    *,
    mutate: dict[str, bytes] | None = None,
    add: dict[str, bytes] | None = None,
    drop: set[str] | None = None,
    record_skip: set[str] | None = None,
) -> None:
    """Rewrite a wheel, regenerating RECORD (used to craft tampered archives)."""
    with ZipFile(source) as zf:
        members = {
            info.filename: zf.read(info.filename)
            for info in zf.infolist()
            if not info.is_dir()
        }

    if mutate:
        members.update(mutate)
    if add:
        members.update(add)
    for name in drop or set():
        members.pop(name, None)

    record_path = f"{DIST_INFO}/RECORD"
    members.pop(record_path, None)
    record_skip = record_skip or set()

    with ZipFile(dest, "w") as zout:
        buffer = StringIO()
        writer = csv.writer(buffer, delimiter=",", quotechar='"', lineterminator="\n")
        for name, data in sorted(members.items()):
            zout.writestr(name, data)
            if name not in record_skip:
                digest = urlsafe_b64encode(hashlib.sha256(data).digest()).decode()
                writer.writerow((name, f"sha256={digest}", len(data)))

        writer.writerow((record_path, "", ""))
        zout.writestr(record_path, buffer.getvalue())


def test_pack_provenance_then_verify(attested_wheel: tuple[str, str]) -> None:
    _, wheel_path = attested_wheel
    output = run_command("verify", wheel_path)
    assert "provenance OK" in output
    assert "attestation v1" in output
    assert "tags: py2-none-any,py3-none-any" in output

    with ZipFile(wheel_path) as zf:
        # The statement itself is recorded in RECORD, with a hash.
        record = zf.read(f"{DIST_INFO}/RECORD").decode("utf-8")
        rows = list(csv.reader(io.StringIO(record)))
        provenance_rows = [row for row in rows if row[0] == PROVENANCE_NAME]
        assert len(provenance_rows) == 1
        assert provenance_rows[0][1].startswith("sha256=")
        assert int(provenance_rows[0][2]) > 0

        provenance = zf.read(PROVENANCE_NAME).decode("utf-8")

    assert "Attestation-Version: 1\n" in provenance
    assert "Build-Tool: wheel\n" in provenance
    assert "Build-Input-Digest: sha256=" in provenance
    assert "Tag: py2-none-any\n" in provenance
    assert "Tag: py3-none-any\n" in provenance
    assert "Time-Policy:" in provenance


def test_pack_without_flag_has_no_provenance(
    tmp_path_factory: TempPathFactory, tmp_path: Path
) -> None:
    unpack_dir = tmp_path_factory.mktemp("wheeldir")
    with ZipFile(TESTWHEEL_PATH) as zf:
        zf.extractall(unpack_dir)

    run_command("pack", "--dest", tmp_path, unpack_dir)
    wheel_path = tmp_path / "test-1.0-py2.py3-none-any.whl"
    with ZipFile(wheel_path) as zf:
        assert PROVENANCE_NAME not in zf.namelist()


def test_verify_without_provenance_fails(
    tmp_path_factory: TempPathFactory,
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    unpack_dir = tmp_path_factory.mktemp("wheeldir")
    with ZipFile(TESTWHEEL_PATH) as zf:
        zf.extractall(unpack_dir)

    run_command("pack", "--dest", tmp_path, unpack_dir)
    wheel_path = str(tmp_path / "test-1.0-py2.py3-none-any.whl")
    run_verify_expect_error(monkeypatch, wheel_path, "No test-1.0.dist-info/PROVENANCE")


def test_repack_provenanced_directory(
    attested_wheel: tuple[str, str],
    tmp_path: Path,
    tmp_path_factory: TempPathFactory,
) -> None:
    # Repacking an unpacked wheel that already contains PROVENANCE must replace
    # the statement rather than create a duplicate entry.
    second_dir = tmp_path_factory.mktemp("wheeldir2")
    with ZipFile(attested_wheel[1]) as zf:
        zf.extractall(second_dir)

    run_command("pack", "--provenance", "--dest", tmp_path, second_dir)
    wheel_path = str(tmp_path / "test-1.0-py2.py3-none-any.whl")
    with ZipFile(wheel_path) as zf:
        assert zf.namelist().count(PROVENANCE_NAME) == 1

    run_command("verify", wheel_path)


def test_source_date_epoch_policy(
    tmp_path_factory: TempPathFactory,
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    unpack_dir = tmp_path_factory.mktemp("wheeldir")
    with ZipFile(TESTWHEEL_PATH) as zf:
        zf.extractall(unpack_dir)

    monkeypatch.setenv("SOURCE_DATE_EPOCH", "946684800")
    run_command("pack", "--provenance", "--dest", tmp_path, unpack_dir)
    wheel_path = str(tmp_path / "test-1.0-py2.py3-none-any.whl")

    output = run_command("verify", wheel_path)
    assert "time policy: source-date-epoch=946684800" in output


def test_verify_missing_file(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    run_verify_expect_error(
        monkeypatch,
        str(tmp_path / "missing-1.0-py3-none-any.whl"),
        "No such file",
    )


def test_tampered_payload_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(
        attested_wheel[1],
        dest,
        mutate={"hello/__init__.py": b"print('tampered')\n"},
    )
    run_verify_expect_error(monkeypatch, dest, "mismatch for 'hello/__init__.py'")


def test_unknown_field_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    with ZipFile(attested_wheel[1]) as zf:
        provenance = zf.read(PROVENANCE_NAME)

    tampered = provenance.replace(
        b"Build-Tool: wheel\n", b"Build-Tool: wheel\nX-Evil: pwned\n"
    )
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, mutate={PROVENANCE_NAME: tampered})
    run_verify_expect_error(monkeypatch, dest, "Unknown or untrusted provenance field")


def test_unsupported_version_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    with ZipFile(attested_wheel[1]) as zf:
        provenance = zf.read(PROVENANCE_NAME)

    tampered = provenance.replace(
        b"Attestation-Version: 1\n", b"Attestation-Version: 2\n"
    )
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, mutate={PROVENANCE_NAME: tampered})
    run_verify_expect_error(monkeypatch, dest, "Unsupported attestation version")


@pytest.mark.parametrize(
    "malicious",
    [
        "../evil",
        "foo/../../evil",
        "/etc/passwd",
        "foo\\bar",
    ],
)
def test_malicious_path_fails(
    attested_wheel: tuple[str, str],
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    malicious: str,
) -> None:
    with ZipFile(attested_wheel[1]) as zf:
        provenance = zf.read(PROVENANCE_NAME)

    injected = ("foo,sha256=" + "A" * 43 + ",3\n").encode("utf-8")
    injected = injected.replace(b"foo,", malicious.encode("utf-8") + b",", 1)
    tampered = provenance.replace(b"hello.pyd,", injected + b"hello.pyd,", 1)
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, mutate={PROVENANCE_NAME: tampered})
    run_verify_expect_error(monkeypatch, dest, "provenance")


def test_duplicate_provenance_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    with ZipFile(attested_wheel[1]) as zf:
        provenance = zf.read(PROVENANCE_NAME)

    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(
        attested_wheel[1],
        dest,
        add={"evil-9.9.dist-info/PROVENANCE": provenance},
    )
    run_verify_expect_error(monkeypatch, dest, "Multiple provenance statements")


def test_missing_provenance_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, drop={PROVENANCE_NAME})
    run_verify_expect_error(monkeypatch, dest, "No test-1.0.dist-info/PROVENANCE")


def test_provenance_not_in_record_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, record_skip={PROVENANCE_NAME})
    run_verify_expect_error(monkeypatch, dest, "No hash found for file")


def test_wheel_tags_mismatch_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    # Regenerate the statement with correct file digests but wrong tags; the
    # archive bytes themselves remain untouched.
    with ZipFile(attested_wheel[1]) as zf:
        members = {
            info.filename: zf.read(info.filename)
            for info in zf.infolist()
            if not info.is_dir()
        }

    retagged = provenance_for(members, ["py3-none-any"])
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, mutate={PROVENANCE_NAME: retagged})
    run_verify_expect_error(
        monkeypatch, dest, "Provenance tags do not match the Tag fields"
    )


def test_filename_tags_mismatch_fails(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    # Provenance and WHEEL agree with each other but disagree with the tags in
    # the wheel filename.
    dist_info = "clash-1.0.dist-info"
    wheel_message = Message()
    wheel_message["Wheel-Version"] = "1.0"
    wheel_message["Root-Is-Purelib"] = "true"
    wheel_message["Tag"] = "py4-none-any"
    metadata = b"Metadata-Version: 2.1\r\nName: clash\r\nVersion: 1.0\r\n\r\n"

    files = {
        "clash/__init__.py": b"",
        f"{dist_info}/WHEEL": wheel_message.as_bytes(),
        f"{dist_info}/METADATA": metadata,
    }
    digests = {
        name: (
            "sha256=" + urlsafe_b64encode(hashlib.sha256(data).digest()).decode(),
            len(data),
        )
        for name, data in files.items()
    }
    files[f"{dist_info}/PROVENANCE"] = build_provenance(
        dist_info_path=dist_info,
        file_digests=digests,
        tags=["py4-none-any"],
    )

    wheel_path = tmp_path / "clash-1.0-py3-none-any.whl"
    with WheelFile(wheel_path, "w") as wf:
        for name, data in files.items():
            wf.writestr(name, data)

    run_verify_expect_error(
        monkeypatch, str(wheel_path), "do not match the wheel filename tags"
    )


def test_time_policy_mismatch_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    with ZipFile(attested_wheel[1]) as zf:
        provenance = zf.read(PROVENANCE_NAME)

    tampered = provenance.replace(
        b"Time-Policy: mtime", b"Time-Policy: source-date-epoch=946684800"
    )
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, mutate={PROVENANCE_NAME: tampered})
    run_verify_expect_error(
        monkeypatch, dest, "does not match the declared time policy"
    )


def test_extra_member_fails(
    attested_wheel: tuple[str, str], tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    dest = str(tmp_path / WHEEL_BASENAME)
    rebuild_wheel(attested_wheel[1], dest, add={"surprise.txt": b"hi"})
    run_verify_expect_error(monkeypatch, dest, "missing from provenance")
