from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

from wheel._commands import main
from wheel._commands.index import index

from .util import run_command

THISDIR = os.path.dirname(__file__)
TESTWHEEL_NAME = "test-1.0-py2.py3-none-any.whl"
TESTWHEEL_PATH = os.path.join(THISDIR, "..", "testdata", TESTWHEEL_NAME)
DIST_INFO = "test-1.0.dist-info"


def _copy_test_wheel(dest_dir: Path, name: str = TESTWHEEL_NAME) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / name
    shutil.copy2(TESTWHEEL_PATH, dest)
    return dest


def _rewrite_member(
    src: Path,
    dst: Path,
    member: str,
    new_data: bytes,
) -> None:
    """Copy a wheel, replacing one member and patching its RECORD hash."""
    with zipfile.ZipFile(src) as zf:
        infos = zf.infolist()
        record_name = next(n for n in zf.namelist() if n.endswith("/RECORD"))
        original_record = zf.read(record_name).decode("utf-8")

    digest = hashlib.sha256(new_data).digest()
    hash_value = "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    record_rows = []
    for row in csv.reader(io.StringIO(original_record)):
        if row and row[0] == member:
            row[1] = hash_value
            row[2] = str(len(new_data))

        record_rows.append(row)

    new_record = "".join(",".join(row) + "\n" for row in record_rows if row)

    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in infos:
            if item.filename == member:
                zout.writestr(item, new_data)
            elif item.filename == record_name:
                zout.writestr(item, new_record.encode("utf-8"))
            else:
                zout.writestr(item, zin.read(item.filename))


def _run_index_raw(*args: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        patch.object(sys, "argv", ("wheel", "index") + args),
        patch.object(sys, "stdout", stdout),
        patch.object(sys, "stderr", stderr),
    ):
        try:
            returncode = main()
        except SystemExit as exc:
            returncode = exc.code if isinstance(exc.code, int) else 1

    return returncode, stdout.getvalue(), stderr.getvalue()


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_index_basic(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    nested = repo / "nested"
    _copy_test_wheel(nested)
    manifest = tmp_path / "manifest.json"
    lockfile = tmp_path / "lock.json"

    output = run_command(
        "index",
        str(repo),
        "--manifest",
        str(manifest),
        "--lockfile",
        str(lockfile),
    )

    assert "Wrote manifest" in output
    assert "Wrote lockfile" in output

    data = _read_json(manifest)
    assert data["schema_version"] == 1
    assert data["roots"] == [str(repo)]
    assert data["filters"] == {"projects": [], "versions": [], "tags": []}
    assert len(data["wheels"]) == 1

    wheel = data["wheels"][0]
    wheel_path = nested / TESTWHEEL_NAME
    assert wheel == {
        "name": "test",
        "version": "1.0",
        "filename": TESTWHEEL_NAME,
        "path": f"nested/{TESTWHEEL_NAME}",
        "size": wheel_path.stat().st_size,
        "sha256": hashlib.sha256(wheel_path.read_bytes()).hexdigest(),
        "tags": ["py2-none-any", "py3-none-any"],
        "metadata_version": "1.3",
        "record": {
            "sha256": hashlib.sha256(
                zipfile.ZipFile(wheel_path).read(f"{DIST_INFO}/RECORD")
            ).hexdigest(),
            "files": 8,
            "size": 7456,
        },
    }

    lock = _read_json(lockfile)
    assert lock["schema_version"] == 1
    assert lock["packages"]["test"] == {
        "version": "1.0",
        "path": f"nested/{TESTWHEEL_NAME}",
        "filename": TESTWHEEL_NAME,
        "sha256": wheel["sha256"],
        "size": wheel["size"],
        "tags": ["py2-none-any", "py3-none-any"],
        "conflicting": False,
    }
    assert lock["duplicates"] == []
    assert lock["conflicts"] == []


def test_index_is_deterministic(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _copy_test_wheel(repo / "a")
    _copy_test_wheel(repo / "b")

    first = index([str(repo)], str(tmp_path / "m1.json"), str(tmp_path / "l1.json"))
    second = index([str(repo)], str(tmp_path / "m2.json"), str(tmp_path / "l2.json"))

    assert (tmp_path / "m1.json").read_bytes() == (tmp_path / "m2.json").read_bytes()
    assert (tmp_path / "l1.json").read_bytes() == (tmp_path / "l2.json").read_bytes()
    assert [entry.path for entry in first.wheels] == [
        f"a/{TESTWHEEL_NAME}",
        f"b/{TESTWHEEL_NAME}",
    ]
    assert [entry.path for entry in second.wheels] == [
        f"a/{TESTWHEEL_NAME}",
        f"b/{TESTWHEEL_NAME}",
    ]


def test_index_no_recursive(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _copy_test_wheel(repo)
    _copy_test_wheel(repo / "subdir")

    recursive = index([str(repo)], str(tmp_path / "r.json"), str(tmp_path / "rl.json"))
    assert len(recursive.wheels) == 2

    flat = index(
        [str(repo)],
        str(tmp_path / "f.json"),
        str(tmp_path / "fl.json"),
        recursive=False,
    )
    assert [entry.path for entry in flat.wheels] == [TESTWHEEL_NAME]


def test_index_project_filter_normalizes_name(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _copy_test_wheel(repo)

    matched = index(
        [str(repo)],
        str(tmp_path / "m.json"),
        str(tmp_path / "l.json"),
        projects=["Test"],
    )
    assert len(matched.wheels) == 1

    excluded = index(
        [str(repo)],
        str(tmp_path / "m2.json"),
        str(tmp_path / "l2.json"),
        projects=["other"],
    )
    assert excluded.wheels == ()


def test_index_version_filter(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _copy_test_wheel(repo)

    exact = index(
        [str(repo)],
        str(tmp_path / "m.json"),
        str(tmp_path / "l.json"),
        versions=["1.0"],
    )
    assert len(exact.wheels) == 1

    specifier = index(
        [str(repo)],
        str(tmp_path / "m2.json"),
        str(tmp_path / "l2.json"),
        versions=[">=1.0"],
    )
    assert len(specifier.wheels) == 1

    mismatched = index(
        [str(repo)],
        str(tmp_path / "m3.json"),
        str(tmp_path / "l3.json"),
        versions=["==0.9"],
    )
    assert mismatched.wheels == ()

    rc, _, stderr = _run_index_raw(
        str(repo),
        "--manifest",
        str(tmp_path / "m4.json"),
        "--lockfile",
        str(tmp_path / "l4.json"),
        "--version",
        "not-a-spec",
    )
    assert rc == 2
    assert "invalid version specifier" in stderr


def test_index_tag_filter(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _copy_test_wheel(repo)

    matched = index(
        [str(repo)],
        str(tmp_path / "m.json"),
        str(tmp_path / "l.json"),
        tags=["py3-none-any"],
    )
    assert len(matched.wheels) == 1

    mismatched = index(
        [str(repo)],
        str(tmp_path / "m2.json"),
        str(tmp_path / "l2.json"),
        tags=["cp39-cp39-linux_x86_64"],
    )
    assert mismatched.wheels == ()


def test_index_duplicates(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _copy_test_wheel(repo)
    _copy_test_wheel(repo / "copy")

    result = index([str(repo)], str(tmp_path / "m.json"), str(tmp_path / "l.json"))
    assert len(result.wheels) == 2
    assert len(result.duplicates) == 1
    assert result.duplicates[0].paths == (
        f"copy/{TESTWHEEL_NAME}",
        TESTWHEEL_NAME,
    )
    assert result.conflicts == ()

    lock = _read_json(tmp_path / "l.json")
    assert lock["packages"]["test"]["conflicting"] is False
    assert len(lock["duplicates"]) == 1

    _, _, stderr = _run_index_raw(
        str(repo),
        "--manifest",
        str(tmp_path / "m.json"),
        "--lockfile",
        str(tmp_path / "l.json"),
    )
    assert "duplicate" in stderr


def test_index_conflicts(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    original = _copy_test_wheel(repo)
    modified = repo / "modified"
    modified.mkdir()
    modified_wheel = modified / TESTWHEEL_NAME
    new_metadata = (
        zipfile.ZipFile(original)
        .read(f"{DIST_INFO}/METADATA")
        .replace(b"Summary: Test module", b"Summary: Modified wheel")
    )
    _rewrite_member(original, modified_wheel, f"{DIST_INFO}/METADATA", new_metadata)

    result = index([str(repo)], str(tmp_path / "m.json"), str(tmp_path / "l.json"))
    assert len(result.wheels) == 2
    assert result.duplicates == ()
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.name == "test"
    assert conflict.version == "1.0"
    assert len(conflict.artifacts) == 2
    artifact_paths = {artifact.paths for artifact in conflict.artifacts}
    assert artifact_paths == {
        (f"modified/{TESTWHEEL_NAME}",),
        (TESTWHEEL_NAME,),
    }

    lock = _read_json(tmp_path / "l.json")
    package = lock["packages"]["test"]
    assert package["conflicting"] is True
    # The deterministic tie-break prefers the lexicographically first path.
    assert package["path"] == f"modified/{TESTWHEEL_NAME}"
    assert package["alternates"] == [TESTWHEEL_NAME]
    assert len(lock["conflicts"]) == 1

    rc, _, stderr = _run_index_raw(
        str(repo),
        "--manifest",
        str(tmp_path / "m.json"),
        "--lockfile",
        str(tmp_path / "l.json"),
        "--fail-on-conflict",
    )
    assert rc == 1
    assert "conflicting candidate" in stderr

    # Without the flag the same scan succeeds, and duplicates do not fail it.
    rc, _, _ = _run_index_raw(
        str(repo),
        "--manifest",
        str(tmp_path / "m.json"),
        "--lockfile",
        str(tmp_path / "l.json"),
        "--fail-on-conflict",
        "--project",
        "absent",
    )
    assert rc == 0


def test_index_skips_unreadable_wheels(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    wheel_path = _copy_test_wheel(repo)
    original_bytes = wheel_path.read_bytes()

    # Truncated/empty zip and a file with an invalid wheel filename.
    (repo / "broken-1.0-py3-none-any.whl").write_bytes(b"")
    (repo / "notawheel.whl").write_bytes(b"")

    # Wheel with an unparseable version in its metadata.
    bad_version = repo / "badversion"
    bad_version.mkdir()
    bad_version_wheel = bad_version / TESTWHEEL_NAME
    bad_metadata = b"Metadata-Version: 2.1\nName: test\nVersion: not a version\n\n"
    _rewrite_member(
        wheel_path,
        bad_version_wheel,
        f"{DIST_INFO}/METADATA",
        bad_metadata,
    )

    result = index([str(repo)], str(tmp_path / "m.json"), str(tmp_path / "l.json"))
    assert [entry.filename for entry in result.wheels] == [TESTWHEEL_NAME]
    skipped_paths = {skipped.path for skipped in result.skipped}
    assert skipped_paths == {
        f"badversion/{TESTWHEEL_NAME}",
        "broken-1.0-py3-none-any.whl",
        "notawheel.whl",
    }
    # Valid wheels are never modified.
    assert wheel_path.read_bytes() == original_bytes

    manifest = _read_json(tmp_path / "m.json")
    assert {item["path"] for item in manifest["skipped"]} == skipped_paths


def test_index_missing_directory(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"
    rc, _, stderr = _run_index_raw(
        str(missing),
        "--manifest",
        str(tmp_path / "m.json"),
        "--lockfile",
        str(tmp_path / "l.json"),
    )
    assert rc == 1
    assert f"Directory not found: {missing}" in stderr


def test_index_multiple_roots_are_labeled_and_deduped(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    wheel_path = _copy_test_wheel(first)
    _copy_test_wheel(second)

    result = index(
        [str(first), str(second)],
        str(tmp_path / "m.json"),
        str(tmp_path / "l.json"),
    )
    assert sorted(entry.path for entry in result.wheels) == sorted(
        [f"{first}/{TESTWHEEL_NAME}", f"{second}/{TESTWHEEL_NAME}"]
    )

    # Overlapping roots do not index the same file twice.
    result = index(
        [str(first), str(wheel_path.parent)],
        str(tmp_path / "m2.json"),
        str(tmp_path / "l2.json"),
    )
    assert len(result.wheels) == 1


def test_index_does_not_touch_network(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _copy_test_wheel(repo)
    manifest = tmp_path / "m.json"
    lockfile = tmp_path / "l.json"

    # Blocking all socket construction proves the command stays offline.
    import socket

    def _deny(*args: object, **kwargs: object) -> None:
        raise AssertionError("the index command must not access the network")

    with patch.object(socket.socket, "__init__", _deny):
        result = index([str(repo)], str(manifest), str(lockfile))

    assert len(result.wheels) == 1


def test_index_help() -> None:
    output = run_command("index", "--help")
    assert "--manifest" in output
    assert "--lockfile" in output
    assert "--project" in output
    assert "--version" in output
    assert "--tag" in output
    assert "--no-recursive" in output
    assert "--fail-on-conflict" in output
