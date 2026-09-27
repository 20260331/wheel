from __future__ import annotations

import json
import stat
import zipfile
from collections.abc import Callable
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from wheel._commands.delta import (
    DELTA_VERSION,
    MANIFEST_NAME,
    PAYLOAD_PREFIX,
    apply_delta,
    make_delta,
)
from wheel.wheelfile import WheelError, WheelFile

from .util import run_command

TESTWHEEL_NAME = "test-1.0-py2.py3-none-any.whl"
TESTWHEEL_PATH = Path(__file__).parent.parent / "testdata" / TESTWHEEL_NAME

BASE_FILES: dict[str, tuple[bytes, int]] = {
    "hello/__init__.py": (b"", 0o644),
    "hello/hello.py": (b"GREETING = 'hi'\n", 0o644),
    "hello/old.py": (b"# obsolete module\n", 0o644),
    "test-1.0.data/scripts/hello.sh": (b"echo hi\n", 0o755),
    "test-1.0.data/data/hello.dat": (b"payload\n", 0o644),
}
OVERLAY_FILES: dict[str, tuple[bytes, int]] = {
    "hello/__init__.py": (b"", 0o644),
    "hello/hello.py": (b"GREETING = 'hello'\n", 0o644),
    "hello/new.py": (b"# brand new module\n", 0o644),
    "test-1.0.data/scripts/hello.sh": (b"echo hello\n", 0o755),
    "test-1.0.data/data/hello.dat": (b"payload\n", 0o644),
}


def build_wheel(
    path: Path,
    files: dict[str, tuple[bytes, int]],
    *,
    name: str = "test",
    version: str = "1.0",
    build: str | None = None,
    python_tags: tuple[str, ...] = ("py3",),
    abi_tags: tuple[str, ...] = ("none",),
    platform_tags: tuple[str, ...] = ("any",),
) -> Path:
    namever = f"{name}-{version}"
    with WheelFile(path, "w") as wf:
        for arcname, (data, mode) in files.items():
            info = zipfile.ZipInfo(arcname)
            info.external_attr = (stat.S_IFREG | mode) << 16
            wf.writestr(info, data)

        tag_lines = "".join(
            f"Tag: {py}-{abi}-{plat}\n"
            for py in python_tags
            for abi in abi_tags
            for plat in platform_tags
        )
        build_line = f"Build: {build}\n" if build else ""
        wf.writestr(
            f"{namever}.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            + tag_lines.encode()
            + build_line.encode()
            + b"Generator: delta-tests\n",
        )
        wf.writestr(
            f"{namever}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
        )

    return path


def wheel_name(
    *,
    name: str = "test",
    version: str = "1.0",
    build: str | None = None,
    python_tags: tuple[str, ...] = ("py3",),
    abi_tags: tuple[str, ...] = ("none",),
    platform_tags: tuple[str, ...] = ("any",),
) -> str:
    parts = [f"{name}-{version}"]
    if build:
        parts.append(build)
    parts.extend(
        [
            ".".join(python_tags),
            ".".join(abi_tags),
            ".".join(platform_tags),
        ]
    )
    return "-".join(parts) + ".whl"


def wheel_contents(path: Path) -> dict[str, bytes]:
    with ZipFile(path) as zf:
        return {
            info.filename: zf.read(info.filename)
            for info in zf.infolist()
            if not info.is_dir()
        }


def wheel_modes(path: Path) -> dict[str, int]:
    with ZipFile(path) as zf:
        return {
            info.filename: (info.external_attr >> 16) & 0o777
            for info in zf.infolist()
            if not info.is_dir()
        }


def assert_readable_wheel(path: Path) -> None:
    """Open the wheel and read every file, enforcing the RECORD hashes."""
    with WheelFile(path) as wf:
        assert len(wf.namelist()) > 0
        for info in wf.infolist():
            if not info.is_dir():
                wf.read(info)


@pytest.fixture
def base_wheel(tmp_path: Path) -> Path:
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    return build_wheel(base_dir / wheel_name(), BASE_FILES)


@pytest.fixture
def overlay_wheel(tmp_path: Path) -> Path:
    overlay_dir = tmp_path / "overlay"
    overlay_dir.mkdir()
    return build_wheel(overlay_dir / wheel_name(), OVERLAY_FILES)


def rewrite_delta(
    source: Path,
    destination: Path,
    *,
    manifest_transform: Callable[[bytes], bytes] | None = None,
    payload_transforms: dict[str, Callable[[bytes], bytes]] | None = None,
) -> None:
    payload_transforms = payload_transforms or {}
    with ZipFile(source) as zin, ZipFile(destination, "w", ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == MANIFEST_NAME and manifest_transform is not None:
                data = manifest_transform(data)
            transform = payload_transforms.get(item.filename)
            if transform is not None:
                data = transform(data)
            zout.writestr(item, data)


def test_delta_from_wheel_adds_replaces_deletes(
    tmp_path: Path, base_wheel: Path, overlay_wheel: Path
) -> None:
    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(out_dir)))
    assert delta_path.name == "test-1.0-py3-none-any.whldelta"

    result = Path(apply_delta(str(base_wheel), str(delta_path), str(out_dir)))
    assert result == out_dir / wheel_name()

    contents = wheel_contents(result)
    expected_contents = {
        name: data
        for name, data in wheel_contents(overlay_wheel).items()
        if not name.endswith("/RECORD")
    }
    assert {
        name: data for name, data in contents.items() if not name.endswith("/RECORD")
    } == expected_contents
    assert "hello/old.py" not in contents
    assert contents["hello/hello.py"] == b"GREETING = 'hello'\n"
    assert contents["hello/new.py"] == b"# brand new module\n"

    modes = wheel_modes(result)
    assert modes["test-1.0.data/scripts/hello.sh"] == 0o755
    assert_readable_wheel(result)


def test_delta_manifest_describes_operations_and_metadata(
    base_wheel: Path, overlay_wheel: Path, tmp_path: Path
) -> None:
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(tmp_path)))
    with ZipFile(delta_path) as zf:
        manifest = json.loads(zf.read(MANIFEST_NAME))
        payload_names = {
            name[len(PAYLOAD_PREFIX) :]
            for name in zf.namelist()
            if name.startswith(PAYLOAD_PREFIX)
        }

    assert manifest["format"] == "wheel-delta"
    assert manifest["delta_version"] == DELTA_VERSION
    assert manifest["base"]["name"] == "test"
    assert manifest["base"]["version"] == "1.0"
    assert manifest["base"]["python_tags"] == ["py3"]
    assert manifest["target"]["version"] == "1.0"

    operations = manifest["operations"]
    assert {entry["path"] for entry in operations["added"]} == {"hello/new.py"}
    assert {entry["path"] for entry in operations["replaced"]} == {
        "hello/hello.py",
        "test-1.0.data/scripts/hello.sh",
    }
    assert {entry["path"] for entry in operations["deleted"]} == {"hello/old.py"}
    replaced = next(
        entry for entry in operations["replaced"] if entry["path"] == "hello/hello.py"
    )
    assert replaced["base_path"] == "hello/hello.py"
    assert replaced["base_hash"].startswith("sha256=")
    assert replaced["hash"] != replaced["base_hash"]
    assert payload_names == {
        "hello/new.py",
        "hello/hello.py",
        "test-1.0.data/scripts/hello.sh",
    }

    record_paths = {entry["path"] for entry in manifest["record"]}
    assert "hello/old.py" in record_paths
    assert "test-1.0.dist-info/RECORD" in record_paths
    assert manifest["metadata"]["WHEEL"]["changed"] is False


def test_delta_from_unpacked_directory(
    tmp_path: Path, base_wheel: Path, overlay_wheel: Path
) -> None:
    unpacked = tmp_path / "unpacked"
    unpacked.mkdir()
    with ZipFile(overlay_wheel) as zf:
        zf.extractall(unpacked)

    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(base_wheel), str(unpacked), str(out_dir)))
    result = Path(apply_delta(str(base_wheel), str(delta_path), str(out_dir)))

    contents = wheel_contents(result)
    assert contents["hello/new.py"] == b"# brand new module\n"
    assert contents["hello/hello.py"] == b"GREETING = 'hello'\n"
    assert "hello/old.py" not in contents
    assert_readable_wheel(result)


def test_delta_rejects_version_change_by_default(
    tmp_path: Path, base_wheel: Path
) -> None:
    overlay_dir = tmp_path / "overlay"
    overlay_dir.mkdir()
    overlay = build_wheel(
        overlay_dir / wheel_name(version="1.1"),
        {
            "hello/__init__.py": (b"", 0o644),
            "hello/hello.py": (b"v2\n", 0o644),
            "test-1.1.data/data/hello.dat": (b"payload\n", 0o644),
        },
        version="1.1",
    )

    with pytest.raises(WheelError, match="--allow-version-change"):
        make_delta(str(base_wheel), str(overlay), str(tmp_path / "delta"))


def test_delta_allow_version_change_rewrites_dist_info(
    tmp_path: Path, base_wheel: Path
) -> None:
    overlay_dir = tmp_path / "overlay"
    overlay_dir.mkdir()
    overlay_files = {
        "hello/__init__.py": (b"", 0o644),
        "hello/hello.py": (b"GREETING = '2.0'\n", 0o644),
        "hello/new.py": (b"# new\n", 0o644),
        "test-2.0.data/data/hello.dat": (b"payload2\n", 0o644),
    }
    overlay = build_wheel(
        overlay_dir / wheel_name(version="2.0"),
        overlay_files,
        version="2.0",
    )

    out_dir = tmp_path / "out"
    delta_path = Path(
        make_delta(
            str(base_wheel),
            str(overlay),
            str(out_dir),
            allow_version_change=True,
        )
    )
    assert delta_path.name == "test-2.0-py3-none-any.whldelta"

    with ZipFile(delta_path) as zf:
        manifest = json.loads(zf.read(MANIFEST_NAME))
    assert manifest["target"]["version"] == "2.0"
    metadata_changes = manifest["metadata"]["METADATA"]["changes"]
    assert {change["header"] for change in metadata_changes} == {"Version"}
    version_change = next(
        change for change in metadata_changes if change["header"] == "Version"
    )
    assert version_change["old"] == ["1.0"]
    assert version_change["new"] == ["2.0"]
    assert manifest["metadata"]["WHEEL"]["changed"] is False

    result = Path(apply_delta(str(base_wheel), str(delta_path), str(out_dir)))
    assert result.name == wheel_name(version="2.0")
    contents = wheel_contents(result)
    assert set(contents) == {
        "hello/__init__.py",
        "hello/hello.py",
        "hello/new.py",
        "test-2.0.data/data/hello.dat",
        "test-2.0.dist-info/METADATA",
        "test-2.0.dist-info/WHEEL",
        "test-2.0.dist-info/RECORD",
    }
    assert b"Version: 2.0" in contents["test-2.0.dist-info/METADATA"]
    assert "test-1.0.dist-info" not in "\n".join(contents)
    assert "test-1.0.data" not in "\n".join(contents)
    assert_readable_wheel(result)


def test_delta_rejects_name_mismatch(tmp_path: Path, base_wheel: Path) -> None:
    overlay_dir = tmp_path / "overlay"
    overlay_dir.mkdir()
    overlay = build_wheel(
        overlay_dir / wheel_name(name="other"),
        {"other/__init__.py": (b"", 0o644)},
        name="other",
    )

    with pytest.raises(WheelError, match="distribution name"):
        make_delta(str(base_wheel), str(overlay), str(tmp_path / "delta"))


def test_delta_rejects_tag_mismatch(tmp_path: Path, base_wheel: Path) -> None:
    overlay_dir = tmp_path / "overlay"
    overlay_dir.mkdir()
    overlay = build_wheel(
        overlay_dir / wheel_name(python_tags=("py3", "py4")),
        OVERLAY_FILES,
        python_tags=("py3", "py4"),
    )

    with pytest.raises(WheelError, match="python tags"):
        make_delta(str(base_wheel), str(overlay), str(tmp_path / "delta"))


def test_apply_rejects_wrong_base_wheel(
    tmp_path: Path, base_wheel: Path, overlay_wheel: Path
) -> None:
    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(out_dir)))

    wrong_dir = tmp_path / "wrong"
    wrong_dir.mkdir()
    wrong_base = build_wheel(
        wrong_dir / wheel_name(),
        {**BASE_FILES, "hello/hello.py": (b"GREETING = 'tampered'\n", 0o644)},
    )
    original_listing = set(out_dir.iterdir())

    with pytest.raises(WheelError, match="file digest"):
        apply_delta(str(wrong_base), str(delta_path), str(out_dir))

    # No partial output wheel may remain
    assert set(out_dir.iterdir()) == original_listing
    assert not (out_dir / wheel_name()).exists()


def test_apply_rejects_content_tampering(
    tmp_path: Path, base_wheel: Path, overlay_wheel: Path
) -> None:
    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(out_dir)))

    # Rebuild the base wheel with one file changed but the original RECORD
    # retained (so only the per-file hash check can catch it)
    tampered_dir = tmp_path / "tampered"
    tampered_dir.mkdir()
    tampered = tampered_dir / wheel_name()
    with ZipFile(base_wheel) as zin, ZipFile(tampered, "w", ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.filename == "hello/hello.py":
                data = b"GREETING = 'tampered'\n"
            zout.writestr(item, data)

    from wheel._commands.delta import _hash_file

    tampered_digest = _hash_file(tampered)

    def patch_digest(raw: bytes) -> bytes:
        manifest = json.loads(raw)
        manifest["base"]["digest"] = tampered_digest
        return json.dumps(manifest, indent=2).encode() + b"\n"

    patched_delta = out_dir / "patched.whldelta"
    rewrite_delta(delta_path, patched_delta, manifest_transform=patch_digest)

    with pytest.raises(WheelError, match="Hash mismatch"):
        apply_delta(str(tampered), str(patched_delta), str(tmp_path / "result"))
    assert not (tmp_path / "result" / wheel_name()).exists()


def test_apply_rejects_record_manifest_mismatch(
    tmp_path: Path, base_wheel: Path, overlay_wheel: Path
) -> None:
    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(out_dir)))

    # A wheel with the same filename/identity but a regenerated RECORD
    wrong_dir = tmp_path / "wrong"
    wrong_dir.mkdir()
    wrong_base = build_wheel(
        wrong_dir / wheel_name(),
        {**BASE_FILES, "hello/hello.py": (b"GREETING = 'different'\n", 0o644)},
    )

    from wheel._commands.delta import _hash_file

    def patch_digest(raw: bytes) -> bytes:
        manifest = json.loads(raw)
        manifest["base"]["digest"] = _hash_file(wrong_base)
        return json.dumps(manifest, indent=2).encode() + b"\n"

    patched_delta = out_dir / "patched.whldelta"
    rewrite_delta(delta_path, patched_delta, manifest_transform=patch_digest)

    with pytest.raises(WheelError, match="RECORD manifest"):
        apply_delta(str(wrong_base), str(patched_delta), str(tmp_path / "result"))


def test_corrupt_delta_payload_leaves_no_output(
    tmp_path: Path, base_wheel: Path, overlay_wheel: Path
) -> None:
    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(out_dir)))

    def corrupt(data: bytes) -> bytes:
        return b"X" + data[1:]

    corrupt_delta = out_dir / "corrupt.whldelta"
    rewrite_delta(
        delta_path,
        corrupt_delta,
        payload_transforms={PAYLOAD_PREFIX + "hello/new.py": corrupt},
    )

    base_before = base_wheel.read_bytes()
    with pytest.raises(WheelError, match="corrupt"):
        apply_delta(str(base_wheel), str(corrupt_delta), str(out_dir))
    assert base_wheel.read_bytes() == base_before
    assert not (out_dir / wheel_name()).exists()
    assert not list(out_dir.glob(".whldelta-apply-*"))


def test_apply_refuses_in_place_overwrite(
    base_wheel: Path, overlay_wheel: Path, tmp_path: Path
) -> None:
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(tmp_path)))
    with pytest.raises(WheelError, match="overwrite the base wheel"):
        apply_delta(str(base_wheel), str(delta_path), str(base_wheel.parent))


def test_cli_roundtrip(tmp_path: Path, base_wheel: Path, overlay_wheel: Path) -> None:
    delta_dir = tmp_path / "deltas"
    wheel_dir = tmp_path / "wheels"
    output = run_command(
        "delta", str(base_wheel), str(overlay_wheel), "--dest-dir", delta_dir
    ).strip()
    assert output.endswith(".whldelta")
    delta_path = Path(output)
    assert delta_path.is_file()

    output = run_command(
        "apply-delta", str(base_wheel), str(delta_path), "--dest-dir", wheel_dir
    ).strip()
    assert output.endswith(".whl")
    result = Path(output)
    assert result.is_file()
    assert_readable_wheel(result)
    assert wheel_contents(result)["hello/new.py"] == b"# brand new module\n"


def test_empty_delta_roundtrips_identical_wheel(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    wheel_path = work_dir / TESTWHEEL_NAME
    wheel_path.write_bytes(TESTWHEEL_PATH.read_bytes())

    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(wheel_path), str(wheel_path), str(out_dir)))
    with ZipFile(delta_path) as zf:
        manifest = json.loads(zf.read(MANIFEST_NAME))
    assert manifest["operations"] == {"added": [], "replaced": [], "deleted": []}

    result_dir = tmp_path / "result"
    result = Path(apply_delta(str(wheel_path), str(delta_path), str(result_dir)))
    assert result.name == TESTWHEEL_NAME
    assert_readable_wheel(result)
    assert wheel_contents(result).keys() == wheel_contents(wheel_path).keys()


def test_missing_inputs_raise_wheel_error(tmp_path: Path) -> None:
    with pytest.raises(WheelError, match="Base wheel not found"):
        make_delta(str(tmp_path / "nope.whl"), str(tmp_path), str(tmp_path))
    with pytest.raises(WheelError, match="Delta file not found"):
        apply_delta(str(TESTWHEEL_PATH), str(tmp_path / "nope.whldelta"), str(tmp_path))


def test_invalid_delta_archive_is_rejected(tmp_path: Path, base_wheel: Path) -> None:
    bogus = tmp_path / "bogus.whldelta"
    with ZipFile(bogus, "w") as zf:
        zf.writestr("readme.txt", b"not a delta")

    with pytest.raises(WheelError, match="missing delta.json"):
        apply_delta(str(base_wheel), str(bogus), str(tmp_path / "out"))


def test_unsupported_delta_version_is_rejected(
    tmp_path: Path, base_wheel: Path, overlay_wheel: Path
) -> None:
    out_dir = tmp_path / "out"
    delta_path = Path(make_delta(str(base_wheel), str(overlay_wheel), str(out_dir)))

    def bump_version(raw: bytes) -> bytes:
        manifest = json.loads(raw)
        manifest["delta_version"] = DELTA_VERSION + 1
        return json.dumps(manifest).encode()

    bumped = out_dir / "bumped.whldelta"
    rewrite_delta(delta_path, bumped, manifest_transform=bump_version)

    with pytest.raises(WheelError, match="unsupported delta version"):
        apply_delta(str(base_wheel), str(bumped), str(tmp_path / "result"))
