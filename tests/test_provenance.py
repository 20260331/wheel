from __future__ import annotations

import csv
import hashlib
from io import StringIO

import pytest

from wheel._provenance import (
    ATTESTATION_VERSION,
    ProvenanceFile,
    _canonical_body,
    build_provenance,
    current_time_policy,
    parse_provenance,
    validate_arcname,
)
from wheel.wheelfile import WheelError, urlsafe_b64encode

DIST_INFO = "foo-1.0.dist-info"
PROVENANCE_PATH = f"{DIST_INFO}/PROVENANCE"
RECORD_PATH = f"{DIST_INFO}/RECORD"


def digest_for(data: bytes) -> tuple[str, int]:
    digest = urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii")
    return f"sha256={digest}", len(data)


def make_body(rows: list[tuple[str, str, str]] | None = None) -> str:
    if rows is None:
        rows = [
            ("foo/__init__.py", *digest_for(b"")),
            (PROVENANCE_PATH, "", ""),
        ]

    buffer = StringIO()
    writer = csv.writer(buffer, delimiter=",", quotechar='"', lineterminator="\n")
    for row in rows:
        writer.writerow(row)

    return buffer.getvalue()


def make_statement(
    headers: dict[str, list[str]] | None = None,
    body: str | None = None,
    *,
    input_digest: str | None = None,
) -> bytes:
    body = body if body is not None else make_body()
    if input_digest is None:
        raw = hashlib.sha256(body.encode("utf-8")).digest()
        input_digest = "sha256=" + urlsafe_b64encode(raw).decode("ascii")

    default_headers: dict[str, list[str]] = {
        "Attestation-Version": [ATTESTATION_VERSION],
        "Build-Tool": ["wheel"],
        "Build-Tool-Version": ["0.48.0"],
        "Build-Input-Digest": [input_digest],
        "Tag": ["py3-none-any"],
        "Time-Policy": ["mtime"],
    }
    if headers is not None:
        default_headers.update(headers)

    lines: list[str] = []
    for key, values in default_headers.items():
        lines.extend(f"{key}: {value}" for value in values)

    return ("\n".join(lines) + "\n\n" + body).encode("utf-8")


def parse(data: bytes) -> object:
    return parse_provenance(
        data, provenance_path=PROVENANCE_PATH, record_path=RECORD_PATH
    )


@pytest.mark.parametrize(
    "path",
    [
        "foo/__init__.py",
        "foo-1.0.data/data/hello.dat",
        "foo/bar.baz-qux/module.py",
        "foo.pyd",
    ],
)
def test_validate_arcname_accepts(path: str) -> None:
    validate_arcname(path)


@pytest.mark.parametrize(
    "path",
    [
        "",
        "../evil",
        "foo/../../evil",
        "/etc/passwd",
        "foo//bar",
        "foo/./bar",
        "foo/bar/",
        "..",
        "foo\\bar",
        "C:/Windows/win.ini",
        "foo\x00bar",
    ],
)
def test_validate_arcname_rejects(path: str) -> None:
    with pytest.raises(WheelError):
        validate_arcname(path)


def test_build_and_parse_roundtrip() -> None:
    files = {
        "foo/__init__.py": digest_for(b""),
        "foo/module.py": digest_for(b"value = 1\n"),
    }
    data = build_provenance(
        dist_info_path=DIST_INFO,
        file_digests=files,
        tags=["py3-none-any", "py2-none-any"],
    )
    statement = parse(data)

    assert statement.build_tool == "wheel"
    assert statement.build_tool_version == "0.48.0"
    assert statement.tags == ("py2-none-any", "py3-none-any")
    assert statement.time_policy == current_time_policy()
    assert {item.path for item in statement.files} == {
        "foo/__init__.py",
        "foo/module.py",
        PROVENANCE_PATH,
    }
    self_row = next(item for item in statement.files if item.path == PROVENANCE_PATH)
    assert self_row.digest == ""
    assert self_row.size is None


def test_build_rejects_invalid_tags() -> None:
    with pytest.raises(WheelError, match="Invalid compatibility tag"):
        build_provenance(dist_info_path=DIST_INFO, file_digests={}, tags=["py3-none"])

    with pytest.raises(WheelError, match="without compatibility tags"):
        build_provenance(dist_info_path=DIST_INFO, file_digests={}, tags=[])


def test_unknown_field_fails() -> None:
    data = make_statement(headers={"X-Evil": ["1"]})
    with pytest.raises(WheelError, match="Unknown or untrusted provenance field"):
        parse(data)


def test_unsupported_version_fails() -> None:
    data = make_statement(headers={"Attestation-Version": ["2"]})
    with pytest.raises(WheelError, match="Unsupported attestation version"):
        parse(data)


def test_duplicate_scalar_field_fails() -> None:
    data = make_statement(headers={"Time-Policy": ["mtime", "mtime"]})
    with pytest.raises(WheelError, match="Duplicate Time-Policy"):
        parse(data)


def test_duplicate_tag_value_fails() -> None:
    data = make_statement(headers={"Tag": ["py3-none-any", "py3-none-any"]})
    with pytest.raises(WheelError, match="Duplicate Tag value"):
        parse(data)


def test_missing_required_field_fails() -> None:
    data = make_statement(headers={"Time-Policy": []})
    with pytest.raises(WheelError, match="Missing required field"):
        parse(data)


def test_missing_tag_fails() -> None:
    data = make_statement(headers={"Tag": []})
    with pytest.raises(WheelError, match="does not declare any compatibility tags"):
        parse(data)


def test_invalid_tag_fails() -> None:
    data = make_statement(headers={"Tag": ["py3-none"]})
    with pytest.raises(WheelError, match="Invalid compatibility tag"):
        parse(data)


def test_invalid_digest_fails() -> None:
    data = make_statement(headers={"Build-Input-Digest": ["md5=abcd"]})
    with pytest.raises(WheelError, match="Invalid or unsupported digest"):
        parse(data)


def test_invalid_time_policy_fails() -> None:
    data = make_statement(headers={"Time-Policy": ["yesterday"]})
    with pytest.raises(WheelError, match="Invalid time policy"):
        parse(data)


def test_input_digest_mismatch_fails() -> None:
    body = make_body(
        [
            ("foo/__init__.py", *digest_for(b"")),
            (PROVENANCE_PATH, "", ""),
        ]
    )
    data = make_statement(body=body, input_digest="sha256=" + "A" * 43)
    with pytest.raises(WheelError, match="Build input digest does not match"):
        parse(data)


def test_missing_manifest_section_fails() -> None:
    data = b"Attestation-Version: 1\n"
    with pytest.raises(WheelError, match="missing the manifest section"):
        parse(data)


@pytest.mark.parametrize(
    "rows, message",
    [
        pytest.param(
            [("foo/__init__.py", *digest_for(b""))],
            "must reference",
            id="missing-self-row",
        ),
        pytest.param(
            [
                ("foo/__init__.py", *digest_for(b"")),
                (PROVENANCE_PATH, "sha256=" + "A" * 43, "10"),
            ],
            "self-reference",
            id="self-row-with-hash",
        ),
        pytest.param(
            [
                ("foo/__init__.py", "", ""),
                (PROVENANCE_PATH, "", ""),
            ],
            "Missing hash",
            id="empty-hash",
        ),
        pytest.param(
            [
                ("foo/__init__.py", *digest_for(b"")),
                (PROVENANCE_PATH, "", ""),
                (RECORD_PATH, "", ""),
            ],
            "RECORD must not be listed",
            id="record-row",
        ),
        pytest.param(
            [
                ("foo/__init__.py", *digest_for(b"")),
                ("foo/__init__.py", *digest_for(b"")),
                (PROVENANCE_PATH, "", ""),
            ],
            "Duplicate manifest entry",
            id="duplicate-path",
        ),
        pytest.param(
            [
                ("../evil", *digest_for(b"")),
                (PROVENANCE_PATH, "", ""),
            ],
            "Unsafe path",
            id="malicious-path",
        ),
    ],
)
def test_manifest_validation(rows: list[tuple[str, str, str]], message: str) -> None:
    body = make_body(rows)
    data = make_statement(body=body)
    with pytest.raises(WheelError, match=message):
        parse(data)


def test_malformed_row_fails() -> None:
    body = "foo/__init__.py,sha256=abc\n"
    data = make_statement(body=body)
    with pytest.raises(WheelError, match="Malformed row"):
        parse(data)


def test_self_row_canonical_form() -> None:
    digest, size = digest_for(b"")
    body = _canonical_body(
        [
            ProvenanceFile(PROVENANCE_PATH, "", None),
            ProvenanceFile("foo/__init__.py", digest, size),
        ]
    )
    # The self-reference is sorted alongside the other rows ("-" sorts before
    # "/").
    lines = body.splitlines()
    assert lines[0] == f"{PROVENANCE_PATH},,"
    assert lines[1] == f"foo/__init__.py,{digest},{size}"
