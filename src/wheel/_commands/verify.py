"""Offline verification of wheel provenance statements."""

from __future__ import annotations

import os.path

from .._provenance import verify_provenance
from ..wheelfile import WheelFile


def verify(path: str) -> None:
    """Verify the provenance statement embedded in a wheel, fully offline.

    :param path: The path to the wheel file
    """
    with WheelFile(path) as wf:
        statement = verify_provenance(wf)

    file_count = sum(item.size is not None for item in statement.files)
    print(
        f"{os.path.basename(path)}: provenance OK "
        f"(attestation v1, {file_count} files, "
        f"built by {statement.build_tool} {statement.build_tool_version}, "
        f"tags: {','.join(statement.tags)}, time policy: {statement.time_policy})"
    )
