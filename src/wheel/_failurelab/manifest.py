"""Self-contained failure bundles and replay.

A bundle directory contains the reduced wheel and a ``manifest.json`` that
records everything required to reproduce the finding without network access, a
build backend or any particular working directory:

* the originating versioned scenario or integer seed and mutation name;
* the import specs of the check targets and their expected reject categories;
* the failure signature and all recorded observations;
* the reduction log.

Replay resolves the targets by import spec, runs inside a fresh empty working
directory and compares the freshly observed signature against the manifest.
"""

from __future__ import annotations

__all__ = [
    "MANIFEST_NAME",
    "SAMPLE_DIR_NAME",
    "ReplayResult",
    "load_bundle",
    "replay_bundle",
    "write_bundle",
]

import json
import os
import platform
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .corpus import WheelImage, render_wheel
from .harness import CheckTarget, Evaluation, evaluate_path
from .mutations import SCHEMA_VERSION
from .reducer import Reduction

MANIFEST_NAME = "manifest.json"
SAMPLE_DIR_NAME = "sample"
_BUNDLE_FORMAT_VERSION = 1


@dataclass
class ReplayResult:
    """Result of replaying a persisted bundle."""

    reproduced: bool
    evaluation: Evaluation
    manifest: dict[str, Any]
    workdir: str


def _source_descriptor(
    scenario: tuple[str, int] | None, seed: int | None
) -> dict[str, Any]:
    if scenario is not None:
        return {"kind": "scenario", "name": scenario[0], "version": scenario[1]}

    return {"kind": "seed", "seed": seed if seed is not None else 0}


def write_bundle(
    out_dir: str | os.PathLike[str],
    image: WheelImage,
    *,
    scenario: tuple[str, int] | None = None,
    seed: int | None = None,
    mutation_name: str | None,
    targets: Sequence[CheckTarget],
    evaluation: Evaluation,
    reduction: Reduction | None = None,
    repeats: int = 3,
    time_limit: float | None = None,
    mem_limit_kb: int | None = None,
    byte_mutation: Callable[[bytes], bytes] | None = None,
) -> Path:
    """Write the reduced wheel and its manifest into *out_dir*.

    The wheel bytes are persisted (not just the spec) so replay exercises the
    exact bytes that triggered the finding.
    """
    bundle = Path(out_dir)
    sample_dir = bundle / SAMPLE_DIR_NAME
    sample_dir.mkdir(parents=True, exist_ok=True)

    wheel_name = image.filename_override or None
    if wheel_name is None:
        from .corpus import wheel_filename

        wheel_name = wheel_filename(image)

    data = render_wheel(image)
    if byte_mutation is not None:
        data = byte_mutation(data)

    sample_path = sample_dir / wheel_name
    sample_path.write_bytes(data)

    manifest: dict[str, Any] = {
        "bundle_format_version": _BUNDLE_FORMAT_VERSION,
        "schema_version": SCHEMA_VERSION,
        "source": _source_descriptor(scenario, seed),
        "mutation": mutation_name,
        "targets": [target.to_dict() for target in targets],
        "limits": {
            "repeats": repeats,
            "time_limit": time_limit,
            "mem_limit_kb": mem_limit_kb,
        },
        "wheel_file": f"{SAMPLE_DIR_NAME}/{wheel_name}",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "evaluation": evaluation.to_dict(),
        "reduction": reduction.to_dict() if reduction is not None else None,
        "replay_requirements": {
            "network": False,
            "build_backend": False,
            "cwd_state": False,
        },
    }
    manifest_path = bundle / MANIFEST_NAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest_path


def load_bundle(bundle_dir: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and return the manifest from *bundle_dir*."""
    manifest_path = Path(bundle_dir) / MANIFEST_NAME
    with manifest_path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    wheel_path = Path(bundle_dir) / manifest["wheel_file"]
    if not wheel_path.is_file():
        raise FileNotFoundError(f"bundled wheel missing: {wheel_path}")

    return manifest


def _targets_from_manifest(manifest: dict[str, Any]) -> list[CheckTarget]:
    targets = []
    for item in manifest["targets"]:
        targets.append(
            CheckTarget(
                label=item["label"],
                spec=item["spec"],
                expected=tuple(item.get("expected", ())),
            )
        )

    return targets


def replay_bundle(
    bundle_dir: str | os.PathLike[str],
    *,
    workdir: str | os.PathLike[str] | None = None,
) -> ReplayResult:
    """Re-run a bundle's wheel through its targets in an empty working dir.

    Returns a :class:`ReplayResult`; ``reproduced`` is true when the observed
    failure signature equals the one recorded in the manifest.
    """
    bundle_dir = Path(bundle_dir)
    manifest = load_bundle(bundle_dir)
    wheel_path = bundle_dir / manifest["wheel_file"]
    targets = _targets_from_manifest(manifest)
    limits = manifest.get("limits", {})

    created_workdir = False
    if workdir is None:
        workdir = tempfile.mkdtemp(prefix="failurelab-replay-")
        created_workdir = True
    else:
        workdir = os.fspath(workdir)
        os.makedirs(workdir, exist_ok=True)
        if os.listdir(workdir):
            raise ValueError(f"replay workdir must be empty: {workdir}")

    try:
        evaluation = evaluate_path(
            wheel_path,
            targets,
            workdir=workdir,
            repeats=int(limits.get("repeats", 1)),
            time_limit=limits.get("time_limit"),
            mem_limit_kb=limits.get("mem_limit_kb"),
        )
    finally:
        if created_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    expected_signature = manifest["evaluation"]["signature"]
    return ReplayResult(
        reproduced=evaluation.signature == expected_signature,
        evaluation=evaluation,
        manifest=manifest,
        workdir="" if created_workdir else workdir,
    )
