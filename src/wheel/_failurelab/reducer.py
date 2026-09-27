"""Failure-preserving sample reduction.

Given a legal baseline image, a declared mutation and the failure signature it
produces, the reducer greedily shrinks the baseline and re-applies the *same*
single mutation to every candidate.  A simplification is only kept when the
mutated result still fails with the identical signature, so the emitted sample
is guaranteed to reproduce the original finding.

Reduction dimensions, iterated to a fixed point:

* payload / dist-info **file sets** (which simultaneously drops the matching
  **RECORD rows**);
* member contents (shrunk to empty bytes);
* optional **metadata fields** in ``WHEEL`` and ``METADATA``;
* **archive structure** (compression normalization, comment removal).
"""

from __future__ import annotations

__all__ = ["Reduction", "reduce_failure"]

import copy
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Callable
from zipfile import ZIP_STORED

from .corpus import WheelImage
from .harness import CheckTarget, Evaluation, evaluate_image
from .mutations import apply_mutation, mutation_applies

#: WHEEL fields the reducer is allowed to drop; Wheel-Version stays.
_OPTIONAL_WHEEL_FIELDS = frozenset({"Generator", "Root-Is-Purelib", "Tag"})
_REQUIRED_METADATA_FIELDS = frozenset({"Metadata-Version", "Name", "Version"})


@dataclass
class Reduction:
    """Outcome of a reduction run."""

    image: WheelImage
    steps: int = 0
    accepted: list[str] = field(default_factory=list)
    passes: int = 0
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "steps": self.steps,
            "passes": self.passes,
            "accepted": self.accepted,
            "skipped_reason": self.skipped_reason,
        }


def _reproduces(
    candidate: WheelImage,
    mutation_name: str,
    signature: list[object],
    targets: Sequence[CheckTarget],
    sample_dir: str,
    workdir: str,
    time_limit: float | None,
    mem_limit_kb: int | None,
) -> bool:
    if not mutation_applies(mutation_name, candidate):
        return False

    mutated = apply_mutation(mutation_name, candidate)
    evaluation = evaluate_image(
        mutated,
        targets,
        sample_dir=sample_dir,
        workdir=workdir,
        mutation_name=mutation_name,
        repeats=1,
        time_limit=time_limit,
        mem_limit_kb=mem_limit_kb,
    )
    return evaluation.failed and evaluation.signature == signature


def reduce_failure(
    image: WheelImage,
    mutation_name: str,
    evaluation: Evaluation,
    targets: Sequence[CheckTarget],
    *,
    sample_dir: str,
    workdir: str,
    time_limit: float | None = None,
    mem_limit_kb: int | None = None,
    max_passes: int = 12,
) -> Reduction:
    """Reduce *image* while preserving *evaluation*'s failure signature.

    Every candidate is built from the legal baseline, then the single declared
    *mutation_name* is re-applied, so the reduced sample still carries exactly
    one declared mutation.
    """
    if not isinstance(evaluation, Evaluation):
        raise TypeError("evaluation must be an Evaluation instance")

    signature = evaluation.signature
    if "nondeterministic" in evaluation.kinds:
        return Reduction(
            image=copy.deepcopy(image),
            skipped_reason="nondeterministic findings cannot be reduced reliably",
        )
    if not evaluation.failed:
        return Reduction(
            image=copy.deepcopy(image), skipped_reason="no failure recorded"
        )

    current = copy.deepcopy(image)
    accepted: list[str] = []
    attempts = 0

    def reproduces(candidate: WheelImage) -> bool:
        nonlocal attempts
        attempts += 1
        return _reproduces(
            candidate,
            mutation_name,
            signature,
            targets,
            sample_dir,
            workdir,
            time_limit,
            mem_limit_kb,
        )

    def commit_if_reproduces(candidate: WheelImage, description: str) -> bool:
        if reproduces(candidate):
            accepted.append(description)
            return True

        return False

    def shrink_member_sets(prefix: str) -> bool:
        nonlocal current
        changed = False
        for collection_name in ("payload", "dist_extra"):
            for member in list(getattr(current, collection_name)):
                candidate = copy.deepcopy(current)
                collection = getattr(candidate, collection_name)
                collection.remove(
                    next(item for item in collection if item.name == member.name)
                )
                if commit_if_reproduces(
                    candidate,
                    f"{prefix}: removed {collection_name} member {member.name!r}",
                ):
                    current = candidate
                    changed = True

        return changed

    def shrink_member_data(prefix: str) -> bool:
        nonlocal current
        changed = False
        for collection_name in ("payload", "dist_extra"):
            for member in list(getattr(current, collection_name)):
                if not member.data:
                    continue

                candidate = copy.deepcopy(current)
                collection = getattr(candidate, collection_name)
                next(item for item in collection if item.name == member.name).data = b""
                if commit_if_reproduces(
                    candidate,
                    f"{prefix}: emptied {collection_name} member {member.name!r}",
                ):
                    current = candidate
                    changed = True

        return changed

    def shrink_fields(
        attr_name: str,
        metadata_name: str,
        is_optional: Callable[[str], bool],
        prefix: str,
    ) -> bool:
        nonlocal current
        changed = False
        # Positions of fields already proven non-removable in the *current*
        # layout; cleared whenever a commit shifts the layout.
        blocked: set[tuple[str, int]] = set()
        while True:
            fields = getattr(current, attr_name)
            choice: tuple[int, str] | None = None
            for index, (key, _value) in enumerate(fields):
                if is_optional(key) and (key, index) not in blocked:
                    choice = (index, key)
                    break

            if choice is None:
                return changed

            index, key = choice
            candidate = copy.deepcopy(current)
            del getattr(candidate, attr_name)[index]
            if commit_if_reproduces(
                candidate, f"{prefix}: removed {metadata_name} field {key!r}"
            ):
                current = candidate
                blocked.clear()
                changed = True
            else:
                blocked.add((key, index))

    def normalize_archive(prefix: str) -> bool:
        nonlocal current
        changed = False
        if any(member.compress_type != ZIP_STORED for member in current.payload):
            candidate = copy.deepcopy(current)
            for member in candidate.payload:
                member.compress_type = ZIP_STORED

            if commit_if_reproduces(
                candidate, f"{prefix}: normalized payload compression to stored"
            ):
                current = candidate
                changed = True

        if current.compression != ZIP_STORED:
            candidate = copy.deepcopy(current)
            candidate.compression = ZIP_STORED
            if commit_if_reproduces(
                candidate, f"{prefix}: normalized metadata compression to stored"
            ):
                current = candidate
                changed = True

        if current.comment:
            candidate = copy.deepcopy(current)
            candidate.comment = b""
            if commit_if_reproduces(candidate, f"{prefix}: removed archive comment"):
                current = candidate
                changed = True

        return changed

    passes = 0
    for passes in range(1, max_passes + 1):
        changed = False
        prefix = f"pass {passes}"
        if shrink_member_sets(prefix):
            changed = True
        if shrink_member_data(prefix):
            changed = True
        if shrink_fields(
            "wheel_fields", "WHEEL", _OPTIONAL_WHEEL_FIELDS.__contains__, prefix
        ):
            changed = True
        if shrink_fields(
            "metadata_fields",
            "METADATA",
            lambda key: key not in _REQUIRED_METADATA_FIELDS,
            prefix,
        ):
            changed = True
        if normalize_archive(prefix):
            changed = True
        if not changed:
            break

    return Reduction(
        image=current,
        steps=attempts,
        accepted=accepted,
        passes=passes,
        skipped_reason=None,
    )
