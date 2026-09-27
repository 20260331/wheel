"""Format-aware failure scenario tooling for wheel maintainers.

This private subpackage generates *synthetic* wheel corpora from versioned
scenarios or integer seeds, applies a single declared structural mutation to a
legal baseline, runs the result through injectable read-only check targets and
reduces any failure to a minimal, replayable sample.

Scope and non-goals
-------------------

* Only newly generated, temporary corpus files are ever touched.  The tool
  never opens an existing wheel in order to modify it.
* It deliberately provides **no** retagging, metadata editing or wheel
  repairing capability.
* The regular ``wheel`` command line interface and :class:`wheel.WheelFile`
  behavior are completely unaffected; the tool is invoked separately through
  ``python -m wheel._failurelab``.
"""

from __future__ import annotations

from .corpus import (
    CORPUS_FORMAT_VERSION,
    SCENARIOS,
    Member,
    WheelImage,
    build_scenario_image,
    build_seeded_image,
    render_wheel,
    wheel_filename,
    write_wheel,
)
from .harness import CheckTarget, Evaluation, Observation, evaluate_image, evaluate_path
from .manifest import load_bundle, replay_bundle, write_bundle
from .mutations import MUTATION_ORDER, MUTATIONS, apply_mutation, mutation_applies
from .reducer import Reduction, reduce_failure
from .targets import BUILTIN_TARGETS, resolve_callable

__all__ = [
    "BUILTIN_TARGETS",
    "CORPUS_FORMAT_VERSION",
    "MUTATIONS",
    "MUTATION_ORDER",
    "SCENARIOS",
    "CheckTarget",
    "Evaluation",
    "Member",
    "Observation",
    "Reduction",
    "WheelImage",
    "apply_mutation",
    "build_scenario_image",
    "build_seeded_image",
    "evaluate_image",
    "evaluate_path",
    "load_bundle",
    "mutation_applies",
    "reduce_failure",
    "render_wheel",
    "replay_bundle",
    "resolve_callable",
    "wheel_filename",
    "write_bundle",
    "write_wheel",
]
