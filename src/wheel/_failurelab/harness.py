"""Run corpus samples against read-only check targets in isolation.

Each run:

* switches the process to an empty, caller-provided working directory (so any
  dependence on CWD state is observable);
* records every file the target opens, stats or lists and classifies the path
  as inside the sample directory or outside of it;
* records the verdict (accepted return value / rejected exception category),
  wall-clock duration, peak resident memory and the peak number of
  simultaneously open handles.

Repeated runs plus a pair of targets surface four failure categories:

* ``crash`` -- an exception outside the target's documented reject set;
* ``disagreement`` -- one target accepts while another rejects the same sample;
* ``nondeterministic`` -- repeated runs of one target disagree;
* ``resource`` / ``boundary`` -- a time/memory budget is exceeded or the target
  touches a path outside the sample directory.
"""

from __future__ import annotations

__all__ = [
    "CheckTarget",
    "Evaluation",
    "Observation",
    "evaluate_image",
    "evaluate_path",
    "exception_full_name",
]

import builtins
import io
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Callable

from .corpus import WheelImage, write_wheel
from .mutations import MUTATIONS
from .targets import (
    BUILTIN_TARGETS,
    DEFAULT_EXPECTED_EXCEPTIONS,
    resolve_callable,
    resolve_exception,
)

try:  # POSIX only
    import resource as _resource
except ImportError:  # pragma: no cover - Windows fallback
    _resource = None  # type: ignore[assignment]

_FAILURE_KINDS = (
    "boundary",
    "crash",
    "disagreement",
    "nondeterministic",
    "resource",
)
_RETURN_REPR_LIMIT = 300


def exception_full_name(exc: BaseException) -> str:
    """Return ``"module.QualifiedName"`` for an exception instance."""
    exc_type = type(exc)
    return f"{exc_type.__module__}.{exc_type.__qualname__}"


@dataclass
class CheckTarget:
    """An injectable, read-only check target."""

    label: str
    spec: str
    expected: tuple[str, ...] = DEFAULT_EXPECTED_EXCEPTIONS
    #: Optional pre-resolved callable (used by tests embedding local targets).
    callable: Callable[[str], object] | None = field(default=None, repr=False)

    @classmethod
    def builtin(
        cls, label: str, expected: tuple[str, ...] | None = None
    ) -> CheckTarget:
        if label not in BUILTIN_TARGETS:
            available = ", ".join(sorted(BUILTIN_TARGETS))
            raise KeyError(f"Unknown built-in target {label!r}. Available: {available}")

        return cls(
            label=label,
            spec=BUILTIN_TARGETS[label],
            expected=expected or DEFAULT_EXPECTED_EXCEPTIONS,
        )

    @classmethod
    def from_callable(
        cls,
        label: str,
        func: Callable[[str], Any],
        expected: tuple[str, ...] = DEFAULT_EXPECTED_EXCEPTIONS,
    ) -> CheckTarget:
        spec = f"{func.__module__}:{func.__qualname__}"
        return cls(label=label, spec=spec, expected=expected, callable=func)

    def resolve(self) -> tuple[Callable[[str], object], frozenset[str]]:
        func = self.callable or resolve_callable(self.spec)
        expected_names = set(self.expected)
        # Validate that every expected exception spec imports, but match by
        # full name so an in-process target stays comparable across replays.
        for spec in self.expected:
            resolve_exception(spec)

        return func, frozenset(expected_names)

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "spec": self.spec, "expected": list(self.expected)}


class _TrackedHandle:
    """File object wrapper counting concurrently open handles."""

    def __init__(self, raw: object, recorder: _AccessRecorder) -> None:
        self._raw = raw
        self._recorder = recorder
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._recorder._handle_closed()
        self._raw.close()

    def __enter__(self) -> _TrackedHandle:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.close()
        return False

    def __getattr__(self, item: str) -> object:
        return getattr(self._raw, item)


class _AccessRecorder:
    """Records filesystem accesses while installed, inside an empty CWD."""

    def __init__(self, sample_root: str, workdir: str) -> None:
        self._sample_root = os.path.abspath(sample_root)
        self._workdir = os.path.abspath(workdir)
        self._sample_accesses: set[str] = set()
        self._outside_accesses: set[str] = set()
        self._open_handles = 0
        self.peak_open_handles = 0
        self._saved: dict[str, object] = {}
        self._installed = False

    def install(self) -> _AccessRecorder:
        self._saved = {
            "builtins_open": builtins.open,
            "io_open": io.open,
            "stat": os.stat,
            "lstat": os.lstat,
            "listdir": os.listdir,
            "scandir": os.scandir,
        }
        # ``io.open`` is a distinct module attribute from ``builtins.open`` and
        # zipfile resolves the file opener through the io module, so patch both.
        builtins.open = self._open  # type: ignore[assignment]
        io.open = self._open  # type: ignore[assignment]
        os.stat = self._stat  # type: ignore[assignment]
        os.lstat = self._lstat  # type: ignore[assignment]
        os.listdir = self._listdir  # type: ignore[assignment]
        os.scandir = self._scandir  # type: ignore[assignment]
        self._installed = True
        return self

    def restore(self) -> None:
        if not self._installed:
            return

        builtins.open = self._saved["builtins_open"]
        io.open = self._saved["io_open"]
        os.stat = self._saved["stat"]
        os.lstat = self._saved["lstat"]
        os.listdir = self._saved["listdir"]
        os.scandir = self._saved["scandir"]
        self._installed = False

    def _handle_closed(self) -> None:
        self._open_handles -= 1

    def _record(self, path: str) -> None:
        absolute = os.path.abspath(path)
        try:
            inside = (
                os.path.commonpath([absolute, self._sample_root]) == self._sample_root
            )
        except ValueError:
            inside = False

        if inside:
            self._sample_accesses.add(absolute)
        else:
            self._outside_accesses.add(absolute)

    def _open(
        self,
        file: str | os.PathLike[str] | int,
        mode: str = "r",
        *args: object,
        **kwargs: object,
    ) -> object:
        opener = self._saved["builtins_open"]
        if isinstance(file, (str, os.PathLike)):
            self._record(os.fspath(file))
            raw = opener(file, mode, *args, **kwargs)
            self._open_handles += 1
            self.peak_open_handles = max(self.peak_open_handles, self._open_handles)
            return _TrackedHandle(raw, self)

        return opener(file, mode, *args, **kwargs)

    def _stat(
        self,
        path: str | os.PathLike[str] | int,
        *args: object,
        **kwargs: object,
    ) -> object:
        if isinstance(path, (str, os.PathLike)):
            self._record(os.fspath(path))

        return self._saved["stat"](path, *args, **kwargs)

    def _lstat(
        self,
        path: str | os.PathLike[str] | int,
        *args: object,
        **kwargs: object,
    ) -> object:
        if isinstance(path, (str, os.PathLike)):
            self._record(os.fspath(path))

        return self._saved["lstat"](path, *args, **kwargs)

    def _listdir(
        self, path: str | os.PathLike[str] = ".", *args: object, **kwargs: object
    ) -> object:
        self._record(os.fspath(path))
        return self._saved["listdir"](path, *args, **kwargs)

    def _scandir(
        self, path: str | os.PathLike[str] = ".", *args: object, **kwargs: object
    ) -> object:
        self._record(os.fspath(path))
        return self._saved["scandir"](path, *args, **kwargs)

    @property
    def sample_accesses(self) -> list[str]:
        return sorted(self._sample_accesses)

    @property
    def outside_accesses(self) -> list[str]:
        return sorted(self._outside_accesses)


def _maxrss_kb() -> int | None:
    if _resource is None:
        return None

    usage = _resource.getrusage(_resource.RUSAGE_SELF)
    return int(usage.ru_maxrss)


@dataclass
class Observation:
    """Result of a single target run."""

    target: str
    run: int
    accepted: bool
    return_value: str | None
    exception_type: str | None
    exception_message: str | None
    duration: float
    maxrss_kb: int | None
    sample_accesses: list[str]
    outside_accesses: list[str]
    peak_open_handles: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "run": self.run,
            "accepted": self.accepted,
            "return_value": self.return_value,
            "exception_type": self.exception_type,
            "exception_message": self.exception_message,
            "duration": round(self.duration, 6),
            "maxrss_kb": self.maxrss_kb,
            "sample_accesses": self.sample_accesses,
            "outside_accesses": self.outside_accesses,
            "peak_open_handles": self.peak_open_handles,
        }


@dataclass
class Evaluation:
    """Aggregated result of running one sample through all targets."""

    failed: bool
    kinds: list[str]
    signature: list[Any]
    observations: list[Observation]

    def to_dict(self) -> dict[str, Any]:
        return {
            "failed": self.failed,
            "kinds": self.kinds,
            "signature": self.signature,
            "observations": [item.to_dict() for item in self.observations],
        }


def _run_once(
    target: CheckTarget,
    run_index: int,
    wheel_path: str,
    sample_root: str,
    workdir: str,
) -> Observation:
    func, _expected_names = target.resolve()
    recorder = _AccessRecorder(sample_root=sample_root, workdir=workdir)
    previous_cwd = os.getcwd()
    os.chdir(workdir)
    accepted = False
    value_repr: str | None = None
    exc_type: str | None = None
    exc_message: str | None = None
    start = time.perf_counter()
    try:
        recorder.install()
        try:
            result = func(wheel_path)
        except Exception as exc:  # every exception category is recorded
            exc_type = exception_full_name(exc)
            exc_message = str(exc).splitlines()[0] if str(exc) else ""
        else:
            accepted = True
            value_repr = repr(result)[:_RETURN_REPR_LIMIT]
    finally:
        recorder.restore()
        os.chdir(previous_cwd)

    duration = time.perf_counter() - start
    return Observation(
        target=target.label,
        run=run_index,
        accepted=accepted,
        return_value=value_repr,
        exception_type=exc_type,
        exception_message=exc_message,
        duration=duration,
        maxrss_kb=_maxrss_kb(),
        sample_accesses=recorder.sample_accesses,
        outside_accesses=recorder.outside_accesses,
        peak_open_handles=recorder.peak_open_handles,
    )


def _build_signature(
    observations: Sequence[Observation],
) -> list[Any]:
    # Pure lists/tuples-of-literals normalized to JSON lists so that an
    # in-memory signature compares equal to one loaded from a manifest.
    by_target: dict[str, set[tuple[bool, str | None]]] = {}
    for obs in observations:
        by_target.setdefault(obs.target, set()).add((obs.accepted, obs.exception_type))

    target_part = [
        [label, [list(outcome) for outcome in sorted(outcomes)]]
        for label, outcomes in sorted(by_target.items())
    ]
    return [[], target_part]  # kinds filled in by caller


def evaluate_path(
    wheel_path: str | os.PathLike[str],
    targets: Sequence[CheckTarget],
    *,
    workdir: str | os.PathLike[str],
    repeats: int = 3,
    time_limit: float | None = None,
    mem_limit_kb: int | None = None,
) -> Evaluation:
    """Run an existing wheel file through *targets* and aggregate findings."""
    if repeats < 1:
        raise ValueError("repeats must be >= 1")

    absolute_wheel = os.path.abspath(os.fspath(wheel_path))
    sample_root = os.path.dirname(absolute_wheel)
    workdir_path = os.path.abspath(os.fspath(workdir))
    if not os.path.isdir(workdir_path):
        raise FileNotFoundError(f"workdir does not exist: {workdir_path}")

    observations: list[Observation] = []
    for target in targets:
        for run_index in range(repeats):
            observations.append(
                _run_once(target, run_index, absolute_wheel, sample_root, workdir_path)
            )

    kinds: set[str] = set()

    # Crashes: exception category outside the target's documented reject set.
    for target in targets:
        _, expected_names = target.resolve()
        for obs in observations:
            if (
                obs.target == target.label
                and obs.exception_type is not None
                and obs.exception_type not in expected_names
            ):
                kinds.add("crash")

    # Non-determinism: repeated verdicts for the same target differ.
    by_target: dict[str, set[tuple[bool, str | None]]] = {}
    for obs in observations:
        by_target.setdefault(obs.target, set()).add((obs.accepted, obs.exception_type))

    if any(len(outcomes) > 1 for outcomes in by_target.values()):
        kinds.add("nondeterministic")

    # Disagreement: accept verdicts differ between targets.
    accepted_values = {obs.accepted for obs in observations}
    if len(accepted_values) > 1:
        kinds.add("disagreement")

    # Boundary: any access outside the sample directory.
    if any(obs.outside_accesses for obs in observations):
        kinds.add("boundary")

    # Resource budgets.
    for obs in observations:
        if time_limit is not None and obs.duration > time_limit:
            kinds.add("resource")

        if mem_limit_kb is not None and (
            obs.maxrss_kb is None or obs.maxrss_kb > mem_limit_kb
        ):
            kinds.add("resource")

    ordered_kinds = [kind for kind in _FAILURE_KINDS if kind in kinds]
    signature = _build_signature(observations)
    signature[0] = ordered_kinds
    return Evaluation(
        failed=bool(ordered_kinds),
        kinds=ordered_kinds,
        signature=signature,
        observations=observations,
    )


def evaluate_image(
    image: WheelImage,
    targets: Sequence[CheckTarget],
    *,
    sample_dir: str | os.PathLike[str],
    workdir: str | os.PathLike[str],
    mutation_name: str | None = None,
    repeats: int = 3,
    time_limit: float | None = None,
    mem_limit_kb: int | None = None,
) -> Evaluation:
    """Materialize *image* (optionally with one declared mutation) and evaluate it."""
    byte_mutation = None
    if mutation_name is not None:
        mutation = MUTATIONS[mutation_name]
        if mutation.apply_bytes is not None:
            byte_mutation = mutation.apply_bytes

    path = write_wheel(image, sample_dir, byte_mutation=byte_mutation)
    return evaluate_path(
        path,
        targets,
        workdir=workdir,
        repeats=repeats,
        time_limit=time_limit,
        mem_limit_kb=mem_limit_kb,
    )
