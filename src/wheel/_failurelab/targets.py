"""Built-in read-only check targets and import-spec resolution.

A check target is any callable ``target(path: str) -> object``: it receives the
absolute path of a wheel file and returns an arbitrary JSON-ish value when it
*accepts* the sample, or raises when it *rejects* it.  Targets are expected to
be strictly read-only; the harness enforces an empty working directory and a
file-access boundary around them.
"""

from __future__ import annotations

__all__ = [
    "BUILTIN_TARGETS",
    "construct_only",
    "read_all_files",
    "resolve_callable",
    "resolve_exception",
]

import importlib
from typing import Callable

from ..wheelfile import WheelFile

#: Label -> import spec.  ``WheelError`` is the documented, expected rejection
#: category for both built-in targets.
BUILTIN_TARGETS: dict[str, str] = {
    "construct-only": "wheel._failurelab.targets:construct_only",
    "read-all": "wheel._failurelab.targets:read_all_files",
}

DEFAULT_EXPECTED_EXCEPTIONS: tuple[str, ...] = ("wheel.wheelfile.WheelError",)


def construct_only(path: str) -> int:
    """Accept when a :class:`WheelFile` can be constructed and closed."""
    with WheelFile(path) as wf:
        return len(wf.infolist())


def read_all_files(path: str) -> int:
    """Accept when every archived member can be opened and fully read.

    This exercises RECORD hash verification for every member, unlike the
    constructor-only target.
    """
    with WheelFile(path) as wf:
        count = 0
        for info in wf.infolist():
            if info.is_dir():
                continue

            with wf.open(info) as handle:
                handle.read()

            count += 1

        return count


def _resolve(spec: str) -> object:
    """Resolve ``"module:attr.path"`` or a dotted ``"module.Attr"`` spec."""
    candidates: list[tuple[str, str]] = []
    if ":" in spec:
        module_name, _, attribute_path = spec.partition(":")
        candidates.append((module_name, attribute_path))
    else:
        parts = spec.split(".")
        for split in range(len(parts) - 1, 0, -1):
            candidates.append((".".join(parts[:split]), ".".join(parts[split:])))

    for module_name, attribute_path in candidates:
        if not module_name or not attribute_path:
            continue

        try:
            obj: object = importlib.import_module(module_name)
        except ImportError:
            continue

        try:
            for part in attribute_path.split("."):
                obj = getattr(obj, part)
        except AttributeError:
            continue

        return obj

    raise ValueError(f"could not resolve import spec {spec!r}")


def resolve_callable(spec: str) -> Callable[..., object]:
    """Resolve ``"module:attr.path"`` to a callable."""
    obj = _resolve(spec)
    if not callable(obj):
        raise TypeError(f"target spec {spec!r} did not resolve to a callable")

    return obj


def resolve_exception(spec: str) -> type[BaseException]:
    """Resolve ``"module:ExceptionName"`` to an exception class."""
    obj = _resolve(spec)
    if not isinstance(obj, type) or not issubclass(obj, BaseException):
        raise TypeError(f"spec {spec!r} did not resolve to an exception class")

    return obj
