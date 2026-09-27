"""Command line interface for the maintainer failure-scenario tool.

Invoked separately through ``python -m wheel._failurelab``; the regular
``wheel`` CLI is untouched.  The tool only generates synthetic corpora in
(copy of, mutated) temporary locations -- it never modifies an existing wheel
and offers no retag/edit/repair operations.
"""

from __future__ import annotations

__all__ = ["main"]

import argparse
import tempfile
from collections.abc import Sequence
from pathlib import Path

from .corpus import (
    CORPUS_FORMAT_VERSION,
    SCENARIOS,
    WheelImage,
    build_seeded_image,
    write_wheel,
)
from .harness import CheckTarget, evaluate_image
from .manifest import replay_bundle, write_bundle
from .mutations import MUTATION_ORDER, MUTATIONS, apply_mutation
from .reducer import reduce_failure


def _add_source_args(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--scenario",
        choices=sorted(SCENARIOS),
        help="Name of a versioned built-in scenario",
    )
    source.add_argument(
        "--seed", type=int, help="Integer seed for deterministic corpus generation"
    )


def _source_image(
    args: argparse.Namespace,
) -> tuple[WheelImage, tuple[str, str | int, int | None]]:
    if args.scenario:
        scenario = SCENARIOS[args.scenario]
        return scenario.build(), ("scenario", scenario.name, scenario.version)

    seed = args.seed if args.seed is not None else 0
    return build_seeded_image(seed), ("seed", seed, None)


def _cmd_list(_args: argparse.Namespace) -> int:
    print(f"Corpus format version: {CORPUS_FORMAT_VERSION}")
    print("Scenarios:")
    for name in sorted(SCENARIOS):
        scenario = SCENARIOS[name]
        print(f"  {name} (v{scenario.version})\n    {scenario.description}")

    print("Mutations:")
    for name in MUTATION_ORDER:
        print(f"  {name}\n    {MUTATIONS[name].description}")

    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    image, source = _source_image(args)
    if args.mutation:
        image = apply_mutation(args.mutation, image)

    out = Path(args.out or tempfile.mkdtemp(prefix="wheel-failurelab-gen-"))
    out.mkdir(parents=True, exist_ok=True)
    mutation = MUTATIONS[args.mutation] if args.mutation else None
    byte_mutation = mutation.apply_bytes if mutation is not None else None
    path = write_wheel(image, out, byte_mutation=byte_mutation)
    source_text = (
        f"scenario {source[1]} v{source[2]}"
        if source[0] == "scenario"
        else f"seed {source[1]}"
    )
    print(f"Generated {source_text} -> {path}")
    if args.mutation:
        print(f"Mutation: {args.mutation} (exactly one declared structural change)")

    return 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    image, source = _source_image(args)
    scenario_tuple = (source[1], source[2]) if source[0] == "scenario" else None
    seed_value = source[1] if source[0] == "seed" else None

    root = Path(args.out or tempfile.mkdtemp(prefix="wheel-failurelab-fuzz-"))
    sample_dir = root / "sample"
    work_dir = root / "work"
    findings_dir = root / "findings"
    sample_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    targets = [
        CheckTarget.builtin("construct-only"),
        CheckTarget.builtin("read-all"),
    ]

    # The unmutated baseline must always be clean; a failure here would mean
    # the corpus generator itself is broken.
    baseline = evaluate_image(
        image,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        repeats=args.repeats,
        time_limit=args.time_limit,
    )
    if baseline.failed:
        print(
            "internal error: legal baseline already fails: "
            f"{', '.join(baseline.kinds)}",
        )
        return 2

    if args.mutation == "all":
        mutation_names = [
            name for name in MUTATION_ORDER if MUTATIONS[name].applies(image)
        ]
    else:
        mutation_names = [args.mutation]

    findings = 0
    for index, name in enumerate(mutation_names):
        mutated = apply_mutation(name, image)
        evaluation = evaluate_image(
            mutated,
            targets,
            sample_dir=sample_dir,
            workdir=work_dir,
            mutation_name=name,
            repeats=args.repeats,
            time_limit=args.time_limit,
        )
        if not evaluation.failed:
            continue

        findings += 1
        print(f"FINDING [{name}] kinds={','.join(evaluation.kinds)}")
        for observation in evaluation.observations:
            outcome = (
                f"accept -> {observation.return_value}"
                if observation.accepted
                else f"reject -> {observation.exception_type}: "
                f"{observation.exception_message}"
            )
            print(f"  {observation.target}#{observation.run}: {outcome}")
            for path in observation.outside_accesses:
                print(f"    outside access: {path}")

        if args.no_reduce:
            reduced_image = mutated
            reduction = None
        else:
            reduction = reduce_failure(
                image,
                name,
                evaluation,
                targets,
                sample_dir=sample_dir,
                workdir=str(work_dir),
                time_limit=args.time_limit,
            )
            reduced_image = apply_mutation(name, reduction.image)
            print(f"  reduced in {reduction.steps} attempt(s):")
            for description in reduction.accepted:
                print(f"    - {description}")

        bundle_dir = findings_dir / f"{index:02d}-{name}"
        write_bundle(
            bundle_dir,
            reduced_image,
            scenario=scenario_tuple,
            seed=seed_value,
            mutation_name=name,
            targets=targets,
            evaluation=evaluation,
            reduction=reduction,
            repeats=args.repeats,
            time_limit=args.time_limit,
            byte_mutation=MUTATIONS[name].apply_bytes,
        )
        print(f"  bundle: {bundle_dir}")

    source_text = (
        f"scenario {source[1]} v{source[2]}"
        if source[0] == "scenario"
        else f"seed {source[1]}"
    )
    print(
        f"Ran {len(mutation_names)} mutation(s) against {source_text}; "
        f"{findings} finding(s). Root: {root}"
    )
    if args.fail_on_finding and findings:
        return 1

    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    result = replay_bundle(args.bundle, workdir=args.workdir)
    print(f"Bundle: {args.bundle}")
    print(f"Mutation: {result.manifest.get('mutation')}")
    print(f"Kinds: {', '.join(result.evaluation.kinds) or 'none'}")
    print(f"Signature reproduced: {result.reproduced}")
    return 0 if result.reproduced else 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m wheel._failurelab",
        description=(
            "Generate synthetic wheel corpora, mutate them with one declared "
            "structural change, fuzz read-only check targets and reduce "
            "findings to replayable samples."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser(
        "list", help="List versioned scenarios and declared mutations"
    )
    list_parser.set_defaults(handler=_cmd_list)

    generate_parser = subparsers.add_parser(
        "generate", help="Render one legal (or single-mutation) corpus wheel"
    )
    _add_source_args(generate_parser)
    generate_parser.add_argument(
        "--mutation",
        choices=MUTATION_ORDER,
        help="Apply exactly one declared structural mutation",
    )
    generate_parser.add_argument(
        "--out", help="Output directory (default: a fresh temporary directory)"
    )
    generate_parser.set_defaults(handler=_cmd_generate)

    fuzz_parser = subparsers.add_parser(
        "fuzz", help="Run mutations through read-only targets and reduce findings"
    )
    _add_source_args(fuzz_parser)
    fuzz_parser.add_argument(
        "--mutation",
        default="all",
        choices=(*MUTATION_ORDER, "all"),
        help="Mutation to run (default: all applicable)",
    )
    fuzz_parser.add_argument(
        "--repeats", type=int, default=3, help="Runs per target (default: 3)"
    )
    fuzz_parser.add_argument(
        "--time-limit",
        type=float,
        default=2.0,
        help="Per-run wall-clock budget in seconds (default: 2.0)",
    )
    fuzz_parser.add_argument(
        "--no-reduce", action="store_true", help="Skip automatic reduction"
    )
    fuzz_parser.add_argument(
        "--fail-on-finding",
        action="store_true",
        help="Exit with status 1 when findings are produced",
    )
    fuzz_parser.add_argument(
        "--out", help="Root output directory (default: a fresh temporary directory)"
    )
    fuzz_parser.set_defaults(handler=_cmd_fuzz)

    replay_parser = subparsers.add_parser(
        "replay", help="Replay a failure bundle from its manifest"
    )
    replay_parser.add_argument(
        "bundle", help="Bundle directory containing manifest.json"
    )
    replay_parser.add_argument(
        "--workdir", help="Empty working directory (default: a fresh temp dir)"
    )
    replay_parser.set_defaults(handler=_cmd_replay)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))
