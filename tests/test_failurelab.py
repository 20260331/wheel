from __future__ import annotations

import argparse
import json
import os
import time
import zipfile
from pathlib import Path

import pytest

import wheel._failurelab as failurelab_pkg
from wheel._failurelab import (
    CORPUS_FORMAT_VERSION,
    MUTATION_ORDER,
    MUTATIONS,
    SCENARIOS,
    CheckTarget,
    WheelImage,
    apply_mutation,
    build_scenario_image,
    build_seeded_image,
    evaluate_image,
    load_bundle,
    mutation_applies,
    reduce_failure,
    render_wheel,
    replay_bundle,
    wheel_filename,
    write_bundle,
    write_wheel,
)
from wheel._failurelab.cli import main as failurelab_main
from wheel._failurelab.harness import Evaluation, evaluate_path
from wheel._failurelab.targets import construct_only, read_all_files
from wheel.wheelfile import WheelError, WheelFile


@pytest.fixture
def targets() -> list[CheckTarget]:
    return [CheckTarget.builtin("construct-only"), CheckTarget.builtin("read-all")]


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    sample_dir = tmp_path / "sample"
    work_dir = tmp_path / "work"
    sample_dir.mkdir()
    work_dir.mkdir()
    return sample_dir, work_dir


# ---------------------------------------------------------------------------
# Corpus generation
# ---------------------------------------------------------------------------


def test_scenarios_are_versioned_and_legal(
    targets: list[CheckTarget], dirs: tuple[Path, Path]
) -> None:
    sample_dir, work_dir = dirs
    for name, scenario in sorted(SCENARIOS.items()):
        assert scenario.version == CORPUS_FORMAT_VERSION
        image = scenario.build()
        evaluation = evaluate_image(
            image,
            targets,
            sample_dir=sample_dir,
            workdir=work_dir,
            repeats=1,
        )
        assert not evaluation.failed, (name, evaluation.kinds)


def test_rendered_baseline_passes_wheelfile_hash_checks(tmp_path: Path) -> None:
    for name in SCENARIOS:
        target_dir = tmp_path / name
        target_dir.mkdir()
        path = write_wheel(build_scenario_image(name), target_dir)
        with WheelFile(path) as wf:
            assert wf.testzip() is None


def test_seeded_corpus_is_legal_and_deterministic(
    targets: list[CheckTarget],
    dirs: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample_dir, work_dir = dirs
    first = render_wheel(build_seeded_image(1234))

    # Rendering must ignore the wall clock / SOURCE_DATE_EPOCH and CWD.
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1000000000")
    monkeypatch.chdir(work_dir)
    second = render_wheel(build_seeded_image(1234))
    assert first == second

    third = render_wheel(build_seeded_image(1235))
    assert first != third

    for seed in range(30):
        evaluation = evaluate_image(
            build_seeded_image(seed),
            targets,
            sample_dir=sample_dir,
            workdir=work_dir,
            repeats=1,
        )
        assert not evaluation.failed, (seed, evaluation.kinds)


def test_wheel_zip_metadata_is_fixed_and_zip64_safe(tmp_path: Path) -> None:
    path = write_wheel(build_seeded_image(7), tmp_path)
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------


def test_every_mutation_is_declared_and_single_flavored() -> None:
    assert tuple(MUTATIONS) == MUTATION_ORDER
    for name, mutation in MUTATIONS.items():
        assert mutation.name == name
        flavors = [mutation.apply_image, mutation.apply_bytes]
        assert flavors.count(None) == 1  # exactly one flavor each
        assert mutation.description


def test_mutations_are_pure_and_deterministic() -> None:
    for name in MUTATION_ORDER:
        baseline = build_seeded_image(9)
        if not mutation_applies(name, baseline):
            with pytest.raises(ValueError):
                apply_mutation(name, baseline)
            continue

        mutated_a = apply_mutation(name, baseline)
        mutated_b = apply_mutation(name, baseline)
        # The baseline image is never mutated in place.
        assert render_wheel(baseline) == render_wheel(build_seeded_image(9))
        # Repeated application to the same baseline is deterministic.
        assert _rendered(name, mutated_a) == _rendered(name, mutated_b)
        # Exactly one declared change is present: either the archive bytes
        # differ, or (for the filename-only mutation) the output name differs.
        if name == "distinfo-filename-mismatch":
            assert (
                mutated_a.filename_override is not None
                and mutated_a.filename_override != wheel_filename(baseline)
            )
            assert _rendered(name, mutated_a) == render_wheel(build_seeded_image(9))
        else:
            assert _rendered(name, mutated_a) != render_wheel(build_seeded_image(9))


def _rendered(name: str, image: WheelImage) -> bytes:
    data = render_wheel(image)
    byte_fn = MUTATIONS[name].apply_bytes
    return byte_fn(data) if byte_fn is not None else data


@pytest.mark.parametrize(
    "mutation_name,expected_kind",
    [
        ("record-malformed-row", "crash"),
        ("archive-truncated", "crash"),
        ("record-drop-row", "disagreement"),
        ("record-corrupt-hash", "disagreement"),
        ("payload-unrecorded-extra", "disagreement"),
        ("payload-duplicate-divergent", "disagreement"),
    ],
)
def test_expected_failures_are_detected(
    mutation_name: str,
    expected_kind: str,
    targets: list[CheckTarget],
    dirs: tuple[Path, Path],
) -> None:
    sample_dir, work_dir = dirs
    image = apply_mutation(mutation_name, build_scenario_image("typical-purelib"))
    evaluation = evaluate_image(
        image,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        mutation_name=mutation_name,
        repeats=2,
    )
    assert evaluation.failed
    assert expected_kind in evaluation.kinds


@pytest.mark.parametrize(
    "mutation_name",
    [
        "record-missing",
        "record-corrupt-size",
        "record-weak-hash-md5",
        "record-unknown-algorithm",
        "record-duplicate-row",
        "distinfo-filename-mismatch",
        "wheel-drop-version",
        "metadata-drop-name",
    ],
)
def test_expected_rejections_are_not_failures(
    mutation_name: str,
    targets: list[CheckTarget],
    dirs: tuple[Path, Path],
) -> None:
    sample_dir, work_dir = dirs
    image = apply_mutation(mutation_name, build_seeded_image(3))
    evaluation = evaluate_image(
        image,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        mutation_name=mutation_name,
        repeats=1,
    )
    assert not evaluation.failed, (mutation_name, evaluation.kinds)


# ---------------------------------------------------------------------------
# Harness observations
# ---------------------------------------------------------------------------


def test_observation_records_value_resources_and_boundaries(
    dirs: tuple[Path, Path],
) -> None:
    sample_dir, work_dir = dirs
    write_wheel(build_scenario_image("minimal-purelib"), sample_dir)
    wheel_path = next(sample_dir.glob("*.whl"))
    target = CheckTarget.builtin("construct-only")

    evaluation = evaluate_path(wheel_path, [target], workdir=work_dir, repeats=1)
    assert not evaluation.failed
    observation = evaluation.observations[0]
    assert observation.accepted
    assert observation.return_value == repr(construct_only(str(wheel_path)))
    assert observation.duration >= 0.0
    assert observation.peak_open_handles >= 1
    assert observation.sample_accesses == [os.path.abspath(wheel_path)]
    assert observation.outside_accesses == []


def test_nondeterministic_target_is_flagged(
    dirs: tuple[Path, Path],
) -> None:
    sample_dir, work_dir = dirs
    wheel_path = write_wheel(build_seeded_image(1), sample_dir)
    state = {"calls": 0}

    def flaky(path: str) -> int:
        state["calls"] += 1
        if state["calls"] % 2 == 0:
            raise WheelError("synthetic flaky rejection")

        return construct_only(path)

    target = CheckTarget.from_callable("flaky", flaky)
    evaluation = evaluate_path(wheel_path, [target], workdir=work_dir, repeats=4)
    assert "nondeterministic" in evaluation.kinds
    assert "crash" not in evaluation.kinds


def test_boundary_violation_is_flagged(dirs: tuple[Path, Path], tmp_path: Path) -> None:
    sample_dir, work_dir = dirs
    wheel_path = write_wheel(build_seeded_image(2), sample_dir)
    secret = tmp_path / "outside-sample.txt"
    secret.write_text("outside the sample root", encoding="utf-8")

    def reads_outside(path: str) -> bool:
        with open(secret, encoding="utf-8") as handle:
            return bool(handle.read())

    target = CheckTarget.from_callable("boundary", reads_outside, expected=())
    evaluation = evaluate_path(wheel_path, [target], workdir=work_dir, repeats=1)
    assert "boundary" in evaluation.kinds
    observed = evaluation.observations[0]
    assert any(
        path.endswith("outside-sample.txt") for path in observed.outside_accesses
    )


def test_resource_time_limit_is_flagged(dirs: tuple[Path, Path]) -> None:
    sample_dir, work_dir = dirs
    wheel_path = write_wheel(build_seeded_image(3), sample_dir)

    def slow(path: str) -> None:
        time.sleep(0.05)

    target = CheckTarget.from_callable("slow", slow, expected=())
    evaluation = evaluate_path(
        wheel_path, [target], workdir=work_dir, repeats=1, time_limit=0.001
    )
    assert "resource" in evaluation.kinds


def test_unexpected_exception_is_a_crash(dirs: tuple[Path, Path]) -> None:
    sample_dir, work_dir = dirs
    wheel_path = write_wheel(build_seeded_image(4), sample_dir)

    def raises_runtime_error(path: str) -> None:
        raise RuntimeError("boom")

    target = CheckTarget.from_callable("crasher", raises_runtime_error, expected=())
    evaluation = evaluate_path(wheel_path, [target], workdir=work_dir, repeats=1)
    assert evaluation.kinds == ["crash"]
    assert evaluation.observations[0].exception_type == "builtins.RuntimeError"


# ---------------------------------------------------------------------------
# Reduction
# ---------------------------------------------------------------------------


def test_reducer_preserves_crash_signature_and_keeps_baseline_legal(
    targets: list[CheckTarget], dirs: tuple[Path, Path]
) -> None:
    sample_dir, work_dir = dirs
    baseline = build_scenario_image("typical-purelib")
    mutated = apply_mutation("record-malformed-row", baseline)
    evaluation = evaluate_image(
        mutated,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        mutation_name="record-malformed-row",
        repeats=1,
    )
    assert evaluation.kinds == ["crash"]

    reduction = reduce_failure(
        baseline,
        "record-malformed-row",
        evaluation,
        targets,
        sample_dir=str(sample_dir),
        workdir=str(work_dir),
    )
    assert reduction.skipped_reason is None
    assert reduction.accepted
    # Reduced baseline is strictly smaller ...
    assert len(reduction.image.payload) < len(baseline.payload)
    # ... and remains a legal wheel on its own (the mutation is re-applied only
    # to candidates, never baked into the baseline).
    legal_check = evaluate_image(
        reduction.image,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        repeats=1,
    )
    assert not legal_check.failed

    reduced_mutated = apply_mutation("record-malformed-row", reduction.image)
    reduced_eval = evaluate_image(
        reduced_mutated,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        mutation_name="record-malformed-row",
        repeats=1,
    )
    assert reduced_eval.signature == evaluation.signature


def test_reducer_shrinks_disagreement_to_mutation_anchor(
    targets: list[CheckTarget], dirs: tuple[Path, Path]
) -> None:
    sample_dir, work_dir = dirs
    baseline = build_scenario_image("typical-purelib")
    mutated = apply_mutation("payload-unrecorded-extra", baseline)
    evaluation = evaluate_image(
        mutated,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        mutation_name="payload-unrecorded-extra",
        repeats=1,
    )
    assert "disagreement" in evaluation.kinds

    reduction = reduce_failure(
        baseline,
        "payload-unrecorded-extra",
        evaluation,
        targets,
        sample_dir=str(sample_dir),
        workdir=str(work_dir),
    )
    assert reduction.image.payload == []
    reduced_mutated = apply_mutation("payload-unrecorded-extra", reduction.image)
    reduced_eval = evaluate_image(
        reduced_mutated,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        mutation_name="payload-unrecorded-extra",
        repeats=1,
    )
    assert reduced_eval.signature == evaluation.signature


def test_reducer_skips_nondeterministic_findings(
    dirs: tuple[Path, Path],
) -> None:
    sample_dir, work_dir = dirs
    wheel_path = write_wheel(build_seeded_image(5), sample_dir)
    state = {"calls": 0}

    def flaky(path: str) -> None:
        state["calls"] += 1
        if state["calls"] % 2:
            raise RuntimeError("sometimes crashes")

    target = CheckTarget.from_callable("flaky", flaky, expected=())
    evaluation = evaluate_path(wheel_path, [target], workdir=work_dir, repeats=4)
    assert "nondeterministic" in evaluation.kinds

    reduction = reduce_failure(
        build_seeded_image(5),
        "record-missing",
        evaluation,
        [target],
        sample_dir=str(sample_dir),
        workdir=str(work_dir),
    )
    assert reduction.skipped_reason is not None


# ---------------------------------------------------------------------------
# Bundles and replay
# ---------------------------------------------------------------------------


def _find_and_bundle(
    name: str, out_dir: Path, targets: list[CheckTarget]
) -> tuple[Path, Evaluation]:
    sample_dir = out_dir / "sample"
    work_dir = out_dir / "work"
    sample_dir.mkdir()
    work_dir.mkdir()
    baseline = build_scenario_image("typical-purelib")
    mutated = apply_mutation(name, baseline)
    evaluation = evaluate_image(
        mutated,
        targets,
        sample_dir=sample_dir,
        workdir=work_dir,
        mutation_name=name,
        repeats=2,
    )
    assert evaluation.failed
    reduction = reduce_failure(
        baseline,
        name,
        evaluation,
        targets,
        sample_dir=str(sample_dir),
        workdir=str(work_dir),
    )
    reduced = apply_mutation(name, reduction.image)
    scenario = SCENARIOS["typical-purelib"]
    manifest_path = write_bundle(
        out_dir / "bundle",
        reduced,
        scenario=(scenario.name, scenario.version),
        mutation_name=name,
        targets=targets,
        evaluation=evaluation,
        reduction=reduction,
        repeats=2,
        byte_mutation=MUTATIONS[name].apply_bytes,
    )
    return manifest_path, evaluation


def test_bundle_roundtrip_replays_without_cwd_state(
    targets: list[CheckTarget], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path, evaluation = _find_and_bundle(
        "record-malformed-row", tmp_path, targets
    )
    bundle_dir = manifest_path.parent

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["mutation"] == "record-malformed-row"
    assert manifest["source"] == {
        "kind": "scenario",
        "name": "typical-purelib",
        "version": CORPUS_FORMAT_VERSION,
    }
    assert manifest["replay_requirements"] == {
        "network": False,
        "build_backend": False,
        "cwd_state": False,
    }
    assert not os.path.isabs(manifest["wheel_file"])
    assert (bundle_dir / manifest["wheel_file"]).is_file()

    # Replay from an unrelated, empty working directory.
    replay_work = tmp_path / "elsewhere"
    replay_work.mkdir()
    monkeypatch.chdir(replay_work)
    result = replay_bundle(bundle_dir, workdir=replay_work / "empty")
    assert result.reproduced
    assert result.evaluation.signature == evaluation.signature
    assert load_bundle(bundle_dir)["mutation"] == "record-malformed-row"


def test_byte_mutation_bundle_roundtrip(
    targets: list[CheckTarget], tmp_path: Path
) -> None:
    manifest_path, evaluation = _find_and_bundle("archive-truncated", tmp_path, targets)
    result = replay_bundle(manifest_path.parent)
    assert result.reproduced
    assert result.evaluation.signature == evaluation.signature


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_lists_scenarios_and_mutations(capsys: pytest.CaptureFixture[str]) -> None:
    assert failurelab_main(["list"]) == 0
    output = capsys.readouterr().out
    assert "minimal-purelib" in output
    assert "record-malformed-row" in output


def test_cli_generate_legal_and_mutated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "gen"
    assert failurelab_main(["generate", "--seed", "11", "--out", str(out)]) == 0
    wheels = list(out.glob("*.whl"))
    assert len(wheels) == 1
    with WheelFile(wheels[0]) as wf:
        assert wf.testzip() is None

    out_mut = tmp_path / "gen-mut"
    assert (
        failurelab_main(
            [
                "generate",
                "--scenario",
                "minimal-purelib",
                "--mutation",
                "record-missing",
                "--out",
                str(out_mut),
            ]
        )
        == 0
    )
    mutated_wheel = next(out_mut.glob("*.whl"))
    with pytest.raises(WheelError, match="Missing"):
        WheelFile(mutated_wheel)


def test_cli_fuzz_reduces_finds_and_replay_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "fuzz"
    code = failurelab_main(
        [
            "fuzz",
            "--scenario",
            "minimal-purelib",
            "--repeats",
            "1",
            "--out",
            str(out),
            "--fail-on-finding",
        ]
    )
    output = capsys.readouterr().out
    assert code == 1
    assert "FINDING [record-malformed-row]" in output
    assert "FINDING [archive-truncated]" in output
    bundles = sorted((out / "findings").iterdir())
    assert any(b.name.endswith("record-malformed-row") for b in bundles)
    manifest = json.loads((bundles[0] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["reduction"]["steps"] >= 0

    # The replay subcommand reproduces every bundle.
    for bundle in bundles:
        assert failurelab_main(["replay", str(bundle)]) == 0


def test_cli_fuzz_clean_scenario_no_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "clean"
    code = failurelab_main(
        [
            "fuzz",
            "--scenario",
            "minimal-purelib",
            "--mutation",
            "record-missing",
            "--repeats",
            "1",
            "--out",
            str(out),
            "--fail-on-finding",
        ]
    )
    assert code == 0
    assert "0 finding(s)" in capsys.readouterr().out


def test_cli_replay_missing_signature_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "fuzz"
    failurelab_main(
        [
            "fuzz",
            "--scenario",
            "minimal-purelib",
            "--mutation",
            "record-malformed-row",
            "--repeats",
            "1",
            "--out",
            str(out),
        ]
    )
    bundle = next((out / "findings").iterdir())
    # Tamper with the persisted wheel: replay must then fail to reproduce.
    wheel = bundle / "sample"
    wheel_file = next(wheel.glob("*.whl"))
    wheel_file.write_bytes(b"definitely not a wheel")
    assert failurelab_main(["replay", str(bundle)]) == 1
    assert "False" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Non-goal guard: the regular CLI, WheelFile behavior and capability surface
# ---------------------------------------------------------------------------


def test_regular_wheel_cli_is_unchanged() -> None:
    from wheel._commands import parser

    root = parser()
    subparsers_action = next(
        action
        for action in root._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparsers_action.choices) == {
        "unpack",
        "pack",
        "convert",
        "tags",
        "info",
        "version",
        "help",
    }


def test_no_repair_retag_or_edit_capability_exposed() -> None:
    forbidden = ("repair", "retag", "edit", "fix")
    public_names = [name for name in dir(failurelab_pkg) if not name.startswith("_")]
    for name in public_names:
        assert not any(word in name.lower() for word in forbidden)

    from wheel._failurelab.cli import _build_parser

    root = _build_parser()
    subparsers_action = next(
        action
        for action in root._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparsers_action.choices) == {"list", "generate", "fuzz", "replay"}

    # Unknown/forbidden commands are rejected by argparse.
    with pytest.raises(SystemExit):
        failurelab_main(["retag"])


def test_read_all_target_counts_every_member(tmp_path: Path) -> None:
    # minimal-purelib: payload + WHEEL + METADATA + RECORD == 4
    wheel_path = write_wheel(build_scenario_image("minimal-purelib"), tmp_path)
    assert read_all_files(str(wheel_path)) == 4
    assert construct_only(str(wheel_path)) == 4
