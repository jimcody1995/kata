from __future__ import annotations

import json
from pathlib import Path

from kata.agent_bundle import AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME
from kata.challenge import ChallengePoolSummary, promotion_reason
from kata.frontier import (
    PRIMARY_SELECTION_RANDOM_LIVE,
    FrontierManifest,
    FrontierModeConfig,
    init_frontier,
    load_frontier_manifest,
    render_frontier_json,
    render_frontier_manifest,
)


def test_render_frontier_manifest_includes_primary_and_holdout_tasks(tmp_path: Path) -> None:
    manifest = FrontierManifest(
        schema_version=1,
        repo_ref="https://github.com/example/repo.git",
        eval_pack=str(tmp_path),
        updated_at="2026-06-28T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_artifact="/tmp/baseline_agent.py",
                frontier_artifact="/tmp/frontier_agent.py",
                primary_tasks=["task-a", "task-b"],
                holdout_tasks=["task-c"],
                promotion_margin_points=4.5,
                holdout_promotion_margin_points=1.5,
                evaluator_version="2026-06-29.v1",
                baseline_artifact_hash="a" * 64,
                frontier_artifact_hash="b" * 64,
                primary_pool_fingerprint="c" * 64,
                holdout_pool_fingerprint="d" * 64,
                frontier_updated_at="2026-06-28T01:00:00+00:00",
                frontier_source="run-123",
            )
        },
    )

    rendered = render_frontier_manifest(manifest, "contributor")

    assert "Primary tasks: task-a, task-b" in rendered
    assert "Holdout tasks: task-c" in rendered
    assert "Frontier source: run-123" in rendered
    assert "Evaluator version: 2026-06-29.v1" in rendered
    assert "Promotion margin: 4.5 points" in rendered
    assert "Holdout margin: 1.5 points" in rendered
    assert "Primary pool fingerprint: cccccccccccc" in rendered


def test_promotion_reason_explains_holdout_failure() -> None:
    primary = ChallengePoolSummary(
        task_ids=["task-a"],
        eval_run_summary="run_summary.json",
        total_task_weight=1.0,
        variant_successes={"frontier": 0, "candidate": 1, "baseline": 0},
        variant_invalid_tasks={"frontier": 0, "candidate": 0, "baseline": 0},
        variant_scores={"frontier": 40.0, "candidate": 75.0, "baseline": 0.0},
        candidate_beats_frontier=True,
        candidate_score_delta=35.0,
    )
    holdout = ChallengePoolSummary(
        task_ids=["task-b"],
        eval_run_summary="run_summary.json",
        total_task_weight=1.0,
        variant_successes={"frontier": 1, "candidate": 1, "baseline": 0},
        variant_invalid_tasks={"frontier": 0, "candidate": 0, "baseline": 0},
        variant_scores={"frontier": 70.0, "candidate": 68.0, "baseline": 0.0},
        candidate_beats_frontier=False,
        candidate_score_delta=-2.0,
    )

    assert (
        promotion_reason(primary, holdout)
        == "candidate cleared the primary score margin but regressed on holdout"
    )


def test_render_frontier_json_includes_mode_configuration(tmp_path: Path) -> None:
    manifest = FrontierManifest(
        schema_version=1,
        repo_ref="https://github.com/example/repo.git",
        eval_pack=str(tmp_path),
        updated_at="2026-06-28T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_artifact="/tmp/baseline_agent.py",
                frontier_artifact="/tmp/frontier_agent.py",
                primary_tasks=["task-a"],
                holdout_tasks=[],
                promotion_margin_points=3.0,
                holdout_promotion_margin_points=1.0,
            )
        },
    )

    payload = json.loads(render_frontier_json(manifest))

    assert payload["repo_ref"] == "https://github.com/example/repo.git"
    assert payload["modes"]["contributor"]["promotion_margin_points"] == 3.0
    assert payload["modes"]["contributor"]["holdout_promotion_margin_points"] == 1.0


def test_render_frontier_manifest_shows_private_holdout_count_when_tasks_are_redacted(
    tmp_path: Path,
) -> None:
    manifest = FrontierManifest(
        schema_version=1,
        repo_ref="https://github.com/example/repo.git",
        eval_pack=str(tmp_path),
        updated_at="2026-06-28T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_artifact="/tmp/baseline_agent.py",
                frontier_artifact="/tmp/frontier_agent.py",
                primary_tasks=["task-a"],
                holdout_tasks=[],
                holdout_task_count=10,
                holdout_eval_pack="example__repo",
                promotion_margin_points=2.0,
                holdout_promotion_margin_points=1.0,
            )
        },
    )

    rendered = render_frontier_manifest(manifest, "contributor")

    assert "Holdout tasks: private (10 tasks)" in rendered
    assert "Promotion margin: 2.0 points" in rendered
    assert "Holdout margin: 1.0 points" in rendered


def test_render_frontier_manifest_shows_random_public_sample_mode(tmp_path: Path) -> None:
    manifest = FrontierManifest(
        schema_version=1,
        repo_ref="https://github.com/example/repo.git",
        eval_pack=str(tmp_path),
        updated_at="2026-06-28T00:00:00+00:00",
        modes={
            "contributor": FrontierModeConfig(
                baseline_artifact="/tmp/baseline_agent.py",
                frontier_artifact="/tmp/frontier_agent.py",
                primary_tasks=[],
                primary_task_count=10,
                primary_selection=PRIMARY_SELECTION_RANDOM_LIVE,
                holdout_tasks=[],
                holdout_task_count=10,
                holdout_eval_pack="example__repo",
                promotion_margin_points=2.0,
            )
        },
    )

    rendered = render_frontier_manifest(manifest, "contributor")

    assert "Primary tasks: random live sample (10 tasks per duel)" in rendered


def test_load_frontier_manifest_merges_private_holdout_overlay(
    monkeypatch,
    tmp_path: Path,
) -> None:
    public_root = tmp_path / "public-registry"
    private_root = tmp_path / "private-registry"
    public_benchmarks = public_root / "benchmarks" / "example__repo"
    private_benchmarks = private_root / "benchmarks" / "example__repo"
    public_benchmarks.mkdir(parents=True)
    private_benchmarks.mkdir(parents=True)
    (public_root / "kata-benchmark-registry.json").write_text("{}", encoding="utf-8")
    (private_root / "kata-benchmark-registry.json").write_text("{}", encoding="utf-8")
    (public_benchmarks / "frontier.json").write_text(
        json.dumps(
            {
                "schema_version": 4,
                "repo_ref": "https://github.com/example/repo.git",
                "eval_pack": str(public_benchmarks),
                "updated_at": "2026-06-28T00:00:00+00:00",
                "modes": {
                    "contributor": {
                        "baseline_artifact": "/tmp/baseline_agent.py",
                        "frontier_artifact": "/tmp/frontier_agent.py",
                        "primary_tasks": ["task-a"],
                        "holdout_tasks": [],
                        "holdout_task_count": 2,
                        "holdout_eval_pack": "example__repo",
                        "promotion_margin_points": 2.0,
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (private_benchmarks / "frontier.private.json").write_text(
        json.dumps(
            {
                "schema_version": 4,
                "repo_ref": "https://github.com/example/repo.git",
                "eval_pack": str(private_benchmarks),
                "updated_at": "2026-06-28T00:00:00+00:00",
                "modes": {
                    "contributor": {
                        "baseline_artifact": "/tmp/baseline_agent.py",
                        "frontier_artifact": "/tmp/frontier_agent.py",
                        "primary_tasks": ["task-a"],
                        "holdout_tasks": ["secret-a", "secret-b"],
                        "holdout_task_count": 2,
                        "holdout_eval_pack": "example__repo",
                        "promotion_margin_points": 2.0,
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(public_root))
    monkeypatch.setenv("KATA_PRIVATE_BENCHMARKS_ROOT", str(private_root))

    manifest = load_frontier_manifest("example__repo")

    assert manifest.modes["contributor"].holdout_tasks == ["secret-a", "secret-b"]
    assert manifest.modes["contributor"].holdout_task_count == 2


def test_init_frontier_stores_lane_artifacts_in_kata_repo_not_benchmark_pack(
    monkeypatch,
    tmp_path: Path,
) -> None:
    kata_root = tmp_path / "kata"
    registry_root = tmp_path / "benchmarks"
    pack_root = registry_root / "benchmarks" / "example__repo"
    repo_root = tmp_path / "repo"
    sn74_registry_path = tmp_path / "registry.json"
    kata_root.mkdir(parents=True)
    pack_root.mkdir(parents=True)
    repo_root.mkdir(parents=True)
    (repo_root / "README.md").write_text("# Example Repo\n\nA sample project.\n", encoding="utf-8")
    (repo_root / "CONTRIBUTING.md").write_text(
        "Run `pytest` before submitting changes.\n",
        encoding="utf-8",
    )
    sn74_registry_path.write_text("{}\n", encoding="utf-8")
    (registry_root / "kata-benchmark-registry.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "registry_name": "test",
                "benchmarks_dir": "benchmarks",
                "active_repo_packs": ["example__repo"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    for index in range(20):
        write_valid_eval_task(pack_root / f"task-{index:02d}")
    monkeypatch.setenv("KATA_BENCHMARKS_ROOT", str(registry_root))
    monkeypatch.setenv("KATA_ROOT", str(kata_root))

    manifest = init_frontier(
        repo_ref=str(repo_root),
        eval_pack_path="example__repo",
        mode="contributor",
        registry_url=sn74_registry_path.as_uri(),
    )

    mode = manifest.modes["contributor"]
    assert mode.baseline_artifact is None
    assert mode.frontier_artifact == "kata://kings/example__repo/contributor"
    assert not (pack_root / "agents").exists()
    assert (
        kata_root / "kings" / "example__repo" / "contributor" / AGENT_ENTRY_FILENAME
    ).exists()
    assert (
        kata_root
        / "kings"
        / "example__repo"
        / "contributor"
        / AGENT_MANIFEST_FILENAME
    ).exists()


def write_valid_eval_task(task_root: Path) -> None:
    task_root.mkdir(parents=True, exist_ok=True)
    (task_root / "task.md").write_text("# Goal\nComplete the task.\n", encoding="utf-8")
    (task_root / "repo_ref.txt").write_text(
        "https://github.com/example/repo.git@test\n",
        encoding="utf-8",
    )
    (task_root / "checks.sh").write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\ntrue\n",
        encoding="utf-8",
    )
    (task_root / "rubric.md").write_text(
        "# Rubric\n\n- Task goal is completed without regressions.\n",
        encoding="utf-8",
    )
    (task_root / "allowed_paths.txt").write_text("src/\n", encoding="utf-8")
    (task_root / "forbidden_paths.txt").write_text("docs/\n", encoding="utf-8")
