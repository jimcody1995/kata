from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from kata.agent_bundle import (
    AGENT_ENTRY_FILENAME,
    AGENT_MANIFEST_FILENAME,
    load_bundle_files,
    replace_bundle_contents,
    write_agent_manifest,
)
from kata.baseline import generate_baseline_seed_instructions
from kata.benchmarks import resolve_eval_pack_path
from kata.eval_pack import discover_eval_pack_tasks
from kata.generator import generate_seed_instructions
from kata.provenance import (
    EVALUATOR_VERSION,
    pool_fingerprint,
    sha256_directory,
    short_hash,
)
from kata.seed_agent import render_seed_agent

FRONTIER_SCHEMA_VERSION = 3
FRONTIER_FILENAME = "frontier.json"
DEFAULT_PROMOTION_MARGIN_POINTS = 3.0


@dataclass(frozen=True)
class FrontierModeConfig:
    baseline_artifact: str
    frontier_artifact: str
    primary_tasks: list[str]
    holdout_tasks: list[str] = field(default_factory=list)
    promotion_margin_points: float = DEFAULT_PROMOTION_MARGIN_POINTS
    evaluator_version: str | None = None
    baseline_artifact_hash: str | None = None
    frontier_artifact_hash: str | None = None
    primary_pool_fingerprint: str | None = None
    holdout_pool_fingerprint: str | None = None
    frontier_updated_at: str | None = None
    frontier_source: str | None = None


@dataclass(frozen=True)
class FrontierManifest:
    schema_version: int
    repo_ref: str
    eval_pack: str
    modes: dict[str, FrontierModeConfig]
    updated_at: str


def frontier_manifest_path(eval_pack_path: str) -> Path:
    return resolve_eval_pack_path(eval_pack_path) / FRONTIER_FILENAME


def load_frontier_manifest(eval_pack_path: str) -> FrontierManifest:
    path = frontier_manifest_path(eval_pack_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    modes = {
        mode: parse_frontier_mode_config(config)
        for mode, config in (payload.get("modes") or {}).items()
    }
    return FrontierManifest(
        schema_version=payload["schema_version"],
        repo_ref=payload["repo_ref"],
        eval_pack=payload["eval_pack"],
        modes=modes,
        updated_at=payload["updated_at"],
    )


def write_frontier_manifest(eval_pack_path: str, manifest: FrontierManifest) -> Path:
    path = frontier_manifest_path(eval_pack_path)
    path.write_text(json.dumps(asdict(manifest), indent=2) + "\n", encoding="utf-8")
    return path


def init_frontier(
    *,
    repo_ref: str,
    eval_pack_path: str,
    mode: str,
    registry_url: str | None = None,
    primary_tasks: list[str] | None = None,
    holdout_tasks: list[str] | None = None,
    promotion_margin_points: float = DEFAULT_PROMOTION_MARGIN_POINTS,
) -> FrontierManifest:
    validations = discover_eval_pack_tasks(eval_pack_path)
    invalid = [result.root.name for result in validations if not result.is_valid]
    if invalid:
        raise ValueError(
            "Eval pack is invalid. Run `kata eval-pack validate` first. "
            f"Invalid task directories: {', '.join(invalid)}"
        )

    available_tasks = [result.root.name for result in validations]
    task_roots_by_name = {result.root.name: result.root for result in validations}
    selected_primary = primary_tasks or available_tasks
    selected_holdout = holdout_tasks or []
    ensure_known_tasks(selected_primary, available_tasks, label="primary")
    ensure_known_tasks(selected_holdout, available_tasks, label="holdout")
    overlap = sorted(set(selected_primary) & set(selected_holdout))
    if overlap:
        raise ValueError(
            "Primary and holdout pools must not overlap. "
            f"Overlapping task ids: {', '.join(overlap)}"
        )
    if not selected_primary:
        raise ValueError("Frontier init requires at least one primary task.")

    eval_pack_root = resolve_eval_pack_path(eval_pack_path)
    artifact_dir = eval_pack_root / "agents" / mode
    baseline_root = artifact_dir / "baseline"
    frontier_root = artifact_dir / "frontier"
    baseline_root.mkdir(parents=True, exist_ok=True)
    frontier_root.mkdir(parents=True, exist_ok=True)
    baseline_instructions = generate_baseline_seed_instructions(repo_ref, mode)
    frontier_instructions = generate_seed_instructions(repo_ref, mode, registry_url)
    write_agent_manifest(baseline_root / AGENT_MANIFEST_FILENAME)
    write_agent_manifest(frontier_root / AGENT_MANIFEST_FILENAME)
    (baseline_root / AGENT_ENTRY_FILENAME).write_text(
        render_seed_agent(instruction_text=baseline_instructions, mode=mode, label="baseline"),
        encoding="utf-8",
    )
    (frontier_root / AGENT_ENTRY_FILENAME).write_text(
        render_seed_agent(instruction_text=frontier_instructions, mode=mode, label="frontier"),
        encoding="utf-8",
    )
    primary_pool = [task_roots_by_name[task_id] for task_id in selected_primary]
    holdout_pool = [task_roots_by_name[task_id] for task_id in selected_holdout]

    manifest = existing_or_new_manifest(repo_ref=repo_ref, eval_pack_path=eval_pack_path)
    updated_modes = dict(manifest.modes)
    updated_modes[mode] = FrontierModeConfig(
        baseline_artifact=str(baseline_root.resolve()),
        frontier_artifact=str(frontier_root.resolve()),
        primary_tasks=selected_primary,
        holdout_tasks=selected_holdout,
        promotion_margin_points=promotion_margin_points,
        evaluator_version=EVALUATOR_VERSION,
        baseline_artifact_hash=sha256_directory(
            baseline_root,
            include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
        ),
        frontier_artifact_hash=sha256_directory(
            frontier_root,
            include=[AGENT_ENTRY_FILENAME, AGENT_MANIFEST_FILENAME],
        ),
        primary_pool_fingerprint=pool_fingerprint(primary_pool),
        holdout_pool_fingerprint=pool_fingerprint(holdout_pool) if holdout_pool else None,
        frontier_updated_at=timestamp_now(),
        frontier_source="kata-init",
    )
    updated_manifest = FrontierManifest(
        schema_version=FRONTIER_SCHEMA_VERSION,
        repo_ref=repo_ref,
        eval_pack=str(eval_pack_root),
        modes=updated_modes,
        updated_at=timestamp_now(),
    )
    write_frontier_manifest(eval_pack_path, updated_manifest)
    return updated_manifest


def promote_frontier_artifact(
    *,
    eval_pack_path: str,
    mode: str,
    candidate_artifact_path: str,
    source: str,
    evaluator_version: str | None = None,
) -> FrontierManifest:
    manifest = load_frontier_manifest(eval_pack_path)
    if mode not in manifest.modes:
        raise ValueError(f"Mode is not configured in frontier manifest: {mode}")
    mode_config = manifest.modes[mode]
    frontier_root = Path(mode_config.frontier_artifact).expanduser().resolve()
    candidate_root = Path(candidate_artifact_path).expanduser().resolve()
    candidate_files = load_bundle_files(candidate_root)
    replace_bundle_contents(frontier_root, candidate_files)
    frontier_hash = sha256_directory(frontier_root, include=sorted(candidate_files))
    updated_modes = dict(manifest.modes)
    updated_modes[mode] = FrontierModeConfig(
        baseline_artifact=mode_config.baseline_artifact,
        frontier_artifact=mode_config.frontier_artifact,
        primary_tasks=mode_config.primary_tasks,
        holdout_tasks=mode_config.holdout_tasks,
        promotion_margin_points=mode_config.promotion_margin_points,
        evaluator_version=evaluator_version or mode_config.evaluator_version or EVALUATOR_VERSION,
        baseline_artifact_hash=resolve_baseline_artifact_hash(mode_config),
        frontier_artifact_hash=frontier_hash,
        primary_pool_fingerprint=mode_config.primary_pool_fingerprint,
        holdout_pool_fingerprint=mode_config.holdout_pool_fingerprint,
        frontier_updated_at=timestamp_now(),
        frontier_source=source,
    )
    updated_manifest = FrontierManifest(
        schema_version=manifest.schema_version,
        repo_ref=manifest.repo_ref,
        eval_pack=manifest.eval_pack,
        modes=updated_modes,
        updated_at=timestamp_now(),
    )
    write_frontier_manifest(eval_pack_path, updated_manifest)
    return updated_manifest


def render_frontier_manifest(manifest: FrontierManifest, mode: str | None = None) -> str:
    lines: list[str] = []
    lines.append(f"Frontier manifest: `{manifest.eval_pack}`")
    lines.append(f"Repo: `{manifest.repo_ref}`")
    lines.append(f"Updated: {manifest.updated_at}")
    lines.append("")
    modes = [mode] if mode else sorted(manifest.modes)
    for selected_mode in modes:
        mode_config = manifest.modes.get(selected_mode)
        if mode_config is None:
            raise ValueError(f"Mode is not configured in frontier manifest: {selected_mode}")
        lines.append(f"Mode: {selected_mode}")
        lines.append(f"- Baseline artifact: `{mode_config.baseline_artifact}`")
        lines.append(f"- Frontier artifact: `{mode_config.frontier_artifact}`")
        lines.append(f"- Primary tasks: {', '.join(mode_config.primary_tasks)}")
        lines.append(
            "- Holdout tasks: "
            + (", ".join(mode_config.holdout_tasks) if mode_config.holdout_tasks else "none")
        )
        if mode_config.frontier_updated_at:
            lines.append(f"- Frontier updated: {mode_config.frontier_updated_at}")
        if mode_config.frontier_source:
            lines.append(f"- Frontier source: {mode_config.frontier_source}")
        if mode_config.evaluator_version:
            lines.append(f"- Evaluator version: {mode_config.evaluator_version}")
        lines.append(f"- Promotion margin: {mode_config.promotion_margin_points:.1f} points")
        if mode_config.baseline_artifact_hash:
            lines.append(
                f"- Baseline artifact hash: {short_hash(mode_config.baseline_artifact_hash)}"
            )
        if mode_config.frontier_artifact_hash:
            lines.append(
                f"- Frontier artifact hash: {short_hash(mode_config.frontier_artifact_hash)}"
            )
        if mode_config.primary_pool_fingerprint:
            lines.append(
                "- Primary pool fingerprint: "
                f"{short_hash(mode_config.primary_pool_fingerprint)}"
            )
        if mode_config.holdout_pool_fingerprint:
            lines.append(
                "- Holdout pool fingerprint: "
                f"{short_hash(mode_config.holdout_pool_fingerprint)}"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def render_frontier_json(manifest: FrontierManifest) -> str:
    return json.dumps(asdict(manifest), indent=2) + "\n"


def existing_or_new_manifest(*, repo_ref: str, eval_pack_path: str) -> FrontierManifest:
    path = frontier_manifest_path(eval_pack_path)
    if path.exists():
        return load_frontier_manifest(eval_pack_path)
    return FrontierManifest(
        schema_version=FRONTIER_SCHEMA_VERSION,
        repo_ref=repo_ref,
        eval_pack=str(resolve_eval_pack_path(eval_pack_path)),
        modes={},
        updated_at=timestamp_now(),
    )


def ensure_known_tasks(selected: list[str], available: list[str], *, label: str) -> None:
    unknown = sorted(set(selected) - set(available))
    if unknown:
        raise ValueError(
            f"Unknown {label} task ids: {', '.join(unknown)}. "
            f"Available tasks: {', '.join(available)}"
        )


def parse_frontier_mode_config(config: dict[str, object]) -> FrontierModeConfig:
    baseline_artifact = str(
        config.get("baseline_artifact") or config.get("baseline_prompt") or ""
    )
    frontier_artifact = str(
        config.get("frontier_artifact") or config.get("frontier_prompt") or ""
    )
    return FrontierModeConfig(
        baseline_artifact=baseline_artifact,
        frontier_artifact=frontier_artifact,
        primary_tasks=list(config.get("primary_tasks") or []),
        holdout_tasks=list(config.get("holdout_tasks") or []),
        promotion_margin_points=float(
            config.get("promotion_margin_points", DEFAULT_PROMOTION_MARGIN_POINTS)
        ),
        evaluator_version=str(config["evaluator_version"])
        if config.get("evaluator_version") is not None
        else None,
        baseline_artifact_hash=str(
            config.get("baseline_artifact_hash") or config.get("baseline_prompt_hash") or ""
        )
        or None,
        frontier_artifact_hash=str(
            config.get("frontier_artifact_hash") or config.get("frontier_prompt_hash") or ""
        )
        or None,
        primary_pool_fingerprint=str(config["primary_pool_fingerprint"])
        if config.get("primary_pool_fingerprint") is not None
        else None,
        holdout_pool_fingerprint=str(config["holdout_pool_fingerprint"])
        if config.get("holdout_pool_fingerprint") is not None
        else None,
        frontier_updated_at=str(config["frontier_updated_at"])
        if config.get("frontier_updated_at") is not None
        else None,
        frontier_source=str(config["frontier_source"])
        if config.get("frontier_source") is not None
        else None,
    )


def resolve_baseline_artifact_hash(mode_config: FrontierModeConfig) -> str:
    if mode_config.baseline_artifact_hash:
        return mode_config.baseline_artifact_hash
    artifact_root = Path(mode_config.baseline_artifact).expanduser().resolve()
    return sha256_directory(artifact_root, include=sorted(load_bundle_files(artifact_root)))


def resolve_frontier_artifact_hash(mode_config: FrontierModeConfig) -> str:
    if mode_config.frontier_artifact_hash:
        return mode_config.frontier_artifact_hash
    artifact_root = Path(mode_config.frontier_artifact).expanduser().resolve()
    return sha256_directory(artifact_root, include=sorted(load_bundle_files(artifact_root)))


def timestamp_now() -> str:
    return datetime.now(UTC).isoformat()
