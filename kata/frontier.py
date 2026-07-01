from __future__ import annotations

import json
import os
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
from kata.benchmarks import (
    PRIVATE_BENCHMARKS_ROOT_ENV,
    resolve_eval_pack_path,
    resolve_private_eval_pack_path,
)
from kata.eval_pack import discover_live_eval_pack_tasks
from kata.generator import generate_seed_instructions
from kata.provenance import (
    EVALUATOR_VERSION,
    pool_fingerprint,
    sha256_directory,
    short_hash,
)
from kata.public_artifacts import (
    build_public_king_artifact_ref,
    publish_public_king,
    resolve_artifact_path,
    resolve_public_king_root,
)
from kata.seed_agent import render_seed_agent

FRONTIER_SCHEMA_VERSION = 4
FRONTIER_FILENAME = "frontier.json"
PRIVATE_FRONTIER_FILENAME = "frontier.private.json"
DEFAULT_PROMOTION_MARGIN_POINTS = 10.0
DEFAULT_HOLDOUT_PROMOTION_MARGIN_POINTS = 10.0
DEFAULT_RANDOM_PRIMARY_TASK_COUNT = 20
PRIMARY_SELECTION_FIXED = "fixed"
PRIMARY_SELECTION_RANDOM_LIVE = "random_live"


@dataclass(frozen=True)
class FrontierModeConfig:
    frontier_artifact: str = ""
    primary_tasks: list[str] = field(default_factory=list)
    baseline_artifact: str | None = None
    primary_task_count: int = 0
    primary_selection: str = PRIMARY_SELECTION_FIXED
    holdout_tasks: list[str] = field(default_factory=list)
    holdout_task_count: int = 0
    holdout_eval_pack: str | None = None
    holdout_is_private: bool = False
    promotion_margin_points: float = DEFAULT_PROMOTION_MARGIN_POINTS
    holdout_promotion_margin_points: float = DEFAULT_HOLDOUT_PROMOTION_MARGIN_POINTS
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
    manifest = parse_frontier_manifest_payload(json.loads(path.read_text(encoding="utf-8")))
    private_path = private_frontier_manifest_path(eval_pack_path)
    if private_path is None or not private_path.exists():
        return manifest
    private_manifest = parse_frontier_manifest_payload(
        json.loads(private_path.read_text(encoding="utf-8"))
    )
    merged_modes = dict(manifest.modes)
    for mode, private_mode in private_manifest.modes.items():
        public_mode = merged_modes.get(mode)
        if public_mode is None:
            merged_modes[mode] = private_mode
            continue
        merged_modes[mode] = FrontierModeConfig(
            frontier_artifact=public_mode.frontier_artifact,
            primary_tasks=public_mode.primary_tasks,
            baseline_artifact=public_mode.baseline_artifact,
            primary_task_count=public_mode.primary_task_count,
            primary_selection=public_mode.primary_selection,
            holdout_tasks=private_mode.holdout_tasks,
            holdout_task_count=max(
                public_mode.holdout_task_count,
                private_mode.holdout_task_count or len(private_mode.holdout_tasks),
            ),
            holdout_eval_pack=private_mode.holdout_eval_pack or public_mode.holdout_eval_pack,
            holdout_is_private=public_mode.holdout_is_private or private_mode.holdout_is_private,
            promotion_margin_points=public_mode.promotion_margin_points,
            holdout_promotion_margin_points=public_mode.holdout_promotion_margin_points,
            evaluator_version=public_mode.evaluator_version,
            baseline_artifact_hash=public_mode.baseline_artifact_hash,
            frontier_artifact_hash=public_mode.frontier_artifact_hash,
            primary_pool_fingerprint=public_mode.primary_pool_fingerprint,
            holdout_pool_fingerprint=public_mode.holdout_pool_fingerprint,
            frontier_updated_at=public_mode.frontier_updated_at,
            frontier_source=public_mode.frontier_source,
        )
    return FrontierManifest(
        schema_version=manifest.schema_version,
        repo_ref=manifest.repo_ref,
        eval_pack=manifest.eval_pack,
        modes=merged_modes,
        updated_at=manifest.updated_at,
    )


def parse_frontier_manifest_payload(payload: dict[str, object]) -> FrontierManifest:
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


def write_frontier_manifest(
    eval_pack_path: str,
    manifest: FrontierManifest,
    *,
    redact_private_holdout_tasks: bool = False,
) -> Path:
    path = frontier_manifest_path(eval_pack_path)
    path.write_text(
        json.dumps(
            frontier_manifest_payload(
                manifest,
                redact_private_holdout_tasks=redact_private_holdout_tasks,
            ),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def write_private_frontier_manifest(eval_pack_path: str, manifest: FrontierManifest) -> Path | None:
    path = private_frontier_manifest_path(eval_pack_path)
    if path is None:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(frontier_manifest_payload(manifest), indent=2) + "\n",
        encoding="utf-8",
    )
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
    holdout_promotion_margin_points: float = DEFAULT_HOLDOUT_PROMOTION_MARGIN_POINTS,
) -> FrontierManifest:
    validations = discover_live_eval_pack_tasks(eval_pack_path)
    invalid = [result.root.name for result in validations if not result.is_valid]
    if invalid:
        raise ValueError(
            "Eval pack is invalid. Run `kata eval-pack validate` first. "
            f"Invalid task directories: {', '.join(invalid)}"
        )
    if not validations:
        raise ValueError(
            "Frontier init requires at least one live benchmark task. "
            "Mark tasks as `live` before initializing the lane."
        )

    eval_pack_root = resolve_eval_pack_path(eval_pack_path)
    available_tasks = [result.root.name for result in validations]
    task_roots_by_name = {result.root.name: result.root for result in validations}
    if primary_tasks is not None:
        selected_primary = primary_tasks
        primary_selection = PRIMARY_SELECTION_FIXED
    else:
        if len(available_tasks) < DEFAULT_RANDOM_PRIMARY_TASK_COUNT:
            raise ValueError(
                "Frontier init requires at least "
                f"{DEFAULT_RANDOM_PRIMARY_TASK_COUNT} live public benchmark tasks "
                "for the random primary pool."
            )
        selected_primary = available_tasks[:DEFAULT_RANDOM_PRIMARY_TASK_COUNT]
        primary_selection = PRIMARY_SELECTION_RANDOM_LIVE
    selected_holdout = holdout_tasks or []
    ensure_known_tasks(selected_primary, available_tasks, label="primary")
    private_holdout_enabled = bool(selected_holdout) and bool(
        os.environ.get(PRIVATE_BENCHMARKS_ROOT_ENV)
    )
    if private_holdout_enabled:
        holdout_validations = discover_live_eval_pack_tasks(
            str(resolve_private_eval_pack_path(eval_pack_root.name))
        )
        invalid_holdout = [
            result.root.name for result in holdout_validations if not result.is_valid
        ]
        if invalid_holdout:
            raise ValueError(
                "Private holdout pack is invalid. Run `kata eval-pack validate` first. "
                f"Invalid task directories: {', '.join(invalid_holdout)}"
            )
        holdout_available_tasks = [result.root.name for result in holdout_validations]
        holdout_roots_by_name = {result.root.name: result.root for result in holdout_validations}
    else:
        holdout_available_tasks = available_tasks
        holdout_roots_by_name = task_roots_by_name
    ensure_known_tasks(selected_holdout, holdout_available_tasks, label="holdout")
    overlap = sorted(set(selected_primary) & set(selected_holdout))
    if overlap:
        raise ValueError(
            "Primary and holdout pools must not overlap. "
            f"Overlapping task ids: {', '.join(overlap)}"
        )
    if not selected_primary:
        raise ValueError("Frontier init requires at least one primary task.")

    repo_pack = eval_pack_root.name
    frontier_root = resolve_public_king_root(
        public_root=None,
        repo_pack=repo_pack,
        mode=mode,
    )
    frontier_root.mkdir(parents=True, exist_ok=True)
    frontier_instructions = generate_seed_instructions(repo_ref, mode, registry_url)
    write_agent_manifest(frontier_root / AGENT_MANIFEST_FILENAME)
    (frontier_root / AGENT_ENTRY_FILENAME).write_text(
        render_seed_agent(instruction_text=frontier_instructions, mode=mode, label="frontier"),
        encoding="utf-8",
    )
    if primary_selection == PRIMARY_SELECTION_RANDOM_LIVE:
        primary_pool = list(task_roots_by_name.values())
        manifest_primary_tasks: list[str] = []
    else:
        primary_pool = [task_roots_by_name[task_id] for task_id in selected_primary]
        manifest_primary_tasks = list(selected_primary)
    holdout_pool = [holdout_roots_by_name[task_id] for task_id in selected_holdout]

    manifest = existing_or_new_manifest(repo_ref=repo_ref, eval_pack_path=eval_pack_path)
    updated_modes = dict(manifest.modes)
    updated_modes[mode] = FrontierModeConfig(
        frontier_artifact=build_public_king_artifact_ref(
            repo_pack=repo_pack,
            mode=mode,
        ),
        primary_tasks=manifest_primary_tasks,
        baseline_artifact=None,
        primary_task_count=len(selected_primary),
        primary_selection=primary_selection,
        holdout_tasks=selected_holdout,
        holdout_task_count=len(selected_holdout),
        holdout_eval_pack=eval_pack_root.name if selected_holdout else None,
        holdout_is_private=private_holdout_enabled,
        promotion_margin_points=promotion_margin_points,
        holdout_promotion_margin_points=holdout_promotion_margin_points,
        evaluator_version=EVALUATOR_VERSION,
        baseline_artifact_hash=None,
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
    if private_holdout_enabled:
        write_frontier_manifest(
            eval_pack_path,
            updated_manifest,
            redact_private_holdout_tasks=True,
        )
        write_private_frontier_manifest(eval_pack_path, updated_manifest)
    else:
        write_frontier_manifest(eval_pack_path, updated_manifest)
    publish_public_king(
        public_root=None,
        repo_pack=repo_pack,
        mode=mode,
        submission_id=f"kata-init-{repo_pack}-{mode}",
        challenge_run_id="kata-init",
        candidate_artifact_path=str(frontier_root),
        frontier_artifact_hash=updated_modes[mode].frontier_artifact_hash or "",
        candidate_artifact_hash=updated_modes[mode].frontier_artifact_hash or "",
    )
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
    frontier_root = resolve_artifact_path(mode_config.frontier_artifact)
    candidate_root = Path(candidate_artifact_path).expanduser().resolve()
    candidate_files = load_bundle_files(candidate_root)
    replace_bundle_contents(frontier_root, candidate_files)
    frontier_hash = sha256_directory(frontier_root, include=sorted(candidate_files))
    updated_modes = dict(manifest.modes)
    updated_modes[mode] = FrontierModeConfig(
        frontier_artifact=mode_config.frontier_artifact,
        primary_tasks=mode_config.primary_tasks,
        baseline_artifact=mode_config.baseline_artifact,
        primary_task_count=mode_config.primary_task_count,
        primary_selection=mode_config.primary_selection,
        holdout_tasks=mode_config.holdout_tasks,
        holdout_task_count=mode_config.holdout_task_count,
        holdout_eval_pack=mode_config.holdout_eval_pack,
        holdout_is_private=mode_config.holdout_is_private,
        promotion_margin_points=mode_config.promotion_margin_points,
        holdout_promotion_margin_points=mode_config.holdout_promotion_margin_points,
        evaluator_version=evaluator_version or mode_config.evaluator_version or EVALUATOR_VERSION,
        baseline_artifact_hash=mode_config.baseline_artifact_hash,
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
    private_holdout_enabled = bool(
        updated_manifest.modes[mode].holdout_task_count
    ) and private_frontier_manifest_path(eval_pack_path) is not None
    if private_holdout_enabled:
        write_frontier_manifest(
            eval_pack_path,
            updated_manifest,
            redact_private_holdout_tasks=True,
        )
        write_private_frontier_manifest(eval_pack_path, updated_manifest)
    else:
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
        lines.append(f"- Frontier artifact: `{mode_config.frontier_artifact}`")
        if mode_config.primary_selection == PRIMARY_SELECTION_RANDOM_LIVE:
            lines.append(
                "- Primary tasks: "
                f"random live sample ({mode_config.primary_task_count} tasks per duel)"
            )
        else:
            lines.append(f"- Primary tasks: {', '.join(mode_config.primary_tasks)}")
        if mode_config.holdout_tasks:
            holdout_label = ", ".join(mode_config.holdout_tasks)
        elif mode_config.holdout_task_count > 0:
            holdout_label = f"private ({mode_config.holdout_task_count} tasks)"
        else:
            holdout_label = "none"
        lines.append("- Holdout tasks: " + holdout_label)
        if mode_config.frontier_updated_at:
            lines.append(f"- Frontier updated: {mode_config.frontier_updated_at}")
        if mode_config.frontier_source:
            lines.append(f"- Frontier source: {mode_config.frontier_source}")
        if mode_config.evaluator_version:
            lines.append(f"- Evaluator version: {mode_config.evaluator_version}")
        lines.append(f"- Promotion margin: {mode_config.promotion_margin_points:.1f} points")
        lines.append(
            "- Holdout margin: "
            f"{mode_config.holdout_promotion_margin_points:.1f} points"
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


def frontier_manifest_payload(
    manifest: FrontierManifest,
    *,
    redact_private_holdout_tasks: bool = False,
) -> dict[str, object]:
    payload = asdict(manifest)
    for mode_name, mode_payload in list((payload.get("modes") or {}).items()):
        if not isinstance(mode_payload, dict):
            continue
        if not mode_payload.get("baseline_artifact"):
            mode_payload.pop("baseline_artifact", None)
        if not mode_payload.get("baseline_artifact_hash"):
            mode_payload.pop("baseline_artifact_hash", None)
        primary_tasks = list(mode_payload.get("primary_tasks") or [])
        mode_payload["primary_task_count"] = int(
            mode_payload.get("primary_task_count") or len(primary_tasks)
        )
        holdout_tasks = list(mode_payload.get("holdout_tasks") or [])
        mode_payload["holdout_task_count"] = int(
            mode_payload.get("holdout_task_count") or len(holdout_tasks)
        )
        if redact_private_holdout_tasks and holdout_tasks:
            mode_payload["holdout_tasks"] = []
            mode_payload["holdout_eval_pack"] = (
                mode_payload.get("holdout_eval_pack") or manifest.eval_pack
            )
    return payload


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
    frontier_artifact = str(
        config.get("frontier_artifact") or config.get("frontier_prompt") or ""
    )
    return FrontierModeConfig(
        frontier_artifact=frontier_artifact,
        primary_tasks=list(config.get("primary_tasks") or []),
        baseline_artifact=str(config["baseline_artifact"])
        if config.get("baseline_artifact") is not None
        else None,
        primary_task_count=int(
            config.get("primary_task_count", len(list(config.get("primary_tasks") or [])))
        ),
        primary_selection=str(config.get("primary_selection") or PRIMARY_SELECTION_FIXED),
        holdout_tasks=list(config.get("holdout_tasks") or []),
        holdout_task_count=int(
            config.get("holdout_task_count", len(list(config.get("holdout_tasks") or [])))
        ),
        holdout_eval_pack=str(config["holdout_eval_pack"])
        if config.get("holdout_eval_pack") is not None
        else None,
        holdout_is_private=bool(config.get("holdout_is_private", False)),
        promotion_margin_points=float(
            config.get("promotion_margin_points", DEFAULT_PROMOTION_MARGIN_POINTS)
        ),
        holdout_promotion_margin_points=float(
            config.get(
                "holdout_promotion_margin_points",
                DEFAULT_HOLDOUT_PROMOTION_MARGIN_POINTS,
            )
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


def resolve_frontier_artifact_hash(mode_config: FrontierModeConfig) -> str:
    if mode_config.frontier_artifact_hash:
        return mode_config.frontier_artifact_hash
    artifact_root = resolve_artifact_path(mode_config.frontier_artifact)
    return sha256_directory(artifact_root, include=sorted(load_bundle_files(artifact_root)))


def timestamp_now() -> str:
    return datetime.now(UTC).isoformat()


def private_frontier_manifest_path(eval_pack_path: str) -> Path | None:
    if not os.environ.get(PRIVATE_BENCHMARKS_ROOT_ENV):
        return None
    public_eval_pack_root = resolve_eval_pack_path(eval_pack_path)
    return (
        resolve_private_eval_pack_path(public_eval_pack_root.name, require_exists=False)
        / PRIVATE_FRONTIER_FILENAME
    )
