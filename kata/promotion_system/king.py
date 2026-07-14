from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from kata.screening_system.rules import hash_submission_bundle
from kata.state_system.lane import (
    KING_STATE_SCHEMA_VERSION,
    LaneKingState,
    PackRegistryEntry,
    lane_king_state_path,
    load_lane_king_state,
    load_pack_registry,
    write_lane_king_state,
)
from kata.state_system.public_artifacts import (
    publish_public_king,
    resolve_kata_root,
    resolve_public_king_root,
)
from kata.submission_system import SUBMISSION_AGENT_FILENAME, SubmissionMetadata


@dataclass(frozen=True)
class LanePromotionResult:
    lane_id: str
    king_root: str
    king: LaneKingState


def find_evaluator_pack_entry(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> PackRegistryEntry | None:
    # A missing registry loads as empty (returns None below); a corrupt registry
    # must surface loudly so production does not close valid PRs for the wrong
    # reason.
    registry = load_pack_registry(public_root=public_root)
    for pack in registry.packs:
        if pack.repo_pack == repo_pack and pack.mode == mode:
            return pack
    return None


def validate_submission_lane(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> list[str]:
    entry = find_evaluator_pack_entry(repo_pack, mode, public_root=public_root)
    if entry is None:
        return [
            f"No evaluator-backed lane is registered in the pack registry for `{repo_pack}/{mode}`."
        ]
    if not entry.active:
        return [f"Evaluator-backed lane is not active in the pack registry: {entry.lane_id}"]
    return []


def resolve_lane_king_hash(
    lane_id: str,
    *,
    repo_pack: str,
    mode: str,
    public_root: str | None = None,
) -> str | None:
    """Resolve the current king artifact hash for a registry-backed SN60 lane."""
    if lane_king_state_path(lane_id, public_root=public_root).exists():
        king = load_lane_king_state(lane_id, public_root=public_root)
        if king.current_king_artifact_hash:
            return king.current_king_artifact_hash
    king_root = resolve_public_king_root(public_root=public_root, repo_pack=repo_pack, mode=mode)
    if (king_root / SUBMISSION_AGENT_FILENAME).exists():
        return hash_submission_bundle(king_root)
    return None


def resolve_sn60_king_artifact(metadata: SubmissionMetadata) -> tuple[str, str]:
    """Resolve (lane_id, king_artifact_path) for an SN60 duel from the pack registry."""
    entry = find_evaluator_pack_entry(metadata.repo_pack, metadata.mode)
    if entry is None:
        raise ValueError(
            f"No evaluator-backed lane is registered for `{metadata.repo_pack}/{metadata.mode}`."
        )
    king_root = resolve_public_king_root(
        public_root=None,
        repo_pack=metadata.repo_pack,
        mode=metadata.mode,
    )
    if not (king_root / SUBMISSION_AGENT_FILENAME).exists():
        raise ValueError(
            f"SN60 lane king artifact is not seeded: {king_root}. "
            "Seed the current king under kings/<subnet-pack>/<mode>/ before running duels."
        )
    return entry.lane_id, str(king_root)


def promote_lane_king(
    *,
    entry: PackRegistryEntry,
    verification,
    summary,
    public_root: str | None = None,
) -> LanePromotionResult:
    from kata.packages.dispatch import plugin_for_evaluator

    plugin = plugin_for_evaluator(entry.evaluator_id)
    if plugin is not None:
        # The lane's plugin persists any subnet-specific provenance (SN60: challenge
        # state + benchmark snapshot + promotion record); the core stays subnet-blind.
        plugin.record_promotion_provenance(
            entry=entry,
            verification=verification,
            summary=summary,
            public_root=public_root,
        )
    published = publish_public_king(
        public_root=str(resolve_kata_root(public_root)),
        repo_pack=verification.repo_pack,
        mode=verification.mode,
        submission_id=verification.submission_id,
        challenge_run_id=summary.run_id,
        candidate_artifact_path=verification.submission_path,
        candidate_artifact_hash=verification.candidate_artifact_hash,
        # Hash the published king the way the subnet's round does, so king_is_current
        # stays true even for non-normalized submissions.
        artifact_hasher=plugin.hash_bundle if plugin is not None else hash_submission_bundle,
    )
    now = datetime.now(UTC).isoformat()
    king = LaneKingState(
        schema_version=KING_STATE_SCHEMA_VERSION,
        current_king_submission_id=verification.submission_id,
        current_king_artifact_hash=published.king_artifact_hash,
        promotion_source_pr=None,
        promotion_timestamp=now,
        updated_at=now,
    )
    write_lane_king_state(entry.lane_id, king, public_root=public_root)
    return LanePromotionResult(
        lane_id=entry.lane_id,
        king_root=str(published.king_root),
        king=king,
    )
