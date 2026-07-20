from __future__ import annotations

from pathlib import Path

from kata.plugins.discovery import plugin_for_evaluator
from kata.screening.models import ScreeningFinding
from kata.screening.python_ast import (
    python_source_similarity,
    python_sources_equivalent,
)
from kata.screening.rules import hash_submission_bundle
from kata.state.artifacts import resolve_public_king_root
from kata.state.lanes import (
    lane_king_state_path,
    load_lane_king_state,
    load_pack_registry,
)
from kata.submissions.bundle import AGENT_ENTRY_FILENAME

KING_NEAR_COPY_SIMILARITY_THRESHOLD = 0.85


def screen_current_king_copycat(
    *,
    submission_root: Path,
    bundle_files: dict[str, str],
    repo_pack: str | None,
    mode: str,
    public_root: str | None = None,
) -> tuple[list[ScreeningFinding], list[ScreeningFinding], int]:
    """Return exact-copy rejects, near-copy reviews, and score contribution."""
    if not repo_pack:
        return [], [], 0
    lane_id = resolve_lane_id(repo_pack, mode, public_root=public_root)
    if lane_id is None:
        return [], [], 0
    reject_findings: list[ScreeningFinding] = []
    review_findings: list[ScreeningFinding] = []
    exact_bundle = screen_exact_bundle_copy(
        lane_id=lane_id,
        submission_root=submission_root,
        public_root=public_root,
    )
    if exact_bundle is not None:
        reject_findings.append(exact_bundle)
    candidate_agent = bundle_files.get(AGENT_ENTRY_FILENAME)
    if candidate_agent is None:
        return reject_findings, review_findings, 0
    king_agent_path = (
        resolve_public_king_root(
            public_root=public_root,
            repo_pack=repo_pack,
            mode=mode,
        )
        / AGENT_ENTRY_FILENAME
    )
    if not king_agent_path.exists():
        return reject_findings, review_findings, 0
    king_agent = king_agent_path.read_text(encoding="utf-8")
    if python_sources_equivalent(candidate_agent, king_agent):
        reject_findings.append(
            ScreeningFinding(
                rule_id="copycat.king_agent_ast",
                severity="reject",
                path=AGENT_ENTRY_FILENAME,
                line=None,
                reason="Submission agent duplicates the current lane king implementation.",
                evidence="candidate agent.py AST equals current king agent.py AST",
            )
        )
        return reject_findings, review_findings, 0
    similarity = python_source_similarity(candidate_agent, king_agent)
    if similarity >= KING_NEAR_COPY_SIMILARITY_THRESHOLD:
        review_findings.append(
            ScreeningFinding(
                rule_id="copycat.king_agent_similarity",
                severity="review",
                path=AGENT_ENTRY_FILENAME,
                line=None,
                reason=(
                    "Screening review required: submission agent is highly similar to the "
                    f"current lane king implementation (similarity {similarity:.2f})."
                ),
                evidence=(
                    f"similarity={similarity:.4f}; "
                    f"threshold={KING_NEAR_COPY_SIMILARITY_THRESHOLD:.2f}"
                ),
            )
        )
        return reject_findings, review_findings, 4
    return reject_findings, review_findings, 0


def _lane_bundle_hasher(lane_id: str, *, public_root: str | None = None):
    """The lane plugin's bundle hasher (``plugin.hash_bundle``), or the generic one.

    The king's recorded hash is produced by ``plugin.hash_bundle``; a subnet may
    override it (SN60 does), so the exact-copy comparison must hash the candidate
    with the same hasher or an identical bundle clone would never match.
    """
    try:
        registry = load_pack_registry(public_root=public_root)
    except Exception:  # noqa: BLE001 - a missing/corrupt registry falls back to generic
        return hash_submission_bundle
    for pack in registry.packs:
        if pack.lane_id == lane_id:
            plugin = plugin_for_evaluator(pack.evaluator_id)
            if plugin is not None:
                return plugin.hash_bundle
            break
    return hash_submission_bundle


def screen_exact_bundle_copy(
    *,
    lane_id: str,
    submission_root: Path,
    public_root: str | None = None,
) -> ScreeningFinding | None:
    if not lane_king_state_path(lane_id, public_root=public_root).exists():
        return None
    king = load_lane_king_state(lane_id, public_root=public_root)
    if king.current_king_artifact_hash is None:
        return None
    candidate_hash = _lane_bundle_hasher(lane_id, public_root=public_root)(submission_root)
    if candidate_hash != king.current_king_artifact_hash:
        return None
    return ScreeningFinding(
        rule_id="copycat.king_bundle_hash",
        severity="reject",
        path=None,
        line=None,
        reason="Submission bundle is an exact copy of the current lane king artifact.",
        evidence=f"candidate_hash={candidate_hash}",
    )


def resolve_lane_id(
    repo_pack: str,
    mode: str,
    *,
    public_root: str | None = None,
) -> str | None:
    registry = load_pack_registry(public_root=public_root)
    for entry in registry.packs:
        if entry.repo_pack == repo_pack and entry.mode == mode:
            return entry.lane_id
    return None
