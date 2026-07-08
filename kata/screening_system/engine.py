from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

from kata.agent_bundle import load_bundle_files
from kata.screening import validate_sn60_static_screening
from kata.screening_system.benchmark_replay import (
    analyze_benchmark_replay,
    is_concrete_replay_finding,
)
from kata.screening_system.llm_review import review_suspicious_submission_with_llm
from kata.screening_system.models import ScreeningDecision, ScreeningFinding

STRICT_REPLAY_ENV = "KATA_SCREENING_STRICT_REPLAY"
REVIEW_MODE_ENV = "KATA_SCREENING_REVIEW_MODE"


def screen_submission(
    *,
    submission_root: Path,
    changed_paths: list[str] | None = None,
    repo_root: Path | None = None,
    public_root: Path | None = None,
    pr_author: str | None = None,
    mode: str = "miner",
    enable_review: bool | None = None,
    strict_replay: bool | None = None,
) -> ScreeningDecision:
    """Run the screening subsystem for a candidate submission.

    Phase 1 intentionally preserves current behavior: it wraps the existing SN60
    static screening checks in a structured decision object. The extra arguments
    are part of the stable subsystem API and will be used by later layers.
    """
    del changed_paths, repo_root, public_root, pr_author
    if mode != "miner":
        return ScreeningDecision(status="pass")

    reject_findings = [
        ScreeningFinding(
            rule_id="sn60.static",
            severity="reject",
            path="agent.py",
            line=None,
            reason=reason,
            evidence=reason,
        )
        for reason in validate_sn60_static_screening(submission_root)
    ]
    bundle_files = load_bundle_files(submission_root)
    review_findings, review_score = analyze_benchmark_replay(bundle_files)
    notes: list[ScreeningFinding] = []
    if resolve_strict_replay(strict_replay):
        concrete_findings = [
            finding for finding in review_findings if is_concrete_replay_finding(finding)
        ]
        reject_findings.extend(promote_replay_findings(concrete_findings))
        review_findings = [
            finding for finding in review_findings if not is_concrete_replay_finding(finding)
        ]
    if reject_findings:
        return ScreeningDecision(
            status="reject",
            reject_reasons=reject_findings,
            review_reasons=review_findings,
            notes=notes,
            score=review_score,
        )
    llm_findings, llm_notes = review_suspicious_submission_with_llm(
        submission_root=submission_root,
        bundle_files=bundle_files,
        decision=ScreeningDecision(
            status="review" if review_findings else "pass",
            review_reasons=review_findings,
            score=review_score,
        ),
    )
    review_findings.extend(llm_findings)
    notes.extend(llm_notes)
    if review_findings and resolve_review_mode(enable_review):
        return ScreeningDecision(
            status="review",
            review_reasons=review_findings,
            notes=notes,
            score=review_score,
        )
    return ScreeningDecision(
        status="pass",
        review_reasons=review_findings,
        notes=notes,
        score=review_score,
    )


def resolve_strict_replay(value: bool | None) -> bool:
    if value is not None:
        return value
    raw = os.environ.get(STRICT_REPLAY_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def resolve_review_mode(value: bool | None) -> bool:
    if value is not None:
        return value
    raw = os.environ.get(REVIEW_MODE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def promote_replay_findings(findings: list[ScreeningFinding]) -> list[ScreeningFinding]:
    return [
        replace(
            finding,
            severity="reject",
            reason=(
                "SN60 screening rejected hardcoded benchmark replay: "
                + finding.reason.partition(": ")[2]
            ),
        )
        for finding in findings
    ]
