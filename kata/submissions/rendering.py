from __future__ import annotations

import json
from dataclasses import asdict

from kata.submissions.models import (
    PullRequestInspectionResult,
    SubmissionDecisionResult,
    SubmissionValidationResult,
    SubmissionVerificationResult,
)


def render_submission_validation(result: SubmissionValidationResult) -> str:
    lines: list[str] = []
    lines.append(f"Submission: {result.submission_path}")
    if result.subnet_pack:
        lines.append(f"Subnet pack: {result.subnet_pack}")
    if result.mode:
        lines.append(f"Mode: {result.mode}")
    if result.submission_id:
        lines.append(f"Submission id: {result.submission_id}")
    if result.agent_path:
        lines.append(f"Agent file: {result.agent_path}")
    lines.append(f"Status: {'valid' if result.is_valid else 'invalid'}")
    if result.changed_paths:
        lines.append("Changed paths:")
        lines.extend(f"- {path}" for path in result.changed_paths)
    if result.off_scope_paths:
        lines.append("Off-scope paths:")
        lines.extend(f"- {path}" for path in result.off_scope_paths)
    if result.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason}" for reason in result.reasons)
    if result.screening_status:
        lines.append(f"Screening status: {result.screening_status}")
    if result.screening_review_reasons:
        lines.append("Screening review reasons:")
        lines.extend(f"- {reason}" for reason in result.screening_review_reasons)
    if result.screening_notes:
        lines.append("Screening notes:")
        lines.extend(f"- {note}" for note in result.screening_notes)
    return "\n".join(lines)


def render_pull_request_inspection(result: PullRequestInspectionResult) -> str:
    lines = [
        f"Action: {result.action}",
        f"Changed paths: {len(result.changed_paths)}",
    ]
    if result.submission_path:
        lines.append(f"Submission path: {result.submission_path}")
    if result.candidate_submission_dirs:
        lines.append("Candidate submission dirs:")
        lines.extend(f"- {path}" for path in result.candidate_submission_dirs)
    if result.reasons:
        lines.append("Reasons:")
        lines.extend(f"- {reason}" for reason in result.reasons)
    return "\n".join(lines)




def render_submission_json(
    value: SubmissionValidationResult
    | SubmissionVerificationResult
    | PullRequestInspectionResult
    | SubmissionDecisionResult,
) -> str:
    return json.dumps(asdict(value), indent=2) + "\n"
