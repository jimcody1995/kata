from __future__ import annotations

import re

from kata.screening_system.models import ScreeningFinding

BENCHMARK_PROJECT_ID_PATTERN = re.compile(
    r"\bcode4rena_[a-z0-9]+(?:-[a-z0-9]+)*_\d{4}_\d{2}\b",
    re.IGNORECASE,
)
BENCHMARK_FINDING_ID_PATTERN = re.compile(
    r"\b20\d{2}-\d{2}-[a-z0-9-]+_[HMS]-\d{2}\b",
    re.IGNORECASE,
)


def analyze_benchmark_replay(bundle_files: dict[str, str]) -> tuple[list[ScreeningFinding], int]:
    """Return report-mode signals for hardcoded benchmark replay.

    Phase 2 is intentionally non-blocking. These findings are review signals
    until strict replay enforcement is enabled in a later phase.
    """
    findings: list[ScreeningFinding] = []
    findings.extend(
        find_pattern_signals(
            bundle_files,
            pattern=BENCHMARK_PROJECT_ID_PATTERN,
            rule_id="benchmark_replay.project_id",
            reason_prefix="SN60 screening found a hardcoded benchmark-style project id",
            points=6,
        )
    )
    findings.extend(
        find_pattern_signals(
            bundle_files,
            pattern=BENCHMARK_FINDING_ID_PATTERN,
            rule_id="benchmark_replay.finding_id",
            reason_prefix="SN60 screening found a hardcoded benchmark finding id",
            points=6,
        )
    )
    return findings, sum(int(finding.evidence.rsplit("points=", 1)[-1]) for finding in findings)


def find_pattern_signals(
    bundle_files: dict[str, str],
    *,
    pattern: re.Pattern[str],
    rule_id: str,
    reason_prefix: str,
    points: int,
) -> list[ScreeningFinding]:
    findings: list[ScreeningFinding] = []
    seen: set[tuple[str, str]] = set()
    for relative_path, content in sorted(bundle_files.items()):
        if not relative_path.endswith(".py"):
            continue
        for match in pattern.finditer(content):
            matched = match.group(0)
            key = (relative_path, matched.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ScreeningFinding(
                    rule_id=rule_id,
                    severity="review",
                    path=relative_path,
                    line=line_for_offset(content, match.start()),
                    reason=f"{reason_prefix}: `{matched}`.",
                    evidence=f"matched={matched}; points={points}",
                )
            )
    return findings


def line_for_offset(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1
