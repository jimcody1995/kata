"""SN60 bitsec as a Kata subnet plugin (Phase 2 of the multi-subnet refactor).

This wraps the existing ``kata.evaluators.sn60_bitsec`` functions behind the
:class:`SubnetPlugin` contract. It is pure delegation -- no scoring or behavior
change -- so the golden characterization tests are unaffected. Nothing in the core
calls this yet; Phase 3 routes the generic round orchestrator through it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kata.evaluators.sn60_bitsec import (
    Sn60EvaluationHook,
    Sn60ExecutionHook,
    Sn60ReplicaResult,
    Sn60SandboxSource,
    Sn60VariantSummary,
    build_default_evaluation_hook,
    build_default_execution_hook,
    hash_bundle_root,
    resolve_sn60_sandbox_source,
    score_variant_on_projects,
    summarize_variant,
)
from kata.packages.plugin import (
    EnvSpec,
    RunContext,
    ScoreCard,
    ScoringProfile,
    SubnetPlugin,
)
from kata.validator_system.challenge import (
    SN60_MINER_LANE_ID,
    SN60_VALIDATOR_MODEL,
    evaluate_sn60_promotion,
    sn60_pass_score,
    sn60_variant_rank,
)
from kata.validator_system.project_selection import resolve_sn60_project_keys

DEFAULT_SCORER_VERSION = "ScaBenchScorerV2"


@dataclass(frozen=True)
class Sn60Problems:
    """SN60's problem set: the sampled projects + the sandbox they run against."""

    project_keys: list[str]
    sandbox_source: Sn60SandboxSource
    replicas_per_project: int
    run_id: str


@dataclass(frozen=True)
class Sn60RawRun:
    """One variant's scored replicas, before summarization."""

    variant_name: str
    artifact_root: str
    artifact_hash: str
    replica_results: list[Sn60ReplicaResult]


class Sn60BitsecPlugin(SubnetPlugin):
    """SN60 bitsec (smart-contract vulnerability detection) plugin."""

    evaluator_id = "sn60_bitsec"
    pack = SN60_MINER_LANE_ID  # "sn60__bitsec"
    mode = "miner"
    scoring_profile = ScoringProfile.DETERMINISTIC
    validator_identity = SN60_VALIDATOR_MODEL  # "sn60-bitsec-sandbox"

    def __init__(
        self,
        *,
        execution_hook: Sn60ExecutionHook | None = None,
        evaluation_hook: Sn60EvaluationHook | None = None,
        scorer_version: str = DEFAULT_SCORER_VERSION,
    ) -> None:
        # Optional hook injection for tests; production builds the real sandbox
        # (Docker) hooks from the resolved sandbox source at run time.
        self._execution_hook = execution_hook
        self._evaluation_hook = evaluation_hook
        self._scorer_version = scorer_version

    def environment_spec(self) -> EnvSpec:
        # SN60 agents run sealed except for the pinned-model inference relay.
        return EnvSpec(network="relay_only")

    def sample_problems(self, *, seed: str, config: dict[str, Any]) -> Sn60Problems:
        sandbox_source = resolve_sn60_sandbox_source(
            sandbox_root=config.get("sandbox_root"),
            benchmark_file=config.get("benchmark_file"),
            sandbox_commit=config.get("sandbox_commit"),
            scorer_version=self._scorer_version,
        )
        project_keys = resolve_sn60_project_keys(
            configured_keys=config.get("project_keys"),
            sandbox_root=config.get("sandbox_root"),
            benchmark_file=config.get("benchmark_file"),
            sandbox_commit=config.get("sandbox_commit"),
        )
        return Sn60Problems(
            project_keys=list(project_keys),
            sandbox_source=sandbox_source,
            replicas_per_project=int(config.get("replicas_per_project", 1)),
            run_id=seed,
        )

    def benchmark_identity(self, problems: Sn60Problems) -> str:
        # Deterministic profile: the benchmark is reproducible, so this is a stable,
        # non-empty identity the core can cache the king score by.
        source = problems.sandbox_source
        return f"{source.benchmark_sha256}:{source.sandbox_commit}:{source.scorer_version}"

    def run_candidate(
        self, *, agent_path: str, problems: Sn60Problems, context: RunContext
    ) -> Sn60RawRun:
        source = problems.sandbox_source
        execution_hook = self._execution_hook or build_default_execution_hook(source)
        evaluation_hook = self._evaluation_hook or build_default_evaluation_hook(source)
        artifact_root = Path(agent_path).expanduser().resolve()
        label = context.label
        replica_results = score_variant_on_projects(
            run_id=f"{problems.run_id}-{label}",
            run_root=Path(context.output_root) / label,
            variant_name=label,
            artifact_root=artifact_root,
            project_keys=problems.project_keys,
            replicas_per_project=problems.replicas_per_project,
            sandbox_source=source,
            execution_hook=execution_hook,
            evaluation_hook=evaluation_hook,
        )
        return Sn60RawRun(
            variant_name=label,
            artifact_root=str(artifact_root),
            artifact_hash=hash_bundle_root(artifact_root),
            replica_results=replica_results,
        )

    def score(self, raw: Sn60RawRun, problems: Sn60Problems) -> ScoreCard:
        summary = summarize_variant(
            variant_name=raw.variant_name,
            artifact_root=Path(raw.artifact_root),
            artifact_hash=raw.artifact_hash,
            replica_results=raw.replica_results,
        )
        return self._score_card(summary)

    @staticmethod
    def _score_card(summary: Sn60VariantSummary) -> ScoreCard:
        # The native SN60 summary drives compare()/beats_king(); it rides in `payload`
        # (opaque to the core) so `metrics` stays JSON-serializable for proofs.
        return ScoreCard(
            comparable=round(sn60_pass_score(summary), 8),
            passed=True,
            metrics={
                "aggregated_score": summary.aggregated_score,
                "codebase_pass_count": summary.codebase_pass_count,
                "true_positives": summary.true_positives,
                "total_expected": summary.total_expected,
                "total_found": summary.total_found,
                "precision": summary.precision,
                "f1_score": summary.f1_score,
                "invalid_runs": summary.invalid_runs,
            },
            payload=summary,
        )

    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        rank_a = sn60_variant_rank(a.payload)
        rank_b = sn60_variant_rank(b.payload)
        return (rank_a > rank_b) - (rank_a < rank_b)

    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        if king is None:
            return True
        decision = evaluate_sn60_promotion(king=king.payload, candidate=candidate.payload)
        return decision.promotion_ready
