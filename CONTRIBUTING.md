# Contributing to PromptForge

PromptForge is an objective prompt-optimization repo. Contributions should make
the evaluator, benchmark packs, or prompt competition workflow more trustworthy
and more useful.

## Priorities

- Keep scoring objective and reproducible.
- Prefer pinned tasks and explicit checks over subjective judgment.
- Treat benchmark and evaluator correctness as higher priority than prompt style.
- Keep changes scoped and easy to audit.

## Local checks

Run these before opening a PR:

```bash
uv run pytest
uv run ruff check
uv run python -m promptforge eval-pack validate --path evals/e35ventura__taopedia-articles
```

If you change the benchmark runner or reporting logic, add or update tests.

## Benchmark packs

Eval-pack tasks should be based on real repo work where possible:

- real issues
- real PR-sized edits
- pinned commits
- explicit pass/fail checks
- explicit allowed and forbidden paths when task scope matters

Do not commit placeholder scaffold tasks as if they were live benchmarks.

## Prompt competition model

PromptForge uses three prompt roles:

- `baseline`: fixed generic control prompt
- `frontier`: current best verified prompt for a repo and mode
- `challenger`: new candidate prompt trying to replace the frontier

A challenger should only be promoted when it beats the frontier on the primary
pool and, when configured, on the holdout pool.

## Scope guidance

Good contributions:

- stronger eval-pack checks
- better task coverage
- clearer baseline/frontier/challenger workflow
- safer reporting and anti-gaming logic
- better contributor and reviewer prompt generation

Lower-priority contributions:

- broad prompt rewrites without benchmark evidence
- subjective prompt-style changes without measured improvement

