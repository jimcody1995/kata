# PromptForge

PromptForge is an objective prompt-optimization repo for SN74/Gittensor.

It evaluates repo-specific agent prompts on pinned benchmark tasks and only
calls a prompt better when it solves more verified work under the same
conditions.

PromptForge is not a prompt library. The main product is the evaluation system:

- fixed benchmark tasks
- fixed baseline prompt
- current frontier prompt
- challenger prompt evaluation
- objective promotion rules

## What It Does

PromptForge currently supports:

- repo-specific prompt generation from repo sources
- fixed generic baseline prompts
- eval-pack validation for pinned repo tasks
- objective eval runs using real agent commands
- baseline/frontier/challenger competition flow
- primary and holdout task pools
- manual frontier promotion after a successful challenge

Current MVP boundary:

- it is a working manual competition system
- it is not yet an automated challenger queue
- it is not yet a full prompt-search engine

## Core Idea

A prompt only improves if it performs better on controlled repo tasks:

- same repo snapshot
- same task definition
- same agent command
- same model and budget
- same checks
- prompt is the variable

Prompt quality is measured by task success, path-policy compliance, and any
other behavior encoded directly in the benchmark checks. It is not judged by
wording quality alone.

## Competition Model

PromptForge uses three prompt roles for each repo and mode:

- `baseline`: fixed generic control prompt
- `frontier`: current best verified prompt
- `challenger`: new candidate prompt

Competition flow:

1. initialize a frontier manifest for a repo and mode
2. evaluate `baseline`, `frontier`, and `challenger` on the same primary pool
3. if the challenger beats the frontier, retest on the holdout pool
4. only promote if the challenger also beats the frontier on holdout

The baseline is not the prompt miners should use in production. It is the fixed
control used to prove that repo-specific optimization is adding value.

## Repository Layout

- `promptforge/`: core package and CLI
- `evals/`: benchmark packs for registered repos
- `scripts/`: adapter commands for real agent evaluation
- `tests/`: regression tests for evaluator behavior

Tracked benchmark artifacts may also include:

- `frontier.json`: repo competition manifest
- `prompts/<mode>/baseline.md`
- `prompts/<mode>/frontier.md`

Generated eval runs are written to `runs/` and are ignored by git.

## Current Benchmark

Current live example benchmark pack:

- `e35ventura/taopedia-articles`

Current contributor tasks:

- `add-delayed-proxies-article`
- `clarify-subnet-77-identity-mapping`
- `clarify-validator-take-vs-stake-weight`

The tracked frontier manifest is:

- `evals/e35ventura__taopedia-articles/frontier.json`

That manifest currently defines:

- a fixed contributor baseline prompt
- a contributor frontier prompt
- a primary task pool
- a holdout task pool

## Quickstart

Generate a repo-specific prompt:

```bash
uv run python -m promptforge generate \
  --repo https://github.com/e35ventura/taopedia-articles.git \
  --mode contributor
```

Generate the fixed baseline prompt:

```bash
uv run python -m promptforge baseline \
  --repo https://github.com/e35ventura/taopedia-articles.git \
  --mode contributor
```

Validate the benchmark pack:

```bash
uv run python -m promptforge eval-pack validate \
  --path evals/e35ventura__taopedia-articles
```

Run a baseline-vs-generated eval:

```bash
uv run python -m promptforge eval \
  --repo https://github.com/e35ventura/taopedia-articles.git \
  --eval-pack evals/e35ventura__taopedia-articles \
  --mode contributor \
  --agent-command "$PWD/scripts/run_codex_eval.sh"
```

Render an eval report:

```bash
uv run python -m promptforge report --run <run-id>
```

## Frontier Workflow

Initialize a frontier manifest:

```bash
uv run python -m promptforge frontier init \
  --repo https://github.com/e35ventura/taopedia-articles.git \
  --eval-pack evals/e35ventura__taopedia-articles \
  --mode contributor \
  --primary-task add-delayed-proxies-article \
  --primary-task clarify-validator-take-vs-stake-weight \
  --holdout-task clarify-subnet-77-identity-mapping
```

Inspect the current frontier:

```bash
uv run python -m promptforge frontier show \
  --eval-pack evals/e35ventura__taopedia-articles \
  --mode contributor
```

Challenge the frontier:

```bash
uv run python -m promptforge challenge \
  --eval-pack evals/e35ventura__taopedia-articles \
  --mode contributor \
  --candidate-prompt path/to/candidate.md \
  --agent-command "$PWD/scripts/run_codex_eval.sh"
```

Promote a winning challenger:

```bash
uv run python -m promptforge frontier promote \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

## Real Agent Commands

This repo includes two adapter scripts:

- `scripts/run_codex_eval.sh`
- `scripts/run_claude_eval.sh`

Optional model overrides:

```bash
PROMPTFORGE_CODEX_MODEL=o3 uv run python -m promptforge eval ...
PROMPTFORGE_CLAUDE_MODEL=sonnet uv run python -m promptforge eval ...
```

These adapters assume the corresponding CLI is already installed and
authenticated.

## Open-Source Status

PromptForge is ready to be public as an MVP.

What is already solid:

- the core objective-eval design
- benchmark-pack validation
- stricter report and path-policy handling
- frontier challenge workflow
- regression tests for evaluator behavior

What is still planned:

- automated challenger submission and queueing
- automated promotion policy
- larger benchmark coverage
- stronger reviewer-mode examples
- prompt-search automation beyond manual challenger prompts
- stronger maintainer-owned evaluator protection

## Development

Run the current checks:

```bash
uv run pytest
uv run ruff check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
