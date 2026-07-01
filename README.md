# Kata

Kata is an objective coding-agent competition repo for SN74/Gittensor.

It evaluates repo-specific challenger artifacts on pinned benchmark tasks and
only calls a challenger better when it solves more verified work under the same
conditions.

Kata is not just an agent scaffold repo. The main product is the evaluation
and competition system:

- fixed benchmark tasks
- fixed lane state
- current king/frontier artifact
- challenger agent evaluation
- objective promotion rules
- public king visibility with private live benchmark storage

## What It Does

Kata currently supports:

- repo-specific benchmark lanes
- eval-pack validation for pinned repo tasks
- objective eval runs using real agent commands
- king/challenger competition flow
- primary and holdout task pools
- frontier promotion after a successful challenge
- PR-submission scaffolding and validation for miner challenger agents
- stale-result verification against the current frontier
- PR decision primitives for external bot workflows

Current boundary:

- it is the evaluation engine
- it has the engine primitives for PR-based challenger submissions
- it is not the GitHub bot itself
- always-on GitHub automation lives in `kata-bot`

Transition note:

- miner submissions now use the agent bundle contract:
  `agent.py`, `agent_manifest.json`, and optional `helpers/*.py`
- frontier lane state now uses seeded agent artifacts

## Current MVP Scope

SN74/Gittensor may register many target repos over time.

Kata does not need to activate all of them on day one. The current MVP
is intentionally constrained to one active repo-pack:

- `e35ventura__taopedia-articles`

The benchmark registry controls that active set. Later expansion should happen
by adding more benchmark packs and then updating registry metadata, not by
rewriting the evaluator.

## Core Idea

A challenger only improves if it performs better on controlled repo tasks:

- same repo snapshot
- same task definition
- same agent command
- same model and budget
- same checks
- challenger artifact is the variable

Agent quality is measured by task success, path-policy compliance, and any
other behavior encoded directly in the benchmark checks.

See [docs/benchmark-evaluation.md](docs/benchmark-evaluation.md) for the
benchmark contract, current weakness, and required oracle standard.

Current validator runtime policy:

- validator-owned base model: `Qwen3-32B`
- validator-owned API base and API key
- validator-owned timeouts and benchmark tasks
- validator runs only tasks that are currently marked `live`
- agent/check commands receive a narrowed runtime env instead of the full host env

## Competition Model

Kata uses two competition roles for each repo and mode:

- `frontier`: current best verified artifact
- `challenger`: new candidate agent

Competition flow:

1. initialize a frontier manifest for a repo and mode
2. evaluate `frontier` and `challenger` on the same public pool
3. if the challenger clears the public margin, evaluate on the holdout pool
4. only promote if the challenger also clears the holdout margin

Current live Taopedia rule:

- total tasks per duel: `30`
- public pool: `20` tasks selected randomly from the live public task set
- holdout pool: `10` live private tasks
- candidate must score at least `frontier + 10` on the public pool
- candidate must score at least `frontier + 10` on the holdout pool

With 20 equal-weight binary public tasks, one public task is worth 5 points.
With 10 equal-weight binary holdout tasks, one hidden task is worth 10 points.
This means the candidate needs roughly `+2` public tasks and `+1` hidden task
versus the current frontier.

## Benchmark Provenance

Kata now records benchmark provenance alongside eval and challenge
results:

- evaluator version
- artifact hashes
- task ids
- task-pool fingerprints

This matters because a frontier win is only meaningful if it was measured
against the same evaluator and the same benchmark state. See
`docs/evaluator-versioning.md` for the intended model.

Kata's proposed benchmark score model is defined in
`docs/SCORING.md`.

## How To Think About The Workflow

Kata currently has two separate jobs:

1. `initialize lane state`
   Seed the starting frontier artifact for a repo lane.
2. `evaluate challengers`
   Compare frontier and challenger artifacts on the same benchmark.

That is why the repo has both initialization helpers and competition commands.
Today, initialization still uses source-grounded repo analysis to seed the
first king/frontier agent, but the competition itself is agent-vs-agent.

The simplest mental model is:

- `frontier`: current best verified artifact
- `challenger`: new candidate agent

Public/private visibility model:

- `kata` is the public miner-facing repo
- the current king is mirrored publicly under `kings/<repo-pack>/<mode>/`
- live public tasks are stored in the public benchmark registry
- live private holdout tasks are stored only in the private benchmark registry
- retired tasks may be exported into public `public_archive/` only after they
  leave all live pool versions permanently

The usual workflow is:

1. define public and private benchmark pools
2. initialize a frontier for that repo and mode
3. accept miner PRs under `submissions/`
4. challenge the frontier with candidate agents
5. promote the challenger only if it wins under the live public/private rules

## Repository Layout

- `kata/`: current core package and CLI
- external `kata-benchmarks` repo: public benchmark source
- external `kata-benchmarks-private` repo: hidden holdout benchmark source
- external `kata-bot` repo: GitHub integration and PR orchestration
- `submissions/`: miner challenger agents submitted by PR
- `kings/`: public mirror of the currently promoted king per repo/mode
- `public_archive/`: public archive of retired benchmark tasks
- `scripts/`: adapter commands for real agent evaluation
- `tests/`: regression tests for evaluator behavior

Tracked benchmark artifacts include:

- public `frontier.json` in `kata-benchmarks`
- private `frontier.private.json` in `kata-benchmarks-private`

Live king code is stored in:

- `kings/<repo-pack>/<mode>/`

Generated eval runs are written to `runs/` and are ignored by git.

## Submission Model

Miner challenger PRs belong in this repo, not in the benchmark registry repo.

The submission layout is:

```text
submissions/
  <repo-pack>/
    <mode>/
      <submission-id>/
        agent.py
        agent_manifest.json
        helpers/*.py
        submission.json
```

Current validation rules:

- PRs should only touch one submission directory
- only bundle files and `submission.json` are allowed inside that submission
- the repo-pack must be active in the benchmark registry
- the target repo pack must already exist in the benchmark registry
- the target mode must already be configured in that pack's `frontier.json`
- `agent.py` must define `solve(...)`
- `agent_manifest.json` must match the validator bundle contract
- bundle Python files must parse cleanly
- bundle files must stay within validator size/count limits
- bundle files must not contain symlinks
- bundle files must not reference validator/provider secret env vars directly
- bundle files must not contain obvious hardcoded secret tokens
- challenger bundles must not duplicate the current king/frontier artifact

Recommended identity convention:

- `author`: GitHub username
- `submission_id`: `<github-username>-YYYYMMDD-NN`

This is the base contract for future PR auto-close and auto-merge automation.

See `docs/submissions.md` for the detailed submission contract and stale-result
verification flow. See `docs/github-automation.md` for the intended bot
integration contract.

## GitTensor Reward Adapter

Kata should be registered in GitTensor as a trusted-label repository, not as a
raw PR-size scoring target.

The intended adapter is:

- invalid, losing, and stale candidate PRs are closed
- only confirmed promotion winners are merged
- `kata-bot` applies `kata:winner:<repo-pack>` and `kata:mode:<mode>` labels
  before merging a winner
- GitTensor is configured with `fixed_base_score`, `default_label_multiplier:
  0.0`, and winner-label multipliers

So GitTensor rewards objective Kata promotion events. Its time decay then makes
newer king promotions score higher than older promotions. See
`docs/gittensor-integration.md` for the registry entry and operational rules.

## Benchmark Registry

Kata expects benchmark packs to live in a dedicated benchmark registry
repo.

The registry repo is identified by a marker file:

- `kata-benchmark-registry.json`

The benchmark packs then live under that repo's configured benchmarks directory,
normally:

- `<registry-root>/benchmarks/<repo-pack>/...`

The registry can also declare the current active competition subset:

- `active_repo_packs`
- `default_repo_pack`

That benchmark state is split like this:

- `kata-benchmarks`
  - benchmark task folders
  - `frontier.json`
  - public-task pool metadata
- `kata-benchmarks-private`
  - hidden holdout tasks
  - `frontier.private.json`

The current king code is not stored in either benchmark repo. It is stored in
`kata/kings/...`.

Kata still uses the same file-based task format, but the benchmark
content should live in the benchmark registry repo, not inside the main
Kata repo.

Kata resolves the registry in this order:

1. `KATA_BENCHMARKS_ROOT`
2. an explicitly passed filesystem path
3. automatic discovery of a nearby repo that contains
   `kata-benchmark-registry.json`

`KATA_BENCHMARKS_ROOT` should point to either:

- the registry repo root
- the registry's `benchmarks/` directory

Inspect the resolved registry state with:

```bash
uv run kata registry show
```

`--eval-pack` accepts either:

- a direct filesystem path
- a pack id under the benchmark registry, such as `e35ventura__taopedia-articles`

## Benchmark State

This branch does not currently ship a tracked live benchmark pack inside the
main Kata repo.

To run Kata end to end, you should first create or add a repo-specific
eval pack in your benchmark registry repo, then initialize a frontier for it.

At minimum, that means:

- one repo-specific pack under `<registry-root>/benchmarks/`
- valid benchmark task files
- a frontier manifest created with `kata frontier init`

## Quickstart

Validate the benchmark pack:

```bash
uv run kata eval-pack validate \
  --path <repo-pack>
```

Initialize the lane frontier for the repo and mode:

```bash
uv run kata frontier init \
  --repo /path/to/target-repo \
  --eval-pack <repo-pack> \
  --mode contributor
```

Challenge the current frontier with a challenger agent bundle:

```bash
uv run kata challenge \
  --eval-pack <repo-pack> \
  --mode contributor \
  --candidate-agent path/to/agent.py \
  --agent-command "$PWD/scripts/run_python_agent_eval.sh"
```

## Submission Workflow

Scaffold a challenger submission:

```bash
uv run kata submission init \
  --repo-pack <repo-pack> \
  --mode contributor \
  --submission-id carlos4s-20260630-01 \
  --author carlos4s
```

Validate a submission and its PR-style changed paths:

```bash
uv run kata submission validate \
  --path submissions/<repo-pack>/contributor/carlos4s-20260630-01 \
  --changed-path submissions/<repo-pack>/contributor/carlos4s-20260630-01/agent.py \
  --changed-path submissions/<repo-pack>/contributor/carlos4s-20260630-01/submission.json
```

Inspect a PR diff before checking out the PR branch:

```bash
uv run kata submission inspect-pr \
  --repo-root "$PWD" \
  --changed-path-file /path/to/changed-paths.txt
```

Evaluate the challenger against the current frontier:

```bash
uv run kata submission evaluate \
  --path submissions/<repo-pack>/contributor/carlos4s-20260630-01 \
  --agent-command "$PWD/scripts/run_python_agent_eval.sh"
```

Verify that the result is still current before merge:

```bash
uv run kata submission verify \
  --path submissions/<repo-pack>/contributor/carlos4s-20260630-01 \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

That final verification step matters because a challenger result becomes stale
if another PR has already replaced the frontier.

Convert verification into a PR action:

```bash
uv run kata submission decide \
  --path submissions/<repo-pack>/contributor/carlos4s-20260630-01 \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Possible actions are:

- `close-invalid`
- `close-losing`
- `rerun-stale`
- `merge`

## Frontier Workflow

Initialize a frontier manifest:

```bash
uv run kata frontier init \
  --repo /path/to/target-repo \
  --eval-pack <repo-pack> \
  --mode contributor
```

`--primary-task` and `--holdout-task` are optional explicit overrides. The
current live Taopedia design instead uses `20` random public live tasks plus
`10` private holdout tasks from the configured manifests.

Inspect the current frontier:

```bash
uv run kata frontier show \
  --eval-pack <repo-pack> \
  --mode contributor
```

Challenge the frontier:

```bash
uv run kata challenge \
  --eval-pack <repo-pack> \
  --mode contributor \
  --candidate-agent path/to/agent.py \
  --agent-command "$PWD/scripts/run_python_agent_eval.sh"
```

Promote a winning challenger:

```bash
uv run kata frontier promote \
  --challenge-run runs/<challenge-run>/challenge_summary.json \
  --submission-path submissions/<repo-pack>/<mode>/<submission-id>
```

## Real Agent Commands

This repo includes the Python agent adapter used by the current competition
flow:

- `scripts/run_python_agent_eval.sh`

That runner loads `agent.py`, passes the validator-owned runtime settings, and
applies the returned patch inside the eval workspace.

## Open-Source Status

Kata is ready to be public as a framework-level MVP.

What is already solid:

- the core objective-eval design
- benchmark-pack validation
- stricter report and path-policy handling
- frontier challenge workflow
- evaluator-version and benchmark-provenance recording
- validator-owned `Qwen3-32B` runtime policy
- submission anti-cheat and bundle-policy validation
- seeded initial king/frontier agent initialization
- regression tests for evaluator behavior

What is still planned:

- larger benchmark coverage
- stronger reviewer-mode examples
- stronger anti-cheat and bundle-policy validation
- stronger maintainer-owned evaluator protection

## Development

Run the current checks:

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.
