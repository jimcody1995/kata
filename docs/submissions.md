# Submission Workflow

Kata accepts miner agents through PR submissions in the public `kata` repo.

Miners only edit `submissions/`. They do not edit `kings/`, benchmark tasks, or
validator configuration.

## Canonical Layout

Each miner PR should add or update exactly one submission directory:

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

Current scope:

- Python agent bundles
- one submission directory per PR
- one repo-pack lane per submission

## Required Files

### `agent.py`

This is the miner entrypoint.

It must define:

```python
def solve(repo_path: str, issue: str, model: str, api_base: str, api_key: str) -> dict:
    ...
```

The validator owns:

- `model`
- `api_base`
- `api_key`
- timeouts
- benchmark tasks

Current validator model:

- `Qwen3-32B`

So miners compete on agent behavior, not on private provider access.

### `agent_manifest.json`

This describes the bundle contract.

Current requirements:

- `schema_version = 1`
- `runtime = "python"`
- `entrypoint = "agent.py"`

### `helpers/*.py`

Optional helper modules may live under `helpers/`.

Current validator rule:

- only Python files under `helpers/` are allowed

### `submission.json`

This identifies the target competition lane.

Example:

```json
{
  "schema_version": 2,
  "repo_pack": "example__repo",
  "mode": "contributor",
  "submission_id": "carlos4s-20260629-01",
  "created_at": "2026-06-29T00:00:00+00:00",
  "author": "carlos4s",
  "title": "short optional title",
  "notes": "short optional notes"
}
```

Recommended identity convention:

- `author`: GitHub username
- `submission_id`: `<github-username>-YYYYMMDD-NN`

## Validation Rules

A competition PR is valid only if:

- it targets the default competition branch
- it edits one submission directory
- it changes at least one agent bundle file
- it does not edit files outside that submission directory
- `agent.py` exists and is not the scaffold placeholder
- `agent.py` defines `solve(...)`
- `agent_manifest.json` exists and matches the validator contract
- it targets a repo-pack that is active in the benchmark registry
- it targets an existing benchmark repo-pack
- the target pack already has a frontier manifest
- the target mode is configured in that frontier manifest

Current anti-cheat rules also reject:

- challenger bundles that duplicate the current king/frontier bundle
- invalid Python syntax in `agent.py` or helper modules
- symlinks inside the submission bundle
- bundles above the current file-count or size limits
- direct references to validator/provider secret env vars
- obvious hardcoded secret-like tokens

Before checking out untrusted PR content, the bot can inspect only the changed
paths:

```bash
uv run kata submission inspect-pr \
  --repo-root "$PWD" \
  --changed-path-file /path/to/changed-paths.txt
```

Validate a checked-out submission bundle:

```bash
uv run kata submission validate \
  --path submissions/<repo-pack>/<mode>/<submission-id>
```

## Evaluation Flow

After validation, Kata evaluates the candidate against the current king.

```bash
uv run kata submission evaluate \
  --path submissions/<repo-pack>/<mode>/<submission-id> \
  --agent-command "$PWD/scripts/run_python_agent_eval.sh"
```

For the current live design:

- `20` public tasks are selected randomly from the live public pool
- `10` private tasks come from the current live holdout pool
- each solved task is worth `1` point

Promotion gate:

- public pool:
  - candidate must score at least `king + 10` normalized score points
- private pool:
  - candidate must score at least `king + 10` normalized score points

With 20 equal-weight binary public tasks and 10 equal-weight binary holdout
tasks, this corresponds to roughly `+2` public tasks and `+1` hidden task.

## Stale Frontier Protection

Results are only safe to merge if the lane has not changed since evaluation.

Kata checks that with:

```bash
uv run kata submission verify \
  --path submissions/<repo-pack>/<mode>/<submission-id> \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Verification checks that:

- the submission hash still matches the evaluated candidate
- the king/frontier hash is still current
- the evaluator version is still current
- the validator model is still current
- the public and private pool fingerprints are still current
- the challenge itself is promotion-ready

If any of those drift, the result is stale and should be rerun.

## PR Decision Actions

After verification, Kata reduces the result to one PR action:

```bash
uv run kata submission decide \
  --path submissions/<repo-pack>/<mode>/<submission-id> \
  --challenge-run runs/<challenge-run>/challenge_summary.json
```

Possible actions are:

- `close-invalid`
- `close-losing`
- `rerun-stale`
- `merge`

## Promotion

If the decision is `merge`, the bot or maintainer can promote the verified
submission:

```bash
uv run kata frontier promote \
  --challenge-run <challenge-summary.json> \
  --submission-path <submission-dir>
```

The production bot does more than promotion:

1. merge the winning PR
2. update the king under `kings/<repo-pack>/<mode>/`
3. update frontier manifests
4. clear the merged `submissions/.../<submission-id>/` directory from `main`

So `submissions/` stays empty between active miner PRs, while `kings/` remains
the public source of truth for the current winner.
