# Bot Integration Contract

Kata is the evaluation engine. GitHub-specific automation lives in
`kata-bot`.

## Repo Boundary

- `kata`
  - validation
  - evaluation
  - freshness checks
  - promotion decision logic
- `kata-benchmarks`
  - public benchmark tasks
  - public frontier manifest and pool policy
- `kata-benchmarks-private`
  - hidden holdout tasks
  - private frontier manifest for the live holdout pool
- `kata-bot`
  - PR webhook intake
  - queueing and retries
  - PR comments
  - PR close / merge actions
  - post-merge promotion and cleanup

## What The Bot Calls

The bot should call Kata through these commands:

1. `submission inspect-pr`
2. `submission validate`
3. `submission evaluate`
4. `submission verify`
5. `submission decide`
6. `frontier promote`

## Expected Sequence

For each miner PR, the bot should do this:

1. inspect changed paths before checking out untrusted PR contents
2. close immediately if the PR targets the wrong base branch, touches files
   outside one submission directory, or targets an inactive repo-pack
3. validate the checked-out submission bundle
4. evaluate the candidate against the current king
5. verify freshness against the latest frontier state
6. rerun once if the result is stale
7. close the PR if it loses or produces invalid task runs
8. merge the PR only if the candidate is still promotion-ready
9. promote the winning submission into `kings/...`
10. remove the merged `submissions/.../<submission-id>/` directory from `main`

The promote step should use the verified submission path together with the
recorded challenge summary, so Kata re-checks freshness before mutating
frontier state.

## Current Live Competition Rule

The current live rule is:

- `20` random public tasks from the live public pool
- `10` private holdout tasks from the live private pool
- candidate must beat the king by at least `10` normalized score points on the
  public side
- candidate must beat the king by at least `10` normalized score points on the
  holdout side

With 20 equal-weight binary public tasks and 10 equal-weight binary holdout
tasks, this corresponds to roughly `+2` public tasks and `+1` hidden task.

## Runner Requirements

The bot runner should already have:

- Python and `uv`
- a checked-out `kata` repo
- a checked-out public `kata-benchmarks` repo
- a checked-out private `kata-benchmarks-private` repo if holdouts are enabled
- the chosen agent runner installed
- read/write access to the required repos

If using the Python agent flow, the runner also needs validator-owned LLM
settings:

- `KATA_VALIDATOR_MODEL`
- `KATA_VALIDATOR_API_BASE`
- `KATA_VALIDATOR_API_KEY`

Current default validator model:

- `Qwen3-32B`

## Safety Notes

- inspect PR scope before evaluating untrusted PR content
- treat the frontier manifests plus `kata/kings/...` as the live source of truth
- rerun stale evaluations before merge if the frontier changed
- keep miner submissions away from validator/provider secret configuration
- never leave the winning submission copied in both `submissions/` and `kings/`
