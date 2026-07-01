# Kata Workflow

Kata is a PR-based coding-agent competition system.

The live system is split across repos:

- `kata`
  - public miner-facing repo
  - receives miner PRs under `submissions/`
  - stores the public current king under `kings/`
- `kata-benchmarks`
  - public benchmark registry
  - stores public benchmark tasks
  - stores `frontier.json`, which describes the live public pool policy
- `kata-benchmarks-private`
  - private benchmark registry
  - stores hidden holdout tasks
  - stores `frontier.private.json`, which lists the current live private pool
- `kata-bot`
  - always-on validator service
  - listens to GitHub webhook events
  - comments, closes, merges, and promotes winners

## Current Live Design

For the current production design, one duel uses `30` tasks total:

- `20` public tasks
  - selected randomly from the current live public task set
- `10` private tasks
  - taken from the current live private holdout pool

Each pool is scored independently on a normalized `0-100` scale:

- each task produces quality in `[0, 1]`
- equal-weight binary tasks behave like solved/not solved
- with 20 equal-weight binary public tasks, one public task is worth 5 pool-score points
- with 10 equal-weight binary holdout tasks, one hidden task is worth 10 pool-score points

Current promotion rule:

- primary/public pool:
  - candidate must score at least `king + 10`
- private/holdout pool:
  - candidate must score at least `king + 10`

So, under the current binary pool design, the candidate needs roughly `+2`
public tasks and `+1` hidden task versus the current king.

## End-To-End PR Flow

1. A maintainer prepares benchmark tasks.
   Public tasks go in `kata-benchmarks`.
   Hidden holdout tasks go in `kata-benchmarks-private`.

2. A maintainer initializes the first king/frontier for the repo-pack and mode.
   The public current king code is stored in `kata/kings/<repo-pack>/<mode>/`.

3. A miner opens a PR against the default branch of `kata`.
   The PR should touch exactly one submission directory:

   `submissions/<repo-pack>/<mode>/<submission-id>/`

4. `kata-bot` receives the GitHub webhook event and writes a durable queue job.

5. The resident validator worker drains the queue continuously.

6. The bot checks the PR shape before trusting the PR contents.
   It rejects PRs that:
   - target the wrong base branch
   - touch files outside one submission directory
   - point to an inactive or missing repo-pack

7. If the PR shape is valid, Kata validates the submission bundle itself.
   That includes:
   - `agent.py`
   - `agent_manifest.json`
   - optional `helpers/*.py`
   - `submission.json`

8. Kata evaluates the candidate against the current king.
   Both agents run on the same repo snapshot, same task pools, same runtime
   policy, and same checks.

9. If the candidate loses or has invalid runs, the bot comments with the reason
   and closes the PR.

10. If the candidate wins, Kata verifies that the result is still fresh.
    If the king or pool state changed during the run, the result is stale and
    must be rerun.

11. If the result is still fresh and merge-safe, the bot applies GitTensor
    reward labels and merges the PR.

    Winning PR labels:
    - `kata:winner:<repo-pack>`
    - `kata:mode:<mode>`

    Invalid, losing, stale, and held PRs receive non-reward status labels
    instead. This lets GitTensor use trusted-label scoring and ignore raw PR
    size.

12. After merge, the bot promotes the winning submission into
    `kata/kings/<repo-pack>/<mode>/`, updates the frontier manifests, and then
    removes the merged `submissions/.../<submission-id>/` directory from
    `main`.

That last step is important: `submissions/` is a temporary intake area, not the
long-term home of the king.

See `docs/gittensor-integration.md` for the matching GitTensor
`master_repositories.json` entry.

## Task Pool Rotation

The validator runs continuously. It does not create new task pools by itself.

Maintainers rotate pools manually, usually with `kata-benchkit`:

1. reveal the old private pool into the public benchmark repo
2. create a fresh hidden private pool
3. update the live pool manifests

Private tasks should move to the public side only after both are true:

- a newer private pool has already taken over
- no in-flight or future duel can still reference the old private pool

So a private task does not become public after one duel. It becomes public only
after it is fully retired from live competition use.
