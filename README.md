# Kata

Kata is a PR-based miner-agent competition engine for evaluator-backed subnet
packs, registered on GitTensor for reward distribution.

One shared engine runs the same king-vs-candidate loop on every active subnet
pack. Each pack keeps its own benchmark definition, scoring rules, and current
king, isolated under `lanes/<lane-id>/` and `kings/<subnet-pack>/<mode>/`.

The first active pack is the SN60 / Bitsec security-agent lane
(`sn60__bitsec/miner`): miners submit an `agent.py` exposing `agent_main()`
that finds critical and high severity vulnerabilities in smart contract
projects, evaluated in the pinned Bitsec sandbox mirror.

## How It Works

1. A miner opens a PR that adds exactly one submission bundle under
   `submissions/<subnet-pack>/<mode>/<submission-id>/`.
2. `kata-bot` inspects and validates the PR shape, then asks Kata to
   evaluate it.
3. Kata screens the candidate (static checks plus one sandbox execution),
   then runs the SN60 duel: candidate vs current king, repeated replica runs
   per benchmark codebase.
4. The promotion comparator is aggregated score first, codebases passed
   second, true positives third. Candidates with invalid replica runs never
   promote.
5. Verified winners are merged, labeled for GitTensor rewards, published to
   `kings/<subnet-pack>/<mode>/`, and recorded in the lane state.

## Repo Layout

- `kata/` — engine: lane state, pack registry, screening, SN60 evaluator
  adapter, submission validation, promotion.
- `lanes/` — central pack registry (`registry.json`) plus per-lane state
  (`lane.json`, `king.json`, `benchmark_snapshot.json`, `challenge_state.json`,
  `promotion_record.json`).
- `kings/` — the published current king artifact per pack and mode.
- `submissions/` — PR-submitted candidate bundles.
- `runs/` — duel artifacts with reproducible provenance.

## CLI

```bash
# register a subnet pack
uv run kata lane init --lane-id sn60__bitsec --evaluator-id sn60_bitsec

# list active packs from the central registry
uv run kata lane list --active-only

# scaffold and validate a miner submission
uv run kata submission init --subnet-pack sn60__bitsec --mode miner --submission-id you-20260702-01
uv run kata submission validate --path submissions/sn60__bitsec/miner/you-20260702-01

# run a duel (requires Docker and the pinned sandbox; tasks come from the benchmark)
uv run kata submission evaluate \
  --path submissions/sn60__bitsec/miner/you-20260702-01 --json

# verify, decide, and promote
uv run kata submission verify --path <submission> --challenge-run <summary>
uv run kata submission decide --path <submission> --challenge-run <summary>
uv run kata king promote --challenge-run <summary> --submission-path <submission>
```

## Environment

- `KATA_ROOT` — kata root that owns `lanes/` and `kings/` (defaults to this repo).
- `KATA_SN60_SANDBOX_ROOT` — pinned Bitsec sandbox mirror checkout.
- `KATA_SN60_PROJECT_KEYS` — optional comma-separated project-key override; by
  default Kata evaluates every `project_id` in the resolved SN60 benchmark.
- `INFERENCE_API_KEY` — miner execution key (injected per submission by the bot).
- `CHUTES_API_KEY` — validator-owned scoring key, never shared with miner code.

## Development

```bash
uv run --extra dev python -m pytest
uv run --extra dev python -m ruff check kata tests
```

See `docs/` for the submission contract, system workflow, and GitTensor
integration, and the `kata-bot` / `kata-board` repos for automation and the
dashboard.
