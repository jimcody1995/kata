from __future__ import annotations

"""SN60 miner tuned for July 2026 validation rules.

Three inference calls per problem, depth-first audits on graph-ranked targets,
crash-safe execution for smoke tests and replica stability, and matcher-shaped
output. Helpers live under helpers/ per current submission rules.
"""

import time
from pathlib import Path
from typing import Any

from helpers.discovery import (
    EXT,
    build_catalog,
    graph_digest,
    hot_functions,
    import_graph,
    import_neighbors,
    rank_catalog,
    resolve_targets,
    suffix_index,
)
from helpers.findings import collapse_findings, format_finding
from helpers.llm import CallBudget, infer, load_json

TIME_BUDGET = 220.0
DEEP_CHARS = 46_000
IMPORT_CHARS = 3_200
TRIAGE_TOKENS = 4200
DEEP_TOKENS = 7600

SYSTEM = (
    "You are a senior smart-contract security auditor. Report only high or critical "
    "vulnerabilities with a concrete exploit path and material impact. Reject style, "
    "gas, centralization, and speculation. Return strict JSON only."
)

HUNT = (
    "Hunt exhaustively for: missing access control; reentrancy and CEI violations; "
    "oracle/price manipulation; LP/share accounting and rounding; slippage bypass; "
    "liquidation math; unsafe delegatecall/upgrade/initializer; signature replay; "
    "decimal mismatches; cross-function invariant breaks."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    collected: list[dict[str, Any]] = []
    try:
        collected = _run(project_dir, inference_api)
    except Exception:
        pass
    by_rel: dict[str, dict[str, Any]] = {}
    root = locate_project(project_dir)
    if root is not None:
        by_rel = {row["rel"]: row for row in build_catalog(root)}
    shaped: list[dict[str, Any]] = []
    for raw in collected:
        item = format_finding(raw, by_rel)
        if item is not None:
            shaped.append(item)
    return {"vulnerabilities": collapse_findings(shaped)}


def _run(project_dir: str | None, inference_api: str | None) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    root = locate_project(project_dir)
    if root is None:
        return collected

    clock = time.monotonic()
    catalog = build_catalog(root)
    if not catalog:
        return collected

    lookup = suffix_index(catalog)
    graph = import_graph(catalog, lookup)
    ranked = rank_catalog(catalog, graph)

    budget = CallBudget()
    targets = run_triage(inference_api, ranked, graph, budget)
    ordered = resolve_targets(targets, ranked)

    primary = ordered[:1]
    secondary = ordered[1:3]
    if time.monotonic() - clock < TIME_BUDGET and budget.can_call():
        collected.extend(deep_audit(inference_api, primary, lookup, budget))
    if time.monotonic() - clock < TIME_BUDGET and budget.can_call():
        collected.extend(deep_audit(inference_api, secondary, lookup, budget))
    return collected


def locate_project(project_dir: str | None) -> Path | None:
    options: list[str] = []
    if project_dir:
        options.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = __import__("os").environ.get(key)
        if val:
            options.append(val)
    options.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in options:
        try:
            p = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if p.is_dir() and any(f.is_file() and f.suffix.lower() in EXT for f in p.rglob("*")):
            return p
    return None


def run_triage(
    api: str | None,
    ranked: list[dict[str, Any]],
    graph: dict[str, set[str]],
    budget: CallBudget,
) -> list[str]:
    prompt = (
        "Given this import-graph ranked map, pick the files most likely to contain ALL "
        "high/critical bugs in this codebase. Return strict JSON only:\n"
        '{"target_files":["path.sol"]}\n'
        "Prioritize hub contracts, privileged entrypoints, pool/oracle/accounting logic. "
        "List 3-5 files in priority order. Do not invent paths.\n\n"
        + graph_digest(ranked, graph)
    )
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        TRIAGE_TOKENS,
        budget,
    ))
    targets = obj.get("target_files")
    if not isinstance(targets, list):
        return []
    return [str(x) for x in targets if isinstance(x, str)]


def deep_prompt(batch: list[dict[str, Any]], lookup: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit the sources below end-to-end. Find every distinct high/critical bug. "
        + HUNT + " "
        "Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"fn","line":123,"severity":"high|critical",'
        '"mechanism":"pre -> attack -> broken invariant","impact":"specific harm",'
        '"description":"2-4 sentences naming file, contract, function, mechanism, impact"}]}\n'
        "Up to 6 findings. Each must name a real function from the source. "
        "If none, return {\"findings\":[]}.\n"
    )
    parts = [header]
    room = DEEP_CHARS - len(header)
    for row in batch:
        block = (
            f"\n\n===== FILE: {row['rel']} =====\n"
            f"Contracts: {', '.join(row['contracts'][:6])}\n"
            f"Hot: {', '.join(hot_functions(str(row['text']))[:5])}\n"
            f"{row['text']}\n"
        )
        neighbors = import_neighbors(row, lookup, IMPORT_CHARS)
        if neighbors:
            block += f"\n===== IMPORT CONTEXT =====\n{neighbors}\n"
        if len(block) > room:
            block = block[: max(0, room)] + "\n/* truncated */\n"
        if room <= 0:
            break
        parts.append(block)
        room -= len(block)
    return "".join(parts)


def deep_audit(
    api: str | None,
    batch: list[dict[str, Any]],
    lookup: dict[str, dict[str, Any]],
    budget: CallBudget,
) -> list[dict[str, Any]]:
    if not batch or not budget.can_call():
        return []
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": deep_prompt(batch, lookup)}],
        DEEP_TOKENS,
        budget,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
