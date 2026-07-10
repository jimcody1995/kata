from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

EXT = (".sol", ".vy", ".rs")
SKIP_GLOBAL = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors", "target",
})
SKIP_IN_SRC = frozenset({"test", "tests", "mock", "mocks"})

RE_FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
RE_FUNC_VY = re.compile(
    r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:",
    re.MULTILINE,
)
RE_FUNC_RS = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[(<]")
RE_CONTRACT = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface|module|struct|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_IMPORT = re.compile(r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?', re.MULTILINE)
RE_STATE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\\[\\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)
RE_RISK = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"onlyOwner|onlyRole|upgradeTo|initialize|withdraw|redeem|borrow|liquidat|"
    r"transferFrom|ecrecover|permit|oracle|flash|swap|slippage|reentr|"
    r"slot0|latestRoundData|add_liquidity|remove_liquidity|get_dy|virtual_price)\b",
    re.IGNORECASE,
)
RE_EXTERNAL_FN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s+"
    r"(?:public|external)\b[^;{]*",
    re.MULTILINE | re.IGNORECASE,
)

MAX_FILES = 70
MAX_BYTES = 260_000
DIGEST_CHARS = 14_000

PATH_HINTS = (
    "vault", "pool", "router", "bridge", "proxy", "oracle", "govern", "treasury",
    "manager", "market", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "token", "staking", "reward", "factory", "escrow", "swap", "stable",
    "liquidity", "liquidat",
)


def should_skip_dir(parts: tuple[str, ...]) -> bool:
    if not parts:
        return False
    in_src = "src" in {p.lower() for p in parts}
    for part in parts:
        low = part.lower()
        if in_src:
            if low in SKIP_IN_SRC:
                return True
        elif low in SKIP_GLOBAL:
            return True
    return False


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_functions(text: str, suffix: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if suffix == ".vy":
        for m in RE_FUNC_VY.finditer(text):
            ret = f" -> {m.group(3).strip()}" if m.group(3) else ""
            out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}){ret}".strip()})
    elif suffix == ".rs":
        for m in RE_FUNC_RS.finditer(text):
            out.append({"name": m.group(1), "sig": m.group(1)})
    else:
        for m in RE_FUNC_SOL.finditer(text):
            tail = " ".join(m.group(3).split())
            out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}) {tail}".strip()})
    return out


def hot_functions(text: str) -> list[str]:
    hits: list[str] = []
    for m in RE_EXTERNAL_FN.finditer(text):
        sig = " ".join(m.group(0).split())
        if RE_RISK.search(sig):
            hits.append(sig[:150])
        elif len(hits) < 6:
            hits.append(sig[:150])
        if len(hits) >= 10:
            break
    return hits


def risk_score(rel: str, text: str, graph: dict[str, set[str]]) -> int:
    name_low, text_low = rel.lower(), text.lower()
    score = min(text_low.count("function ") + text_low.count("\ndef ") + text_low.count("\nfn "), 34)
    score += min(len(graph.get(rel, set())), 8) * 4
    for hint in PATH_HINTS:
        if hint in name_low:
            score += 9
        elif hint in text_low:
            score += 2
    score += min(len(RE_RISK.findall(text)), 20) * 3
    if any(tok in text_low for tok in ("external", "public", "@external", "pub fn")):
        score += 5
    if "initializer" in text_low or "upgrade" in text_low:
        score += 5
    return score


def state_names(text: str) -> list[str]:
    seen: list[str] = []
    for name in RE_STATE.findall(text):
        if name not in seen and len(name) < 42:
            seen.append(name)
    return seen[:14]


def risk_snippets(text: str) -> list[str]:
    lines: list[str] = []
    for num, line in enumerate(text.splitlines(), start=1):
        if RE_RISK.search(line):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{num}: {compact[:160]}")
        if len(lines) >= 14:
            break
    return lines


def build_catalog(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXT:
            continue
        try:
            rel_path = path.relative_to(root)
            if should_skip_dir(tuple(rel_path.parts[:-1])):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = read_text(path)
        suffix = path.suffix.lower()
        if suffix == ".rs":
            has_code = "fn " in text or "pub fn" in text
        else:
            has_code = any(tok in text for tok in ("function", "contract ", "library ", "\ndef "))
        if not has_code:
            continue
        rel = rel_path.as_posix()
        contracts = RE_CONTRACT.findall(text)
        if not contracts:
            contracts = [path.stem]
        rows.append({
            "rel": rel,
            "text": text,
            "suffix": suffix,
            "contracts": contracts,
            "functions": parse_functions(text, suffix),
            "imports": RE_IMPORT.findall(text),
        })
    return rows[:MAX_FILES]


def suffix_index(catalog: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in catalog:
        rel = str(row["rel"])
        out[rel] = row
        out[Path(rel).name] = row
        for part in Path(rel).parts:
            out[part] = row
    return out


def import_graph(
    catalog: list[dict[str, Any]],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    for row in catalog:
        rel = str(row["rel"])
        for imp in row["imports"]:
            base = imp.rsplit("/", 1)[-1]
            peer = lookup.get(base) or lookup.get(imp)
            if peer and peer["rel"] != rel:
                graph[rel].add(str(peer["rel"]))
                graph[str(peer["rel"])].add(rel)
    return graph


def rank_catalog(
    catalog: list[dict[str, Any]],
    graph: dict[str, set[str]],
) -> list[dict[str, Any]]:
    for row in catalog:
        row["score"] = risk_score(str(row["rel"]), str(row["text"]), graph)
    return sorted(catalog, key=lambda r: (-int(r["score"]), str(r["rel"])))


def graph_digest(ranked: list[dict[str, Any]], graph: dict[str, set[str]]) -> str:
    chunks: list[str] = []
    for row in ranked[:14]:
        rel = str(row["rel"])
        chunks.append(json.dumps({
            "file": rel,
            "score": row["score"],
            "neighbors": sorted(graph.get(rel, set()))[:4],
            "contracts": row["contracts"][:6],
            "hot_functions": hot_functions(str(row["text"]))[:6],
            "functions": [f["sig"][:130] for f in row["functions"][:18]],
            "risk_lines": risk_snippets(str(row["text"])),
        }, separators=(",", ":")))
    return "\n".join(chunks)[:DIGEST_CHARS]


def resolve_targets(targets: list[str], ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_rel = {r["rel"]: r for r in ranked}
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for rel, row in by_rel.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if row not in ordered:
                    ordered.append(row)
                break
    for row in ranked:
        if row not in ordered:
            ordered.append(row)
    return ordered


def import_neighbors(
    row: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
    limit: int,
) -> str:
    blocks: list[str] = []
    for imp in row["imports"]:
        key = imp.rsplit("/", 1)[-1]
        other = lookup.get(key) or lookup.get(imp)
        if other and other["rel"] != row["rel"]:
            blocks.append(f"// import {other['rel']}\n{str(other['text'])[:limit]}")
        if len(blocks) >= 2:
            break
    return "\n\n".join(blocks)
