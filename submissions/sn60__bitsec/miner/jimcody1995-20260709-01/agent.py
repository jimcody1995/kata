from __future__ import annotations

"""SN60 miner: triage plus two batched deep audits with static prioritization.

Inspired by the current king triage-and-batch flow (kiannidev-20260708-01) and
prior depth-first matcher work, but with richer static context in the repo digest
(hot external functions, import neighbors) and generic audit prompts. Pure LLM
analysis within the 3-call budget; no fingerprint branches or canned findings.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXT = (".sol", ".vy")
SKIP_GLOBAL = frozenset({
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist", "docs",
    "example", "examples", "interfaces", "lib", "mock", "mocks", "node_modules", "out",
    "script", "scripts", "test", "tests", "vendor", "vendors",
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
RE_CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
RE_IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
RE_STATE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\\[\\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)
RE_RISK = re.compile(
    r"\b(delegatecall|selfdestruct|tx\.origin|assembly|unchecked|\.call\s*\{|"
    r"onlyOwner|onlyRole|upgradeTo|initialize|withdraw|redeem|borrow|liquidat|"
    r"transferFrom|ecrecover|permit|oracle|flash|swap|slippage|reentr)\b",
    re.IGNORECASE,
)
RE_EXTERNAL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s+"
    r"(?:public|external)\b[^;{]*",
    re.MULTILINE | re.IGNORECASE,
)

MAX_FILES = 70
MAX_BYTES = 260_000
DIGEST_LIMIT = 18_000
BATCH_LIMIT = 31_000
IMPORT_LIMIT = 3_500
MAX_OUT = 8
TIME_BUDGET = 228.0
HTTP_WAIT = 148

PATH_HINTS = (
    "vault", "pool", "router", "bridge", "proxy", "oracle", "govern", "treasury",
    "manager", "market", "lend", "borrow", "collateral", "controller", "strategy",
    "auction", "token", "staking", "reward", "factory", "escrow", "swap",
)

SYSTEM = (
    "You are a senior smart-contract security auditor. Report only high or critical "
    "vulnerabilities with a concrete exploit path and material impact. Reject style, "
    "gas, centralization, and speculation. Return strict JSON only."
)


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict[str, Any]] = []
    root = locate_project(project_dir)
    if root is None:
        return {"vulnerabilities": findings}

    clock = time.monotonic()
    catalog = build_catalog(root)
    if not catalog:
        return {"vulnerabilities": findings}

    by_rel = {row["rel"]: row for row in catalog}
    by_basename = {Path(row["rel"]).name: row for row in catalog}
    collected: list[dict[str, Any]] = []

    ranked_paths, triage_items = run_triage(inference_api, catalog)
    collected.extend(triage_items)

    batch_a, batch_b = plan_batches(ranked_paths, catalog)
    if time.monotonic() - clock < TIME_BUDGET:
        collected.extend(run_deep_pass(inference_api, batch_a, by_basename))
    if time.monotonic() - clock < TIME_BUDGET:
        collected.extend(run_deep_pass(inference_api, batch_b, by_basename))

    for raw in collected:
        shaped = format_finding(raw, by_rel)
        if shaped is not None:
            findings.append(shaped)
    return {"vulnerabilities": collapse_findings(findings)}


def locate_project(project_dir: str | None) -> Path | None:
    options: list[str] = []
    if project_dir:
        options.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            options.append(val)
    options.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in options:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if root.is_dir() and has_contract_sources(root):
            return root
    return None


def has_contract_sources(root: Path) -> bool:
    try:
        return any(p.is_file() and p.suffix.lower() in EXT for p in root.rglob("*"))
    except OSError:
        return False


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


def parse_functions(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for m in RE_FUNC_SOL.finditer(text):
        tail = " ".join(m.group(3).split())
        out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}) {tail}".strip()})
    for m in RE_FUNC_VY.finditer(text):
        ret = f" -> {m.group(3).strip()}" if m.group(3) else ""
        out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}){ret}".strip()})
    return out


def hot_functions(text: str) -> list[str]:
    hits: list[str] = []
    for m in RE_EXTERNAL.finditer(text):
        sig = " ".join(m.group(0).split())
        if RE_RISK.search(sig):
            hits.append(sig[:160])
        elif len(hits) < 6:
            hits.append(sig[:160])
        if len(hits) >= 10:
            break
    return hits


def risk_score(rel: str, text: str) -> int:
    name_low, text_low = rel.lower(), text.lower()
    score = min(text_low.count("function ") + text_low.count("\ndef "), 34)
    for hint in PATH_HINTS:
        if hint in name_low:
            score += 9
        elif hint in text_low:
            score += 2
    score += min(len(RE_RISK.findall(text)), 24) * 3
    if any(tok in text_low for tok in ("external", "public", "@external")):
        score += 5
    if "nonreentrant" not in text_low and ".call" in text_low:
        score += 4
    if "initializer" in text_low or "upgrade" in text_low:
        score += 5
    return score


def state_names(text: str) -> list[str]:
    seen: list[str] = []
    for name in RE_STATE.findall(text):
        if name not in seen and len(name) < 42:
            seen.append(name)
    return seen[:15]


def risk_snippets(text: str) -> list[str]:
    lines: list[str] = []
    for num, line in enumerate(text.splitlines(), start=1):
        if RE_RISK.search(line):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{num}: {compact[:170]}")
        if len(lines) >= 16:
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
        if not any(tok in text for tok in ("function", "contract ", "library ", "\ndef ")):
            continue
        rel = rel_path.as_posix()
        contracts = RE_CONTRACT.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
            contracts = [path.stem]
        rows.append({
            "rel": rel,
            "text": text,
            "contracts": contracts,
            "functions": parse_functions(text),
            "score": risk_score(rel, text),
        })
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_FILES]


def repo_map(rows: list[dict[str, Any]]) -> str:
    chunks: list[str] = []
    for row in rows:
        chunks.append(json.dumps({
            "file": row["rel"],
            "language": Path(str(row["rel"])).suffix.lstrip("."),
            "contracts": row["contracts"][:7],
            "score": row["score"],
            "state": state_names(str(row["text"])),
            "hot_functions": hot_functions(str(row["text"])),
            "functions": [f["sig"][:150] for f in row["functions"][:24]],
            "risk_lines": risk_snippets(str(row["text"])),
        }, separators=(",", ":")))
    return "\n".join(chunks)[:DIGEST_LIMIT]


def import_neighbors(row: dict[str, Any], by_basename: dict[str, dict[str, Any]]) -> str:
    blocks: list[str] = []
    for imp in RE_IMPORT.findall(str(row["text"])):
        base = imp.rsplit("/", 1)[-1]
        other = by_basename.get(base)
        if other and other["rel"] != row["rel"]:
            blocks.append(f"// import {other['rel']}\n{str(other['text'])[:IMPORT_LIMIT]}")
        if len(blocks) >= 2:
            break
    return "\n\n".join(blocks)[:IMPORT_LIMIT * 2]


def infer(api: str | None, messages: list[dict[str, str]], token_cap: int) -> str:
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        raise RuntimeError("missing inference endpoint")
    payload = json.dumps({
        "messages": messages,
        "max_tokens": token_cap,
        "reasoning": {"effort": "low", "exclude": True},
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=payload, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_WAIT) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            last = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last = exc
        if attempt < 2:
            time.sleep(1.2 * (attempt + 1))
    raise RuntimeError(f"inference failed: {last}")


def pull_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    return ""


def load_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        obj = json.loads(stripped)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start = stripped.find("{")
    if start < 0:
        return {}
    depth = 0
    in_str = False
    esc = False
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(stripped[start : idx + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def run_triage(api: str | None, rows: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this smart-contract repository map (scores, hot external functions, risk lines). "
        "Pick files most likely to hold exploitable high/critical bugs. Return strict JSON only:\n"
        '{"target_files":["path.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path.sol","contract":"Contract","function":"fn","severity":"high|critical",'
        '"mechanism":"precondition -> attacker action -> broken invariant",'
        '"impact":"fund loss, insolvency, privilege, or permanent DoS",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize: missing access control on privileged state changes; unsafe external calls "
        "and reentrancy; broken share/LP/oracle accounting; initialization or upgrade gaps; "
        "slippage or ordering bugs in swaps and liquidity flows. "
        "Use hot_functions and risk_lines as hints only. "
        "Prefer precision over volume. Do not invent files or functions.\n\n"
        + repo_map(rows)
    )
    try:
        obj = load_json(infer(api, [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}], 5000))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def deep_prompt(batch: list[dict[str, Any]], by_basename: dict[str, dict[str, Any]]) -> str:
    header = (
        "Deep-audit the contract sources below with full cross-file import context. "
        "Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Contract","function":"fn","line":123,"severity":"high|critical",'
        '"mechanism":"pre -> attack steps -> broken invariant",'
        '"impact":"specific material harm",'
        '"description":"2-4 sentences naming file, contract, function, mechanism, impact"}]}\n'
        "Checklist: access control on admin/user flows; external call ordering and reentrancy; "
        "token decimal/rate scaling; LP/share mint-burn math; oracle freshness and manipulation; "
        "initializer guards; state updates before value transfers. "
        "At most 5 findings. Omit weak or speculative issues.\n"
    )
    parts = [header]
    room = BATCH_LIMIT - len(header)
    for row in batch:
        block = (
            f"\n\n===== FILE: {row['rel']} =====\n"
            f"Contracts: {', '.join(row['contracts'][:7])}\n"
            f"Hot functions: {', '.join(hot_functions(str(row['text']))[:6])}\n"
            f"{row['text']}\n"
        )
        neighbors = import_neighbors(row, by_basename)
        if neighbors:
            block += f"\n===== IMPORT CONTEXT =====\n{neighbors}\n"
        if len(block) > room:
            block = block[: max(0, room)] + "\n/* truncated */\n"
        if room <= 0:
            break
        parts.append(block)
        room -= len(block)
    return "".join(parts)


def run_deep_pass(
    api: str | None,
    batch: list[dict[str, Any]],
    by_basename: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        obj = load_json(infer(
            api,
            [{"role": "system", "content": SYSTEM}, {"role": "user", "content": deep_prompt(batch, by_basename)}],
            8000,
        ))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def plan_batches(targets: list[str], rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_rel = {r["rel"]: r for r in rows}
    ordered: list[dict[str, Any]] = []
    for target in targets:
        for rel, row in by_rel.items():
            if target == rel or rel.endswith(target) or target.endswith(rel):
                if row not in ordered:
                    ordered.append(row)
                break
    for row in rows:
        if row not in ordered:
            ordered.append(row)
    return ordered[:2], ordered[2:6]


def line_number(text: str, needle: str) -> int | None:
    if not needle:
        return None
    idx = text.find(needle)
    return None if idx < 0 else text.count("\n", 0, idx) + 1


def format_finding(raw: dict[str, Any], by_rel: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    file_hint = str(raw.get("file") or raw.get("path") or "").strip()
    if not file_hint:
        return None
    row = None
    for rel, candidate in by_rel.items():
        if file_hint == rel or rel.endswith(file_hint) or file_hint.endswith(rel):
            row, file_hint = candidate, rel
            break
    if row is None:
        return None
    severity = str(raw.get("severity") or "").lower().strip()
    if severity not in {"high", "critical"}:
        return None
    function = str(raw.get("function") or "").strip().strip("`() ")
    if "." in function:
        function = function.split(".")[-1]
    valid = {f["name"] for f in row["functions"]}
    if function and function not in valid:
        function = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and row["contracts"]:
        contract = str(row["contracts"][0])
    mechanism = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    description = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mechanism) < 22 and len(description) < 100:
        return None
    loc = ".".join(x for x in (contract, function) if x)
    if not title:
        title = f"{loc or file_hint} - high-impact vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    where = f"In `{file_hint}`"
    if contract:
        where += f", contract `{contract}`"
    if function:
        where += f", function `{function}()`"
    rebuilt = where + ". "
    if mechanism:
        rebuilt += "Mechanism: " + mechanism.rstrip(".") + ". "
    if impact:
        rebuilt += "Impact: " + impact.rstrip(".") + ". "
    if description:
        rebuilt += description
    description = " ".join(rebuilt.split())
    if len(description) < 100:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and function:
        line = line_number(str(row["text"]), f"function {function}")
    return {
        "title": title[:220],
        "description": description[:3000],
        "severity": severity,
        "file": file_hint,
        "function": function,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.91 if severity == "critical" else 0.85,
    }


def collapse_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in sorted(
        items,
        key=lambda f: (f.get("severity") == "critical", float(f.get("confidence") or 0), len(str(f.get("description")))),
        reverse=True,
    ):
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            str(item.get("title") or "").lower()[:110],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_OUT:
            break
    return out


if __name__ == "__main__":
    import sys

    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
