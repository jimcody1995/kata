from __future__ import annotations

"""SN60 miner: evidence-first depth audits for the Phala TEE.

Beats shallow multi-file dumps by spending the sealed-room budget on a few
whole-contract deep reads. Static heuristics only rank targets — every emitted
finding comes from the model. Supports Solidity / Vyper / Cairo / Rust.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

EXTS = (".sol", ".vy", ".cairo", ".rs")
MAX_FILES = 80
MAX_BYTES = 340_000
MAP_CHARS = 22_000
AUDIT_CHARS = 56_000
RELATED_CHARS = 4_500
MAX_FINDINGS = 8
RUN_CAP = 790.0
HTTP_TIMEOUT = 195
MAX_CALLS = 5
MODEL = os.environ.get("KATA_MINER_MODEL", "deepseek-ai/DeepSeek-V3.2-TEE")

SKIP_DIRS = frozenset({
    ".git", ".github", ".venv", "artifacts", "broadcast", "cache", "coverage",
    "dist", "docs", "example", "examples", "lib", "libs", "node_modules", "out",
    "script", "scripts", "target", "test", "tests", "vendor", "vendors",
    "mock", "mocks", "fixtures", "fixture", "deps", "build",
})

RISK_WORDS = (
    "withdraw", "redeem", "borrow", "repay", "liquidat", "claim", "stake",
    "unstake", "deposit", "mint", "burn", "swap", "bridge", "permit",
    "delegatecall", "call{", ".call", "assembly", "unchecked", "tx.origin",
    "selfdestruct", "upgrade", "initialize", "onlyowner", "onlyrole", "oracle",
    "price", "share", "ratio", "rounding", "fee", "collateral", "solvency",
    "signature", "ecrecover", "nonce", "reentr", "slippage", "flash",
    "transferfrom", "approve", "allowance", "settle", "rebalance", "invoke",
    "cpi", "signer", "authority", "lamports",
)

NAME_WORDS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "bridge", "staking", "reward", "treasury", "govern", "proxy",
    "liquidat", "borrow", "token", "perp", "position", "lending", "escrow",
    "auction", "amm", "pair", "adapter", "clearing", "margin", "program",
)

FUNC_SOL = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
FUNC_VY = re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
FUNC_CAIRO = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]", re.MULTILINE)
FUNC_RS = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CONTRACT_SOL = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CONTRACT_CAIRO = re.compile(
    r"^\s*(?:#\[starknet::contract\]\s*)?(?:mod|impl|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
CONTRACT_RS = re.compile(r"^\s*(?:pub\s+)?(?:mod|struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
IMPORT_RE = re.compile(r'^\s*(?:import|use)\b[^;\n]*?["\']?([A-Za-z0-9_./]+)["\']?', re.MULTILINE)

SYSTEM = (
    "You are an elite smart-contract security researcher. Report only "
    "exploitable HIGH or CRITICAL bugs with a concrete attacker path and "
    "material fund or privilege impact. Skip gas, style, natspec, missing "
    "events, and trusted-admin assumptions unless authorization is truly "
    "missing. Prefer precision over volume. Return strict JSON only."
)

LENSES = {
    "value": (
        "Focus on value movement, share/supply/reserve accounting, rounding, "
        "first-depositor inflation, fee skimming, and insolvency."
    ),
    "auth": (
        "Focus on missing access control, unprotected initializers/upgrades, "
        "delegatecall, tx.origin auth, reentrancy ordering, and privilege grants."
    ),
    "oracle": (
        "Focus on oracle/price manipulation, stale reads, signature replay, "
        "permit/nonce flaws, liquidation edge cases, and cross-contract assumptions."
    ),
}


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    started = time.monotonic()
    findings: list[dict[str, Any]] = []
    try:
        root = project_root(project_dir)
        if root is None:
            return {"vulnerabilities": findings}
        records = discover(root)
        if not records:
            return {"vulnerabilities": findings}

        rel_map = {r["rel"]: r for r in records}
        by_name = {Path(r["rel"]).name: r for r in records}
        raw: list[dict[str, Any]] = []
        calls = 0

        targets, mapped = triage(inference_api, records, started)
        raw.extend(mapped)
        calls = 1

        ordered = order_targets(targets, records)
        # One whole file per deep call — more context, fewer truncated answers.
        slots = [
            (ordered[:1], "value"),
            (ordered[1:2], "auth"),
            (ordered[2:3], "oracle"),
        ]
        # If triage was thin, fall back to top static ranks with a second file each.
        if len(ordered) >= 4:
            slots.append((ordered[3:5], "value"))

        for batch, lens in slots:
            if calls >= MAX_CALLS or not time_left(started, 205):
                break
            if not batch:
                continue
            raw.extend(deep_audit(inference_api, batch, by_name, started, lens=lens))
            calls += 1

        # Final verify pass: keep only findings the source still supports.
        if raw and calls < MAX_CALLS and time_left(started, 205):
            verified = verify_findings(inference_api, raw, rel_map, started)
            if verified:
                raw = verified
            calls += 1

        for item in raw:
            norm = normalize(item, rel_map)
            if norm is not None:
                findings.append(norm)
    except Exception:
        pass
    return {"vulnerabilities": dedupe(findings)}


def time_left(started: float, need: float = 0.0) -> bool:
    return time.monotonic() - started < RUN_CAP - need


def project_root(project_dir: str | None) -> Path | None:
    opts: list[str] = []
    if project_dir:
        opts.append(project_dir)
    for key in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        val = os.environ.get(key)
        if val:
            opts.append(val)
    opts.extend(("/app/project_code", "/app/project", "/project", "/code", "."))
    for raw in opts:
        try:
            path = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if path.is_dir() and has_sources(path):
            return path
    return None


def has_sources(root: Path) -> bool:
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")
            ]
            for name in filenames:
                if Path(name).suffix.lower() in EXTS:
                    return True
    except OSError:
        return False
    return False


def should_skip(rel: Path) -> bool:
    for part in rel.parts[:-1]:
        low = part.lower()
        if low in SKIP_DIRS or low.startswith("."):
            return True
    name = rel.name.lower()
    return name.endswith((".t.sol", ".s.sol", "_test.sol", ".test.sol", "_test.rs"))


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_functions(text: str, ext: str) -> list[dict[str, Any]]:
    patterns = [FUNC_SOL]
    if ext == ".vy":
        patterns = [FUNC_VY]
    elif ext == ".cairo":
        patterns = [FUNC_CAIRO, FUNC_SOL]
    elif ext == ".rs":
        patterns = [FUNC_RS]
    out: list[dict[str, Any]] = []
    for pat in patterns:
        for match in pat.finditer(text):
            out.append({
                "name": match.group(1),
                "line": text.count("\n", 0, match.start()) + 1,
                "sig": " ".join(match.group(0).strip().split())[:180],
            })
    return out


def contracts_for(text: str, ext: str, stem: str) -> list[str]:
    found = list(CONTRACT_SOL.findall(text))
    if ext == ".cairo":
        found.extend(CONTRACT_CAIRO.findall(text))
    elif ext == ".rs":
        found.extend(CONTRACT_RS.findall(text))
    seen: list[str] = []
    for name in found:
        if name not in seen:
            seen.append(name)
    return seen or [stem]


def risk_lines(text: str) -> list[str]:
    lines: list[str] = []
    terms = tuple(w.lower() for w in RISK_WORDS)
    for num, line in enumerate(text.splitlines(), start=1):
        low = line.lower().replace(" ", "")
        if any(t in low for t in terms):
            compact = " ".join(line.strip().split())
            if compact:
                lines.append(f"{num}: {compact[:170]}")
        if len(lines) >= 16:
            break
    return lines


def score_file(rel: str, text: str, ext: str) -> int:
    ln, body = rel.lower(), text.lower()
    compact = body.replace(" ", "")
    score = min(
        body.count("function ") + body.count("\ndef ") + body.count(" fn ") + body.count("\nfn "),
        45,
    )
    for word in NAME_WORDS:
        if word in ln:
            score += 10
        elif word in body:
            score += 2
    for word in RISK_WORDS:
        if word in compact:
            score += 3
    if any(tok in body for tok in ("external", "public", "#[external", "pub fn", "entry")):
        score += 7
    if "nonreentrant" not in body and (".call" in body or "call{" in compact or "invoke" in body):
        score += 6
    if "delegatecall" in compact:
        score += 9
    if "tx.origin" in compact:
        score += 7
    if "ecrecover" in compact or "recover(" in compact:
        score += 5
    if "interface" in ln or ln.endswith(".rs") and "test" in ln:
        score -= 8
    if ext == ".rs":
        score += 4
    return score


def discover(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d.lower() not in SKIP_DIRS and not d.startswith(".")
            ]
            for fname in filenames:
                path = Path(dirpath) / fname
                ext = path.suffix.lower()
                if ext not in EXTS:
                    continue
                try:
                    rel = path.relative_to(root)
                    if should_skip(rel):
                        continue
                    if path.stat().st_size > MAX_BYTES:
                        continue
                except OSError:
                    continue
                text = read_text(path)
                markers = (
                    "function", "contract ", "library ", "\ndef ", " fn ", "\nfn ",
                    "pub fn", "mod ", "struct ",
                )
                if not any(tok in text for tok in markers):
                    continue
                rel_s = rel.as_posix()
                rows.append({
                    "rel": rel_s,
                    "text": text,
                    "ext": ext,
                    "contracts": contracts_for(text, ext, path.stem),
                    "functions": parse_functions(text, ext),
                    "risk": risk_lines(text),
                    "score": score_file(rel_s, text, ext),
                })
                if len(rows) >= MAX_FILES * 2:
                    break
            if len(rows) >= MAX_FILES * 2:
                break
    except OSError:
        return []
    rows.sort(key=lambda r: (-int(r["score"]), str(r["rel"])))
    return rows[:MAX_FILES]


def line_at(text: str, offset: int) -> int:
    return 1 if offset < 0 else text.count("\n", 0, offset) + 1


def repo_map(records: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for rec in records:
        parts.append(json.dumps({
            "file": rec["rel"],
            "kind": rec["ext"].lstrip("."),
            "score": rec["score"],
            "contracts": rec["contracts"][:6],
            "functions": [f"{f['line']}:{f['sig']}" for f in rec["functions"][:24]],
            "risk_lines": rec["risk"][:14],
        }, separators=(",", ":")))
    return "\n".join(parts)[:MAP_CHARS]


def infer(api: str | None, messages: list[dict[str, str]], max_tokens: int, started: float) -> str:
    if not time_left(started, 5):
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    body = json.dumps({
        "model": MODEL,
        "temperature": 0.05,
        "messages": messages,
        "max_tokens": max_tokens,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    for attempt in range(2):
        if not time_left(started, 5):
            return ""
        try:
            req = urllib.request.Request(
                endpoint + "/inference", data=body, method="POST", headers=headers,
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code in {429, 503}:
                time.sleep(1.0)
                continue
            if attempt == 0:
                time.sleep(0.5)
        except (OSError, TimeoutError, ValueError):
            if attempt == 0:
                time.sleep(0.5)
    return ""


def pull_text(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    content = msg.get("content")
    if isinstance(content, str) and content.strip():
        return content
    if isinstance(content, list):
        joined = "".join(str(p.get("text") or "") for p in content if isinstance(p, dict))
        if joined.strip():
            return joined
    for key in ("reasoning_content", "reasoning"):
        alt = msg.get(key)
        if isinstance(alt, str) and alt.strip():
            return alt
    return ""


def load_json(text: str) -> dict[str, Any]:
    s = text.strip()
    if not s:
        return {}
    if s.startswith("```"):
        s = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        obj = json.loads(s)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        pass
    start = s.find("{")
    if start < 0:
        return {}
    depth, in_str, esc = 0, False, False
    for i in range(start, len(s)):
        ch = s[i]
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
                    obj = json.loads(s[start : i + 1])
                    return obj if isinstance(obj, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def triage(
    api: str | None,
    records: list[dict[str, Any]],
    started: float,
) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this repository map. Pick the highest-yield files for a deep audit "
        "and report only bugs you can already justify from signatures and risk lines.\n"
        '{"target_files":["path"],"findings":[{"title":"Contract.function - bug","file":"path",'
        '"contract":"Name","function":"fn","line":1,"severity":"high|critical","type":"logic",'
        '"mechanism":"pre -> attack -> effect","impact":"harm","description":"2-4 sentences"}]}\n'
        "Prioritize value movement, accounting, access control, oracle, signatures, "
        "liquidation, and reentrancy. Prefer precision over volume.\n\n"
        + repo_map(records)
    )
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        4500,
        started,
    ))
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def order_targets(targets: list[str], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for target in targets:
        tl = target.lower().strip()
        for rec in records:
            rl = str(rec["rel"]).lower()
            if tl == rl or rl.endswith(tl) or tl.endswith(rl):
                if rec not in out:
                    out.append(rec)
                break
    for rec in records:
        if rec not in out:
            out.append(rec)
    return out


def related_context(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    chunks: list[str] = []
    for imp in IMPORT_RE.findall(str(rec["text"])):
        name = imp.rsplit("/", 1)[-1]
        other = by_name.get(name) or by_name.get(name + ".sol") or by_name.get(name + ".rs")
        if other and other["rel"] != rec["rel"]:
            chunks.append(f"\n--- RELATED {other['rel']} ---\n{str(other['text'])[:RELATED_CHARS]}")
        if len(chunks) >= 2:
            break
    return "".join(chunks)


def audit_prompt(
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    lens: str,
) -> str:
    focus = LENSES.get(lens, LENSES["value"])
    header = (
        f"Deep whole-contract audit ({lens}). {focus}\n"
        "Return strict JSON:\n"
        '{"findings":[{"title":"Contract.function - bug","file":"path","contract":"C",'
        '"function":"fn","line":1,"severity":"high|critical","type":"logic",'
        '"mechanism":"pre->attack->effect","impact":"harm",'
        '"description":"2-5 sentences with exploit path"}]}\n'
        "Max 4 findings. Name real functions from the source. Omit weak speculation.\n"
    )
    parts, room = [header], AUDIT_CHARS - len(header)
    for rec in batch:
        sigs = [f"{f['line']}:{f['sig']}" for f in rec["functions"][:28]]
        block = (
            f"\n\n=== {rec['rel']} ===\nContracts: {', '.join(rec['contracts'][:8])}\n"
            f"Functions: {json.dumps(sigs)}\nRisk: {json.dumps(rec['risk'][:14])}\n"
            f"{rec['text']}\n{related_context(rec, by_name)}\n"
        )
        if room <= 0:
            break
        if len(block) > room:
            block = block[:room] + "\n/* truncated */\n"
        parts.append(block)
        room -= len(block)
    return "".join(parts)


def deep_audit(
    api: str | None,
    batch: list[dict[str, Any]],
    by_name: dict[str, dict[str, Any]],
    started: float,
    *,
    lens: str,
) -> list[dict[str, Any]]:
    if not batch:
        return []
    obj = load_json(infer(
        api,
        [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": audit_prompt(batch, by_name, lens)},
        ],
        6500,
        started,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def verify_findings(
    api: str | None,
    candidates: list[dict[str, Any]],
    rel_map: dict[str, dict[str, Any]],
    started: float,
) -> list[dict[str, Any]]:
    packed: list[dict[str, Any]] = []
    for item in candidates[:12]:
        rel, rec = match_file(str(item.get("file") or ""), rel_map)
        if not rel or not rec:
            continue
        fn = str(item.get("function") or "").strip()
        snippet = str(rec["text"])
        if fn:
            for needle in (f"function {fn}", f"def {fn}", f"fn {fn}"):
                idx = snippet.find(needle)
                if idx >= 0:
                    snippet = snippet[max(0, idx - 200) : idx + 1800]
                    break
        packed.append({
            "title": item.get("title"),
            "file": rel,
            "function": fn,
            "severity": item.get("severity"),
            "mechanism": item.get("mechanism"),
            "impact": item.get("impact"),
            "description": item.get("description"),
            "source_excerpt": snippet[:2200],
        })
    if not packed:
        return []
    prompt = (
        "Verify each candidate against its source excerpt. Keep only findings the "
        "excerpt proves are exploitable high/critical bugs. Drop speculation and "
        "false positives. Return strict JSON:\n"
        '{"findings":[{"title":"...","file":"...","contract":"...","function":"...",'
        '"line":1,"severity":"high|critical","type":"logic","mechanism":"...",'
        '"impact":"...","description":"..."}]}\n\n'
        + json.dumps({"candidates": packed}, separators=(",", ":"))[:MAP_CHARS]
    )
    obj = load_json(infer(
        api,
        [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
        5000,
        started,
    ))
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def match_file(
    file_value: str,
    rel_map: dict[str, dict[str, Any]],
) -> tuple[str | None, dict[str, Any] | None]:
    low = file_value.lower().strip().strip("`")
    if not low:
        return None, None
    for rel, rec in rel_map.items():
        rl = rel.lower()
        if low == rl or rl.endswith(low) or low.endswith(rl):
            return rel, rec
    base = Path(low).name
    if base:
        hits = [(rel, rec) for rel, rec in rel_map.items() if Path(rel).name.lower() == base]
        if len(hits) == 1:
            return hits[0]
    return None, None


def normalize(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    rel, rec = match_file(str(raw.get("file") or raw.get("path") or ""), rel_map)
    if not rel or not rec:
        return None
    sev = str(raw.get("severity") or "").lower().strip()
    if sev not in {"high", "critical"}:
        return None
    fn = str(raw.get("function") or "").strip().strip("`() ")
    if "." in fn:
        fn = fn.split(".")[-1]
    valid = {str(f["name"]) for f in rec["functions"]}
    if fn and fn not in valid:
        fn = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    mech = clean(raw.get("mechanism"))
    impact = clean(raw.get("impact"))
    desc = clean(raw.get("description"))
    title = clean(raw.get("title")) or f"{contract}.{fn or 'logic'} - high-impact bug"
    if len(mech) < 24 and len(desc) < 120:
        return None
    where = f"In `{rel}`"
    if contract:
        where += f", contract `{contract}`"
    if fn:
        where += f", function `{fn}()`"
    rebuilt = where + ". "
    if mech:
        rebuilt += f"Mechanism: {mech.rstrip('.')}. "
    if impact:
        rebuilt += f"Impact: {impact.rstrip('.')}. "
    if desc:
        rebuilt += desc
    rebuilt = " ".join(rebuilt.split())
    if len(rebuilt) < 120:
        return None
    line = raw.get("line")
    if not isinstance(line, int) and fn:
        for needle in (f"function {fn}", f"def {fn}", f"fn {fn}"):
            idx = str(rec["text"]).find(needle)
            if idx >= 0:
                line = line_at(str(rec["text"]), idx)
                break
    base = rel.rsplit("/", 1)[-1]
    loc = f" Affected location: `{rel}`, `{base}`" + (f", `{fn}()`" if fn else "") + "."
    if loc.strip() not in rebuilt:
        rebuilt += loc
    return {
        "title": title[:220],
        "description": rebuilt[:3000],
        "severity": sev,
        "file": rel,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.92 if sev == "critical" else 0.86,
    }


def clean(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in sorted(
        items,
        key=lambda f: (
            f.get("severity") == "critical",
            float(f.get("confidence") or 0),
            len(str(f.get("description"))),
        ),
        reverse=True,
    ):
        key = (
            str(item.get("file") or "").lower(),
            str(item.get("function") or "").lower(),
            str(item.get("title") or "").lower()[:100],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_FINDINGS:
            break
    return out


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
