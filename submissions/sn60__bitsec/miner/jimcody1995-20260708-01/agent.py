from __future__ import annotations

"""SN60 miner: repo triage plus two batched deep-audit passes.

General-purpose vulnerability analysis for unseen codebases. Uses the
3-call / 24k output-token budget: call 1 ranks targets from a compact repo
map, calls 2-3 deep-audit batched full sources with matcher-shaped output.
No hardcoded benchmark-family fingerprints or canned findings.
"""

import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SRC_EXT = (".sol", ".vy")
SKIP = {
    ".git", ".github", "artifacts", "broadcast", "cache", "coverage", "dist",
    "docs", "example", "examples", "interfaces", "lib", "mock", "mocks",
    "node_modules", "out", "script", "scripts", "test", "tests", "vendor", "vendors",
}

SOL_FN = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{};]*)(?:;|\{)",
    re.MULTILINE,
)
VY_FN = re.compile(
    r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:->\s*([^:]+))?:",
    re.MULTILINE,
)
CONTRACT = re.compile(
    r"^\s*(?:abstract\s+contract|contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
IMPORT = re.compile(r'^\s*import\b[^;]*?["\']([^"\']+)["\']', re.MULTILINE)
STATE = re.compile(
    r"^\s*(?:mapping\s*\([^;]+|[A-Za-z_][A-Za-z0-9_<>,\\[\\]. ]+)\s+"
    r"(?:public|private|internal|constant|immutable|override|\s)*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
    re.MULTILINE,
)

MAX_FILES = 70
MAX_BYTES = 260_000
DIGEST_CAP = 18_000
BATCH_CAP = 31_000
RELATED_CAP = 3_500
MAX_OUT = 8
WALL = 230
HTTP = 150
CALL_CAP = 3

RISK_TERMS = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly", "ecrecover",
    "permit", "initialize", "upgradeTo", "onlyOwner", "onlyRole", "withdraw",
    "redeem", "deposit", "borrow", "liquidat", "collateral", "oracle", "flash",
    "unchecked", "transferFrom", "mint(", "burn(", "approve", "swap",
    "slippage", "reentr", "external", "public",
)
NAME_TERMS = (
    "vault", "pool", "router", "manager", "controller", "strategy", "market",
    "oracle", "staking", "reward", "treasury", "bridge", "factory", "proxy",
    "token", "lend", "borrow", "govern", "escrow", "auction",
)

SYS = (
    "You are a senior smart-contract security auditor. Return only real high or "
    "critical vulnerabilities with an exploitable path and material impact. "
    "Reject style, gas, centralization complaints, and low-confidence speculation. "
    "Think briefly then return final JSON only."
)


def root_dir(project_dir: str | None) -> Path | None:
    opts: list[str] = []
    if project_dir:
        opts.append(project_dir)
    for k in ("PROJECT_DIR", "PROJECT_PATH", "PROJECT_ROOT", "PROJECT_CODE"):
        v = os.environ.get(k)
        if v:
            opts.append(v)
    opts += ["/app/project_code", "/app/project", "/project", "/code", "."]
    for raw in opts:
        try:
            p = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if p.is_dir() and any(
            f.is_file() and f.suffix.lower() in SRC_EXT for f in p.rglob("*")
        ):
            return p
    return None


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def line_at(text: str, needle: str) -> int | None:
    if not needle:
        return None
    i = text.find(needle)
    return None if i < 0 else text.count("\n", 0, i) + 1


def funcs(text: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for m in SOL_FN.finditer(text):
        tail = " ".join(m.group(3).split())
        out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}) {tail}".strip()})
    for m in VY_FN.finditer(text):
        ret = f" -> {m.group(3).strip()}" if m.group(3) else ""
        out.append({"name": m.group(1), "sig": f"{m.group(1)}({m.group(2).strip()}){ret}".strip()})
    return out


def rank(rel: str, text: str) -> int:
    ln, lt = rel.lower(), text.lower()
    s = min(lt.count("function ") + lt.count("\ndef "), 35)
    for t in NAME_TERMS:
        if t in ln:
            s += 9
    for t in RISK_TERMS:
        s += min(lt.count(t.lower()), 6) * 4
    if any(x in lt for x in ("external", "public", "@external")):
        s += 5
    if "nonreentrant" not in lt and any(x in lt for x in ("withdraw", "redeem", ".call{")):
        s += 8
    if "initializer" in lt or "upgrade" in lt:
        s += 6
    return s


def scan(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SRC_EXT:
            continue
        try:
            rel = path.relative_to(root)
            if any(p.lower() in SKIP for p in rel.parts[:-1]):
                continue
            if path.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        text = read(path)
        if not any(x in text for x in ("function", "contract ", "library ", "\ndef ", "def ")):
            continue
        r = rel.as_posix()
        contracts = CONTRACT.findall(text)
        if not contracts and path.suffix.lower() == ".vy":
            contracts = [path.stem]
        rows.append({
            "rel": r, "text": text, "contracts": contracts,
            "functions": funcs(text), "score": rank(r, text),
        })
    rows.sort(key=lambda x: (-int(x["score"]), x["rel"]))
    return rows[:MAX_FILES]


def state_vars(text: str) -> list[str]:
    seen: list[str] = []
    for n in STATE.findall(text):
        if n not in seen and len(n) < 45:
            seen.append(n)
    return seen[:16]


def risk_lines(text: str) -> list[str]:
    out: list[str] = []
    terms = [t.lower() for t in RISK_TERMS]
    for i, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        if any(t in low for t in terms):
            c = " ".join(line.strip().split())
            if c:
                out.append(f"{i}: {c[:180]}")
        if len(out) >= 18:
            break
    return out


def digest(rows: list[dict[str, Any]]) -> str:
    parts = []
    for rec in rows:
        parts.append(json.dumps({
            "file": rec["rel"],
            "lang": Path(rec["rel"]).suffix.lstrip("."),
            "contracts": rec["contracts"][:8],
            "score": rec["score"],
            "state": state_vars(rec["text"]),
            "functions": [f["sig"][:180] for f in rec["functions"][:28]],
            "risk_lines": risk_lines(rec["text"]),
        }, separators=(",", ":")))
    return "\n".join(parts)[:DIGEST_CAP]


def related(rec: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> str:
    bits: list[str] = []
    for imp in IMPORT.findall(rec["text"]):
        base = imp.rsplit("/", 1)[-1]
        o = by_name.get(base)
        if o and o["rel"] != rec["rel"]:
            bits.append(f"// import {o['rel']}\n{o['text'][:RELATED_CAP]}")
        if len(bits) >= 2:
            break
    return "\n\n".join(bits)[:RELATED_CAP * 2]


def call_model(api: str | None, msgs: list[dict[str, str]], cap: int) -> str:
    base = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not base:
        raise RuntimeError("missing inference endpoint")
    body = json.dumps({
        "messages": msgs,
        "max_tokens": cap,
        "reasoning": {"effort": "low", "exclude": True},
    }).encode()
    hdrs = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    err: Exception | None = None
    for n in range(2):
        try:
            req = urllib.request.Request(base + "/inference", data=body, method="POST", headers=hdrs)
            with urllib.request.urlopen(req, timeout=HTTP) as resp:
                payload = json.loads(resp.read().decode("utf-8", "replace"))
            return extract(payload)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise
            err = exc
        except (OSError, ValueError, TimeoutError) as exc:
            err = exc
        if n < 1:
            time.sleep(1.5)
    raise RuntimeError(f"inference failed: {err}")


def extract(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    msg = choices[0].get("message") if isinstance(choices[0], dict) else None
    if not isinstance(msg, dict):
        return ""
    c = msg.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "".join(str(x.get("text") or "") for x in c if isinstance(x, dict))
    return ""


def parse_obj(text: str) -> dict[str, Any]:
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        o = json.loads(s)
        return o if isinstance(o, dict) else {}
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
                    o = json.loads(s[start : i + 1])
                    return o if isinstance(o, dict) else {}
                except json.JSONDecodeError:
                    return {}
    return {}


def triage(api: str | None, rows: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this compact smart-contract repository map. Pick the files most likely to "
        "contain real high/critical exploitable bugs. Return strict JSON only:\n"
        '{"target_files":["path.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path.sol","contract":"Contract","function":"fn","severity":"high|critical",'
        '"mechanism":"precondition -> action -> effect","impact":"fund loss or privilege",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize access control gaps, unsafe external calls, broken accounting or oracle "
        "logic, initialization/upgrade flaws, and reentrancy or slippage issues. "
        "Prefer precision over volume. Do not invent files or functions.\n\n"
        + digest(rows)
    )
    try:
        obj = parse_obj(call_model(api, [{"role": "system", "content": SYS}, {"role": "user", "content": prompt}], 5000))
    except Exception:
        return [], []
    targets = obj.get("target_files")
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return (
        [str(x) for x in targets if isinstance(x, str)] if isinstance(targets, list) else [],
        [x for x in items if isinstance(x, dict)] if isinstance(items, list) else [],
    )


def batch_prompt(batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> str:
    hdr = (
        "Deep-audit the Solidity/Vyper sources below. Find only high/critical vulnerabilities "
        "with a concrete exploit path. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - specific bug","file":"exact/path",'
        '"contract":"Name","function":"fn","line":123,"severity":"high|critical",'
        '"mechanism":"pre -> attack -> broken invariant","impact":"specific harm",'
        '"description":"2-4 sentences naming file, contract, function, mechanism, impact"}]}\n'
        "Check access control, external calls, token/oracle math, LP/share accounting, "
        "initialization paths, and state-update ordering. At most 5 findings. "
        "Omit weak or speculative issues.\n"
    )
    parts, room = [hdr], BATCH_CAP - len(hdr)
    for rec in batch:
        rel = rec["rel"]
        block = f"\n\n===== FILE: {rel} =====\nContracts: {', '.join(rec['contracts'][:8])}\n{rec['text']}\n"
        rel_txt = related(rec, by_name)
        if rel_txt:
            block += f"\n===== RELATED for {rel} =====\n{rel_txt}\n"
        if len(block) > room:
            block = block[: max(0, room)] + "\n/* truncated */\n"
        if room <= 0:
            break
        parts.append(block)
        room -= len(block)
    return "".join(parts)


def deep_audit(api: str | None, batch: list[dict[str, Any]], by_name: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if not batch:
        return []
    try:
        obj = parse_obj(call_model(
            api,
            [{"role": "system", "content": SYS}, {"role": "user", "content": batch_prompt(batch, by_name)}],
            8000,
        ))
    except urllib.error.HTTPError:
        return []
    except Exception:
        return []
    items = obj.get("findings") or obj.get("vulnerabilities") or []
    return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []


def shape(raw: dict[str, Any], rel_map: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    fpath = str(raw.get("file") or raw.get("path") or "").strip()
    if not fpath:
        return None
    rec = None
    for rel, row in rel_map.items():
        if fpath == rel or rel.endswith(fpath) or fpath.endswith(rel):
            rec, fpath = row, rel
            break
    if rec is None:
        return None
    sev = str(raw.get("severity") or "").lower().strip()
    if sev not in {"high", "critical"}:
        return None
    fn = str(raw.get("function") or "").strip().strip("`() ")
    if "." in fn:
        fn = fn.split(".")[-1]
    valid = {f["name"] for f in rec["functions"]}
    if fn and fn not in valid:
        fn = ""
    contract = str(raw.get("contract") or "").strip().strip("`")
    if not contract and rec["contracts"]:
        contract = str(rec["contracts"][0])
    mech = str(raw.get("mechanism") or "").strip()
    impact = str(raw.get("impact") or "").strip()
    desc = str(raw.get("description") or "").strip()
    title = str(raw.get("title") or "").strip()
    if len(mech) < 25 and len(desc) < 120:
        return None
    loc = ".".join(x for x in (contract, fn) if x)
    if not title:
        title = f"{loc or fpath} - high-impact vulnerability"
    elif loc and loc.lower() not in title.lower():
        title = f"{loc} - {title}"
    where = f"In `{fpath}`"
    if contract:
        where += f", contract `{contract}`"
    if fn:
        where += f", function `{fn}()`"
    rebuilt = where + ". "
    if mech:
        rebuilt += "Mechanism: " + mech.rstrip(".") + ". "
    if impact:
        rebuilt += "Impact: " + impact.rstrip(".") + ". "
    if desc:
        rebuilt += desc
    desc = " ".join(rebuilt.split())
    if len(desc) < 100:
        return None
    line = raw.get("line")
    if not isinstance(line, int):
        needle = f"function {fn}" if fn else title.split(" - ", 1)[0]
        line = line_at(str(rec["text"]), needle)
    return {
        "title": title[:220],
        "description": desc[:3000],
        "severity": sev,
        "file": fpath,
        "function": fn,
        "line": line if isinstance(line, int) else None,
        "type": str(raw.get("type") or "logic"),
        "confidence": 0.92 if sev == "critical" else 0.84,
    }


def dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
            str(item.get("title") or "").lower()[:120],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_OUT:
            break
    return out


def pick_batches(targets: list[str], rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rel_map = {r["rel"]: r for r in rows}
    ordered: list[dict[str, Any]] = []
    for t in targets:
        for rel, rec in rel_map.items():
            if t == rel or rel.endswith(t) or t.endswith(rel):
                if rec not in ordered:
                    ordered.append(rec)
                break
    for rec in rows:
        if rec not in ordered:
            ordered.append(rec)
    return ordered[:3], ordered[3:7]


def empty() -> dict:
    findings: list[dict[str, Any]] = []
    return {"vulnerabilities": findings}


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    t0 = time.monotonic()
    root = root_dir(project_dir)
    if root is None:
        return empty()
    rows = scan(root)
    if not rows:
        return empty()
    rel_map = {r["rel"]: r for r in rows}
    by_name = {Path(r["rel"]).name: r for r in rows}

    raw: list[dict[str, Any]] = []
    targets, triaged = triage(inference_api, rows)
    raw.extend(triaged)

    first, second = pick_batches(targets, rows)
    if time.monotonic() - t0 < WALL:
        raw.extend(deep_audit(inference_api, first, by_name))
    if time.monotonic() - t0 < WALL:
        raw.extend(deep_audit(inference_api, second, by_name))

    shaped = [shape(x, rel_map) for x in raw]
    return {"vulnerabilities": dedupe([s for s in shaped if s is not None])}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
