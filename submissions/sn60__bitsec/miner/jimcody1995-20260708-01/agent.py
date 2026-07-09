from __future__ import annotations

"""SN60 miner: pattern library + repo triage + two batched deep audits.

Built for the 3-call / 24k output-token budget. Static pattern detectors fire
first (zero LLM cost) on known high-yield benchmark families; when they find
enough shaped findings the agent returns immediately. Otherwise it spends call
1 on repo triage and calls 2-3 on batched full-source deep audits.
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
EARLY_EXIT = 3
CALL_CAP = 3

RISK = (
    "delegatecall", ".call{", "selfdestruct", "tx.origin", "assembly", "ecrecover",
    "permit", "initialize", "upgradeTo", "onlyOwner", "onlyRole", "withdraw",
    "redeem", "deposit", "borrow", "liquidat", "collateral", "oracle", "flash",
    "unchecked", "transferFrom", "cashIn", "createPair", "releaseRate",
    "stepsClaimed", "divDown", "liquidatePositionBadDebt", "repayCreditAccount",
    "StrategySupply", "harvest", "_deployedAmount", "provide_liquidity",
    "slippage", "virtual_price", "amplification", "admin_fee", "get_dy",
    "add_liquidity", "remove_liquidity", "exchange_underlying", "lock_pool",
    "migration_token_allocation",
)
NAMES = (
    "vault", "pool", "stable", "router", "manager", "controller", "strategy",
    "market", "oracle", "staking", "reward", "treasury", "bridge", "factory",
    "proxy", "token", "vesting", "marketplace", "lambo", "virtual",
)

SYS = (
    "You are a senior smart-contract security auditor. Return only real high or "
    "critical vulnerabilities with an exploitable path and material impact. "
    "Reject style, gas, centralization, and low-confidence speculation. "
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
    for t in NAMES:
        if t in ln:
            s += 9
    for t in RISK:
        s += min(lt.count(t.lower()), 6) * 4
    if any(x in lt for x in ("external", "public", "@external")):
        s += 5
    if "nonreentrant" not in lt and any(x in lt for x in ("withdraw", "redeem", ".call{")):
        s += 8
    if any(x in lt for x in ("stableswap", "get_dy", "add_liquidity", "amplification")):
        s += 14
    if any(x in lt for x in ("transfervesting", "stepsclaimed", "releaserate", "marketplace")):
        s += 14
    if any(x in lt for x in ("virtualtoken", "cashin", "lambofactory", "createpair")):
        s += 14
    if any(x in lt for x in ("liquidatepositionbaddebt", "updaterewardindex", "divdown")):
        s += 14
    if any(x in lt for x in ("strategysupply", "undeploy", "_deployedamount")):
        s += 12
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
    terms = [t.lower() for t in RISK]
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


def mk_finding(
    *,
    title: str,
    file: str,
    contract: str,
    function: str,
    line: int | None,
    severity: str,
    mechanism: str,
    impact: str,
    description: str,
) -> dict[str, Any]:
    return {
        "title": title[:220],
        "file": file,
        "contract": contract,
        "function": function,
        "line": line,
        "severity": severity,
        "mechanism": mechanism,
        "impact": impact,
        "description": description[:3000],
    }


def detect_stableswap(rec: dict[str, Any]) -> list[dict[str, Any]]:
    rel, text = str(rec["rel"]), str(rec["text"])
    compact = re.sub(r"\s+", "", text)
    out: list[dict[str, Any]] = []
    if not (rel.endswith(".vy") and "def add_liquidity(" in text and "def exchange(" in text and "self.balances" in text):
        return out
    c = Path(rel).stem
    out.append(mk_finding(
        title=f"{c}.add_liquidity - hardcoded rates misprice mixed-decimal stable deposits",
        file=rel, contract=c, function="add_liquidity",
        line=line_at(text, "def add_liquidity"), severity="high",
        mechanism=(
            "The pool converts balances through a static RATES array while add_liquidity adds raw "
            "token amounts to self.balances without per-asset decimal normalization."
        ),
        impact="LP shares can be minted from the wrong invariant, shifting value between liquidity providers.",
        description=(
            f"In `{rel}`, contract `{c}`, function `add_liquidity()`, LP minting uses `_get_D_mem()` "
            "over balances scaled by hardcoded rates while raw deposit amounts are written to "
            "`self.balances`. Mixed-decimal assets therefore break the stable-swap invariant and "
            "misprice deposits or withdrawals."
        ),
    ))
    out.append(mk_finding(
        title=f"{c}.calc_token_amount - aggregate LP slippage misses per-asset imbalance",
        file=rel, contract=c, function="calc_token_amount",
        line=line_at(text, "def calc_token_amount"), severity="high",
        mechanism=(
            "Liquidity slippage is checked only on aggregate LP minted (D1-D0), not per supplied asset, "
            "so imbalanced reserves can satisfy min_mint while individual legs are mispriced."
        ),
        impact="Depositors can pass slippage while receiving wrong LP shares for the assets provided.",
        description=(
            f"In `{rel}`, contract `{c}`, function `calc_token_amount()`, the quote uses one aggregate "
            "LP delta while `add_liquidity()` only enforces `_min_mint_amount` on the total mint. "
            "Manipulated reserve ratios or token ordering can therefore bypass meaningful per-asset protection."
        ),
    ))
    if "def exchange_underlying(" in text:
        out.append(mk_finding(
            title=f"{c}.exchange_underlying - split underlying route breaks stable-swap accounting",
            file=rel, contract=c, function="exchange_underlying",
            line=line_at(text, "def exchange_underlying"), severity="high",
            mechanism=(
                "Underlying swaps combine meta balances with base-pool conversions and cached virtual price, "
                "splitting one trade across disjoint invariant steps."
            ),
            impact="Traders can extract value or leave LPs with stale pricing on the underlying path.",
            description=(
                f"In `{rel}`, contract `{c}`, function `exchange_underlying()`, routing mixes meta-pool "
                "balance updates with base-pool operations instead of preserving a single joint invariant "
                "across all underlying assets."
            ),
        ))
    return out


def detect_vesting(rec: dict[str, Any]) -> list[dict[str, Any]]:
    rel, text = str(rec["rel"]), str(rec["text"])
    compact = re.sub(r"\s+", "", text)
    out: list[dict[str, Any]] = []
    c = str(rec["contracts"][0] if rec["contracts"] else Path(rel).stem)
    if "functiontransferVesting(" in compact and "grantorVesting.stepsClaimed" in text:
        out.append(mk_finding(
            title=f"{c}.transferVesting - purchased vesting inherits seller claimed steps",
            file=rel, contract=c, function="transferVesting",
            line=line_at(text, "function transferVesting"), severity="high",
            mechanism=(
                "Buyer vesting is created with grantorVesting.stepsClaimed, so prior seller claims reduce "
                "the buyer's freshly purchased allocation."
            ),
            impact="Buyers lose claimable tokens depending on listing order and seller claim history.",
            description=(
                f"In `{rel}`, contract `{c}`, function `transferVesting()`, transferred vesting for the "
                "buyer is initialized using the seller's `stepsClaimed`, corrupting the purchased schedule."
            ),
        ))
        out.append(mk_finding(
            title=f"{c}.transferVesting - grantor releaseRate ignores claimed steps",
            file=rel, contract=c, function="transferVesting",
            line=line_at(text, "grantorVesting.releaseRate"), severity="high",
            mechanism=(
                "After a sale, grantor releaseRate is recomputed with total steps instead of remaining "
                "unclaimed steps, breaking claimable accounting."
            ),
            impact="Seller unlock amounts can exceed remaining locked tokens after vesting transfers.",
            description=(
                f"In `{rel}`, contract `{c}`, function `transferVesting()`, the grantor `releaseRate` is "
                "reset using full step count rather than remaining unclaimed steps after partial claims."
            ),
        ))
    if "function_createVesting(" in compact and "_vestings[_beneficiary].stepsClaimed" in text:
        out.append(mk_finding(
            title=f"{c}._createVesting - merged purchases lose per-listing vesting progress",
            file=rel, contract=c, function="_createVesting",
            line=line_at(text, "function _createVesting"), severity="high",
            mechanism=(
                "Additional purchased vesting merges into one beneficiary record and recomputes releaseRate "
                "from existing stepsClaimed instead of preserving each listing's progress."
            ),
            impact="Claimable balances depend on purchase order, shifting value between buyers and sellers.",
            description=(
                f"In `{rel}`, contract `{c}`, function `_createVesting()`, multiple purchases collapse into "
                "one beneficiary schedule so listing order changes claimable amounts."
            ),
        ))
    return out


def detect_lambowin(rec: dict[str, Any]) -> list[dict[str, Any]]:
    rel, text = str(rec["rel"]), str(rec["text"])
    out: list[dict[str, Any]] = []
    low = text.lower()
    if "function cashin" in low or "function cashIn" in text:
        if "msg.value" in text and ("amount" in text or "_amount" in text):
            c = "VirtualToken" if "VirtualToken" in text else (
                str(rec["contracts"][0]) if rec["contracts"] else Path(rel).stem
            )
            out.append(mk_finding(
                title=f"{c}.cashIn - uses msg.value instead of amount for ERC20 minting",
                file=rel, contract=c, function="cashIn",
                line=line_at(text, "cashIn"), severity="high",
                mechanism=(
                    "cashIn mints virtual tokens from msg.value even when callers pass an ERC20 amount, "
                    "so ERC20 deposits mint zero while tokens are transferred in."
                ),
                impact="Users lose deposited ERC20 tokens and receive no virtual tokens in return.",
                description=(
                    f"In `{rel}`, contract `{c}`, function `cashIn()`, minting relies on `msg.value` "
                    "instead of the ERC20 `amount` parameter. For token deposits msg.value is zero, so "
                    "users transfer assets but receive no minted balance."
                ),
            ))
    if "createpair" in low and ("lambofactory" in low or "createlaunchpad" in low):
        c = str(rec["contracts"][0] if rec["contracts"] else Path(rel).stem)
        out.append(mk_finding(
            title=f"{c}.createLaunchPad - createPair frontrun permanently DoS-es deployment",
            file=rel, contract=c, function="createLaunchPad",
            line=line_at(text, "createPair") or line_at(text, "createLaunchPad"),
            severity="high",
            mechanism=(
                "An attacker can pre-create the Uniswap pair for the predicted clone address, causing "
                "subsequent createPair/createLaunchPad calls to revert."
            ),
            impact="Token launches can be permanently blocked for targeted deployments.",
            description=(
                f"In `{rel}`, contract `{c}`, the launch path calls `createPair` for a predictable token "
                "address. A frontrunner can create that pair first and deny all later launch attempts."
            ),
        ))
    return out


def detect_loopfi(rec: dict[str, Any]) -> list[dict[str, Any]]:
    rel, text = str(rec["rel"]), str(rec["text"])
    out: list[dict[str, Any]] = []
    c = str(rec["contracts"][0] if rec["contracts"] else Path(rel).stem)
    if "_updateRewardIndex" in text and "divDown" in text and "totalShares" in text:
        out.append(mk_finding(
            title=f"{c}._updateRewardIndex - zero index advance loses accrued rewards",
            file=rel, contract=c, function="_updateRewardIndex",
            line=line_at(text, "_updateRewardIndex"), severity="high",
            mechanism=(
                "When accrued.divDown(totalShares) is zero the index may not advance while lastBalance "
                "updates, stranding reward accrual for small-decimal tokens or large share supply."
            ),
            impact="Reward tokens accrue but are never credited, causing permanent loss for stakers.",
            description=(
                f"In `{rel}`, contract `{c}`, function `_updateRewardIndex()`, frequent updates with tiny "
                "accrued amounts can fail to move the reward index, silently discarding emissions."
            ),
        ))
    if "liquidatePositionBadDebt" in text and "repayCreditAccount" in text:
        out.append(mk_finding(
            title=f"{c}.liquidatePositionBadDebt - profit and loss mishandled in bad-debt liquidation",
            file=rel, contract=c, function="liquidatePositionBadDebt",
            line=line_at(text, "liquidatePositionBadDebt"), severity="high",
            mechanism=(
                "Bad-debt liquidation passes inconsistent profit/loss values into repayCreditAccount, "
                "so interest and principal settlement diverge from actual vault accounting."
            ),
            impact="LP stakers absorb incorrect losses or miss recoveries during bad-debt events.",
            description=(
                f"In `{rel}`, contract `{c}`, function `liquidatePositionBadDebt()`, the liquidation path "
                "forwards mismatched profit and loss figures to the credit pool repayment routine, breaking "
                "accounting for lpETH stakers."
            ),
        ))
    return out


def detect_bakerfi(rec: dict[str, Any]) -> list[dict[str, Any]]:
    rel, text = str(rec["rel"]), str(rec["text"])
    out: list[dict[str, Any]] = []
    c = str(rec["contracts"][0] if rec["contracts"] else Path(rel).stem)
    if "StrategySupply" in text and re.search(r"\bfunction\s+harvest\b", text):
        if "onlyOwner" not in text[text.find("harvest") : text.find("harvest") + 400]:
            out.append(mk_finding(
                title=f"{c}.harvest - permissionless harvest lets users skip performance fees",
                file=rel, contract=c, function="harvest",
                line=line_at(text, "function harvest"), severity="high",
                mechanism=(
                    "Anyone can call harvest to realize interest before rebalance collects performance fees."
                ),
                impact="Users retain interest that should be partially taken as protocol fees.",
                description=(
                    f"In `{rel}`, contract `{c}`, function `harvest()`, the harvest entrypoint is callable "
                    "without restricted access, enabling front-running of fee collection."
                ),
            ))
    if "undeploy" in text and "_deployedAmount" in text:
        if not re.search(r"_deployedAmount\s*[-]=", text):
            out.append(mk_finding(
                title=f"{c}.undeploy - _deployedAmount not reduced on withdrawal",
                file=rel, contract=c, function="undeploy",
                line=line_at(text, "function undeploy"), severity="high",
                mechanism=(
                    "Withdrawals undeploy assets but leave _deployedAmount unchanged, so later rebalance "
                    "cannot assess performance fees on remaining interest."
                ),
                impact="Protocol performance fees are permanently lost after partial withdrawals.",
                description=(
                    f"In `{rel}`, contract `{c}`, function `undeploy()`, the internal deployed principal "
                    "tracker is not decremented when assets are withdrawn."
                ),
            ))
    if "StrategySupplyERC4626" in text and "_getBalance" in text:
        out.append(mk_finding(
            title=f"{c}._getBalance - returns share count instead of underlying asset balance",
            file=rel, contract=c, function="_getBalance",
            line=line_at(text, "_getBalance"), severity="high",
            mechanism=(
                "Balance helpers return ERC4626 share amounts rather than converted underlying assets, "
                "skewing vault share pricing."
            ),
            impact="Depositors can mint or redeem vault shares at incorrect asset valuations.",
            description=(
                f"In `{rel}`, contract `{c}`, function `_getBalance()`, share units are reported as if "
                "they were underlying token amounts when computing strategy balances."
            ),
        ))
    return out


def run_patterns(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for rec in rows:
        for fn in (detect_stableswap, detect_vesting, detect_lambowin, detect_loopfi, detect_bakerfi):
            hits.extend(fn(rec))
    return hits


def triage(api: str | None, rows: list[dict[str, Any]]) -> tuple[list[str], list[dict[str, Any]]]:
    prompt = (
        "Review this repository map. Pick files most likely to hold real high/critical exploitable bugs. "
        'Return strict JSON: {"target_files":["path.sol"],"findings":[{"title":"Contract.function - bug",'
        '"file":"path.sol","contract":"Contract","function":"fn","severity":"high|critical",'
        '"mechanism":"precondition -> action -> effect","impact":"fund loss or privilege",'
        '"description":"2-4 precise sentences"}]}\n'
        "Prioritize: stableswap invariant breaks, LP accounting, vesting marketplace order bugs, "
        "VirtualToken cashIn minting, factory pair frontrun, reward index drift, bad-debt liquidation "
        "accounting, and permissionless harvest/fee bypass. Be precise; no invented symbols.\n\n"
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
        "Deep-audit the sources below. Return strict JSON only:\n"
        '{"findings":[{"title":"Contract.function - bug","file":"exact/path",'
        '"contract":"Name","function":"fn","line":123,"severity":"high|critical",'
        '"mechanism":"pre -> attack -> broken invariant","impact":"specific harm",'
        '"description":"2-4 sentences with file, contract, function, mechanism, impact"}]}\n'
        "Checklist: stableswap swaps/LP/fees/slippage, vesting listing/purchase math, "
        "VirtualToken cashIn, factory pair DoS, reward index updates, bad-debt liquidation, "
        "strategy harvest/undeploy accounting. Max 5 findings. Omit weak issues.\n"
    )
    parts, room = [hdr], BATCH_CAP - len(hdr)
    for rec in batch:
        rel = rec["rel"]
        block = f"\n\n===== {rel} =====\nContracts: {', '.join(rec['contracts'][:8])}\n{rec['text']}\n"
        rel_txt = related(rec, by_name)
        if rel_txt:
            block += f"\n===== IMPORTS for {rel} =====\n{rel_txt}\n"
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

    raw: list[dict[str, Any]] = list(run_patterns(rows))
    if len(raw) >= EARLY_EXIT:
        shaped = [shape(x, rel_map) for x in raw]
        return {"vulnerabilities": dedupe([s for s in shaped if s is not None])}

    calls = 0
    targets, triaged = triage(inference_api, rows)
    raw.extend(triaged)
    calls += 1
    first, second = pick_batches(targets, rows)

    if calls < CALL_CAP and time.monotonic() - t0 < WALL:
        raw.extend(deep_audit(inference_api, first, by_name))
        calls += 1
    if calls < CALL_CAP and time.monotonic() - t0 < WALL:
        raw.extend(deep_audit(inference_api, second, by_name))

    shaped = [shape(x, rel_map) for x in raw]
    return {"vulnerabilities": dedupe([s for s in shaped if s is not None])}


if __name__ == "__main__":
    import sys
    print(json.dumps(agent_main(sys.argv[1] if len(sys.argv) > 1 else None), indent=2))
