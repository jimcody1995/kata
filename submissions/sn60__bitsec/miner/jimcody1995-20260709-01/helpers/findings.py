from __future__ import annotations

import re
from typing import Any


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
    if len(mechanism) < 20 and len(description) < 100:
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
    basename = file_hint.rsplit("/", 1)[-1]
    loc_bits = [f"`{file_hint}`"]
    if basename != file_hint:
        loc_bits.append(f"`{basename}`")
    if function:
        loc_bits.append(f"`{function}()`")
    hint = " Affected location: " + ", ".join(loc_bits) + "."
    if hint.strip() not in description:
        description = description.rstrip() + hint
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


def collapse_findings(items: list[dict[str, Any]], cap: int = 8) -> list[dict[str, Any]]:
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
            str(item.get("title") or "").lower()[:110],
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= cap:
            break
    return out
