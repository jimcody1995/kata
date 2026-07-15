"""Maintained SN60 baseline king.

This is deliberately modest: it walks Solidity source files and uses the
in-room, miner-funded ``INFERENCE_API`` only when one is provided.  Without a
sealed miner credential it makes no inference calls and returns no findings.
It establishes an auditable, non-empty starting bar for the first competition
round; challengers must beat it under the same benchmark selection.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

MAX_FILES = 8
MAX_FILE_CHARS = 10_000
MAX_FINDINGS = 8


def _project_root(project_dir: str | None) -> Path | None:
    for candidate in (project_dir, os.environ.get("PROJECT_DIR"), "/app/project_code", "."):
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return None


def _source_files(root: Path) -> list[tuple[str, str]]:
    files: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*.sol")):
        if len(files) >= MAX_FILES or not path.is_file():
            break
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if source.strip():
            files.append((str(path.relative_to(root)), source[:MAX_FILE_CHARS]))
    return files


def _findings_from_response(content: str, source_file: str) -> list[dict[str, object]]:
    match = re.search(r"\[.*\]", content, re.DOTALL)
    if not match:
        return []
    try:
        items = json.loads(match.group(0))
    except ValueError:
        return []
    findings: list[dict[str, object]] = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            line = int(item.get("line", 0))
        except (TypeError, ValueError):
            line = 0
        findings.append(
            {
                "title": str(item.get("title", "security issue"))[:200],
                "severity": str(item.get("severity", "medium")).lower(),
                "file": source_file,
                "line": line,
                "description": str(item.get("description", ""))[:1000],
            }
        )
    return findings


def _audit_file(inference_api: str | None, source_file: str, source: str) -> list[dict[str, object]]:
    endpoint = (inference_api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return []
    prompt = (
        "Audit this Solidity file for exploitable high-severity vulnerabilities. "
        "Return only a JSON array of objects with title, severity, line, and description. "
        "Do not invent findings.\n\n"
        f"FILE: {source_file}\n```solidity\n{source}\n```"
    )
    body = json.dumps(
        {"messages": [{"role": "user", "content": prompt}], "max_tokens": 1800}
    ).encode()
    request = urllib.request.Request(
        endpoint + "/inference",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return _findings_from_response(payload["choices"][0]["message"]["content"], source_file)
    except (urllib.error.URLError, OSError, KeyError, IndexError, TypeError, ValueError):
        return []


def agent_main(project_dir: str | None = None, inference_api: str | None = None) -> dict:
    findings: list[dict[str, object]] = []
    root = _project_root(project_dir)
    if root is not None:
        for source_file, source in _source_files(root):
            findings.extend(_audit_file(inference_api, source_file, source))
            if len(findings) >= MAX_FINDINGS:
                break
    return {"vulnerabilities": findings[:MAX_FINDINGS]}
