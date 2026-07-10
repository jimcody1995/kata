from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any

HTTP_WAIT = 145
MAX_CALLS = 3


class CallBudget:
    def __init__(self) -> None:
        self.used = 0

    def can_call(self) -> bool:
        return self.used < MAX_CALLS

    def mark(self) -> None:
        self.used += 1


def infer(
    api: str | None,
    msgs: list[dict[str, str]],
    token_cap: int,
    budget: CallBudget,
) -> str:
    if not budget.can_call():
        return ""
    endpoint = (api or os.environ.get("INFERENCE_API") or "").rstrip("/")
    if not endpoint:
        return ""
    payload = json.dumps({
        "messages": msgs,
        "max_tokens": token_cap,
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-inference-api-key": os.environ.get("INFERENCE_API_KEY", ""),
    }
    last: Exception | None = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(endpoint + "/inference", data=payload, method="POST", headers=headers)
            with urllib.request.urlopen(req, timeout=HTTP_WAIT) as resp:
                budget.mark()
                return pull_text(json.loads(resp.read().decode("utf-8", "replace")))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                return ""
            last = exc
        except (OSError, ValueError, TimeoutError) as exc:
            last = exc
        if attempt < 1:
            time.sleep(1.0)
    return ""


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
    if not stripped:
        return {}
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
