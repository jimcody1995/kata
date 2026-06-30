from __future__ import annotations

import json


def render_seed_agent(*, instruction_text: str, mode: str, label: str) -> str:
    instruction_literal = json.dumps(instruction_text.rstrip() + "\n")
    lane_literal = json.dumps(mode)
    label_literal = json.dumps(label)
    return f"""from __future__ import annotations

\"\"\"Seeded Kata agent for the {mode} lane ({label}).\"\"\"

import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

SEED_INSTRUCTIONS = {instruction_literal}
LANE_MODE = {lane_literal}
AGENT_LABEL = {label_literal}
MAX_FILE_BYTES = 4000
MAX_TOTAL_BYTES = 48000
MAX_FILES = 40


def solve(repo_path: str, issue: str, model: str, api_base: str, api_key: str) -> dict:
    if not model:
        return {{
            "success": False,
            "message": "validator did not provide a model",
            "diff": "",
        }}
    if not api_base:
        return {{
            "success": False,
            "message": "validator did not provide an api_base",
            "diff": "",
        }}

    repo_root = Path(repo_path).resolve()
    repo_context = build_repo_context(repo_root)
    response_text = request_diff(
        model=model,
        api_base=api_base,
        api_key=api_key,
        issue=issue,
        repo_context=repo_context,
    )
    diff_text = normalize_diff(response_text)
    if not diff_text:
        return {{
            "success": False,
            "message": "model did not return an applicable unified diff",
            "diff": "",
        }}
    return {{
        "success": True,
        "message": f"{{AGENT_LABEL}} seed agent produced a diff",
        "diff": diff_text,
    }}


def build_repo_context(repo_root: Path) -> str:
    tracked_files = list_tracked_files(repo_root)
    tree_lines: list[str] = []
    file_sections: list[str] = []
    total_bytes = 0
    included = 0

    for relative_path in tracked_files:
        tree_lines.append(relative_path)
        if included >= MAX_FILES:
            continue
        absolute_path = repo_root / relative_path
        if not absolute_path.is_file():
            continue
        if absolute_path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            content = absolute_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        encoded_size = len(content.encode("utf-8"))
        if total_bytes + encoded_size > MAX_TOTAL_BYTES:
            continue
        file_sections.append(
            f"### FILE: {{relative_path}}\\n```\\n{{content.rstrip()}}\\n```"
        )
        total_bytes += encoded_size
        included += 1

    tree_text = "\\n".join(tree_lines)
    files_text = "\\n\\n".join(file_sections) if file_sections else "(no file contents captured)"
    return (
        "## Repository Tree\\n"
        f"{{tree_text}}\\n\\n"
        "## Sample File Contents\\n"
        f"{{files_text}}"
    )


def list_tracked_files(repo_root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def request_diff(
    *,
    model: str,
    api_base: str,
    api_key: str,
    issue: str,
    repo_context: str,
) -> str:
    system_prompt = (
        "You are a repo-specific coding agent for Kata. "
        "Return only a unified diff that can be applied with git apply. "
        "Do not return prose, markdown fences, or explanations.\\n\\n"
        "Repo-specific instructions:\\n"
        f"{{SEED_INSTRUCTIONS}}"
    )
    user_prompt = (
        f"Lane mode: {{LANE_MODE}}\\n\\n"
        "Task:\\n"
        f"{{issue.strip()}}\\n\\n"
        f"{{repo_context}}\\n\\n"
        "Output requirement: return only the final unified diff."
    )
    payload = {{
        "model": model,
        "messages": [
            {{"role": "system", "content": system_prompt}},
            {{"role": "user", "content": user_prompt}},
        ],
        "temperature": 0.2,
        "max_tokens": 2000,
    }}
    request = urllib.request.Request(
        build_chat_completions_url(api_base),
        data=json.dumps(payload).encode("utf-8"),
        headers=build_headers(api_key),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"chat completion request failed: {{exc.code}} {{detail}}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"chat completion request failed: {{exc.reason}}") from exc
    return extract_message_content(response_payload)


def build_chat_completions_url(api_base: str) -> str:
    base = api_base.rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def build_headers(api_key: str) -> dict[str, str]:
    headers = {{
        "Content-Type": "application/json",
    }}
    if api_key:
        headers["Authorization"] = f"Bearer {{api_key}}"
    return headers


def extract_message_content(payload: dict) -> str:
    choices = payload.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {{}}
    content = message.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(str(item.get("text", "")))
        return "".join(parts)
    return str(content)


def normalize_diff(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\\n".join(lines).strip()
    if text.startswith("diff --git") or text.startswith("--- "):
        return text + "\\n"
    return ""
"""
