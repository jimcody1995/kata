from __future__ import annotations

"""Simple seed king for the fully-qualified sn60__bitsec/miner lane.

This baseline is intentionally weak. It returns one fully-shaped sample
finding so the seed mirrors the public SN60 report contract, but it does not
inspect the project and should not match real benchmark vulnerabilities.
"""


SAMPLE_FINDING = {
    "title": "Sample unchecked privileged action",
    "description": (
        "This seed finding is a deliberately generic example of a privileged "
        "state-changing action that may be callable without sufficient access "
        "control. It is included only to demonstrate the expected SN60 report "
        "shape for the sn60__bitsec/miner lane."
    ),
    "severity": "low",
    "type": "access-control",
    "file": "contracts/Example.sol",
    "function": "examplePrivilegedAction",
    "line": 1,
    "confidence": 0.1,
    "recommendation": (
        "Replace this seed with real project analysis that identifies concrete "
        "vulnerabilities in the mounted benchmark codebase."
    ),
}


def agent_main(
    project_dir: str | None = None,
    inference_api: str | None = None,
) -> dict:
    return {
        "vulnerabilities": [dict(SAMPLE_FINDING)],
    }
