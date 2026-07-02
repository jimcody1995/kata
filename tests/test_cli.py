from __future__ import annotations

import json
from pathlib import Path

from kata.cli import build_parser, main


def test_top_level_cli_exposes_agent_competition_commands() -> None:
    parser = build_parser()
    subparser_action = next(
        action
        for action in parser._actions
        if getattr(action, "choices", None)
    )
    commands = set(subparser_action.choices)

    assert {"frontier", "challenge", "submission", "eval-pack", "registry", "report"} <= commands
    assert "lane" in commands
    assert "generate" not in commands
    assert "baseline" not in commands
    assert "eval" not in commands


def test_lane_cli_registers_and_lists_packs(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    init_payload = json.loads(capsys.readouterr().out)
    assert init_payload["lane_id"] == "sn60__bitsec"

    assert (
        main(
            [
                "lane",
                "list",
                "--active-only",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    list_payload = json.loads(capsys.readouterr().out)
    assert [pack["lane_id"] for pack in list_payload["packs"]] == ["sn60__bitsec"]
    assert list_payload["packs"][0]["evaluator_id"] == "sn60_bitsec"
    assert list_payload["packs"][0]["active"] is True

    registry_path = tmp_path / "lanes" / "registry.json"
    assert registry_path.exists()

    # Deactivate and confirm active-only listing excludes the lane.
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--inactive",
                "--public-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "lane",
                "list",
                "--active-only",
                "--public-root",
                str(tmp_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["packs"] == []


def test_lane_cli_sync_registry_rebuilds_from_disk(tmp_path: Path, capsys) -> None:
    assert (
        main(
            [
                "lane",
                "init",
                "--lane-id",
                "sn60__bitsec",
                "--evaluator-id",
                "sn60_bitsec",
                "--public-root",
                str(tmp_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    (tmp_path / "lanes" / "registry.json").unlink()

    assert main(["lane", "sync-registry", "--public-root", str(tmp_path), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["packs"] == ["sn60__bitsec"]
