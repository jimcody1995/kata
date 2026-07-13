"""Layer 2 tests: the renaming-invariance canary.

A memorizer keyed on project identifiers loses its findings when identifiers are
renamed; a genuine analyzer keeps them. The canary turns that into a review signal.
"""

from __future__ import annotations

from kata.screening_system.mutation_canary import (
    assess_rename_invariance,
    find_rename_dependent_findings,
    rename_solidity_identifiers,
    run_rename_invariance_canary,
)

SOLIDITY = """
// buffer accounting for HYPE withdrawals
pragma solidity ^0.8.20;

contract StakingBuffer {
    uint256 public hypeBuffer;
    mapping(address => uint256) public _cancelledWithdrawalAmount;

    function cancelWithdrawal(address user, uint256 amountFromBuffer) external {
        // note: redelegateWithdrawnHYPE is called elsewhere
        _cancelledWithdrawalAmount[user] += amountFromBuffer;
        require(msg.sender == user, "not user");
    }
}
"""


def test_renamer_renames_distinctive_identifiers_consistently() -> None:
    renamed, mapping = rename_solidity_identifiers(SOLIDITY)
    # Distinctive project identifiers are renamed...
    # These identifiers appear only in code (not comments), so renaming removes them.
    for ident in ("hypeBuffer", "cancelWithdrawal", "amountFromBuffer", "StakingBuffer",
                  "_cancelledWithdrawalAmount"):
        assert ident in mapping, f"{ident} should be renamed"
        assert ident not in renamed
    # ...consistently (same original -> same replacement everywhere).
    assert renamed.count(mapping["_cancelledWithdrawalAmount"]) == 2


def test_renamer_preserves_reserved_and_structure() -> None:
    renamed, mapping = rename_solidity_identifiers(SOLIDITY)
    for reserved in ("pragma", "contract", "function", "uint256", "address", "mapping",
                     "external", "require", "msg", "public"):
        assert reserved not in mapping
        assert reserved in renamed
    # Comments/strings are untouched (identifiers inside them are not renamed).
    assert "redelegateWithdrawnHYPE" in renamed  # only appears in a comment
    assert '"not user"' in renamed


def test_renamer_breaks_the_kings_fingerprint_identifiers() -> None:
    # The exact identifiers the reigning king fingerprints on must be renamed away.
    src = "uint256 redelegateWithdrawnHYPE; function targetCollateral() {}"
    renamed, mapping = rename_solidity_identifiers(src)
    assert "redelegateWithdrawnHYPE" in mapping
    assert "targetCollateral" in mapping
    assert "redelegateWithdrawnHYPE" not in renamed
    assert "targetCollateral" not in renamed


def _memorizer_agent(source: str) -> list[dict]:
    """Simulates the gaming king: emits a canned finding only when a benchmark-unique
    code identifier is present (fingerprint match). Keys on `hypeBuffer`, which is a
    real variable in the source (so renaming removes it), not a comment-only token."""
    if "hypebuffer" in source.lower():
        return [
            {
                "title": "Withdrawal cancellation leaves buffer funds locked",
                "description": "Canned pre-written finding about the HYPE buffer.",
                "severity": "high",
            }
        ]
    return []


def _genuine_agent(source: str) -> list[dict]:
    """Simulates a real analyzer: finds a += inside a function -- a logic pattern that
    survives identifier renaming."""
    if "+=" in source and "function" in source:
        return [
            {
                "title": "Unchecked accounting increment",
                "description": "A balance is incremented without a matching decrement.",
                "severity": "high",
            }
        ]
    return []


def test_canary_flags_memorizer_findings_collapse() -> None:
    result = run_rename_invariance_canary(run_agent=_memorizer_agent, project_source=SOLIDITY)
    assert result.suspicious is True
    assert result.original_count == 1
    assert result.renamed_count == 0
    assert result.rename_dependent  # the canned finding vanished under renaming


def test_canary_passes_genuine_analyzer() -> None:
    result = run_rename_invariance_canary(run_agent=_genuine_agent, project_source=SOLIDITY)
    assert result.suspicious is False
    assert result.original_count == 1 and result.renamed_count == 1
    assert result.rename_dependent == []


def test_find_rename_dependent_findings_matches_verbatim() -> None:
    original = [
        {"title": "A", "description": "canned"},
        {"title": "B", "description": "kept"},
    ]
    renamed = [{"title": "B", "description": "kept"}]
    assert find_rename_dependent_findings(original, renamed) == ["A"]


def test_assess_respects_min_rename_dependent_threshold() -> None:
    original = [{"title": "A", "description": "x"}]
    renamed: list[dict] = []
    assert assess_rename_invariance(original, renamed, min_rename_dependent=1).suspicious is True
    assert assess_rename_invariance(original, renamed, min_rename_dependent=2).suspicious is False
