"""Subnet-agnostic core orchestration for Kata.

This package holds the platform's King-of-the-Hill machinery that is driven through
the :class:`~kata.plugins.contract.SubnetPlugin` interface and shared by every subnet.
"""

from __future__ import annotations

from .challenge import ChallengeOutcome, ScoredVariant, run_plugin_challenge

__all__ = ["ChallengeOutcome", "ScoredVariant", "run_plugin_challenge"]
