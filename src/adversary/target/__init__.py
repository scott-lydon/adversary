"""Target adapter package."""

from __future__ import annotations

from adversary.target.adapter import (
    TargetAdapter,
    TargetUnreachable,
    open_adapter,
)
from adversary.target.echo import EchoTarget
from adversary.target.copilot import ClinicalCoPilotAdapter
from adversary.target.registry import (
    TargetNotAllowlisted,
    assert_allowlisted,
    register_from_submission,
    resolve_by_name,
    resolve_by_url,
)

__all__ = [
    "ClinicalCoPilotAdapter",
    "EchoTarget",
    "TargetAdapter",
    "TargetNotAllowlisted",
    "TargetUnreachable",
    "assert_allowlisted",
    "open_adapter",
    "register_from_submission",
    "resolve_by_name",
    "resolve_by_url",
]
