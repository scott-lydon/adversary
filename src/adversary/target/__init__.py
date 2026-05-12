"""Target adapter package."""

from __future__ import annotations

from adversary.target.adapter import (
    TargetAdapter,
    TargetUnreachable,
    open_adapter,
)
from adversary.target.echo import EchoTarget
from adversary.target.copilot import ClinicalCoPilotAdapter

__all__ = [
    "ClinicalCoPilotAdapter",
    "EchoTarget",
    "TargetAdapter",
    "TargetUnreachable",
    "open_adapter",
]
