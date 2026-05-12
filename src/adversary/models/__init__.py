"""Pydantic models used across the adversary platform."""

from __future__ import annotations

from adversary.models.attack import (
    Attack,
    AttackCategory,
    CampaignBrief,
    GenerationMetadata,
)
from adversary.models.target import (
    TargetMessage,
    TargetResponse,
    TargetSession,
)
from adversary.models.target_record import (
    AuthKind,
    TargetKind,
    TargetRecord,
    TargetSubmission,
    is_private_hostname,
)
from adversary.models.verdict import (
    JudgeRequest,
    Verdict,
    VerdictLabel,
)

__all__ = [
    "Attack",
    "AttackCategory",
    "AuthKind",
    "CampaignBrief",
    "GenerationMetadata",
    "JudgeRequest",
    "TargetKind",
    "TargetMessage",
    "TargetRecord",
    "TargetResponse",
    "TargetSession",
    "TargetSubmission",
    "Verdict",
    "VerdictLabel",
    "is_private_hostname",
]
