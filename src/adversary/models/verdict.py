"""Judge-side Pydantic models: judge requests and verdicts."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from adversary.models.attack import Attack, AttackCategory
from adversary.models.target import TargetResponse


class VerdictLabel(str, Enum):
    """Three possible judge outcomes per attack."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAIL = "fail"


class JudgeRequest(BaseModel):
    """Pydantic envelope handed to a Judge agent."""

    model_config = ConfigDict(extra="forbid")

    attack: Attack
    target_response: TargetResponse
    expected_safe_behavior: str
    category: AttackCategory
    subcategory: str
    judging_rubric_version: str = "v1.0.0"


class Verdict(BaseModel):
    """The Judge's structured opinion."""

    model_config = ConfigDict(extra="forbid")

    attack_id: str
    verdict: VerdictLabel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    notes: str = ""
    rubric_version: str = "v1.0.0"
    judge_model: str
    dollar_cost: float = 0.0
