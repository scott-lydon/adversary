"""JudgeAgent: wraps an LLMProvider to evaluate attack/response pairs."""

from __future__ import annotations

from adversary.models import (
    Attack,
    AttackCategory,
    JudgeRequest,
    TargetResponse,
    Verdict,
)
from adversary.providers.base import LLMProvider


class JudgeAgent:
    """Evaluates attack/response pairs and emits a Verdict."""

    name = "judge"

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    async def evaluate(
        self,
        attack: Attack,
        target_response: TargetResponse,
        expected_safe_behavior: str,
        rubric_version: str = "v1.0.0",
    ) -> Verdict:
        request = JudgeRequest(
            attack=attack,
            target_response=target_response,
            expected_safe_behavior=expected_safe_behavior,
            category=AttackCategory(attack.category),
            subcategory=attack.subcategory,
            judging_rubric_version=rubric_version,
        )
        return await self.provider.judge(request)
