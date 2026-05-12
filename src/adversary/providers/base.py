"""LLM provider protocol shared between RedTeam, Judge, Documentation agents.

The provider is the only seam through which a model speaks. The scripted
provider is fully deterministic and offline; the litellm provider is the
production path. Tests pin themselves to ``ScriptedProvider`` unless
``ADVERSARY_LIVE_PROVIDER=1`` is set.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from adversary.models import (
    Attack,
    AttackCategory,
    CampaignBrief,
    JudgeRequest,
    Verdict,
)


class ProviderError(RuntimeError):
    """Raised when a provider cannot complete a request.

    The message must include the failing operation, the offending model/agent
    role, and a concrete remediation. The most common case is a missing
    API key; ``LiteLLMProvider.__init__`` documents which env var to set.
    """


@runtime_checkable
class LLMProvider(Protocol):
    """Minimal protocol an LLM provider implements for each agent role."""

    name: str

    async def red_team(self, brief: CampaignBrief) -> list[Attack]:
        """Produce one or more attacks from a campaign brief."""

    async def judge(self, request: JudgeRequest) -> Verdict:
        """Evaluate an attack/response pair and return a Verdict."""

    async def documentation(
        self, exploit: dict[str, Any]
    ) -> str:
        """Produce the markdown body for a vulnerability report."""

    async def orchestrate(
        self, coverage_snapshot: dict[str, Any]
    ) -> AttackCategory:
        """Pick the next category to test from a coverage snapshot."""
