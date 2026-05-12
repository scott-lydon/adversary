"""LiteLLMProvider: import-guarded wrapper around litellm.completion.

This module never imports litellm at module-import time. The
``LiteLLMProvider.__init__`` raises with a comprehensive remediation message if
the required API key for a given agent role is missing. The provider is the
seam where swapping to a real model is one config switch.
"""

from __future__ import annotations

import os
from typing import Any

from adversary.models import (
    Attack,
    AttackCategory,
    CampaignBrief,
    JudgeRequest,
    Verdict,
)
from adversary.providers.base import ProviderError

# Map agent role -> (model name, required env var).
_DEFAULT_MODELS: dict[str, tuple[str, str]] = {
    "red_team": ("together_ai/meta-llama/Llama-3.1-70B-Instruct-Turbo", "TOGETHER_API_KEY"),
    "judge": ("anthropic/claude-sonnet-4-20250514", "ANTHROPIC_API_KEY"),
    "documentation": ("openai/gpt-5", "OPENAI_API_KEY"),
    "orchestrator": ("openai/gpt-5-mini", "OPENAI_API_KEY"),
}


class LiteLLMProvider:
    """Live LLM provider backed by litellm.completion.

    The provider validates required API keys up-front. Per-method calls lazy-
    import litellm so the package imports cleanly without litellm installed.
    """

    name = "live"

    def __init__(
        self,
        models: dict[str, str] | None = None,
        require_keys: bool = True,
    ) -> None:
        self.models: dict[str, str] = {
            role: (models or {}).get(role, default[0])
            for role, default in _DEFAULT_MODELS.items()
        }
        if require_keys:
            missing: list[str] = []
            for role, (_, env_var) in _DEFAULT_MODELS.items():
                if not os.environ.get(env_var):
                    missing.append(f"{role}->{env_var}")
            if missing:
                raise ProviderError(
                    "LiteLLMProvider: provider='live' was selected but the "
                    "following API keys are missing from the environment: "
                    f"{', '.join(missing)}. Set them or pass --provider scripted "
                    "for offline mode."
                )

    def _completion(self, role: str, messages: list[dict[str, str]]) -> str:
        try:
            import litellm  # noqa: WPS433 - lazy import is intentional
        except ImportError as exc:  # pragma: no cover - litellm import path
            raise ProviderError(
                "LiteLLMProvider: litellm is not installed. "
                "Run `pip install 'adversary[dev]'` to bring it in, or use "
                "--provider scripted for the offline path."
            ) from exc

        model = self.models[role]
        try:
            response = litellm.completion(model=model, messages=messages)
        except Exception as exc:  # pragma: no cover - exercised only with keys
            raise ProviderError(
                f"LiteLLMProvider.{role}: litellm.completion failed for "
                f"model={model!r}: {exc}. Check the model name in "
                "config/models.yaml and the corresponding API key."
            ) from exc
        # litellm returns OpenAI-shaped responses.
        return str(response["choices"][0]["message"]["content"])

    async def red_team(self, brief: CampaignBrief) -> list[Attack]:  # pragma: no cover
        raise ProviderError(
            "LiteLLMProvider.red_team: real RedTeam generation is not "
            "exercised in the offline test suite. Run with "
            "ADVERSARY_LIVE_PROVIDER=1 and real keys to use it."
        )

    async def judge(self, request: JudgeRequest) -> Verdict:  # pragma: no cover
        raise ProviderError(
            "LiteLLMProvider.judge: live Judge calls require ANTHROPIC_API_KEY "
            "and exercise the production path. Use ScriptedProvider for tests."
        )

    async def documentation(self, exploit: dict[str, Any]) -> str:  # pragma: no cover
        raise ProviderError(
            "LiteLLMProvider.documentation: live Documentation runs require "
            "OPENAI_API_KEY. Use ScriptedProvider for the offline path."
        )

    async def orchestrate(  # pragma: no cover
        self, coverage_snapshot: dict[str, Any]
    ) -> AttackCategory:
        raise ProviderError(
            "LiteLLMProvider.orchestrate: live Orchestrator runs require "
            "OPENAI_API_KEY. Use ScriptedProvider for the offline path."
        )
