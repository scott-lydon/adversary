"""T12: live LLM provider (marker-gated)."""

from __future__ import annotations

import os

import pytest

from adversary.providers import LiteLLMProvider, ProviderError

LIVE = os.environ.get("ADVERSARY_LIVE_PROVIDER") == "1"


def test_litellm_raises_without_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ["TOGETHER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"]:
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ProviderError, match="missing"):
        LiteLLMProvider()


def test_litellm_loads_with_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOGETHER_API_KEY", "test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    # Just constructing it should succeed; calls are not made here.
    prov = LiteLLMProvider()
    assert prov.name == "live"


@pytest.mark.live
@pytest.mark.skipif(not LIVE, reason="ADVERSARY_LIVE_PROVIDER=1 required")
def test_live_provider_runs() -> None:
    # Placeholder: a real test would exercise an actual completion.
    LiteLLMProvider()
