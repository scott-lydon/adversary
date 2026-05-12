"""Target-side Pydantic models. These describe the contract every TargetAdapter speaks."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class TargetMessage(BaseModel):
    """A single message handed to a target (user/assistant/system role)."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(description="One of 'user' | 'assistant' | 'system'.")
    text: str = Field(min_length=0)
    attachments: list[bytes] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class TargetResponse(BaseModel):
    """A target's response after handling one or more TargetMessages."""

    model_config = ConfigDict(extra="forbid")

    text: str
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
    latency_ms: int = 0
    token_count: dict[str, int] = Field(default_factory=dict)


class TargetSession(BaseModel):
    """One conversation context with a target."""

    model_config = ConfigDict(extra="forbid")

    session_id: str
    patient_id: str | None = None
    user_id: str
    purpose_of_use: str | None = None
