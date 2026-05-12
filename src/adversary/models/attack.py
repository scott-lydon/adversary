"""Attack-side Pydantic models: campaign briefs, attacks, generation metadata."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from adversary.models.target import TargetMessage


class AttackCategory(str, Enum):
    """Closed set of attack categories drawn from THREAT_MODEL.md."""

    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    MULTI_TURN_PROMPT_INJECTION = "multi_turn_prompt_injection"
    DATA_EXFILTRATION_CROSS_PATIENT = "data_exfiltration_cross_patient"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    SNAPSHOT_POISONING = "snapshot_poisoning"
    PERSONA_HIJACKING = "persona_hijacking"
    TRUST_BOUNDARY_DISCLOSURE = "trust_boundary_disclosure"
    COST_AMPLIFICATION = "cost_amplification"
    TOOL_MISUSE = "tool_misuse"


class GenerationMetadata(BaseModel):
    """Per-attack metadata: which model produced it, what it cost."""

    model_config = ConfigDict(extra="forbid")

    model: str
    prompt_version: str
    dollar_cost: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0


class Attack(BaseModel):
    """A single adversarial probe with a planned prompt sequence."""

    model_config = ConfigDict(extra="forbid")

    attack_id: str
    category: AttackCategory
    subcategory: str
    prompt_sequence: list[TargetMessage] = Field(min_length=1)
    expected_unsafe_behavior: str
    mutation_lineage: list[str] = Field(default_factory=list)
    generation_metadata: GenerationMetadata


class CampaignBrief(BaseModel):
    """Marching orders the Orchestrator hands to the RedTeam agent."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    category: AttackCategory
    subcategory: str
    seed_examples: list[str] = Field(default_factory=list)
    prior_failures: list[str] = Field(default_factory=list)
    target_session_template: dict[str, Any] = Field(default_factory=dict)
    budget_remaining_usd: float
    max_attacks: int = Field(ge=1, le=200, default=5)
    seed: int | None = None
