"""T4: RedTeam agent generates structured Attack objects."""

from __future__ import annotations

from uuid import uuid4

import pytest

from adversary.agents import RedTeamAgent
from adversary.models import AttackCategory, CampaignBrief
from adversary.providers import ScriptedProvider


@pytest.mark.asyncio
async def test_scripted_generates_valid_attack() -> None:
    agent = RedTeamAgent(ScriptedProvider(seed=42))
    brief = CampaignBrief(
        campaign_id=f"camp-{uuid4().hex[:6]}",
        category=AttackCategory.INDIRECT_PROMPT_INJECTION,
        subcategory="chart_notes",
        budget_remaining_usd=1.0,
        max_attacks=3,
        seed=42,
    )
    attacks = await agent.generate(brief)
    assert len(attacks) >= 1
    a = attacks[0]
    assert a.category == AttackCategory.INDIRECT_PROMPT_INJECTION
    assert a.subcategory == "chart_notes"
    assert a.prompt_sequence and a.prompt_sequence[0].text
    assert a.expected_unsafe_behavior
    assert a.generation_metadata.dollar_cost > 0


@pytest.mark.asyncio
async def test_deterministic_seed() -> None:
    a1 = await ScriptedProvider().red_team(
        CampaignBrief(
            campaign_id="c1",
            category=AttackCategory.DIRECT_PROMPT_INJECTION,
            subcategory="ignore_prior",
            budget_remaining_usd=1.0,
            max_attacks=3,
            seed=99,
        )
    )
    a2 = await ScriptedProvider().red_team(
        CampaignBrief(
            campaign_id="c2",
            category=AttackCategory.DIRECT_PROMPT_INJECTION,
            subcategory="ignore_prior",
            budget_remaining_usd=1.0,
            max_attacks=3,
            seed=99,
        )
    )
    assert [att.prompt_sequence[0].text for att in a1] == [
        att.prompt_sequence[0].text for att in a2
    ]
