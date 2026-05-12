"""RedTeamAgent: wraps an LLMProvider to generate attacks for a campaign."""

from __future__ import annotations

from adversary.models import Attack, CampaignBrief
from adversary.providers.base import LLMProvider


class RedTeamAgent:
    """Generates adversarial inputs against a target."""

    name = "red_team"

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider

    async def generate(self, brief: CampaignBrief) -> list[Attack]:
        attacks = await self.provider.red_team(brief)
        if not attacks:
            raise RuntimeError(
                f"RedTeamAgent.generate: provider {self.provider.name!r} "
                f"returned zero attacks for campaign {brief.campaign_id!r} "
                f"(category={brief.category}, subcategory={brief.subcategory}). "
                "Check the provider's category coverage."
            )
        return attacks
