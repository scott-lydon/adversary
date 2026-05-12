"""Agents package."""

from __future__ import annotations

from adversary.agents.documentation import DocumentationAgent
from adversary.agents.judge import JudgeAgent
from adversary.agents.orchestrator import OrchestratorAgent, CampaignOutcome
from adversary.agents.red_team import RedTeamAgent

__all__ = [
    "CampaignOutcome",
    "DocumentationAgent",
    "JudgeAgent",
    "OrchestratorAgent",
    "RedTeamAgent",
]
