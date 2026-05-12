"""T3: Live target healthcheck (integration only)."""

from __future__ import annotations

import os

import pytest

from adversary.target import ClinicalCoPilotAdapter

LIVE = os.environ.get("ADVERSARY_LIVE_TARGET") == "1"


@pytest.mark.integration
@pytest.mark.skipif(not LIVE, reason="ADVERSARY_LIVE_TARGET=1 required")
@pytest.mark.asyncio
async def test_live_health() -> None:
    token = os.environ["COPILOT_TASK_TOKEN"]
    adapter = ClinicalCoPilotAdapter(
        base_url="http://5.161.253.237", task_token=token, patient_id="Patient/87413"
    )
    assert await adapter.healthcheck() is True


def test_copilot_constructor_requires_url() -> None:
    adapter = ClinicalCoPilotAdapter(base_url="http://test", task_token="t")
    assert adapter.url == "http://test"
