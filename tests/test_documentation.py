"""T6: Documentation agent emits required sections."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adversary.agents.documentation import REQUIRED_SECTIONS, DocumentationAgent
from adversary.providers import ScriptedProvider

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "confirmed_exploit.json"


@pytest.mark.asyncio
async def test_required_sections_present(tmp_path: Path) -> None:
    exploit = json.loads(FIXTURE.read_text(encoding="utf-8"))
    agent = DocumentationAgent(ScriptedProvider())
    report_path = await agent.write_report(exploit, tmp_path)
    assert report_path.exists()
    body = report_path.read_text(encoding="utf-8")
    for section in REQUIRED_SECTIONS:
        assert section in body, f"missing section {section!r}"
    assert report_path.stem.startswith("ADV-")
