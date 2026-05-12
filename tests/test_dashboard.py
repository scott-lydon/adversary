"""T10: every dashboard page renders 200 with content."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adversary.agents import OrchestratorAgent
from adversary.dashboard import create_app
from adversary.providers import ScriptedProvider
from adversary.storage import SqliteStore
from adversary.target import EchoTarget


@pytest.fixture
def seeded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    store = SqliteStore(tmp_path / "adversary.db")
    return tmp_path


@pytest.mark.asyncio
async def test_all_pages_render_200_with_content(seeded: Path) -> None:
    store = SqliteStore(seeded / "adversary.db")
    orch = OrchestratorAgent(
        adapter=EchoTarget(variant="demo"),
        provider=ScriptedProvider(seed=42),
        store=store,
        reports_dir=seeded / "vulnerability-reports",
        budget_usd=1.0,
        max_campaigns=2,
        seed=42,
    )
    await orch.run_scan()
    store.close()

    client = TestClient(create_app())
    for path in ["/", "/findings", "/coverage", "/audit"]:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert "Adversary" in resp.text
