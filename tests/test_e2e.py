"""T7: full multi-agent campaign on the Echo target."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from adversary.agents import OrchestratorAgent
from adversary.providers import ScriptedProvider
from adversary.storage import SqliteStore
from adversary.target import EchoTarget

from adversary.cli import app

runner = CliRunner()


@pytest.mark.asyncio
async def test_full_scan_echo_target_produces_finding(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "adversary.db")
    reports_dir = tmp_path / "vulnerability-reports"
    orch = OrchestratorAgent(
        adapter=EchoTarget(variant="demo"),
        provider=ScriptedProvider(seed=42),
        store=store,
        reports_dir=reports_dir,
        budget_usd=1.0,
        max_campaigns=3,
        seed=42,
    )
    outcomes = await orch.run_scan()
    assert len(outcomes) == 3
    total_attacks = sum(o.attacks_run for o in outcomes)
    total_success = sum(o.successes for o in outcomes)
    assert total_attacks >= 10, f"expected >= 10 attacks across 3 campaigns, got {total_attacks}"
    assert total_success >= 1, "scripted EchoTarget should produce at least one success"

    success_rows = store.conn.execute(
        "SELECT COUNT(*) c FROM verdicts WHERE verdict='success'"
    ).fetchone()
    assert success_rows["c"] >= 1
    reports = list(reports_dir.glob("ADV-*.md"))
    assert reports, "expected at least one vulnerability report"
    store.close()


def test_cli_scan_smokes_through() -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "echo://demo",
            "--budget-usd",
            "1.00",
            "--max-campaigns",
            "2",
            "--provider",
            "scripted",
            "--seed",
            "42",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "campaigns=" in result.output
