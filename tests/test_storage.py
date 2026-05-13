"""T1: storage bootstrap creates every required table."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adversary.storage import REQUIRED_TABLES, SqliteStore


def test_schema_creates_all_tables(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "adversary.db")
    found = {
        row["name"]
        for row in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    for table in REQUIRED_TABLES:
        assert table in found, f"missing table {table!r}"
    store.close()


def test_reset_drops_and_recreates(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "adversary.db")
    store.append_audit(
        agent="test", action="seed", payload={"x": 1}, occurred_at="2026-05-12T00:00:00Z"
    )
    assert store.summary()["audit_rows"] == 1
    store.reset()
    assert store.summary()["audit_rows"] == 0
    store.close()


def _seed_cost_fixture(store: SqliteStore, campaign_id: str) -> None:
    """Seed one orchestrator run, one attack (red_team cost in JSON), one
    verdict (judge cost in column). All three cost-bearing tables exercised.
    """
    store.insert_agent_run(
        {
            "agent": "orchestrator",
            "model": "live",
            "session_id": campaign_id,
            "dollar_cost": 0.0,
            "latency_ms": 0,
            "tokens_in": 0,
            "tokens_out": 0,
            "error": None,
            "created_at": "2026-05-13T00:00:00+00:00",
            "target_id": "tgt-x",
        }
    )
    store.insert_attack(
        {
            "attack_id": f"{campaign_id}-att000",
            "category": "persona_hijacking",
            "subcategory": "developer_mode_jailbreak",
            "prompt_sequence": [],
            "expected_unsafe_behavior": "x",
            "mutation_lineage": [],
            "generation_metadata": {
                "dollar_cost": 0.0125,
                "model": "together_ai/test-model",
                "tokens_in": 100,
                "tokens_out": 50,
                "prompt_version": "test",
            },
        },
        "2026-05-13T00:00:01+00:00",
        target_id="tgt-x",
    )
    store.insert_verdict(
        verdict_dict={
            "attack_id": f"{campaign_id}-att000",
            "verdict": "fail",
            "confidence": 0.9,
            "judge_model": "anthropic/claude-sonnet-4",
            "rubric_version": "v1",
            "evidence": {},
            "notes": "",
            "dollar_cost": 0.0036,
        },
        target_response_hash="deadbeef",
        created_at="2026-05-13T00:00:02+00:00",
    )


def test_summary_total_dollar_cost_sums_all_three_tables(tmp_path: Path) -> None:
    """Regression guard for the 2026-05-13 dashboard bug.

    Cost lives in agent_runs (orchestrator placeholder), attacks JSON
    (red_team), and verdicts.dollar_cost (judge). summary() must sum
    all three or the dashboard card silently shows $0.0000.
    """
    store = SqliteStore(tmp_path / "adversary.db")
    _seed_cost_fixture(store, "camp-test-001")

    summary = store.summary()
    # orchestrator $0 + red_team $0.0125 + judge $0.0036 = $0.0161
    assert summary["total_dollar_cost"] == pytest.approx(0.0161, abs=1e-9)
    breakdown = store.cost_breakdown()
    assert summary["total_dollar_cost"] == pytest.approx(
        breakdown["total_dollar_cost"], abs=1e-9
    )
    store.close()


def test_campaign_breakdown_scopes_cost_to_one_campaign(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "adversary.db")
    _seed_cost_fixture(store, "camp-test-001")
    _seed_cost_fixture(store, "camp-test-002")

    b1 = store.campaign_breakdown("camp-test-001")
    assert b1["attacks_total"] == 1
    assert b1["verdict_mix"]["fail"] == 1
    assert b1["total_dollar_cost"] == pytest.approx(0.0161, abs=1e-9)
    assert b1["red_team_models"] == ["together_ai/test-model"]
    assert b1["judge_models"] == ["anthropic/claude-sonnet-4"]
    store.close()


def test_update_agent_run_totals_errors_when_row_missing(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "adversary.db")
    with pytest.raises(ValueError, match="no agent_runs row"):
        store.update_agent_run_totals(
            agent="orchestrator",
            session_id="camp-does-not-exist",
            dollar_cost=1.23,
            latency_ms=42,
            tokens_in=0,
            tokens_out=0,
        )
    store.close()
