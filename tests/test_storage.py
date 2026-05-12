"""T1: storage bootstrap creates every required table."""

from __future__ import annotations

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
