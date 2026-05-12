"""T9: audit log is hash-chained and tamper-evident."""

from __future__ import annotations

from pathlib import Path

import pytest

from adversary.storage import SqliteStore, audit_tamper, audit_verify


def test_chain_verify_and_tamper_detect(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "adversary.db")
    for i in range(5):
        store.append_audit(
            agent="orchestrator",
            action="seed",
            payload={"idx": i},
            occurred_at=f"2026-05-12T00:00:0{i}Z",
        )
    ok, rows, reason = audit_verify(store)
    assert ok, f"chain should verify intact: {reason}"
    assert rows == 5

    audit_tamper(store, row_index=2)
    ok2, rows2, reason2 = audit_verify(store)
    assert not ok2, "chain should detect tampering"
    assert "at_row=" in reason2 and "BROKEN" in reason2
    store.close()


def test_tamper_out_of_range(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "adversary.db")
    store.append_audit(
        agent="orchestrator",
        action="seed",
        payload={"i": 1},
        occurred_at="2026-05-12T00:00:00Z",
    )
    with pytest.raises(ValueError, match="out of range"):
        audit_tamper(store, row_index=42)
    store.close()
