"""Shared pytest fixtures."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from adversary.providers import ScriptedProvider
from adversary.storage import SqliteStore


@pytest.fixture
def store(tmp_path: Path) -> SqliteStore:
    s = SqliteStore(tmp_path / "adversary.db")
    yield s
    s.close()


@pytest.fixture
def provider() -> ScriptedProvider:
    return ScriptedProvider(seed=42)


@pytest.fixture(autouse=True)
def chdir_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Force every test to run inside its own tmp dir so adversary.db lands there."""
    monkeypatch.chdir(tmp_path)
