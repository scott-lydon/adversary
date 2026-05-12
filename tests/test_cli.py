"""T0 + T1 + T2: CLI smoke tests."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from adversary.cli import app
from adversary.storage import SqliteStore, REQUIRED_TABLES

runner = CliRunner()


def test_help_lists_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    out = result.output
    for cmd in ["scan", "regress", "serve", "status", "validate-target", "debug"]:
        assert cmd in out, f"missing subcommand {cmd!r} in --help output"


def test_status_reset_creates_tables() -> None:
    result = runner.invoke(app, ["status", "--reset-db"])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["campaigns"] == 0
    assert summary["attacks"] == 0


def test_validate_target_echo_demo() -> None:
    result = runner.invoke(app, ["validate-target", "--target", "echo://demo"])
    assert result.exit_code == 0, result.output
    assert "healthcheck=ok" in result.output


def test_validate_target_rejects_unknown_scheme() -> None:
    result = runner.invoke(app, ["validate-target", "--target", "ftp://nope"])
    assert result.exit_code != 0
    assert "cannot route" in result.output or "unsupported" in result.output
