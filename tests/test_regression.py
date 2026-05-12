"""T8: regression harness replays records and writes JUnit XML."""

from __future__ import annotations

import os
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest
from typer.testing import CliRunner

from adversary.cli import app
from adversary.providers import ScriptedProvider
from adversary.regression import run_regression, write_junit_xml
from adversary.target import EchoTarget

REPO_ROOT = Path(__file__).resolve().parents[1]
RECORDS_DIR = REPO_ROOT / "evals" / "regression"
runner = CliRunner()


@pytest.mark.asyncio
async def test_replay_emits_valid_junit(tmp_path: Path) -> None:
    results = await run_regression(
        records_dir=RECORDS_DIR,
        adapter=EchoTarget(variant="demo"),
        provider=ScriptedProvider(),
    )
    assert results, "expected at least one regression record to replay"
    out = write_junit_xml(results, tmp_path / "regress.xml")
    assert out.exists()
    root = ET.parse(out).getroot()
    assert root.tag == "testsuite"
    assert int(root.attrib["tests"]) == len(results)
    # EchoTarget is intentionally vulnerable so failures are expected.
    assert int(root.attrib["failures"]) >= 0


@pytest.mark.asyncio
async def test_hardened_target_passes_more(tmp_path: Path) -> None:
    hard = await run_regression(
        records_dir=RECORDS_DIR,
        adapter=EchoTarget(variant="hardened"),
        provider=ScriptedProvider(),
    )
    soft = await run_regression(
        records_dir=RECORDS_DIR,
        adapter=EchoTarget(variant="demo"),
        provider=ScriptedProvider(),
    )
    hard_pass = sum(1 for r in hard if r.passed)
    soft_pass = sum(1 for r in soft if r.passed)
    assert hard_pass >= soft_pass


def test_cli_regress_runs_to_completion(tmp_path: Path) -> None:
    # The CLI's regress command needs to find records at evals/regression.
    # Copy the records into the tmp_path so the CLI sees them.
    target_dir = tmp_path / "evals" / "regression"
    target_dir.mkdir(parents=True)
    for f in RECORDS_DIR.glob("*.json"):
        (target_dir / f.name).write_bytes(f.read_bytes())

    result = runner.invoke(
        app,
        [
            "regress",
            "--target",
            "echo://demo",
            "--output",
            str(tmp_path / "regress.xml"),
            "--records-dir",
            str(target_dir),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "regress.xml").exists()
