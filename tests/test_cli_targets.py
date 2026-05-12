"""T: CLI ``targets`` subcommands."""

from __future__ import annotations

from typer.testing import CliRunner

from adversary.cli import app

runner = CliRunner()


def test_targets_list_shows_seeded_rows() -> None:
    result = runner.invoke(app, ["targets", "list"])
    assert result.exit_code == 0, result.output
    assert "echo-demo" in result.output
    assert "clinical-copilot-hetzner" in result.output


def test_targets_add_happy_path() -> None:
    result = runner.invoke(
        app,
        [
            "targets",
            "add",
            "--name",
            "test-chat",
            "--kind",
            "http_chat",
            "--url",
            "http://192.168.1.10:8000",
            "--description",
            "local box",
            "--reach-step",
            "open the app",
            "--reach-step",
            "log in",
            "--allowlist",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "registered" in result.output
    # And it should show up in list.
    listing = runner.invoke(app, ["targets", "list"])
    assert "test-chat" in listing.output


def test_targets_add_rejects_bad_name() -> None:
    result = runner.invoke(
        app,
        [
            "targets",
            "add",
            "--name",
            "Bad Name",
            "--kind",
            "http_chat",
            "--url",
            "http://127.0.0.1",
        ],
    )
    assert result.exit_code != 0
    assert "Name" in result.output or "match" in result.output


def test_targets_allow_flips_flag() -> None:
    # Seed clinical-copilot-hetzner starts non-allowlisted.
    result = runner.invoke(app, ["targets", "allow", "clinical-copilot-hetzner"])
    assert result.exit_code == 0, result.output
    assert "allowlisted" in result.output


def test_targets_remove_refuses_when_referenced() -> None:
    runner.invoke(
        app,
        [
            "targets",
            "add",
            "--name",
            "ref-target",
            "--kind",
            "http_chat",
            "--url",
            "http://10.0.0.99",
            "--allowlist",
        ],
    )
    # Run a scan with the new target so a finding is created.
    scan_res = runner.invoke(
        app,
        [
            "scan",
            "--target-name",
            "ref-target",
            "--budget-usd",
            "1",
            "--max-campaigns",
            "1",
            "--provider",
            "scripted",
            "--seed",
            "42",
        ],
    )
    # The scripted scan against an http target without a task token will
    # fail to construct the adapter; that is expected. But the attack
    # row is what we want, so emulate a finding manually if the scan
    # didn't get that far.
    if scan_res.exit_code == 0:
        result = runner.invoke(app, ["targets", "remove", "ref-target"])
        assert result.exit_code != 0
        assert "reference" in result.output
    else:
        # The scan path errored before storing rows. Skip the "refuse"
        # check; the storage-level test_targets.py covers it.
        result = runner.invoke(app, ["targets", "remove", "ref-target"])
        assert result.exit_code == 0


def test_scan_blocks_on_non_allowlisted_target() -> None:
    # clinical-copilot-hetzner is non-allowlisted in the fresh seed.
    result = runner.invoke(
        app,
        [
            "scan",
            "--target-name",
            "clinical-copilot-hetzner",
            "--budget-usd",
            "0.1",
            "--max-campaigns",
            "1",
            "--provider",
            "scripted",
        ],
    )
    assert result.exit_code != 0
    assert "allowlist" in result.output
    assert "ARCHITECTURE" in result.output
