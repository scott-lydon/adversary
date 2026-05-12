"""T: dashboard target routes + target identity surfacing across pages."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adversary.agents import OrchestratorAgent
from adversary.dashboard import create_app
from adversary.providers import ScriptedProvider
from adversary.storage import SqliteStore
from adversary.target import EchoTarget, resolve_by_name


@pytest.fixture
def seeded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    SqliteStore(tmp_path / "adversary.db").close()
    return tmp_path


async def _run_scan(seeded: Path) -> None:
    store = SqliteStore(seeded / "adversary.db")
    record = resolve_by_name(store, "echo-demo")
    orch = OrchestratorAgent(
        adapter=EchoTarget(variant="demo"),
        provider=ScriptedProvider(seed=42),
        store=store,
        reports_dir=seeded / "vulnerability-reports",
        budget_usd=1.0,
        max_campaigns=2,
        seed=42,
        target_record=record,
    )
    await orch.run_scan()
    store.close()


def test_get_targets_lists_seeded_rows(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get("/targets")
    assert resp.status_code == 200
    assert "echo-demo" in resp.text
    assert "clinical-copilot-hetzner" in resp.text


def test_get_targets_new_renders_form(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get("/targets/new")
    assert resp.status_code == 200
    assert "Register a target" in resp.text
    assert 'name="name"' in resp.text
    assert 'name="base_url"' in resp.text
    assert 'name="auth_kind"' in resp.text


def test_post_targets_redirects_303_on_success(seeded: Path) -> None:
    client = TestClient(create_app(), follow_redirects=False)
    resp = client.post(
        "/targets",
        data={
            "name": "my-test-target",
            "kind": "http_chat",
            "base_url": "http://192.168.5.5:8000",
            "description": "test",
            "reach_steps_text": "step one\nstep two",
            "auth_kind": "none",
            "allow_public": "",
            "allowlist_on_create": "true",
        },
    )
    assert resp.status_code == 303, resp.text
    assert resp.headers["location"] == "/targets/my-test-target"


def test_post_targets_with_bad_name_re_renders_with_field_error(
    seeded: Path,
) -> None:
    client = TestClient(create_app(), follow_redirects=False)
    resp = client.post(
        "/targets",
        data={
            "name": "Has Space",
            "kind": "http_chat",
            "base_url": "http://127.0.0.1",
            "auth_kind": "none",
        },
    )
    assert resp.status_code == 400
    body = resp.text
    assert "Has Space" in body or "match" in body
    # Field-specific error has to appear in the HTML.
    assert "name" in body.lower()


def test_post_targets_public_url_blocked_without_allow_public(
    seeded: Path,
) -> None:
    client = TestClient(create_app(), follow_redirects=False)
    resp = client.post(
        "/targets",
        data={
            "name": "public-target",
            "kind": "http_chat",
            "base_url": "http://api.example.com",
            "auth_kind": "none",
            "allow_public": "",
        },
    )
    assert resp.status_code == 400
    assert "public-internet" in resp.text or "Allow-public" in resp.text


@pytest.mark.asyncio
async def test_findings_table_includes_target_column(seeded: Path) -> None:
    await _run_scan(seeded)
    client = TestClient(create_app())
    resp = client.get("/findings")
    assert resp.status_code == 200
    assert "Target" in resp.text  # column header
    assert "echo-demo" in resp.text


@pytest.mark.asyncio
async def test_finding_detail_shows_target_badge_and_panel(seeded: Path) -> None:
    await _run_scan(seeded)
    store = SqliteStore(seeded / "adversary.db")
    row = store.conn.execute("SELECT id FROM findings LIMIT 1").fetchone()
    fid = row["id"]
    store.close()
    client = TestClient(create_app())
    resp = client.get(f"/findings/{fid}")
    assert resp.status_code == 200
    # Header badge: target name appears.
    assert "echo-demo" in resp.text
    # The Step 3 identity panel header.
    assert "Target identity" in resp.text


def test_get_target_detail(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get("/targets/echo-demo")
    assert resp.status_code == 200
    assert "echo-demo" in resp.text
    assert "echo://demo" in resp.text


def test_target_detail_404(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get("/targets/nope-not-real")
    assert resp.status_code == 404


def test_glossary_overlay_appears_with_target_query(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get(
        "/glossary/indirect_prompt_injection?target=clinical-copilot-hetzner"
    )
    assert resp.status_code == 200
    # Overlay block presence.
    assert "target-specific" in resp.text.lower()
    # EMR-flavored prose from the overlay.
    assert "HIPAA" in resp.text or "chart" in resp.text


def test_glossary_no_overlay_without_target_query(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get("/glossary/indirect_prompt_injection")
    assert resp.status_code == 200
    # No target-specific overlay panel header.
    assert "target-specific addendum" not in resp.text.lower()


def test_targets_nav_link_present(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'href="/targets"' in resp.text


def test_index_card_shows_targets_count(seeded: Path) -> None:
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Targets configured" in resp.text


def test_post_allowlist(seeded: Path) -> None:
    client = TestClient(create_app(), follow_redirects=False)
    resp = client.post("/targets/clinical-copilot-hetzner/allowlist")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/targets/clinical-copilot-hetzner"
    # Re-fetch the detail page; should now say allowlisted.
    client2 = TestClient(create_app())
    detail = client2.get("/targets/clinical-copilot-hetzner")
    assert "allowlisted" in detail.text.lower()


def test_post_reach_steps_updates(seeded: Path) -> None:
    client = TestClient(create_app(), follow_redirects=False)
    resp = client.post(
        "/targets/echo-demo/reach-steps",
        data={"reach_steps_text": "first step\nsecond step\nthird"},
    )
    assert resp.status_code == 303
    # Refetch detail and confirm.
    client2 = TestClient(create_app())
    detail = client2.get("/targets/echo-demo")
    assert "first step" in detail.text
    assert "second step" in detail.text
