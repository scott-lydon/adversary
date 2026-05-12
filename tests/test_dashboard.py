"""T10: every dashboard page renders 200 with content.

Also covers the new drilldown routes (campaigns, attacks, verdicts,
cost, glossary, glossary/<category>, finding chain detail) and the
plain-markdown finding raw path. The summary card hrefs are asserted to
exist as <a> tags so the drilldown UX is enforced.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adversary.agents import OrchestratorAgent
from adversary.categories import CATEGORIES
from adversary.dashboard import create_app
from adversary.models import AttackCategory
from adversary.providers import ScriptedProvider
from adversary.storage import SqliteStore
from adversary.target import EchoTarget


class _AnchorHrefCollector(HTMLParser):
    """Tiny HTML parser that collects <a href=...> values."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for name, value in attrs:
            if name.lower() == "href" and value is not None:
                self.hrefs.append(value)


def _hrefs(html: str) -> list[str]:
    p = _AnchorHrefCollector()
    p.feed(html)
    return p.hrefs


@pytest.fixture
def seeded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    SqliteStore(tmp_path / "adversary.db").close()
    return tmp_path


async def _run_scan(seeded: Path) -> None:
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


@pytest.mark.asyncio
async def test_all_pages_render_200_with_content(seeded: Path) -> None:
    await _run_scan(seeded)
    client = TestClient(create_app())
    for path in [
        "/",
        "/findings",
        "/coverage",
        "/audit",
        "/campaigns",
        "/attacks",
        "/verdicts",
        "/cost",
        "/glossary",
    ]:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        assert "Adversary" in resp.text


@pytest.mark.asyncio
async def test_summary_cards_are_anchors_with_drilldown_hrefs(seeded: Path) -> None:
    """The six summary cards on `/` must be clickable drilldown links."""
    await _run_scan(seeded)
    client = TestClient(create_app())
    resp = client.get("/")
    assert resp.status_code == 200
    hrefs = _hrefs(resp.text)
    required = {
        "/campaigns",
        "/attacks",
        "/findings",
        "/cost",
        "/verdicts",
        "/audit",
    }
    missing = required - set(hrefs)
    assert not missing, (
        f"summary cards missing drilldown links: {missing} "
        f"(saw {sorted(set(hrefs))[:20]}…)"
    )


@pytest.mark.asyncio
async def test_glossary_lists_every_attack_category(seeded: Path) -> None:
    await _run_scan(seeded)
    client = TestClient(create_app())
    resp = client.get("/glossary")
    assert resp.status_code == 200
    for cat in AttackCategory:
        assert cat.value in resp.text, f"glossary missing {cat.value!r}"


@pytest.mark.asyncio
async def test_glossary_snapshot_poisoning_has_authored_content(
    seeded: Path,
) -> None:
    await _run_scan(seeded)
    client = TestClient(create_app())
    resp = client.get("/glossary/snapshot_poisoning")
    assert resp.status_code == 200
    assert "fabricated_allergy" in resp.text
    assert "What it means" in resp.text


@pytest.mark.asyncio
async def test_glossary_unknown_category_returns_404(seeded: Path) -> None:
    await _run_scan(seeded)
    client = TestClient(create_app())
    resp = client.get("/glossary/does_not_exist")
    assert resp.status_code == 404
    assert "no encyclopedia entry" in resp.text


@pytest.mark.asyncio
async def test_finding_detail_renders_prompt_sequence(seeded: Path) -> None:
    await _run_scan(seeded)
    store = SqliteStore(seeded / "adversary.db")
    row = store.conn.execute(
        "SELECT id, lineage_root FROM findings LIMIT 1"
    ).fetchone()
    assert row is not None, "scan should have produced at least one finding"
    finding_id = row["id"]
    attack_id = row["lineage_root"]
    attack_row = store.conn.execute(
        "SELECT prompt_sequence_json FROM attacks WHERE attack_id=?",
        (attack_id,),
    ).fetchone()
    assert attack_row is not None
    import json

    prompt_sequence = json.loads(attack_row["prompt_sequence_json"])
    assert prompt_sequence, "attack should have at least one message"
    first_text = prompt_sequence[0]["text"]
    store.close()

    client = TestClient(create_app())
    resp = client.get(f"/findings/{finding_id}")
    assert resp.status_code == 200
    # The chain-of-events page must contain the attack's first prompt text.
    assert first_text in resp.text, (
        f"finding detail did not render the attack's prompt sequence; "
        f"looking for {first_text!r}"
    )


@pytest.mark.asyncio
async def test_finding_raw_returns_plain_markdown(seeded: Path) -> None:
    await _run_scan(seeded)
    store = SqliteStore(seeded / "adversary.db")
    row = store.conn.execute("SELECT id FROM findings LIMIT 1").fetchone()
    finding_id = row["id"]
    store.close()
    client = TestClient(create_app())
    resp = client.get(f"/findings/{finding_id}/raw")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")
    # Markdown reports always have a top-level heading.
    assert resp.text.lstrip().startswith("#"), (
        "raw markdown report should start with a Markdown heading"
    )


@pytest.mark.asyncio
async def test_finding_unknown_id_returns_404(seeded: Path) -> None:
    await _run_scan(seeded)
    client = TestClient(create_app())
    resp = client.get("/findings/ADV-9999-9999")
    assert resp.status_code == 404
    resp_raw = client.get("/findings/ADV-9999-9999/raw")
    assert resp_raw.status_code == 404


@pytest.mark.asyncio
async def test_campaign_detail_renders(seeded: Path) -> None:
    await _run_scan(seeded)
    store = SqliteStore(seeded / "adversary.db")
    row = store.conn.execute(
        "SELECT session_id FROM agent_runs WHERE agent='orchestrator' LIMIT 1"
    ).fetchone()
    assert row is not None
    campaign_id = row["session_id"]
    store.close()
    client = TestClient(create_app())
    resp = client.get(f"/campaigns/{campaign_id}")
    assert resp.status_code == 200
    assert campaign_id in resp.text


@pytest.mark.asyncio
async def test_attack_detail_renders(seeded: Path) -> None:
    await _run_scan(seeded)
    store = SqliteStore(seeded / "adversary.db")
    row = store.conn.execute("SELECT attack_id FROM attacks LIMIT 1").fetchone()
    assert row is not None
    attack_id = row["attack_id"]
    store.close()
    client = TestClient(create_app())
    resp = client.get(f"/attacks/{attack_id}")
    assert resp.status_code == 200
    assert attack_id in resp.text


def test_categories_required_subcategories_authored() -> None:
    """The three subcategories the scripted RedTeam emits must exist."""
    required_pairs = [
        ("snapshot_poisoning", "fabricated_allergy"),
        ("data_exfiltration_cross_patient", "vector_store_namespace"),
        ("multi_turn_prompt_injection", "progressive_reframing"),
    ]
    for cat_key, sub_key in required_pairs:
        info = CATEGORIES.get(cat_key)
        assert info is not None, f"category {cat_key!r} missing from CATEGORIES"
        keys = [s.key for s in info.subcategories]
        assert sub_key in keys, (
            f"subcategory {sub_key!r} missing from {cat_key!r} "
            f"(have {keys})"
        )


def test_categories_cover_every_attack_category() -> None:
    """Every AttackCategory enum value must have an encyclopedia entry."""
    for cat in AttackCategory:
        assert cat.value in CATEGORIES, (
            f"AttackCategory.{cat.name} ({cat.value}) has no entry in CATEGORIES"
        )
