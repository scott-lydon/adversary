"""FastAPI dashboard app and routes.

The dashboard is read-only. Every route opens a fresh `SqliteStore`,
queries it, and closes the connection. Templates render against the rows
plus the encyclopedia in `adversary.categories`.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from adversary.categories import CATEGORIES, category as _category_info, subcategory as _subcategory_info
from adversary.models import AttackCategory
from adversary.storage import SqliteStore

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# Agents we will badge in the audit + chain pages. The order is the order they
# appear in a typical campaign.
_AGENT_ORDER: tuple[str, ...] = (
    "orchestrator",
    "red_team",
    "target_adapter",
    "judge",
    "documentation",
)


def _store() -> SqliteStore:
    return SqliteStore("adversary.db")


def _campaign_id_for_attack(attack_id: str) -> str:
    """Return the campaign_id that owns an attack_id.

    Attack ids look like ``camp-YYYYMMDD-HHMMSS-IDX-HEX-attNNN``. The
    campaign id is everything up to and including the hex chunk.
    """
    parts = attack_id.split("-")
    if len(parts) < 6:
        return attack_id
    return "-".join(parts[:5])


def _parse_payload(payload_json: str | None) -> dict[str, Any]:
    if not payload_json:
        return {}
    try:
        return json.loads(payload_json)
    except json.JSONDecodeError:
        return {}


def _common_context(store: SqliteStore) -> dict[str, Any]:
    """Context every page needs (footer audit head)."""
    return {"footer_audit_head": store.head_hash()}


def create_app() -> FastAPI:
    """Build and return a configured FastAPI application."""
    app = FastAPI(title="Adversary Dashboard")
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # -----------------------------------------------------------------
    # Summary + drilldown cards
    # -----------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Any:
        store = _store()
        summary = store.summary()
        recent_audit = [
            dict(r)
            for r in store.conn.execute(
                "SELECT rowid_seq, occurred_at, agent, action, this_hash "
                "FROM audit_log ORDER BY rowid_seq DESC LIMIT 8"
            ).fetchall()
        ]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "summary": summary,
                "recent_audit": recent_audit,
                **ctx,
            },
        )

    # -----------------------------------------------------------------
    # Findings + finding detail
    # -----------------------------------------------------------------

    @app.get("/findings", response_class=HTMLResponse)
    async def findings(request: Request, severity: str | None = None) -> Any:
        store = _store()
        if severity:
            rows = [
                dict(r)
                for r in store.conn.execute(
                    "SELECT * FROM findings WHERE severity=? "
                    "ORDER BY created_at DESC LIMIT 200",
                    (severity,),
                ).fetchall()
            ]
        else:
            rows = [
                dict(r)
                for r in store.conn.execute(
                    "SELECT * FROM findings ORDER BY created_at DESC LIMIT 200"
                ).fetchall()
            ]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="findings.html",
            context={"findings": rows, "severity_filter": severity, **ctx},
        )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    async def finding_detail(request: Request, finding_id: str) -> Any:
        store = _store()
        f_row = store.conn.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if not f_row:
            store.close()
            raise HTTPException(
                status_code=404,
                detail=f"no finding with id={finding_id!r}",
            )
        finding = dict(f_row)
        attack_id = finding["lineage_root"]
        attack_row = store.conn.execute(
            "SELECT * FROM attacks WHERE attack_id=?", (attack_id,)
        ).fetchone()
        attack = dict(attack_row) if attack_row else None
        if attack is not None:
            attack["prompt_sequence"] = json.loads(
                attack["prompt_sequence_json"] or "[]"
            )
            attack["mutation_lineage"] = json.loads(
                attack["mutation_lineage_json"] or "[]"
            )
            attack["generation_metadata"] = json.loads(
                attack["generation_metadata_json"] or "{}"
            )

        verdict_row = store.conn.execute(
            "SELECT * FROM verdicts WHERE attack_id=? ORDER BY id DESC LIMIT 1",
            (attack_id,),
        ).fetchone()
        verdict = dict(verdict_row) if verdict_row else None
        if verdict is not None:
            verdict["evidence"] = json.loads(verdict["evidence_json"] or "[]")

        campaign_id = _campaign_id_for_attack(attack_id) if attack_id else None
        campaign_run = None
        if campaign_id:
            cr = store.conn.execute(
                "SELECT * FROM agent_runs WHERE session_id=? "
                "AND agent='orchestrator'",
                (campaign_id,),
            ).fetchone()
            if cr:
                campaign_run = dict(cr)

        # Audit rows whose payload mentions this attack or campaign.
        audit_rows: list[dict[str, Any]] = []
        for r in store.conn.execute(
            "SELECT * FROM audit_log ORDER BY rowid_seq ASC"
        ).fetchall():
            row = dict(r)
            payload_text = row.get("payload_json") or ""
            if attack_id and attack_id in payload_text:
                row["payload"] = _parse_payload(row["payload_json"])
                audit_rows.append(row)
            elif campaign_id and campaign_id in payload_text:
                row["payload"] = _parse_payload(row["payload_json"])
                audit_rows.append(row)

        # Encyclopedia entry
        category_info = CATEGORIES.get(finding["category"])
        subcat_info = _subcategory_info(finding["category"], finding["subcategory"])

        # Mutation tree
        mutation_lineage = attack["mutation_lineage"] if attack else []

        # Full request/response transcript from agent_messages (Step 3 payload).
        exchange = None
        if attack_id:
            ex_row = store.conn.execute(
                "SELECT payload_json FROM agent_messages "
                "WHERE trace_id=? AND schema_name='TargetExchange/v1' "
                "ORDER BY id DESC LIMIT 1",
                (attack_id,),
            ).fetchone()
            if ex_row:
                try:
                    exchange = json.loads(ex_row["payload_json"])
                except json.JSONDecodeError as exc:
                    raise HTTPException(
                        status_code=500,
                        detail=(
                            f"corrupt agent_messages row for trace_id={attack_id!r}: "
                            f"{exc}. Re-run `adversary status --reset-db` and rescan."
                        ),
                    ) from exc

        # Determine target URL: prefer the persisted exchange (truth of what
        # was actually sent), fall back to finding's recorded target.
        target_url = (
            (exchange or {}).get("target_url")
            or finding.get("target_version_when_discovered")
            or "echo://demo"
        )
        request_body = (exchange or {}).get("request")
        response_body = (exchange or {}).get("response")

        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="finding_detail.html",
            context={
                "finding": finding,
                "attack": attack,
                "verdict": verdict,
                "campaign_id": campaign_id,
                "campaign_run": campaign_run,
                "audit_rows": audit_rows,
                "category_info": category_info,
                "subcategory_info": subcat_info,
                "mutation_lineage": mutation_lineage,
                "target_url": target_url,
                "request_body": request_body,
                "response_body": response_body,
                **ctx,
            },
        )


    @app.get("/findings/{finding_id}/raw", response_class=PlainTextResponse)
    async def finding_markdown(finding_id: str) -> str:
        store = _store()
        row = store.conn.execute(
            "SELECT report_path FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        store.close()
        if not row or not row["report_path"]:
            raise HTTPException(
                status_code=404,
                detail=f"no report for finding id={finding_id!r}",
            )
        path = Path(row["report_path"])
        if not path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"report file missing at {path!r}",
            )
        return path.read_text(encoding="utf-8")

    # -----------------------------------------------------------------
    # Coverage
    # -----------------------------------------------------------------

    @app.get("/coverage", response_class=HTMLResponse)
    async def coverage(request: Request) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM coverage ORDER BY category, subcategory"
            ).fetchall()
        ]
        for r in rows:
            total = max(1, int(r["runs"]))
            r["pass_rate"] = float(r["fails"]) / total
            r["success_rate"] = float(r["successes"]) / total
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="coverage.html",
            context={"rows": rows, **ctx},
        )

    # -----------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------

    @app.get("/audit", response_class=HTMLResponse)
    async def audit(request: Request) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT rowid_seq, prev_hash, this_hash, occurred_at, agent, "
                "action FROM audit_log ORDER BY rowid_seq DESC LIMIT 200"
            ).fetchall()
        ]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="audit.html",
            context={"rows": rows, **ctx},
        )

    # -----------------------------------------------------------------
    # Campaigns
    # -----------------------------------------------------------------

    @app.get("/campaigns", response_class=HTMLResponse)
    async def campaigns(request: Request) -> Any:
        store = _store()
        runs = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM agent_runs WHERE agent='orchestrator' "
                "ORDER BY created_at DESC"
            ).fetchall()
        ]
        # Build a per-campaign aggregate from audit rows.
        # campaign_start audit rows carry {campaign_id, category, subcategory}.
        per_campaign_meta: dict[str, dict[str, str]] = {}
        for r in store.conn.execute(
            "SELECT payload_json FROM audit_log "
            "WHERE agent='orchestrator' AND action='campaign_start'"
        ).fetchall():
            payload = _parse_payload(r["payload_json"])
            cid = payload.get("campaign_id")
            if cid:
                per_campaign_meta[cid] = {
                    "category": payload.get("category", ""),
                    "subcategory": payload.get("subcategory", ""),
                }

        # Aggregate attack + verdict counts per campaign id (via attack_id prefix).
        attacks_by_campaign: dict[str, int] = defaultdict(int)
        verdicts_by_campaign: dict[str, dict[str, int]] = defaultdict(
            lambda: {"success": 0, "partial": 0, "fail": 0}
        )
        for r in store.conn.execute("SELECT attack_id FROM attacks").fetchall():
            cid = _campaign_id_for_attack(r["attack_id"])
            attacks_by_campaign[cid] += 1
        for r in store.conn.execute(
            "SELECT attack_id, verdict FROM verdicts"
        ).fetchall():
            cid = _campaign_id_for_attack(r["attack_id"])
            label = r["verdict"]
            if label in verdicts_by_campaign[cid]:
                verdicts_by_campaign[cid][label] += 1

        for run in runs:
            cid = run.get("session_id") or ""
            meta = per_campaign_meta.get(cid, {})
            run["category"] = meta.get("category", "")
            run["subcategory"] = meta.get("subcategory", "")
            run["attacks_count"] = attacks_by_campaign.get(cid, 0)
            run["verdict_counts"] = verdicts_by_campaign.get(
                cid, {"success": 0, "partial": 0, "fail": 0}
            )

        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="campaigns.html",
            context={"campaigns": runs, **ctx},
        )

    @app.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
    async def campaign_detail(request: Request, campaign_id: str) -> Any:
        store = _store()
        run = store.conn.execute(
            "SELECT * FROM agent_runs WHERE agent='orchestrator' AND session_id=?",
            (campaign_id,),
        ).fetchone()
        # Find every audit row whose payload mentions this campaign or whose
        # attack_id begins with the campaign id.
        audit_rows = []
        for r in store.conn.execute(
            "SELECT * FROM audit_log ORDER BY rowid_seq ASC"
        ).fetchall():
            row = dict(r)
            payload_text = row["payload_json"] or ""
            payload = _parse_payload(row["payload_json"])
            attack_id = str(payload.get("attack_id") or "")
            if campaign_id in payload_text or attack_id.startswith(campaign_id):
                row["payload"] = payload
                # one-line narrative
                row["narrative"] = _narrative_for_audit(row)
                audit_rows.append(row)
        if not audit_rows and not run:
            store.close()
            raise HTTPException(
                status_code=404,
                detail=(
                    f"campaign_id {campaign_id!r} has no audit rows or run. "
                    "Typo?"
                ),
            )

        # Category/subcategory from the campaign_start row.
        category_key = ""
        subcategory_key = ""
        for r in audit_rows:
            if r["agent"] == "orchestrator" and r["action"] == "campaign_start":
                category_key = r["payload"].get("category", "")
                subcategory_key = r["payload"].get("subcategory", "")
                break

        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="campaign_detail.html",
            context={
                "campaign_id": campaign_id,
                "run": dict(run) if run else None,
                "audit_rows": audit_rows,
                "category_key": category_key,
                "subcategory_key": subcategory_key,
                **ctx,
            },
        )

    # -----------------------------------------------------------------
    # Attacks
    # -----------------------------------------------------------------

    @app.get("/attacks", response_class=HTMLResponse)
    async def attacks(request: Request, page: int = 1) -> Any:
        store = _store()
        page = max(1, page)
        per_page = 50
        offset = (page - 1) * per_page
        total = store.conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT attack_id, category, subcategory, expected_unsafe_behavior, "
                "created_at FROM attacks ORDER BY created_at DESC "
                "LIMIT ? OFFSET ?",
                (per_page, offset),
            ).fetchall()
        ]
        total_pages = max(1, (total + per_page - 1) // per_page)
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="attacks.html",
            context={
                "attacks": rows,
                "page": page,
                "total_pages": total_pages,
                "total": total,
                **ctx,
            },
        )

    @app.get("/attacks/{attack_id}", response_class=HTMLResponse)
    async def attack_detail(request: Request, attack_id: str) -> Any:
        store = _store()
        row = store.conn.execute(
            "SELECT * FROM attacks WHERE attack_id=?", (attack_id,)
        ).fetchone()
        if not row:
            store.close()
            raise HTTPException(
                status_code=404,
                detail=f"no attack with attack_id={attack_id!r}",
            )
        attack = dict(row)
        attack["prompt_sequence"] = json.loads(
            attack["prompt_sequence_json"] or "[]"
        )
        attack["mutation_lineage"] = json.loads(
            attack["mutation_lineage_json"] or "[]"
        )
        attack["generation_metadata"] = json.loads(
            attack["generation_metadata_json"] or "{}"
        )
        verdicts = [
            dict(v)
            for v in store.conn.execute(
                "SELECT * FROM verdicts WHERE attack_id=? ORDER BY created_at DESC",
                (attack_id,),
            ).fetchall()
        ]
        for v in verdicts:
            v["evidence"] = json.loads(v["evidence_json"] or "[]")
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="attack_detail.html",
            context={
                "attack": attack,
                "verdicts": verdicts,
                "campaign_id": _campaign_id_for_attack(attack_id),
                **ctx,
            },
        )

    # -----------------------------------------------------------------
    # Verdicts
    # -----------------------------------------------------------------

    @app.get("/verdicts", response_class=HTMLResponse)
    async def verdicts(request: Request) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM verdicts ORDER BY created_at DESC LIMIT 500"
            ).fetchall()
        ]
        for r in rows:
            r["evidence"] = json.loads(r["evidence_json"] or "[]")
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="verdicts.html",
            context={"verdicts": rows, **ctx},
        )

    # -----------------------------------------------------------------
    # Cost
    # -----------------------------------------------------------------

    @app.get("/cost", response_class=HTMLResponse)
    async def cost(request: Request) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT agent, "
                "SUM(dollar_cost) as dollar_cost, "
                "SUM(tokens_in) as tokens_in, "
                "SUM(tokens_out) as tokens_out, "
                "COUNT(*) as runs "
                "FROM agent_runs GROUP BY agent ORDER BY dollar_cost DESC"
            ).fetchall()
        ]
        # Also pull per-attack generation cost from generation_metadata
        # and per-verdict cost so the chart reflects more than just
        # agent_runs (which orchestrator currently leaves at $0).
        for r in store.conn.execute(
            "SELECT generation_metadata_json FROM attacks"
        ).fetchall():
            md = _parse_payload(r["generation_metadata_json"])
            rt = next((x for x in rows if x["agent"] == "red_team"), None)
            if rt is None:
                rt = {
                    "agent": "red_team",
                    "dollar_cost": 0.0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                    "runs": 0,
                }
                rows.append(rt)
            rt["dollar_cost"] = (rt["dollar_cost"] or 0.0) + float(
                md.get("dollar_cost", 0.0)
            )
            rt["tokens_in"] = (rt["tokens_in"] or 0) + int(md.get("tokens_in", 0))
            rt["tokens_out"] = (rt["tokens_out"] or 0) + int(md.get("tokens_out", 0))
        for r in store.conn.execute(
            "SELECT dollar_cost FROM verdicts"
        ).fetchall():
            judge = next((x for x in rows if x["agent"] == "judge"), None)
            if judge is None:
                judge = {
                    "agent": "judge",
                    "dollar_cost": 0.0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                    "runs": 0,
                }
                rows.append(judge)
            judge["dollar_cost"] = (judge["dollar_cost"] or 0.0) + float(
                r["dollar_cost"] or 0.0
            )

        rows.sort(key=lambda x: -(x.get("dollar_cost") or 0.0))
        total = sum(r["dollar_cost"] or 0.0 for r in rows)
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="cost.html",
            context={
                "rows": rows,
                "total_cost": total,
                "agents_json": json.dumps([r["agent"] for r in rows]),
                "costs_json": json.dumps(
                    [round(float(r["dollar_cost"] or 0.0), 6) for r in rows]
                ),
                **ctx,
            },
        )

    # -----------------------------------------------------------------
    # Glossary
    # -----------------------------------------------------------------

    @app.get("/glossary", response_class=HTMLResponse)
    async def glossary(request: Request) -> Any:
        store = _store()
        # Walk the AttackCategory enum so the dashboard reflects the canonical
        # list, not just the entries we authored.
        items = []
        for cat in AttackCategory:
            info = CATEGORIES.get(cat.value)
            items.append(
                {
                    "key": cat.value,
                    "title": info.title if info else cat.value,
                    "elevator": info.elevator if info else "(no entry yet)",
                    "has_entry": info is not None,
                    "subcount": len(info.subcategories) if info else 0,
                }
            )
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="glossary.html",
            context={"items": items, **ctx},
        )

    @app.get("/glossary/{category_key}", response_class=HTMLResponse)
    async def glossary_detail(request: Request, category_key: str) -> Any:
        store = _store()
        try:
            info = _category_info(category_key)
        except KeyError as exc:
            store.close()
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        # Pull coverage rows for this category so the encyclopedia page also
        # shows how the live system has been doing.
        cov_rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM coverage WHERE category=? ORDER BY subcategory",
                (category_key,),
            ).fetchall()
        ]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="category_detail.html",
            context={"info": info, "coverage": cov_rows, **ctx},
        )

    return app


# ---------------------------------------------------------------------
# Helpers used by the templates indirectly (via context).
# ---------------------------------------------------------------------

def _narrative_for_audit(row: dict[str, Any]) -> str:
    """One-line "what happened" rendering of an audit row's payload."""
    agent = row["agent"]
    action = row["action"]
    payload = row.get("payload", {}) or {}
    if agent == "orchestrator" and action == "campaign_start":
        cat = payload.get("category", "?")
        sub = payload.get("subcategory", "?")
        return f"Orchestrator launched a {cat} / {sub} campaign."
    if agent == "target_adapter" and action == "response":
        aid = payload.get("attack_id", "?")
        return f"Target returned a response for {aid}."
    if agent == "judge" and action == "verdict":
        v = payload.get("verdict", "?")
        c = payload.get("confidence", "?")
        return f"Judge returned verdict={v} confidence={c}."
    if agent == "documentation" and action == "report_written":
        rid = payload.get("report_id", "?")
        return f"Documentation wrote report {rid}."
    return f"{agent}.{action}"
