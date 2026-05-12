"""FastAPI dashboard app and routes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from adversary.storage import SqliteStore

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _store() -> SqliteStore:
    return SqliteStore("adversary.db")


def create_app() -> FastAPI:
    """Build and return a configured FastAPI application."""
    app = FastAPI(title="Adversary Dashboard")
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Any:
        store = _store()
        summary = store.summary()
        store.close()
        return templates.TemplateResponse(
            request=request, name="index.html", context={"summary": summary}
        )

    @app.get("/findings", response_class=HTMLResponse)
    async def findings(request: Request) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM findings ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        ]
        store.close()
        return templates.TemplateResponse(
            request=request, name="findings.html", context={"findings": rows}
        )

    @app.get("/findings/{report_id}", response_class=PlainTextResponse)
    async def finding_markdown(report_id: str) -> str:
        store = _store()
        row = store.conn.execute(
            "SELECT report_path FROM findings WHERE id=?", (report_id,)
        ).fetchone()
        store.close()
        if not row or not row["report_path"]:
            raise HTTPException(status_code=404, detail=f"no report for {report_id!r}")
        path = Path(row["report_path"])
        if not path.exists():
            raise HTTPException(
                status_code=404, detail=f"report file missing at {path!r}"
            )
        return path.read_text(encoding="utf-8")

    @app.get("/coverage", response_class=HTMLResponse)
    async def coverage(request: Request) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM coverage ORDER BY category, subcategory"
            ).fetchall()
        ]
        store.close()
        for r in rows:
            total = max(1, int(r["runs"]))
            r["pass_rate"] = float(r["fails"]) / total
            r["success_rate"] = float(r["successes"]) / total
            if r["pass_rate"] >= 0.8:
                r["cell_class"] = "bg-green-700"
            elif r["pass_rate"] >= 0.5:
                r["cell_class"] = "bg-yellow-600"
            else:
                r["cell_class"] = "bg-red-700"
        return templates.TemplateResponse(
            request=request, name="coverage.html", context={"rows": rows}
        )

    @app.get("/audit", response_class=HTMLResponse)
    async def audit(request: Request) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT rowid_seq, prev_hash, this_hash, occurred_at, agent, "
                "action FROM audit_log ORDER BY rowid_seq DESC LIMIT 100"
            ).fetchall()
        ]
        store.close()
        return templates.TemplateResponse(
            request=request, name="audit.html", context={"rows": rows}
        )

    return app
