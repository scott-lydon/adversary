"""FastAPI dashboard app and routes.

Most routes are read-only — every request opens a fresh `SqliteStore`,
queries it, closes the connection. The /scan and /replay routes also
mutate state by invoking the same orchestrator the CLI uses; they sit
behind the allowlist gate.
"""

from __future__ import annotations

import asyncio
import json
import os
import time as _time_module
import uuid as _uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.templating import Jinja2Templates

from adversary.categories import (
    CATEGORIES,
    category as _category_info,
    overlay_for_kind,
    subcategory as _subcategory_info,
)
from adversary.models import (
    AttackCategory,
    AuthKind,
    TargetKind,
    TargetSubmission,
)
from adversary.runners import (
    AttackNotFound,
    ProviderUnavailable,
    RunnerError,
    replay_attack,
    run_scan_for_target,
)
from adversary.storage import SqliteStore
from adversary.target import (
    TargetNotAllowlisted,
    register_from_submission,
    resolve_by_name,
)

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


# --- live scan job registry --------------------------------------------------
#
# POST /targets/{name}/scan no longer blocks the request thread for the
# duration of a live LLM scan (which can be 30-120s). Instead it spawns an
# asyncio.create_task and redirects to /scans/{scan_id}; the page subscribes
# to /scans/{scan_id}/events via Server-Sent Events and renders per-agent
# progress as the orchestrator fires its progress_callback.
#
# Storage is process-local. The dashboard is a single-process FastAPI app
# bound to 127.0.0.1, so a dict is sufficient and dodges Redis / sqlite-pub-sub
# entirely. Jobs hang around for SCAN_JOB_TTL_S after they finish so a slow
# tab reload still gets the terminal event; older entries are pruned lazily.
SCAN_JOB_TTL_S = 3600  # 1h is generous; covers a grader stepping away.


@dataclass
class ScanJob:
    """One live scan kicked off by the dashboard.

    The orchestrator pushes events via ``ScanJob.emit``; ``ScanJob.stream``
    is an async generator the SSE endpoint pulls from. Both sides
    coordinate via ``asyncio.Condition`` so a reader blocks cheaply between
    events instead of polling.
    """

    id: str
    target_name: str
    target_id: str | None
    expected_attacks: int
    provider: str
    started_at: datetime
    events: list[dict[str, Any]] = field(default_factory=list)
    cond: asyncio.Condition = field(default_factory=asyncio.Condition)
    done: bool = False
    error: str | None = None
    result_url: str | None = None

    async def emit(self, kind: str, fields: dict[str, Any]) -> None:
        async with self.cond:
            ev = {"kind": kind, "ts": _time_module.time(), **fields}
            self.events.append(ev)
            self.cond.notify_all()

    async def mark_done(
        self, *, result_url: str | None = None, error: str | None = None
    ) -> None:
        async with self.cond:
            self.done = True
            self.result_url = result_url
            self.error = error
            self.cond.notify_all()


_SCANS: dict[str, ScanJob] = {}


def _prune_scan_jobs() -> None:
    """Drop finished scans older than SCAN_JOB_TTL_S. Cheap to call from any
    route that touches the registry."""
    now = _time_module.time()
    stale = [
        sid
        for sid, job in _SCANS.items()
        if job.done and (now - job.started_at.timestamp()) > SCAN_JOB_TTL_S
    ]
    for sid in stale:
        _SCANS.pop(sid, None)


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
    """Context every page needs (footer audit head + target lookup map)."""
    targets_by_id: dict[str, dict[str, Any]] = {}
    for row in store.list_targets():
        targets_by_id[row["id"]] = row
    return {
        "footer_audit_head": store.head_hash(),
        "targets_by_id": targets_by_id,
    }


def _target_filter_clause(
    base_sql: str, target: str | None, store: SqliteStore
) -> tuple[str, tuple[Any, ...]]:
    """Append a `target_id=?` filter to ``base_sql`` when ``target`` is set.

    ``target`` may be a target name. Returns (sql, params).
    """
    if not target:
        return base_sql, ()
    row = store.get_target(target)
    if row is None:
        return base_sql, ()
    # Inject WHERE before ORDER BY if present, else append.
    return (f"{base_sql} AND target_id=?", (row["id"],))


# ---------------------------------------------------------------------------
# Clinical Co-Pilot task-token auto-mint
# ---------------------------------------------------------------------------
#
# The Clinical Co-Pilot sidecar at /chat enforces a 5-minute HMAC-SHA-256 JWT.
# To remove paste-the-token friction from the local single-user dashboard, the
# scan and replay handlers below will auto-mint a token when the form field is
# left blank. Two paths:
#
#   1. Local mint (fast, no network):
#      Set env var COPILOT_BFF_JWT_SIGNING_KEY to the same value the sidecar
#      uses (the BFF's signing key, found in /opt/openemr/.env on the
#      deployment box). The dashboard then mints in-process with no SSH hop.
#
#   2. SSH mint (default, no secret on the Mac):
#      `ssh root@<hostname-of-target> docker exec copilot-bff python3 -c …`
#      shells into the BFF container where the signing key already lives.
#      SSH key auth must already work from the dashboard's shell.
#      Override via env: ADVERSARY_BFF_SSH_HOST, ADVERSARY_BFF_CONTAINER.
#
# Tokens are cached in-process keyed by (base_url, patient_id, user_id) so a
# burst of scans against the same target/patient does not re-mint on every
# click. The cache refreshes ~2 minutes before expiry.

_AUTO_MINT_TTL_SECONDS = 900
_AUTO_MINT_REFRESH_BEFORE = 120
_AUTO_MINT_USER_ID_DEFAULT = "dashboard-auto"
_AUTO_MINT_PURPOSES: tuple[str, ...] = (
    "diagnostic_cross_check",
    "chart_error_scan",
    "follow_up_question",
)
_AUTO_MINT_DEFAULT_PATIENT_ID = "barbara-boston-001"
_AUTO_MINT_PLACEHOLDER_SIGNING_KEY = "change-me-to-a-32-byte-hex-string"

_TOKEN_CACHE: dict[tuple[str, str, str], tuple[str, float]] = {}
_TOKEN_CACHE_LOCK = asyncio.Lock()


class AutoMintError(RuntimeError):
    """Raised when auto-minting a Clinical Co-Pilot task token fails.

    The message is intentionally surface-friendly: every raise site explains
    the precise failure mode and the next manual step (env var to set, SSH
    diagnostic to run, paste path in the form, etc.) so the dashboard's
    400-response detail is enough to fix the problem without grepping code.
    """


def _mint_token_locally(
    *,
    signing_key: str,
    user_id: str,
    patient_id: str,
    ttl_seconds: int,
    purposes: list[str],
) -> str:
    """Forge an HMAC-SHA-256 JWT identical in shape to the BFF's mint output."""
    import base64
    import hashlib
    import hmac
    import secrets

    now_unix = int(_time_module.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload: dict[str, object] = {
        "iss": "clinical-copilot-bff",
        "sub": user_id,
        "patient_id": patient_id,
        "purpose_of_use": purposes,
        "scope": "patient/*.read",
        "iat": now_unix,
        "nbf": now_unix,
        "exp": now_unix + ttl_seconds,
        "jti": secrets.token_urlsafe(12),
    }

    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    h_seg = _b64(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_seg = _b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_seg}.{p_seg}".encode("ascii")
    sig = hmac.new(
        signing_key.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    s_seg = _b64(sig)
    return f"{h_seg}.{p_seg}.{s_seg}"


async def _mint_token_via_ssh(
    *,
    ssh_host: str,
    bff_container: str,
    user_id: str,
    patient_id: str,
    ttl_seconds: int,
    purposes: list[str],
) -> str:
    """Run mint_task_token inside the BFF container over SSH.

    The signing key never leaves the deployment host. Every failure mode
    (missing ssh binary, SSH auth refused, container down, mint module not
    importable, malformed return value) raises `AutoMintError` with the
    exact diagnostic command to run next.
    """
    import shlex

    purposes_literal = json.dumps(purposes)
    mint_script = (
        "import os\n"
        "from sidecar.auth import mint_task_token\n"
        "print(mint_task_token(\n"
        "  signing_key=os.environ['COPILOT_BFF_JWT_SIGNING_KEY'],\n"
        f"  user_id={user_id!r},\n"
        f"  patient_id={patient_id!r},\n"
        f"  purposes_of_use={purposes_literal},\n"
        "  scopes=['patient/*.read'],\n"
        f"  lifetime_seconds={ttl_seconds},\n"
        "  issuer='clinical-copilot-bff',\n"
        "))\n"
    )
    remote_cmd = (
        f"docker exec -i {shlex.quote(bff_container)} "
        f"python3 -c {shlex.quote(mint_script)}"
    )
    try:
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            ssh_host,
            remote_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise AutoMintError(
            f"auto-mint failed: `ssh` binary not found in PATH ({exc}). "
            "Install OpenSSH client or paste a token into the form manually."
        ) from exc
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=20)
    except asyncio.TimeoutError as exc:
        proc.kill()
        raise AutoMintError(
            "auto-mint timed out after 20s while running "
            f"`ssh {ssh_host} docker exec {bff_container} ...`. "
            "Diagnose with: "
            f"ssh -o BatchMode=yes -o ConnectTimeout=5 {ssh_host} echo ok"
        ) from exc
    if proc.returncode != 0:
        err = (stderr or b"").decode("utf-8", errors="replace").strip()
        raise AutoMintError(
            f"auto-mint ssh exit={proc.returncode}: {err or '(empty stderr)'}.\n"
            "Common causes: SSH key auth not set up "
            f"(try `ssh {ssh_host} echo ok`), container {bff_container!r} not "
            f"running (try `ssh {ssh_host} docker ps`), or "
            "COPILOT_BFF_JWT_SIGNING_KEY missing from that container's env."
        )
    token = (stdout or b"").decode("utf-8", errors="replace").strip()
    if token.count(".") != 2:
        raise AutoMintError(
            f"auto-mint produced a non-JWT value: {token[:80]!r} "
            "(expected three dot-separated segments). The BFF container's "
            "mint_task_token may have changed its return shape, or the SSH "
            "session printed banner text before the script output."
        )
    return token


async def _preflight_validate_token(
    *,
    base_url: str,
    task_token: str,
    patient_id: str,
) -> str | None:
    """Probe the target's /chat with the resolved task token.

    Returns None on success, or a human-readable error string naming the
    specific failure shape on rejection. Caller wires the string straight
    into the ScanJob's error field so the user sees it on the scan-progress
    page instead of losing it inside the orchestrator's first /chat call.

    The probe sends a deliberately benign healthcheck-shaped message that
    the sidecar's injection guard does not pattern-match against; any 401
    therefore really is a token problem, not a guard rejection.
    """
    import httpx

    url = f"{base_url.rstrip('/')}/chat"
    payload = {
        "patient_id": patient_id,
        "purpose": "follow_up_question",
        "message": "preflight token validation ping from dashboard",
        "session_id": f"adv-preflight-{_uuid.uuid4().hex[:8]}",
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {task_token}",
                    "Content-Type": "application/json",
                },
            )
    except httpx.HTTPError as exc:
        return (
            f"Task token preflight failed: cannot reach {url!r} ({exc}). "
            "Check VPN, that the sidecar container is running on the "
            "deployment host, and that the URL in the target record is "
            "correct."
        )

    if resp.status_code == 401:
        return (
            f"Task token preflight failed: sidecar at {url!r} returned 401. "
            "This almost always means the COPILOT_BFF_JWT_SIGNING_KEY this "
            "dashboard is running with does NOT match the value the sidecar "
            "verifies against. Two fixes: (1) align the dashboard's env key "
            "with the sidecar's value "
            "(`ssh root@<host> 'docker exec copilot-bff env | grep "
            "COPILOT_BFF_JWT_SIGNING_KEY'`, then update this deployment's "
            ".env and `docker compose up -d adversary`), or (2) paste a "
            "freshly-minted JWT into the Task token field directly. The "
            "scan was NOT started; nothing has been billed."
        )
    if resp.status_code == 403:
        return (
            f"Task token preflight failed: sidecar at {url!r} returned 403. "
            f"The token signature was accepted, but the patient claim "
            f"{patient_id!r} is not authorized for this clinician+purpose "
            "tuple. Either widen the token's `purpose_of_use` claims at "
            "mint time, or scope the scan to a patient the token is "
            "authorized for. The scan was NOT started."
        )
    if resp.status_code >= 500:
        return (
            f"Task token preflight inconclusive: sidecar at {url!r} returned "
            f"{resp.status_code}. The target itself is unhealthy. Check the "
            "sidecar container logs on the deployment host. The scan was "
            "NOT started."
        )
    # 200 / 400 (guard block) / etc. all count as "the sidecar accepted the
    # signature" — the orchestrator can take it from here.
    return None


async def auto_mint_task_token(
    *,
    base_url: str,
    patient_id: str,
    user_id: str = _AUTO_MINT_USER_ID_DEFAULT,
) -> str:
    """Return a Clinical Co-Pilot task token, minting if no cached copy is valid.

    Cache key is (base_url, patient_id, user_id). A cached token is reused
    until it has less than `_AUTO_MINT_REFRESH_BEFORE` seconds remaining.
    """
    if not patient_id:
        raise AutoMintError(
            "auto-mint requires a non-empty patient_id; pass one in the "
            "Patient id field (the sidecar's task token is scoped per patient)."
        )
    cache_key = (base_url, patient_id, user_id)
    now = _time_module.time()
    async with _TOKEN_CACHE_LOCK:
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and (cached[1] - now) > _AUTO_MINT_REFRESH_BEFORE:
            return cached[0]
        purposes = list(_AUTO_MINT_PURPOSES)
        ttl = _AUTO_MINT_TTL_SECONDS
        signing_key = os.environ.get("COPILOT_BFF_JWT_SIGNING_KEY")
        if signing_key and signing_key != _AUTO_MINT_PLACEHOLDER_SIGNING_KEY:
            token = _mint_token_locally(
                signing_key=signing_key,
                user_id=user_id,
                patient_id=patient_id,
                ttl_seconds=ttl,
                purposes=purposes,
            )
        else:
            ssh_host = os.environ.get("ADVERSARY_BFF_SSH_HOST")
            if not ssh_host:
                parsed = urlparse(base_url)
                hostname = parsed.hostname
                if not hostname:
                    raise AutoMintError(
                        "auto-mint cannot derive an SSH host from "
                        f"base_url={base_url!r} (no hostname). "
                        "Set ADVERSARY_BFF_SSH_HOST=user@host."
                    )
                ssh_host = f"root@{hostname}"
            bff_container = os.environ.get(
                "ADVERSARY_BFF_CONTAINER", "copilot-bff"
            )
            token = await _mint_token_via_ssh(
                ssh_host=ssh_host,
                bff_container=bff_container,
                user_id=user_id,
                patient_id=patient_id,
                ttl_seconds=ttl,
                purposes=purposes,
            )
        _TOKEN_CACHE[cache_key] = (token, now + ttl)
        return token


async def _resolve_copilot_auth(
    *,
    target_kind: TargetKind,
    base_url: str,
    task_token: str,
    patient_id: str,
) -> tuple[str | None, str | None]:
    """Return (effective_task_token, effective_patient_id) for a scan/replay.

    For non-Co-Pilot targets the inputs pass through unchanged. For
    `clinical_copilot` targets: a blank patient_id defaults to
    `_AUTO_MINT_DEFAULT_PATIENT_ID`, and a blank token triggers auto-mint
    against `base_url` (which feeds the SSH hostname fallback).
    """
    effective_token: str | None = task_token.strip() or None
    effective_patient_id: str | None = patient_id.strip() or None
    if target_kind != TargetKind.CLINICAL_COPILOT:
        return effective_token, effective_patient_id
    if not effective_patient_id:
        effective_patient_id = _AUTO_MINT_DEFAULT_PATIENT_ID
    if not effective_token:
        effective_token = await auto_mint_task_token(
            base_url=base_url,
            patient_id=effective_patient_id,
        )
    return effective_token, effective_patient_id


async def _resolve_replay_auth(
    store: SqliteStore,
    attack_id: str,
    task_token: str,
    patient_id: str,
) -> tuple[str | None, str | None]:
    """Resolve auth for replay endpoints by looking up the attack's target.

    Mirrors what `replay_attack` does internally so we can auto-mint a token
    before the call. Raises `AttackNotFound` if the lookup fails (the caller
    re-raises as 404) and `AutoMintError` if minting fails (re-raised as 400).
    """
    attack_row = store.conn.execute(
        "SELECT target_id FROM attacks WHERE attack_id=?", (attack_id,)
    ).fetchone()
    if attack_row is None:
        raise AttackNotFound(
            f"no attack row with attack_id={attack_id!r}. "
            "Browse /attacks to find a valid id before replaying."
        )
    target_id = attack_row["target_id"]
    if not target_id:
        raise AttackNotFound(
            f"attack {attack_id!r} has no target_id stamped; cannot auto-mint."
        )
    target_dict = store.get_target(target_id)
    if target_dict is None:
        raise AttackNotFound(
            f"attack {attack_id!r} references missing target_id={target_id!r}."
        )
    kind_str = str(target_dict.get("kind") or "")
    try:
        kind = TargetKind(kind_str)
    except ValueError:
        # Unknown kinds skip auto-mint entirely.
        return task_token.strip() or None, patient_id.strip() or None
    return await _resolve_copilot_auth(
        target_kind=kind,
        base_url=str(target_dict.get("base_url") or ""),
        task_token=task_token,
        patient_id=patient_id,
    )


def create_app() -> FastAPI:
    """Build and return a configured FastAPI application."""
    app = FastAPI(title="Adversary Dashboard")
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    # Filter: wrap a timestamp string (or datetime) into a <time
    # class="user-tz"> so the client-side script in _base.html re-renders it
    # in the viewer's locale + timezone. Returns Markup so Jinja does not
    # double-escape the angle brackets. Empty / falsy values pass through
    # as a literal em-dash so tables stay aligned.
    from markupsafe import Markup, escape as _esc

    def _local_time(value: Any) -> str:
        if not value:
            return "—"
        text = value.isoformat() if hasattr(value, "isoformat") else str(value)
        return Markup(
            f'<time class="user-tz" datetime="{_esc(text)}">{_esc(text)}</time>'
        )

    templates.env.filters["local_time"] = _local_time

    # -----------------------------------------------------------------
    # Liveness / readiness for the deploy host.
    # -----------------------------------------------------------------
    #
    # GET /healthz returns 200 when the SqliteStore opens cleanly. The
    # container HEALTHCHECK in deploy/Dockerfile and the upstream Caddy
    # reverse proxy both depend on this; if it ever returns non-200,
    # Docker marks the container unhealthy and Caddy starts returning 502.
    #
    # We deliberately do NOT call any LLM provider here. Provider failures
    # are surfaced per-request from /scan and /replay, where they belong.

    @app.get("/healthz", response_class=PlainTextResponse)
    async def healthz() -> Any:
        try:
            store = _store()
            store.head_hash()  # round-trip to the audit table
            store.close()
        except Exception as exc:
            # Bubble the underlying message so `docker logs` and the
            # Caddy access log point at the broken dependency immediately.
            raise HTTPException(
                status_code=503,
                detail=(
                    "adversary dashboard not ready: SqliteStore failed to "
                    f"open or query (error={type(exc).__name__}: {exc}). "
                    "Check /data is writable inside the container and that "
                    "/opt/adversary/data exists with mode 0755 on the host."
                ),
            ) from exc
        return "ok"

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
                "SELECT rowid_seq, occurred_at, agent, action, this_hash, "
                "payload_json FROM audit_log ORDER BY rowid_seq DESC LIMIT 8"
            ).fetchall()
        ]
        for r in recent_audit:
            p = _parse_payload(r.get("payload_json"))
            r["target_id"] = p.get("target_id")
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
    # Targets: list, detail, new, register, allowlist, reach-steps
    # -----------------------------------------------------------------

    @app.get("/targets", response_class=HTMLResponse)
    async def targets_list(request: Request) -> Any:
        store = _store()
        rows = store.list_targets()
        # decorate each with per-target stats
        for r in rows:
            r["stats"] = store.target_stats(r["id"])
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="targets.html",
            context={"targets": rows, **ctx},
        )

    @app.get("/targets/new", response_class=HTMLResponse)
    async def target_new(request: Request) -> Any:
        store = _store()
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="target_new.html",
            context={
                "form": {},
                "errors": {},
                "auth_kinds": [k.value for k in AuthKind],
                "target_kinds": [k.value for k in TargetKind],
                **ctx,
            },
        )

    @app.post("/targets", response_class=HTMLResponse)
    async def target_create(
        request: Request,
        name: str = Form(""),
        kind: str = Form("http_chat"),
        base_url: str = Form(""),
        description: str = Form(""),
        reach_steps_text: str = Form(""),
        auth_kind: str = Form("none"),
        bearer_token: str = Form(""),
        header_name: str = Form(""),
        header_value: str = Form(""),
        basic_user: str = Form(""),
        basic_pass: str = Form(""),
        allow_public: bool = Form(False),
        allowlist_on_create: bool = Form(False),
    ) -> Any:
        store = _store()
        form = {
            "name": name,
            "kind": kind,
            "base_url": base_url,
            "description": description,
            "reach_steps_text": reach_steps_text,
            "auth_kind": auth_kind,
            "header_name": header_name,
            "basic_user": basic_user,
            "allow_public": allow_public,
            "allowlist_on_create": allowlist_on_create,
        }
        errors: dict[str, str] = {}

        kind_enum: TargetKind = TargetKind.HTTP_CHAT
        try:
            kind_enum = TargetKind(kind)
        except ValueError:
            errors["kind"] = (
                f"Unknown kind {kind!r}; choose one of "
                f"{', '.join(k.value for k in TargetKind)}."
            )

        try:
            auth_enum = AuthKind(auth_kind)
        except ValueError:
            errors["auth_kind"] = (
                f"Unknown auth_kind {auth_kind!r}; choose one of "
                f"{', '.join(k.value for k in AuthKind)}."
            )
            auth_enum = AuthKind.NONE

        auth_meta: dict[str, Any] = {}
        auth_secret: str | None = None
        if "auth_kind" not in errors:
            if auth_enum == AuthKind.BEARER:
                if not bearer_token:
                    errors["bearer_token"] = "Bearer token is required."
                else:
                    auth_secret = bearer_token
            elif auth_enum == AuthKind.HEADER:
                if not header_name:
                    errors["header_name"] = "Header name is required."
                if not header_value:
                    errors["header_value"] = "Header value is required."
                else:
                    auth_secret = header_value
                auth_meta = {"header_name": header_name}
            elif auth_enum == AuthKind.BASIC:
                if not basic_user:
                    errors["basic_user"] = "Username is required."
                if not basic_pass:
                    errors["basic_pass"] = "Password is required."
                else:
                    auth_secret = basic_pass
                auth_meta = {"username": basic_user}

        reach_steps = [
            line.strip() for line in reach_steps_text.splitlines() if line.strip()
        ]

        submission: TargetSubmission | None = None
        if not errors:
            try:
                submission = TargetSubmission(
                    name=name,
                    kind=kind_enum,
                    base_url=base_url,
                    description=description,
                    reach_steps=reach_steps,
                    auth_kind=auth_enum,
                    auth_meta=auth_meta,
                    auth_secret=auth_secret,
                    allow_public=bool(allow_public),
                    allowlist_on_create=bool(allowlist_on_create),
                )
            except Exception as exc:
                # Pydantic ValidationError. Re-raise messages on the right field.
                msg = str(exc)
                # crude field detection: pick the first explicit field message
                for field in ("name", "base_url", "auth_secret", "auth_meta"):
                    if field in msg:
                        errors[field] = msg
                        break
                else:
                    errors["form"] = msg

        if submission is not None and not errors:
            try:
                record = register_from_submission(store, submission)
            except ValueError as exc:
                errors["name"] = str(exc)
            else:
                ctx = _common_context(store)
                store.close()
                return RedirectResponse(
                    url=f"/targets/{record.name}", status_code=303
                )

        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="target_new.html",
            context={
                "form": form,
                "errors": errors,
                "auth_kinds": [k.value for k in AuthKind],
                "target_kinds": [k.value for k in TargetKind],
                **ctx,
            },
            status_code=400 if errors else 200,
        )

    @app.get("/targets/{name}", response_class=HTMLResponse)
    async def target_detail(request: Request, name: str) -> Any:
        store = _store()
        row = store.get_target(name)
        if row is None:
            store.close()
            raise HTTPException(
                status_code=404,
                detail=f"no target named {name!r}.",
            )
        stats = store.target_stats(row["id"])
        # Recent campaigns + findings filtered to this target.
        recent_campaigns = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM agent_runs WHERE agent='orchestrator' "
                "AND target_id=? ORDER BY created_at DESC LIMIT 20",
                (row["id"],),
            ).fetchall()
        ]
        recent_findings = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM findings WHERE target_id=? "
                "ORDER BY created_at DESC LIMIT 20",
                (row["id"],),
            ).fetchall()
        ]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="target_detail.html",
            context={
                "target": row,
                "stats": stats,
                "recent_campaigns": recent_campaigns,
                "recent_findings": recent_findings,
                **ctx,
            },
        )

    @app.post("/targets/{name}/allowlist")
    async def target_allowlist(name: str) -> Any:
        store = _store()
        row = store.get_target(name)
        if row is None:
            store.close()
            raise HTTPException(
                status_code=404, detail=f"no target named {name!r}."
            )
        store.set_allowlisted(row["id"], True)
        store.close()
        return RedirectResponse(url=f"/targets/{name}", status_code=303)

    @app.post("/targets/{name}/reach-steps")
    async def target_reach_steps(
        name: str,
        reach_steps_text: str = Form(""),
    ) -> Any:
        store = _store()
        row = store.get_target(name)
        if row is None:
            store.close()
            raise HTTPException(
                status_code=404, detail=f"no target named {name!r}."
            )
        steps = [
            line.strip()
            for line in reach_steps_text.splitlines()
            if line.strip()
        ]
        store.set_reach_steps(row["id"], steps)
        store.close()
        return RedirectResponse(url=f"/targets/{name}", status_code=303)

    @app.post("/targets/{name}/scan")
    async def target_run_scan(
        name: str,
        budget_usd: float = Form(0.50),
        max_campaigns: int = Form(3),
        provider: str = Form("scripted"),
        seed: str = Form(""),
        task_token: str = Form(""),
        patient_id: str = Form(""),
    ) -> Any:
        """Run a real scan against this target.

        Inputs are form-encoded. The store row is resolved via the registry
        (not by re-trusting the URL), the allowlist gate is enforced, and
        the orchestrator runs in-process. For scripted scans this returns
        within a couple of seconds; for live-LLM scans the request may
        block for tens of seconds. We block intentionally for the local
        single-user dashboard — the production multi-tenant path is the
        CLI.
        """
        store = _store()
        record = resolve_by_name(store, name)
        if record is None:
            store.close()
            raise HTTPException(
                status_code=404, detail=f"no target named {name!r}."
            )
        # Soft-clamp budget so a stray form submission can't burn $$$.
        budget_usd = max(0.01, min(budget_usd, 5.00))
        max_campaigns = max(1, min(max_campaigns, 10))
        seed_int: int | None
        if seed.strip():
            try:
                seed_int = int(seed.strip())
            except ValueError:
                store.close()
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"seed must be an integer, got {seed!r}. Leave the "
                        "field blank for a random seed."
                    ),
                )
        else:
            seed_int = None
        # Create the ScanJob FIRST so we can emit events during auto-mint
        # and the early background steps. The user reported a "long pause"
        # before any progress shows up; that pause is auto-mint plus the
        # lazy litellm import inside make_provider. Both deserve their own
        # visible events so the user sees motion the second the page loads.
        store.close()
        scan_id = _uuid.uuid4().hex[:12]
        expected_attacks = max_campaigns * 5
        job = ScanJob(
            id=scan_id,
            target_name=record.name,
            target_id=record.id,
            expected_attacks=expected_attacks,
            provider=provider,
            started_at=datetime.now(timezone.utc),
        )
        _SCANS[scan_id] = job
        _prune_scan_jobs()

        async def _progress_cb(kind: str, fields: dict[str, Any]) -> None:
            await job.emit(kind, fields)

        # Emit a banner event before we even kick off auto-mint so the
        # /scans/{id} page renders with content the moment it loads.
        await job.emit(
            "startup",
            {
                "step": "form_received",
                "label": (
                    f"Form received · target={record.name}, provider={provider}, "
                    f"budget=${budget_usd:.2f}, campaigns={max_campaigns}"
                ),
            },
        )

        # Run auto-mint inline with explicit start/done events. For env-based
        # signing this is millisecond-fast; for the SSH fallback path it can
        # take 2-4s while the dashboard shells out to docker exec.
        await job.emit(
            "startup",
            {
                "step": "auto_mint_start",
                "label": (
                    "Resolving task token (env-signing if "
                    "COPILOT_BFF_JWT_SIGNING_KEY is set, else SSH to BFF)…"
                ),
            },
        )
        try:
            effective_task_token, effective_patient_id = await _resolve_copilot_auth(
                target_kind=record.kind,
                base_url=record.base_url,
                task_token=task_token,
                patient_id=patient_id,
            )
        except AutoMintError as exc:
            await job.mark_done(
                error=(
                    f"auto-mint of task token for {name!r} failed: {exc}. "
                    "Manual fallback: run `adversary debug mint-task-token "
                    f"--user-id you --patient-id "
                    f"{patient_id.strip() or _AUTO_MINT_DEFAULT_PATIENT_ID} "
                    "--remote-host root@<host> --bff-container copilot-bff` "
                    "and paste the JWT into the Task token field."
                )
            )
            return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)
        await job.emit(
            "startup",
            {
                "step": "auto_mint_done",
                "label": (
                    "Task token ready"
                    if effective_task_token
                    else "No task token needed for this target"
                ),
            },
        )

        # Pre-flight: before spawning the background scan, prove the resolved
        # task token actually opens /chat. If the dashboard's signing key is
        # out of date relative to the sidecar's COPILOT_BFF_JWT_SIGNING_KEY,
        # auto-mint will succeed (it just signs a JWT, no validation) but the
        # very first /chat call will 401. Surfacing that here instead of
        # mid-scan saves the user from a confusing in-flight failure and
        # gives a specific, actionable error message.
        if effective_task_token and record.kind == "clinical_copilot":
            await job.emit(
                "startup",
                {
                    "step": "token_preflight_start",
                    "label": "Validating task token against /chat before kicking off scan…",
                },
            )
            preflight_error = await _preflight_validate_token(
                base_url=record.base_url,
                task_token=effective_task_token,
                patient_id=effective_patient_id or _AUTO_MINT_DEFAULT_PATIENT_ID,
            )
            if preflight_error:
                await job.mark_done(error=preflight_error)
                return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)
            await job.emit(
                "startup",
                {
                    "step": "token_preflight_ok",
                    "label": "Task token validated — sidecar accepted /chat call.",
                },
            )

        async def _run_in_background() -> None:
            await job.emit(
                "startup",
                {
                    "step": "background_start",
                    "label": "Background scan task starting…",
                },
            )
            inner_store = _store()
            try:
                await job.emit(
                    "startup",
                    {
                        "step": "loading_provider",
                        "label": (
                            f"Loading {provider} provider (this triggers the "
                            "litellm cold import on first use, ~1-2s)…"
                        ),
                    },
                )
                outcomes = await run_scan_for_target(
                    store=inner_store,
                    record=record,
                    budget_usd=budget_usd,
                    max_campaigns=max_campaigns,
                    provider_name=provider,
                    seed=seed_int,
                    task_token=effective_task_token,
                    patient_id=effective_patient_id,
                    reports_dir=Path("vulnerability-reports"),
                    progress_callback=_progress_cb,
                )
                total_attacks = sum(o.attacks_run for o in outcomes)
                total_success = sum(o.successes for o in outcomes)
                total_cost = sum(o.dollar_cost for o in outcomes)
                # The dashboard already renders /campaigns nicely; keep the
                # same query-string shape the old sync redirect used so any
                # bookmark / cohort handout that pasted the URL still works.
                result_url = (
                    f"/campaigns?target={record.name}&scanned=ok"
                    f"&attacks={total_attacks}&exploits={total_success}"
                )
                await job.emit(
                    "scan_done",
                    {
                        "attacks": total_attacks,
                        "exploits": total_success,
                        "dollar_cost": total_cost,
                        "campaigns": len(outcomes),
                    },
                )
                await job.mark_done(result_url=result_url)
            except TargetNotAllowlisted as exc:
                await job.mark_done(error=f"target not allowlisted: {exc}")
            except ProviderUnavailable as exc:
                await job.mark_done(error=f"provider unavailable: {exc}")
            except ValueError as exc:
                await job.mark_done(
                    error=(
                        f"could not start scan against {record.name!r}: {exc}. "
                        "For clinical_copilot you usually need a non-empty "
                        "task_token and patient_id."
                    )
                )
            except RunnerError as exc:
                await job.mark_done(error=f"runner error: {exc}")
            except Exception as exc:  # noqa: BLE001
                # Any other crash is surfaced verbatim in the UI; the user
                # sees the type+message and can re-mint a token or refile a
                # bug. Stash full traceback for the server log too.
                import traceback

                tb = traceback.format_exc()
                await job.emit("server_traceback", {"traceback": tb})
                await job.mark_done(
                    error=f"{type(exc).__name__}: {exc}"
                )
            finally:
                inner_store.close()

        asyncio.create_task(_run_in_background())
        return RedirectResponse(url=f"/scans/{scan_id}", status_code=303)

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    async def scan_progress(request: Request, scan_id: str) -> Any:
        job = _SCANS.get(scan_id)
        if job is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"no scan with id {scan_id!r} in this process. The job "
                    "may have expired (TTL is 1 hour) or the dashboard was "
                    "restarted after launch. Re-submit the form."
                ),
            )
        return templates.TemplateResponse(
            request=request,
            name="scan_progress.html",
            context={
                "scan_id": scan_id,
                "target_name": job.target_name,
                "target_id": job.target_name,  # routes use name as the slug
                "expected_attacks": job.expected_attacks,
                "provider": job.provider,
                "started_at": job.started_at.isoformat(),
                "footer_audit_head": None,
            },
        )

    @app.get("/scans/{scan_id}/events")
    async def scan_events(scan_id: str) -> Any:
        job = _SCANS.get(scan_id)
        if job is None:
            raise HTTPException(status_code=404, detail="scan id not found")

        async def stream() -> Any:
            idx = 0
            while True:
                # Drain any pending events under the condition, then yield
                # outside it so a slow client can't hold the lock.
                async with job.cond:
                    pending = job.events[idx:]
                    idx = len(job.events)
                    done = job.done
                    err = job.error
                    url = job.result_url
                for ev in pending:
                    yield f"data: {json.dumps(ev)}\n\n"
                if done:
                    yield (
                        "data: "
                        + json.dumps(
                            {
                                "kind": "terminal",
                                "error": err,
                                "result_url": url,
                            }
                        )
                        + "\n\n"
                    )
                    return
                # Block up to 8s for the next event; emit an SSE comment as
                # a heartbeat if we time out so proxies don't close the
                # connection for being idle.
                async with job.cond:
                    try:
                        await asyncio.wait_for(job.cond.wait(), timeout=8.0)
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-transform",
                "Connection": "keep-alive",
                # Caddy + nginx hint: do not buffer this response.
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/attacks/{attack_id}/replay")
    async def attack_replay(
        attack_id: str,
        task_token: str = Form(""),
        patient_id: str = Form(""),
    ) -> Any:
        """Replay a single previously-persisted attack."""
        store = _store()
        try:
            effective_task_token, effective_patient_id = (
                await _resolve_replay_auth(
                    store, attack_id, task_token, patient_id
                )
            )
        except AttackNotFound as exc:
            store.close()
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AutoMintError as exc:
            store.close()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            summary = await replay_attack(
                store=store,
                attack_id=attack_id,
                task_token=effective_task_token,
                patient_id=effective_patient_id,
            )
        except AttackNotFound as exc:
            store.close()
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except TargetNotAllowlisted as exc:
            store.close()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            store.close()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store.close()
        return RedirectResponse(
            url=(
                f"/attacks/{attack_id}?replayed=ok"
                f"&new_verdict={summary['new_verdict']}"
                f"&confidence={summary['confidence']:.2f}"
            ),
            status_code=303,
        )

    @app.post("/findings/{finding_id}/replay")
    async def finding_replay(
        finding_id: str,
        task_token: str = Form(""),
        patient_id: str = Form(""),
    ) -> Any:
        """Re-run the underlying attack of a finding to confirm a fix or
        regression."""
        store = _store()
        row = store.conn.execute(
            "SELECT lineage_root FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if not row or not row["lineage_root"]:
            store.close()
            raise HTTPException(
                status_code=404,
                detail=(
                    f"no replayable attack for finding {finding_id!r} "
                    "(lineage_root is empty)."
                ),
            )
        attack_id = row["lineage_root"]
        try:
            effective_task_token, effective_patient_id = (
                await _resolve_replay_auth(
                    store, attack_id, task_token, patient_id
                )
            )
        except AttackNotFound as exc:
            store.close()
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except AutoMintError as exc:
            store.close()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            summary = await replay_attack(
                store=store,
                attack_id=attack_id,
                task_token=effective_task_token,
                patient_id=effective_patient_id,
            )
        except AttackNotFound as exc:
            store.close()
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except TargetNotAllowlisted as exc:
            store.close()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            store.close()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store.close()
        return RedirectResponse(
            url=(
                f"/findings/{finding_id}?replayed=ok"
                f"&new_verdict={summary['new_verdict']}"
                f"&confidence={summary['confidence']:.2f}"
            ),
            status_code=303,
        )

    # -----------------------------------------------------------------
    # Findings + finding detail
    # -----------------------------------------------------------------

    @app.get("/findings", response_class=HTMLResponse)
    async def findings(
        request: Request,
        severity: str | None = None,
        target: str | None = None,
    ) -> Any:
        store = _store()
        clauses: list[str] = []
        params: list[Any] = []
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if target:
            t_row = store.get_target(target)
            if t_row is not None:
                clauses.append("target_id=?")
                params.append(t_row["id"])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = [
            dict(r)
            for r in store.conn.execute(
                f"SELECT * FROM findings {where} ORDER BY created_at DESC LIMIT 200",
                tuple(params),
            ).fetchall()
        ]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="findings.html",
            context={
                "findings": rows,
                "severity_filter": severity,
                "target_filter": target,
                **ctx,
            },
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

        # Resolve the registered target. Prefer the finding's target_id; fall
        # back to the exchange payload's target_id, then to URL lookup.
        target_record: dict[str, Any] | None = None
        target_id_lookup = (
            finding.get("target_id")
            or (exchange or {}).get("target_id")
        )
        if target_id_lookup:
            target_record = store.get_target(target_id_lookup)
        if target_record is None and target_url:
            for r in store.list_targets():
                if r["base_url"] == target_url:
                    target_record = r
                    break

        # Encyclopedia overlay keyed on target kind (dual-layer prose).
        target_overlay = None
        if subcat_info is not None and target_record is not None:
            target_overlay = overlay_for_kind(
                subcat_info, TargetKind(target_record["kind"])
            )

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
                "target_overlay": target_overlay,
                "target_record": target_record,
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
    async def coverage(request: Request, target: str | None = None) -> Any:
        store = _store()
        # Coverage rows are not target-scoped in the schema today. When
        # ?target= is supplied, we approximate by intersecting with
        # attacks.target_id so the matrix only shows categories the
        # target has been hit on. Without ?target= it shows the global
        # matrix as before.
        if target:
            t_row = store.get_target(target)
            if t_row is not None:
                seen = {
                    (r["category"], r["subcategory"])
                    for r in store.conn.execute(
                        "SELECT DISTINCT category, subcategory FROM attacks "
                        "WHERE target_id=?",
                        (t_row["id"],),
                    ).fetchall()
                }
                rows = [
                    dict(r)
                    for r in store.conn.execute(
                        "SELECT * FROM coverage ORDER BY category, subcategory"
                    ).fetchall()
                    if (r["category"], r["subcategory"]) in seen
                ]
            else:
                rows = []
        else:
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
            context={"rows": rows, "target_filter": target, **ctx},
        )

    # -----------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------

    @app.get("/audit", response_class=HTMLResponse)
    async def audit(request: Request, target: str | None = None) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT rowid_seq, prev_hash, this_hash, occurred_at, agent, "
                "action, payload_json FROM audit_log ORDER BY rowid_seq DESC "
                "LIMIT 200"
            ).fetchall()
        ]
        # Decorate each row with its target_id (parsed from payload) so the
        # template can render the target badge and the filter pill works.
        for r in rows:
            p = _parse_payload(r.get("payload_json"))
            r["target_id"] = p.get("target_id")
            r["target_name"] = p.get("target_name")
        if target:
            t_row = store.get_target(target)
            if t_row is not None:
                rows = [r for r in rows if r.get("target_id") == t_row["id"]]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="audit.html",
            context={"rows": rows, "target_filter": target, **ctx},
        )

    # -----------------------------------------------------------------
    # Campaigns
    # -----------------------------------------------------------------

    @app.get("/campaigns", response_class=HTMLResponse)
    async def campaigns(request: Request, target: str | None = None) -> Any:
        store = _store()
        where = ""
        params: tuple[Any, ...] = ()
        if target:
            t_row = store.get_target(target)
            if t_row is not None:
                where = "AND target_id=?"
                params = (t_row["id"],)
        runs = [
            dict(r)
            for r in store.conn.execute(
                f"SELECT * FROM agent_runs WHERE agent='orchestrator' {where} "
                f"ORDER BY created_at DESC",
                params,
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
            context={"campaigns": runs, "target_filter": target, **ctx},
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

        # Real cost / latency / verdict mix for this specific campaign.
        # The orchestrator's agent_runs row is a placeholder (cost=0,
        # latency=0) so the page header used to show $0.0000 / 0 ms for
        # every campaign even when the campaign actually spent money.
        breakdown = store.campaign_breakdown(campaign_id)
        latency_ms: int | None = None
        if breakdown["started_at"] and breakdown["ended_at"]:
            try:
                from datetime import datetime
                t0 = datetime.fromisoformat(breakdown["started_at"])
                t1 = datetime.fromisoformat(breakdown["ended_at"])
                latency_ms = max(0, int((t1 - t0).total_seconds() * 1000))
            except ValueError as exc:
                raise ValueError(
                    f"campaign_detail: cannot parse occurred_at "
                    f"timestamps for campaign {campaign_id}: {exc}. "
                    "Audit rows must use ISO-8601 UTC."
                ) from exc

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
                "breakdown": breakdown,
                "latency_ms": latency_ms,
                **ctx,
            },
        )

    # -----------------------------------------------------------------
    # Attacks
    # -----------------------------------------------------------------

    @app.get("/attacks", response_class=HTMLResponse)
    async def attacks(
        request: Request,
        page: int = 1,
        target: str | None = None,
    ) -> Any:
        store = _store()
        page = max(1, page)
        per_page = 50
        offset = (page - 1) * per_page
        where = ""
        params: tuple[Any, ...] = ()
        if target:
            t_row = store.get_target(target)
            if t_row is not None:
                where = "WHERE target_id=?"
                params = (t_row["id"],)
        total = store.conn.execute(
            f"SELECT COUNT(*) FROM attacks {where}", params
        ).fetchone()[0]
        rows = [
            dict(r)
            for r in store.conn.execute(
                f"SELECT attack_id, category, subcategory, expected_unsafe_behavior, "
                f"created_at, target_id FROM attacks {where} ORDER BY created_at DESC "
                f"LIMIT ? OFFSET ?",
                (*params, per_page, offset),
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
                "target_filter": target,
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
    async def verdicts(request: Request, target: str | None = None) -> Any:
        store = _store()
        rows = [
            dict(r)
            for r in store.conn.execute(
                "SELECT * FROM verdicts ORDER BY created_at DESC LIMIT 500"
            ).fetchall()
        ]
        for r in rows:
            r["evidence"] = json.loads(r["evidence_json"] or "[]")
        # Join in target_id by looking up the attack row.
        attack_target_map: dict[str, str | None] = {}
        for r in rows:
            aid = r["attack_id"]
            if aid in attack_target_map:
                continue
            ar = store.conn.execute(
                "SELECT target_id FROM attacks WHERE attack_id=?", (aid,)
            ).fetchone()
            attack_target_map[aid] = ar["target_id"] if ar else None
        for r in rows:
            r["target_id"] = attack_target_map.get(r["attack_id"])
        if target:
            t_row = store.get_target(target)
            if t_row is not None:
                rows = [r for r in rows if r["target_id"] == t_row["id"]]
        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="verdicts.html",
            context={"verdicts": rows, "target_filter": target, **ctx},
        )

    # -----------------------------------------------------------------
    # Cost
    # -----------------------------------------------------------------

    @app.get("/cost", response_class=HTMLResponse)
    async def cost(request: Request) -> Any:
        # Single source of truth lives in store.cost_breakdown() so the
        # /cost page and the summary card on / never disagree. See
        # storage/store.py for the rationale (three tables hold spend).
        store = _store()
        breakdown = store.cost_breakdown()
        rows = breakdown["rows"]
        total = breakdown["total_dollar_cost"]
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
    async def glossary_detail(
        request: Request,
        category_key: str,
        target: str | None = None,
    ) -> Any:
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

        # Optional dual-layer overlay: ?target=<name> merges target-specific
        # risks/fixes addenda into each subcategory render.
        overlays_by_sub: dict[str, Any] = {}
        target_record: dict[str, Any] | None = None
        if target:
            target_record = store.get_target(target)
            if target_record is not None:
                kind = TargetKind(target_record["kind"])
                for sub in info.subcategories:
                    ov = overlay_for_kind(sub, kind)
                    if ov is not None:
                        overlays_by_sub[sub.key] = ov

        ctx = _common_context(store)
        store.close()
        return templates.TemplateResponse(
            request=request,
            name="category_detail.html",
            context={
                "info": info,
                "coverage": cov_rows,
                "target_record": target_record,
                "overlays_by_sub": overlays_by_sub,
                **ctx,
            },
        )

    return app


# ---------------------------------------------------------------------
# Helpers used by the templates indirectly (via context).
# ---------------------------------------------------------------------

def _narrative_for_audit(row: dict[str, Any]) -> str:
    """One-line "what happened" rendering of an audit row's payload.

    NOTE: every new audit row written by an agent should also get a case
    here, otherwise the campaign timeline falls back to the cryptic
    "agent.action" form. Bug-prevention checklist entry T1 covers this.
    """
    agent = row["agent"]
    action = row["action"]
    payload = row.get("payload", {}) or {}
    if agent == "orchestrator" and action == "campaign_start":
        cat = payload.get("category", "?")
        sub = payload.get("subcategory", "?")
        return f"Orchestrator launched a {cat} / {sub} campaign."
    if agent == "orchestrator" and action == "campaign_done":
        s = payload.get("successes", 0)
        p = payload.get("partials", 0)
        f = payload.get("fails", 0)
        cost = payload.get("dollar_cost", 0.0)
        return (
            f"Orchestrator closed campaign — success={s} partial={p} "
            f"fail={f} cost=${float(cost):.4f}."
        )
    if agent == "red_team" and action == "attack_generated":
        aid = payload.get("attack_id", "?")
        model = payload.get("model", "?")
        cost = payload.get("dollar_cost", 0.0)
        return (
            f"Red Team generated {aid} via {model} for "
            f"${float(cost):.6f}."
        )
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
