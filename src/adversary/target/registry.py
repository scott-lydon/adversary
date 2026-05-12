"""Target-registry resolution helpers used by the CLI and dashboard.

The registry lives in the ``targets`` SQL table. This module wraps the
store with helpers that:
  - resolve a TargetRecord by name (the new identity-first path).
  - resolve a TargetRecord by URL (the legacy ``--target <url>`` path):
    echo URLs map to the seeded ``echo-demo`` row; HTTP URLs match an
    existing http_chat row by base_url, or auto-register one when the
    caller explicitly opts in.
  - register a new target from a TargetSubmission, encrypting the secret
    via ``security.secrets`` before persisting.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from adversary.models import (
    AuthKind,
    TargetKind,
    TargetRecord,
    TargetSubmission,
)
from adversary.security import encrypt_secret
from adversary.storage import SqliteStore


class TargetNotAllowlisted(RuntimeError):
    """Raised when a scan would proceed against a non-allowlisted target.

    Per ARCHITECTURE §9, the allowlist is the gate that prevents the
    platform from becoming a denial-of-service weapon. The error message
    is the operator's call to action.
    """


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _record_from_row(row: dict[str, Any]) -> TargetRecord:
    return TargetRecord(
        id=row["id"],
        name=row["name"],
        kind=TargetKind(row["kind"]),
        base_url=row["base_url"],
        description=row.get("description", ""),
        reach_steps=list(row.get("reach_steps", [])),
        auth_kind=AuthKind(row.get("auth_kind", "none")),
        auth_meta=dict(row.get("auth_meta", {})),
        allowlisted=bool(row.get("allowlisted", False)),
        registered_at=row["registered_at"],
        last_used_at=row.get("last_used_at"),
    )


def resolve_by_name(store: SqliteStore, name: str) -> TargetRecord:
    """Look up a registered target by name. Raises ValueError on miss."""
    row = store.get_target(name)
    if row is None:
        raise ValueError(
            f"No registered target named {name!r}. Run "
            "`adversary targets list` to see available names, or "
            "`adversary targets add --name {name} --kind http_chat "
            "--url ...` to register one."
        )
    return _record_from_row(row)


def resolve_by_url(
    store: SqliteStore,
    url: str,
    *,
    auto_register: bool = False,
) -> TargetRecord:
    """Resolve a target by ``--target <url>``.

    - ``echo://demo``/``echo://hardened`` resolve to a seeded row when
      possible; for ``echo://hardened`` (not seeded), a transient row is
      auto-registered.
    - ``http(s)://...`` matches an existing http_chat row by base_url
      verbatim; otherwise behavior depends on ``auto_register``:
        - True: create an ``auto-<sha8>`` http_chat row (not allowlisted).
        - False: raise ValueError directing the operator to
          ``adversary targets add``.
    """
    if url.startswith("echo://"):
        # Prefer an existing row keyed on base_url.
        for row in store.list_targets():
            if row["base_url"] == url:
                return _record_from_row(row)
        # Auto-register hardened (or any other echo variant) deterministically.
        slug = url.removeprefix("echo://")
        name = f"echo-{slug}"
        rid = f"tgt-{name}"
        store.register_target(
            id=rid,
            name=name,
            kind="echo",
            base_url=url,
            description="Auto-registered echo target.",
            reach_steps=[],
            auth_kind="none",
            auth_meta={},
            auth_secret_encrypted=None,
            allowlisted=True,
            registered_at=_utcnow(),
        )
        return _record_from_row(store.get_target(rid) or {})

    if not url.startswith(("http://", "https://")):
        raise ValueError(
            f"target URL {url!r} is not a recognized scheme. "
            "Accepted schemes: 'echo://', 'http://', 'https://'."
        )

    # http(s) target: match existing.
    for row in store.list_targets():
        if row["base_url"] == url:
            return _record_from_row(row)

    if not auto_register:
        raise ValueError(
            f"No registered target matches URL {url!r}. "
            f"Register it first: `adversary targets add --name <slug> "
            f"--kind http_chat --url {url}`. "
            "Pass --auto-register to skip this check (the target will "
            "still be disallowed until you run `adversary targets allow`)."
        )

    digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:8]
    name = f"auto-{digest}"
    rid = f"tgt-{name}"
    # If a previous auto-register with the same hash exists, reuse it.
    existing = store.get_target(name)
    if existing is not None:
        return _record_from_row(existing)
    store.register_target(
        id=rid,
        name=name,
        kind="http_chat",
        base_url=url,
        description=f"Auto-registered http_chat target for {url}.",
        reach_steps=[],
        auth_kind="none",
        auth_meta={},
        auth_secret_encrypted=None,
        allowlisted=False,
        registered_at=_utcnow(),
    )
    return _record_from_row(store.get_target(rid) or {})


def register_from_submission(
    store: SqliteStore, submission: TargetSubmission
) -> TargetRecord:
    """Persist a new target. Encrypts the secret if one was provided."""
    ciphertext: bytes | None = None
    if submission.auth_secret:
        ciphertext = encrypt_secret(submission.auth_secret)

    rid = f"tgt-{uuid4().hex[:10]}"
    try:
        store.register_target(
            id=rid,
            name=submission.name,
            kind=submission.kind.value,
            base_url=submission.base_url,
            description=submission.description,
            reach_steps=submission.reach_steps,
            auth_kind=submission.auth_kind.value,
            auth_meta=submission.auth_meta,
            auth_secret_encrypted=ciphertext,
            allowlisted=submission.allowlist_on_create,
            registered_at=_utcnow(),
        )
    except sqlite3.IntegrityError as exc:
        # The UNIQUE constraint on name is the only one that fires here.
        raise ValueError(
            f"A target named {submission.name!r} already exists. "
            "Pick a different slug, or run "
            f"`adversary targets remove {submission.name}` first."
        ) from exc
    row = store.get_target(rid)
    assert row is not None
    return _record_from_row(row)


def assert_allowlisted(record: TargetRecord) -> None:
    """Raise ``TargetNotAllowlisted`` if the record is not allowlisted."""
    if record.allowlisted:
        return
    raise TargetNotAllowlisted(
        f"target {record.name!r} is not in the allowlist; run "
        f"`adversary targets allow {record.name}` first. "
        "Per ARCHITECTURE §9 this gate prevents the platform from "
        "becoming a denial-of-service weapon."
    )
