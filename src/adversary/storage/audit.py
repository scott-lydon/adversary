"""Audit-chain verify and tamper helpers.

Verification walks every row in order: each row's ``prev_hash`` must equal the
previous row's ``this_hash``, and each row's own ``this_hash`` must equal
``sha256(canonical_json({prev_hash, occurred_at, agent, action, payload}))``.

Tampering flips a single byte in a row's payload so the chain breaks at the
next row's hash check.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from adversary.storage.store import SqliteStore, canonical_json


class AuditChainBroken(RuntimeError):
    """Raised when the audit chain is broken. Includes the offending row id."""


def audit_verify(store: SqliteStore) -> tuple[bool, int, str]:
    """Verify the audit chain end-to-end.

    Returns ``(ok, row_count, reason)``. If ``ok`` is ``False`` the row index
    where the chain broke is encoded in ``reason``.
    """
    rows = store.conn.execute(
        "SELECT rowid_seq, prev_hash, this_hash, occurred_at, agent, action, "
        "payload_json FROM audit_log ORDER BY rowid_seq"
    ).fetchall()
    if not rows:
        return True, 0, "empty"

    prev = "0" * 64
    for idx, row in enumerate(rows, start=1):
        if row["prev_hash"] != prev:
            return False, len(rows), (
                f"audit_chain=BROKEN at_row={idx} reason=prev_hash_mismatch "
                f"expected={prev} got={row['prev_hash']}"
            )
        body = canonical_json(
            {
                "prev_hash": row["prev_hash"],
                "occurred_at": row["occurred_at"],
                "agent": row["agent"],
                "action": row["action"],
                "payload": _decode_payload(row["payload_json"]),
            }
        )
        expected = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if expected != row["this_hash"]:
            return False, len(rows), (
                f"audit_chain=BROKEN at_row={idx} reason=this_hash_mismatch "
                f"expected={expected} got={row['this_hash']}"
            )
        prev = row["this_hash"]
    return True, len(rows), "ok"


def _decode_payload(payload_json: str) -> object:
    import json

    return json.loads(payload_json)


def audit_tamper(store: SqliteStore, row_index: int) -> None:
    """Flip a single byte of the payload at the given (1-indexed) row.

    The hash on that row is intentionally NOT updated so the next-row check
    fails on the immediately following row.
    """
    rows = store.conn.execute(
        "SELECT rowid_seq, payload_json FROM audit_log ORDER BY rowid_seq"
    ).fetchall()
    if row_index < 1 or row_index > len(rows):
        raise ValueError(
            f"audit_tamper: row_index={row_index} out of range "
            f"(1..{len(rows)}). The audit log currently has {len(rows)} rows. "
            "Run `adversary scan --target echo://demo --max-campaigns 1` first "
            "to seed the table."
        )
    target = rows[row_index - 1]
    import json as _json

    payload = _json.loads(target["payload_json"])
    # Add a sentinel key so the canonical-json hash differs from the stored
    # this_hash on the SAME row, which the verifier catches as
    # "this_hash_mismatch" on this row.
    if isinstance(payload, dict):
        payload["_tampered"] = True
    else:
        payload = {"_tampered": True, "original": payload}
    new_payload = _json.dumps(payload, sort_keys=True, separators=(",", ":"))
    store.conn.execute(
        "UPDATE audit_log SET payload_json=? WHERE rowid_seq=?",
        (new_payload, target["rowid_seq"]),
    )
    store.conn.commit()


def find_default_db(cwd: str | Path | None = None) -> Path:
    """Return the canonical adversary.db path under the working dir."""
    base = Path(cwd) if cwd else Path.cwd()
    return base / "adversary.db"
