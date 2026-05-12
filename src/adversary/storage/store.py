"""SqliteStore: schema bootstrap, inserts, basic reads.

The store is intentionally thin. Every write is logged to the audit table by
``append_audit`` which is hash-chained so tampering is detectable.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

REQUIRED_TABLES: tuple[str, ...] = (
    "coverage",
    "findings",
    "verdicts",
    "agent_runs",
    "agent_messages",
    "audit_log",
    "attacks",
    "regression_records",
    "targets",
)


_SCHEMA: dict[str, str] = {
    "coverage": """
        CREATE TABLE IF NOT EXISTS coverage (
            category TEXT NOT NULL,
            subcategory TEXT NOT NULL,
            runs INTEGER NOT NULL DEFAULT 0,
            successes INTEGER NOT NULL DEFAULT 0,
            partials INTEGER NOT NULL DEFAULT 0,
            fails INTEGER NOT NULL DEFAULT 0,
            last_run TEXT,
            PRIMARY KEY (category, subcategory)
        )
    """,
    "findings": """
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT NOT NULL,
            status TEXT NOT NULL,
            target_version_when_discovered TEXT,
            target_version_when_resolved TEXT,
            lineage_root TEXT,
            report_path TEXT,
            created_at TEXT NOT NULL
        )
    """,
    "verdicts": """
        CREATE TABLE IF NOT EXISTS verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id TEXT NOT NULL,
            target_response_hash TEXT NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL NOT NULL,
            judge_model TEXT NOT NULL,
            rubric_version TEXT NOT NULL,
            evidence_json TEXT,
            notes TEXT,
            dollar_cost REAL NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """,
    "agent_runs": """
        CREATE TABLE IF NOT EXISTS agent_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT NOT NULL,
            model TEXT NOT NULL,
            session_id TEXT,
            dollar_cost REAL NOT NULL DEFAULT 0,
            latency_ms INTEGER NOT NULL DEFAULT 0,
            tokens_in INTEGER NOT NULL DEFAULT 0,
            tokens_out INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """,
    "agent_messages": """
        CREATE TABLE IF NOT EXISTS agent_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_agent TEXT NOT NULL,
            to_agent TEXT NOT NULL,
            schema_name TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            trace_id TEXT,
            created_at TEXT NOT NULL
        )
    """,
    "audit_log": """
        CREATE TABLE IF NOT EXISTS audit_log (
            rowid_seq INTEGER PRIMARY KEY AUTOINCREMENT,
            prev_hash TEXT NOT NULL,
            this_hash TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            agent TEXT NOT NULL,
            action TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
    """,
    "attacks": """
        CREATE TABLE IF NOT EXISTS attacks (
            attack_id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            subcategory TEXT NOT NULL,
            prompt_sequence_json TEXT NOT NULL,
            expected_unsafe_behavior TEXT NOT NULL,
            mutation_lineage_json TEXT NOT NULL,
            generation_metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """,
    "regression_records": """
        CREATE TABLE IF NOT EXISTS regression_records (
            id TEXT PRIMARY KEY,
            category TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            target_version_when_discovered TEXT,
            attack_sequence_json TEXT NOT NULL,
            expected_safe_behavior TEXT NOT NULL,
            judging_rubric_version TEXT NOT NULL,
            mutation_parent TEXT,
            variants_count INTEGER NOT NULL DEFAULT 0
        )
    """,
    "targets": """
        CREATE TABLE IF NOT EXISTS targets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            base_url TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            reach_steps_json TEXT NOT NULL DEFAULT '[]',
            auth_kind TEXT NOT NULL DEFAULT 'none',
            auth_secret_encrypted BLOB,
            auth_meta_json TEXT NOT NULL DEFAULT '{}',
            allowlisted INTEGER NOT NULL DEFAULT 0,
            registered_at TEXT NOT NULL,
            last_used_at TEXT
        )
    """,
}


# Additive columns added after the original schema was published. Each row
# is (table_name, column_name, ddl_fragment). ``_ensure_additive_columns``
# only adds a column when ``PRAGMA table_info`` does not already list it,
# so re-running on an already-migrated database is a no-op.
_ADDITIVE_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("findings", "target_id", "TEXT"),
    ("attacks", "target_id", "TEXT"),
    ("agent_runs", "target_id", "TEXT"),
    ("regression_records", "target_id", "TEXT"),
)


def canonical_json(payload: Any) -> str:
    """Stable JSON serializer used by the audit chain.

    ``sort_keys=True`` plus separator pinning makes the hash chain reproducible
    across Python versions.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


class SqliteStore:
    """A thin wrapper around a single sqlite3 connection.

    The connection lives for the SqliteStore's lifetime and is closed in
    ``close()``. Tests use ``SqliteStore(tmp_path / 'adversary.db')`` and rely
    on ``reset()`` to drop and recreate the schema between tests.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.init_schema()

    def init_schema(self) -> None:
        for table, ddl in _SCHEMA.items():
            self.conn.execute(ddl)
        self._ensure_additive_columns()
        self.conn.commit()
        self._seed_default_targets()

    def _ensure_additive_columns(self) -> None:
        """Apply ALTER TABLE ADD COLUMN for columns added post-launch.

        Existing databases pre-date these columns; running on a fresh
        schema is a no-op because ``PRAGMA table_info`` already lists
        them. Never drops or renames; strictly additive.
        """
        for table, column, ddl_type in _ADDITIVE_COLUMNS:
            cols = {
                row["name"]
                for row in self.conn.execute(f"PRAGMA table_info({table})")
            }
            if column not in cols:
                self.conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}"
                )

    def _seed_default_targets(self) -> None:
        """Idempotent: insert the two seed rows if they are missing.

        Re-running ``init_schema`` does not duplicate rows because both
        seeds have a UNIQUE name; we use INSERT OR IGNORE keyed on name.
        """
        # Local import to avoid a circular import at module load.
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        seeds: tuple[dict[str, Any], ...] = (
            {
                "id": "tgt-echo-demo",
                "name": "echo-demo",
                "kind": "echo",
                "base_url": "echo://demo",
                "description": (
                    "Local in-process intentionally-vulnerable demo target "
                    "no network, no LLM keys."
                ),
                "reach_steps_json": canonical_json(
                    [
                        "Run `adversary scan --target-name echo-demo`.",
                        "Inspect findings on the dashboard.",
                    ]
                ),
                "auth_kind": "none",
                "auth_meta_json": "{}",
                "allowlisted": 1,
                "registered_at": now,
            },
            {
                "id": "tgt-clinical-copilot-hetzner",
                "name": "clinical-copilot-hetzner",
                "kind": "clinical_copilot",
                "base_url": "http://5.161.253.237",
                "description": (
                    "OpenEMR fork with Clinical Co-Pilot sidecar Week 1/2 "
                    "Gauntlet deliverable. Requires --task-token and "
                    "--patient-id at scan time."
                ),
                "reach_steps_json": canonical_json(
                    [
                        "Open OpenEMR in a browser at http://5.161.253.237",
                        "Log in with admin / OpenEmrAdmin!2026",
                        "Click the Patients tab in the left rail, then 'Patient List'",
                        "Click the row for Patient/87413 (the Demo Patient)",
                        "On the patient chart, click the 'Launch Co-Pilot' button in the action bar (the BFF mints a 5-minute task token in the background)",
                        "The Co-Pilot sidecar opens at http://localhost:8801 with the task token in the URL fragment",
                        "Wait for the patient picker and purpose dropdowns to populate (they call GET /patients)",
                        "Pick 'Patient/87413' in the patient dropdown",
                        "Pick 'Pre-visit cross-check (Use Case A)' in the purpose dropdown",
                        "Click Run to send the initial diagnostic-cross-check request",
                        "After the response renders, switch the purpose dropdown to 'Follow-up question'",
                        "Type your follow-up into the message text box (this is the chat input - the attack surface)",
                        "Click Run again. The browser POSTs to /chat with the task token in the Authorization header and your text in the JSON field 'message'.",
                        "To get a task token for the Adversary scanner: mint one yourself via `adversary debug mint-task-token --user-id admin --patient-id Patient/87413` and paste it into the Run scan form below.",
                    ]
                ),
                "auth_kind": "none",
                "auth_meta_json": "{}",
                "allowlisted": 0,
                "registered_at": now,
            },
        )
        for s in seeds:
            self.conn.execute(
                "INSERT OR IGNORE INTO targets "
                "(id, name, kind, base_url, description, reach_steps_json, "
                "auth_kind, auth_secret_encrypted, auth_meta_json, "
                "allowlisted, registered_at, last_used_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL)",
                (
                    s["id"],
                    s["name"],
                    s["kind"],
                    s["base_url"],
                    s["description"],
                    s["reach_steps_json"],
                    s["auth_kind"],
                    s["auth_meta_json"],
                    s["allowlisted"],
                    s["registered_at"],
                ),
            )
        self.conn.commit()

    def reset(self) -> None:
        """Drop and recreate every table. Used by `adversary status --reset-db`."""
        for table in REQUIRED_TABLES:
            self.conn.execute(f"DROP TABLE IF EXISTS {table}")
        self.conn.commit()
        self.init_schema()

    def close(self) -> None:
        self.conn.close()

    # --- audit log -------------------------------------------------------

    def head_hash(self) -> str:
        row = self.conn.execute(
            "SELECT this_hash FROM audit_log ORDER BY rowid_seq DESC LIMIT 1"
        ).fetchone()
        return str(row["this_hash"]) if row else "0" * 64

    def append_audit(
        self,
        *,
        agent: str,
        action: str,
        payload: dict[str, Any],
        occurred_at: str,
    ) -> str:
        prev = self.head_hash()
        body = canonical_json(
            {
                "prev_hash": prev,
                "occurred_at": occurred_at,
                "agent": agent,
                "action": action,
                "payload": payload,
            }
        )
        this_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT INTO audit_log "
            "(prev_hash, this_hash, occurred_at, agent, action, payload_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (prev, this_hash, occurred_at, agent, action, canonical_json(payload)),
        )
        self.conn.commit()
        return this_hash

    # --- coverage / findings / verdicts / attacks -----------------------

    def upsert_coverage(
        self,
        *,
        category: str,
        subcategory: str,
        verdict: str,
        occurred_at: str,
    ) -> None:
        row = self.conn.execute(
            "SELECT * FROM coverage WHERE category=? AND subcategory=?",
            (category, subcategory),
        ).fetchone()
        increments = {"success": 0, "partial": 0, "fail": 0}
        if verdict in increments:
            increments[verdict] += 1
        if row is None:
            self.conn.execute(
                "INSERT INTO coverage "
                "(category, subcategory, runs, successes, partials, fails, last_run) "
                "VALUES (?, ?, 1, ?, ?, ?, ?)",
                (
                    category,
                    subcategory,
                    increments["success"],
                    increments["partial"],
                    increments["fail"],
                    occurred_at,
                ),
            )
        else:
            self.conn.execute(
                "UPDATE coverage "
                "SET runs=runs+1, successes=successes+?, partials=partials+?, "
                "fails=fails+?, last_run=? "
                "WHERE category=? AND subcategory=?",
                (
                    increments["success"],
                    increments["partial"],
                    increments["fail"],
                    occurred_at,
                    category,
                    subcategory,
                ),
            )
        self.conn.commit()

    def insert_attack(
        self,
        attack_dict: dict[str, Any],
        created_at: str,
        target_id: str | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO attacks "
            "(attack_id, category, subcategory, prompt_sequence_json, "
            "expected_unsafe_behavior, mutation_lineage_json, "
            "generation_metadata_json, created_at, target_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attack_dict["attack_id"],
                attack_dict["category"],
                attack_dict["subcategory"],
                canonical_json(attack_dict.get("prompt_sequence", [])),
                attack_dict["expected_unsafe_behavior"],
                canonical_json(attack_dict.get("mutation_lineage", [])),
                canonical_json(attack_dict.get("generation_metadata", {})),
                created_at,
                target_id,
            ),
        )
        self.conn.commit()

    def insert_verdict(
        self,
        *,
        verdict_dict: dict[str, Any],
        target_response_hash: str,
        created_at: str,
    ) -> None:
        self.conn.execute(
            "INSERT INTO verdicts "
            "(attack_id, target_response_hash, verdict, confidence, "
            "judge_model, rubric_version, evidence_json, notes, "
            "dollar_cost, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                verdict_dict["attack_id"],
                target_response_hash,
                verdict_dict["verdict"],
                verdict_dict["confidence"],
                verdict_dict["judge_model"],
                verdict_dict["rubric_version"],
                canonical_json(verdict_dict.get("evidence", [])),
                verdict_dict.get("notes", ""),
                verdict_dict.get("dollar_cost", 0.0),
                created_at,
            ),
        )
        self.conn.commit()

    def insert_finding(self, finding: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings "
            "(id, severity, category, subcategory, status, "
            "target_version_when_discovered, target_version_when_resolved, "
            "lineage_root, report_path, created_at, target_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding["id"],
                finding["severity"],
                finding["category"],
                finding["subcategory"],
                finding["status"],
                finding.get("target_version_when_discovered"),
                finding.get("target_version_when_resolved"),
                finding.get("lineage_root"),
                finding.get("report_path"),
                finding["created_at"],
                finding.get("target_id"),
            ),
        )
        self.conn.commit()

    def insert_agent_run(self, run: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO agent_runs "
            "(agent, model, session_id, dollar_cost, latency_ms, "
            "tokens_in, tokens_out, error, created_at, target_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run["agent"],
                run["model"],
                run.get("session_id"),
                run.get("dollar_cost", 0.0),
                run.get("latency_ms", 0),
                run.get("tokens_in", 0),
                run.get("tokens_out", 0),
                run.get("error"),
                run["created_at"],
                run.get("target_id"),
            ),
        )
        self.conn.commit()

    def insert_agent_message(self, msg: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO agent_messages "
            "(from_agent, to_agent, schema_name, payload_json, trace_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                msg["from_agent"],
                msg["to_agent"],
                msg["schema_name"],
                canonical_json(msg.get("payload", {})),
                msg.get("trace_id"),
                msg["created_at"],
            ),
        )
        self.conn.commit()

    # --- targets ---------------------------------------------------------

    def register_target(
        self,
        *,
        id: str,
        name: str,
        kind: str,
        base_url: str,
        description: str,
        reach_steps: list[str],
        auth_kind: str,
        auth_meta: dict[str, Any],
        auth_secret_encrypted: bytes | None,
        allowlisted: bool,
        registered_at: str,
    ) -> None:
        """Insert a new target. Raises sqlite3.IntegrityError on duplicate name."""
        self.conn.execute(
            "INSERT INTO targets "
            "(id, name, kind, base_url, description, reach_steps_json, "
            "auth_kind, auth_secret_encrypted, auth_meta_json, allowlisted, "
            "registered_at, last_used_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            (
                id,
                name,
                kind,
                base_url,
                description,
                canonical_json(reach_steps),
                auth_kind,
                auth_secret_encrypted,
                canonical_json(auth_meta),
                1 if allowlisted else 0,
                registered_at,
            ),
        )
        self.conn.commit()

    def get_target(self, id_or_name: str) -> dict[str, Any] | None:
        """Look up a target by id or name. Returns the raw row as a dict.

        The encrypted credential is NOT included in the returned dict
        (callers that need the cleartext must explicitly call
        ``get_target_secret_ciphertext``).
        """
        row = self.conn.execute(
            "SELECT id, name, kind, base_url, description, reach_steps_json, "
            "auth_kind, auth_meta_json, allowlisted, registered_at, "
            "last_used_at FROM targets WHERE id=? OR name=? LIMIT 1",
            (id_or_name, id_or_name),
        ).fetchone()
        if row is None:
            return None
        out = dict(row)
        out["reach_steps"] = json.loads(out.pop("reach_steps_json") or "[]")
        out["auth_meta"] = json.loads(out.pop("auth_meta_json") or "{}")
        out["allowlisted"] = bool(out["allowlisted"])
        return out

    def get_target_secret_ciphertext(self, target_id: str) -> bytes | None:
        row = self.conn.execute(
            "SELECT auth_secret_encrypted FROM targets WHERE id=?",
            (target_id,),
        ).fetchone()
        if row is None:
            return None
        val = row["auth_secret_encrypted"]
        if val is None:
            return None
        return bytes(val)

    def list_targets(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT id, name, kind, base_url, description, reach_steps_json, "
            "auth_kind, auth_meta_json, allowlisted, registered_at, "
            "last_used_at FROM targets ORDER BY registered_at ASC"
        ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            d["reach_steps"] = json.loads(d.pop("reach_steps_json") or "[]")
            d["auth_meta"] = json.loads(d.pop("auth_meta_json") or "{}")
            d["allowlisted"] = bool(d["allowlisted"])
            out.append(d)
        return out

    def set_allowlisted(self, target_id: str, value: bool) -> None:
        self.conn.execute(
            "UPDATE targets SET allowlisted=? WHERE id=?",
            (1 if value else 0, target_id),
        )
        self.conn.commit()

    def set_reach_steps(self, target_id: str, steps: list[str]) -> None:
        self.conn.execute(
            "UPDATE targets SET reach_steps_json=? WHERE id=?",
            (canonical_json(steps), target_id),
        )
        self.conn.commit()

    def touch_target(self, target_id: str, *, used_at: str) -> None:
        self.conn.execute(
            "UPDATE targets SET last_used_at=? WHERE id=?",
            (used_at, target_id),
        )
        self.conn.commit()

    def delete_target(self, target_id: str) -> None:
        """Refuse if any findings/attacks reference this target_id."""
        f_count = self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE target_id=?", (target_id,)
        ).fetchone()[0]
        a_count = self.conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE target_id=?", (target_id,)
        ).fetchone()[0]
        if f_count or a_count:
            raise ValueError(
                f"Cannot remove target {target_id!r}: "
                f"{f_count} finding(s) and {a_count} attack(s) reference it. "
                "Targets are kept for audit traceability once they have been "
                "scanned. Run `adversary status --reset-db` to wipe everything "
                "if you really want to start over."
            )
        self.conn.execute("DELETE FROM targets WHERE id=?", (target_id,))
        self.conn.commit()

    def target_stats(self, target_id: str) -> dict[str, int]:
        f = self.conn.execute(
            "SELECT COUNT(*) FROM findings WHERE target_id=?", (target_id,)
        ).fetchone()[0]
        a = self.conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE target_id=?", (target_id,)
        ).fetchone()[0]
        # campaigns count: distinct orchestrator session_ids whose target_id
        # column matches.
        c = self.conn.execute(
            "SELECT COUNT(DISTINCT session_id) FROM agent_runs "
            "WHERE agent='orchestrator' AND target_id=?",
            (target_id,),
        ).fetchone()[0]
        return {"campaigns": int(c), "attacks": int(a), "findings": int(f)}

    # --- summaries -------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        def scalar(sql: str, params: tuple[Any, ...] = ()) -> Any:
            row = self.conn.execute(sql, params).fetchone()
            return row[0] if row else 0

        campaigns = scalar("SELECT COUNT(*) FROM agent_runs WHERE agent='orchestrator'")
        attacks = scalar("SELECT COUNT(*) FROM attacks")
        verdicts_by_label: dict[str, int] = {"success": 0, "partial": 0, "fail": 0}
        for row in self.conn.execute(
            "SELECT verdict, COUNT(*) c FROM verdicts GROUP BY verdict"
        ):
            verdicts_by_label[row["verdict"]] = int(row["c"])

        findings_by_severity: dict[str, int] = {}
        for row in self.conn.execute(
            "SELECT severity, COUNT(*) c FROM findings GROUP BY severity"
        ):
            findings_by_severity[row["severity"]] = int(row["c"])

        total_cost = scalar("SELECT COALESCE(SUM(dollar_cost), 0.0) FROM agent_runs")
        head_hash = self.head_hash()
        audit_rows = scalar("SELECT COUNT(*) FROM audit_log")
        targets_total = scalar("SELECT COUNT(*) FROM targets")
        return {
            "campaigns": int(campaigns),
            "attacks": int(attacks),
            "verdicts": verdicts_by_label,
            "findings_by_severity": findings_by_severity,
            "total_dollar_cost": float(total_cost),
            "audit_head_hash": head_hash,
            "audit_rows": int(audit_rows),
            "targets_total": int(targets_total),
        }
