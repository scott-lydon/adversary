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
}


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

    def insert_attack(self, attack_dict: dict[str, Any], created_at: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO attacks "
            "(attack_id, category, subcategory, prompt_sequence_json, "
            "expected_unsafe_behavior, mutation_lineage_json, "
            "generation_metadata_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                attack_dict["attack_id"],
                attack_dict["category"],
                attack_dict["subcategory"],
                canonical_json(attack_dict.get("prompt_sequence", [])),
                attack_dict["expected_unsafe_behavior"],
                canonical_json(attack_dict.get("mutation_lineage", [])),
                canonical_json(attack_dict.get("generation_metadata", {})),
                created_at,
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
            "lineage_root, report_path, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            ),
        )
        self.conn.commit()

    def insert_agent_run(self, run: dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO agent_runs "
            "(agent, model, session_id, dollar_cost, latency_ms, "
            "tokens_in, tokens_out, error, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        return {
            "campaigns": int(campaigns),
            "attacks": int(attacks),
            "verdicts": verdicts_by_label,
            "findings_by_severity": findings_by_severity,
            "total_dollar_cost": float(total_cost),
            "audit_head_hash": head_hash,
            "audit_rows": int(audit_rows),
        }
